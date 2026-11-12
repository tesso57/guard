/**
 * guard — judges the risk of every pi tool call before it runs.
 *
 * Evaluation order:
 *   1. hard deny (protected paths, obvious destruction)          → block; an exact retry may ask once
 *   2. deny / ask rules (any scope)                               → block / confirm
 *   3. allow rule matching every subcommand                       → light model check (exfiltration, intent, judge manipulation)
 *   4. sensitive paths                                            → confirm
 *   5. safe list (read-only bash, plain edits inside the project) → allow without the model
 *   6. skipModelTools (read/grep/find/ls)                         → allow
 *   7. Decisions API with intent, history and past decisions      → allow / confirm / block
 *   Failures confirm (or block without a UI). Without GUARD_OPENAI_API_KEY guard runs in rules-only mode.
 */
import { createHash } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { basename, isAbsolute, relative } from "node:path";
import { types as utilTypes } from "node:util";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { audit, tail, type AuditRecord } from "./audit.ts";
import { type Config, loadConfig } from "./config.ts";
import { predictEdits } from "./edits.ts";
import { MAX_FILE_BYTES, readBoundedText } from "./files.ts";
import { buildRequest, callDecisions, evaluate, MAX_ATTACHED_FILES, type ModelVerdict } from "./judge.ts";
import { redact } from "./redact.ts";
import { clearPathCache, createTrustedDirState, isFreelyReadable, listTrustedDirs, trustDir, type TrustedDirState, isHardLinked, isInsideExact, pathLikeTokens, pathVariants, protectedReason, protectedRoots, realPath, recentlyChangedFiles, resolvePath, sensitiveReason } from "./paths.ts";
import { BUILTIN_TOOLS, hardDeny, hasUninspectedToolInput, inputPaths, inspectExecutablePath, pathsStayInProject, piString, safeAllow, searchNeedsJudgement, sensitive, usesRipgrepConfig, writesStayPlain } from "./policy.ts";
import { type Decision, deriveDenyPatterns, derivePatterns, describeMatch, globalAllowPatternIsReadOnly, type Match, newId, type Rule, RuleStore, type Scope, supportsAnyInputAllow } from "./rules.ts";
import { isReadOnlyArgv, normalizeArgv, type Parsed, parseShell } from "./shell.ts";
import { isSkillRead } from "./skill-read.ts";
import { confirmDialog, displayText, preview } from "./ui.ts";

const STATE_ENTRY = "guard-state";
/** Commands that run project scripts, tests or build files, which an earlier edit may have changed. */
const SCRIPT_RUNNERS = new Set([
  "npm", "pnpm", "yarn", "bun", "npx", "make", "gmake", "just", "pytest", "tox", "nox", "cargo", "go", "gradle", "gradlew", "mvn", "rake", "bundle",
  "deno", "uv", "poetry", "turbo", "nx", "jest", "vitest", "pre-commit", "docker", "docker-compose",
  // Interpreters load project code too (python -m pytest, node --test, sh script.sh)
  "python", "python3", "node", "ruby", "perl", "php", "sh", "bash", "zsh",
]);
const MAX_CACHE = 500;
const MAX_BLOCKED_RETRIES = 500;
const MAX_STATE_RECHECKS = 3;
const MAX_BATCH_CALLS = 128;
const MAX_PREFLIGHT_CALLS = 8;

type ToolCallLike = { id: string; name: string; arguments: any };
type BatchContext = { earlier: ToolCallLike[]; peers: ToolCallLike[]; historyBoundary?: number; problem?: string };

function batchProblem(calls: ToolCallLike[]): string | undefined {
  if (calls.length > MAX_BATCH_CALLS) return "tool batch exceeds the inspection limit";
  const ids = new Set<string>();
  for (const call of calls) {
    if (typeof call.id !== "string" || !call.id.trim() || ids.has(call.id)) return "tool batch has duplicate or invalid call IDs";
    ids.add(call.id);
  }
  return undefined;
}

type Assessment = {
  action: "allow" | "confirm" | "block";
  source: "hard-deny" | "rule-deny" | "rule-ask" | "rule-allow" | "sensitive" | "safe" | "skip" | "model" | "cache" | "concurrent" | "error";
  reasons: string[];
  /** A separately sanitized explanation for persistent audit records, when needed. */
  auditReasons?: string[];
  verdict?: ModelVerdict;
  patterns?: Match[];
  denyPatterns?: Match[];
  rememberAllow: boolean;
  globalAllow: boolean;
  rules?: Rule[];
};

function stableHash(v: unknown): string {
  const norm = (x: any): any =>
    Array.isArray(x) ? x.map(norm) : x && typeof x === "object" ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, norm(x[k])])) : x;
  return createHash("sha256").update(JSON.stringify(norm(v))).digest("hex");
}

/** Tool arguments must remain JSON data for comparisons to be reliable. */
function toolInputHash(tool: string, input: unknown): string {
  const ancestors = new WeakSet<object>();
  let remaining = 100_000;
  const visit = (value: unknown): void => {
    if (--remaining < 0) throw new Error("tool input is too complex");
    if (value === null || typeof value === "string" || typeof value === "boolean") return;
    // JSON.stringify collapses -0 to 0, but a tool can distinguish them.
    if (typeof value === "number" && Number.isFinite(value) && !Object.is(value, -0)) return;
    if (typeof value !== "object") throw new Error("tool input is not JSON data");
    if (utilTypes.isProxy(value)) throw new Error("tool input contains a proxy");
    const array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (array && prototype !== Array.prototype) throw new Error("tool input is not a plain array");
    if (!array && prototype !== Object.prototype && prototype !== null) throw new Error("tool input is not a plain object");
    if (ancestors.has(value)) throw new Error("tool input contains a cycle");
    ancestors.add(value);
    try {
      if (array && value.length > remaining) throw new Error("tool input is too complex");
      const keys = Reflect.ownKeys(value);
      if (keys.length - (array ? 1 : 0) > remaining) throw new Error("tool input is too complex");
      if (array && keys.length !== value.length + 1) throw new Error("tool input contains a sparse array or extra properties");
      for (const key of keys) {
        if (typeof key !== "string") throw new Error("tool input contains symbol keys");
        if (array && key === "length") continue;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !descriptor.enumerable || !("value" in descriptor) || (array && (!/^(0|[1-9]\d*)$/.test(key) || Number(key) >= value.length))) throw new Error("tool input has unsupported properties");
        visit(descriptor.value);
      }
    } finally { ancestors.delete(value); }
  };
  visit(input);
  return stableHash([tool, input]);
}

/** Shell lookup and startup settings can change while the approval dialog is open. */
function shellEnvironmentHash(): string {
  return stableHash(Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    key.toLowerCase() === "path" || ["BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS", "PS4"].includes(key) || (key.startsWith("BASH_FUNC_") && key.endsWith("%%")),
  )));
}

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.filter((c: any) => c?.type === "text").map((c: any) => c.text).join("\n");
  return "";
}

const TREE_TOOLS = new Set(["tar", "unzip", "7z", "bsdtar", "rsync", "cp", "mv", "ln", "patch", "curl", "wget", "git-lfs"]);
/** Package-manager subcommands that replace dependency trees (and their bin links). */
const PM_TREE = new Set(["install", "i", "ci", "add", "update", "upgrade", "up", "remove", "rm", "uninstall", "rebuild", "link", "sync", "dedupe", "prune"]);
const PACKAGE_MANAGERS = new Set(["npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "go", "gem", "bundle", "composer"]);

/** Calls that may replace or add many files at once (and so create symlinks guard has not seen). */
function changesTrees(c: ToolCallLike): boolean {
  if (c.name !== "bash") return !["read", "grep", "find", "ls", "write", "edit"].includes(c.name);
  const p = parseShell(String(c.arguments?.command ?? ""));
  if (!p.ok || p.dynamic.length) return true;
  return p.subcommands.some((raw) => {
    const a = normalizeArgv(raw, "deny").argv;
    const sub = a.find((t, i) => i > 0 && !t.startsWith("-")) ?? "";
    // Git operations that change state can run hooks, which may modify arbitrary files.
    return TREE_TOOLS.has(a[0]) || (a[0] === "git" && !isReadOnlyArgv(raw)) || (PACKAGE_MANAGERS.has(a[0]) && PM_TREE.has(sub));
  });
}

/** Whether the call writes anything (tools that write, or bash that is not strictly read-only). */
function callWrites(tool: string, input: any, cwd: string, parsed?: Parsed): boolean {
  if (tool === "write" || tool === "edit") return true;
  if (tool !== "bash") return !["read", "grep", "find", "ls"].includes(tool);
  if (!parsed || !parsed.ok || parsed.dynamic.length) return true;
  return parsed.writes.length > 0 || !parsed.subcommands.every(isReadOnlyArgv) || inputPaths(tool, input, cwd, parsed).writes.length > 0;
}

/** Snapshot deterministic access checks and the resolved paths they examined. */
function filesystemPolicyHash(tool: string, input: unknown, cwd: string, sessionDir: string | undefined, trustedDirs: TrustedDirState, parsed?: Parsed, checked?: { hard: string | undefined; sens: string | undefined; uncertainSearch: boolean }): string {
  const roots = protectedRoots(cwd, sessionDir);
  const paths = inputPaths(tool, input, cwd, parsed);
  return stableHash({
    hard: checked ? checked.hard : hardDeny(tool, input, cwd, roots, parsed),
    sens: checked ? checked.sens : sensitive(tool, input, cwd, roots, parsed),
    uncertainSearch: checked ? checked.uncertainSearch : searchNeedsJudgement(tool, input, cwd, parsed),
    trustedDirsVersion: trustedDirs.version,
    paths: { reads: paths.reads.map((path) => [path, realPath(path)]), writes: paths.writes.map((path) => [path, realPath(path)]) },
  });
}

function siblingWrites(c: ToolCallLike, cwd: string): string[] {
  try {
    const p = c.name === "bash" ? parseShell(String(c.arguments?.command ?? "")) : undefined;
    return inputPaths(c.name, c.arguments, cwd, p).writes;
  } catch {
    return [];
  }
}

/** Ignore files change what later searches (rg, fd, git grep) read. */
const IGNORE_FILES = new Set([".ignore", ".rgignore", ".gitignore", ".fdignore"]);
/** Read-only shell commands that operate on strings or process identity without opening project paths. */
const NO_PATH_READ_COMMANDS = new Set(["echo", "printf", "pwd", "true", "false", "whoami", "uname", "id", "groups", "basename", "dirname"]);

/** Plain edits of ordinary project files and mkdir/touch: they cannot create links or reach outside the project. */
function isPlainChange(c: ToolCallLike, cwd: string, trustedDirs: TrustedDirState): boolean {
  if (siblingWrites(c, cwd).some((p) => IGNORE_FILES.has(basename(p)))) return false;
  if (c.name === "write" || c.name === "edit") return safeAllow(c.name, c.arguments, cwd, { trusted: false, touched: new Set(), trustedDirs });
  if (c.name !== "bash") return false;
  const p = parseShell(String(c.arguments?.command ?? ""));
  return p.subcommands.every((a) => ["mkdir", "touch"].includes(normalizeArgv(a).argv[0])) && safeAllow("bash", c.arguments, cwd, { trusted: false, touched: new Set(), trustedDirs }, p);
}

/** True for calls that cannot change the file system: read tools and strictly read-only bash. */
function isPureRead(c: ToolCallLike, cwd: string, trustedDirs: TrustedDirState): boolean {
  if (["read", "grep", "find", "ls"].includes(c.name)) return true;
  if (c.name !== "bash") return false;
  const p = parseShell(String(c.arguments?.command ?? ""));
  return p.ok && !p.dynamic.length && !p.writes.length && p.subcommands.every(isReadOnlyArgv) && writesStayPlain("bash", c.arguments, cwd, p, trustedDirs) && inputPaths("bash", c.arguments, cwd, p).writes.length === 0;
}

function isRegularFile(p: string): boolean {
  try {
    const st = statSync(p);
    return st.isFile();
  } catch {
    return false;
  }
}

export default function (pi: ExtensionAPI) {
  const trustedDirs = createTrustedDirState();
  let cfg: Config = loadConfig();
  const store = new RuleStore();
  let enabled = true;
  let trusted = false;
  let storeCwd = "";
  /**
   * Model verdicts started at message_end, reused by tool_call. Only the model call is reused:
   * every deterministic check runs again at tool_call, because earlier calls may have changed the file system.
   */
  const modelMemo = new Map<string, Promise<ModelVerdict>>();
  const obsoletePreflight = new Error("preflight no longer valid");
  let preflightController: AbortController | undefined;
  const stopPreflight = () => {
    preflightController?.abort(obsoletePreflight);
    preflightController = undefined;
  };
  /** Earlier calls for context and all other calls for concurrent filesystem risks. */
  const siblingsById = new Map<string, BatchContext>();
  const judged = new Map<string, { hash: string; session: string }>();
  const verdictCache = new Map<string, { at: number; a: Assessment }>();
  /** Files written or edited in this session. */
  const touched = new Set<string>();
  /** True once an allowed call changed files in ways guard cannot list (git checkout, tar x, rsync, ...). */
  let opaqueChanges = false;
  const promoted = new Set<string>();
  /** Calls guard blocked this session (tool + input); the same call again asks the user instead of blocking. */
  const blockedOnce = new Set<string>();
  let consecutiveBlocks = 0;
  let totalBlocks = 0;
  let auditState: "unknown" | "ok" | "failed" = "unknown";
  let auditFailureNotified = false;
  let auditRecoveryPending = false;
  let stateEpoch = 0;

  const append = (type: string, data: unknown) => pi.appendEntry(type, data);

  function warn(ctx: ExtensionContext, message: string) {
    try {
      const text = displayText(message);
      if (ctx.hasUI) ctx.ui.notify(text, "warning");
      else process.stderr.write(`${text}\n`);
      return true;
    } catch { return false; /* notifications must not affect decisions */ }
  }

  function recordAudit(ctx: ExtensionContext, record: AuditRecord) {
    const written = audit(record);
    if (!written) {
      if (auditState !== "failed") auditFailureNotified = false;
      auditState = "failed";
      if (!auditFailureNotified) auditFailureNotified = warn(ctx, "guard: audit log unavailable; decisions will not be recorded until it recovers");
    } else {
      if (auditState === "failed") auditRecoveryPending = true;
      auditState = "ok";
      auditFailureNotified = false;
      if (auditRecoveryPending && warn(ctx, "guard: audit logging recovered; some decisions may be missing")) auditRecoveryPending = false;
    }
  }

  /** A preview in a persistent log must not copy contents supplied for sensitive files. */
  function auditPreview(ctx: ExtensionContext, tool: string, input: unknown): string {
    try {
      const parsed = tool === "bash" ? parseShell(String((input as any)?.command ?? "")) : undefined;
      if ((parsed && !parsed.ok) || hasUninspectedToolInput(tool, input)) return `${tool} [arguments withheld: input could not be inspected]`;
      const paths = inputPaths(tool, input, ctx.cwd, parsed);
      const roots = protectedRoots(ctx.cwd, ctx.sessionManager.getSessionDir());
      if (sensitive(tool, input, ctx.cwd, roots, parsed) || [...paths.reads, ...paths.writes].some((path) => sensitiveReason(path) || protectedReason(path, roots) || isHardLinked(path)))
        return `${tool} [arguments withheld: sensitive, protected or hard-linked path]`;
      return preview(tool, redact(input));
    } catch {
      return `${tool} [arguments withheld: input could not be inspected]`;
    }
  }

  function privatePastRule(ctx: ExtensionContext, rule: Rule): boolean {
    const match = rule.match;
    if (match.kind === "tool") return false;
    try {
      const roots = protectedRoots(ctx.cwd, ctx.sessionManager.getSessionDir());
      const words = match.kind === "path" ? [match.path] : match.kind === "argv" ? match.prefix : match.argv;
      if (words.some((word) => word.length >= 16 * 1024)) return true;
      const paths = [...pathLikeTokens(ctx.cwd, words), ...words.flatMap((word) => pathVariants(ctx.cwd, word))];
      return paths.some((path) => sensitiveReason(path) || protectedReason(path, roots) || isHardLinked(path));
    } catch {
      return true;
    }
  }

  function syncProject(ctx: ExtensionContext) {
    const currentTrust = ctx.isProjectTrusted();
    if (ctx.cwd === storeCwd && currentTrust === trusted) return;
    stopPreflight();
    trusted = currentTrust;
    storeCwd = ctx.cwd;
    store.load(storeCwd, trusted);
    modelMemo.clear();
    verdictCache.clear();
    blockedOnce.clear();
    for (const warning of store.warnings) warn(ctx, `guard: ${warning}`);
  }

  /**
   * Tools other extensions vouch for (`pi.events.emit("guard:trust-tool", { tool, by })`), e.g. a notes extension's
   * notes_write. They run without judgement. Extensions are code the user installed and run with full privileges anyway;
   * built-in tools cannot be vouched for, and tools of project-local extensions count only in trusted projects.
   */
  const extensionTrust = new Map<string, string>();
  pi.events.on("guard:trust-tool", (data) => {
    const d = data as { tool?: unknown; by?: unknown } | undefined;
    if (typeof d?.tool !== "string" || !d.tool) return;
    extensionTrust.set(d.tool, typeof d.by === "string" && d.by ? d.by.slice(0, 64) : "an extension");
  });
  // Folders another extension vouches for: { path: "~/.pi/artifacts", by: "artifacts", access?: "read" | "write" }
  pi.events.on("guard:trust-dir", (data) => {
    const d = data as { path?: unknown; by?: unknown; access?: unknown } | undefined;
    if (typeof d?.path !== "string" || !d.path) return;
    if (d.access !== undefined && d.access !== "read" && d.access !== "write") return;
    trustDir(d.path, d.access !== "read", typeof d.by === "string" && d.by ? d.by.slice(0, 64) : "an extension", trustedDirs);
  });
  /** Why a vouched-for tool name does not count (undefined when it does). */
  function trustProblem(tool: string): string | undefined {
    if (BUILTIN_TOOLS.has(tool)) return "built-in tools cannot be vouched for";
    try {
      const info = pi.getAllTools().find((t) => t.name === tool);
      const src = info?.sourceInfo;
      if (!info) return "no tool with this name is registered";
      if (!src || src.path.startsWith("builtin:")) return "built-in tools cannot be vouched for";
      if (src.scope === "project" && !trusted) return "the tool comes from a project-local extension and this project is not trusted";
      return undefined;
    } catch {
      return "could not read the registered tools";
    }
  }
  function trustedByExtension(tool: string): string | undefined {
    const by = extensionTrust.get(tool);
    return by && !trustProblem(tool) ? by : undefined;
  }

  const registeredSkillTargets = new Map<string, string>();
  function snapshotRegisteredSkills(): void {
    clearPathCache();
    try {
      for (const command of pi.getCommands()) {
        const path = command.sourceInfo?.path;
        if (command.source !== "skill" || typeof path !== "string" || !isAbsolute(path)) continue;
        if (registeredSkillTargets.has(path)) continue;
        try { if (statSync(path).isFile()) registeredSkillTargets.set(path, realPath(path)); } catch { /* unavailable skills do not qualify */ }
      }
    } catch { /* unavailable registry does not grant new bypasses */ }
  }

  function registeredSkillPaths(): string[] {
    clearPathCache();
    try {
      return pi.getCommands().filter((command) => {
        const path = command.sourceInfo?.path;
        return command.source === "skill" && typeof path === "string" && registeredSkillTargets.has(path) && registeredSkillTargets.get(path) === realPath(path);
      }).map((command) => command.sourceInfo.path);
    } catch { return []; }
  }

  /** Other tool calls of the assistant message that contains callId, from the session branch. */
  function siblingsFromBranch(ctx: ExtensionContext, callId: string): BatchContext {
    const branch = ctx.sessionManager.getBranch() as any[];
    for (let i = branch.length - 1; i >= 0; i--) {
      const m = branch[i]?.message;
      if (branch[i]?.type !== "message" || m?.role !== "assistant" || !Array.isArray(m.content)) continue;
      const calls = m.content.filter((c: any) => c?.type === "toolCall");
      const idx = calls.findIndex((c: any) => c.id === callId);
      if (idx >= 0) {
        const problem = batchProblem(calls);
        if (problem) return { earlier: [], peers: [], historyBoundary: i, problem };
        const mapped = calls.map((c: any) => ({ id: c.id, name: c.name, arguments: c.arguments }));
        return { earlier: mapped.slice(0, idx), peers: mapped.filter((_: ToolCallLike, j: number) => j !== idx), historyBoundary: i };
      }
    }
    return { earlier: [], peers: [] };
  }

  /** Builds the judge's context from the session branch plus earlier calls of the same assistant message. */
  function context(ctx: ExtensionContext, callId: string, tool: string, parsed: Parsed | undefined, siblings: ToolCallLike[], peers: ToolCallLike[], historyBoundary?: number) {
    const users: unknown[] = [];
    const calls: ToolCallLike[] = [];
    const siblingIds = new Set(siblings.map((s) => s.id));
    const seenSiblings = new Set<string>();
    const pushBounded = <T>(items: T[], value: T, limit: number) => {
      if (!limit) return;
      items.push(value);
      if (items.length > limit) items.shift();
    };
    const addCall = (call: ToolCallLike, currentMessage = false) => {
      if (currentMessage && siblingIds.has(call.id)) seenSiblings.add(call.id);
      pushBounded(calls, call, cfg.contextToolCalls);
    };
    const branch = ctx.sessionManager.getBranch() as any[];
    const boundary = historyBoundary ?? branch.length;
    for (let entryIndex = 0; entryIndex < branch.length; entryIndex++) {
      const e = branch[entryIndex];
      if (e.type !== "message") continue;
      const m = e.message;
      if (m?.role === "user") pushBounded(users, m.content, cfg.contextUserMessages);
      if (m?.role === "assistant" && Array.isArray(m.content)) {
        const current = entryIndex < boundary ? -1 : m.content.findIndex((c: any) => c?.type === "toolCall" && c.id === callId);
        const end = current < 0 ? m.content.length : current;
        for (let i = 0; i < end; i++) {
          const c = m.content[i];
          if (c?.type === "toolCall") addCall({ id: c.id, name: c.name, arguments: c.arguments }, current >= 0);
        }
        if (current >= 0) break;
      }
    }
    // At message_end the current message is not in the branch yet, so add earlier siblings explicitly
    for (const s of siblings) if (!seenSiblings.has(s.id)) addCall(s, true);

    // Proposed contents from concurrent calls; Pi has not executed them when this call is judged.
    const roots = protectedRoots(ctx.cwd, ctx.sessionManager.getSessionDir());
    let historyIncomplete = false;
    let historyLiteralBudget = 128;
    const historyForJudge = (call: ToolCallLike): ToolCallLike => {
      const withholdUninspectable = () => {
        historyIncomplete = true;
        return { ...call, arguments: { note: "[arguments withheld by guard: prior call could not be inspected]" } };
      };
      const parsedCall = call.name === "bash" ? parseShell(String(call.arguments?.command ?? "")) : undefined;
      if ((parsedCall && !parsedCall.ok) || hasUninspectedToolInput(call.name, call.arguments)) return withholdUninspectable();
      const paths = inputPaths(call.name, call.arguments, ctx.cwd, parsedCall);
      // Interpreter snippets can hide path strings inside code rather than as shell operands.
      const embedded: string[] = [];
      if (parsedCall?.dynamic.length) for (const word of parsedCall.subcommands.flat()) {
        for (const match of word.matchAll(/(['"])([\s\S]*?)\1/g)) {
          if (historyLiteralBudget-- <= 0) return withholdUninspectable();
          embedded.push(...pathVariants(ctx.cwd, match[2]));
        }
      }
      const privatePaths = [...new Set([...paths.reads, ...paths.writes, ...embedded])].filter((path) => sensitiveReason(path) || protectedReason(path, roots) || isHardLinked(path));
      if (!privatePaths.length) return call;
      return { ...call, arguments: { paths: privatePaths, note: "[arguments withheld by guard: call involves a sensitive or protected file]" } };
    };
    const virtual = new Map<string, string>();
    const unknownEdits = new Set<string>();
    const concurrentPaths = new Map<string, string[]>();
    // Only bash assessments attach project files; other tools need history, not edit predictions.
    for (const s of tool === "bash" ? peers : []) {
      const path = piString(s.arguments?.path);
      const p = path === undefined ? undefined : resolvePath(ctx.cwd, path);
      if (!p || (s.name !== "write" && s.name !== "edit")) continue;
      const target = realPath(p);
      const aliases = concurrentPaths.get(target);
      if (aliases) {
        aliases.push(p);
        for (const alias of aliases) { virtual.delete(alias); unknownEdits.add(alias); }
        continue;
      }
      concurrentPaths.set(target, [p]);
      if (s.name === "write") {
        const content = piString(s.arguments.content);
        if (content !== undefined) {
          if (Buffer.byteLength(content, "utf8") < MAX_FILE_BYTES) { virtual.set(p, content); unknownEdits.delete(p); }
          else { virtual.delete(p); unknownEdits.add(p); }
        } else { virtual.delete(p); unknownEdits.add(p); }
      }
      if (s.name === "edit") {
        if (concurrentPaths.size > MAX_ATTACHED_FILES) { unknownEdits.add(p); continue; }
        const mayRead = !sensitiveReason(p) && !protectedReason(p, roots) && !isHardLinked(p);
        const before = unknownEdits.has(p) ? undefined : virtual.get(p) ?? (mayRead ? readBoundedText(p) : undefined);
        const after = before === undefined || before.length >= MAX_FILE_BYTES ? undefined : predictEdits(before, s.arguments);
        if (after === undefined) { virtual.delete(p); unknownEdits.add(p); }
        else virtual.set(p, after);
      }
    }
    const attached: Record<string, string> = Object.create(null);
    let attachmentCount = 0;
    let attachmentsIncomplete = false;
    const fromSiblings: string[] = [];
    const unreadableFiles: string[] = [];
    const hardlinkedFiles = new Set<string>();
    const attach = (p: string, fromDisk = false, mustInspect = false) => {
      if (attached[p] !== undefined) {
        if (mustInspect && hardlinkedFiles.has(p) && !unreadableFiles.includes(p)) unreadableFiles.push(p);
        return;
      }
      if (virtual.has(p) || unknownEdits.has(p)) fromSiblings.push(p);
      if (attachmentCount >= MAX_ATTACHED_FILES && (virtual.has(p) || unknownEdits.has(p) || touched.has(p) || fromDisk)) {
        attachmentsIncomplete = true;
        return;
      }
      const record = (text: string) => {
        if (attachmentCount >= MAX_ATTACHED_FILES) { attachmentsIncomplete = true; return; }
        attached[p] = text;
        attachmentCount++;
      };
      // Its other name may be a secret outside the project, which cannot be inferred from this path.
      if (isHardLinked(p)) {
        record("[contents withheld by guard: file has multiple hard links]");
        hardlinkedFiles.add(p);
        if (mustInspect) unreadableFiles.push(p);
        return;
      }
      // Never send secrets (or guard's own state) to the judge; the name is enough for it to know the file is involved
      if (sensitiveReason(p) || protectedReason(p, roots)) {
        record("[contents withheld by guard: file likely holds secrets]");
        return;
      }
      if (unknownEdits.has(p)) {
        record("[contents unknown: concurrent edits could not be predicted]");
        return;
      }
      if (virtual.has(p)) {
        record(`[proposed contents from a concurrent call; execution order is not guaranteed]\n${virtual.get(p)!}`);
        return;
      }
      const shouldRead = touched.has(p) || fromDisk;
      if (shouldRead && isRegularFile(p)) {
        try {
          if (statSync(p).size >= MAX_FILE_BYTES) {
            unreadableFiles.push(p);
            return;
          }
        } catch {
          unreadableFiles.push(p);
          return;
        }
      }
      const text = shouldRead ? readBoundedText(p) : undefined;
      if (text !== undefined) record(text);
      else if (shouldRead && isRegularFile(p)) unreadableFiles.push(p);
    };
    let runsScripts = false;
    let changedCount = 0;
    if (tool === "bash" && parsed) {
      for (const tok of parsed.subcommands.flat()) attach(resolvePath(ctx.cwd, tok));
      // Interpreters, runners, and scripts run by path (./run.sh) execute file contents
      const versionQuery = (a: string[]) => a.length === 2 && !a[0].includes("/") && /^(--version|-V|--help)$/.test(a[1]) && isReadOnlyArgv(a);
      runsScripts = parsed.subcommands.some((a) => !versionQuery(a) && (SCRIPT_RUNNERS.has(normalizeArgv(a, "deny").argv[0]) || (a[0] ?? "").includes("/")));
      if (runsScripts) {
        // The script an interpreter or runner is given is what will run, whoever wrote it
        for (const tok of parsed.subcommands.flat()) {
          const p = resolvePath(ctx.cwd, tok);
          if (isRegularFile(p)) attach(p, true, true);
          else {
            try {
              const st = statSync(p);
              if (!st.isDirectory()) unreadableFiles.push(p);
            } catch { /* missing path */ }
          }
        }
        // Test runners and build tools also load project files that are not named in the command
        // (tests, conftest.py, package.json scripts, node_modules/.bin): attach every file changed in this session,
        // and recently changed project files (which may come from an earlier session or a git checkout)
        let candidates = 0;
        candidateScan: for (const paths of [virtual.keys(), unknownEdits.values(), touched.values()]) for (const p of paths) {
          if (!isInsideExact(p, ctx.cwd)) continue;
          if (++candidates > 256) { attachmentsIncomplete = true; break candidateScan; }
          attach(p, false, true);
          if (attachmentsIncomplete) break candidateScan;
        }
        // Changes guard could not follow (git checkout, extracting archives) also call for a full judgement
        changedCount = Object.keys(attached).length + (opaqueChanges ? 1 : 0);
        // Context only: recently changed files do not by themselves force a full judgement
        if (!attachmentsIncomplete) for (const p of recentlyChangedFiles(ctx.cwd)) {
          attach(p, true);
          if (attachmentsIncomplete) break;
        }
      }
    }
    const history = calls.map(historyForJudge);
    return {
      userMessages: users.map(textOf),
      history,
      historyIncomplete,
      attachmentsIncomplete,
      attachedFiles: attached,
      fromSiblings,
      unreadableFiles,
      changedFilesRun: runsScripts && (changedCount > 0 || attachmentsIncomplete),
    };
  }

  async function judgeWithModel(tool: string, input: any, ctx: ExtensionContext, callId: string, cx: ReturnType<typeof context>, past: Rule[], light: boolean, judgementStateKey: string, signal?: AbortSignal): Promise<ModelVerdict> {
    const config = cfg;
    const key = stableHash([callId, tool, input, light, ctx.cwd, cx.attachedFiles, cx.userMessages, cx.history, cx.historyIncomplete, cx.attachmentsIncomplete, past, config, judgementStateKey]);
    const run = async () => {
      const { body, truncated, redacted } = buildRequest(config, { tool, input, cwd: ctx.cwd, callId, past, light, ...cx, sessionId: ctx.sessionManager.getSessionId() });
      return evaluate(config, await callDecisions(config, body, signal), {
        light, truncated, redacted,
        expectPastDenial: !light && past.some((r) => r.decision === "deny"),
        expectPastApproval: !light && past.some((r) => r.decision === "allow"),
      });
    };
    // Unknown changes may alter files without changing any of the visible context.
    if (opaqueChanges && cx.changedFilesRun) return run();
    const memo = modelMemo.get(key);
    if (memo) {
      modelMemo.delete(key);
      try {
        return await memo;
      } catch (e) {
        if (e === obsoletePreflight) throw e;
        if (signal?.aborted) throw new Error("aborted");
        return run(); // the early call failed (e.g. aborted turn); judge again now
      }
    }
    const p = run();
    if (modelMemo.size >= MAX_CACHE) modelMemo.delete(modelMemo.keys().next().value!);
    modelMemo.set(key, p);
    p.catch(() => {});
    return p;
  }

  async function assess(callId: string, tool: string, input: any, ctx: ExtensionContext, opts: { signal?: AbortSignal; siblings?: ToolCallLike[]; peers?: ToolCallLike[]; historyBoundary?: number; stateRechecks?: number } = {}): Promise<Assessment> {
    const config = cfg;
    const epoch = stateEpoch;
    const inputHash = toolInputHash(tool, input);
    clearPathCache();
    const parsed = tool === "bash" ? parseShell(String(input?.command ?? "")) : undefined;
    const roots = protectedRoots(ctx.cwd, ctx.sessionManager.getSessionDir());
    const base = { rememberAllow: false, globalAllow: false };
    const inputChanged = () => {
      try { return toolInputHash(tool, input) !== inputHash; } catch { return true; }
    };
    const changedInput = (): Assessment => ({ ...base, action: "block", source: "error", reasons: ["input changed during judgement"] });
    const recheck = (): Promise<Assessment> => (opts.stateRechecks ?? 0) >= MAX_STATE_RECHECKS
      ? Promise.resolve({ ...base, action: "block", source: "error", reasons: ["rules or settings changed repeatedly during judgement"] })
      : assess(callId, tool, input, ctx, { ...opts, stateRechecks: (opts.stateRechecks ?? 0) + 1 });

    const hard = hardDeny(tool, input, ctx.cwd, roots, parsed);
    if (hard) return { ...base, action: "block", source: "hard-deny", reasons: [hard] };

    syncProject(ctx);
    store.syncSession(ctx.sessionManager.getBranch() as any[]);
    const found = store.find(tool, input, ctx.cwd, parsed);
    // An allow rule only covers calls whose paths stay inside the project, writing only plain files
    const rule = found?.decision === "allow" && (!writesStayPlain(tool, input, ctx.cwd, parsed, trustedDirs) || !pathsStayInProject(tool, input, ctx.cwd, parsed)) ? undefined : found;
    const patterns = derivePatterns(tool, input, ctx.cwd, parsed);
    const denyPatterns = deriveDenyPatterns(tool, input, ctx.cwd, parsed);
    if (rule?.decision === "deny") return { ...base, action: "block", source: "rule-deny", reasons: rule.rules.map((r) => `${r.scope} deny rule: ${describeMatch(r.tool, r.match)}`), auditReasons: rule.rules.map((r) => `${r.scope} deny rule [${r.id}]`), rules: rule.rules };
    if (rule?.decision === "ask") return { ...base, action: "confirm", source: "rule-ask", reasons: rule.rules.map((r) => `${r.scope} ask rule: ${describeMatch(r.tool, r.match)}`), auditReasons: rule.rules.map((r) => `${r.scope} ask rule [${r.id}]`), rules: rule.rules, denyPatterns };

    if (hasUninspectedToolInput(tool, input)) return { ...base, action: "confirm", source: "sensitive", reasons: ["tool input exceeds the deterministic inspection limit"], denyPatterns };
    if (usesRipgrepConfig(parsed)) return { ...base, action: "confirm", source: "sensitive", reasons: ["ripgrep may load options from RIPGREP_CONFIG_PATH"], denyPatterns };

    // Pi may execute all calls in this message concurrently, regardless of their order in the message.
    const peers = opts.peers ?? opts.siblings ?? [];
    const cx = context(ctx, callId, tool, parsed, opts.siblings ?? [], peers, opts.historyBoundary);
    const siblingMayChange = peers.some((sb) => !isPureRead(sb, ctx.cwd, trustedDirs) && !isPlainChange(sb, ctx.cwd, trustedDirs));
    // Concurrent tree changes and non-plain writes can change paths or execution configuration.
    const treeChanger = peers.find((sb) => {
      if (changesTrees(sb)) return true;
      const writes = siblingWrites(sb, ctx.cwd);
      if (sb.name === "bash") return !isPlainChange(sb, ctx.cwd, trustedDirs) && writes.length > 0;
      if (sb.name !== "write" && sb.name !== "edit") return false;
      return !isPlainChange(sb, ctx.cwd, trustedDirs);
    });
    const readsPaths = !!treeChanger && (inputPaths(tool, input, ctx.cwd, parsed).reads.length > 0 || ["grep", "find", "ls"].includes(tool) ||
      (tool === "bash" && !!parsed?.subcommands.some((raw) => {
        const a = normalizeArgv(raw, "deny").argv;
        return !NO_PATH_READ_COMMANDS.has(a[0]);
      })));
    const treeConflict = !!treeChanger && (callWrites(tool, input, ctx.cwd, parsed) || readsPaths);
    const explainTree = (other: string) => `may run alongside "${other.split("\n")[0].slice(0, 80)}" in the same message, which may change the paths this call accesses`;
    const treeReason = treeConflict && treeChanger ? explainTree(preview(treeChanger.name, treeChanger.arguments)) : undefined;
    const treeAuditReason = treeConflict ? explainTree("other call arguments withheld") : undefined;
    if (treeReason && !cx.fromSiblings.length) {
      return { rememberAllow: false, globalAllow: false, action: "confirm", source: "concurrent", reasons: [treeReason], auditReasons: [treeAuditReason!] };
    }
    const sens = sensitive(tool, input, ctx.cwd, roots, parsed);
    const uncertainSearch = searchNeedsJudgement(tool, input, ctx.cwd, parsed);
    // A peer can change the file before or while this call executes it.
    const siblingRun = cx.fromSiblings.length ? `runs ${cx.fromSiblings.map((p) => relative(ctx.cwd, p)).join(", ")}, which may change concurrently in this message` : undefined;

    if (cx.unreadableFiles.length) {
      const reasons = [`cannot inspect file(s) used by this call: ${cx.unreadableFiles.map((p) => relative(ctx.cwd, p)).join(", ")}`, ...(siblingRun ? [siblingRun] : [])];
      return { ...base, action: "confirm", source: "error", reasons: [...reasons, ...(treeReason ? [treeReason] : [])], ...(treeAuditReason ? { auditReasons: [...reasons, treeAuditReason] } : {}), denyPatterns };
    }

    const allRelated = store.related(tool, input, ctx.cwd, parsed);
    const related = allRelated.slice(0, 5);
    const past = related.filter((rule) => !privatePastRule(ctx, rule));
    const historyIncomplete = cx.historyIncomplete || past.length !== related.length || allRelated.length > related.length;
    const ruleVersion = store.version;
    const sessionChanged = (): Assessment => ({ ...base, action: "block", source: "error", reasons: ["session changed during judgement"] });
    const shellEnvironment = parsed ? shellEnvironmentHash() : undefined;
    const executable = parsed ? inspectExecutablePath(parsed, ctx.cwd) : undefined;
    const shellKey = parsed ? stableHash([shellEnvironment, executable]) : undefined;
    const shellChanged = () => {
      if (!parsed) return false;
      if (shellEnvironmentHash() !== shellEnvironment) return true;
      clearPathCache();
      const current = inspectExecutablePath(parsed, ctx.cwd);
      return current.risk !== executable?.risk || (executable?.fingerprint !== undefined && current.fingerprint !== executable.fingerprint);
    };
    const changedShell = (): Assessment => ({ ...base, action: "block", source: "error", reasons: ["shell environment or executable lookup changed during judgement"] });
    const contextHash = stableHash(cx);
    const contextChanged = () => {
      clearPathCache();
      return stableHash(context(ctx, callId, tool, parsed, opts.siblings ?? [], peers, opts.historyBoundary)) !== contextHash;
    };
    const changedContext = (): Assessment => ({ ...base, action: "block", source: "error", reasons: ["judgement context changed during judgement"] });
    const policyHash = filesystemPolicyHash(tool, input, ctx.cwd, ctx.sessionManager.getSessionDir(), trustedDirs, parsed, { hard, sens, uncertainSearch });
    const judgementStateKey = stableHash([shellKey, policyHash]);
    const policyChanged = () => {
      clearPathCache();
      return filesystemPolicyHash(tool, input, ctx.cwd, ctx.sessionManager.getSessionDir(), trustedDirs, parsed) !== policyHash;
    };
    const changedPolicy = (): Assessment => ({ ...base, action: "block", source: "error", reasons: ["filesystem policy changed during judgement"] });
    const stateChanged = () => {
      if (cfg !== config || stateEpoch !== epoch) return true;
      syncProject(ctx);
      store.syncSession(ctx.sessionManager.getBranch() as any[]);
      store.all(); // Refresh rule files that may have changed in another process.
      return cfg !== config || stateEpoch !== epoch || store.version !== ruleVersion;
    };
    if (rule?.decision === "allow" && !sens && !uncertainSearch && !historyIncomplete && !siblingRun && !cx.changedFilesRun && !siblingMayChange) {
      const reasons = rule.rules.map((r) => `${r.scope} allow rule: ${describeMatch(r.tool, r.match)}`);
      const auditReasons = rule.rules.map((r) => `${r.scope} allow rule [${r.id}]`);
      if (!process.env.GUARD_OPENAI_API_KEY) return { ...base, action: "allow", source: "rule-allow", reasons: [...reasons, "rules-only mode (no API key)"], auditReasons: [...auditReasons, "rules-only mode (no API key)"], rules: rule.rules };
      try {
        const v = await judgeWithModel(tool, input, ctx, callId, cx, [], true, judgementStateKey, opts.signal);
        if (inputChanged()) return changedInput();
        if (stateEpoch !== epoch) return sessionChanged();
        if (shellChanged()) return changedShell();
        if (stateChanged()) return recheck();
        if (contextChanged()) return changedContext();
        if (policyChanged()) return changedPolicy();
        if (v.action === "allow") return { ...base, action: "allow", source: "rule-allow", reasons, auditReasons, rules: rule.rules, verdict: v };
        return { ...base, action: v.action, source: "model", reasons: [...v.reasons, "(matches an allow rule, but failed the light check)"], verdict: v, denyPatterns };
      } catch (e: any) {
        if (opts.signal?.aborted) throw e;
        if (inputChanged()) return changedInput();
        if (stateEpoch !== epoch) return sessionChanged();
        if (shellChanged()) return changedShell();
        if (stateChanged()) return recheck();
        if (contextChanged()) return changedContext();
        if (policyChanged()) return changedPolicy();
        return { ...base, action: "confirm", source: "error", reasons: [...reasons, `light check failed: ${e.message}`], auditReasons: [...auditReasons, `light check failed: ${e.message}`], denyPatterns };
      }
    }

    if (sens) {
      const reasons = [`may expose secrets: ${sens}`, ...(siblingRun ? [siblingRun] : []), ...(uncertainSearch ? ["search scope could not be inspected completely"] : [])];
      return { ...base, action: "confirm", source: "sensitive", reasons: [...reasons, ...(treeReason ? [treeReason] : [])], ...(treeAuditReason ? { auditReasons: [...reasons, treeAuditReason] } : {}), patterns, denyPatterns, rememberAllow: !!patterns && !siblingRun && !treeConflict && !uncertainSearch };
    }
    const shortcutsOk = !siblingRun && !siblingMayChange;
    // Files earlier calls of this message will write count as touched for this judgement (git dirs, ignore files)
    const touchedNow = new Set([...touched, ...peers.flatMap((sb) => siblingWrites(sb, ctx.cwd))]);
    if (shortcutsOk && !cx.changedFilesRun && safeAllow(tool, input, ctx.cwd, { trusted, touched: touchedNow, trustedDirs }, parsed)) return { ...base, action: "allow", source: "safe", reasons: [] };
    if (shortcutsOk && !cx.changedFilesRun && !historyIncomplete && !uncertainSearch && cfg.skipModelTools.includes(tool)) {
      // read/grep/find/ls skip the model only inside the project (or public system directories). pi's read tries
      // other spellings (curly quotes, NFD, AM/PM) when a path does not exist, so a read must name an existing file.
      const reads = inputPaths(tool, input, ctx.cwd).reads;
      const exists = tool !== "read" || reads.every((p) => existsSync(p));
      if (exists && (reads.length ? reads : [ctx.cwd]).every((p) => isFreelyReadable(p, ctx.cwd, trustedDirs))) return { ...base, action: "allow", source: "skip", reasons: [] };
    }

    const judgeContext = historyIncomplete === cx.historyIncomplete ? cx : { ...cx, historyIncomplete };
    const cacheKey = stableHash([tool, input, ctx.cwd, judgeContext.attachedFiles, judgeContext.userMessages, judgeContext.history, judgeContext.historyIncomplete, judgeContext.attachmentsIncomplete, store.version, past, cfg, judgementStateKey]);
    const cached = verdictCache.get(cacheKey);
    if (cached && Date.now() - cached.at < cfg.verdictCacheMs && !siblingRun && !uncertainSearch && !(opaqueChanges && cx.changedFilesRun)) return { ...cached.a, source: "cache" };

    try {
      const v = await judgeWithModel(tool, input, ctx, callId, judgeContext, past, false, judgementStateKey, opts.signal);
      if (inputChanged()) return changedInput();
      if (stateEpoch !== epoch) return sessionChanged();
      if (shellChanged()) return changedShell();
      if (stateChanged()) return recheck();
      if (contextChanged()) return changedContext();
      if (policyChanged()) return changedPolicy();
      if (allRelated.length > related.length || past.length !== related.length) v.reasons.push("some related decisions were omitted from judgement");
      const t = cfg.thresholds;
      const rememberAllow =
        !!patterns && v.action !== "block" && (v.pHigh ?? 1) < t.confirmPHigh && (v.exfiltration ?? 1) < t.confirmExfil &&
        (v.addressesEvaluator ?? 1) < t.confirmAddressesEvaluator && !v.truncated && !v.redacted;
      // Global allow rules apply in every trusted project, so only read-only calls may become one
      const globalAllow = rememberAllow && trusted && v.category === "read_only" && (v.risk ?? 9) < t.confirmScore && !!patterns?.every((p) => globalAllowPatternIsReadOnly(tool, p));
      const a: Assessment = { action: v.action, source: "model", reasons: v.reasons, verdict: v, patterns, denyPatterns, rememberAllow, globalAllow };
      if (siblingRun) {
        if (a.action === "allow") a.action = "confirm";
        a.reasons = [...a.reasons, siblingRun, ...(treeReason ? [treeReason] : [])];
        if (treeAuditReason) a.auditReasons = [...v.reasons, siblingRun, treeAuditReason];
        a.rememberAllow = false;
        a.globalAllow = false;
      }
      if (uncertainSearch) {
        const reason = "search scope could not be inspected completely";
        if (a.action === "allow") a.action = "confirm";
        a.reasons = [...a.reasons, reason];
        if (a.auditReasons) a.auditReasons = [...a.auditReasons, reason];
        a.rememberAllow = false;
        a.globalAllow = false;
      }
      if (a.action === "allow" && !siblingRun && !uncertainSearch && !(opaqueChanges && cx.changedFilesRun)) {
        if (verdictCache.size >= MAX_CACHE) {
          for (const [k, e] of verdictCache) if (Date.now() - e.at >= cfg.verdictCacheMs) verdictCache.delete(k);
          if (verdictCache.size >= MAX_CACHE) verdictCache.delete(verdictCache.keys().next().value!);
        }
        verdictCache.set(cacheKey, { at: Date.now(), a });
      }
      return a;
    } catch (e: any) {
      if (opts.signal?.aborted) throw e;
      if (inputChanged()) return changedInput();
      if (stateEpoch !== epoch) return sessionChanged();
      if (shellChanged()) return changedShell();
      if (stateChanged()) return recheck();
      if (contextChanged()) return changedContext();
      if (policyChanged()) return changedPolicy();
      const reasons = [`could not judge: ${e.message}`, ...(siblingRun ? [siblingRun] : []), ...(uncertainSearch ? ["search scope could not be inspected completely"] : [])];
      return { ...base, action: "confirm", source: "error", reasons: [...reasons, ...(treeReason ? [treeReason] : [])], ...(treeAuditReason ? { auditReasons: [...reasons, treeAuditReason] } : {}), patterns, denyPatterns };
    }
  }

  function status(ctx: ExtensionContext, text: string) {
    try { ctx.ui.setStatus("guard", displayText(text)); } catch { /* status display must not affect decisions */ }
  }

  function addRule(decision: Decision, scope: Exclude<Scope, "repo">, tool: string, match: Match, cwd: string, risk?: number, note?: string): Rule {
    const now = new Date();
    const rule: Rule = {
      id: newId(), decision, tool, match, scope, createdAt: now.toISOString(), model: cfg.model, risk, note,
      ...(scope === "session" ? { cwd } : {}),
      ...(decision === "allow" && scope !== "session" ? { expiresAt: new Date(now.getTime() + cfg.allowRuleTtlDays * 86400_000).toISOString() } : {}),
    };
    store.add(rule, append);
    return rule;
  }

  function blockResult(reason: string, retry: "ask-user" | "none" = "none") {
    const next =
      retry === "ask-user"
        ? "Do not try to work around the check. If this exact call is really needed, explain to the user why and ask them; if they agree, run the same call again and guard will ask them to confirm it."
        : "Do not try to work around the check; choose a safer approach or ask the user.";
    return { block: true as const, reason: `guard: ${reason}. ${next}` };
  }

  function updateStatus(ctx: ExtensionContext) {
    status(ctx, cfg.disabled ? "guard: disabled" : !enabled ? "guard: off" : process.env.GUARD_OPENAI_API_KEY ? `guard: ${cfg.model}` : "guard: rules only");
  }

  function restoreState(ctx: ExtensionContext) {
    store.syncSession(ctx.sessionManager.getBranch() as any[]);
    enabled = true;
    for (const e of ctx.sessionManager.getBranch() as any[]) if (e.type === "custom" && e.customType === STATE_ENTRY) enabled = e.data?.enabled !== false;
    updateStatus(ctx);
  }

  pi.on("session_start", async (_e, ctx) => {
    stopPreflight();
    stateEpoch++;
    registeredSkillTargets.clear();
    snapshotRegisteredSkills();
    const loaded = loadConfig();
    cfg = loaded;
    trusted = ctx.isProjectTrusted();
    storeCwd = ctx.cwd;
    store.load(storeCwd, trusted);
    store.resetSession();
    modelMemo.clear(); siblingsById.clear(); judged.clear(); touched.clear(); promoted.clear(); verdictCache.clear(); blockedOnce.clear();
    opaqueChanges = false;
    consecutiveBlocks = totalBlocks = 0;
    for (const w of [...loaded.warnings, ...store.warnings]) warn(ctx, `guard: ${w}`);
    restoreState(ctx);
    if (!cfg.disabled && !process.env.GUARD_OPENAI_API_KEY)
      warn(ctx, "guard: GUARD_OPENAI_API_KEY is not set. Running in rules-only mode: calls that need a model judgement will ask you first.");
  });

  // Pi may bind its command registry after session_start.
  pi.on("before_agent_start", () => { snapshotRegisteredSkills(); });

  // Rewinding with /tree changes which session rules and on/off state apply
  pi.on("session_tree", async (_e, ctx) => {
    stopPreflight();
    stateEpoch++;
    modelMemo.clear();
    siblingsById.clear();
    verdictCache.clear();
    blockedOnce.clear();
    store.resetSession();
    promoted.clear();
    restoreState(ctx);
  });

  // Start judging every tool call of an assistant message in parallel as soon as the message ends
  // (pi preflights sibling calls one by one, which would otherwise add up the latency).
  pi.on("message_end", async (event, ctx) => {
    if (cfg.disabled || !enabled) return;
    const m: any = event.message;
    if (m?.role !== "assistant" || !Array.isArray(m.content)) return;
    // A provider may reuse an ID in a later message; no preflight belongs to two messages.
    stopPreflight();
    stateEpoch++;
    modelMemo.clear();
    siblingsById.clear();
    const historyBoundary = ctx.sessionManager.getBranch().length;
    const calls: ToolCallLike[] = m.content.filter((c: any) => c?.type === "toolCall").map((c: any) => ({ id: c.id, name: c.name, arguments: c.arguments }));
    if (!calls.length) return;
    const problem = batchProblem(calls);
    if (problem) {
      const invalid = { earlier: [], peers: [], historyBoundary, problem };
      for (const c of calls) siblingsById.set(c.id, invalid);
      return;
    }
    // Synchronize trust and project state before creating the controller, so this message's
    // own preflight cannot cancel itself when Pi's context changes after session_start.
    syncProject(ctx);
    preflightController = new AbortController();
    const preflightSignal = ctx.signal ? AbortSignal.any([ctx.signal, preflightController.signal]) : preflightController.signal;
    const skillPaths = registeredSkillPaths();
    calls.forEach((c, i) => {
      if (siblingsById.has(c.id) || isSkillRead(c.name, c.arguments, ctx.cwd, skillPaths) || trustedByExtension(c.name)) return;
      const siblings = calls.slice(0, i);
      const peers = calls.filter((_, j) => j !== i);
      siblingsById.set(c.id, { earlier: siblings, peers, historyBoundary });
      // Bound speculative work; later calls are assessed normally when Pi reaches tool_call.
      if (i < MAX_PREFLIGHT_CALLS) assess(c.id, c.name, c.arguments, ctx, { signal: preflightSignal, siblings, peers, historyBoundary }).catch(() => {});
    });
  });

  pi.on("agent_end", async () => {
    stopPreflight();
    stateEpoch++;
    modelMemo.clear();
    siblingsById.clear();
  });

  pi.on("tool_call", async (event, ctx) => {
    // Providers may reuse an ID; a blocked or disabled call must not inherit
    // drift tracking from an earlier allowed call with that ID.
    judged.delete(event.toolCallId);
    if (cfg.disabled || !enabled) return;
    if (isSkillRead(event.toolName, event.input, ctx.cwd, registeredSkillPaths())) return;
    const tool = event.toolName;
    const input: any = event.input;
    const onBlocked = (reason: string, retry: "ask-user" | "none" = "none") => {
      consecutiveBlocks++;
      totalBlocks++;
      if (consecutiveBlocks >= cfg.escalateConsecutive || totalBlocks >= cfg.escalateTotal) {
        const message = `guard: too many blocked calls (${consecutiveBlocks} in a row, ${totalBlocks} total). Stopped the agent.`;
        if (ctx.hasUI) { try { ctx.ui.notify(message, "error"); } catch { /* notification failure must not prevent stopping */ } }
        else warn(ctx, message);
        consecutiveBlocks = 0;
        try { ctx.abort(); } catch { /* the current call must still be blocked */ }
        return { ...blockResult(reason, retry), terminate: true };
      }
      return blockResult(reason, retry);
    };
    let session: string;
    try {
      session = ctx.sessionManager.getSessionId();
      if (typeof session !== "string" || !session) throw new Error("invalid session id");
    }
    catch {
      recordAudit(ctx, { tool, preview: `${tool} [arguments withheld: session unavailable]`, action: "block", source: "error", reasons: ["session context unavailable"], final: "blocked" });
      return onBlocked("session context unavailable");
    }
    let vouched: string | undefined;
    let trustAvailable = false;
    // Project trust may have changed since the last event. If it cannot be
    // refreshed, continue through the guarded path instead of taking a shortcut.
    try { syncProject(ctx); trustAvailable = true; vouched = trustedByExtension(tool); } catch { /* assess will fail closed */ }
    if (vouched) {
      siblingsById.delete(event.toolCallId);
      recordAudit(ctx, { session, tool, preview: auditPreview(ctx, tool, input), action: "allow", source: "extension", reasons: [`trusted by ${vouched}`], final: "run" });
      return;
    }
    let hash: string;
    try { hash = toolInputHash(tool, input); }
    catch {
      recordAudit(ctx, { session, tool, preview: `${tool} [arguments withheld: input could not be inspected]`, action: "block", source: "error", reasons: ["tool input could not be inspected"], final: "blocked" });
      return onBlocked("the tool input could not be inspected");
    }
    let batch: BatchContext;
    try { batch = siblingsById.get(event.toolCallId) ?? siblingsFromBranch(ctx, event.toolCallId); }
    catch {
      recordAudit(ctx, { session, tool, preview: `${tool} [arguments withheld: session history unavailable]`, action: "block", source: "error", reasons: ["session history unavailable"], final: "blocked" });
      return onBlocked("session history unavailable");
    }
    if (!batch.problem) siblingsById.delete(event.toolCallId);

    status(ctx, `guard: judging ${tool}…`);
    let a: Assessment;
    try {
      // Deterministic checks always run on the current state; a model verdict started at message_end is reused
      // only if the input, attachments and past decisions it was based on are unchanged
      a = batch.problem
        ? { action: "block", source: "error", reasons: [batch.problem], rememberAllow: false, globalAllow: false }
        : await assess(event.toolCallId, tool, input, ctx, { signal: ctx.signal, siblings: batch.earlier, peers: batch.peers, historyBoundary: batch.historyBoundary });
    } catch (error) {
      // Context and extension errors can contain credentials or file contents.
      const rulesScope = error instanceof Error ? /(?:^|; )cannot read (global|project|repository) rules \(/.exec(error.message)?.[1] : undefined;
      const reason = rulesScope ? `cannot read ${rulesScope} rules` : "could not judge: context unavailable";
      a = { action: "confirm", source: "error", reasons: [reason], rememberAllow: false, globalAllow: false };
    }
    let inputChanged = true;
    try { inputChanged = toolInputHash(tool, input) !== hash; } catch { /* treat uninspectable input as changed */ }
    const judgementAborted = !!ctx.signal?.aborted;
    if (judgementAborted) a = { action: "block", source: "error", reasons: ["judgement was aborted"], rememberAllow: false, globalAllow: false };
    else if (inputChanged) a = { action: "block", source: "error", reasons: ["input changed during judgement"], rememberAllow: false, globalAllow: false };
    let retryRulesVersion: number | undefined;
    try {
      store.syncSession(ctx.sessionManager.getBranch() as any[]);
      store.all();
      if (!store.hasErrors) retryRulesVersion = store.version;
    } catch { /* no retry shortcut when rules cannot be refreshed */ }
    const retryKey = stableHash([hash, ctx.cwd, trustAvailable ? trusted : "unavailable", session, trustedDirs.version, retryRulesVersion]);
    const what = inputChanged || judgementAborted || batch.problem ? `${tool} [arguments withheld: input could not be inspected]` : preview(tool, input);
    const risk = a.verdict?.risk;
    const tag = `${a.source}${risk !== undefined ? ` ${risk.toFixed(1)}` : ""}${a.verdict?.category ? ` ${a.verdict.category}` : ""}`;
    const shellChangedDuringJudgement = a.source === "error" && a.reasons[0] === "shell environment or executable lookup changed during judgement";
    const contextChangedDuringJudgement = a.source === "error" && a.reasons[0] === "judgement context changed during judgement";
    const policyChangedDuringJudgement = a.source === "error" && a.reasons[0] === "filesystem policy changed during judgement";
    const rec = { session, tool, preview: judgementAborted ? `${tool} [arguments withheld: judgement was aborted]` : inputChanged ? `${tool} [arguments withheld: input changed during judgement]` : batch.problem ? `${tool} [arguments withheld: invalid tool batch]` : shellChangedDuringJudgement ? `${tool} [arguments withheld: shell environment changed during judgement]` : contextChangedDuringJudgement ? `${tool} [arguments withheld: judgement context changed]` : policyChangedDuringJudgement ? `${tool} [arguments withheld: filesystem policy changed]` : auditPreview(ctx, tool, input), action: a.action, source: a.source, reasons: a.auditReasons ?? a.reasons, risk, ruleIds: a.rules?.map((r) => r.id) };

    const onAllowed = () => {
      judged.set(event.toolCallId, { hash, session });
      consecutiveBlocks = 0;
      // Files this call changes; running them later attaches their new contents
      try {
        if (changesTrees({ id: "", name: tool, arguments: input })) opaqueChanges = true;
        const parsedNow = tool === "bash" ? parseShell(String(input?.command ?? "")) : undefined;
        if (tool === "edit" || tool === "write" || tool === "bash") for (const p of inputPaths(tool, input, ctx.cwd, parsedNow).writes) touched.add(p);
      } catch {
        // The approved call may still change files, even if tracking failed.
        // Force later script runners through full judgement instead of shortcuts.
        opaqueChanges = true;
      }
      if (a.rules && a.source === "rule-allow") {
        store.hit(a.rules);
        for (const r of a.rules) {
          if (r.scope === "session" && store.hitCount(r.id) >= 3 && !promoted.has(r.id)) {
            try {
              ctx.ui.notify(displayText(`guard: "${describeMatch(r.tool, r.match)}" was allowed ${store.hitCount(r.id)} times this session. Remember it for this project with /guard rules promote ${r.id} project`), "info");
              promoted.add(r.id);
            } catch { /* notification failure must not affect an allowed call */ }
          }
        }
      }
    };
    const onCancelled = (reason: string) => {
      consecutiveBlocks = 0;
      status(ctx, `guard: ${tool} cancelled`);
      return blockResult(reason);
    };

    // A repeated model or hard-deny block can be approved once, with the same
    // context and policy rechecks used for every other confirmation.
    const retryOverride = retryRulesVersion !== undefined && a.action === "block" && (a.source === "hard-deny" || a.source === "model") && blockedOnce.has(retryKey) && ctx.hasUI;
    if (retryOverride) {
      blockedOnce.delete(retryKey);
      a = { ...a, action: "confirm", rememberAllow: false, globalAllow: false, patterns: undefined };
    }

    if (a.action === "allow") {
      status(ctx, `guard: ${tool} ok (${tag})`);
      recordAudit(ctx, { ...rec, final: "run" });
      onAllowed();
      return;
    }
    if (a.action === "block") {
      if (judgementAborted) {
        recordAudit(ctx, { ...rec, final: "blocked" });
        return onCancelled("judgement was aborted");
      }
      status(ctx, `guard: ${tool} BLOCKED (${tag})`);
      try { ctx.ui.notify(displayText(`guard: blocked ${tool} — ${a.reasons.join("; ")}`), "error"); } catch { /* notification failure must not prevent blocking */ }
      recordAudit(ctx, { ...rec, final: "blocked" });
      if (retryRulesVersion !== undefined && (a.source === "hard-deny" || a.source === "model") && ctx.hasUI) {
        blockedOnce.delete(retryKey);
        if (blockedOnce.size >= MAX_BLOCKED_RETRIES) blockedOnce.delete(blockedOnce.values().next().value!);
        blockedOnce.add(retryKey);
      } else blockedOnce.delete(retryKey);
      return onBlocked(inputChanged ? "the input changed during judgement" : batch.problem ? batch.problem : shellChangedDuringJudgement ? "the shell environment or executable lookup changed during judgement" : contextChangedDuringJudgement ? "the judgement context changed during judgement" : policyChangedDuringJudgement ? "the filesystem policy changed during judgement" : a.source === "error" && a.reasons[0] === "session changed during judgement" ? "the session changed during judgement" : a.source === "hard-deny" ? `blocked (${a.reasons[0]})` : a.source === "rule-deny" ? "blocked by the user's deny rule" : "blocked as too dangerous", retryRulesVersion !== undefined && (a.source === "hard-deny" || a.source === "model") && ctx.hasUI ? "ask-user" : "none");
    }

    status(ctx, `guard: ${tool} needs confirmation (${tag})`);
    if (!ctx.hasUI) {
      recordAudit(ctx, { ...rec, final: "blocked", choice: "no-ui" });
      return onBlocked("this call needs the user's confirmation, but no UI is available");
    }
    const v = a.verdict;
    const head = `${retryOverride ? "Previously blocked — " : ""}${tool}: ${v?.risk !== undefined ? `risk ${v.risk.toFixed(2)}/4` : "confirm"}${v?.category ? ` [${v.category}]` : ""}`;
    const dialogEpoch = stateEpoch;
    const dialogConfig = cfg;
    const dialogCwd = ctx.cwd;
    let dialogTrusted: boolean;
    const dialogShellEnvironment = tool === "bash" ? shellEnvironmentHash() : undefined;
    let dialogExecutable: ReturnType<typeof inspectExecutablePath> | undefined;
    let dialogContextHash: string;
    let dialogPolicyHash: string;
    try {
      dialogTrusted = ctx.isProjectTrusted();
      const dialogParsed = tool === "bash" ? parseShell(String(input?.command ?? "")) : undefined;
      clearPathCache();
      dialogContextHash = stableHash(context(ctx, event.toolCallId, tool, dialogParsed, batch.earlier, batch.peers, batch.historyBoundary));
      dialogPolicyHash = filesystemPolicyHash(tool, input, ctx.cwd, ctx.sessionManager.getSessionDir(), trustedDirs, dialogParsed);
      if (dialogParsed) dialogExecutable = inspectExecutablePath(dialogParsed, ctx.cwd);
    } catch {
      recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: confirmation context could not be inspected]`, action: "block", source: "error", reasons: ["could not inspect context before confirmation"], final: "blocked" });
      return onBlocked("could not inspect context before confirmation");
    }
    let choice: Awaited<ReturnType<typeof confirmDialog>>;
    try {
      choice = await confirmDialog(ctx, {
      title: head,
      body: `${what}\n\nWhy: ${a.reasons.join("; ") || "-"}`,
      tool,
      patterns: a.patterns,
      denyPatterns: a.denyPatterns,
      rememberAllow: a.rememberAllow,
      globalAllow: a.globalAllow,
      projectName: basename(ctx.cwd),
      timeoutMs: cfg.dialogTimeoutMs,
      });
    } catch {
      if (ctx.signal?.aborted) {
        recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: confirmation was aborted]`, action: "block", source: "error", reasons: ["confirmation was aborted"], final: "blocked" });
        return onCancelled("confirmation was aborted");
      }
      warn(ctx, "guard: approval dialog failed");
      recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: approval dialog failed]`, final: "blocked", choice: "dialog-error" });
      return onBlocked("the approval dialog failed");
    }
    if (ctx.signal?.aborted) {
      recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: confirmation was aborted]`, action: "block", source: "error", reasons: ["confirmation was aborted"], final: "blocked" });
      return onCancelled("confirmation was aborted");
    }
    if (stateEpoch !== dialogEpoch) {
      recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: session changed during confirmation]`, action: "block", source: "error", reasons: ["session changed during confirmation"], final: "blocked" });
      return onBlocked("the session changed during confirmation");
    }
    if (cfg !== dialogConfig) {
      recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: settings changed during confirmation]`, action: "block", source: "error", reasons: ["settings changed during confirmation"], final: "blocked" });
      return onBlocked("the settings changed during confirmation");
    }
    let trustAfterDialog: boolean;
    try { trustAfterDialog = ctx.isProjectTrusted(); }
    catch {
      recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: project trust could not be inspected]`, action: "block", source: "error", reasons: ["could not inspect project trust after confirmation"], final: "blocked" });
      return onBlocked("could not inspect project trust after confirmation");
    }
    if (ctx.cwd !== dialogCwd || trustAfterDialog !== dialogTrusted) {
      recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: project changed during confirmation]`, action: "block", source: "error", reasons: ["project or trust changed during confirmation"], final: "blocked" });
      return onBlocked("the project or trust changed during confirmation");
    }
    try {
      clearPathCache();
      rec.preview = toolInputHash(tool, input) === hash ? auditPreview(ctx, tool, input) : `${tool} [arguments withheld: input changed during confirmation]`;
    } catch {
      rec.preview = `${tool} [arguments withheld: input could not be inspected]`;
    }
    if (choice.decision === "allow") {
      try {
        if (toolInputHash(tool, input) !== hash) {
          recordAudit(ctx, { ...rec, action: "block", source: "error", reasons: ["input changed during confirmation"], final: "blocked" });
          return onBlocked("the input changed during confirmation");
        }
        if (dialogShellEnvironment !== undefined && shellEnvironmentHash() !== dialogShellEnvironment) {
          recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: shell environment changed during confirmation]`, action: "block", source: "error", reasons: ["shell environment changed during confirmation"], final: "blocked" });
          return onBlocked("shell environment changed during confirmation");
        }
        clearPathCache();
        const currentParsed = tool === "bash" ? parseShell(String(input?.command ?? "")) : undefined;
        if (stableHash(context(ctx, event.toolCallId, tool, currentParsed, batch.earlier, batch.peers, batch.historyBoundary)) !== dialogContextHash) {
          recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: confirmation context changed]`, action: "block", source: "error", reasons: ["judgement context changed during confirmation"], final: "blocked" });
          return onBlocked("judgement context changed during confirmation");
        }
        const currentExecutable = currentParsed ? inspectExecutablePath(currentParsed, ctx.cwd) : undefined;
        if ((currentExecutable?.risk && currentExecutable.risk !== dialogExecutable?.risk) ||
            (dialogExecutable?.fingerprint !== undefined && currentExecutable?.fingerprint !== dialogExecutable.fingerprint)) {
          recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: executable lookup changed during confirmation]`, action: "block", source: "error", reasons: ["executable lookup changed during confirmation"], final: "blocked" });
          return onBlocked("executable lookup changed during confirmation");
        }
        const hard = hardDeny(tool, input, ctx.cwd, protectedRoots(ctx.cwd, ctx.sessionManager.getSessionDir()), currentParsed);
        syncProject(ctx);
        store.syncSession(ctx.sessionManager.getBranch() as any[]);
        const currentRule = store.find(tool, input, ctx.cwd, currentParsed);
        const changedHardDeny = hard && !(retryOverride && a.source === "hard-deny" && hard === a.reasons[0]) ? hard : undefined;
        if (changedHardDeny || currentRule?.decision === "deny") {
          recordAudit(ctx, { ...rec, action: "block", source: changedHardDeny ? "hard-deny" : "rule-deny", reasons: [changedHardDeny || "deny rule applied after confirmation"], ruleIds: changedHardDeny ? undefined : currentRule?.rules.map((rule) => rule.id), final: "blocked" });
          return onBlocked(changedHardDeny ? `blocked (${changedHardDeny})` : "blocked by the user's deny rule");
        }
        if (filesystemPolicyHash(tool, input, ctx.cwd, ctx.sessionManager.getSessionDir(), trustedDirs, currentParsed) !== dialogPolicyHash) {
          recordAudit(ctx, { ...rec, preview: `${tool} [arguments withheld: filesystem policy changed during confirmation]`, action: "block", source: "error", reasons: ["filesystem policy changed during confirmation"], final: "blocked" });
          return onBlocked("filesystem policy changed during confirmation");
        }
      } catch {
        recordAudit(ctx, { ...rec, action: "block", source: "error", reasons: ["could not recheck after confirmation"], final: "blocked" });
        return onBlocked("could not recheck this call after confirmation");
      }
    }
    const saved: Rule[] = [];
    const toSave = choice.decision === "deny" ? a.denyPatterns : a.patterns;
    if (choice.scope !== "once" && toSave) {
      try {
        for (const m of toSave) saved.push(addRule(choice.decision, choice.scope, tool, m, ctx.cwd, v?.risk, choice.reason));
      } catch (e: any) {
        warn(ctx, `guard: could not save all ${choice.decision} rules: ${e?.message ?? String(e)}. This decision still applies to the current call.`);
      }
    }
    if (saved.length) {
      try { ctx.ui.notify(displayText(`guard: saved ${choice.scope} ${choice.decision} rule: ${saved.map((r) => `${describeMatch(r.tool, r.match)} [${r.id}]`).join(", ")} (undo: /guard rules rm <id>)`), "info"); } catch { /* notification failure must not affect the decision */ }
    }
    recordAudit(ctx, { ...rec, ...(retryOverride ? { event: "override" as const } : {}), final: choice.decision === "allow" ? "run" : "blocked", choice: `${choice.decision}:${choice.scope}`, ruleIds: [...(rec.ruleIds ?? []), ...saved.map((r) => r.id)] });

    if (choice.decision === "allow") {
      onAllowed();
      return;
    }
    consecutiveBlocks = 0; // the user's own denials do not count towards escalation
    return blockResult(choice.reason ? `the user denied this call: ${choice.reason}` : "the user denied this call");
  });

  // Detect input that changed after guard judged it (an extension loaded after guard rewrote it)
  pi.on("tool_result", async (event, ctx) => {
    const previous = judged.get(event.toolCallId);
    judged.delete(event.toolCallId);
    if (!previous) return;
    let inspectable = true;
    try { if (previous.hash === toolInputHash(event.toolName, event.input)) return; } catch { inspectable = false; }
    const auditText = inspectable ? auditPreview(ctx, event.toolName, event.input) : `${event.toolName} [arguments withheld: input could not be inspected]`;
    recordAudit(ctx, { session: previous.session, tool: event.toolName, preview: auditText, action: "allow", source: "drift", reasons: ["input changed after judgement"], event: "drift" });
    warn(ctx, `guard: the input of ${event.toolName} was changed by another extension after guard judged it. Load guard last.`);
  });

  pi.on("tool_execution_end", async (event) => {
    judged.delete(event.toolCallId);
  });

  pi.registerCommand("guard", {
    description: "Tool-call guard: /guard [on|off|check <cmd>|rules [rm|promote|add]|log [n]|reload]",
    handler: async (args, ctx) => {
      const [sub, ...rest] = (args ?? "").trim().split(/\s+/).filter(Boolean);
      const say = (m: string, t: "info" | "warning" | "error" = "info") => ctx.ui.notify(displayText(m), t);
      syncProject(ctx);

      if (!sub) {
        const all = store.all();
        const count = (s: Scope) => all.filter((r) => r.scope === s).length;
        return say(
          `guard: ${cfg.disabled ? "disabled" : enabled ? "on" : "off"} | model=${cfg.model} key=${process.env.GUARD_OPENAI_API_KEY ? "set" : "unset"} trusted=${trusted} | ` +
          `rules: session ${count("session")} / project ${count("project")} / global ${count("global")} / repo ${count("repo")} | audit=${auditState}${auditRecoveryPending ? " (recovery notice pending)" : ""} | blocks ${totalBlocks}`,
        );
      }
      if (sub === "on" || sub === "off") {
        if (rest.length) return say("usage: /guard on|off", "warning");
        blockedOnce.clear();
        enabled = sub === "on";
        append(STATE_ENTRY, { enabled });
        restoreState(ctx);
        if (enabled && cfg.disabled) return say("guard: on for this session, but disabled by configuration", "warning");
        return say(`guard: ${sub} for this session`);
      }
      if (sub === "reload") {
        if (rest.length) return say("usage: /guard reload", "warning");
        stopPreflight();
        const loaded = loadConfig();
        cfg = loaded;
        trusted = ctx.isProjectTrusted();
        storeCwd = ctx.cwd;
        store.load(storeCwd, trusted);
        modelMemo.clear();
        verdictCache.clear();
        blockedOnce.clear();
        updateStatus(ctx);
        for (const w of [...loaded.warnings, ...store.warnings]) say(`guard: ${w}`, "warning");
        return say("guard: reloaded settings and rules");
      }
      if (sub === "log") {
        const n = Number(rest[0] ?? 15);
        if (rest.length > 1 || !Number.isSafeInteger(n) || n < 1 || n > 1000) return say("usage: /guard log [1..1000]", "warning");
        const lines = tail(n).map((r) => `${r.ts?.slice(5, 19).replace("T", " ")} ${r.final ?? r.event ?? ""} ${r.source}${r.choice ? `→${r.choice}` : ""} ${r.preview.split("\n")[0].slice(0, 80)}${r.reasons.length ? ` — ${r.reasons.join("; ").slice(0, 120)}` : ""}`);
        if (auditState === "failed") return say(`guard: audit log unavailable; recent decisions may be missing${lines.length ? `\n${lines.join("\n")}` : ""}`, "warning");
        if (auditRecoveryPending) return say(`guard: audit logging recovered; some decisions may be missing${lines.length ? `\n${lines.join("\n")}` : ""}`, "warning");
        return say(lines.length ? lines.join("\n") : "guard: the audit log is empty");
      }
      if (sub === "rules") {
        const op = rest[0] ?? "list";
        if (op === "list") {
          if (rest.length > 1) return say("usage: /guard rules list", "warning");
          const order: Scope[] = ["session", "repo", "project", "global"];
          const lines = [
            ...[...extensionTrust.keys()].map((tool) => {
              const why = trustProblem(tool);
              return displayText(`[extension] allow tool ${tool}  (trusted by ${extensionTrust.get(tool)}${why ? `; ignored: ${why}` : ""})`).replace(/\n/g, "\\n");
            }),
            ...listTrustedDirs(trustedDirs).map((dir) => displayText(`[extension] ${dir.write ? "read/write" : "read"} folder ${dir.path}  (trusted by ${dir.by}${dir.ignored ? `; ignored: ${dir.ignored}` : ""})`).replace(/\n/g, "\\n")),
            ...store.all().sort((a, b) => order.indexOf(a.scope) - order.indexOf(b.scope))
              .map((r) => displayText(`[${r.scope}] ${r.decision.padEnd(5)} ${describeMatch(r.tool, r.match)}  (id ${r.id}, hits ${store.hitCount(r.id)}${r.decision === "allow" && r.expiresAt ? `, expires ${r.expiresAt.slice(0, 10)}` : ""})`).replace(/\n/g, "\\n")),
          ];
          if (!lines.length) return say("guard: no rules, and no tools or folders vouched for by extensions (guard:trust-tool / guard:trust-dir)");
          if (!ctx.hasUI) return say(lines.join("\n"));
          const pick = await ctx.ui.select("Rules (select one to delete it)", [...lines, "Close"]);
          const id = pick?.match(/\(id ([^,)]+)/)?.[1];
          if (!id) return;
          if (id.startsWith("repo-")) return say("guard: edit .pi/guard.json to change repository rules", "warning");
          if (await ctx.ui.confirm("Delete rule", pick!)) {
            store.remove(id, append);
            say(`guard: deleted rule ${id}`);
          }
          return;
        }
        if (op === "rm") {
          if (rest.length !== 2) return say("usage: /guard rules rm <id>", "warning");
          const r = store.remove(rest[1], append);
          return r ? say(`guard: deleted ${describeMatch(r.tool, r.match)}`) : say("guard: no rule with that id", "warning");
        }
        if (op === "promote") {
          const [id, to] = [rest[1], rest[2]];
          if (rest.length !== 3) return say("usage: /guard rules promote <id> project|global", "warning");
          const r = store.all().find((x) => x.id === id);
          if (!r || (to !== "project" && to !== "global")) return say("usage: /guard rules promote <id> project|global", "warning");
          const globalAllow = to === "global" && r.decision === "allow";
          // Global allows apply in every trusted project: only read-only commands, and only with the human confirming
          if (globalAllow && !globalAllowPatternIsReadOnly(r.tool, r.match))
            return say("guard: only read-only commands can become global allow rules", "warning");
          if (globalAllow && !ctx.hasUI) return say("guard: promoting to a global allow rule needs the interactive UI", "warning");
          const warn = globalAllow ? " Global allow rules apply in every trusted project." : "";
          if (ctx.hasUI && !(await ctx.ui.confirm("Promote rule", displayText(`Save ${describeMatch(r.tool, r.match)} as a ${to} rule?${warn}`)))) return;
          const nr = addRule(r.decision, to, r.tool, r.match, ctx.cwd, r.risk, r.note);
          if (r.scope === "session") store.remove(r.id, append);
          return say(`guard: saved as ${to} rule [${nr.id}]`);
        }
        if (op === "add") {
          const [decision, scope, ...pat] = rest.slice(1);
          if (!["allow", "deny", "ask"].includes(decision) || !["session", "project", "global"].includes(scope) || !pat.length)
            return say("usage: /guard rules add <allow|deny|ask> <session|project|global> <command words… | tool:<name> | path:<path> [tool]>", "warning");
          if (decision === "ask" && scope === "session") return say("guard: ask rules can only be project or global", "warning");
          let tool = "bash";
          let match: Match;
          if (pat[0].startsWith("tool:")) {
            if (!pat[0].slice(5) || pat.length !== 1) return say("guard: invalid rule; use tool:<name> without extra arguments", "warning");
            tool = pat[0].slice(5); match = { kind: "tool" };
          } else if (pat[0].startsWith("path:")) {
            if (!pat[0].slice(5) || pat.length > 2) return say("guard: invalid rule; use path:<path> followed by an optional tool name", "warning");
            tool = pat[1] ?? "edit"; match = { kind: "path", path: resolvePath(ctx.cwd, pat[0].slice(5)) };
          }
          else {
            const patternText = (args ?? "").trim().match(/^rules\s+add\s+\S+\s+\S+\s+([\s\S]+)$/)?.[1] ?? "";
            const parsed = parseShell(patternText);
            if (!parsed.ok || parsed.dynamic.length || parsed.subcommands.length !== 1 || parsed.writes.length || parsed.globs.length || parsed.subs.some((sub) => sub.reads.length || sub.heredocs.length))
              return say("guard: invalid rule; use one static command without redirects or wildcards", "warning");
            const normalized = normalizeArgv(parsed.subcommands[0], decision === "allow" ? "allow" : "deny");
            if (decision === "allow" && normalized.unknownOption)
              return say("guard: invalid allow rule; location or unrecognized options cannot be approved by a rule", "warning");
            const allowPattern = decision === "allow" ? derivePatterns("bash", { command: patternText }, ctx.cwd, parsed)?.[0] : undefined;
            match = allowPattern?.kind === "argv-exact"
              ? { kind: "argv-exact", argv: normalized.argv }
              : { kind: "argv", prefix: normalized.argv };
          }
          if (decision === "allow" && match.kind === "tool" && !supportsAnyInputAllow(tool))
            return say("guard: this tool cannot use an any-input allow rule; use a command or path rule where supported", "warning");
          if (decision === "allow" && scope === "global" && !globalAllowPatternIsReadOnly(tool, match))
            return say("guard: only read-only commands can become global allow rules", "warning");
          try {
            const r = addRule(decision as Decision, scope as "session" | "project" | "global", tool, match, ctx.cwd);
            return say(`guard: added ${scope} ${decision} rule: ${describeMatch(tool, match)} [${r.id}]`);
          } catch (e: any) {
            return say(`guard: could not add rule: ${e?.message ?? String(e)}`, "warning");
          }
        }
        return say("usage: /guard rules [list|rm <id>|promote <id> project|global|add …]", "warning");
      }
      // Anything else is scored as a bash command without running it (/guard check <cmd> or /guard <cmd>)
      const raw = (args ?? "").trim();
      const cmd = sub === "check" ? raw.replace(/^check(?:\s+|$)/, "") : raw;
      if (!cmd) return say("usage: /guard check <command>", "warning");
      const a = await assess(`guard-check-${Date.now()}`, "bash", { command: cmd }, ctx);
      const v = a.verdict;
      say(
        `${a.action.toUpperCase()} via ${a.source}${v?.risk !== undefined ? ` | risk ${v.risk.toFixed(2)} pHigh ${v.pHigh?.toFixed(2)} conf ${v.confidence?.toFixed(2)} ${v.category ?? ""}` : ""}` +
          `${a.reasons.length ? `\n${a.reasons.join("; ")}` : ""}`,
        a.action === "allow" ? "info" : a.action === "confirm" ? "warning" : "error",
      );
    },
  });
}
