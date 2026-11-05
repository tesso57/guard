/**
 * guard — judges the risk of every pi tool call before it runs.
 *
 * Evaluation order:
 *   1. hard deny (protected paths, obvious destruction)          → block (cannot be overridden)
 *   2. deny / ask rules (any scope)                               → block / confirm
 *   3. allow rule matching every subcommand                       → light model check (exfiltration, intent, judge manipulation)
 *   4. sensitive paths                                            → confirm
 *   5. safe list (read-only bash, plain edits inside the project) → allow without the model
 *   6. skipModelTools (read/grep/find/ls)                         → allow
 *   7. Decisions API with intent, history and past decisions      → allow / confirm / block
 *   Failures confirm (or block without a UI). Without GUARD_OPENAI_API_KEY guard runs in rules-only mode.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, relative } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { audit, tail } from "./audit.ts";
import { type Config, loadConfig } from "./config.ts";
import { buildRequest, callDecisions, evaluate, type ModelVerdict } from "./judge.ts";
import { clearPathCache, isFreelyReadable, isInside, protectedReason, protectedRoots, recentlyChangedFiles, resolvePath, sensitiveReason } from "./paths.ts";
import { hardDeny, inputPaths, pathsStayInProject, safeAllow, sensitive, writesStayPlain } from "./policy.ts";
import { type Decision, deriveDenyPatterns, derivePatterns, describeMatch, type Match, newId, type Rule, RuleStore, type Scope } from "./rules.ts";
import { isReadOnlyArgv, normalizeArgv, type Parsed, parseShell } from "./shell.ts";
import { confirmDialog, preview } from "./ui.ts";

const STATE_ENTRY = "guard-state";
/** Commands that run project scripts, tests or build files, which an earlier edit may have changed. */
const SCRIPT_RUNNERS = new Set([
  "npm", "pnpm", "yarn", "bun", "npx", "make", "gmake", "just", "pytest", "tox", "nox", "cargo", "go", "gradle", "gradlew", "mvn", "rake", "bundle",
  "deno", "uv", "poetry", "turbo", "nx", "jest", "vitest", "pre-commit", "docker", "docker-compose",
  // Interpreters load project code too (python -m pytest, node --test, sh script.sh)
  "python", "python3", "node", "ruby", "perl", "php", "sh", "bash", "zsh",
]);
const MAX_CACHE = 500;

type ToolCallLike = { id: string; name: string; arguments: any };

type Assessment = {
  action: "allow" | "confirm" | "block";
  source: "hard-deny" | "rule-deny" | "rule-ask" | "rule-allow" | "sensitive" | "safe" | "skip" | "model" | "cache" | "error";
  reasons: string[];
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

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.filter((c: any) => c?.type === "text").map((c: any) => c.text).join("\n");
  return "";
}

/** Applies an edit tool call to file contents (first occurrence of each oldText), to see what the file will contain. */
function applyEdits(content: string, input: any): string {
  // pi accepts `edits` as an array or a JSON string, plus a legacy top-level oldText/newText pair
  let list: any = input?.edits;
  if (typeof list === "string") {
    try { list = JSON.parse(list); } catch { list = []; }
  }
  const edits = [...(Array.isArray(list) ? list : []), ...(input?.oldText !== undefined ? [input] : [])];
  let out = content;
  for (const e of edits) if (typeof e?.oldText === "string" && typeof e?.newText === "string") out = out.replace(e.oldText, () => e.newText);
  return out;
}

const TREE_GIT = new Set(["checkout", "switch", "merge", "pull", "reset", "stash", "apply", "am", "rebase", "cherry-pick", "clone", "worktree", "restore", "revert", "submodule", "read-tree"]);
const TREE_TOOLS = new Set(["tar", "unzip", "7z", "bsdtar", "rsync", "cp", "mv", "ln", "patch", "curl", "wget", "git-lfs"]);
/** Package-manager subcommands that replace dependency trees (and their bin links). */
const PM_TREE = new Set(["install", "i", "ci", "add", "update", "upgrade", "up", "remove", "rm", "uninstall", "rebuild", "link", "sync", "dedupe", "prune"]);
const PACKAGE_MANAGERS = new Set(["npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "go", "gem", "bundle", "composer"]);

/** Calls that may replace or add many files at once (and so create symlinks guard has not seen). */
function changesTrees(c: ToolCallLike): boolean {
  if (c.name !== "bash") return false;
  const p = parseShell(String(c.arguments?.command ?? ""));
  if (!p.ok || p.dynamic.length) return true;
  return p.subcommands.some((raw) => {
    const a = normalizeArgv(raw, "deny").argv;
    const sub = a.find((t, i) => i > 0 && !t.startsWith("-")) ?? "";
    // Creating a branch from the current HEAD (checkout -b, switch -c) leaves the files as they are
    const newBranchOnly = a[0] === "git" && ((sub === "checkout" && a.some((t) => t === "-b" || t === "-B") && nonFlagsAfter(a, sub).length <= 1) || (sub === "switch" && a.some((t) => t === "-c" || t === "-C") && nonFlagsAfter(a, sub).length <= 1));
    return TREE_TOOLS.has(a[0]) || (a[0] === "git" && TREE_GIT.has(sub) && !newBranchOnly) || (PACKAGE_MANAGERS.has(a[0]) && PM_TREE.has(sub));
  });
}

function nonFlagsAfter(a: string[], word: string): string[] {
  return a.slice(a.indexOf(word) + 1).filter((t) => !t.startsWith("-"));
}

/** Whether the call writes anything (tools that write, or bash that is not strictly read-only). */
function callWrites(tool: string, input: any, cwd: string, parsed?: Parsed): boolean {
  if (tool === "write" || tool === "edit") return true;
  if (tool !== "bash") return !["read", "grep", "find", "ls"].includes(tool);
  if (!parsed || !parsed.ok || parsed.dynamic.length) return true;
  return parsed.writes.length > 0 || !parsed.subcommands.every(isReadOnlyArgv) || inputPaths(tool, input, cwd, parsed).writes.length > 0;
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

/** Plain edits of ordinary project files and mkdir/touch: they cannot create links or reach outside the project. */
function isPlainChange(c: ToolCallLike, cwd: string): boolean {
  if (siblingWrites(c, cwd).some((p) => IGNORE_FILES.has(basename(p)))) return false;
  if (c.name === "write" || c.name === "edit") return safeAllow(c.name, c.arguments, cwd, { trusted: false, touched: new Set() });
  if (c.name !== "bash") return false;
  const p = parseShell(String(c.arguments?.command ?? ""));
  return p.subcommands.every((a) => ["mkdir", "touch"].includes(normalizeArgv(a).argv[0])) && safeAllow("bash", c.arguments, cwd, { trusted: false, touched: new Set() }, p);
}

/** True for calls that cannot change the file system: read tools and strictly read-only bash. */
function isPureRead(c: ToolCallLike, cwd: string): boolean {
  if (["read", "grep", "find", "ls"].includes(c.name)) return true;
  if (c.name !== "bash") return false;
  const p = parseShell(String(c.arguments?.command ?? ""));
  return p.ok && !p.dynamic.length && !p.writes.length && p.subcommands.every(isReadOnlyArgv) && writesStayPlain("bash", c.arguments, cwd, p) && inputPaths("bash", c.arguments, cwd, p).writes.length === 0;
}

function isRegularSmallFile(p: string): boolean {
  try {
    const st = statSync(p);
    return st.isFile() && st.size < 1_000_000;
  } catch {
    return false;
  }
}

function readText(p: string): string | undefined {
  try {
    return existsSync(p) ? readFileSync(p, "utf8") : undefined;
  } catch {
    return undefined;
  }
}

export default function (pi: ExtensionAPI) {
  let cfg: Config = loadConfig();
  const store = new RuleStore();
  let enabled = true;
  let trusted = false;
  /**
   * Model verdicts started at message_end, reused by tool_call. Only the model call is reused:
   * every deterministic check runs again at tool_call, because earlier calls may have changed the file system.
   */
  const modelMemo = new Map<string, Promise<ModelVerdict>>();
  /** Earlier calls of the same assistant message, recorded at message_end. */
  const siblingsById = new Map<string, ToolCallLike[]>();
  const judged = new Map<string, string>();
  const verdictCache = new Map<string, { at: number; a: Assessment }>();
  /** Files written or edited in this session. */
  const touched = new Set<string>();
  /** True once an allowed call changed files in ways guard cannot list (git checkout, tar x, rsync, ...). */
  let opaqueChanges = false;
  const promoted = new Set<string>();
  let consecutiveBlocks = 0;
  let totalBlocks = 0;

  const append = (type: string, data: unknown) => pi.appendEntry(type, data);

  /** Earlier tool calls of the assistant message that contains callId, from the session branch. */
  function siblingsFromBranch(ctx: ExtensionContext, callId: string): ToolCallLike[] {
    const branch = ctx.sessionManager.getBranch() as any[];
    for (let i = branch.length - 1; i >= 0; i--) {
      const m = branch[i]?.message;
      if (branch[i]?.type !== "message" || m?.role !== "assistant" || !Array.isArray(m.content)) continue;
      const calls = m.content.filter((c: any) => c?.type === "toolCall");
      const idx = calls.findIndex((c: any) => c.id === callId);
      if (idx >= 0) return calls.slice(0, idx).map((c: any) => ({ id: c.id, name: c.name, arguments: c.arguments }));
    }
    return [];
  }

  /** Builds the judge's context from the session branch plus earlier calls of the same assistant message. */
  function context(ctx: ExtensionContext, callId: string, tool: string, parsed: Parsed | undefined, siblings: ToolCallLike[]) {
    const users: string[] = [];
    const calls: ToolCallLike[] = [];
    for (const e of ctx.sessionManager.getBranch() as any[]) {
      if (e.type !== "message") continue;
      const m = e.message;
      if (m?.role === "user") users.push(textOf(m.content));
      if (m?.role === "assistant" && Array.isArray(m.content))
        for (const c of m.content) if (c?.type === "toolCall" && c.id !== callId) calls.push({ id: c.id, name: c.name, arguments: c.arguments });
    }
    // At message_end the current message is not in the branch yet, so add earlier siblings explicitly
    for (const s of siblings) if (!calls.some((c) => c.id === s.id)) calls.push(s);

    // Contents the earlier siblings will produce. They have not run yet when this call is judged.
    const virtual = new Map<string, string>();
    for (const s of siblings) {
      const p = typeof s.arguments?.path === "string" ? resolvePath(ctx.cwd, s.arguments.path) : undefined;
      if (!p) continue;
      if (s.name === "write") virtual.set(p, String(s.arguments.content ?? ""));
      if (s.name === "edit") virtual.set(p, applyEdits(virtual.get(p) ?? readText(p) ?? "", s.arguments));
    }
    const writtenEarlier = new Map<string, string>();
    for (const c of calls) if (c.name === "write" && typeof c.arguments?.path === "string") writtenEarlier.set(resolvePath(ctx.cwd, c.arguments.path), String(c.arguments.content ?? ""));

    const attached: Record<string, string> = {};
    const fromSiblings: string[] = [];
    const roots = protectedRoots(ctx.cwd, ctx.sessionManager.getSessionDir());
    const attach = (p: string, fromDisk = false) => {
      if (attached[p] !== undefined) return;
      // Never send secrets (or guard's own state) to the judge; the name is enough for it to know the file is involved
      if (sensitiveReason(p) || protectedReason(p, roots)) {
        attached[p] = "[contents withheld by guard: file likely holds secrets]";
        return;
      }
      if (virtual.has(p)) {
        attached[p] = virtual.get(p)!;
        fromSiblings.push(p);
        return;
      }
      const text = touched.has(p) || fromDisk ? readText(p) : undefined;
      if (text !== undefined) attached[p] = text;
      else if (writtenEarlier.has(p)) attached[p] = writtenEarlier.get(p)!;
    };
    let runsScripts = false;
    let changedCount = 0;
    if (tool === "bash" && parsed) {
      for (const tok of parsed.subcommands.flat()) attach(resolvePath(ctx.cwd, tok));
      // Interpreters, runners, and scripts run by path (./run.sh) execute file contents
      const versionQuery = (a: string[]) => a.length === 2 && /^(--version|-V|-v|--help|-h)$/.test(a[1]);
      runsScripts = parsed.subcommands.some((a) => !versionQuery(a) && (SCRIPT_RUNNERS.has(normalizeArgv(a, "deny").argv[0]) || (a[0] ?? "").includes("/")));
      if (runsScripts) {
        // The script an interpreter or runner is given is what will run, whoever wrote it
        for (const tok of parsed.subcommands.flat()) {
          const p = resolvePath(ctx.cwd, tok);
          if (isRegularSmallFile(p)) attach(p, true);
        }
        // Test runners and build tools also load project files that are not named in the command
        // (tests, conftest.py, package.json scripts, node_modules/.bin): attach every file changed in this session,
        // and recently changed project files (which may come from an earlier session or a git checkout)
        for (const p of [...touched, ...virtual.keys()]) if (isInside(p, ctx.cwd)) attach(p);
        // Changes guard could not follow (git checkout, extracting archives) also call for a full judgement
        changedCount = Object.keys(attached).length + (opaqueChanges ? 1 : 0);
        // Context only: recently changed files do not by themselves force a full judgement
        for (const p of recentlyChangedFiles(ctx.cwd)) attach(p, true);
      }
    }
    return {
      userMessages: users.slice(-cfg.contextUserMessages),
      history: calls.slice(-cfg.contextToolCalls),
      attachedFiles: attached,
      fromSiblings,
      changedFilesRun: runsScripts && changedCount > 0,
    };
  }

  async function judgeWithModel(tool: string, input: any, ctx: ExtensionContext, callId: string, cx: ReturnType<typeof context>, past: Rule[], light: boolean, signal?: AbortSignal): Promise<ModelVerdict> {
    const key = stableHash([callId, tool, input, light, cx.attachedFiles, cx.userMessages.at(-1), past.map((r) => r.id)]);
    const run = async () => {
      const { body, truncated } = buildRequest(cfg, { tool, input, cwd: ctx.cwd, callId, past, light, ...cx, sessionId: ctx.sessionManager.getSessionId() });
      return evaluate(cfg, await callDecisions(cfg, body, signal), { light, truncated });
    };
    const memo = modelMemo.get(key);
    if (memo) {
      modelMemo.delete(key);
      try {
        return await memo;
      } catch {
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

  async function assess(callId: string, tool: string, input: any, ctx: ExtensionContext, opts: { signal?: AbortSignal; siblings?: ToolCallLike[] } = {}): Promise<Assessment> {
    clearPathCache();
    const parsed = tool === "bash" ? parseShell(String(input?.command ?? "")) : undefined;
    const roots = protectedRoots(ctx.cwd, ctx.sessionManager.getSessionDir());
    const base = { rememberAllow: false, globalAllow: false };

    const hard = hardDeny(tool, input, ctx.cwd, roots, parsed);
    if (hard) return { ...base, action: "block", source: "hard-deny", reasons: [hard] };

    store.syncSession(ctx.sessionManager.getBranch() as any[]);
    const found = store.find(tool, input, ctx.cwd, parsed);
    // An allow rule only covers calls whose paths stay inside the project, writing only plain files
    const rule = found?.decision === "allow" && (!writesStayPlain(tool, input, ctx.cwd, parsed) || !pathsStayInProject(tool, input, ctx.cwd, parsed)) ? undefined : found;
    const patterns = derivePatterns(tool, input, ctx.cwd, parsed);
    const denyPatterns = deriveDenyPatterns(tool, input, ctx.cwd, parsed);
    if (rule?.decision === "deny") return { ...base, action: "block", source: "rule-deny", reasons: rule.rules.map((r) => `${r.scope} deny rule: ${describeMatch(r.tool, r.match)}`), rules: rule.rules };
    if (rule?.decision === "ask") return { ...base, action: "confirm", source: "rule-ask", reasons: rule.rules.map((r) => `${r.scope} ask rule: ${describeMatch(r.tool, r.match)}`), rules: rule.rules, denyPatterns };

    const cx = context(ctx, callId, tool, parsed, opts.siblings ?? []);
    // pi judges every call of a message before running any of them, so a later call cannot rely on the file system
    // as it is now if an earlier sibling may change it (a checkout that adds a symlink, a write through one)
    const siblingMayChange = (opts.siblings ?? []).some((sb) => !isPureRead(sb, ctx.cwd) && !isPlainChange(sb, ctx.cwd));
    // An earlier call in this message may swap whole directories (checkout, extract, copy, link) before this one runs:
    // neither the deterministic checks nor the model can see the result, so writes after it ask the human
    const treeChanger = (opts.siblings ?? []).find((sb) => changesTrees(sb));
    if (treeChanger && callWrites(tool, input, ctx.cwd, parsed))
      return { rememberAllow: false, globalAllow: false, action: "confirm", source: "model", reasons: [`runs after "${preview(treeChanger.name, treeChanger.arguments).split("\n")[0].slice(0, 80)}" in the same message, which may change what this call writes to`] };
    const sens = sensitive(tool, input, ctx.cwd, roots, parsed);
    // Running a file that an earlier call in the same message is about to change: the human should see it
    const siblingRun = cx.fromSiblings.length ? `runs ${cx.fromSiblings.map((p) => relative(ctx.cwd, p)).join(", ")}, changed earlier in this same message` : undefined;

    if (rule?.decision === "allow" && !sens && !siblingRun && !cx.changedFilesRun && !siblingMayChange) {
      const reasons = rule.rules.map((r) => `${r.scope} allow rule: ${describeMatch(r.tool, r.match)}`);
      if (!process.env.GUARD_OPENAI_API_KEY) return { ...base, action: "allow", source: "rule-allow", reasons: [...reasons, "rules-only mode (no API key)"], rules: rule.rules };
      try {
        const v = await judgeWithModel(tool, input, ctx, callId, cx, [], true, opts.signal);
        if (v.action === "allow") return { ...base, action: "allow", source: "rule-allow", reasons, rules: rule.rules, verdict: v };
        return { ...base, action: "confirm", source: "model", reasons: [...v.reasons, "(matches an allow rule, but failed the light check)"], verdict: v, denyPatterns };
      } catch (e: any) {
        if (opts.signal?.aborted) throw e;
        return { ...base, action: "confirm", source: "error", reasons: [...reasons, `light check failed: ${e.message}`], denyPatterns };
      }
    }

    if (sens) return { ...base, action: "confirm", source: "sensitive", reasons: [`may expose secrets: ${sens}`], patterns, denyPatterns, rememberAllow: !!patterns };
    const shortcutsOk = !siblingRun && !siblingMayChange;
    // Files earlier calls of this message will write count as touched for this judgement (git dirs, ignore files)
    const touchedNow = new Set([...touched, ...(opts.siblings ?? []).flatMap((sb) => siblingWrites(sb, ctx.cwd))]);
    if (shortcutsOk && !cx.changedFilesRun && safeAllow(tool, input, ctx.cwd, { trusted, touched: touchedNow }, parsed)) return { ...base, action: "allow", source: "safe", reasons: [] };
    if (shortcutsOk && cfg.skipModelTools.includes(tool)) {
      // read/grep/find/ls skip the model only inside the project (or public system directories). pi's read tries
      // other spellings (curly quotes, NFD, AM/PM) when a path does not exist, so a read must name an existing file.
      const reads = inputPaths(tool, input, ctx.cwd).reads;
      const exists = tool !== "read" || reads.every((p) => existsSync(p));
      if (exists && (reads.length ? reads : [ctx.cwd]).every((p) => isFreelyReadable(p, ctx.cwd))) return { ...base, action: "allow", source: "skip", reasons: [] };
    }

    const cacheKey = stableHash([tool, input, ctx.cwd, cx.attachedFiles, cx.userMessages.at(-1), store.version]);
    const cached = verdictCache.get(cacheKey);
    if (cached && Date.now() - cached.at < cfg.verdictCacheMs && !siblingRun) return { ...cached.a, source: "cache" };

    try {
      const past = store.related(tool, input, ctx.cwd, parsed);
      const v = await judgeWithModel(tool, input, ctx, callId, cx, past, false, opts.signal);
      const t = cfg.thresholds;
      const rememberAllow =
        !!patterns && v.action !== "block" && (v.pHigh ?? 1) < t.confirmPHigh && (v.exfiltration ?? 1) < t.confirmExfil &&
        (v.addressesEvaluator ?? 1) < t.confirmAddressesEvaluator && !v.truncated;
      // Global allow rules apply in every trusted project, so only read-only calls may become one
      const globalAllow = rememberAllow && trusted && v.category === "read_only" && (v.risk ?? 9) < t.confirmScore;
      const a: Assessment = { action: v.action, source: "model", reasons: v.reasons, verdict: v, patterns, denyPatterns, rememberAllow, globalAllow };
      if (siblingRun && a.action === "allow") {
        a.action = "confirm";
        a.reasons = [...a.reasons, siblingRun];
      }
      if (a.action === "allow" && !siblingRun) {
        if (verdictCache.size >= MAX_CACHE) {
          for (const [k, e] of verdictCache) if (Date.now() - e.at >= cfg.verdictCacheMs) verdictCache.delete(k);
          if (verdictCache.size >= MAX_CACHE) verdictCache.delete(verdictCache.keys().next().value!);
        }
        verdictCache.set(cacheKey, { at: Date.now(), a });
      }
      return a;
    } catch (e: any) {
      if (opts.signal?.aborted) throw e;
      return { ...base, action: "confirm", source: "error", reasons: [`could not judge: ${e.message}`, ...(siblingRun ? [siblingRun] : [])], patterns, denyPatterns };
    }
  }

  function status(ctx: ExtensionContext, text: string) {
    ctx.ui.setStatus("guard", text);
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

  function blockResult(reason: string) {
    return { block: true as const, reason: `guard: ${reason}. Do not retry this call or try to work around the check; choose a safer approach or ask the user.` };
  }

  function restoreState(ctx: ExtensionContext) {
    store.syncSession(ctx.sessionManager.getBranch() as any[]);
    enabled = true;
    for (const e of ctx.sessionManager.getBranch() as any[]) if (e.type === "custom" && e.customType === STATE_ENTRY) enabled = e.data?.enabled !== false;
    status(ctx, cfg.disabled ? "guard: disabled" : !enabled ? "guard: off" : process.env.GUARD_OPENAI_API_KEY ? `guard: ${cfg.model}` : "guard: rules only");
  }

  pi.on("session_start", async (_e, ctx) => {
    const loaded = loadConfig();
    cfg = loaded;
    trusted = ctx.isProjectTrusted();
    store.load(ctx.cwd, trusted);
    store.resetSession();
    modelMemo.clear(); siblingsById.clear(); judged.clear(); touched.clear(); promoted.clear(); verdictCache.clear();
    opaqueChanges = false;
    consecutiveBlocks = totalBlocks = 0;
    for (const w of [...loaded.warnings, ...store.warnings]) ctx.ui.notify(`guard: ${w}`, "warning");
    restoreState(ctx);
    if (!cfg.disabled && !process.env.GUARD_OPENAI_API_KEY)
      ctx.ui.notify("guard: GUARD_OPENAI_API_KEY is not set. Running in rules-only mode: calls that need a model judgement will ask you first.", "warning");
  });

  // Rewinding with /tree changes which session rules and on/off state apply
  pi.on("session_tree", async (_e, ctx) => {
    modelMemo.clear();
    siblingsById.clear();
    restoreState(ctx);
  });

  // Start judging every tool call of an assistant message in parallel as soon as the message ends
  // (pi preflights sibling calls one by one, which would otherwise add up the latency).
  pi.on("message_end", async (event, ctx) => {
    if (cfg.disabled || !enabled) return;
    const m: any = event.message;
    if (m?.role !== "assistant" || !Array.isArray(m.content)) return;
    const calls: ToolCallLike[] = m.content.filter((c: any) => c?.type === "toolCall").map((c: any) => ({ id: c.id, name: c.name, arguments: c.arguments }));
    calls.forEach((c, i) => {
      if (siblingsById.has(c.id)) return;
      const siblings = calls.slice(0, i);
      siblingsById.set(c.id, siblings);
      // Warms modelMemo; the result itself is discarded and recomputed at tool_call
      assess(c.id, c.name, c.arguments, ctx, { signal: ctx.signal, siblings }).catch(() => {});
    });
  });

  pi.on("agent_end", async () => {
    modelMemo.clear();
    siblingsById.clear();
  });

  pi.on("tool_call", async (event, ctx) => {
    if (cfg.disabled || !enabled) return;
    const tool = event.toolName;
    const input: any = event.input;
    const hash = stableHash([tool, input]);
    const siblings = siblingsById.get(event.toolCallId) ?? siblingsFromBranch(ctx, event.toolCallId);
    siblingsById.delete(event.toolCallId);

    status(ctx, `guard: judging ${tool}…`);
    let a: Assessment;
    try {
      // Deterministic checks always run on the current state; a model verdict started at message_end is reused
      // only if the input, attachments and past decisions it was based on are unchanged
      a = await assess(event.toolCallId, tool, input, ctx, { signal: ctx.signal, siblings });
    } catch (e: any) {
      a = { action: "confirm", source: "error", reasons: [`could not judge: ${e.message}`], rememberAllow: false, globalAllow: false };
    }
    judged.set(event.toolCallId, hash);
    const what = preview(tool, input);
    const session = ctx.sessionManager.getSessionId();
    const risk = a.verdict?.risk;
    const tag = `${a.source}${risk !== undefined ? ` ${risk.toFixed(1)}` : ""}${a.verdict?.category ? ` ${a.verdict.category}` : ""}`;
    const rec = { session, tool, preview: what, action: a.action, source: a.source, reasons: a.reasons, risk, ruleIds: a.rules?.map((r) => r.id) };

    const onAllowed = () => {
      consecutiveBlocks = 0;
      // Files this call changes; running them later attaches their new contents
      try {
        if (changesTrees({ id: "", name: tool, arguments: input })) opaqueChanges = true;
        const parsedNow = tool === "bash" ? parseShell(String(input?.command ?? "")) : undefined;
        if (tool === "edit" || tool === "write" || tool === "bash") for (const p of inputPaths(tool, input, ctx.cwd, parsedNow).writes) touched.add(p);
      } catch {
        /* bookkeeping must never turn an approved call into a block */
      }
      if (a.rules && a.source === "rule-allow") {
        store.hit(a.rules);
        for (const r of a.rules) {
          if (r.scope === "session" && store.hitCount(r.id) >= 3 && !promoted.has(r.id)) {
            promoted.add(r.id);
            ctx.ui.notify(`guard: "${describeMatch(r.tool, r.match)}" was allowed ${store.hitCount(r.id)} times this session. Remember it for this project with /guard rules promote ${r.id} project`, "info");
          }
        }
      }
    };
    const onBlocked = (reason: string) => {
      consecutiveBlocks++;
      totalBlocks++;
      if (consecutiveBlocks >= cfg.escalateConsecutive || totalBlocks >= cfg.escalateTotal) {
        ctx.ui.notify(`guard: too many blocked calls (${consecutiveBlocks} in a row, ${totalBlocks} total). Stopped the agent.`, "error");
        consecutiveBlocks = 0;
        ctx.abort();
        return { ...blockResult(reason), terminate: true };
      }
      return blockResult(reason);
    };

    if (a.action === "allow") {
      status(ctx, `guard: ${tool} ok (${tag})`);
      audit({ ...rec, final: "run" });
      onAllowed();
      return;
    }
    if (a.action === "block") {
      status(ctx, `guard: ${tool} BLOCKED (${tag})`);
      ctx.ui.notify(`guard: blocked ${tool} — ${a.reasons.join("; ")}`, "error");
      audit({ ...rec, final: "blocked" });
      return onBlocked(a.source === "hard-deny" ? `blocked (${a.reasons[0]})` : a.source === "rule-deny" ? "blocked by the user's deny rule" : "blocked as too dangerous");
    }

    status(ctx, `guard: ${tool} needs confirmation (${tag})`);
    if (!ctx.hasUI) {
      audit({ ...rec, final: "blocked", choice: "no-ui" });
      return onBlocked("this call needs the user's confirmation, but no UI is available");
    }
    const v = a.verdict;
    const head = `${tool}: ${v?.risk !== undefined ? `risk ${v.risk.toFixed(2)}/4` : "confirm"}${v?.category ? ` [${v.category}]` : ""}`;
    const choice = await confirmDialog(ctx, {
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
    const saved: Rule[] = [];
    const toSave = choice.decision === "deny" ? a.denyPatterns : a.patterns;
    if (choice.scope !== "once" && toSave)
      for (const m of toSave) saved.push(addRule(choice.decision, choice.scope, tool, m, ctx.cwd, v?.risk, choice.reason));
    if (saved.length)
      ctx.ui.notify(`guard: saved ${choice.scope} ${choice.decision} rule: ${saved.map((r) => `${describeMatch(r.tool, r.match)} [${r.id}]`).join(", ")} (undo: /guard rules rm <id>)`, "info");
    audit({ ...rec, final: choice.decision === "allow" ? "run" : "blocked", choice: `${choice.decision}:${choice.scope}`, ruleIds: [...(rec.ruleIds ?? []), ...saved.map((r) => r.id)] });

    if (choice.decision === "allow") {
      onAllowed();
      return;
    }
    consecutiveBlocks = 0; // the user's own denials do not count towards escalation
    return blockResult(choice.reason ? `the user denied this call: ${choice.reason}` : "the user denied this call");
  });

  // Detect input that changed after guard judged it (an extension loaded after guard rewrote it)
  pi.on("tool_result", async (event, ctx) => {
    const h = judged.get(event.toolCallId);
    judged.delete(event.toolCallId);
    if (!h || h === stableHash([event.toolName, event.input])) return;
    audit({ session: ctx.sessionManager.getSessionId(), tool: event.toolName, preview: preview(event.toolName, event.input), action: "allow", source: "drift", reasons: ["input changed after judgement"], event: "drift" });
    ctx.ui.notify(`guard: the input of ${event.toolName} was changed by another extension after guard judged it. Load guard last.`, "warning");
  });

  pi.on("tool_execution_end", async (event) => {
    judged.delete(event.toolCallId);
  });

  pi.registerCommand("guard", {
    description: "Tool-call guard: /guard [on|off|check <cmd>|rules [rm|promote|add]|log [n]|reload]",
    handler: async (args, ctx) => {
      const [sub, ...rest] = (args ?? "").trim().split(/\s+/).filter(Boolean);
      const say = (m: string, t: "info" | "warning" | "error" = "info") => ctx.ui.notify(m, t);

      if (!sub) {
        const all = store.all();
        const count = (s: Scope) => all.filter((r) => r.scope === s).length;
        return say(
          `guard: ${cfg.disabled ? "disabled" : enabled ? "on" : "off"} | model=${cfg.model} key=${process.env.GUARD_OPENAI_API_KEY ? "set" : "unset"} trusted=${trusted} | ` +
            `rules: session ${count("session")} / project ${count("project")} / global ${count("global")} / repo ${count("repo")} | blocks ${totalBlocks}`,
        );
      }
      if (sub === "on" || sub === "off") {
        enabled = sub === "on";
        append(STATE_ENTRY, { enabled });
        restoreState(ctx);
        return say(`guard: ${sub} for this session`);
      }
      if (sub === "reload") {
        const loaded = loadConfig();
        cfg = loaded;
        store.load(ctx.cwd, ctx.isProjectTrusted());
        verdictCache.clear();
        for (const w of [...loaded.warnings, ...store.warnings]) say(`guard: ${w}`, "warning");
        return say("guard: reloaded settings and rules");
      }
      if (sub === "log") {
        const n = Number(rest[0] ?? 15) || 15;
        const lines = tail(n).map((r) => `${r.ts?.slice(5, 19).replace("T", " ")} ${r.final ?? r.event ?? ""} ${r.source}${r.choice ? `→${r.choice}` : ""} ${r.preview.split("\n")[0].slice(0, 80)}${r.reasons.length ? ` — ${r.reasons.join("; ").slice(0, 120)}` : ""}`);
        return say(lines.length ? lines.join("\n") : "guard: the audit log is empty");
      }
      if (sub === "rules") {
        const op = rest[0] ?? "list";
        if (op === "list") {
          const order: Scope[] = ["session", "repo", "project", "global"];
          const lines = store.all().sort((a, b) => order.indexOf(a.scope) - order.indexOf(b.scope))
            .map((r) => `[${r.scope}] ${r.decision.padEnd(5)} ${describeMatch(r.tool, r.match)}  (id ${r.id}, hits ${store.hitCount(r.id)}${r.expiresAt ? `, expires ${r.expiresAt.slice(0, 10)}` : ""})`);
          if (!lines.length) return say("guard: no rules");
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
          const r = rest[1] ? store.remove(rest[1], append) : undefined;
          return r ? say(`guard: deleted ${describeMatch(r.tool, r.match)}`) : say("guard: no rule with that id", "warning");
        }
        if (op === "promote") {
          const [id, to] = [rest[1], rest[2]];
          const r = store.all().find((x) => x.id === id);
          if (!r || (to !== "project" && to !== "global")) return say("usage: /guard rules promote <id> project|global", "warning");
          const globalAllow = to === "global" && r.decision === "allow";
          // Global allows apply in every trusted project: only read-only commands, and only with the human confirming
          if (globalAllow && !(r.tool === "bash" && r.match.kind !== "tool" && r.match.kind !== "path" && isReadOnlyArgv(r.match.kind === "argv" ? r.match.prefix : r.match.argv)))
            return say("guard: only read-only commands can become global allow rules", "warning");
          if (globalAllow && !ctx.hasUI) return say("guard: promoting to a global allow rule needs the interactive UI", "warning");
          const warn = globalAllow ? " Global allow rules apply in every trusted project." : "";
          if (ctx.hasUI && !(await ctx.ui.confirm("Promote rule", `Save ${describeMatch(r.tool, r.match)} as a ${to} rule?${warn}`))) return;
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
          if (pat[0].startsWith("tool:")) { tool = pat[0].slice(5); match = { kind: "tool" }; }
          else if (pat[0].startsWith("path:")) { tool = pat[1] ?? "edit"; match = { kind: "path", path: resolvePath(ctx.cwd, pat[0].slice(5)) }; }
          else match = { kind: "argv", prefix: normalizeArgv(pat).argv };
          const r = addRule(decision as Decision, scope as "session" | "project" | "global", tool, match, ctx.cwd);
          return say(`guard: added ${scope} ${decision} rule: ${describeMatch(tool, match)} [${r.id}]`);
        }
        return say("usage: /guard rules [list|rm <id>|promote <id> project|global|add …]", "warning");
      }
      // Anything else is scored as a bash command without running it (/guard check <cmd> or /guard <cmd>)
      const cmd = (sub === "check" ? rest : [sub, ...rest]).join(" ");
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
