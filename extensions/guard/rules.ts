/**
 * Remembered decisions.
 *
 * Scopes: session (pi session log) / project / global / repo (.pi/guard.json, trusted projects only, deny/ask only).
 * Precedence follows strictness, not scope: deny > ask > allow.
 * A bash allow applies only when every subcommand matches and the command has no dynamic parts.
 * Global allow rules apply only in trusted projects, so a freshly cloned repository cannot reuse them.
 */
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { DATA_DIR } from "./config.ts";
import { innerCommands, isLongOption, normalizeArgv, type Parsed, parseShell } from "./shell.ts";
import { inputPaths } from "./policy.ts";

export type Decision = "allow" | "deny" | "ask";
export type Scope = "session" | "project" | "global" | "repo";
export type Match =
  | { kind: "argv"; prefix: string[] }
  | { kind: "argv-exact"; argv: string[] }
  | { kind: "path"; path: string }
  | { kind: "tool" };

export type Rule = {
  id: string;
  decision: Decision;
  tool: string;
  match: Match;
  scope: Scope;
  /** cwd a session rule was created in; it does not apply elsewhere. */
  cwd?: string;
  createdAt: string;
  expiresAt?: string;
  /** Model and risk at decision time, for investigating drift. */
  model?: string;
  risk?: number;
  note?: string;
};

const SESSION_ENTRY = "guard-rule";

/** Commands that are dangerous to allow by prefix. Allow rules for them must match the whole argv. */
const EXACT_ONLY: string[][] = [
  ["rm"], ["rmdir"], ["mv"], ["dd"], ["chmod"], ["chown"], ["kill"], ["pkill"], ["killall"], ["truncate"], ["shred"],
  ["git", "push"], ["git", "reset"], ["git", "clean"], ["git", "checkout"], ["git", "restore"], ["git", "rebase"], ["git", "branch"],
  ["git", "tag"], ["git", "remote"], ["git", "config"], ["git", "filter-branch"], ["git", "update-ref"],
  ["curl"], ["wget"], ["ssh"], ["scp"], ["rsync"], ["docker"], ["kubectl"], ["terraform"], ["helm"], ["aws"], ["gcloud"], ["az"],
  ["npm", "publish"], ["pnpm", "publish"], ["yarn", "publish"], ["cargo", "publish"], ["gem", "push"], ["twine"], ["gh"],
  // Installing packages runs their install scripts, so each package must be approved on its own
  ["npm", "install"], ["npm", "i"], ["npm", "add"], ["pnpm", "add"], ["pnpm", "install"], ["pnpm", "i"], ["yarn", "add"],
  ["bun", "add"], ["bun", "install"], ["pip", "install"], ["pip3", "install"], ["uv", "add"], ["uv", "pip"], ["cargo", "install"],
  ["go", "install"], ["gem", "install"], ["brew", "install"],
];
/**
 * Tools whose second word is a subcommand. Only these get prefix rules (`npm test …`); for every other command
 * the arguments are paths or data (`cp a b`), so the rule must match the whole argv.
 */
const SUBCOMMAND_TOOLS = new Set(["git", "npm", "pnpm", "yarn", "bun", "cargo", "go", "make", "gmake", "just", "uv", "poetry", "deno", "mvn", "gradle", "dotnet", "mix", "bundle", "rake", "tox", "nox", "turbo", "nx", "pre-commit"]);
/** Subcommands whose next word picks an arbitrary script, so the rule needs three words. */
const SCRIPT_SUBCOMMANDS = new Set(["run", "run-script", "exec", "x", "dlx"]);

const isExactOnly = (a: string[]) => EXACT_ONLY.some((p) => p.every((t, i) => a[i] === t));
const isWord = (t?: string) => !!t && /^[a-z][\w:@-]*$/i.test(t);

export function newId(): string {
  return randomBytes(3).toString("hex");
}

export function describeMatch(tool: string, m: Match): string {
  switch (m.kind) {
    case "argv": return `${m.prefix.join(" ")} …`;
    case "argv-exact": return m.argv.join(" ");
    case "path": return `${tool} ${m.path}`;
    case "tool": return `${tool} (any input)`;
  }
}

function dedupe(ms: Match[]): Match[] {
  return ms.filter((m, i) => ms.findIndex((x) => JSON.stringify(x) === JSON.stringify(m)) === i);
}

function nonBashPattern(tool: string, input: any, cwd: string): Match[] | undefined {
  const { reads, writes } = inputPaths(tool, input, cwd);
  const paths = [...new Set([...reads, ...writes])];
  if (paths.length === 1 && ["edit", "write", "read", "grep", "find", "ls"].includes(tool)) return [{ kind: "path", path: paths[0] }];
  // "Any input" is only offered for tools whose arguments contain no command-like text
  const commandLike = JSON.stringify(input ?? {}).match(/"[^"]*\s[^"]*"/g)?.length ?? 0;
  if (paths.length === 0 && commandLike === 0 && !["bash", "edit", "write", "read", "powershell"].includes(tool)) return [{ kind: "tool" }];
  return undefined;
}

/**
 * Patterns for remembering an allow. Undefined when the call cannot be generalized safely.
 * npm test -- foo → ["npm","test"] / npm run lint → ["npm","run","lint"] / cp a b → exact / python x.py → none
 */
export function derivePatterns(tool: string, input: any, cwd: string, parsed?: Parsed): Match[] | undefined {
  if (tool !== "bash") return nonBashPattern(tool, input, cwd);
  if (!parsed || !parsed.ok || parsed.dynamic.length || !parsed.subcommands.length) return undefined;
  return dedupe(
    parsed.subs.map((s): Match => {
      const { argv: a, unknownOption } = normalizeArgv(s.argv);
      const sub = a[1];
      if (unknownOption || s.writes.length || isExactOnly(a) || !SUBCOMMAND_TOOLS.has(a[0]) || !isWord(sub)) return { kind: "argv-exact", argv: a };
      if (SCRIPT_SUBCOMMANDS.has(sub)) return isWord(a[2]) ? { kind: "argv", prefix: a.slice(0, 3) } : { kind: "argv-exact", argv: a };
      return { kind: "argv", prefix: a.slice(0, 2) };
    }),
  );
}

/**
 * Patterns for remembering a deny: the command words plus its flags, without values.
 * `git push --force origin main` → ["git","push","--force"], which also blocks `git push -f origin dev`.
 */
export function deriveDenyPatterns(tool: string, input: any, cwd: string, parsed?: Parsed): Match[] | undefined {
  if (tool !== "bash") return nonBashPattern(tool, input, cwd);
  if (!parsed || !parsed.subcommands.length) return undefined;
  return dedupe(
    parsed.subcommands
      .map((raw) => normalizeArgv(raw, "deny").argv)
      .filter((a) => a.length)
      .map((a): Match => {
        const words = a.filter((t) => !t.startsWith("-"));
        const n = SUBCOMMAND_TOOLS.has(a[0]) ? (SCRIPT_SUBCOMMANDS.has(words[1]) ? 3 : 2) : 1;
        return { kind: "argv", prefix: [...words.slice(0, n), ...splitFlags(a.filter((t) => /^-/.test(t) && !t.includes("=")))] };
      }),
  );
}

/** An example the rule matches and one it does not, for the dialog. */
export function examples(m: Match): { yes: string; no: string } | undefined {
  if (m.kind === "argv") {
    const words = m.prefix.filter((t) => !t.startsWith("-"));
    return { yes: `${m.prefix.join(" ")} --foo`, no: words.length > 1 ? `${words.slice(0, -1).join(" ")} other` : `${words[0]}x` };
  }
  if (m.kind === "argv-exact") return { yes: m.argv.join(" "), no: `${m.argv.join(" ")} --other` };
  return undefined;
}

/** Strict matching for allow rules. Location options never match, and prefix rules never cover EXACT_ONLY commands. */
function allowMatchesArgv(m: Match, raw: string[]): boolean {
  const { argv: a, unknownOption } = normalizeArgv(raw);
  if (unknownOption) return false;
  if (m.kind === "argv-exact") return m.argv.length === a.length && m.argv.every((t, i) => a[i] === t);
  if (m.kind === "argv") return !isExactOnly(a) && m.prefix.every((t, i) => a[i] === t);
  return false;
}

/** `-rf` → `-r`, `-f`, so remembered flags match in any order or grouping. */
function splitFlags(flags: string[]): string[] {
  return [...new Set(flags.flatMap((f) => (/^-[A-Za-z0-9]{2,}$/.test(f) ? [...f.slice(1)].map((c) => `-${c}`) : [f])))];
}

const FLAG_ALIASES: Record<string, string[]> = {
  "--force": ["-f", "--force-with-lease", "--force-if-includes"],
  "-f": ["--force", "--force-with-lease", "--force-if-includes"],
  "--recursive": ["-r", "-R"],
  "-r": ["-R", "--recursive"],
  "-R": ["-r", "--recursive"],
  "--force-with-lease": ["--force", "-f"],
  "--delete": ["-d", "-D"],
  "-d": ["--delete", "-D"],
  "-D": ["-d", "--delete"],
  "--all": ["-a"],
  "-a": ["--all"],
};

/**
 * Loose matching for deny and ask rules: the rule's words must prefix the command's words (flags ignored),
 * and each flag in the rule must be present in any spelling (`--force` also matches `-f`, `-fu`, `--force-with-lease`,
 * and a `+refspec` for git push).
 */
function strictMatchesArgv(m: Match, raw: string[]): boolean {
  const ruleTokens = m.kind === "argv" ? m.prefix : m.kind === "argv-exact" ? m.argv : undefined;
  if (!ruleTokens) return false;
  const a = normalizeArgv(raw, "deny").argv;
  const words = a.filter((t, i) => i === 0 || !t.startsWith("-"));
  const ruleWords = ruleTokens.filter((t, i) => i === 0 || !t.startsWith("-"));
  if (!ruleWords.every((t, i) => words[i] === t)) return false;
  const present = (f: string) =>
    a.some(
      (t) =>
        t === f ||
        t.startsWith(`${f}=`) ||
        // abbreviations of long options (--force-w for --force-with-lease)
        (f.startsWith("--") && isLongOption(t, f)) ||
        // a letter inside a cluster of short options (-fr, -Rf)
        (f.length === 2 && /^-[A-Za-z0-9]+$/.test(t) && t.includes(f[1])),
    );
  const forcePush = a[0] === "git" && words[1] === "push" && words.slice(2).some((w) => w.startsWith("+"));
  return splitFlags(ruleTokens.filter((t, i) => i > 0 && t.startsWith("-")))
    .every((f) => present(f) || (Object.hasOwn(FLAG_ALIASES, f) ? FLAG_ALIASES[f] : []).some(present) || ((f === "--force" || f === "-f") && forcePush));
}

/**
 * Subcommands plus the commands hidden inside `bash -c '…'`, `eval '…'` and similar (up to 3 levels),
 * so deny and ask rules also see them.
 */
function expandSubcommands(subs: string[][], depth = 0): string[][] {
  const out: string[][] = [];
  for (const raw of subs) {
    out.push(raw);
    if (depth >= 3) continue;
    for (const x of innerCommands(raw)) out.push(...expandSubcommands(parseShell(x).subcommands, depth + 1));
  }
  return out;
}

function matchesNonBash(r: Rule, tool: string, input: any, cwd: string, mode: "any" | "all"): boolean {
  const m = r.match;
  if (m.kind === "tool") return true;
  if (m.kind !== "path") return false;
  const { reads, writes } = inputPaths(tool, input, cwd);
  const ps = [...reads, ...writes];
  return mode === "any" ? ps.includes(m.path) : ps.length > 0 && ps.every((p) => p === m.path);
}

/** Parses a rule file line by line. Broken lines are kept verbatim so a later write never drops them. */
function readJsonl(file: string): { rules: Rule[]; broken: string[] } {
  let text = "";
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return { rules: [], broken: [] };
  }
  const rules: Rule[] = [];
  const broken: string[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line);
      if (r && typeof r.id === "string" && r.match && r.decision) rules.push(r);
      else broken.push(line);
    } catch {
      broken.push(line);
    }
  }
  return { rules, broken };
}

const sleep = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

/**
 * Runs fn on the freshly read file contents under a lock, then writes atomically.
 * Prevents lost updates when several pi processes change rules at the same time.
 */
function updateFile(file: string, fn: (rules: Rule[]) => Rule[]): Rule[] {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const lock = `${file}.lock`;
  const deadline = Date.now() + 3000;
  for (;;) {
    try {
      mkdirSync(lock);
      break;
    } catch {
      try {
        // Steal a stale lock by renaming it first: only one process can win the rename
        if (Date.now() - statSync(lock).mtimeMs > 10_000) {
          const grave = `${lock}.stale.${process.pid}.${randomBytes(3).toString("hex")}`;
          renameSync(lock, grave);
          rmSync(grave, { recursive: true, force: true });
          continue;
        }
      } catch { /* someone else got there first */ }
      if (Date.now() > deadline) throw new Error(`guard: could not lock ${file}`);
      sleep(20);
    }
  }
  try {
    const { rules, broken } = readJsonl(file);
    const next = fn(rules);
    const tmp = `${file}.${process.pid}.tmp`;
    const lines = [...next.map((r) => JSON.stringify(r)), ...broken];
    writeFileSync(tmp, lines.join("\n") + (lines.length ? "\n" : ""), { mode: 0o600 });
    renameSync(tmp, file);
    return next;
  } finally {
    rmSync(lock, { recursive: true, force: true });
  }
}

function projectFile(cwd: string): string {
  const h = createHash("sha256").update(cwd).digest("hex").slice(0, 16);
  return join(DATA_DIR, "projects", `${basename(cwd).replace(/[^\w.-]/g, "_")}-${h}.jsonl`);
}

const live = (r: Rule) => !r.expiresAt || Date.parse(r.expiresAt) >= Date.now();

export class RuleStore {
  global: Rule[] = [];
  project: Rule[] = [];
  repo: Rule[] = [];
  /** Problems found while reading rule files, for the user. */
  warnings: string[] = [];
  /** Bumped on every change, so pre-judged results made before a change can be discarded. */
  version = 0;
  private sessionFromBranch: Rule[] = [];
  private sessionPending: Rule[] = [];
  private hits = new Map<string, number>();
  private mtimes = new Map<string, number>();
  private trusted = false;
  private cwd = "";

  private files() {
    return { global: join(DATA_DIR, "rules.jsonl"), project: projectFile(this.cwd) };
  }

  load(cwd: string, trusted: boolean) {
    this.cwd = cwd;
    this.trusted = trusted;
    this.mtimes.clear();
    this.warnings = [];
    this.refresh(true);
    this.repo = [];
    if (trusted) {
      try {
        const cfg = JSON.parse(readFileSync(join(cwd, ".pi", "guard.json"), "utf8"));
        // A repository may only add deny and ask rules, never allow rules
        for (const d of ["deny", "ask"] as const)
          for (const p of cfg[d] ?? [])
            this.repo.push({ id: `repo-${d}-${p}`, decision: d, tool: "bash", match: { kind: "argv", prefix: String(p).trim().split(/\s+/) }, scope: "repo", createdAt: "" });
      } catch {
        /* no repo config */
      }
    }
    this.version++;
  }

  /** Re-reads rule files that another pi process changed. */
  private refresh(force = false) {
    const f = this.files();
    for (const scope of ["global", "project"] as const) {
      let m = -1;
      try { m = statSync(f[scope]).mtimeMs; } catch { /* missing file */ }
      if (force || this.mtimes.get(scope) !== m) {
        const { rules, broken } = readJsonl(f[scope]);
        this[scope] = rules;
        if (broken.length) this.warnings.push(`${broken.length} unreadable line(s) in ${f[scope]} were ignored (kept in the file)`);
        this.mtimes.set(scope, m);
        if (!force) this.version++;
      }
    }
  }

  /** Rebuilds session rules from the current branch of the pi session, so rewinding with /tree drops later approvals. */
  syncSession(branch: { type: string; customType?: string; data?: any }[]) {
    const rules = new Map<string, Rule>();
    for (const e of branch) {
      if (e.type !== "custom" || e.customType !== SESSION_ENTRY) continue;
      if (e.data?.op === "add") rules.set(e.data.rule.id, e.data.rule);
      if (e.data?.op === "remove") rules.delete(e.data.id);
    }
    const before = this.sessionFromBranch.map((r) => r.id).join();
    this.sessionFromBranch = [...rules.values()];
    this.sessionPending = this.sessionPending.filter((r) => !rules.has(r.id));
    if (before !== this.sessionFromBranch.map((r) => r.id).join()) this.version++;
  }

  resetSession() {
    this.sessionFromBranch = [];
    this.sessionPending = [];
    this.hits.clear();
  }

  session(): Rule[] {
    return [...this.sessionFromBranch, ...this.sessionPending];
  }

  hitCount(id: string): number {
    return this.hits.get(id) ?? 0;
  }

  all(): Rule[] {
    this.refresh();
    return [...this.session(), ...this.repo, ...this.project, ...this.global].filter(live);
  }

  /** The strictest decision that applies. A bash allow needs every subcommand to match an allow rule. */
  find(tool: string, input: any, cwd: string, parsed?: Parsed): { decision: Decision; rules: Rule[] } | undefined {
    const rules = this.all().filter((r) => r.tool === tool && (r.scope !== "session" || !r.cwd || r.cwd === cwd));
    const expanded = parsed ? expandSubcommands(parsed.subcommands) : [];
    for (const d of ["deny", "ask"] as const) {
      const hit = rules.filter((r) => r.decision === d && (tool === "bash" ? expanded.some((a) => strictMatchesArgv(r.match, a)) : matchesNonBash(r, tool, input, cwd, "any")));
      if (hit.length) return { decision: d, rules: hit };
    }
    const allows = rules.filter((r) => r.decision === "allow" && (r.scope !== "global" || this.trusted));
    if (tool === "bash") {
      if (!parsed || !parsed.ok || parsed.dynamic.length || !parsed.subcommands.length) return undefined;
      const used: Rule[] = [];
      for (const a of parsed.subcommands) {
        const r = allows.find((x) => allowMatchesArgv(x.match, a));
        if (!r) return undefined;
        if (!used.includes(r)) used.push(r);
      }
      return { decision: "allow", rules: used };
    }
    const hit = allows.filter((r) => matchesNonBash(r, tool, input, cwd, "all"));
    return hit.length ? { decision: "allow", rules: hit } : undefined;
  }

  /** Past decisions on the same tool with a similar pattern, passed to the model as evidence (max 5). */
  related(tool: string, input: any, cwd: string, parsed?: Parsed): Rule[] {
    const heads = new Set(parsed ? expandSubcommands(parsed.subcommands).map((a) => normalizeArgv(a, "deny").argv[0]) : []);
    const { reads, writes } = inputPaths(tool, input, cwd, parsed);
    const dirs = new Set([...reads, ...writes].map((p) => dirname(p)));
    return this.all()
      .filter((r) => r.scope !== "repo" && r.tool === tool)
      .filter((r) => {
        const m = r.match;
        if (m.kind === "argv") return heads.has(m.prefix[0]);
        if (m.kind === "argv-exact") return heads.has(m.argv[0]);
        if (m.kind === "path") return dirs.has(dirname(m.path));
        return true;
      })
      .slice(0, 5);
  }

  add(rule: Rule, appendEntry: (type: string, data: unknown) => void) {
    if (rule.scope === "session") {
      this.sessionPending.push(rule);
      appendEntry(SESSION_ENTRY, { op: "add", rule });
    } else if (rule.scope === "project" || rule.scope === "global") {
      const file = this.files()[rule.scope];
      this[rule.scope] = updateFile(file, (rs) => [...rs, rule]);
      this.mtimes.set(rule.scope, statSync(file).mtimeMs);
    }
    this.version++;
  }

  remove(id: string, appendEntry: (type: string, data: unknown) => void): Rule | undefined {
    const s = this.session().find((r) => r.id === id);
    if (s) {
      this.sessionPending = this.sessionPending.filter((r) => r.id !== id);
      this.sessionFromBranch = this.sessionFromBranch.filter((r) => r.id !== id);
      appendEntry(SESSION_ENTRY, { op: "remove", id });
      this.version++;
      return s;
    }
    this.refresh();
    const scope = (["project", "global"] as const).find((sc) => this[sc].some((x) => x.id === id));
    if (!scope) return undefined;
    let removed: Rule | undefined;
    const file = this.files()[scope];
    this[scope] = updateFile(file, (rs) => {
      removed = rs.find((x) => x.id === id);
      return rs.filter((x) => x.id !== id);
    });
    this.mtimes.set(scope, statSync(file).mtimeMs);
    this.version++;
    return removed;
  }

  /** Hit counts are kept in memory only, so counting never rewrites rule files. */
  hit(rules: Rule[]) {
    for (const r of rules) this.hits.set(r.id, this.hitCount(r.id) + 1);
  }
}
