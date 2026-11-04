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
import { normalizeArgv, type Parsed } from "./shell.ts";
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
/** Subcommands whose next word picks an arbitrary script, so the rule needs three words. */
const SCRIPT_SUBCOMMANDS = new Set(["run", "run-script", "exec", "x", "dlx"]);

const isExactOnly = (a: string[]) => EXACT_ONLY.some((p) => p.every((t, i) => a[i] === t));

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

/**
 * Derives rule patterns from a call the user wants to remember. Returns undefined when it cannot be generalized safely.
 * npm test -- foo → ["npm","test"] / npm run lint → ["npm","run","lint"] / rm a.txt → exact / git -C x status → ["git","status"] / python x.py → none
 */
export function derivePatterns(tool: string, input: any, cwd: string, parsed?: Parsed): Match[] | undefined {
  if (tool === "bash") {
    if (!parsed || !parsed.ok || parsed.dynamic.length || !parsed.subcommands.length) return undefined;
    const out: Match[] = [];
    for (const raw of parsed.subcommands) {
      const { argv: a, unknownOption } = normalizeArgv(raw);
      const sub = a[1];
      const word = (t?: string) => !!t && /^[a-z][\w:.@/-]*$/i.test(t) && !t.startsWith("-");
      let m: Match;
      if (unknownOption || isExactOnly(a) || parsed.writes.length || !word(sub)) m = { kind: "argv-exact", argv: a };
      else if (SCRIPT_SUBCOMMANDS.has(sub)) m = word(a[2]) ? { kind: "argv", prefix: a.slice(0, 3) } : { kind: "argv-exact", argv: a };
      else m = { kind: "argv", prefix: a.slice(0, 2) };
      if (!out.some((x) => JSON.stringify(x) === JSON.stringify(m))) out.push(m);
    }
    return out;
  }
  const { reads, writes } = inputPaths(tool, input, cwd);
  const paths = [...reads, ...writes];
  if (paths.length === 1) return [{ kind: "path", path: paths[0] }];
  if (paths.length === 0 && !["bash", "edit", "write", "read"].includes(tool)) return [{ kind: "tool" }];
  return undefined;
}

/** An example the rule matches and one it does not, for the dialog. */
export function examples(m: Match): { yes: string; no: string } | undefined {
  if (m.kind === "argv") return { yes: `${m.prefix.join(" ")} --foo`, no: m.prefix.length > 1 ? `${m.prefix.slice(0, -1).join(" ")} publish` : `${m.prefix[0]}x` };
  if (m.kind === "argv-exact") return { yes: m.argv.join(" "), no: `${m.argv.join(" ")} --other` };
  return undefined;
}

/** Strict matching for allow rules. Prefix rules never cover EXACT_ONLY commands. */
function allowMatchesArgv(m: Match, raw: string[]): boolean {
  const a = normalizeArgv(raw).argv;
  if (m.kind === "argv-exact") return m.argv.length === a.length && m.argv.every((t, i) => a[i] === t);
  if (m.kind === "argv") return !isExactOnly(a) && m.prefix.every((t, i) => a[i] === t);
  return false;
}

const FLAG_ALIASES: Record<string, string[]> = {
  "--force": ["-f", "--force-with-lease", "--force-if-includes"],
  "-f": ["--force", "--force-with-lease", "--force-if-includes"],
  "--recursive": ["-r", "-R"],
  "-r": ["-R", "--recursive"],
  "-R": ["-r", "--recursive"],
  "--delete": ["-d", "-D"],
  "-d": ["--delete", "-D"],
  "-D": ["-d", "--delete"],
  "--all": ["-a"],
  "-a": ["--all"],
};

/**
 * Loose matching for deny and ask rules: the rule's words must prefix the command's words (flags ignored),
 * and each flag in the rule must be present in any spelling (`--force` also matches `-f`, `-fu`, `--force-with-lease`).
 */
function strictMatchesArgv(m: Match, raw: string[]): boolean {
  const ruleTokens = m.kind === "argv" ? m.prefix : m.kind === "argv-exact" ? m.argv : undefined;
  if (!ruleTokens) return false;
  const a = normalizeArgv(raw).argv;
  const words = a.filter((t, i) => i === 0 || !t.startsWith("-"));
  const ruleWords = ruleTokens.filter((t, i) => i === 0 || !t.startsWith("-"));
  if (!ruleWords.every((t, i) => words[i] === t)) return false;
  const present = (f: string) =>
    a.some((t) => t === f || t.startsWith(`${f}=`) || (f.length === 2 && /^-[A-Za-z]+$/.test(t) && t.includes(f[1])));
  return ruleTokens.filter((t, i) => i > 0 && t.startsWith("-")).every((f) => present(f) || (FLAG_ALIASES[f] ?? []).some(present));
}

function matchesNonBash(r: Rule, tool: string, input: any, cwd: string, mode: "any" | "all"): boolean {
  const m = r.match;
  if (m.kind === "tool") return true;
  if (m.kind !== "path") return false;
  const { reads, writes } = inputPaths(tool, input, cwd);
  const ps = [...reads, ...writes];
  return mode === "any" ? ps.includes(m.path) : ps.length > 0 && ps.every((p) => p === m.path);
}

function readJsonl(file: string): Rule[] {
  try {
    return readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

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
        if (Date.now() - statSync(lock).mtimeMs > 10_000) rmSync(lock, { recursive: true, force: true });
      } catch { /* the lock disappeared in the meantime */ }
      if (Date.now() > deadline) throw new Error(`guard: could not lock ${file}`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    }
  }
  try {
    const next = fn(readJsonl(file));
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, next.map((r) => JSON.stringify(r)).join("\n") + (next.length ? "\n" : ""), { mode: 0o600 });
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
        this[scope] = readJsonl(f[scope]);
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
    for (const d of ["deny", "ask"] as const) {
      const hit = rules.filter((r) => r.decision === d && (tool === "bash" ? !!parsed && parsed.subcommands.some((a) => strictMatchesArgv(r.match, a)) : matchesNonBash(r, tool, input, cwd, "any")));
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
    const heads = new Set(parsed?.subcommands.map((a) => normalizeArgv(a).argv[0]) ?? []);
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
      this[rule.scope] = updateFile(this.files()[rule.scope], (rs) => [...rs, rule]);
      this.mtimes.set(rule.scope, statSync(this.files()[rule.scope]).mtimeMs);
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
