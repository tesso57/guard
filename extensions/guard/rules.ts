/**
 * 利用者の判断を規則として記憶する。
 *
 * スコープ: session(pi のセッション記録) / project / global / repo(.pi/guard.json、信頼済みのみ・deny/ask 限定)
 * 優先順位はスコープの広さではなく判定の厳しさ: deny > ask > allow
 * bash の allow は「すべてのサブコマンドが一致」かつ「動的要素なし」のときだけ適用する。
 */
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { DATA_DIR } from "./config.ts";
import type { Parsed } from "./shell.ts";
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
  /** session 規則が作られた cwd。違う cwd では当てない */
  cwd?: string;
  createdAt: string;
  expiresAt?: string;
  hits: number;
  /** 判断したときの model と危険度(ドリフト調査用) */
  model?: string;
  risk?: number;
  note?: string;
};

const SESSION_ENTRY ="guard-rule";

/** 前方一致で許すと危ないコマンド。これらは引数まで完全一致の規則にする */
const EXACT_ONLY: string[][] = [
  ["rm"], ["rmdir"], ["mv"], ["dd"], ["chmod"], ["chown"], ["kill"], ["pkill"], ["killall"], ["truncate"], ["shred"],
  ["git", "push"], ["git", "reset"], ["git", "clean"], ["git", "checkout"], ["git", "restore"], ["git", "rebase"], ["git", "branch"],
  ["curl"], ["wget"], ["ssh"], ["scp"], ["rsync"], ["docker"], ["kubectl"], ["terraform"], ["npm", "publish"], ["cargo", "publish"],
];

export function newId(): string {
  return randomBytes(3).toString("hex");
}

export function describeMatch(tool: string, m: Match): string {
  switch (m.kind) {
    case "argv": return `${m.prefix.join(" ")} …`;
    case "argv-exact": return m.argv.join(" ");
    case "path": return `${tool} ${m.path}`;
    case "tool": return `${tool}(すべての入力)`;
  }
}

/**
 * 承認したい呼び出しから規則のパターンを導く。導けない(安全に一般化できない)なら undefined。
 * 例: npm test -- foo → ["npm","test"] / rm a.txt → 完全一致 / python x.py → 不可
 */
export function derivePatterns(tool: string, input: any, cwd: string, parsed?: Parsed): Match[] | undefined {
  if (tool === "bash") {
    if (!parsed || !parsed.ok || parsed.dynamic.length || !parsed.subcommands.length) return undefined;
    const out: Match[] = [];
    for (const a of parsed.subcommands) {
      const exact = EXACT_ONLY.some((p) => p.every((t, i) => a[i] === t));
      let m: Match;
      if (exact || parsed.writes.length) m = { kind: "argv-exact", argv: a };
      else {
        const prefix = a[1] && /^[a-z][\w:.-]*$/.test(a[1]) ? a.slice(0, 2) : a.slice(0, 1);
        m = { kind: "argv", prefix };
      }
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

/** 規則が一致する例・一致しない例(ダイアログ表示用) */
export function examples(m: Match): { yes: string; no: string } | undefined {
  if (m.kind === "argv") return { yes: `${m.prefix.join(" ")} --foo`, no: m.prefix.length > 1 ? `${m.prefix[0]} publish` : `${m.prefix[0]}x` };
  if (m.kind === "argv-exact") return { yes: m.argv.join(" "), no: `${m.argv.join(" ")} --other` };
  return undefined;
}

function matchArgv(m: Match, a: string[]): boolean {
  if (m.kind === "argv") return m.prefix.every((t, i) => a[i] === t);
  if (m.kind === "argv-exact") return m.argv.length === a.length && m.argv.every((t, i) => a[i] === t);
  return false;
}

function matches(r: Rule, tool: string, input: any, cwd: string, parsed: Parsed | undefined, mode: "any" | "all"): boolean {
  if (r.tool !== tool) return false;
  if (r.scope === "session" && r.cwd && r.cwd !== cwd) return false;
  if (r.expiresAt && Date.parse(r.expiresAt) < Date.now()) return false;
  const m = r.match;
  if (m.kind === "tool") return true;
  if (m.kind === "path") {
    const { reads, writes } = inputPaths(tool, input, cwd, parsed);
    const ps = [...reads, ...writes];
    return mode === "any" ? ps.includes(m.path) : ps.length > 0 && ps.every((p) => p === m.path);
  }
  if (!parsed) return false;
  return mode === "any" ? parsed.subcommands.some((a) => matchArgv(m, a)) : false;
}

function readJsonl(file: string): Rule[] {
  try {
    return readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

function writeJsonl(file: string, rules: Rule[]) {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, rules.map((r) => JSON.stringify(r)).join("\n") + (rules.length ? "\n" : ""), { mode: 0o600 });
  renameSync(tmp, file);
}

function projectFile(cwd: string): string {
  const h = createHash("sha256").update(cwd).digest("hex").slice(0, 16);
  return join(DATA_DIR, "projects", `${basename(cwd).replace(/[^\w.-]/g, "_")}-${h}.jsonl`);
}

export class RuleStore {
  global: Rule[] = [];
  project: Rule[] = [];
  repo: Rule[] = [];
  /** セッション記録から再構築した規則 + まだ記録に現れていない追加分 */
  private sessionFromBranch: Rule[] = [];
  private sessionPending: Rule[] = [];
  private sessionHits = new Map<string, number>();
  cwd = "";

  load(cwd: string, trusted: boolean) {
    this.cwd = cwd;
    this.global = readJsonl(join(DATA_DIR, "rules.jsonl"));
    this.project = readJsonl(projectFile(cwd));
    this.repo = [];
    if (trusted) {
      try {
        const cfg = JSON.parse(readFileSync(join(cwd, ".pi", "guard.json"), "utf8"));
        // リポジトリからは deny / ask だけを受け付ける(allow を持ち込ませない)
        for (const d of ["deny", "ask"] as const)
          for (const p of cfg[d] ?? [])
            this.repo.push({ id: `repo-${d}-${p}`, decision: d, tool: "bash", match: { kind: "argv", prefix: String(p).trim().split(/\s+/) }, scope: "repo", createdAt: "", hits: 0 });
      } catch {
        /* 無ければ何もしない */
      }
    }
  }

  /** pi のセッション記録(現在のブランチ)から session 規則を復元する。/tree で戻れば承認も外れる */
  syncSession(branch: { type: string; customType?: string; data?: any }[]) {
    const rules = new Map<string, Rule>();
    for (const e of branch) {
      if (e.type !== "custom" || e.customType !== SESSION_ENTRY) continue;
      if (e.data?.op === "add") rules.set(e.data.rule.id, e.data.rule);
      if (e.data?.op === "remove") rules.delete(e.data.id);
    }
    this.sessionFromBranch = [...rules.values()];
    this.sessionPending = this.sessionPending.filter((r) => !rules.has(r.id));
  }

  resetSession() {
    this.sessionFromBranch = [];
    this.sessionPending = [];
    this.sessionHits.clear();
  }

  session(): Rule[] {
    return [...this.sessionFromBranch, ...this.sessionPending].map((r) => ({ ...r, hits: this.sessionHits.get(r.id) ?? r.hits }));
  }

  all(): Rule[] {
    return [...this.session(), ...this.repo, ...this.project, ...this.global];
  }

  /** 最も厳しい判定を返す。bash の allow は全サブコマンドが allow 規則に一致した場合のみ */
  find(tool: string, input: any, cwd: string, parsed?: Parsed): { decision: Decision; rules: Rule[] } | undefined {
    const rules = this.all();
    for (const d of ["deny", "ask"] as const) {
      const hit = rules.filter((r) => r.decision === d && matches(r, tool, input, cwd, parsed, "any"));
      if (hit.length) return { decision: d, rules: hit };
    }
    const allows = rules.filter((r) => r.decision === "allow");
    if (tool === "bash") {
      if (!parsed || !parsed.ok || parsed.dynamic.length || !parsed.subcommands.length) return undefined;
      const used: Rule[] = [];
      for (const a of parsed.subcommands) {
        const r = allows.find((x) => x.tool === "bash" && (x.scope !== "session" || !x.cwd || x.cwd === cwd) && (!x.expiresAt || Date.parse(x.expiresAt) >= Date.now()) && matchArgv(x.match, a));
        if (!r) return undefined;
        if (!used.includes(r)) used.push(r);
      }
      return { decision: "allow", rules: used };
    }
    const hit = allows.filter((r) => matches(r, tool, input, cwd, parsed, "all"));
    return hit.length ? { decision: "allow", rules: hit } : undefined;
  }

  /** 判定の参考に model へ渡す、同じツール・近いパターンの過去の判断(最大 5 件) */
  related(tool: string, input: any, cwd: string, parsed?: Parsed): Rule[] {
    const heads = new Set(parsed?.subcommands.map((a) => a[0]) ?? []);
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
    } else if (rule.scope === "project") {
      this.project.push(rule);
      writeJsonl(projectFile(this.cwd), this.project);
    } else if (rule.scope === "global") {
      this.global.push(rule);
      writeJsonl(join(DATA_DIR, "rules.jsonl"), this.global);
    }
  }

  remove(id: string, appendEntry: (type: string, data: unknown) => void): Rule | undefined {
    const s = this.session().find((r) => r.id === id);
    if (s) {
      this.sessionPending = this.sessionPending.filter((r) => r.id !== id);
      this.sessionFromBranch = this.sessionFromBranch.filter((r) => r.id !== id);
      appendEntry(SESSION_ENTRY, { op: "remove", id });
      return s;
    }
    for (const scope of ["project", "global"] as const) {
      const list = this[scope];
      const r = list.find((x) => x.id === id);
      if (r) {
        this[scope] = list.filter((x) => x.id !== id);
        writeJsonl(scope === "project" ? projectFile(this.cwd) : join(DATA_DIR, "rules.jsonl"), this[scope]);
        return r;
      }
    }
    return undefined;
  }

  hit(rules: Rule[]) {
    let dirty: ("project" | "global")[] = [];
    for (const r of rules) {
      if (r.scope === "session") this.sessionHits.set(r.id, (this.sessionHits.get(r.id) ?? r.hits) + 1);
      else if (r.scope === "project" || r.scope === "global") {
        const x = this[r.scope].find((y) => y.id === r.id);
        if (x) { x.hits++; dirty.push(r.scope); }
      }
    }
    if (dirty.includes("project")) writeJsonl(projectFile(this.cwd), this.project);
    if (dirty.includes("global")) writeJsonl(join(DATA_DIR, "rules.jsonl"), this.global);
  }
}
