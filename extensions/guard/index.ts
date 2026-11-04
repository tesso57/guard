/**
 * guard — ツール呼び出しの危険度を実行前に判定する pi 拡張
 *
 * 評価順序:
 *   ① hard-deny(保護パス・明白な破壊)        → block(上書き不可)
 *   ② deny / ask 規則(全スコープ)             → block / confirm
 *   ③ allow 規則に全サブコマンドが一致          → 軽量チェック(流出・意図外・判定者操作)だけ model に聞く
 *   ④ 機密パス                                  → confirm
 *   ⑤ 安全リスト(読み取り専用 bash・cwd 内の通常ファイル編集)→ allow(model 省略)
 *   ⑥ skipModelTools(read/grep/find/ls)        → allow
 *   ⑦ Decisions API(意図・履歴・過去の判断を文脈に)→ allow / confirm / block
 *   失敗・キー未設定は confirm(UI なしなら block)
 *
 * 詳細は README.md を参照。
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { basename } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { audit, tail } from "./audit.ts";
import { type Config, loadConfig } from "./config.ts";
import { buildRequest, callDecisions, evaluate, type ModelVerdict } from "./judge.ts";
import { protectedRoots, resolvePath } from "./paths.ts";
import { hardDeny, inputPaths, safeAllow, sensitive } from "./policy.ts";
import { type Decision, derivePatterns, describeMatch, type Match, newId, type Rule, RuleStore, type Scope } from "./rules.ts";
import { type Parsed, parseShell } from "./shell.ts";
import { confirmDialog, preview } from "./ui.ts";

const STATE_ENTRY = "guard-state";
const LOW_RISK_CATEGORIES = ["read_only", "build_test", "project_edit"];

type Assessment = {
  action: "allow" | "confirm" | "block";
  source: "hard-deny" | "rule-deny" | "rule-ask" | "rule-allow" | "sensitive" | "safe" | "skip" | "model" | "error";
  reasons: string[];
  verdict?: ModelVerdict;
  patterns?: Match[];
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

export default function (pi: ExtensionAPI) {
  let cfg: Config = loadConfig();
  const store = new RuleStore();
  let enabled = true;
  const pending = new Map<string, { hash: string; p: Promise<Assessment> }>();
  const judged = new Map<string, string>();
  /** このセッション中に edit されたファイル(bash で実行されたら中身を判定に添付する) */
  const touched = new Set<string>();
  const promoted = new Set<string>();
  let consecutiveBlocks = 0;
  let totalBlocks = 0;

  const append = (type: string, data: unknown) => pi.appendEntry(type, data);

  /** 判定 API に渡す文脈を、現在のセッションブランチから組み立てる */
  function context(ctx: ExtensionContext, callId: string, tool: string, parsed?: Parsed) {
    const users: string[] = [];
    const calls: { id: string; name: string; arguments: any }[] = [];
    for (const e of ctx.sessionManager.getBranch() as any[]) {
      if (e.type !== "message") continue;
      const m = e.message;
      if (m?.role === "user") users.push(textOf(m.content));
      if (m?.role === "assistant" && Array.isArray(m.content))
        for (const c of m.content) if (c?.type === "toolCall" && c.id !== callId) calls.push({ id: c.id, name: c.name, arguments: c.arguments });
    }
    // bash が触るパスのうち、このセッションで書かれた/編集されたファイルの中身を添付(write → bash の多段攻撃対策)
    const attached: Record<string, string> = {};
    if (tool === "bash" && parsed) {
      const written = new Map<string, string>();
      for (const c of calls) if (c.name === "write" && typeof c.arguments?.path === "string") written.set(resolvePath(ctx.cwd, c.arguments.path), String(c.arguments.content ?? ""));
      for (const tok of parsed.subcommands.flat()) {
        const p = resolvePath(ctx.cwd, tok);
        if (attached[p] !== undefined) continue;
        if (touched.has(p) && existsSync(p)) {
          try { attached[p] = readFileSync(p, "utf8"); } catch { /* 読めなければ添付しない */ }
        } else if (written.has(p)) attached[p] = written.get(p)!;
      }
    }
    return { userMessages: users.slice(-cfg.contextUserMessages), history: calls.slice(-cfg.contextToolCalls), attachedFiles: attached };
  }

  async function assess(callId: string, tool: string, input: any, ctx: ExtensionContext, signal?: AbortSignal): Promise<Assessment> {
    const parsed = tool === "bash" ? parseShell(String(input?.command ?? "")) : undefined;
    const roots = protectedRoots(ctx.cwd, ctx.sessionManager.getSessionDir());
    const base = { rememberAllow: false, globalAllow: false };

    const hard = hardDeny(tool, input, ctx.cwd, roots, parsed);
    if (hard) return { ...base, action: "block", source: "hard-deny", reasons: [hard] };

    store.syncSession(ctx.sessionManager.getBranch() as any[]);
    const rule = store.find(tool, input, ctx.cwd, parsed);
    const patterns = derivePatterns(tool, input, ctx.cwd, parsed);
    if (rule?.decision === "deny") return { ...base, action: "block", source: "rule-deny", reasons: rule.rules.map((r) => `${r.scope} の拒否規則: ${describeMatch(r.tool, r.match)}`), rules: rule.rules };
    if (rule?.decision === "ask") return { ...base, action: "confirm", source: "rule-ask", reasons: rule.rules.map((r) => `${r.scope} の確認規則: ${describeMatch(r.tool, r.match)}`), rules: rule.rules, patterns };

    const ctxInfo = () => ({ ...context(ctx, callId, tool, parsed), sessionId: ctx.sessionManager.getSessionId() });

    if (rule?.decision === "allow") {
      const reasons = rule.rules.map((r) => `${r.scope} の許可規則: ${describeMatch(r.tool, r.match)}`);
      if (!process.env.OPENAI_API_KEY) return { ...base, action: "allow", source: "rule-allow", reasons: [...reasons, "軽量チェック省略(キー未設定)"], rules: rule.rules };
      try {
        const { body, truncated } = buildRequest(cfg, { tool, input, cwd: ctx.cwd, callId, past: [], light: true, ...ctxInfo() });
        const v = evaluate(cfg, await callDecisions(cfg, body, signal), { light: true, truncated });
        if (v.action === "allow") return { ...base, action: "allow", source: "rule-allow", reasons, rules: rule.rules, verdict: v };
        return { ...base, action: "confirm", source: "model", reasons: [...v.reasons, "(許可規則があるが軽量チェックに該当)"], verdict: v, patterns };
      } catch (e: any) {
        // 利用者が明示的に許可したパターンなので、軽量チェックの失敗では止めない
        return { ...base, action: "allow", source: "rule-allow", reasons: [...reasons, `軽量チェック失敗: ${e.message}`], rules: rule.rules };
      }
    }

    const sens = sensitive(tool, input, ctx.cwd, parsed);
    if (sens) return { ...base, action: "confirm", source: "sensitive", reasons: [`機密情報の可能性: ${sens}`], patterns, rememberAllow: !!patterns };
    if (safeAllow(tool, input, ctx.cwd, parsed)) return { ...base, action: "allow", source: "safe", reasons: [] };
    if (cfg.skipModelTools.includes(tool)) return { ...base, action: "allow", source: "skip", reasons: [] };

    try {
      const past = store.related(tool, input, ctx.cwd, parsed);
      const { body, truncated } = buildRequest(cfg, { tool, input, cwd: ctx.cwd, callId, past, light: false, ...ctxInfo() });
      const v = evaluate(cfg, await callDecisions(cfg, body, signal), { light: false, truncated });
      const t = cfg.thresholds;
      const rememberAllow =
        !!patterns && v.action !== "block" && (v.pHigh ?? 1) < t.confirmPHigh && (v.exfiltration ?? 1) < t.confirmExfil &&
        (v.addressesEvaluator ?? 1) < t.confirmAddressesEvaluator && !v.truncated;
      const globalAllow = rememberAllow && LOW_RISK_CATEGORIES.includes(v.category ?? "") && (v.risk ?? 9) < t.confirmScore;
      return { action: v.action, source: "model", reasons: v.reasons, verdict: v, patterns, rememberAllow, globalAllow };
    } catch (e: any) {
      if (signal?.aborted) throw e;
      return { ...base, action: "confirm", source: "error", reasons: [`判定できませんでした: ${e.message}`], patterns };
    }
  }

  function status(ctx: ExtensionContext, text: string) {
    ctx.ui.setStatus("guard", text);
  }

  function addRule(decision: Decision, scope: Exclude<Scope, "repo">, tool: string, match: Match, cwd: string, risk?: number, note?: string): Rule {
    const now = new Date();
    const rule: Rule = {
      id: newId(), decision, tool, match, scope, createdAt: now.toISOString(), hits: 0, model: cfg.model, risk, note,
      ...(scope === "session" ? { cwd } : {}),
      ...(decision === "allow" && scope !== "session" ? { expiresAt: new Date(now.getTime() + cfg.allowRuleTtlDays * 86400_000).toISOString() } : {}),
    };
    store.add(rule, append);
    return rule;
  }

  function blockResult(reason: string, terminate = false) {
    return { block: true as const, reason: `guard: ${reason}. Do not retry this call or try to work around the check; choose a safer approach or ask the user.`, ...(terminate ? { terminate: true } : {}) };
  }

  pi.on("session_start", async (_e, ctx) => {
    cfg = loadConfig();
    store.load(ctx.cwd, ctx.isProjectTrusted());
    store.resetSession();
    store.syncSession(ctx.sessionManager.getBranch() as any[]);
    enabled = true;
    for (const e of ctx.sessionManager.getBranch() as any[]) if (e.type === "custom" && e.customType === STATE_ENTRY) enabled = e.data?.enabled !== false;
    pending.clear(); judged.clear(); touched.clear(); promoted.clear();
    consecutiveBlocks = totalBlocks = 0;
    if (cfg.disabled) return status(ctx, "guard: disabled");
    if (!process.env.OPENAI_API_KEY) {
      ctx.ui.notify("guard: OPENAI_API_KEY が未設定です。model 判定が必要な呼び出しはすべて確認に回します", "warning");
      return status(ctx, "guard: no key");
    }
    status(ctx, enabled ? `guard: ${cfg.model}` : "guard: off");
  });

  // アシスタントがツール呼び出しを出した時点で、全呼び出しの判定を並列に開始する
  // (pi は兄弟呼び出しの tool_call を逐次処理するため、待ち時間が直列に積み上がるのを防ぐ)
  pi.on("message_end", async (event, ctx) => {
    if (cfg.disabled || !enabled) return;
    const m: any = event.message;
    if (m?.role !== "assistant" || !Array.isArray(m.content)) return;
    for (const c of m.content) {
      if (c?.type !== "toolCall" || pending.has(c.id)) continue;
      const p = assess(c.id, c.name, c.arguments, ctx);
      p.catch(() => {});
      pending.set(c.id, { hash: stableHash([c.name, c.arguments]), p });
    }
  });

  pi.on("tool_call", async (event, ctx) => {
    if (cfg.disabled || !enabled) return;
    const tool = event.toolName;
    const input: any = event.input;
    const hash = stableHash([tool, input]);
    const pre = pending.get(event.toolCallId);
    pending.delete(event.toolCallId);

    status(ctx, `guard: judging ${tool}…`);
    let a: Assessment;
    try {
      // 先行判定の後に他の拡張が入力を書き換えていたら判定し直す
      a = pre && pre.hash === hash ? await pre.p : await assess(event.toolCallId, tool, input, ctx, ctx.signal);
    } catch (e: any) {
      a = { action: "confirm", source: "error", reasons: [`判定できませんでした: ${e.message}`], rememberAllow: false, globalAllow: false };
    }
    judged.set(event.toolCallId, hash);
    const what = preview(tool, input);
    const session = ctx.sessionManager.getSessionId();
    const risk = a.verdict?.risk;
    const tag = `${a.source}${risk !== undefined ? ` ${risk.toFixed(1)}` : ""}${a.verdict?.category ? ` ${a.verdict.category}` : ""}`;
    const rec = { session, tool, preview: what, action: a.action, source: a.source, reasons: a.reasons, risk, ruleIds: a.rules?.map((r) => r.id) };

    const onAllowed = () => {
      consecutiveBlocks = 0;
      if (tool === "edit" || tool === "write") for (const p of inputPaths(tool, input, ctx.cwd).writes) touched.add(p);
      if (a.rules && a.source === "rule-allow") {
        store.hit(a.rules);
        for (const r of store.session()) {
          if (a.rules.some((x) => x.id === r.id) && r.hits >= 3 && !promoted.has(r.id)) {
            promoted.add(r.id);
            ctx.ui.notify(`guard: 「${describeMatch(r.tool, r.match)}」をこのセッションで ${r.hits} 回許可しました。/guard rules promote ${r.id} project で記憶できます`, "info");
          }
        }
      }
    };
    const onBlocked = (reason: string) => {
      consecutiveBlocks++;
      totalBlocks++;
      const escalate = consecutiveBlocks >= cfg.escalateConsecutive || totalBlocks >= cfg.escalateTotal;
      if (escalate) {
        ctx.ui.notify(`guard: ブロックが続いています(連続 ${consecutiveBlocks} / 合計 ${totalBlocks})。エージェントを停止しました`, "error");
        consecutiveBlocks = 0;
      }
      return blockResult(reason, escalate);
    };

    if (a.action === "allow") {
      status(ctx, `guard: ${tool} ok (${tag})`);
      audit({ ...rec, final: "run" });
      onAllowed();
      return;
    }
    if (a.action === "block") {
      status(ctx, `guard: ${tool} BLOCK (${tag})`);
      ctx.ui.notify(`guard: ブロック ${tool} — ${a.reasons.join("; ")}`, "error");
      audit({ ...rec, final: "blocked" });
      return onBlocked(a.source === "hard-deny" ? `blocked (${a.reasons[0]})` : a.source === "rule-deny" ? "blocked by the user's deny rule" : "blocked as too dangerous");
    }

    // confirm
    status(ctx, `guard: ${tool} confirm (${tag})`);
    if (!ctx.hasUI) {
      audit({ ...rec, final: "blocked", choice: "no-ui" });
      return onBlocked("requires user confirmation, but no UI is available");
    }
    const v = a.verdict;
    const head = `${tool}: ${v?.risk !== undefined ? `危険度 ${v.risk.toFixed(2)}/4` : "確認"}${v?.category ? ` [${v.category}]` : ""}`;
    const choice = await confirmDialog(ctx, {
      title: head,
      body: `${what}\n\n理由: ${a.reasons.join("; ") || "-"}`,
      tool,
      patterns: a.patterns,
      rememberAllow: a.rememberAllow,
      globalAllow: a.globalAllow,
      projectName: basename(ctx.cwd),
    });
    const choiceTag = `${choice.decision}:${choice.scope}`;
    const saved: Rule[] = [];
    if (choice.scope !== "once" && a.patterns)
      for (const m of a.patterns) saved.push(addRule(choice.decision, choice.scope, tool, m, ctx.cwd, v?.risk, choice.reason));
    if (saved.length)
      ctx.ui.notify(`guard: ${choice.scope} に${choice.decision === "allow" ? "許可" : "拒否"}規則を保存: ${saved.map((r) => `${describeMatch(r.tool, r.match)} [${r.id}]`).join(", ")}(取り消し: /guard rules rm <id>)`, "info");
    audit({ ...rec, final: choice.decision === "allow" ? "run" : "blocked", choice: choiceTag, ruleIds: [...(rec.ruleIds ?? []), ...saved.map((r) => r.id)] });

    if (choice.decision === "allow") {
      onAllowed();
      return;
    }
    consecutiveBlocks = 0; // 利用者自身の拒否はエスカレーションの対象外
    const why = choice.reason ?`the user denied this call: ${choice.reason}` : "the user denied this call";
    return blockResult(why);
  });

  // 判定した入力と実際に実行される入力のずれ(後続の拡張による書き換え)を検出する
  pi.on("tool_execution_start", async (event, ctx) => {
    const h = judged.get(event.toolCallId);
    if (!h) return;
    judged.delete(event.toolCallId);
    if (h !== stableHash([event.toolName, event.args])) {
      audit({ session: ctx.sessionManager.getSessionId(), tool: event.toolName, preview: preview(event.toolName, event.args), action: "allow", source: "drift", reasons: ["判定後に入力が書き換えられた"], event: "drift" });
      ctx.ui.notify(`guard: ${event.toolName} の入力が判定後に他の拡張で書き換えられました。guard を最後にロードしてください`, "warning");
    }
  });

  pi.registerCommand("guard", {
    description: "危険度判定: /guard [on|off|check <cmd>|rules [rm|promote|add]|log [n]|reload]",
    handler: async (args, ctx) => {
      const [sub, ...rest] = (args ?? "").trim().split(/\s+/).filter(Boolean);
      const say = (m: string, t: "info" | "warning" | "error" = "info") => ctx.ui.notify(m, t);

      if (!sub) {
        const c = store.all();
        return say(
          `guard: ${cfg.disabled ? "disabled" : enabled ? "on" : "off"} | model=${cfg.model} key=${process.env.OPENAI_API_KEY ? "set" : "unset"} | ` +
            `rules: session ${c.filter((r) => r.scope === "session").length} / project ${store.project.length} / global ${store.global.length} / repo ${store.repo.length} | blocks ${totalBlocks}`,
        );
      }
      if (sub === "on" || sub === "off") {
        enabled = sub === "on";
        append(STATE_ENTRY, { enabled });
        status(ctx, enabled ? `guard: ${cfg.model}` : "guard: off");
        return say(`guard: ${sub}(このセッション)`);
      }
      if (sub === "reload") {
        cfg = loadConfig();
        store.load(ctx.cwd, ctx.isProjectTrusted());
        return say("guard: 設定と規則を再読み込みしました");
      }
      if (sub === "log") {
        const n = Number(rest[0] ?? 15) || 15;
        const lines = tail(n).map((r) => `${r.ts?.slice(5, 19).replace("T", " ")} ${r.final ?? r.event ?? ""} ${r.source}${r.choice ? `→${r.choice}` : ""} ${r.preview.split("\n")[0].slice(0, 80)}${r.reasons.length ? ` — ${r.reasons.join("; ").slice(0, 120)}` : ""}`);
        return say(lines.length ? lines.join("\n") : "guard: 監査ログは空です");
      }
      if (sub === "rules") {
        const op = rest[0] ?? "list";
        if (op === "list") {
          const order: Scope[] = ["session", "repo", "project", "global"];
          const lines = store.all().sort((a, b) => order.indexOf(a.scope) - order.indexOf(b.scope))
            .map((r) => `[${r.scope}] ${r.decision.padEnd(5)} ${describeMatch(r.tool, r.match)}  (id ${r.id}, hits ${r.hits}${r.expiresAt ? `, expires ${r.expiresAt.slice(0, 10)}` : ""})`);
          if (!lines.length) return say("guard: 規則はありません");
          if (!ctx.hasUI) return say(lines.join("\n"));
          const pick = await ctx.ui.select("規則(選ぶと削除できます)", [...lines, "閉じる"]);
          const id = pick?.match(/\(id ([^,)]+)/)?.[1];
          if (!id || id.startsWith("repo-")) return id ? say("repo 規則は .pi/guard.json を編集してください", "warning") : undefined;
          if (await ctx.ui.confirm("規則を削除", pick!)) {
            store.remove(id, append);
            say(`guard: 規則 ${id} を削除しました`);
          }
          return;
        }
        if (op === "rm") {
          const r = rest[1] && store.remove(rest[1], append);
          return r ? say(`guard: 削除 ${describeMatch(r.tool, r.match)}`) : say("guard: その id の規則はありません", "warning");
        }
        if (op === "promote") {
          const [id, to] = [rest[1], rest[2]];
          const r = store.all().find((x) => x.id === id);
          if (!r || (to !== "project" && to !== "global")) return say("使い方: /guard rules promote <id> project|global", "warning");
          if (ctx.hasUI && !(await ctx.ui.confirm("規則を昇格", `${describeMatch(r.tool, r.match)} を ${to} に保存しますか?`))) return;
          const nr = addRule(r.decision, to, r.tool, r.match, ctx.cwd, r.risk, r.note);
          if (r.scope === "session") store.remove(r.id, append);
          return say(`guard: ${to} に保存しました [${nr.id}]`);
        }
        if (op === "add") {
          // /guard rules add <allow|deny|ask> <session|project|global> <bash の先頭語…> | tool:<name> | path:<path>
          const [decision, scope, ...pat] = rest.slice(1);
          if (!["allow", "deny", "ask"].includes(decision) || !["session", "project", "global"].includes(scope) || !pat.length)
            return say("使い方: /guard rules add <allow|deny|ask> <session|project|global> <コマンドの先頭語… | tool:<name> | path:<path>>", "warning");
          if (decision === "ask" && scope === "session") return say("ask 規則は project / global のみです", "warning");
          let tool = "bash";
          let match: Match;
          if (pat[0].startsWith("tool:")) { tool = pat[0].slice(5); match = { kind: "tool" }; }
          else if (pat[0].startsWith("path:")) { tool = pat[1] ?? "edit"; match = { kind: "path", path: resolvePath(ctx.cwd, pat[0].slice(5)) }; }
          else match = { kind: "argv", prefix: pat };
          const r = addRule(decision as Decision, scope as "session" | "project" | "global", tool, match, ctx.cwd);
          return say(`guard: ${scope} に ${decision} 規則を追加: ${describeMatch(tool, match)} [${r.id}]`);
        }
        return say("使い方: /guard rules [list|rm <id>|promote <id> project|global|add …]", "warning");
      }
      // それ以外は bash コマンドとして採点だけ行う(/guard check <cmd> または /guard <cmd>)
      const cmd = (sub === "check" ? rest : [sub, ...rest]).join(" ");
      const a = await assess(`risk-check-${Date.now()}`, "bash", { command: cmd }, ctx);
      const v = a.verdict;
      say(
        `${a.action.toUpperCase()} via ${a.source}${v?.risk !== undefined ? ` | risk ${v.risk.toFixed(2)} pHigh ${v.pHigh?.toFixed(2)} conf ${v.confidence?.toFixed(2)} ${v.category ?? ""}` : ""}` +
          `${a.reasons.length ? `\n${a.reasons.join("; ")}` : ""}`,
        a.action === "allow" ? "info" : a.action === "confirm" ? "warning" : "error",
      );
    },
  });
}
