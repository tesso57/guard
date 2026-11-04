import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { describeMatch, examples, type Match } from "./rules.ts";

export type Choice = { decision: "allow" | "deny"; scope: "once" | "session" | "project" | "global"; reason?: string };

export type DialogSpec = {
  title: string;
  body: string;
  tool: string;
  patterns?: Match[];
  /** 記憶して許可を出すか(高リスク・ask 規則・パターン不可なら false) */
  rememberAllow: boolean;
  /** 全体スコープの許可を出すか(低リスク区分のみ) */
  globalAllow: boolean;
  projectName: string;
};

const ONCE = "許可(今回だけ)";
const DENY = "拒否";

/** 2 段構成の確認ダイアログ。Esc・タイムアウト・未選択は「拒否(今回だけ)」 */
export async function confirmDialog(ctx: ExtensionContext, s: DialogSpec): Promise<Choice> {
  const label = s.patterns?.map((p) => describeMatch(s.tool, p)).join(" / ");
  const sessionOpt = label ? `許可(このセッション中: ${label})` : undefined;
  const rememberOpt = "許可して記憶… ▸";
  const denyRememberOpt = "拒否して記憶… ▸";
  const opts = [ONCE];
  if (sessionOpt && s.rememberAllow) opts.push(sessionOpt);
  if (label && s.rememberAllow) opts.push(rememberOpt);
  opts.push(DENY);
  if (label) opts.push(denyRememberOpt);

  for (;;) {
    const pick = await ctx.ui.select(`${s.title}\n\n${s.body}`, opts);
    if (pick === ONCE) return { decision: "allow", scope: "once" };
    if (pick === sessionOpt) return { decision: "allow", scope: "session" };
    if (pick === rememberOpt || pick === denyRememberOpt) {
      const decision = pick === rememberOpt ? "allow" : "deny";
      const ex = s.patterns?.map((p) => examples(p)).filter(Boolean)[0];
      const scopes = [`このプロジェクト(${s.projectName})`];
      // deny はどのスコープでも安全側なので常に全体を出す
      if (decision === "deny" || s.globalAllow) scopes.push("全体");
      if (decision === "deny") scopes.push("このセッション中");
      scopes.push("← 戻る");
      const head = `${decision === "allow" ? "許可" : "拒否"}として記憶: ${label}` + (ex ? `\n一致: ${ex.yes}\n不一致: ${ex.no}` : "");
      const sc = await ctx.ui.select(head, scopes);
      if (!sc || sc === "← 戻る") continue;
      const scope = sc === "全体" ? "global" : sc === "このセッション中" ? "session" : "project";
      let reason: string | undefined;
      if (decision === "deny") reason = (await ctx.ui.input("拒否の理由(任意・エージェントに伝えます)", ""))?.trim() || undefined;
      return { decision, scope, reason };
    }
    if (pick === DENY) {
      const reason = (await ctx.ui.input("拒否の理由(任意・エージェントに伝えます)", ""))?.trim() || undefined;
      return { decision: "deny", scope: "once", reason };
    }
    return { decision: "deny", scope: "once" };
  }
}

/** 確認ダイアログ用の要約。edit は差分、write は本文の先頭と末尾を見せる */
export function preview(tool: string, input: any): string {
  const cut = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);
  if (tool === "bash" || tool === "powershell") return cut(String(input?.command ?? ""), 1500);
  if (tool === "edit" && Array.isArray(input?.edits)) {
    const parts = input.edits.slice(0, 3).map((e: any) => `- ${cut(String(e.oldText ?? ""), 200)}\n+ ${cut(String(e.newText ?? ""), 200)}`);
    return `edit ${input.path}\n${parts.join("\n")}${input.edits.length > 3 ? `\n…(他 ${input.edits.length - 3} 箇所)` : ""}`;
  }
  if (tool === "write" && typeof input?.content === "string") {
    const c: string = input.content;
    return `write ${input.path} (${c.length} chars)\n${c.length > 600 ? `${c.slice(0, 300)}\n…\n${c.slice(-300)}` : c}`;
  }
  if (typeof input?.path === "string") return `${tool} ${input.path}`;
  return `${tool} ${cut(JSON.stringify(input), 500)}`;
}
