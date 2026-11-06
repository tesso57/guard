import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { describeMatch, examples, type Match } from "./rules.ts";

export type Choice = { decision: "allow" | "deny"; scope: "once" | "session" | "project" | "global"; reason?: string };

export type DialogSpec = {
  title: string;
  body: string;
  tool: string;
  patterns?: Match[];
  /** Patterns a remembered deny would use (command words plus flags). */
  denyPatterns?: Match[];
  /** Offer "allow and remember" (false for high risk, ask rules, or calls without a safe pattern). */
  rememberAllow: boolean;
  /** Offer a global allow (low-risk categories in trusted projects only). */
  globalAllow: boolean;
  projectName: string;
  timeoutMs: number;
};

const ONCE = "Allow (this time only)";
const DENY = "Deny";
const BACK = "← Back";

/** Two-step approval dialog. Esc, timeout or no selection count as "deny this time". */
export async function confirmDialog(ctx: ExtensionContext, s: DialogSpec): Promise<Choice> {
  const opts = { timeout: s.timeoutMs };
  const label = s.patterns?.map((p) => describeMatch(s.tool, p)).join(" / ");
  const denyLabel = s.denyPatterns?.map((p) => describeMatch(s.tool, p)).join(" / ");
  const sessionOpt = label ? `Allow (this session: ${label})` : undefined;
  // Only a trusted read-only call can become a global allow; otherwise the project is the only scope, so no submenu
  const rememberOpt = s.globalAllow ? "Allow and remember… ▸" : `Allow and remember (this project: ${s.projectName})`;
  const denyRememberOpt = "Deny and remember… ▸";
  const options = [ONCE];
  if (sessionOpt && s.rememberAllow) options.push(sessionOpt, rememberOpt);
  options.push(DENY);
  if (denyLabel) options.push(denyRememberOpt);
  const askReason = async () => (await ctx.ui.input("Reason (optional, passed to the agent)", "", opts))?.trim() || undefined;

  for (;;) {
    const pick = await ctx.ui.select(`${s.title}\n\n${s.body}`, options, opts);
    if (pick === ONCE) return { decision: "allow", scope: "once" };
    if (pick === sessionOpt) return { decision: "allow", scope: "session" };
    if (pick === rememberOpt || pick === denyRememberOpt) {
      const decision = pick === rememberOpt ? "allow" : "deny";
      if (decision === "allow" && !s.globalAllow) return { decision, scope: "project" };
      const pats = decision === "allow" ? s.patterns : s.denyPatterns;
      const ex = pats?.map((p) => examples(p)).find(Boolean);
      const scopes = [`This project (${s.projectName})`];
      // A deny is always on the safe side, so every scope is offered for it
      if (decision === "deny" || s.globalAllow) scopes.push("Global");
      if (decision === "deny") scopes.push("This session");
      scopes.push(BACK);
      const head = `Remember as ${decision}: ${decision === "allow" ? label : denyLabel}` + (ex ? `\nmatches: ${ex.yes}\ndoes not match: ${ex.no}` : "");
      const sc = await ctx.ui.select(head, scopes, opts);
      if (!sc) return { decision: "deny", scope: "once" };
      if (sc === BACK) continue;
      const scope = sc === "Global" ? "global" : sc === "This session" ? "session" : "project";
      return { decision, scope, reason: decision === "deny" ? await askReason() : undefined };
    }
    if (pick === DENY) return { decision: "deny", scope: "once", reason: await askReason() };
    return { decision: "deny", scope: "once" };
  }
}

/** Summary for the dialog: diffs for edit, head and tail of the content for write. */
export function preview(tool: string, input: any): string {
  const cut = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);
  if (tool === "bash" || tool === "powershell") return cut(String(input?.command ?? ""), 1500);
  if (tool === "edit" && Array.isArray(input?.edits)) {
    const parts = input.edits.slice(0, 3).map((e: any) => `- ${cut(String(e?.oldText ?? ""), 200)}\n+ ${cut(String(e?.newText ?? ""), 200)}`);
    return `edit ${input.path}\n${parts.join("\n")}${input.edits.length > 3 ? `\n… (${input.edits.length - 3} more)` : ""}`;
  }
  if (tool === "write" && typeof input?.content === "string") {
    const c: string = input.content;
    return `write ${input.path} (${c.length} chars)\n${c.length > 600 ? `${c.slice(0, 300)}\n…\n${c.slice(-300)}` : c}`;
  }
  if (typeof input?.path === "string") return `${tool} ${input.path}`;
  return `${tool} ${cut(JSON.stringify(input), 500)}`;
}
