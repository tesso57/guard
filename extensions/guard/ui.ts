import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { describeMatch, examples, type Match } from "./rules.ts";
import { extractEdits } from "./edits.ts";

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

/** Prevent terminal control sequences and bidirectional controls from disguising displayed input. */
export function displayText(text: string): string {
  return text.replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
const inline = (text: string) => displayText(text).replace(/\n/g, "\\n");

/** Two-step approval dialog. Esc, timeout or no selection count as "deny this time". */
export async function confirmDialog(ctx: ExtensionContext, s: DialogSpec): Promise<Choice> {
  const opts = { timeout: s.timeoutMs, signal: ctx.signal };
  const label = s.patterns?.map((p) => inline(describeMatch(s.tool, p))).join(" / ");
  const denyLabel = s.denyPatterns?.map((p) => inline(describeMatch(s.tool, p))).join(" / ");
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
    const pick = await ctx.ui.select(displayText(`${s.title}\n\n${s.body}`), options, opts);
    if (pick === ONCE) return { decision: "allow", scope: "once" };
    if (sessionOpt && s.rememberAllow && pick === sessionOpt) return { decision: "allow", scope: "session" };
    if ((pick === rememberOpt && options.includes(rememberOpt)) || (pick === denyRememberOpt && options.includes(denyRememberOpt))) {
      const decision = pick === rememberOpt ? "allow" : "deny";
      if (decision === "allow" && !s.globalAllow) return { decision, scope: "project" };
      const pats = decision === "allow" ? s.patterns : s.denyPatterns;
      const ex = pats?.map((p) => examples(p)).find(Boolean);
      const scopes = [`This project (${inline(s.projectName)})`];
      // A deny is always on the safe side, so every scope is offered for it
      if (decision === "deny" || s.globalAllow) scopes.push("Global");
      if (decision === "deny") scopes.push("This session");
      scopes.push(BACK);
      const head = `Remember as ${decision}: ${decision === "allow" ? label : denyLabel}` + (ex ? `\nmatches: ${inline(ex.yes)}\ndoes not match: ${inline(ex.no)}` : "");
      const sc = await ctx.ui.select(head, scopes, opts);
      if (!sc) return { decision: "deny", scope: "once" };
      if (sc === BACK) continue;
      if (!scopes.includes(sc)) return { decision: "deny", scope: "once" };
      const scope = sc === "Global" ? "global" : sc === "This session" ? "session" : "project";
      return { decision, scope, reason: decision === "deny" ? await askReason() : undefined };
    }
    if (pick === DENY) return { decision: "deny", scope: "once", reason: await askReason() };
    return { decision: "deny", scope: "once" };
  }
}

/** Show both ends when a command or file change is too long for the dialog. */
export function preview(tool: string, input: any): string {
  const cut = (s: string, n: number) => {
    if (s.length <= n) return s;
    const head = Math.ceil(n / 2);
    const tail = n - head;
    return `${s.slice(0, head)}\n… [${s.length - n} chars omitted] …\n${s.slice(-tail)}`;
  };
  if (tool === "bash" || tool === "powershell") return displayText(cut(String(input?.command ?? ""), 1500));
  const edits = tool === "edit" ? extractEdits(input) : undefined;
  if (edits) {
    const parts = edits.slice(0, 3).map((e) => `- ${cut(e.oldText, 200)}\n+ ${cut(e.newText, 200)}`);
    return displayText(`edit ${inline(cut(String(input.path), 1500))}\n${parts.join("\n")}${edits.length > 3 ? `\n… (${edits.length - 3} more)` : ""}`);
  }
  if (tool === "write" && typeof input?.content === "string") {
    const c: string = input.content;
    return displayText(`write ${inline(cut(String(input.path), 1500))} (${c.length} chars)\n${cut(c, 600)}`);
  }
  if (typeof input?.path === "string") return displayText(`${tool} ${inline(cut(input.path, 1500))}`);
  return displayText(`${tool} ${cut(JSON.stringify(input) ?? String(input), 500)}`);
}
