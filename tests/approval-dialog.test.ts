import assert from "node:assert/strict";
import test from "node:test";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { confirmDialog, type DialogSpec } from "../extensions/guard/ui.ts";

test("every step of a remembered denial receives the same timeout and abort signal", async () => {
  const controller = new AbortController();
  const received: { timeout?: number; signal?: AbortSignal }[] = [];
  const choices = ["Deny and remember… ▸", "This session"];
  const context = {
    signal: controller.signal,
    ui: {
      async select(_title: string, _options: string[], options: { timeout?: number; signal?: AbortSignal }) {
        received.push(options);
        return choices.shift();
      },
      async input(_title: string, _placeholder: string, options: { timeout?: number; signal?: AbortSignal }) {
        received.push(options);
        return "reason";
      },
    },
  } as unknown as ExtensionContext;
  const result = await confirmDialog(context, {
    title: "Test", body: "Test", tool: "bash", denyPatterns: [{ kind: "argv", prefix: ["git", "push"] }],
    rememberAllow: false, globalAllow: false, projectName: "project", timeoutMs: 1234,
  });
  assert.deepEqual(result, { decision: "deny", scope: "session", reason: "reason" });
  assert.equal(received.length, 3);
  assert.ok(received.every((options) => options.timeout === 1234 && options.signal === controller.signal));
});

const once = "Allow (this time only)";
const sessionAllow = "Allow (this session: git status)";
const projectAllow = "Allow and remember (this project: project)";
const rememberAllow = "Allow and remember… ▸";
const rememberDeny = "Deny and remember… ▸";
const back = "← Back";
const project = "This project (project)";
const main = [once, sessionAllow, rememberAllow, "Deny", rememberDeny];
const projectMain = [once, sessionAllow, projectAllow, "Deny", rememberDeny];
const allowScopes = [project, "Global", back];
const denyScopes = [project, "Global", "This session", back];
const denyOnce = { decision: "deny", scope: "once" };
const spec: DialogSpec = {
  title: "Test", body: "Test", tool: "bash",
  patterns: [{ kind: "argv-exact", argv: ["git", "status"] }],
  denyPatterns: [{ kind: "argv-exact", argv: ["git", "status"] }],
  rememberAllow: true, globalAllow: true, projectName: "project", timeoutMs: 1234,
};

type Selection = [options: string[], reply: string | undefined];

async function scriptedDialog(selections: Selection[], config: Partial<DialogSpec> = {}, reason?: { reply: string | undefined }) {
  const remaining = [...selections];
  let askedForReason = false;
  const context = {
    ui: {
      async select(_title: string, options: string[]) {
        const step = remaining.shift();
        assert.ok(step, "unexpected selection prompt");
        assert.deepEqual(options, step[0]);
        return step[1];
      },
      async input() {
        assert.ok(reason, "unexpected reason prompt");
        assert.equal(askedForReason, false);
        askedForReason = true;
        return reason.reply;
      },
    },
  } as unknown as ExtensionContext;
  const result = await confirmDialog(context, { ...spec, ...config });
  assert.equal(remaining.length, 0);
  assert.equal(askedForReason, reason !== undefined);
  return result;
}

test("allow returns the scope selected on the current screen", async () => {
  assert.deepEqual(await scriptedDialog([[main, once]]), { decision: "allow", scope: "once" });
  assert.deepEqual(await scriptedDialog([[main, sessionAllow]]), { decision: "allow", scope: "session" });
  assert.deepEqual(await scriptedDialog([[projectMain, projectAllow]], { globalAllow: false }), { decision: "allow", scope: "project" });
  assert.deepEqual(await scriptedDialog([[main, rememberAllow], [allowScopes, project]]), { decision: "allow", scope: "project", reason: undefined });
  assert.deepEqual(await scriptedDialog([[main, rememberAllow], [allowScopes, "Global"]]), { decision: "allow", scope: "global", reason: undefined });
});

test("back abandons the earlier decision and shared scope labels use the current submenu", async () => {
  assert.deepEqual(await scriptedDialog([
    [main, rememberAllow], [allowScopes, back],
    [main, rememberDeny], [denyScopes, "Global"],
  ], {}, { reply: "  reason  " }), { decision: "deny", scope: "global", reason: "reason" });
  assert.deepEqual(await scriptedDialog([
    [main, rememberDeny], [denyScopes, back],
    [main, rememberAllow], [allowScopes, project],
  ]), { decision: "allow", scope: "project", reason: undefined });
  assert.deepEqual(await scriptedDialog([
    [main, rememberAllow], [allowScopes, back],
    [main, rememberDeny], [denyScopes, back],
    [main, sessionAllow],
  ]), { decision: "allow", scope: "session" });
});

test("cancel or a label absent from the current menu denies once", async () => {
  assert.deepEqual(await scriptedDialog([[main, undefined]]), denyOnce);
  assert.deepEqual(await scriptedDialog([[main, rememberAllow], [allowScopes, undefined]]), denyOnce);
  assert.deepEqual(await scriptedDialog([[main, rememberDeny], [denyScopes, undefined]]), denyOnce);
  assert.deepEqual(await scriptedDialog([[main, rememberAllow], [allowScopes, back], [main, undefined]]), denyOnce);
  assert.deepEqual(await scriptedDialog([[main, rememberAllow], [allowScopes, back], [main, "Global"]]), denyOnce);
  assert.deepEqual(await scriptedDialog([
    [main, rememberDeny], [denyScopes, back],
    [main, rememberAllow], [allowScopes, "This session"],
  ]), denyOnce);
  assert.deepEqual(await scriptedDialog([[projectMain, rememberAllow]], { globalAllow: false }), denyOnce);
  assert.deepEqual(await scriptedDialog([[[once, "Deny", rememberDeny], sessionAllow]], { patterns: [] }), denyOnce);
});

test("dismissing the optional reason keeps the selected denial scope", async () => {
  for (const [label, scope] of [["This session", "session"], [project, "project"], ["Global", "global"]]) {
    assert.deepEqual(await scriptedDialog([[main, rememberDeny], [denyScopes, label]], {}, { reply: undefined }),
      { decision: "deny", scope, reason: undefined });
  }
});
