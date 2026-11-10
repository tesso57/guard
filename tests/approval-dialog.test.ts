import assert from "node:assert/strict";
import test from "node:test";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { confirmDialog } from "../extensions/guard/ui.ts";

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
