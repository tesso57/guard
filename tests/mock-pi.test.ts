import assert from "node:assert/strict";
import test from "node:test";
import { createMockPi } from "./helpers/mock-pi.ts";

test("commands receive arguments and record notifications", async () => {
  const mock = createMockPi();
  mock.pi.registerCommand("greet", { handler: async (args, ctx) => ctx.ui.notify(args, "info") });
  await mock.runCommand("greet", "hello");
  assert.deepEqual(mock.notifications, [{ message: "hello", type: "info" }]);
  await assert.rejects(mock.runCommand("missing"), /Unknown command/);
});

test("invalid command registrations fail before invocation", () => {
  const mock = createMockPi();
  assert.throws(() => mock.pi.registerCommand("", { handler: async () => {} }), /non-empty string name/);
  assert.throws(() => mock.pi.registerCommand("invalid", {} as never), /must define handler/);
  assert.equal(mock.commands.size, 0);
});

test("event handlers run in registration order and may unsubscribe", async () => {
  const mock = createMockPi();
  const calls: number[] = [];
  const unsubscribe = mock.pi.on("session_start", async () => { calls.push(1); });
  mock.pi.on("session_start", async () => { calls.push(2); });
  await mock.emit("session_start", { type: "session_start" });
  unsubscribe();
  await mock.emit("session_start", { type: "session_start" });
  assert.deepEqual(calls, [1, 2, 2]);
});

test("unsubscribing twice leaves another registration of the same handler intact", async () => {
  const mock = createMockPi();
  let calls = 0;
  const handler = async () => { calls++; };
  const unsubscribe = mock.pi.on("session_start", handler);
  mock.pi.on("session_start", handler);
  unsubscribe();
  unsubscribe();
  await mock.emit("session_start", { type: "session_start" });
  assert.equal(calls, 1);
});

test("handler changes take effect on the next event emission", async () => {
  const mock = createMockPi();
  const calls: string[] = [];
  let unsubscribe = () => {};
  mock.pi.on("session_start", async () => {
    calls.push("first");
    unsubscribe();
    mock.pi.on("session_start", async () => { calls.push("added"); });
  });
  unsubscribe = mock.pi.on("session_start", async () => { calls.push("removed"); });
  await mock.emit("session_start", { type: "session_start" });
  await mock.emit("session_start", { type: "session_start" });
  assert.deepEqual(calls, ["first", "removed", "first", "added"]);
});

test("handler exceptions are propagated to the test", async () => {
  const mock = createMockPi();
  let laterHandlerRan = false;
  mock.pi.on("session_start", async () => { throw new Error("fixture handler failed"); });
  mock.pi.on("session_start", async () => { laterHandlerRan = true; });
  await assert.rejects(mock.emit("session_start", { type: "session_start" }), /fixture handler failed/);
  assert.equal(laterHandlerRan, false);
});

test("dialog responses are consumed in order and missing responses fail", async () => {
  const mock = createMockPi({ confirm: [true, false], input: ["value", undefined], select: ["A"] });
  assert.equal(await mock.context.ui.confirm("title", "message"), true);
  assert.equal(await mock.context.ui.confirm("title", "message"), false);
  assert.equal(await mock.context.ui.input("title"), "value");
  assert.equal(await mock.context.ui.input("title"), undefined);
  assert.equal(await mock.context.ui.select("title", ["A", "B"]), "A");
  await assert.rejects(mock.context.ui.confirm("title", "message"), /No mock response/);
});

test("registered tools are accessible by name", () => {
  const mock = createMockPi();
  const tool = { name: "example" };
  mock.pi.registerTool(tool as never);
  assert.equal(mock.tools.get("example"), tool);
});

test("captures dialogs and UI status and widget changes", async () => {
  const mock = createMockPi({ select: ["Allow"], input: ["reason"], confirm: [true] });
  await mock.context.ui.select("Decision", ["Allow", "Deny"]);
  await mock.context.ui.input("Why?", "optional");
  await mock.context.ui.confirm("Sure?", "Proceed?");
  assert.deepEqual(mock.dialogs.map((dialog) => dialog.kind), ["select", "input", "confirm"]);
  assert.deepEqual(mock.dialogs[0], { kind: "select", title: "Decision", options: ["Allow", "Deny"] });
  mock.context.ui.setStatus("guard", "enabled");
  mock.context.ui.setWidget("questions", ["pending"]);
  assert.equal(mock.statuses.get("guard"), "enabled");
  assert.deepEqual(mock.widgets.get("questions"), ["pending"]);
  mock.context.ui.setStatus("guard", undefined);
  mock.context.ui.setWidget("questions", undefined);
  assert.equal(mock.statuses.has("guard"), false);
  assert.equal(mock.widgets.has("questions"), false);
});

test("appended custom entries appear in the in-memory session branch", () => {
  const mock = createMockPi();
  mock.pi.appendEntry("question", { id: 1 });
  const entry = mock.context.sessionManager.getBranch().at(-1);
  assert.ok(entry && entry.type === "custom");
  assert.equal(entry.customType, "question");
  assert.deepEqual(entry.data, { id: 1 });
});

test("records user and custom messages without starting agent turns", () => {
  const mock = createMockPi();
  mock.pi.sendUserMessage("answer", { deliverAs: "steer" });
  mock.pi.sendMessage({ customType: "result", content: "done", display: true }, { triggerTurn: true });
  assert.deepEqual(mock.userMessages, [{ content: "answer", options: { deliverAs: "steer" } }]);
  assert.deepEqual(mock.messages, [{ message: { customType: "result", content: "done", display: true }, options: { triggerTurn: true } }]);
});
