import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { createMockPi } from "./helpers/mock-pi.ts";

test("read honours exact session-note approvals while keeping other decisions private", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "guard-note-approval-")));
  const isolated = (k: string) => /^(RISK_|GUARD_|PI_|OPENAI_)/.test(k) || k === "HOME";
  const previous = new Map(Object.entries(process.env).filter(([k]) => isolated(k)));
  const previousFetch = globalThis.fetch;
  let requests = 0;
  try {
    for (const key of previous.keys()) delete process.env[key];
    process.env.HOME = dir;
    process.env.PI_CODING_AGENT_DIR = join(dir, "agent");
    process.env.GUARD_OPENAI_API_KEY = "test-key";
    globalThis.fetch = async () => { requests++; return new Response(null, { status: 400 }); };
    const { default: guard } = await import("../extensions/index.ts");
    const { RuleStore } = await import("../extensions/guard/rules.ts");
    const { tail } = await import("../extensions/guard/audit.ts");
    const mock = createMockPi();
    const project = join(dir, "project");
    Object.assign(mock.context, { cwd: project, hasUI: false, isProjectTrusted: () => true });
    const note = join(project, ".pi", "_notes", mock.sessionManager.getSessionId(), "note.md");
    mkdirSync(dirname(note), { recursive: true });
    writeFileSync(note, "session note");
    const rules = new RuleStore();
    rules.load(project, true);
    const add = (id: string, decision: "allow" | "ask" | "deny", path: string) =>
      rules.add({ id, tool: "read", decision, scope: "project", match: { kind: "path", path }, createdAt: new Date().toISOString() }, () => {});
    add("saved", "allow", note);
    guard(mock.pi);
    await mock.emit("session_start", { reason: "startup" });
    const startNote = () => mock.emit("before_agent_start", { messageType: "custom", message: { customType: "pi-session-notes-request" } });
    let sequence = 0;
    const read = async (path = note) => {
      const call = { type: "toolCall", id: String(++sequence), name: "read", arguments: { path } };
      await mock.emit("message_end", { message: { role: "assistant", content: [call] } });
      await mock.emit("tool_call", { toolCallId: call.id, toolName: call.name, input: call.arguments });
      return tail(1)[0];
    };
    await startNote();
    assert.equal((await read()).final, "blocked", "a stored allow alone is insufficient");
    mock.pi.events.emit("guard:trust-dir", { path: dirname(note), by: "note" });
    await mock.emit("before_agent_start", { messageType: "user" });
    assert.equal((await read()).final, "blocked", "the same read in an ordinary conversation still needs judgement");
    await startNote();
    requests = 0;
    const allowed = await read();
    assert.equal(allowed.source, "rule-allow", JSON.stringify(allowed));
    assert.equal(allowed.final, "run");
    assert.deepEqual(allowed.ruleIds, ["saved"]);
    assert.equal(requests, 0, "neither preflight nor tool_call should send a request");
    assert.ok(!JSON.stringify(allowed).includes(note));

    await mock.emit("message_start", { message: { role: "user" } });
    assert.equal((await read()).final, "blocked", "steering a running note turn restores normal judgement");
    await startNote();
    assert.equal((await read(dirname(note) + "/./note.md")).final, "blocked", "only the exact note path is covered");
    const siblingSessionNote = join(dirname(dirname(note)), "other-session", "note.md");
    mkdirSync(dirname(siblingSessionNote));
    writeFileSync(siblingSessionNote, "other session");
    add("other-session", "allow", siblingSessionNote);
    mock.pi.events.emit("guard:trust-dir", { path: dirname(siblingSessionNote), by: "note" });
    assert.equal((await read(siblingSessionNote)).final, "blocked", "a different session has its own note");
    add("different", "deny", join(dirname(note), "other.md"));
    assert.equal((await read()).final, "blocked", "another omitted decision still requires review");
    rules.remove("different", () => {});
    for (const decision of ["ask", "deny"] as const) {
      add(decision, decision, note);
      assert.equal((await read()).source, `rule-${decision}`);
      rules.remove(decision, () => {});
    }
    linkSync(note, join(project, "second-name.md"));
    assert.equal((await read()).source, "sensitive");
  } finally {
    globalThis.fetch = previousFetch;
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(dir, { recursive: true, force: true });
  }
});
