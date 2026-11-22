import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import { createFakeModel } from "./helpers/fake-model.ts";

test("write and edit replace the current session note without modifying the sync copy", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "guard-note-save-")));
  const project = join(dir, "project"), agentDir = join(dir, "agent");
  const isolated = (key: string) => /^(RISK_|GUARD_|OPENAI_|PI_)/.test(key) || ["HOME", "XDG_CONFIG_HOME"].includes(key);
  const previous = Object.entries(process.env).filter(([key]) => isolated(key));
  const oldFetch = globalThis.fetch;
  try {
    for (const [key] of previous) delete process.env[key];
    Object.assign(process.env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agentDir });
    globalThis.fetch = async () => { throw new Error("unexpected network request"); };

    const manager = SessionManager.inMemory(project);
    const note = join(project, ".pi", "_notes", manager.getSessionId(), "note.md");
    const firstCopy = join(dir, "sync-original"), secondCopy = join(dir, "sync-after-write");
    const plain = join(project, "ordinary.txt");
    mkdirSync(dirname(note), { recursive: true });
    writeFileSync(note, "original note\n");
    linkSync(note, firstCopy);
    writeFileSync(plain, "ordinary file\n");
    const plainInode = statSync(plain).ino;
    const done = { content: [{ type: "text" as const, text: "done" }] };
    const fake = createFakeModel([
      { content: [{ type: "toolCall", id: "note-write", name: "write", arguments: { path: note, content: "written note\n" } }] }, done,
      { content: [{ type: "toolCall", id: "edit-without-read", name: "edit", arguments: { path: note, edits: [{ oldText: "written", newText: "unread" }] } }] }, done,
      { content: [{ type: "toolCall", id: "redacted-read", name: "read", arguments: { path: note } }] },
      { content: [{ type: "toolCall", id: "edit-after-redacted-read", name: "edit", arguments: { path: note, edits: [{ oldText: "written", newText: "unread" }] } }] }, done,
      { content: [{ type: "toolCall", id: "note-read", name: "read", arguments: { path: note } }] },
      { content: [{ type: "toolCall", id: "note-edit", name: "edit", arguments: { path: note, edits: [{ oldText: "written", newText: "edited" }] } }] }, done,
      { content: [{ type: "toolCall", id: "read-before-change", name: "read", arguments: { path: note } }] }, done,
      { content: [{ type: "toolCall", id: "write-after-change", name: "write", arguments: { path: note, content: "outdated replacement\n" } }] }, done,
      { content: [{ type: "toolCall", id: "edit-after-change", name: "edit", arguments: { path: note, edits: [{ oldText: "edited", newText: "finished" }] } }] }, done,
      { content: [{ type: "toolCall", id: "reread", name: "read", arguments: { path: note } }] },
      { content: [{ type: "toolCall", id: "edit-after-reread", name: "edit", arguments: { path: note, edits: [{ oldText: "edited", newText: "finished" }] } }] }, done,
      { content: [{ type: "toolCall", id: "recreate-note", name: "write", arguments: { path: note, content: "new note\n" } }] }, done,
      { content: [{ type: "toolCall", id: "ordinary-write", name: "write", arguments: { path: "ordinary.txt", content: "rewritten file\n" } }] },
      { content: [{ type: "toolCall", id: "ordinary-edit", name: "edit", arguments: { path: "ordinary.txt", edits: [{ oldText: "rewritten", newText: "edited" }] } }] }, done,
    ]);
    const loader = new DefaultResourceLoader({
      cwd: project, agentDir,
      additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))],
      extensionFactories: [(pi) => {
        pi.on("session_start", () => pi.events.emit("guard:trust-dir", { path: dirname(note), by: "note" }));
        pi.on("tool_result", event => {
          if (event.toolCallId === "redacted-read") return { content: [{ type: "text", text: "[withheld]" }] };
        });
      }],
      noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
    });
    await loader.reload();
    assert.deepEqual(loader.getExtensions().errors, []);
    const { session } = await createAgentSession({ cwd: project, agentDir, model: fake.model, sessionManager: manager, tools: ["read", "write", "edit"], resourceLoader: loader });
    try {
      await session.bindExtensions({
        uiContext: {
          ...session.extensionRunner.getUIContext(),
          select: async (_title, options) => options.includes("Allow (this time only)") ? "Allow (this time only)" : undefined,
        },
      });
      session.modelRuntime.hasConfiguredAuth = () => true;
      session.agent.streamFunction = fake.stream;
      const save = (content: string) => session.sendCustomMessage({ customType: "pi-session-notes-request", display: false, content }, { triggerTurn: true });
      const succeeded = (id: string) => {
        const result = session.messages.find(message => message.role === "toolResult" && message.toolCallId === id);
        assert.ok(result && result.role === "toolResult" && !result.isError, JSON.stringify(result));
        return result;
      };
      const failed = (id: string, reason: RegExp) => {
        const result = session.messages.find(message => message.role === "toolResult" && message.toolCallId === id);
        assert.ok(result && result.role === "toolResult" && result.isError, JSON.stringify(result));
        assert.match(JSON.stringify(result.content), reason);
        return result;
      };

      await save("Save the session note");
      succeeded("note-write");
      assert.equal(readFileSync(note, "utf8"), "written note\n");
      assert.equal(readFileSync(firstCopy, "utf8"), "original note\n");
      linkSync(note, secondCopy);

      await save("Try to edit without reading the linked note");
      failed("edit-without-read", /read the linked session note/i);
      await save("Try to edit after an extension withheld the note body");
      assert.deepEqual(succeeded("redacted-read").content, [{ type: "text", text: "[withheld]" }]);
      failed("edit-after-redacted-read", /read it again/i);
      assert.equal(readFileSync(note, "utf8"), "written note\n");

      await save("Read and update the session note");
      succeeded("note-read");
      succeeded("note-edit");
      assert.equal(readFileSync(note, "utf8"), "edited note\n");
      assert.equal(readFileSync(secondCopy, "utf8"), "written note\n");
      const audit = readFileSync(join(agentDir, "guard", "audit.jsonl"), "utf8").trim().split("\n").map(line => JSON.parse(line));
      assert.ok(audit.some(row => row.tool === "read" && row.final === "run" && row.choice === "allow:once"), "the read was explicitly approved");
      for (const tool of ["write", "edit"]) {
        assert.ok(audit.some(row => row.tool === tool && row.action === "allow" && row.final === "run"), `the note ${tool} should run without an additional confirmation`);
      }

      const latestCopy = join(dir, "sync-after-edit");
      linkSync(note, latestCopy);
      await save("Read the current note");
      succeeded("read-before-change");
      const concurrentText = "edited note\nA colleague added a line.\n";
      writeFileSync(note, concurrentText);
      const requiresReread = (id: string) => {
        const result = failed(id, /read it again/i);
        assert.doesNotMatch(JSON.stringify(result), /A colleague added a line/);
        assert.equal(readFileSync(note, "utf8"), concurrentText);
      };
      await save("Replace the previously read note");
      requiresReread("write-after-change");
      assert.equal(readFileSync(latestCopy, "utf8"), concurrentText);
      unlinkSync(latestCopy);

      await save("Apply an edit to the previously read text");
      requiresReread("edit-after-change");

      const rereadCopy = join(dir, "sync-after-concurrent-change");
      linkSync(note, rereadCopy);
      await save("Read the changed note before editing it");
      succeeded("reread");
      succeeded("edit-after-reread");
      assert.equal(readFileSync(note, "utf8"), concurrentText.replace("edited", "finished"));
      assert.equal(readFileSync(rereadCopy, "utf8"), concurrentText);

      unlinkSync(note);
      await save("Recreate the missing note");
      succeeded("recreate-note");
      assert.equal(readFileSync(note, "utf8"), "new note\n");

      await session.prompt("Write and edit the ordinary project file");
      succeeded("ordinary-write");
      succeeded("ordinary-edit");
      assert.equal(readFileSync(plain, "utf8"), "edited file\n");
      assert.equal(statSync(plain).ino, plainInode, "ordinary files retain the SDK's in-place write behavior");
    } finally { session.dispose(); }
  } finally {
    globalThis.fetch = oldFetch;
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(dir, { recursive: true, force: true });
  }
});
