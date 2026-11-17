import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import { createFakeModel } from "./helpers/fake-model.ts";

test("installed notes and guard save project notes together", { skip: !process.env.GUARD_TEST_NOTES_EXTENSION }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-real-notes-"));
  const project = join(dir, "project"), agentDir = join(dir, "agent");
  const isolated = (key: string) => /^(RISK_|GUARD_|OPENAI_|PI_)/.test(key) || ["HOME", "XDG_CONFIG_HOME"].includes(key);
  const previous = new Map(Object.entries(process.env).filter(([key]) => isolated(key)));
  const notesExtension = process.env.GUARD_TEST_NOTES_EXTENSION!;
  for (const key of previous.keys()) delete process.env[key];
  Object.assign(process.env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agentDir });
  const oldFetch = globalThis.fetch;
  globalThis.fetch = (async () => { throw new Error("unexpected network request"); }) as typeof fetch;
  try {
    mkdirSync(join(project, ".pi"), { recursive: true });
    writeFileSync(join(project, ".pi/notes.json"), JSON.stringify({ path: ".pi/_notes/{sessionId}/note.md" }));
    writeFileSync(join(project, ".pi/notes-factory.json"), JSON.stringify(Object.fromEntries(["plan", "review", "learnings"].map((name) => [name, `.pi/_notes/{sessionId}/factory/${name}.md`]))));
    const manager = SessionManager.inMemory(project);
    const base = join(project, ".pi/_notes", manager.getSessionId());
    const files = [join(base, "note.md"), ...["plan", "review", "learnings"].map((name) => join(base, "factory", `${name}.md`))];
    const fake = createFakeModel([
      { content: files.map((path, i) => ({ type: "toolCall" as const, id: `note-${i}`, name: "write", arguments: { path, content: `saved ${i}` } })) },
      { content: [{ type: "text", text: "done" }] },
    ]);
    const loader = new DefaultResourceLoader({ cwd: project, agentDir, additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url)), notesExtension], noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true });
    await loader.reload();
    assert.deepEqual(loader.getExtensions().errors, []);
    const { session } = await createAgentSession({ cwd: project, agentDir, model: fake.model, sessionManager: manager, tools: ["write"], resourceLoader: loader });
    try {
      await session.bindExtensions({});
      session.modelRuntime.hasConfiguredAuth = () => true;
      session.agent.streamFunction = fake.stream;
      await session.prompt("/note");
      await session.agent.waitForIdle();
      const results = session.messages.filter((message) => message.role === "toolResult");
      assert.equal(results.length, 4, JSON.stringify(session.messages));
      for (const result of results) assert.equal(result.isError, false, JSON.stringify(result));
      files.forEach((path, i) => assert.equal(readFileSync(path, "utf8"), `saved ${i}`));
    } finally { session.dispose(); }
  } finally {
    globalThis.fetch = oldFetch;
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(dir, { recursive: true, force: true });
  }
});
