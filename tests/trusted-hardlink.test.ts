import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import { createFakeModel } from "./helpers/fake-model.ts";

test("extension directory grants cover hard-linked notes with the granted access", { skip: process.platform === "win32" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-trusted-hardlink-"));
  const project = join(dir, "project"), agentDir = join(dir, "agent"), notes = join(dir, "notes");
  const target = join(notes, "note.txt"), alias = join(dir, "note-alias.txt");
  const isolated = (key: string) => ["RISK_", "GUARD_", "OPENAI_", "PI_", "BASH_FUNC_", "LD_", "DYLD_"].some((prefix) => key.startsWith(prefix)) || ["HOME", "XDG_CONFIG_HOME", "BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key);
  const previous = new Map(Object.entries(process.env).filter(([key]) => isolated(key)));
  for (const key of previous.keys()) delete process.env[key];
  Object.assign(process.env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agentDir });
  const oldFetch = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = (async () => { requests++; throw new Error("unexpected network request"); }) as typeof fetch;
  try {
    mkdirSync(project); mkdirSync(notes);
    writeFileSync(alias, "original note\n");
    linkSync(alias, target);
    const run = async (tool: "read" | "write" | "edit" | "bash", path: string, access?: "read" | "write" | "default") => {
      const input = tool === "read" ? { path } : tool === "write" ? { path, content: "updated note\n" } : tool === "edit" ? { path, edits: [{ oldText: "original", newText: "edited" }] } : { command: `cat '${path.replace(/'/g, "'\\''")}'` };
      const fake = createFakeModel([
        { content: [{ type: "toolCall", id: "operation", name: tool, arguments: input as never }] },
        { content: [{ type: "text", text: "done" }] },
      ]);
      const loader = new DefaultResourceLoader({
        cwd: project, agentDir,
        additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))],
        extensionFactories: access ? [(pi) => { pi.on("session_start", () => pi.events.emit("guard:trust-dir", { path: notes, by: "note", ...(access === "default" ? {} : { access }) })); }] : [],
        noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
      });
      await loader.reload();
      assert.deepEqual(loader.getExtensions().errors, []);
      const { session } = await createAgentSession({ cwd: project, agentDir, model: fake.model, sessionManager: SessionManager.inMemory(project), tools: [tool], resourceLoader: loader });
      try {
        await session.bindExtensions({});
        session.modelRuntime.hasConfiguredAuth = () => true;
        session.agent.streamFunction = fake.stream;
        await session.prompt("Work with the note");
        const result = session.messages.find((message) => message.role === "toolResult" && message.toolCallId === "operation");
        assert.ok(result && result.role === "toolResult");
        return result;
      } finally { session.dispose(); }
    };
    assert.equal((await run("read", target)).isError, true, "unvouched reads still require confirmation");
    assert.equal((await run("bash", target)).isError, true, "unvouched shell reads still require confirmation");
    assert.equal((await run("write", target)).isError, true, "unvouched writes still require confirmation");
    assert.equal((await run("read", target, "read")).isError, false);
    assert.equal((await run("bash", target, "read")).isError, false);
    assert.equal((await run("write", target, "read")).isError, true, "read-only grants cannot authorize writes");
    assert.equal((await run("edit", target, "write")).isError, false);
    assert.equal(readFileSync(alias, "utf8"), "edited note\n");
    assert.equal((await run("write", target, "default")).isError, false, "notes emits a grant without an access field");
    assert.equal(readFileSync(alias, "utf8"), "updated note\n");
    mkdirSync(join(agentDir, "guard"), { recursive: true });
    const protectedFile = join(agentDir, "guard", "config.json");
    writeFileSync(protectedFile, "{}\n");
    const protectedAlias = join(notes, "protected.txt");
    linkSync(protectedFile, protectedAlias);
    assert.equal((await run("read", protectedAlias, "read")).isError, true, "grants do not expose known protected hard links");
    assert.equal((await run("bash", protectedAlias, "read")).isError, true, "shell reads cannot expose known protected hard links");
    assert.equal((await run("write", protectedAlias, "write")).isError, true, "grants do not override protected state");
    assert.equal(readFileSync(protectedFile, "utf8"), "{}\n");
    const secretName = join(notes, ".env");
    linkSync(alias, secretName);
    assert.equal((await run("read", secretName, "read")).isError, true, "sensitive names remain subject to confirmation");
    assert.equal(requests, 0);
  } finally {
    globalThis.fetch = oldFetch;
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(dir, { recursive: true, force: true });
  }
});
