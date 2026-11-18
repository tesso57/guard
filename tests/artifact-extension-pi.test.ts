import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import { createFakeModel } from "./helpers/fake-model.ts";

test("artifact PR grants let Pi write and edit the project artifact from root and nested cwd", { skip: !process.env.GUARD_TEST_ARTIFACT_EXTENSION }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-real-artifact-"));
  const project = join(dir, "project"), nested = join(project, "src"), agentDir = join(dir, "agent");
  const isolated = (key: string) => /^(RISK_|GUARD_|OPENAI_|PI_)/.test(key) || ["HOME", "XDG_CONFIG_HOME"].includes(key);
  const previous = new Map(Object.entries(process.env).filter(([key]) => isolated(key)));
  const artifactExtension = process.env.GUARD_TEST_ARTIFACT_EXTENSION!;
  for (const key of previous.keys()) delete process.env[key];
  Object.assign(process.env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agentDir });
  const oldFetch = globalThis.fetch;
  globalThis.fetch = (async () => { throw new Error("unexpected network request"); }) as typeof fetch;
  try {
    mkdirSync(nested, { recursive: true });
    mkdirSync(join(project, ".git"));
    const file = join(project, ".pi/_artifacts/dashboard/index.tsx");
    for (const cwd of [project, nested]) {
      const fake = createFakeModel([
        { content: [{ type: "toolCall", id: "write-artifact", name: "write", arguments: { path: file, content: "export default function View() { return null; }\n" } }] },
        { content: [{ type: "toolCall", id: "edit-artifact", name: "edit", arguments: { path: file, edits: [{ oldText: "return null", newText: "return 42" }] } }] },
        { content: [{ type: "toolCall", id: "read-artifact", name: "read", arguments: { path: file } }] },
        { content: [{ type: "text", text: "done" }] },
      ]);
      const loader = new DefaultResourceLoader({ cwd, agentDir, additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url)), artifactExtension], noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true });
      await loader.reload();
      assert.deepEqual(loader.getExtensions().errors, []);
      const { session } = await createAgentSession({ cwd, agentDir, model: fake.model, sessionManager: SessionManager.inMemory(cwd), tools: ["write", "edit", "read"], resourceLoader: loader });
      try {
        await session.bindExtensions({});
        session.modelRuntime.hasConfiguredAuth = () => true;
        session.agent.streamFunction = fake.stream;
        await session.prompt("Update the artifact");
        const results = session.messages.filter((message) => message.role === "toolResult");
        assert.equal(results.length, 3, JSON.stringify(results));
        for (const result of results) assert.equal(result.isError, false, JSON.stringify(result));
        assert.match(readFileSync(file, "utf8"), /return 42/);
      } finally { session.dispose(); }
    }
  } finally {
    globalThis.fetch = oldFetch;
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(dir, { recursive: true, force: true });
  }
});
