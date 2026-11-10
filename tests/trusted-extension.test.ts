import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import { createFakeModel } from "./helpers/fake-model.ts";

test("an extension can vouch for its registered tool in a real Pi session", async () => {
  const dir = await mkdtemp(join(tmpdir(), "guard-real-trust-"));
  const project = join(dir, "project"), agentDir = join(dir, "agent");
  await mkdir(project);
  const isolated = (key: string) => ["RISK_", "GUARD_", "OPENAI_", "PI_"].some((prefix) => key.startsWith(prefix)) || ["HOME", "XDG_CONFIG_HOME"].includes(key);
  const previous = new Map(Object.entries(process.env).filter(([key]) => isolated(key)));
  for (const key of previous.keys()) delete process.env[key];
  Object.assign(process.env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agentDir });
  const oldFetch = globalThis.fetch;
  let requests = 0, executions = 0, started = false;
  let source: unknown;
  globalThis.fetch = (async () => { requests++; throw new Error("unexpected network request"); }) as typeof fetch;
  try {
    const fake = createFakeModel([
      { content: [{ type: "toolCall", id: "trusted-call", name: "notes_write", arguments: { text: "TOKEN=opaque-trusted-test-secret" } }] },
      { content: [{ type: "text", text: "done" }] },
    ]);
    const loader = new DefaultResourceLoader({
      cwd: project,
      agentDir,
      additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))],
      extensionFactories: [(pi) => {
        pi.registerTool({
          name: "notes_write", label: "Notes", description: "Record a note",
          parameters: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } as never,
          async execute() { executions++; return { content: [{ type: "text", text: "saved" }], details: {} }; },
        });
        pi.on("session_start", () => { started = true; source = pi.getAllTools().find((tool) => tool.name === "notes_write")?.sourceInfo; pi.events.emit("guard:trust-tool", { tool: "notes_write", by: "notes" }); });
      }],
      noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
    });
    await loader.reload();
    assert.deepEqual(loader.getExtensions().errors, []);
    const { session } = await createAgentSession({ cwd: project, agentDir, model: fake.model, sessionManager: SessionManager.inMemory(project), resourceLoader: loader });
    try {
      await session.bindExtensions({});
      session.setActiveToolsByName(["notes_write"]);
      session.modelRuntime.hasConfiguredAuth = () => true;
      session.agent.streamFunction = fake.stream;
      await session.prompt("Save a note");
      const result = session.messages.find((message) => message.role === "toolResult");
      assert.ok(result && result.role === "toolResult" && !result.isError, JSON.stringify({ result, started, source }));
      assert.equal(executions, 1);
      assert.equal(requests, 0);
      const records = readFileSync(join(agentDir, "guard", "audit.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
      assert.ok(records.some((record) => record.tool === "notes_write" && record.source === "extension" && record.final === "run"));
      assert.doesNotMatch(JSON.stringify(records), /opaque-trusted-test-secret/);
    } finally { session.dispose(); }
  } finally {
    globalThis.fetch = oldFetch;
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) process.env[key] = value;
    await rm(dir, { recursive: true, force: true });
  }
});
