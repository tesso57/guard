import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import { createFakeModel } from "./helpers/fake-model.ts";

test("Pi can read a skill without guard handling the call", async () => {
  const dir = await mkdtemp(join(tmpdir(), "guard-skill-pi-"));
  const project = join(dir, "project"), agentDir = join(dir, "agent"), skillDir = join(project, ".agents", "skills", "fixture");
  const isolated = (key: string) => ["RISK_", "GUARD_", "OPENAI_", "PI_"].some((prefix) => key.startsWith(prefix)) || ["HOME", "XDG_CONFIG_HOME"].includes(key);
  const previous = new Map(Object.entries(process.env).filter(([key]) => isolated(key)));
  for (const key of previous.keys()) delete process.env[key];
  Object.assign(process.env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agentDir });
  try {
    await mkdir(skillDir, { recursive: true });
    await writeFile(join(skillDir, "SKILL.md"), "skill-read-fixture");
    const fake = createFakeModel([
      { content: [{ type: "toolCall", id: "skill", name: "read", arguments: { path: ".agents/skills/fixture/SKILL.md" } }] },
      { content: [{ type: "text", text: "done" }] },
    ]);
    const loader = new DefaultResourceLoader({
      cwd: project, agentDir,
      additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))],
      noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
      extensionFactories: [(pi) => { pi.on("session_start", () => pi.appendEntry("guard-rule", { op: "add", rule: {
        id: "deny-skill-read", decision: "deny", tool: "read", match: { kind: "path", path: join(skillDir, "SKILL.md") }, scope: "session", cwd: project, createdAt: new Date().toISOString(),
      } })); }],
    });
    await loader.reload();
    assert.deepEqual(loader.getExtensions().errors, []);
    const { session } = await createAgentSession({ cwd: project, agentDir, model: fake.model, sessionManager: SessionManager.inMemory(project), tools: ["read"], resourceLoader: loader });
    try {
      session.modelRuntime.hasConfiguredAuth = () => true;
      session.agent.streamFunction = fake.stream;
      await session.prompt("Read the skill");
      const result = session.messages.find((message) => message.role === "toolResult" && message.toolCallId === "skill");
      assert.ok(result && result.role === "toolResult" && !result.isError && JSON.stringify(result.content).includes("skill-read-fixture"));
      const audit = join(agentDir, "guard", "audit.jsonl");
      assert.equal(existsSync(audit) && readFileSync(audit, "utf8").includes("skill-read-fixture"), false);
    } finally { session.dispose(); }
  } finally {
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    await rm(dir, { recursive: true, force: true });
  }
});
