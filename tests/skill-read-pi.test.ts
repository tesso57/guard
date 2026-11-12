import assert from "node:assert/strict";
import { existsSync, readFileSync, symlinkSync, unlinkSync } from "node:fs";
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
  const externalSkillDir = join(dir, "external-package", "skills", "registered");
  const isolated = (key: string) => ["RISK_", "GUARD_", "OPENAI_", "PI_", "BASH_FUNC_"].some((prefix) => key.startsWith(prefix)) || ["HOME", "XDG_CONFIG_HOME", "GREP_OPTIONS", "BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS"].includes(key);
  const previous = new Map(Object.entries(process.env).filter(([key]) => isolated(key)));
  for (const key of previous.keys()) delete process.env[key];
  Object.assign(process.env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agentDir });
  try {
    await mkdir(skillDir, { recursive: true });
    await mkdir(externalSkillDir, { recursive: true });
    await mkdir(join(dir, ".ssh"));
    await writeFile(join(dir, ".ssh", "id_rsa"), "secret-not-a-skill");
    await writeFile(join(skillDir, "SKILL.md"), "skill-read-fixture\nhttps://example.test/path\n");
    await writeFile(join(externalSkillDir, "SKILL.md"), "---\nname: registered\ndescription: Test skill\n---\nregistered-skill-fixture\n");
    const fake = createFakeModel([
      { content: [{ type: "toolCall", id: "skill", name: "read", arguments: { path: ".agents/skills/fixture/SKILL.md" } }] },
      { content: [{ type: "toolCall", id: "skill-grep", name: "bash", arguments: { command: "cat .agents/skills/fixture/SKILL.md | grep -n -e 'https://example.test/path'" } }] },
      { content: [{ type: "toolCall", id: "registered-skill", name: "read", arguments: { path: join(externalSkillDir, "SKILL.md") } }] },
      { content: [{ type: "toolCall", id: "retargeted-skill", name: "read", arguments: { path: join(externalSkillDir, "SKILL.md") } }] },
      { content: [{ type: "text", text: "done" }] },
    ]);
    const loader = new DefaultResourceLoader({
      cwd: project, agentDir,
      additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))],
      additionalSkillPaths: [externalSkillDir],
      noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
      extensionFactories: [(pi) => { pi.on("session_start", () => {
        for (const [id, path] of [["deny-skill-read", join(skillDir, "SKILL.md")], ["deny-registered-skill", join(externalSkillDir, "SKILL.md")]]) {
          pi.appendEntry("guard-rule", { op: "add", rule: { id, decision: "deny", tool: "read", match: { kind: "path", path }, scope: "session", cwd: project, createdAt: new Date().toISOString() } });
        }
        pi.appendEntry("guard-rule", { op: "add", rule: { id: "deny-grep", decision: "deny", tool: "bash", match: { kind: "argv", prefix: ["grep"] }, scope: "session", cwd: project, createdAt: new Date().toISOString() } });
      }); pi.on("tool_result", (event) => {
        if (event.toolCallId === "registered-skill") {
          const path = join(externalSkillDir, "SKILL.md");
          unlinkSync(path);
          symlinkSync(join(dir, ".ssh", "id_rsa"), path);
        }
      }); }],
    });
    await loader.reload();
    assert.deepEqual(loader.getExtensions().errors, []);
    const { session } = await createAgentSession({ cwd: project, agentDir, model: fake.model, sessionManager: SessionManager.inMemory(project), tools: ["read", "bash"], resourceLoader: loader });
    try {
      session.modelRuntime.hasConfiguredAuth = () => true;
      session.agent.streamFunction = fake.stream;
      await session.prompt("Read the skill");
      const result = session.messages.find((message) => message.role === "toolResult" && message.toolCallId === "skill");
      assert.ok(result && result.role === "toolResult" && !result.isError && JSON.stringify(result.content).includes("skill-read-fixture"));
      const grep = session.messages.find((message) => message.role === "toolResult" && message.toolCallId === "skill-grep");
      assert.ok(grep && grep.role === "toolResult" && !grep.isError && JSON.stringify(grep.content).includes("https://example.test/path"));
      const external = session.messages.find((message) => message.role === "toolResult" && message.toolCallId === "registered-skill");
      assert.ok(external && external.role === "toolResult" && !external.isError && JSON.stringify(external.content).includes("registered-skill-fixture"));
      const retargeted = session.messages.find((message) => message.role === "toolResult" && message.toolCallId === "retargeted-skill");
      assert.ok(retargeted && retargeted.role === "toolResult" && retargeted.isError && !JSON.stringify(retargeted.content).includes("secret-not-a-skill"));
      const audit = join(agentDir, "guard", "audit.jsonl");
      assert.equal(existsSync(audit) && readFileSync(audit, "utf8").includes("skill-read-fixture"), false);
    } finally { session.dispose(); }
  } finally {
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    await rm(dir, { recursive: true, force: true });
  }
});
