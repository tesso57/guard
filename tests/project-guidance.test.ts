import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import type { ToolCall } from "@earendil-works/pi-ai";
import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import type { AuditRecord } from "../extensions/guard/audit.ts";
import { createFakeModel } from "./helpers/fake-model.ts";
import { createMockPi } from "./helpers/mock-pi.ts";

test("Pi uses this project's recent manual confirmations to plan later sessions", async t => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "guard-project-guidance-")));
  const agentDir = join(dir, "agent");
  const cwd = join(dir, "project");
  mkdirSync(cwd);
  for (const file of ["a.ts", "b.ts"]) writeFileSync(join(cwd, file), file);
  const isolated = (key: string) => /^(PI_|RISK_|GUARD_|OPENAI_)/.test(key) || ["HOME", "XDG_CONFIG_HOME"].includes(key);
  const previous = Object.entries(process.env).filter(([key]) => isolated(key));
  for (const [key] of previous) delete process.env[key];
  Object.assign(process.env, { HOME: dir, PI_CODING_AGENT_DIR: agentDir, XDG_CONFIG_HOME: join(dir, "config"), PI_OFFLINE: "1" });
  try {
    const { projectGuidance } = await import("../extensions/guard/project-guidance.ts");
    const { audit, tail } = await import("../extensions/guard/audit.ts");

    async function run(batches: ToolCall[][]) {
      const fake = createFakeModel([...batches.map(content => ({ content })), { content: [{ type: "text", text: "done" }] }]);
      const loader = new DefaultResourceLoader({ cwd, agentDir, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
        additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))] });
      await loader.reload();
      assert.deepEqual(loader.getExtensions().errors, []);
      const manager = SessionManager.inMemory(cwd);
      const { session } = await createAgentSession({ cwd, agentDir, sessionManager: manager, resourceLoader: loader, model: fake.model });
      const ui = createMockPi({ select: Array(4).fill("Allow (this time only)") });
      try {
        await session.bindExtensions({ uiContext: ui.context.ui });
        session.modelRuntime.hasConfiguredAuth = () => true;
        session.agent.streamFunction = fake.stream;
        await session.prompt("Read a.ts and b.ts and copy a.ts to copy.txt.");
        const results = session.messages.filter(m => m.role === "toolResult");
        assert.equal(results.length, batches.flat().length);
        assert.ok(results.every(r => !r.isError), JSON.stringify(results));
        const records = tail(100).filter(r => r.session === manager.getSessionId());
        const guidance = fake.requests[0].messages.find(m => m.role === "system")?.sections?.guard_project_guidance;
        return { guidance, records, dialogs: ui.dialogs.length };
      } finally { session.dispose(); }
    }

    const reads: ToolCall[] = ["a.ts", "b.ts"].map(path => ({ type: "toolCall", name: "read", id: path, arguments: { path } }));
    const copy: ToolCall = { type: "toolCall", name: "bash", id: "copy", arguments: { command: "cp a.ts copy.txt" } };
    const mixed = await run([[...reads, copy]]);
    assert.equal(mixed.guidance, undefined);
    assert.equal(mixed.records.filter(r => r.tool === "read" && r.source === "concurrent" && r.choice === "allow:once").length, 2);
    const grouped = await run([reads, [copy]]);
    assert.match(String(grouped.guidance), /Group independent file reads/);
    assert.equal(grouped.records.filter(r => r.tool === "read" && r.choice).length, 0);
    assert.equal(mixed.dialogs - grouped.dialogs, 2);
    t.diagnostic(`scripted mixed batch: ${mixed.dialogs} dialogs; same operations in separate batches: ${grouped.dialogs}`);

    const peer = join(dir, "peer"), sessions = join(dir, "shared-sessions");
    mkdirSync(sessions);
    const prior = "12345678-1234-1234-1234-1234567890ab";
    const row: AuditRecord = { tool: "bash", preview: "untrusted text", session: prior, action: "confirm", source: "sensitive",
      reasons: ["may expose secrets: the search would include private-marker"], final: "run", choice: "allow:once" };
    const append = (r: AuditRecord) => assert.equal(audit(r), true);
    writeFileSync(join(sessions, "timestamp_" + prior + ".jsonl"), JSON.stringify({ type: "session", id: prior, cwd: peer }) + "\n");
    append(row);
    append({ ...row, source: "safe", action: "allow" });
    append({ ...row, choice: "deny:once", final: "blocked" });
    assert.equal(projectGuidance(peer, sessions), "");
    append(row);
    assert.match(projectGuidance(peer, sessions), /list filenames first/);
    assert.doesNotMatch(projectGuidance(peer, sessions), /private-marker|untrusted text|Group independent/);
    assert.doesNotMatch(projectGuidance(cwd, sessions), /list filenames first/);
    assert.equal(projectGuidance(peer, join(dir, "missing")), "");
    const tagged = { ...row, project: mixed.records.find(r => r.choice)!.project };
    assert.ok(tagged.project);
    append(tagged);
    append(tagged);
    assert.match(projectGuidance(cwd, join(dir, "missing")), /-g '\*\.ts'/);
    assert.doesNotMatch(projectGuidance(peer, sessions), /-g '\*\.ts'/);
    assert.equal(projectGuidance(join(dir, "other"), sessions), "");
  } finally {
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(dir, { recursive: true, force: true });
  }
});
