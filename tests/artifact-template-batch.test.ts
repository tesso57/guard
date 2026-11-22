import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import type { ToolCall } from "@earendil-works/pi-ai";
import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import type { AuditRecord } from "../extensions/guard/audit.ts";
import { parseShell } from "../extensions/guard/shell.ts";
import { createFakeModel } from "./helpers/fake-model.ts";

const read = (id: string, path: string): ToolCall => ({ type: "toolCall", name: "read", id, arguments: { path } });
const template = (id: string, action: string): ToolCall => ({
  type: "toolCall", name: "artifact_template", id, arguments: action === "list" ? { action } : { action, name: "sample" },
});

test("Guard separates template lookups from file reads in a real Pi tool batch", async t => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "guard-template-batch-")));
  const cwd = join(dir, "project"), agentDir = join(dir, "agent");
  const files = Array.from({ length: 5 }, (_, i) => `document-${i}.txt`);
  mkdirSync(cwd);
  for (const file of files) writeFileSync(join(cwd, file), "contents of " + file);
  writeFileSync(join(cwd, ".env"), "private fixture");
  const isolated = (key: string) => /^(PI_|RISK_|GUARD_|OPENAI_)/.test(key) || ["HOME", "XDG_CONFIG_HOME"].includes(key);
  const previous = new Map(Object.entries(process.env).filter(([key]) => isolated(key)));
  for (const key of previous.keys()) delete process.env[key];
  Object.assign(process.env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agentDir, PI_OFFLINE: "1" });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("Unexpected network request in a local Pi test"); };
  try {
    async function run(batches: ToolCall[][], vouched = true) {
      const executed: string[] = [];
      const marker = join(cwd, "viewer-state-" + batches[0][0].id);
      const fake = createFakeModel([...batches.map(content => ({ content })), { content: [{ type: "text", text: "done" }] }]);
      const loader = new DefaultResourceLoader({
        cwd, agentDir, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
        additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))],
        extensionFactories: [pi => {
          pi.registerTool({
            name: "artifact_template", label: "Template", description: "Look up or manage templates",
            parameters: { type: "object", properties: { action: { type: "string" }, name: { type: "string" } }, required: ["action"] },
            async execute(id) {
              executed.push(id);
              if (!existsSync(marker)) writeFileSync(marker, "viewer ready", { flag: "wx" });
              return { content: [{ type: "text", text: "sample template" }], details: undefined };
            },
          });
          if (vouched) pi.on("session_start", () => pi.events.emit("guard:trust-tool", { tool: "artifact_template", by: "artifacts" }));
        }],
      });
      await loader.reload();
      assert.deepEqual(loader.getExtensions().errors, []);
      const manager = SessionManager.inMemory(cwd);
      const { session } = await createAgentSession({ cwd, agentDir, model: fake.model, sessionManager: manager, resourceLoader: loader });
      try {
        await session.bindExtensions({});
        session.modelRuntime.hasConfiguredAuth = () => true;
        session.agent.streamFunction = fake.stream;
        await session.prompt("Inspect the project and its templates");
        const results = session.messages.filter(m => m.role === "toolResult");
        const result = (id: string) => {
          const item = results.find(r => r.toolCallId === id);
          assert.ok(item, "missing tool result: " + id);
          return { error: item.isError, text: item.content.map(c => c.type === "text" ? c.text : "").join("") };
        };
        const audit: AuditRecord[] = readFileSync(join(agentDir, "guard", "audit.jsonl"), "utf8").trim().split("\n").map(line => JSON.parse(line));
        const prompt = fake.requests[0].messages.filter(m => m.role === "system").map(m => m.sections?.guard_artifact_lookups).join("\n");
        return { result, audit: audit.filter(e => e.session === manager.getSessionId()), prompt, executed, marker, requests: fake.requests.length };
      } finally { session.dispose(); }
    }

    for (const action of ["list", "get"]) {
      await t.test(action + " finishes once and files are read on the next turn", async () => {
        const first = files.map((file, i) => read(action + "-first-" + i, file));
        first[0].arguments.limit = null;
        const retry = files.map((file, i) => read(action + "-retry-" + i, file));
        const lookup = template("lookup-" + action, action);
        const observed = await run([[...first, lookup], retry]);
        assert.equal(observed.requests, 3, "deferring five calls must not abort the run");
        assert.match(observed.prompt, /artifact_template list or get by itself/i);
        assert.deepEqual(observed.executed, [lookup.id]);
        assert.equal(readFileSync(observed.marker, "utf8"), "viewer ready");
        assert.equal(observed.result(lookup.id).error, false);
        for (const [i, item] of first.entries()) {
          assert.equal(observed.result(item.id).error, true);
          assert.match(observed.result(item.id).text, /retry|next message/i);
          assert.deepEqual(observed.result(retry[i].id), { error: false, text: "contents of " + files[i] });
        }
        const deferred = observed.audit.filter(e => e.source === "deferred");
        assert.equal(deferred.length, first.length);
        assert.ok(deferred.every(e => e.action === "block" && e.final === "blocked" && !e.choice));
        assert.ok(observed.audit.every(e => e.action !== "confirm"));
      });
    }

    await t.test("repeating a mixed batch falls back to confirmation", async () => {
      const observed = await run([
        [read("mixed-1", files[0]), read("mixed-duplicate", files[0]), template("lookup-1", "list")],
        [read("mixed-2", files[0]), template("lookup-2", "list")],
      ]);
      assert.deepEqual(observed.audit.filter(e => e.tool === "read").map(e => [e.source, e.action]), [
        ["deferred", "block"], ["deferred", "block"], ["concurrent", "confirm"],
      ]);
    });

    const { inspectExecutablePath, shellStartupRisk } = await import("../extensions/guard/policy.ts");
    const command = "rg -n contents " + files[0];
    const searchProblem = shellStartupRisk() ?? inspectExecutablePath(parseShell(command), cwd, process.platform, true).risk;
    await t.test("an eligible Bash search runs under normal policy on retry", { skip: searchProblem }, async () => {
      const bash = (id: string): ToolCall => ({ type: "toolCall", name: "bash", id, arguments: { command } });
      const observed = await run([[template("lookup-search", "list"), bash("search")], [bash("search-retry")]]);
      assert.match(observed.result("search").text, /retry/i);
      assert.equal(observed.result("search-retry").error, false);
      assert.match(observed.result("search-retry").text, /contents of document-0\.txt/);
      assert.deepEqual(observed.audit.filter(e => e.tool === "bash").map(e => [e.source, e.action]), [
        ["deferred", "block"], ["safe", "allow"],
      ]);
    });

    await t.test("a batch that also writes retains the existing decisions", async () => {
      const write: ToolCall = { type: "toolCall", id: "protected-write", name: "write", arguments: { path: ".pi/guard.json", content: "{}" } };
      const observed = await run([[read("mixed-read", files[0]), template("lookup-write", "list"), write]]);
      assert.ok(observed.audit.some(e => e.tool === "read" && e.source === "concurrent"));
      assert.ok(observed.audit.some(e => e.tool === "write" && e.source === "hard-deny"));
      assert.equal(existsSync(join(cwd, ".pi/guard.json")), false);
      assert.ok(observed.audit.every(e => e.source !== "deferred"));
    });

    for (const [action, vouched] of [["save", true], ["delete", true], ["list", false]] as const) {
      await t.test(`${action} (vouched=${vouched}) keeps independent checks`, async () => {
        const id = "control-" + action;
        const observed = await run([[read(id, files[0]), template("peer-" + action, action)]], vouched);
        assert.equal(observed.result(id).error, true);
        assert.ok(observed.audit.some(e => e.tool === "read" && e.source === "concurrent" && e.choice === "no-ui"));
        if (!vouched) assert.doesNotMatch(observed.prompt, /artifact_template list or get by itself/i);
      });
    }

    await t.test("a sensitive file still requires confirmation when retried alone", async () => {
      const observed = await run([[read("sensitive", ".env"), template("lookup-env", "get")], [read("alone", ".env")]]);
      assert.equal(observed.result("sensitive").error, true);
      assert.equal(observed.result("alone").error, true);
      assert.ok(observed.audit.some(e => e.tool === "read" && e.source === "sensitive" && e.choice === "no-ui"));
    });
    await t.test("a missing read returns to normal judgement", async () => {
      const observed = await run([
        [read("missing", "missing.txt"), template("lookup-missing", "get")],
        [read("missing-retry", "missing.txt")],
      ]);
      assert.match(observed.result("missing").text, /retry/i);
      assert.equal(observed.result("missing-retry").error, true);
      const attempts = observed.audit.filter(e => e.tool === "read");
      assert.equal(attempts[0]?.source, "deferred");
      assert.equal(attempts[1]?.action, "confirm");
      assert.equal(attempts[1]?.choice, "no-ui");
    });
  } finally {
    globalThis.fetch = originalFetch;
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(dir, { recursive: true, force: true });
  }
});
