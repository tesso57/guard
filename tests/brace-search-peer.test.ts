import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";
import { createBashToolDefinition, createReadToolDefinition } from "@earendil-works/pi-coding-agent";
import { isBracePathSearch, parseShell } from "../extensions/guard/shell.ts";
import { createMockPi } from "./helpers/mock-pi.ts";

const search = "rg -n 'module|region' infra/{service,worker}/{prod/main.tf,modules/{network,db}.tf}; rg -l 'region' infra -g '*.tf' | head -25";

test("only literal rg path alternatives and plain search pipelines qualify as read peers", () => {
  const qualifies = (command: string) => isBracePathSearch(command, parseShell(command));
  assert.equal(qualifies(search), true);
  assert.equal(qualifies("rg pattern infra/{api,worker}/main.tf"), true);
  for (const command of [
    "rg pattern infra/{api,worker} > report.txt",
    "rg pattern infra/{api,worker} 2>/dev/null",
    "rg pattern infra/{1..10}",
    "rg 'pattern' {api,worker}",
    "rg -e {one,two} infra/main.tf",
    "rg pattern infra/{api,worker}; touch report.txt",
    "rg --unknown-option pattern infra/{api,worker}",
    "rg --pre=formatter pattern infra/{api,worker}",
    "rg pattern infra/{api,worker} | head -10 extra.txt",
  ]) assert.equal(qualifies(command), false, command);
});

test("a brace search peer preserves independent checks on the read and search", async t => {
  const dir = mkdtempSync(join(tmpdir(), "guard-brace-peer-"));
  const project = join(dir, "project");
  const requireRipgrep = process.env.GUARD_REQUIRE_RG === "1";
  const isolated = (key: string) => /^(PI_|RISK_|GUARD_|OPENAI_)/.test(key) || key === "RIPGREP_CONFIG_PATH";
  const previous = Object.entries(process.env).filter(([key]) => isolated(key));
  try {
    for (const [key] of previous) delete process.env[key];
    process.env.PI_CODING_AGENT_DIR = join(dir, "pi");
    mkdirSync(project);
    writeFileSync(join(project, "main.tf"), "ordinary content");
    writeFileSync(join(project, ".env"), "private fixture");
    const { default: guard } = await import("../extensions/index.ts");
    const { tail } = await import("../extensions/guard/audit.ts");
    const { RuleStore } = await import("../extensions/guard/rules.ts");
    const { inspectExecutablePath, shellStartupRisk } = await import("../extensions/guard/policy.ts");
    const verificationProblem = shellStartupRisk() ?? inspectExecutablePath(parseShell(search), project, process.platform, true).risk;
    if (requireRipgrep) assert.equal(verificationProblem, undefined);
    let prefix: string | undefined;
    let builtin = true;
    let sdkOverride = false;
    const definitions = [createBashToolDefinition(project), createReadToolDefinition(project)];
    const mock = createMockPi();
    Object.assign(mock.context, { cwd: project, hasUI: false, isProjectTrusted: () => true });
    Object.assign(mock.pi, {
      getAllTools: () => definitions.map(({ name, parameters, promptGuidelines }) => ({
        name, parameters, promptGuidelines: sdkOverride ? undefined : promptGuidelines,
        sourceInfo: { source: builtin ? "builtin" : "local", path: builtin ? `builtin:${name}` : "custom-tool" },
      })),
      getSettings: () => ({ shellCommandPrefix: prefix }),
    });
    guard(mock.pi);
    await mock.emit("session_start", { reason: "startup" });
    let number = 0;
    const assess = async (command: string, subject = "read", path = "main.tf", withWrite = false) => {
      const id = String(++number);
      const read = { id: "r" + id, type: "toolCall", name: "read", arguments: { path } };
      const bash = { id: "b" + id, type: "toolCall", name: "bash", arguments: { command } };
      const call = subject === "read" ? read : bash;
      const content = [read, bash, ...(withWrite ? [{ id: "w" + id, type: "toolCall", name: "write", arguments: { path, content: "new text" } }] : [])];
      await mock.emit("message_end", { message: { role: "assistant", content } });
      await mock.emit("tool_call", { toolCallId: call.id, toolName: call.name, input: call.arguments });
      return tail(1)[0];
    };
    if (!verificationProblem) {
      assert.equal((await assess(search)).final, "run");
      assert.equal((await assess(search, "read", ".env")).source, "concurrent");
      assert.equal((await assess(search, "read", "missing.tf")).source, "concurrent");
      assert.equal((await assess(search + " ; rg pattern .env", "bash")).source, "sensitive");
    } else {
      t.diagnostic(`Exercising the conservative branch: ${verificationProblem}`);
      assert.equal((await assess(search)).source, "concurrent");
    }
    const rules = new RuleStore();
    rules.load(project, true);
    for (const [decision, source] of [["allow", "concurrent"], ["ask", "rule-ask"], ["deny", "rule-deny"]] as const) {
      rules.add({ id: "peer-read-rule", scope: "project", decision, tool: "read", match: { kind: "path", path: join(project, "main.tf") }, createdAt: new Date().toISOString() }, () => {});
      assert.equal((await assess(search)).source, source, "a stored rule must still get the original review");
      rules.remove("peer-read-rule", () => {});
    }
    assert.equal((await assess(search, "read", "main.tf", true)).source, "concurrent");
    assert.equal((await assess(search + " > report.txt")).source, "concurrent");
    prefix = "pwd";
    assert.equal((await assess(search)).source, "concurrent");
    prefix = undefined;
    builtin = false;
    assert.equal((await assess(search)).source, "concurrent");
    builtin = true;
    sdkOverride = true;
    assert.equal((await assess(search)).source, "concurrent");
    sdkOverride = false;
    if (!verificationProblem) {
      const originalPath = process.env.PATH;
      try {
        symlinkSync(process.execPath, join(dir, "head"));
        process.env.PATH = [dir, originalPath].filter(Boolean).join(delimiter);
        assert.match(inspectExecutablePath(parseShell(search), project, process.platform, true).risk ?? "", /system head executable/);
        assert.equal((await assess(search)).source, "concurrent");
      } finally {
        if (originalPath === undefined) delete process.env.PATH;
        else process.env.PATH = originalPath;
      }
    }
    process.env.RIPGREP_CONFIG_PATH = join(project, "rg.conf");
    assert.equal((await assess(search)).source, "concurrent");
  } finally {
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(dir, { recursive: true, force: true });
  }
});
