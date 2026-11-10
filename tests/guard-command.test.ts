import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createMockPi } from "./helpers/mock-pi.ts";

test("guard restores session state and enforces rules across Pi branches", async () => {
  const dir = await mkdtemp(join(tmpdir(), "guard-command-"));
  const isolated = (name: string) => name.startsWith("RISK_") || name.startsWith("GUARD_") || name === "PI_CODING_AGENT_DIR" || name === "OPENAI_BASE_URL";
  const previous = new Map(Object.entries(process.env).filter(([name]) => isolated(name)));
  for (const name of previous.keys()) delete process.env[name];
  process.env.PI_CODING_AGENT_DIR = join(dir, "agent");
  try {
    const { default: guard } = await import("../extensions/index.ts");
    const mock = createMockPi();
    Object.assign(mock.context, { cwd: dir, isProjectTrusted: () => false });
    guard(mock.pi);

    await mock.runCommand("guard", "off unexpected");
    assert.match(mock.notifications.at(-1)!.message, /usage: \/guard on\|off/);
    assert.equal(mock.sessionManager.getLeafId(), null);
    await mock.runCommand("guard");
    assert.match(mock.notifications.at(-1)!.message, /guard: on \|/);
    await mock.runCommand("guard", "off");
    await mock.runCommand("guard");
    assert.match(mock.notifications.at(-1)!.message, /guard: off \|/);
    await mock.runCommand("guard", "on");
    await mock.runCommand("guard");
    assert.match(mock.notifications.at(-1)!.message, /guard: on \|/);

    const entries = mock.context.sessionManager.getBranch().filter((entry) => entry.type === "custom");
    assert.deepEqual(entries.map((entry) => entry.data), [{ enabled: false }, { enabled: true }]);

    mock.sessionManager.branch(entries[0].id);
    await mock.emit("session_tree", { type: "session_tree" });
    await mock.runCommand("guard");
    assert.match(mock.notifications.at(-1)!.message, /guard: off \|/);
    assert.equal(mock.statuses.get("guard"), "guard: off");

    mock.sessionManager.branch(entries[1].id);
    await mock.emit("session_tree", { type: "session_tree" });
    await mock.runCommand("guard");
    assert.match(mock.notifications.at(-1)!.message, /guard: on \|/);
    assert.equal(mock.statuses.get("guard"), "guard: rules only");

    for (const tool of ["bash", "read", "write", "edit", "powershell"]) {
      await mock.runCommand("guard", `rules add allow session tool:${tool}`);
      assert.match(mock.notifications.at(-1)!.message, /cannot use an any-input allow rule/);
    }
    for (const pattern of ["tool:custom extra", "tool:", "path:", "path:example.txt write extra"]) {
      await mock.runCommand("guard", `rules add deny session ${pattern}`);
      assert.match(mock.notifications.at(-1)!.message, /invalid rule/);
    }
    await mock.runCommand("guard", "rules add allow session git -C . status");
    assert.match(mock.notifications.at(-1)!.message, /location or unrecognized options/);
    await mock.runCommand("guard");
    assert.match(mock.notifications.at(-1)!.message, /rules: session 0 \/ /);
    await mock.runCommand("guard", "rules add deny session tool:write");
    assert.match(mock.notifications.at(-1)!.message, /added session deny rule/);
    const ruleBranch = mock.sessionManager.getLeafId();
    assert.ok(ruleBranch);
    const denyRule = mock.sessionManager.getLeafEntry();
    assert.ok(denyRule && denyRule.type === "custom");
    const ruleId = (denyRule.data as { rule: { id: string } }).rule.id;
    await mock.runCommand("guard", `rules rm ${ruleId} unexpected`);
    assert.match(mock.notifications.at(-1)!.message, /usage: \/guard rules rm/);
    await mock.runCommand("guard", `rules promote ${ruleId} project unexpected`);
    assert.match(mock.notifications.at(-1)!.message, /usage: \/guard rules promote/);
    assert.equal(mock.sessionManager.getLeafId(), ruleBranch);
    await mock.runCommand("guard");
    assert.match(mock.notifications.at(-1)!.message, /rules: session 1 \/ /);
    const call = (id: string) => mock.emit("tool_call", { type: "tool_call", toolCallId: id, toolName: "write", input: { path: join(dir, "example.txt"), content: "example" } });
    const [blockedBeforeRewind] = await call("before-rewind");
    assert.equal((blockedBeforeRewind as { block?: boolean })?.block, true);

    mock.sessionManager.branch(entries[1].id);
    await mock.emit("session_tree", { type: "session_tree" });
    await mock.runCommand("guard");
    assert.match(mock.notifications.at(-1)!.message, /rules: session 0 \/ /);
    assert.deepEqual(await call("without-rule"), [undefined]);

    mock.sessionManager.branch(ruleBranch);
    await mock.emit("session_tree", { type: "session_tree" });
    await mock.runCommand("guard");
    assert.match(mock.notifications.at(-1)!.message, /rules: session 1 \/ /);
    const [blockedAfterRestore] = await call("restored-rule");
    assert.equal((blockedAfterRestore as { block?: boolean })?.block, true);

    await mock.runCommand("guard", "rules add deny session git -C . push --force");
    assert.match(mock.notifications.at(-1)!.message, /added session deny rule/);
    const wrappedRuleEntry = mock.sessionManager.getLeafEntry();
    assert.ok(wrappedRuleEntry && wrappedRuleEntry.type === "custom");
    assert.deepEqual((wrappedRuleEntry.data as { rule: { match: { prefix: string[] } } }).rule.match.prefix, ["git", "push", "--force"]);
    const [blockedWrapped] = await mock.emit("tool_call", { type: "tool_call", toolCallId: "wrapped-rule", toolName: "bash", input: { command: "git push --force" } });
    assert.equal((blockedWrapped as { block?: boolean })?.block, true);
    assert.deepEqual(await mock.emit("tool_call", { type: "tool_call", toolCallId: "reset-counter", toolName: "bash", input: { command: "printf safe" } }), [undefined]);

    await mock.runCommand("guard", "rules add deny session printf 'hello  world'");
    assert.match(mock.notifications.at(-1)!.message, /added session deny rule/);
    assert.match(mock.notifications.at(-1)!.message, /printf 'hello  world'/);
    const ruleEntry = mock.sessionManager.getLeafEntry();
    assert.ok(ruleEntry && ruleEntry.type === "custom");
    assert.deepEqual((ruleEntry.data as { rule: { match: { prefix: string[] } } }).rule.match.prefix, ["printf", "hello  world"]);
    await mock.runCommand("guard", "check printf 'hello  world'");
    assert.match(mock.notifications.at(-1)!.message, /BLOCK via rule-deny/);
    await mock.runCommand("guard", "printf 'hello  world'");
    assert.match(mock.notifications.at(-1)!.message, /BLOCK via rule-deny/);
    await mock.runCommand("guard", "check");
    assert.match(mock.notifications.at(-1)!.message, /usage: \/guard check/);
    const [blockedQuoted] = await mock.emit("tool_call", { type: "tool_call", toolCallId: "quoted-rule", toolName: "bash", input: { command: "printf 'hello  world'" } });
    assert.equal((blockedQuoted as { block?: boolean })?.block, true);
    const leaf = mock.sessionManager.getLeafId();
    for (const pattern of ["echo ok; rm file", "echo $(whoami)", "cat *.txt", "cat < file"]) {
      await mock.runCommand("guard", `rules add deny session ${pattern}`);
      assert.match(mock.notifications.at(-1)!.message, /one static command/);
      assert.equal(mock.sessionManager.getLeafId(), leaf);
    }
    await mock.runCommand("guard", "rules add allow session rm disposable.txt");
    assert.match(mock.notifications.at(-1)!.message, /added session allow rule/);
    const exactRule = mock.sessionManager.getLeafEntry();
    assert.ok(exactRule && exactRule.type === "custom");
    assert.deepEqual((exactRule.data as { rule: { match: unknown } }).rule.match, { kind: "argv-exact", argv: ["rm", "disposable.txt"] });
    assert.deepEqual(await mock.emit("tool_call", { type: "tool_call", toolCallId: "exact-allow", toolName: "bash", input: { command: "rm disposable.txt" } }), [undefined]);
    await mock.runCommand("guard", "rules add allow session cp source.txt dest.txt");
    const copyRule = mock.sessionManager.getLeafEntry();
    assert.ok(copyRule && copyRule.type === "custom");
    assert.deepEqual((copyRule.data as { rule: { match: unknown } }).rule.match, { kind: "argv-exact", argv: ["cp", "source.txt", "dest.txt"] });
    assert.deepEqual(await mock.emit("tool_call", { type: "tool_call", toolCallId: "exact-copy", toolName: "bash", input: { command: "cp source.txt dest.txt" } }), [undefined]);
    Object.assign(mock.context, { hasUI: false });
    const [extraCopyArgument] = await mock.emit("tool_call", { type: "tool_call", toolCallId: "extra-copy", toolName: "bash", input: { command: "cp source.txt dest.txt extra.txt" } });
    assert.equal((extraCopyArgument as { block?: boolean })?.block, true);
    Object.assign(mock.context, { hasUI: true });
    await mock.runCommand("guard", "rules add allow session npm test");
    const npmRule = mock.sessionManager.getLeafEntry();
    assert.ok(npmRule && npmRule.type === "custom");
    assert.deepEqual((npmRule.data as { rule: { match: unknown } }).rule.match, { kind: "argv", prefix: ["npm", "test"] });
  } finally {
    for (const name of Object.keys(process.env)) if (isolated(name)) delete process.env[name];
    for (const [name, value] of previous) {
      if (value !== undefined) process.env[name] = value;
    }
    await rm(dir, { recursive: true, force: true });
  }
});
