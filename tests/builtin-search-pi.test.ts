import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("Pi does not run a shadowed built-in search executable before confirmation", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-builtin-pi-"));
  const project = join(dir, "project"), agent = join(dir, "agent"), bin = join(dir, "bin"), marker = join(dir, "executed");
  try {
    mkdirSync(project); mkdirSync(bin);
    writeFileSync(join(project, "file.txt"), "needle\n");
    for (const binary of ["rg", "fd"]) writeFileSync(join(bin, binary), "#!/bin/sh\nprintf executed > \"$GUARD_TEST_MARKER\"\n", { mode: 0o755 });
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
    Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agent, GUARD_TEST_PROJECT: project, GUARD_TEST_MARKER: marker, PATH: `${bin}:/usr/bin:/bin` });
    for (const tool of ["grep", "find"]) {
      env.GUARD_TEST_TOOL = tool;
      const result = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
      assert.equal(result.status, 0, result.stderr);
      const output = JSON.parse(result.stdout);
      assert.equal(output.blocked, true, tool);
      assert.match(JSON.stringify(output.content), /guard/i, tool);
      assert.equal(existsSync(marker), false, `the fake executable for ${tool} must not run even for --version`);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("Pi cannot fall through a broken trusted candidate to an untrusted search executable", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-builtin-fallback-"));
  const first = mkdtempSync(join(process.cwd(), ".guard-builtin-fallback-"));
  const project = join(dir, "project"), agent = join(dir, "agent"), later = join(dir, "later"), marker = join(dir, "executed");
  try {
    mkdirSync(project); mkdirSync(later);
    writeFileSync(join(project, "file.txt"), "needle\n");
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
    Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agent, GUARD_TEST_PROJECT: project, GUARD_TEST_MARKER: marker, PATH: `${first}:${later}:/usr/bin:/bin` });
    for (const [tool, primary, fallback] of [["grep", "rg", "rg"], ["find", "fd", "fdfind"]]) {
      writeFileSync(join(first, primary), "#!/guard-missing-interpreter\n", { mode: 0o755 });
      writeFileSync(join(later, fallback), "#!/bin/sh\nprintf executed > \"$GUARD_TEST_MARKER\"\n", { mode: 0o755 });
      env.GUARD_TEST_TOOL = tool;
      const result = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
      assert.equal(result.status, 0, result.stderr);
      const output = JSON.parse(result.stdout);
      assert.equal(output.blocked, true, tool);
      assert.equal(existsSync(marker), false, tool);
      rmSync(join(first, primary)); rmSync(join(later, fallback));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(first, { recursive: true, force: true });
  }
});

test("Pi asks before a broken search executable can trigger a download", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-builtin-broken-"));
  const bin = mkdtempSync(join(process.cwd(), ".guard-builtin-broken-"));
  const project = join(dir, "project"), agent = join(dir, "agent");
  try {
    mkdirSync(project);
    writeFileSync(join(project, "file.txt"), "needle\n");
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
    Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agent, GUARD_TEST_PROJECT: project, PATH: bin });
    for (const [tool, binary] of [["grep", "rg"], ["find", "fd"]]) {
      writeFileSync(join(bin, binary), "#!/guard-missing-interpreter\n", { mode: 0o755 });
      env.GUARD_TEST_TOOL = tool;
      const result = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
      assert.equal(result.status, 0, result.stderr);
      const output = JSON.parse(result.stdout);
      assert.equal(output.blocked, true, tool);
      assert.match(JSON.stringify(output.content), /guard/i, tool);
      assert.equal(existsSync(join(agent, "bin")), false, tool);
      rmSync(join(bin, binary));
    }
    const nested = join(bin, "nested-interpreter");
    writeFileSync(nested, "#!/guard-missing-interpreter\n", { mode: 0o755 });
    writeFileSync(join(bin, "rg"), `#!${nested}\n`, { mode: 0o755 });
    env.GUARD_TEST_TOOL = "grep";
    const nestedResult = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
    assert.equal(nestedResult.status, 0, nestedResult.stderr);
    const nestedOutput = JSON.parse(nestedResult.stdout);
    assert.equal(nestedOutput.blocked, true);
    assert.match(JSON.stringify(nestedOutput.content), /guard/i);
    assert.equal(existsSync(join(agent, "bin")), false);
    writeFileSync(nested, "exit 0\n", { mode: 0o755 });
    const textResult = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
    assert.equal(textResult.status, 0, textResult.stderr);
    const textOutput = JSON.parse(textResult.stdout);
    assert.equal(textOutput.blocked, true);
    assert.match(JSON.stringify(textOutput.content), /guard/i);
    assert.equal(existsSync(join(agent, "bin")), false);
    writeFileSync(join(bin, "rg"), "not a runnable executable\n", { mode: 0o755 });
    const invalidResult = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
    assert.equal(invalidResult.status, 0, invalidResult.stderr);
    const invalidOutput = JSON.parse(invalidResult.stdout);
    assert.equal(invalidOutput.blocked, true);
    assert.match(JSON.stringify(invalidOutput.content), /guard/i);
    assert.equal(existsSync(join(agent, "bin")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(bin, { recursive: true, force: true });
  }
});

test("Pi skips guard for verified built-in searches inside skill directories", { skip: process.platform === "win32" }, (t) => {
  const dir = mkdtempSync(join(tmpdir(), "guard-builtin-skill-pi-"));
  const project = join(dir, "project"), agent = join(dir, "agent"), skill = join(project, ".agents", "skills", "fixture");
  try {
    mkdirSync(skill, { recursive: true });
    writeFileSync(join(skill, "needle"), "needle\n");
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
    Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agent, GUARD_TEST_PROJECT: project, GUARD_TEST_PATH: skill, GUARD_TEST_DENY: "1" });
    let exercised = 0;
    for (const [tool, binary] of [["grep", "rg"], ["find", "fd"]]) {
      const location = spawnSync("which", [binary], { encoding: "utf8" });
      if (location.status !== 0) continue;
      const executable = realpathSync(location.stdout.trim());
      if (basename(executable) !== binary) continue;
      env.PATH = `${dirname(executable)}:/usr/bin:/bin`;
      env.GUARD_TEST_TOOL = tool;
      const result = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
      assert.equal(result.status, 0, result.stderr);
      const output = JSON.parse(result.stdout);
      assert.equal(output.blocked, false, tool);
      assert.match(JSON.stringify(output.content), /needle/, tool);
      exercised++;
    }
    if (!exercised) t.skip("rg and fd are unavailable");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("offline Pi reports missing search tools without a confirmation or download", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-builtin-offline-"));
  const project = join(dir, "project"), agent = join(dir, "agent"), bin = join(dir, "empty-bin");
  const skill = join(project, ".agents", "skills", "fixture");
  try {
    mkdirSync(skill, { recursive: true }); mkdirSync(bin);
    writeFileSync(join(skill, "needle"), "needle\n");
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
    Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agent, PI_OFFLINE: "1", GUARD_TEST_PROJECT: project, GUARD_TEST_PATH: skill, PATH: bin });
    for (const tool of ["grep", "find"]) {
      env.GUARD_TEST_TOOL = tool;
      const result = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
      assert.equal(result.status, 0, result.stderr);
      const output = JSON.parse(result.stdout);
      assert.equal(output.blocked, true, tool);
      assert.match(JSON.stringify(output.content), /not available/i, tool);
      assert.doesNotMatch(JSON.stringify(output.content), /guard/i, tool);
      assert.equal(existsSync(join(agent, "bin")), false, tool);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
