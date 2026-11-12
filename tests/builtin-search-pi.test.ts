import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { machoLoaders } from "../extensions/guard/macho.ts";

test("Pi does not run a shadowed built-in search executable before confirmation", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-builtin-pi-"));
  const project = join(dir, "project"), agent = join(dir, "agent"), bin = join(dir, "bin"), marker = join(dir, "executed");
  try {
    mkdirSync(project); mkdirSync(bin);
    writeFileSync(join(project, "file.txt"), "needle\n");
    for (const binary of ["rg", "fd"]) writeFileSync(join(bin, binary), "#!/bin/sh\nprintf executed > \"$GUARD_TEST_MARKER\"\n", { mode: 0o755 });
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_|LD_|DYLD_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
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
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_|LD_|DYLD_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
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
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_|LD_|DYLD_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
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
    const emptyNative = Buffer.alloc(64);
    if (process.platform === "darwin") {
      Buffer.from("cffaedfe", "hex").copy(emptyNative);
      emptyNative.writeUInt32LE(2, 12);
    } else {
      Buffer.from("7f454c46", "hex").copy(emptyNative);
      emptyNative[4] = 2; emptyNative[5] = 1; emptyNative[6] = 1;
      emptyNative.writeUInt16LE(2, 16);
    }
    writeFileSync(join(bin, "rg"), emptyNative, { mode: 0o755 });
    const nativeResult = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
    assert.equal(nativeResult.status, 0, nativeResult.stderr);
    const nativeOutput = JSON.parse(nativeResult.stdout);
    assert.equal(nativeOutput.blocked, true);
    assert.match(JSON.stringify(nativeOutput.content), /guard/i);
    assert.equal(existsSync(join(agent, "bin")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(bin, { recursive: true, force: true });
  }
});

test("Pi asks before an ELF with a missing dynamic loader can trigger a download", { skip: process.platform !== "linux" }, (t) => {
  const original = readFileSync(realpathSync("/bin/sh"));
  if (original.subarray(0, 4).toString("hex") !== "7f454c46" || original[4] !== 2 || original[5] !== 1) return t.skip("requires a little-endian ELF64 /bin/sh");
  const table = Number(original.readBigUInt64LE(32)), entrySize = original.readUInt16LE(54), count = original.readUInt16LE(56);
  let offset = 0, length = 0, entry = 0;
  for (let i = 0; i < count; i++) {
    const base = table + i * entrySize;
    if (base + 56 > original.length) return t.skip("program header table is unavailable");
    if (original.readUInt32LE(base) === 3) { entry = base; offset = Number(original.readBigUInt64LE(base + 8)); length = Number(original.readBigUInt64LE(base + 32)); break; }
  }
  if (length < 5 || offset + length > original.length) return t.skip("/bin/sh has no usable PT_INTERP");
  const missing = `/${"z".repeat(length - 2)}`;
  if (existsSync(missing)) return t.skip("fixture loader unexpectedly exists");
  const dir = mkdtempSync(join(tmpdir(), "guard-elf-loader-"));
  const bin = mkdtempSync(join(process.cwd(), ".guard-elf-loader-"));
  const project = join(dir, "project"), agent = join(dir, "agent");
  try {
    mkdirSync(project);
    writeFileSync(join(project, "file.txt"), "needle\n");
    original.fill(0, offset, offset + length);
    Buffer.from(missing).copy(original, offset);
    const executable = join(bin, "rg");
    writeFileSync(executable, original, { mode: 0o755 });
    assert.equal((spawnSync(executable, ["--version"]).error as NodeJS.ErrnoException | undefined)?.code, "ENOENT");
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_|LD_|DYLD_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
    Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agent, GUARD_TEST_PROJECT: project, GUARD_TEST_TOOL: "grep", PATH: bin });
    const result = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.blocked, true);
    assert.match(JSON.stringify(output.content), /guard/i);
    assert.equal(existsSync(join(agent, "bin")), false);
    const unexpected = "/usr/bin/env";
    if (existsSync(unexpected) && unexpected.length + 1 <= length) {
      original.fill(0, offset, offset + length);
      Buffer.from(unexpected).copy(original, offset);
      original.writeBigUInt64LE(BigInt(unexpected.length + 1), entry + 32);
      writeFileSync(executable, original, { mode: 0o755 });
      const unexpectedResult = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
      assert.equal(unexpectedResult.status, 0, unexpectedResult.stderr);
      const unexpectedOutput = JSON.parse(unexpectedResult.stdout);
      assert.equal(unexpectedOutput.blocked, true);
      assert.match(JSON.stringify(unexpectedOutput.content), /guard/i);
      assert.equal(existsSync(join(agent, "bin")), false);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); rmSync(bin, { recursive: true, force: true }); }
});

test("Pi asks before a Mach-O with an untrusted loader can trigger a download", { skip: process.platform !== "darwin" }, (t) => {
  const location = spawnSync("which", ["rg"], { encoding: "utf8" });
  if (location.status !== 0) return t.skip("ripgrep is unavailable");
  const file = readFileSync(realpathSync(location.stdout.trim()));
  const needle = Buffer.from("/usr/lib/dyld\0"), replacement = Buffer.from(`/${"z".repeat(needle.length - 2)}\0`);
  let changed = false, from = 0;
  for (;;) {
    const at = file.indexOf(needle, from);
    if (at < 0) break;
    replacement.copy(file, at); changed = true; from = at + needle.length;
  }
  if (!changed) return t.skip("ripgrep does not contain a standard loader path");
  const parsed = machoLoaders(file.length, (offset, length) => file.subarray(offset, offset + length));
  assert.ok(parsed?.loaders.some((loader) => loader !== "/usr/lib/dyld"));
  const dir = mkdtempSync(join(tmpdir(), "guard-macho-loader-"));
  const bin = mkdtempSync(join(process.cwd(), ".guard-macho-loader-"));
  const project = join(dir, "project"), agent = join(dir, "agent");
  try {
    mkdirSync(project);
    writeFileSync(join(project, "file.txt"), "needle\n");
    writeFileSync(join(bin, "rg"), file, { mode: 0o755 });
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_|LD_|DYLD_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
    Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agent, GUARD_TEST_PROJECT: project, GUARD_TEST_TOOL: "grep", PATH: bin });
    const result = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.blocked, true);
    assert.match(JSON.stringify(output.content), /guard/i);
    assert.equal(existsSync(join(agent, "bin")), false);
  } finally { rmSync(dir, { recursive: true, force: true }); rmSync(bin, { recursive: true, force: true }); }
});

test("Pi skips guard for verified built-in searches inside skill directories", { skip: process.platform === "win32" }, (t) => {
  const dir = mkdtempSync(join(tmpdir(), "guard-builtin-skill-pi-"));
  const project = join(dir, "project"), agent = join(dir, "agent"), skill = join(project, ".agents", "skills", "fixture");
  try {
    mkdirSync(skill, { recursive: true });
    writeFileSync(join(skill, "needle"), "needle\n");
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_|LD_|DYLD_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
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
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_|LD_|DYLD_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
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

test("Pi does not skip a skill search with dynamic-loader injection settings", { skip: process.platform !== "darwin" && process.platform !== "linux" }, (t) => {
  const location = spawnSync("which", ["rg"], { encoding: "utf8" });
  if (location.status !== 0) return t.skip("ripgrep is unavailable");
  const executable = realpathSync(location.stdout.trim());
  if (basename(executable) !== "rg") return t.skip("ripgrep executable name cannot be verified");
  const dir = mkdtempSync(join(tmpdir(), "guard-builtin-loader-env-"));
  const project = join(dir, "project"), agent = join(dir, "agent"), skill = join(project, ".agents", "skills", "fixture");
  try {
    mkdirSync(skill, { recursive: true });
    writeFileSync(join(skill, "needle"), "needle\n");
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_|LD_|DYLD_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
    Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agent, GUARD_TEST_PROJECT: project, GUARD_TEST_PATH: skill, GUARD_TEST_TOOL: "grep", GUARD_TEST_LOADER_KEY: process.platform === "darwin" ? "DYLD_INSERT_LIBRARIES" : "LD_PRELOAD", PATH: `${dirname(executable)}:/usr/bin:/bin` });
    const result = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.blocked, true);
    assert.match(JSON.stringify(output.content), /guard/i);
    const audit = readFileSync(join(agent, "guard", "audit.jsonl"), "utf8");
    assert.match(audit, /dynamic loader environment/);
    assert.doesNotMatch(audit, /guard-test-loader/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("Pi blocks an active empty loader-debug output path before it creates a file", { skip: process.platform !== "linux" }, (t) => {
  const location = spawnSync("which", ["rg"], { encoding: "utf8" });
  if (location.status !== 0) return t.skip("ripgrep is unavailable");
  const executable = realpathSync(location.stdout.trim());
  if (basename(executable) !== "rg") return t.skip("ripgrep executable name cannot be verified");
  const dir = mkdtempSync(join(tmpdir(), "guard-empty-loader-debug-"));
  const project = join(dir, "project"), agent = join(dir, "agent"), skill = join(project, ".agents", "skills", "fixture");
  try {
    mkdirSync(skill, { recursive: true });
    writeFileSync(join(skill, "needle"), "needle\n");
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_|LD_|DYLD_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "RIPGREP_CONFIG_PATH", "GREP_OPTIONS"].includes(key)));
    Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agent, GUARD_TEST_PROJECT: project, GUARD_TEST_PATH: skill, GUARD_TEST_TOOL: "grep", GUARD_TEST_EMPTY_DEBUG: "1", PATH: `${dirname(executable)}:/usr/bin:/bin` });
    const result = spawnSync(process.execPath, ["--experimental-strip-types", fileURLToPath(new URL("./helpers/builtin-search-child.mjs", import.meta.url))], { cwd: project, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.blocked, true);
    assert.match(JSON.stringify(output.content), /guard/i);
    assert.match(readFileSync(join(agent, "guard", "audit.jsonl"), "utf8"), /dynamic loader environment/);
    assert.equal(readdirSync(project).some((name) => /^\.\d+$/.test(name)), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
