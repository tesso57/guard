import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("Pi does not run a shadowed built-in search executable before confirmation", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-builtin-pi-"));
  const project = join(dir, "project"), agent = join(dir, "agent"), bin = join(dir, "bin"), marker = join(dir, "executed");
  try {
    mkdirSync(project); mkdirSync(bin);
    writeFileSync(join(project, "file.txt"), "needle\n");
    for (const binary of ["rg", "fd"]) writeFileSync(join(bin, binary), "#!/bin/sh\nprintf executed > \"$GUARD_TEST_MARKER\"\n", { mode: 0o755 });
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GUARD_|RISK_|PI_|OPENAI_|BASH_FUNC_)/.test(key) && !["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"].includes(key)));
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
