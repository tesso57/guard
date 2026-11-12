import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("ripgrep visibility and guard decisions agree on representative searches", async (t) => {
  const executable = spawnSync("rg", ["--version"], { stdio: "ignore" });
  if ((executable.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
    assert.notEqual(process.env.GUARD_REQUIRE_RG, "1", "ripgrep is required in this test environment");
    return t.skip("ripgrep is not installed");
  }
  assert.equal(executable.status, 0, "ripgrep must be runnable");
  const dir = mkdtempSync(join(tmpdir(), "guard-rg-parity-"));
  const home = join(dir, "home"), project = join(dir, "project");
  mkdirSync(home); mkdirSync(project);
  const isolated = (key: string) => ["GIT_", "PI_", "RISK_", "GUARD_", "OPENAI_", "BASH_FUNC_"].some((prefix) => key.startsWith(prefix)) || ["HOME", "XDG_CONFIG_HOME", "RIPGREP_CONFIG_PATH", "BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS", "PS4"].includes(key);
  const previous = new Map(Object.entries(process.env).filter(([key]) => isolated(key)));
  for (const key of previous.keys()) delete process.env[key];
  Object.assign(process.env, { HOME: home, XDG_CONFIG_HOME: join(home, "config"), PI_CODING_AGENT_DIR: join(dir, "agent"), GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" });
  try {
    writeFileSync(join(project, ".env"), "needle\n");
    writeFileSync(join(project, ".ignore"), "!.env\n");
    writeFileSync(join(project, "visible.txt"), "needle\n");
    const { parseShell } = await import("../extensions/guard/shell.ts");
    const { safeAllow, searchNeedsJudgement, sensitive } = await import("../extensions/guard/policy.ts");
    const { clearPathCache, protectedRoots } = await import("../extensions/guard/paths.ts");
    const cases = [
      { options: [], expectSafe: false },
      { options: ["-u"], expectSafe: true },
      { options: ["--no-ignore"], expectSafe: true },
      { options: ["--engine", "auto", "-u"], expectSafe: true },
      { options: ["-uu"], expectSafe: false },
      { options: ["--hidden"], expectSafe: false },
      { options: ["-tsh"], expectSafe: false },
      { options: ["--type-add", "custom:.env", "-tcustom"], expectSafe: false },
      { options: ["-g", "*.txt"], expectSafe: true },
      { options: ["-g", "*.env"], expectSafe: false },
    ];
    for (const { options, expectSafe } of cases) {
      const args = ["--no-config", ...options, "needle", "."];
      const result = spawnSync("rg", ["-l", ...args], { cwd: project, encoding: "utf8" });
      assert.ok(result.status === 0 || result.status === 1, result.stderr);
      const command = ["rg", ...args.map((value) => /^[\w./=-]+$/.test(value) ? value : `'${value.replace(/'/g, "'\\''")}'`)].join(" ");
      clearPathCache();
      const parsed = parseShell(command);
      const flagged = !!sensitive("bash", { command }, project, protectedRoots(project), parsed) || searchNeedsJudgement("bash", { command }, project, parsed);
      if (result.stdout.split("\n").some((line) => line.endsWith("/.env"))) assert.equal(flagged, true, command);
      if (expectSafe) assert.equal(!flagged && safeAllow("bash", { command }, project, { trusted: true, touched: new Set() }, parsed), true, command);
    }
    writeFileSync(join(project, ".ignore"), "!README.md\n");
    writeFileSync(join(project, "README.md"), "needle\n");
    const literalRule = spawnSync("rg", ["--no-config", "-l", "needle", "."], { cwd: project, encoding: "utf8" });
    assert.equal(literalRule.status, 0);
    assert.equal(literalRule.stdout.includes(".env"), false);
    const literalCommand = "rg --no-config needle .";
    clearPathCache();
    const literalParsed = parseShell(literalCommand);
    assert.equal(sensitive("bash", { command: literalCommand }, project, protectedRoots(project), literalParsed), undefined);
    assert.equal(safeAllow("bash", { command: literalCommand }, project, { trusted: true, touched: new Set() }, literalParsed), true);
    const typeList = spawnSync("rg", ["--no-config", "--type-list"], { cwd: project, encoding: "utf8" });
    assert.equal(typeList.status, 0);
    clearPathCache();
    assert.equal(safeAllow("bash", { command: "rg --type-list" }, project, { trusted: true, touched: new Set() }, parseShell("rg --type-list")), true);
    unlinkSync(join(project, ".ignore"));
    assert.equal(spawnSync("git", ["init", "--quiet", project], { stdio: "ignore" }).status, 0);
    writeFileSync(join(project, ".gitignore"), "!.env\n");
    delete process.env.GIT_CONFIG_NOSYSTEM;
    for (const [options, dotRule, expectHidden] of [
      [["--no-ignore-vcs"], false, false],
      [["--no-ignore-vcs"], true, true],
      [["--no-ignore-vcs", "--no-ignore-dot"], true, false],
    ] as const) {
      if (dotRule) writeFileSync(join(project, ".ignore"), "!.env\n");
      const result = spawnSync("rg", ["--no-config", ...options, "-l", "needle", "."], { cwd: project, encoding: "utf8" });
      assert.equal(result.stdout.includes(".env"), expectHidden);
      const command = `rg --no-config ${options.join(" ")} needle .`;
      clearPathCache();
      const parsed = parseShell(command);
      const flagged = !!sensitive("bash", { command }, project, protectedRoots(project), parsed) || searchNeedsJudgement("bash", { command }, project, parsed);
      assert.equal(flagged, expectHidden, command);
    }
    if (process.platform !== "win32") {
      const marker = join(dir, "preprocessor-ran"), script = join(dir, "preprocessor"), config = join(dir, "ripgrep.conf");
      writeFileSync(script, '#!/bin/sh\nprintf called > "$GUARD_PARITY_MARKER"\ncat "$1"\n', { mode: 0o700 });
      writeFileSync(config, `--pre=${script}\n`);
      process.env.RIPGREP_CONFIG_PATH = config;
      process.env.GUARD_PARITY_MARKER = marker;
      clearPathCache();
      assert.equal(safeAllow("bash", { command: "rg --type-list" }, project, { trusted: true, touched: new Set() }, parseShell("rg --type-list")), false);
      const search = spawnSync("rg", ["needle", "visible.txt"], { cwd: project, encoding: "utf8" });
      assert.equal(search.status, 0);
      assert.equal(existsSync(marker), true, "the configured preprocessor must run for a normal search");
      rmSync(marker);
      for (const option of ["--version", "-V", "--help", "-h"]) {
        const result = spawnSync("rg", [option], { cwd: project, encoding: "utf8" });
        assert.equal(result.status, 0, option);
        assert.equal(existsSync(marker), false, option);
        const command = `rg ${option}`;
        clearPathCache();
        assert.equal(safeAllow("bash", { command }, project, { trusted: true, touched: new Set() }, parseShell(command)), true, command);
      }
    }
  } finally {
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(dir, { recursive: true, force: true });
  }
});
