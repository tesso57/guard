import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("package check detects excluded extension files", () => {
  const dir = mkdtempSync(join(tmpdir(), "guard-package-check-"));
  const script = fileURLToPath(new URL("../scripts/check-package.mjs", import.meta.url));
  const manifest = {
    name: "guard-package-check-fixture",
    version: "1.0.0",
    files: ["extensions"],
    pi: { extensions: ["./extensions/index.ts"] },
  };
  const saveManifest = () => writeFileSync(join(dir, "package.json"), JSON.stringify(manifest));
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toLowerCase().startsWith("npm_config_")));
  Object.assign(env, {
    HOME: dir,
    npm_config_cache: join(dir, "cache"),
    npm_config_userconfig: join(dir, "user.npmrc"),
    npm_config_globalconfig: join(dir, "global.npmrc"),
  });
  const check = () => spawnSync(process.execPath, [script], {
    cwd: dir,
    encoding: "utf8",
    env,
  });
  try {
    mkdirSync(join(dir, "extensions"));
    writeFileSync(join(dir, "README.md"), "fixture");
    writeFileSync(join(dir, "LICENSE"), "fixture");
    writeFileSync(join(dir, "extensions", "index.ts"), "export {};\n");
    writeFileSync(join(dir, "extensions", "helper.ts"), "export {};\n");
    writeFileSync(join(dir, "extensions", ".DS_Store"), "Finder metadata");
    writeFileSync(join(dir, "extensions", ".npmignore"), "not-a-real-file\n");
    writeFileSync(join(dir, "extensions", ".gitignore"), "not-a-real-file\n");
    writeFileSync(join(dir, "extensions", ".npmrc"), "registry=https://example.invalid\n");
    writeFileSync(join(dir, "extensions", "npm-debug.log"), "debug output");
    writeFileSync(join(dir, "extensions", "._index.ts"), "resource fork");
    writeFileSync(join(dir, "extensions", ".index.ts.swp"), "editor swap");
    mkdirSync(join(dir, "extensions", ".git"));
    writeFileSync(join(dir, "extensions", ".git", "config"), "repository metadata");
    mkdirSync(join(dir, "extensions", "linked"));
    writeFileSync(join(dir, "extensions", "linked", ".git"), "gitdir: /tmp/example\n");
    saveManifest();

    const complete = check();
    assert.equal(complete.status, 0, complete.stderr);

    writeFileSync(join(dir, "extensions", ".npmignore"), "helper.ts\n");
    const ignoredSource = check();
    assert.notEqual(ignoredSource.status, 0);
    assert.match(ignoredSource.stderr, /Missing from npm package: extensions\/helper\.ts/);
    writeFileSync(join(dir, "extensions", ".npmignore"), "not-a-real-file\n");

    manifest.files = ["extensions/index.ts"];
    saveManifest();
    const incomplete = check();
    assert.notEqual(incomplete.status, 0);
    assert.match(incomplete.stderr, /Missing from npm package: extensions\/helper\.ts/);

    manifest.pi.extensions = [];
    saveManifest();
    const noEntry = check();
    assert.notEqual(noEntry.status, 0);
    assert.match(noEntry.stderr, /must declare at least one non-empty pi\.extensions entry/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
