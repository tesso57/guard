import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { artifactProjectRoot, clearPathCache, createTrustedDirState, protectedRoots, trustDir } from "../extensions/guard/paths.ts";
import { hardDeny, safeAllow, sensitive } from "../extensions/guard/policy.ts";
import { parseShell } from "../extensions/guard/shell.ts";

test("artifact grants cover only same-project sources and Markdown, including nested cwd", () => {
  const base = mkdtempSync(join(tmpdir(), "guard-artifact-"));
  const project = join(base, "project"), cwd = join(project, "src", "feature");
  const artifacts = join(project, ".pi", "_artifacts"), file = join(artifacts, "dashboard", "index.tsx");
  const state = createTrustedDirState();
  try {
    mkdirSync(cwd, { recursive: true });
    mkdirSync(join(artifacts, "dashboard", "docs"), { recursive: true });
    mkdirSync(join(project, ".git"));
    const roots = protectedRoots(cwd);
    const deny = (path: string, tool = "write") => { clearPathCache(); return hardDeny(tool, { path, content: "x" }, cwd, roots, undefined, 0, state); };
    assert.equal(artifactProjectRoot(cwd), project);
    assert.ok(deny(join(project, ".pi/settings.json")), "the Git root's .pi is protected from nested cwd");
    assert.ok(deny(file));
    assert.equal(trustDir(artifacts, false, "artifacts", state), undefined);
    assert.ok(deny(file));
    assert.equal(trustDir(artifacts, true, "artifacts", state), undefined);
    for (const path of [file, join(artifacts, "dashboard/docs/report.md")]) {
      assert.equal(deny(path), undefined, path);
      assert.equal(deny(path, "edit"), undefined, path);
      assert.equal(sensitive("write", { path, content: "x" }, cwd, roots, undefined, state), undefined, path);
      assert.equal(safeAllow("write", { path, content: "x" }, cwd, { trusted: false, touched: new Set(), trustedDirs: state, protectedPaths: roots }), true, path);
    }
    for (const path of [join(project, ".pi/settings.json"), join(project, ".pi/extensions/evil.ts"), join(project, ".pi/_artifacts-state/viewer.json"), join(artifacts, "dashboard/meta.json"), join(artifacts, "dashboard/package.json"), join(artifacts, "../settings.json"), join(base, "other/.pi/_artifacts/dashboard/index.tsx")]) {
      if (path.startsWith(base + "/other/")) { assert.notEqual(safeAllow("write", { path, content: "x" }, cwd, { trusted: false, touched: new Set(), trustedDirs: state, protectedPaths: roots }), true, path); continue; }
      assert.ok(deny(path), path);
    }
    const command = `echo x > '${file}'`;
    assert.ok(hardDeny("bash", { command }, cwd, roots, parseShell(command), 0, state));
    const config = join(project, ".pi/settings.json");
    writeFileSync(config, "protected");
    linkSync(config, file);
    assert.ok(deny(file), "hard link to settings");
    rmSync(file); symlinkSync(config, file);
    assert.ok(deny(file), "symlink to settings");
    rmSync(file);
    symlinkSync(base, join(artifacts, "dashboard", "escape"));
    assert.ok(deny(join(artifacts, "dashboard/escape/out.md")), "symlinked parent");
    rmSync(join(project, ".git"), { recursive: true });
    assert.equal(artifactProjectRoot(cwd), project, "without Git, the nearest .pi root is used");
  } finally { rmSync(base, { recursive: true, force: true }); }
});
