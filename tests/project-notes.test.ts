import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { clearPathCache, createTrustedDirState, protectedRoots, trustDir } from "../extensions/guard/paths.ts";
import { hardDeny, safeAllow } from "../extensions/guard/policy.ts";
import { parseShell } from "../extensions/guard/shell.ts";

test("project notes require an exact write grant without weakening pi protection", () => {
  const project = mkdtempSync(join(tmpdir(), "guard-project-notes-"));
  const state = createTrustedDirState();
  const roots = protectedRoots(project);
  const note = join(project, ".pi/_notes/session-1/note.md");
  const factory = join(project, ".pi/_notes/session-1/factory");
  const check = (path: string, tool = "write") => {
    clearPathCache();
    return hardDeny(tool, { path, content: "text" }, project, roots, undefined, 0, state);
  };
  try {
    mkdirSync(factory, { recursive: true });
    assert.ok(check(note), "an ungranted note is protected");
    assert.equal(trustDir(dirname(note), false, "note", state), undefined);
    assert.ok(check(note), "a read grant does not allow writes");
    assert.equal(trustDir(dirname(note), true, "note", state), undefined);
    assert.equal(trustDir(factory, true, "note", state), undefined);
    for (const path of [note, ...["plan", "review", "learnings"].map((name) => join(factory, `${name}.md`))]) {
      assert.equal(check(path), undefined, path);
      assert.equal(check(path, "edit"), undefined, path);
      assert.equal(safeAllow("write", { path, content: "text" }, project, { trustedDirs: state, protectedPaths: roots, trusted: false, touched: new Set() }), true, path);
    }
    for (const path of [join(project, ".pi/settings.json"), join(project, ".pi/extensions/evil.ts"), join(factory, "other.md"), join(project, ".pi/_notes/session-1/../settings.json")]) assert.ok(check(path), path);
    const command = `echo x > '${note}'`;
    assert.ok(hardDeny("bash", { command }, project, roots, parseShell(command), 0, state), "shell writes remain protected");
    const secret = join(project, ".pi/settings.json");
    writeFileSync(secret, "protected");
    linkSync(secret, note);
    assert.ok(check(note), "hard links cannot bypass protected files");
    rmSync(note);
    symlinkSync(secret, note);
    assert.ok(check(note), "symlinks cannot bypass protected files");
  } finally { rmSync(project, { recursive: true, force: true }); }
});
