import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { isSkillRead } from "../extensions/guard/skill-read.ts";

test("only direct read-only access within standard skill directories bypasses guard", () => {
  const cwd = mkdtempSync(join(tmpdir(), "guard-skill-read-"));
  const skill = join(cwd, ".agents", "skills", "example", "SKILL.md");
  const outside = join(cwd, "outside.txt");
  try {
    mkdirSync(join(cwd, ".agents", "skills", "example"), { recursive: true });
    writeFileSync(skill, "example");
    writeFileSync(outside, "outside");
    symlinkSync(outside, join(cwd, ".agents", "skills", "example", "outside"));
    assert.equal(isSkillRead("read", { path: skill }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}'` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' '${outside}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' > '${outside}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}'; rm '${outside}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${join(cwd, ".agents", "skills", "example", "outside")}'` }, cwd), false);
    assert.equal(isSkillRead("write", { path: skill, content: "changed" }, cwd), false);
    assert.equal(isSkillRead("read", { path: outside }, cwd, [outside]), true);
    assert.equal(isSkillRead("read", { path: outside }, cwd, [join(cwd, "different.md")]), false);
    unlinkSync(skill);
    symlinkSync(outside, skill);
    assert.equal(isSkillRead("read", { path: skill }, cwd), false, "a retargeted path must not reuse a cached in-scope result");
  } finally { rmSync(cwd, { recursive: true, force: true }); }
});
