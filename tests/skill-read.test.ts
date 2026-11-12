import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { isSkillRead } from "../extensions/guard/skill-read.ts";
import { searchNeedsJudgement, sensitive } from "../extensions/guard/policy.ts";
import { isReadOnlyArgv, parseShell, rgExplicitPaths } from "../extensions/guard/shell.ts";

test("ripgrep patterns and option values are not mistaken for search paths", () => {
  assert.deepEqual(rgExplicitPaths(["rg", "-e", "/skill/SKILL.md"]), []);
  assert.deepEqual(rgExplicitPaths(["rg", "-g", "*.md", "pattern", "/skill"]), ["/skill"]);
  assert.deepEqual(rgExplicitPaths(["rg", "-e", "pattern", "/skill"]), ["/skill"]);
  assert.deepEqual(rgExplicitPaths(["rg", "--files", "/skill"]), ["/skill"]);
  assert.deepEqual(rgExplicitPaths(["rg", "--", "pattern", "/skill"]), ["/skill"]);
});

test("skill reads with an unknown hard link use the normal guard checks", () => {
  const parent = mkdtempSync(join(tmpdir(), "guard-skill-hardlink-"));
  const cwd = join(parent, "project");
  const dir = join(cwd, ".agents", "skills", "example");
  const external = join(parent, "external");
  const skill = join(dir, "SKILL.md");
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(external, "example");
    linkSync(external, skill);
    assert.equal(isSkillRead("read", { path: skill }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `rg example '${dir}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `grep -r example '${dir}'` }, cwd), false);
    assert.ok(sensitive("read", { path: skill }, cwd, []));
    for (const command of [`cat '${skill}'`, `rg example '${dir}'`, `grep -r example '${dir}'`])
      assert.ok(sensitive("bash", { command }, cwd, [], parseShell(command)) || searchNeedsJudgement("bash", { command }, cwd, parseShell(command)), command);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test("skill reads bypass guard only when every hard link is known and non-sensitive", () => {
  const parent = mkdtempSync(join(tmpdir(), "guard-skill-known-links-"));
  const cwd = join(parent, "project");
  const dir = join(cwd, ".agents", "skills", "example");
  const skill = join(dir, "SKILL.md");
  const alias = join(cwd, "copy.md");
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(skill, "example");
    linkSync(skill, alias);
    assert.equal(isSkillRead("read", { path: skill }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}'` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `tail -n 10 '${skill}'` }, cwd), true);
    for (const option of ["-f", "-F", "-qF", "--follow", "--follow=name", "--fol"]) {
      assert.equal(isSkillRead("bash", { command: `tail ${option} '${skill}'` }, cwd), false, option);
      assert.equal(isReadOnlyArgv(["tail", option, skill]), false, option);
    }
    linkSync(skill, join(parent, "outside"));
    assert.equal(isSkillRead("read", { path: skill }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}'` }, cwd), false);
    unlinkSync(join(parent, "outside"));
    linkSync(skill, join(cwd, ".env"));
    assert.equal(isSkillRead("read", { path: skill }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}'` }, cwd), false);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

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
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | head -n 1` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | sed -n '1p'` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `grep -n example '${skill}'` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `grep -n 'example/path' '${skill}'` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `grep -n -e 'https://example.test/path' '${skill}' | head -n 1` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | grep example` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | rg example` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | rg -e 'example/path'` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | rg --files` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | rg --ignore-file '${outside}' example` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' && rg example` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | grep example | head -n 1` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | grep example\n` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' && grep example` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `grep example | cat '${skill}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | grep example '${outside}'` }, cwd), false);
    writeFileSync(join(cwd, ".agents", "skills", "example", "1"), "fixture");
    assert.equal(isSkillRead("bash", { command: "head -n 1 | grep example" }, join(cwd, ".agents", "skills", "example")), false, "an option value is not a pipeline source");
    assert.equal(isSkillRead("bash", { command: `grep -r example '${join(cwd, ".agents", "skills", "example")}'` }, cwd), true);
    assert.equal(isSkillRead("bash", { command: `grep -f '${outside}' '${skill}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `grep -if '${outside}' '${skill}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `grep -e example '${skill}' '${outside}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `grep --exclude-from='${outside}' example '${skill}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `grep -R example '${join(cwd, ".agents", "skills", "example")}'` }, cwd), false);
    const previousOptions = process.env.GREP_OPTIONS;
    process.env.GREP_OPTIONS = "--version";
    try { assert.equal(isSkillRead("bash", { command: `grep example '${skill}'` }, cwd), false); }
    finally { if (previousOptions === undefined) delete process.env.GREP_OPTIONS; else process.env.GREP_OPTIONS = previousOptions; }
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | tee '${outside}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' | head '${outside}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `rg -e '${skill}'` }, cwd), false, "a pattern is not a search root");
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' && rg -e '${skill}'` }, cwd), false, "a later rg must not search the working directory implicitly");
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' '${outside}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}' > '${outside}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${skill}'; rm '${outside}'` }, cwd), false);
    assert.equal(isSkillRead("bash", { command: `cat '${join(cwd, ".agents", "skills", "example", "outside")}'` }, cwd), false);
    assert.equal(isSkillRead("write", { path: skill, content: "changed" }, cwd), false);
    const registered = { path: outside, target: realpathSync(outside) };
    assert.equal(isSkillRead("read", { path: outside }, cwd, [registered]), true);
    assert.equal(isSkillRead("read", { path: outside }, cwd, [{ path: join(cwd, "different.md"), target: join(cwd, "different.md") }]), false);
    const replacement = join(cwd, "replacement.txt");
    writeFileSync(replacement, "replacement");
    unlinkSync(outside);
    symlinkSync(replacement, outside);
    assert.equal(isSkillRead("read", { path: outside }, cwd, [registered]), false, "a registered path cannot be retargeted after its target was captured");
    unlinkSync(skill);
    symlinkSync(outside, skill);
    assert.equal(isSkillRead("read", { path: skill }, cwd), false, "a retargeted path must not reuse a cached in-scope result");
  } finally { rmSync(cwd, { recursive: true, force: true }); }
});
