import assert from "node:assert/strict";
import test from "node:test";
import { createEditTool } from "@earendil-works/pi-coding-agent";
import { predictEdits } from "../extensions/guard/edits.ts";

test("edit predictions do not assume success when Pi sees fuzzy duplicates", async () => {
  for (const content of ["hello—world\nhello-world\n", "say ‘hi’\nsay 'hi'\n", "name  \nname\n", "ＡＢＣ\nABC\n"]) {
    const oldText = content.split("\n")[1];
    const input = { path: "fixture", edits: [{ oldText, newText: "replacement" }] };
    let wrote = false;
    const tool = createEditTool("/tmp", { operations: {
      access: async () => {},
      readFile: async () => Buffer.from(content),
      writeFile: async () => { wrote = true; },
    } });
    await assert.rejects(tool.execute("fixture", input));
    assert.equal(wrote, false);
    assert.equal(predictEdits(content, input), undefined);
  }
});

test("unambiguous predictions agree with the real Pi edit tool", async () => {
  for (const content of ["before\nafter\n", "\uFEFFbefore\r\nafter\r\n", "日本語 before\nafter\n"]) {
    const input = { path: "fixture", edits: [{ oldText: "before", newText: "changed" }] };
    let written: string | undefined;
    const tool = createEditTool("/tmp", { operations: {
      access: async () => {},
      readFile: async () => Buffer.from(content),
      writeFile: async (_path, value) => { written = value; },
    } });
    await tool.execute("fixture", input);
    assert.notEqual(written, undefined);
    assert.equal(predictEdits(content, input), written);
  }
});

test("edits that leave normalized content unchanged are not predicted as successful", async () => {
  for (const content of ["before\n", "\uFEFFbefore\r\n"]) {
    const input = { path: "fixture", edits: [{ oldText: "before", newText: "before" }] };
    const tool = createEditTool("/tmp", { operations: {
      access: async () => {},
      readFile: async () => Buffer.from(content),
      writeFile: async () => { throw new Error("unexpected write"); },
    } });
    await assert.rejects(tool.execute("fixture", input), /No changes made/);
    assert.equal(predictEdits(content, input), undefined);
  }
});

test("large edit batches fall back to confirmation instead of monopolizing the event loop", () => {
  const edits = Array.from({ length: 3000 }, (_, index) => ({
    oldText: `key${String(index).padStart(5, "0")}END`,
    newText: `val${String(index).padStart(5, "0")}END`,
  }));
  const content = edits.map((edit) => edit.oldText).join("\n");
  assert.equal(predictEdits(content, { edits }), undefined);
  assert.equal(predictEdits(content, { edits: edits.slice(0, 10) })?.startsWith("val00000END"), true);
});

test("predictions do not materialize oversized edited files", () => {
  const replacement = "x".repeat(600_000);
  const input = { edits: [{ oldText: "first", newText: replacement }, { oldText: "second", newText: replacement }] };
  assert.equal(predictEdits("first second", input) === undefined, true);
  assert.equal(predictEdits("first", { edits: [{ oldText: "first", newText: "x".repeat(999_999) }] })?.length, 999_999);
  assert.equal(predictEdits("first", { edits: [{ oldText: "first", newText: "x".repeat(1_000_000) }] }), undefined);
  assert.equal(predictEdits("first", { edits: [{ oldText: "first", newText: "あ".repeat(400_000) }] }), undefined);
});
