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
