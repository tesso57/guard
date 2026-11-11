import assert from "node:assert/strict";
import test from "node:test";
import { validateToolArguments } from "@earendil-works/pi-ai";
import { createWriteTool } from "@earendil-works/pi-coding-agent";

test("Pi write validation coerces primitives and rejects structured content", () => {
  const tool = createWriteTool("/tmp");
  for (const [content, expected] of [[null, "null"], [42, "42"], [true, "true"], ["value", "value"]] as const) {
    const result = validateToolArguments(tool, { type: "toolCall", id: "fixture", name: "write", arguments: { path: "file", content } });
    assert.equal(result.content, expected);
  }
  for (const content of [{}, []]) {
    assert.throws(() => validateToolArguments(tool, { type: "toolCall", id: "fixture", name: "write", arguments: { path: "file", content } }));
  }
  assert.throws(() => validateToolArguments(tool, { type: "toolCall", id: "fixture", name: "write", arguments: { path: "file" } }));
  for (const [path, expected] of [[123, "123"], [null, "null"], [true, "true"]] as const) {
    const result = validateToolArguments(tool, { type: "toolCall", id: "fixture", name: "write", arguments: { path, content: "data" } });
    assert.equal(result.path, expected);
  }
});
