import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { machoLoaders } from "../extensions/guard/macho.ts";

function thin(loader = "/usr/lib/dyld"): Buffer {
  const file = Buffer.alloc(64);
  Buffer.from("cffaedfe", "hex").copy(file);
  file.writeUInt32LE(2, 12); file.writeUInt32LE(1, 16); file.writeUInt32LE(32, 20); file.writeUInt32LE(4, 24);
  file.writeUInt32LE(0xe, 32); file.writeUInt32LE(32, 36); file.writeUInt32LE(12, 40);
  Buffer.from(`${loader}\0`).copy(file, 44);
  return file;
}
const parse = (file: Buffer) => machoLoaders(file.length, (offset, length) => file.subarray(offset, offset + length));

test("Mach-O loader parsing supports thin and universal executables", () => {
  const one = thin();
  assert.deepEqual(parse(one), { loaders: ["/usr/lib/dyld"], dyldEnvironment: false });
  const fat = Buffer.alloc(48 + one.length * 2);
  Buffer.from("cafebabe", "hex").copy(fat); fat.writeUInt32BE(2, 4);
  fat.writeUInt32BE(48, 16); fat.writeUInt32BE(one.length, 20);
  fat.writeUInt32BE(48 + one.length, 36); fat.writeUInt32BE(one.length, 40);
  one.copy(fat, 48); one.copy(fat, 48 + one.length);
  assert.deepEqual(parse(fat), { loaders: ["/usr/lib/dyld", "/usr/lib/dyld"], dyldEnvironment: false });
});

test("Mach-O loader parsing rejects malformed commands and reports dyld environment", () => {
  for (const mutate of [
    (file: Buffer) => file.writeUInt32LE(4, 36),
    (file: Buffer) => file.writeUInt32LE(33, 40),
    (file: Buffer) => file.fill(65, 44, 64),
    (file: Buffer) => file.writeUInt32LE(2, 16),
    (file: Buffer) => file.writeUInt32LE(0x19, 32),
  ]) {
    const file = thin(); mutate(file);
    assert.equal(parse(file), undefined);
  }
  const file = thin();
  file.writeUInt32LE(0x27, 32); file.writeUInt32LE(0, 24);
  assert.deepEqual(parse(file), { loaders: [], dyldEnvironment: true });
});

test("the parser accepts the host's actual Mach-O shell", { skip: process.platform !== "darwin" }, () => {
  const file = readFileSync("/bin/sh");
  const result = parse(file);
  assert.ok(result);
  assert.ok(result.loaders.length > 0);
  assert.ok(result.loaders.every((loader) => loader === "/usr/lib/dyld"));
  assert.equal(result.dyldEnvironment, false);
});
