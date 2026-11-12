import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import { elfPrograms } from "../extensions/guard/elf.ts";

function fixture(path = "/lib/guard-loader"): Buffer {
  const file = Buffer.alloc(512);
  Buffer.from("7f454c46", "hex").copy(file);
  file[4] = 2; file[5] = 1; file[6] = 1;
  file.writeBigUInt64LE(64n, 32); file.writeUInt16LE(56, 54); file.writeUInt16LE(2, 56);
  const interpreter = Buffer.from(`${path}\0`);
  file.writeUInt32LE(3, 64); file.writeBigUInt64LE(256n, 72); file.writeBigUInt64LE(BigInt(interpreter.length), 96);
  file.writeUInt32LE(1, 120); file.writeBigUInt64LE(0n, 128); file.writeBigUInt64LE(300n, 152); file.writeBigUInt64LE(300n, 160);
  interpreter.copy(file, 256);
  return file;
}

test("ELF program headers identify a bounded absolute interpreter", () => {
  const file = fixture();
  const read = (offset: number, length: number) => file.subarray(offset, offset + length);
  assert.deepEqual(elfPrograms(file.subarray(0, 64), file.length, read), { interpreter: "/lib/guard-loader" });
  file.writeUInt32LE(0, 64);
  assert.deepEqual(elfPrograms(file.subarray(0, 64), file.length, read), { interpreter: undefined });
  file.writeUInt32LE(0, 120);
  assert.equal(elfPrograms(file.subarray(0, 64), file.length, read), undefined);
});

test("ELF program headers reject incomplete, escaping and malformed data", () => {
  for (const mutate of [
    (file: Buffer) => file.writeBigUInt64LE(500n, 72),
    (file: Buffer) => file.writeBigUInt64LE(4097n, 96),
    (file: Buffer) => { Buffer.from("relative\0").copy(file, 256); file.writeBigUInt64LE(9n, 96); },
    (file: Buffer) => file.writeBigUInt64LE(1n, 160),
    (file: Buffer) => file.writeUInt32LE(3, 120),
  ]) {
    const file = fixture();
    mutate(file);
    assert.equal(elfPrograms(file.subarray(0, 64), file.length, (offset, length) => file.subarray(offset, offset + length)), undefined);
  }
  const file = fixture();
  assert.equal(elfPrograms(file.subarray(0, 64), file.length, () => Buffer.alloc(0)), undefined);
});

test("ELF32 big-endian program headers are interpreted without native-endian assumptions", () => {
  const file = Buffer.alloc(512), interpreter = Buffer.from("/lib/loader\0");
  Buffer.from("7f454c46", "hex").copy(file);
  file[4] = 1; file[5] = 2; file[6] = 1;
  file.writeUInt32BE(52, 28); file.writeUInt16BE(32, 42); file.writeUInt16BE(2, 44);
  file.writeUInt32BE(3, 52); file.writeUInt32BE(200, 56); file.writeUInt32BE(interpreter.length, 68);
  file.writeUInt32BE(1, 84); file.writeUInt32BE(0, 88); file.writeUInt32BE(300, 100); file.writeUInt32BE(300, 104);
  interpreter.copy(file, 200);
  assert.deepEqual(elfPrograms(file.subarray(0, 52), file.length, (offset, length) => file.subarray(offset, offset + length)), { interpreter: "/lib/loader" });
});

test("the parser accepts the host's actual ELF shell", { skip: process.platform !== "linux" }, () => {
  const file = readFileSync("/bin/sh");
  const result = elfPrograms(file.subarray(0, 64), file.length, (offset, length) => file.subarray(offset, offset + length));
  assert.ok(result);
  if (result.interpreter) assert.ok(existsSync(result.interpreter));
});
