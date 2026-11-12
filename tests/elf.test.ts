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

test("ELF dynamic entries expose bounded library search paths and dependencies", () => {
  const file = fixture(), strings = Buffer.from("\0libc.so.6\0$ORIGIN/../lib\0");
  file.writeUInt16LE(3, 56);
  file.writeBigUInt64LE(0x400000n, 136); file.writeBigUInt64LE(512n, 152); file.writeBigUInt64LE(512n, 160);
  file.writeUInt32LE(2, 176); file.writeBigUInt64LE(320n, 184); file.writeBigUInt64LE(80n, 208);
  for (const [index, tag, value] of [[0, 5n, 0x4001a0n], [1, 10n, BigInt(strings.length)], [2, 1n, 1n], [3, 29n, 11n]] as const) {
    file.writeBigUInt64LE(tag, 320 + index * 16); file.writeBigUInt64LE(value, 328 + index * 16);
  }
  strings.copy(file, 416);
  const read = (offset: number, length: number) => file.subarray(offset, offset + length);
  assert.deepEqual(elfPrograms(file.subarray(0, 64), file.length, read), { interpreter: "/lib/guard-loader", libraryPaths: ["$ORIGIN/../lib"], dependencies: ["libc.so.6"] });
  file.writeBigUInt64LE(0x6ffffefcn, 368);
  assert.deepEqual(elfPrograms(file.subarray(0, 64), file.length, read), { interpreter: "/lib/guard-loader", dependencies: ["libc.so.6"], audit: true });
  file.writeBigUInt64LE(29n, 368);
  file.writeBigUInt64LE(0x6ffffefcn, 320);
  assert.equal(elfPrograms(file.subarray(0, 64), file.length, read), undefined, "string metadata must exist when path tags are present");
});

test("ELF32 big-endian dynamic entries use the correct offsets", () => {
  const file = Buffer.alloc(512), strings = Buffer.from("\0lib.so\0$ORIGIN/lib\0");
  Buffer.from("7f454c46", "hex").copy(file);
  file[4] = 1; file[5] = 2; file[6] = 1;
  file.writeUInt32BE(52, 28); file.writeUInt16BE(32, 42); file.writeUInt16BE(2, 44);
  file.writeUInt32BE(1, 52); file.writeUInt32BE(0, 56); file.writeUInt32BE(0x1000, 60); file.writeUInt32BE(512, 68); file.writeUInt32BE(512, 72);
  file.writeUInt32BE(2, 84); file.writeUInt32BE(256, 88); file.writeUInt32BE(40, 100);
  for (const [index, tag, value] of [[0, 5, 0x1140], [1, 10, strings.length], [2, 1, 1], [3, 29, 8]]) {
    file.writeUInt32BE(tag, 256 + index * 8); file.writeUInt32BE(value, 260 + index * 8);
  }
  strings.copy(file, 320);
  assert.deepEqual(elfPrograms(file.subarray(0, 52), file.length, (offset, length) => file.subarray(offset, offset + length)), { interpreter: undefined, libraryPaths: ["$ORIGIN/lib"], dependencies: ["lib.so"] });
});

test("the parser accepts the host's actual ELF shell", { skip: process.platform !== "linux" }, () => {
  const file = readFileSync("/bin/sh");
  const result = elfPrograms(file.subarray(0, 64), file.length, (offset, length) => file.subarray(offset, offset + length));
  assert.ok(result);
  if (result.interpreter) assert.ok(existsSync(result.interpreter));
});
