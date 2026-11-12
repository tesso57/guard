import { isUtf8 } from "node:buffer";
import { posix } from "node:path";

/** Read bounded ELF program headers without executing the candidate. */
export function elfPrograms(header: Buffer, size: number, read: (offset: number, length: number) => Buffer): { interpreter?: string; libraryPaths?: string[]; dependencies?: string[]; audit?: boolean } | undefined {
  try {
    if (!Number.isSafeInteger(size) || size < 0 || header.length < 52 || header.subarray(0, 4).toString("hex") !== "7f454c46" || ![1, 2].includes(header[4]) || ![1, 2].includes(header[5]) || header[6] !== 1) return undefined;
    const wide = header[4] === 2, little = header[5] === 1, minimum = wide ? 64 : 52;
    if (header.length < minimum) return undefined;
    const u16 = (b: Buffer, n: number) => little ? b.readUInt16LE(n) : b.readUInt16BE(n);
    const u32 = (b: Buffer, n: number) => little ? b.readUInt32LE(n) : b.readUInt32BE(n);
    const u64 = (b: Buffer, n: number) => little ? b.readBigUInt64LE(n) : b.readBigUInt64BE(n);
    const offset = wide ? u64(header, 32) : BigInt(u32(header, 28));
    const entrySize = u16(header, wide ? 54 : 42), count = u16(header, wide ? 56 : 44);
    const tableSize = entrySize * count;
    if (entrySize !== (wide ? 56 : 32) || count === 0 || count === 0xffff || tableSize > 65_536 || offset > BigInt(size) || offset + BigInt(tableSize) > BigInt(size)) return undefined;
    const table = read(Number(offset), tableSize);
    if (table.length !== tableSize) return undefined;
    const segments: { start: bigint; length: bigint; virtual: bigint }[] = [];
    let loads = 0, interpreter: string | undefined, dynamic: { start: bigint; length: bigint } | undefined;
    for (let i = 0; i < count; i++) {
      const base = i * entrySize, type = u32(table, base);
      if (type !== 1 && type !== 2 && type !== 3) continue;
      const start = wide ? u64(table, base + 8) : BigInt(u32(table, base + 4));
      const length = wide ? u64(table, base + 32) : BigInt(u32(table, base + 16));
      if (start > BigInt(size) || start + length > BigInt(size)) return undefined;
      if (type === 1) {
        const memory = wide ? u64(table, base + 40) : BigInt(u32(table, base + 20));
        if (memory < length) return undefined;
        segments.push({ start, length, virtual: wide ? u64(table, base + 16) : BigInt(u32(table, base + 8)) });
        loads++;
      } else if (type === 2) {
        if (dynamic || length === 0n || length > 65_536n) return undefined;
        dynamic = { start, length };
      } else {
        if (interpreter !== undefined || loads > 0 || length < 2n || length > 4096n) return undefined;
        const bytes = read(Number(start), Number(length));
        if (bytes.length !== Number(length) || bytes.at(-1) !== 0 || bytes.subarray(0, -1).includes(0) || !isUtf8(bytes.subarray(0, -1))) return undefined;
        interpreter = bytes.subarray(0, -1).toString("utf8");
        if (!posix.isAbsolute(interpreter)) return undefined;
      }
    }
    if (!loads) return undefined;
    if (!dynamic) return { interpreter };
    const bytes = read(Number(dynamic.start), Number(dynamic.length)), width = wide ? 16 : 8;
    if (bytes.length !== Number(dynamic.length) || bytes.length % width !== 0) return undefined;
    let stringAddress: bigint | undefined, stringSize: bigint | undefined, terminated = false, audit = false;
    const pathOffsets: bigint[] = [], dependencyOffsets: bigint[] = [];
    for (let at = 0; at < bytes.length; at += width) {
      const tag = wide ? u64(bytes, at) : BigInt(u32(bytes, at));
      const value = wide ? u64(bytes, at + 8) : BigInt(u32(bytes, at + 4));
      if (tag === 0n) { terminated = true; break; }
      if (tag === 5n) { if (stringAddress !== undefined) return undefined; stringAddress = value; }
      else if (tag === 10n) { if (stringSize !== undefined) return undefined; stringSize = value; }
      else if (tag === 15n || tag === 29n) pathOffsets.push(value);
      else if (tag === 1n) dependencyOffsets.push(value);
      else if ([0x6ffffefan, 0x6ffffefbn, 0x6ffffefcn, 0x7ffffffdn, 0x7fffffffn].includes(tag)) audit = true;
      if (pathOffsets.length > 16 || dependencyOffsets.length > 128) return undefined;
    }
    if (!terminated) return undefined;
    const offsets = [...pathOffsets, ...dependencyOffsets];
    const values: string[] = [];
    if (offsets.length) {
      if (stringAddress === undefined || stringSize === undefined || stringSize === 0n) return undefined;
      const mappings = segments.filter((s) => stringAddress! >= s.virtual && stringAddress! - s.virtual + stringSize! <= s.length)
        .map((s) => s.start + stringAddress! - s.virtual);
      if (!mappings.length || mappings.some((start) => start !== mappings[0])) return undefined;
      const start = mappings[0];
      for (const offset of offsets) {
        if (offset >= stringSize) return undefined;
        const length = Number(stringSize - offset > 4096n ? 4096n : stringSize - offset);
        const value = read(Number(start + offset), length), end = value.indexOf(0);
        if (value.length !== length || end < 0 || !isUtf8(value.subarray(0, end))) return undefined;
        values.push(value.subarray(0, end).toString("utf8"));
      }
    }
    return { interpreter, ...(pathOffsets.length ? { libraryPaths: values.slice(0, pathOffsets.length) } : {}), ...(dependencyOffsets.length ? { dependencies: values.slice(pathOffsets.length) } : {}), ...(audit ? { audit } : {}) };
  } catch { return undefined; }
}
