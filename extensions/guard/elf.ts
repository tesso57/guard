import { isUtf8 } from "node:buffer";
import { posix } from "node:path";

/** Read bounded ELF program headers without executing the candidate. */
export function elfPrograms(header: Buffer, size: number, read: (offset: number, length: number) => Buffer): { interpreter?: string } | undefined {
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
    let loads = 0, interpreter: string | undefined;
    for (let i = 0; i < count; i++) {
      const base = i * entrySize, type = u32(table, base);
      if (type !== 1 && type !== 3) continue;
      const start = wide ? u64(table, base + 8) : BigInt(u32(table, base + 4));
      const length = wide ? u64(table, base + 32) : BigInt(u32(table, base + 16));
      if (start > BigInt(size) || start + length > BigInt(size)) return undefined;
      if (type === 1) {
        const memory = wide ? u64(table, base + 40) : BigInt(u32(table, base + 20));
        if (memory < length) return undefined;
        loads++;
      } else {
        if (interpreter !== undefined || loads > 0 || length < 2n || length > 4096n) return undefined;
        const bytes = read(Number(start), Number(length));
        if (bytes.length !== Number(length) || bytes.at(-1) !== 0 || bytes.subarray(0, -1).includes(0) || !isUtf8(bytes.subarray(0, -1))) return undefined;
        interpreter = bytes.subarray(0, -1).toString("utf8");
        if (!posix.isAbsolute(interpreter)) return undefined;
      }
    }
    return loads ? { interpreter } : undefined;
  } catch { return undefined; }
}
