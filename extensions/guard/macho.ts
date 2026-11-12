import { isUtf8 } from "node:buffer";
import { posix } from "node:path";

/** Read bounded Mach-O load commands, including each slice of a universal binary. */
export function machoLoaders(size: number, read: (offset: number, length: number) => Buffer): { loaders: string[]; dyldEnvironment: boolean } | undefined {
  try {
    if (!Number.isSafeInteger(size) || size < 8) return undefined;
    const readExact = (offset: number, length: number) => {
      if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > size) throw new Error("out of bounds");
      const bytes = read(offset, length);
      if (bytes.length !== length) throw new Error("short read");
      return bytes;
    };
    const first = readExact(0, Math.min(size, 512));
    const magic = first.subarray(0, 4).toString("hex");
    const slices: { offset: number; size: number }[] = [];
    if (["cafebabe", "bebafeca", "cafebabf", "bfbafeca"].includes(magic)) {
      const little = magic === "bebafeca" || magic === "bfbafeca", wide = magic === "cafebabf" || magic === "bfbafeca";
      const count = little ? first.readUInt32LE(4) : first.readUInt32BE(4), entrySize = wide ? 32 : 20;
      if (count === 0 || count > 16 || 8 + count * entrySize > first.length) return undefined;
      const u32 = (at: number) => little ? first.readUInt32LE(at) : first.readUInt32BE(at);
      const u64 = (at: number) => little ? first.readBigUInt64LE(at) : first.readBigUInt64BE(at);
      for (let i = 0; i < count; i++) {
        const at = 8 + i * entrySize;
        const offset = wide ? u64(at + 8) : BigInt(u32(at + 8));
        const length = wide ? u64(at + 16) : BigInt(u32(at + 12));
        if (offset < BigInt(8 + count * entrySize) || length < 28n || offset + length > BigInt(size)) return undefined;
        slices.push({ offset: Number(offset), size: Number(length) });
      }
    } else slices.push({ offset: 0, size });

    const loaders: string[] = [];
    let dyldEnvironment = false;
    for (const slice of slices) {
      const header = readExact(slice.offset, Math.min(slice.size, 32));
      const kind = header.subarray(0, 4).toString("hex");
      if (!["feedface", "cefaedfe", "feedfacf", "cffaedfe"].includes(kind)) return undefined;
      const wide = kind === "feedfacf" || kind === "cffaedfe", little = kind === "cefaedfe" || kind === "cffaedfe", headerSize = wide ? 32 : 28;
      if (header.length < headerSize) return undefined;
      const u32 = (b: Buffer, at: number) => little ? b.readUInt32LE(at) : b.readUInt32BE(at);
      const count = u32(header, 16), commandsSize = u32(header, 20), flags = u32(header, 24);
      if (u32(header, 12) !== 2 || count === 0 || count > 4096 || commandsSize < count * 8 || commandsSize > 65_536 || headerSize + commandsSize > slice.size) return undefined;
      const commands = readExact(slice.offset + headerSize, commandsSize);
      let position = 0, loader: string | undefined;
      for (let i = 0; i < count; i++) {
        if (position + 8 > commands.length) return undefined;
        const command = u32(commands, position), length = u32(commands, position + 4);
        if (length < 8 || length % 4 !== 0 || position + length > commands.length) return undefined;
        if (command === 0x27) dyldEnvironment = true;
        if (command === 0xe) {
          if (loader !== undefined || length < 12) return undefined;
          const nameOffset = u32(commands, position + 8);
          if (nameOffset < 12 || nameOffset >= length) return undefined;
          const start = position + nameOffset, end = commands.indexOf(0, start);
          if (end < start || end >= position + length || !isUtf8(commands.subarray(start, end))) return undefined;
          loader = commands.subarray(start, end).toString("utf8");
          if (!posix.isAbsolute(loader)) return undefined;
        }
        position += length;
      }
      if (position !== commands.length || ((flags & 4) !== 0 && loader === undefined)) return undefined;
      if (loader !== undefined) loaders.push(loader);
    }
    return { loaders, dyldEnvironment };
  } catch { return undefined; }
}
