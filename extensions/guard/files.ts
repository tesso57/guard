import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

const MAX_BYTES = 1_000_000;

/** Read a regular file without blocking on a special file or exceeding a fixed byte limit. */
export function readRegularText(path: string, maxBytes = MAX_BYTES, rejectHardLinks = false): string {
  let fd: number | undefined;
  try {
    // Nonblocking open prevents a path swapped to a FIFO from hanging before fstat.
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error(`not a regular file: ${path}`);
    if (rejectHardLinks && st.nlink > 1) throw new Error(`multiple hard links: ${path}`);
    if (st.size >= maxBytes) throw new Error(`file too large: ${path}`);
    const chunks: Buffer[] = [];
    let used = 0;
    while (used < maxBytes) {
      const buf = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes - used));
      const count = readSync(fd, buf, 0, buf.length, null);
      if (count === 0) {
        try {
          // Preserve a BOM while rejecting byte sequences that would otherwise be silently replaced.
          return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks, used));
        } catch {
          throw new Error(`invalid UTF-8: ${path}`);
        }
      }
      chunks.push(buf.subarray(0, count));
      used += count;
    }
    throw new Error(`file grew too large: ${path}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Do not load large or hard-linked files into a judgement. */
export function readBoundedText(path: string): string | undefined {
  try { return readRegularText(path, MAX_BYTES, true); } catch { return undefined; }
}
