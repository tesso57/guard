import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

export const MAX_FILE_BYTES = 1_000_000;

export function readRegularText(path: string, maxBytes = MAX_FILE_BYTES, rejectHardLinks = false): string {
  let fd: number | undefined;
  try {
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

export function readBoundedText(path: string): string | undefined {
  try { return readRegularText(path, MAX_FILE_BYTES, true); } catch { return undefined; }
}
