import { appendFileSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readSync, renameSync, rmdirSync } from "node:fs";
import { join } from "node:path";
import { DATA_DIR } from "./config.ts";
import { redact } from "./redact.ts";

const FILE = join(DATA_DIR, "audit.jsonl");
const MAX_BYTES = 5 * 1024 * 1024;

export type AuditRecord = {
  ts?: string;
  session?: string;
  tool: string;
  preview: string;
  action: "allow" | "confirm" | "block";
  source: string;
  reasons: string[];
  final?: "run" | "blocked";
  choice?: string;
  risk?: number;
  ruleIds?: string[];
  event?: string;
};

function isAuditRecord(value: unknown): value is AuditRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return typeof r.tool === "string" && typeof r.preview === "string" && typeof r.source === "string" &&
    (r.action === "allow" || r.action === "confirm" || r.action === "block") && Array.isArray(r.reasons) && r.reasons.every((reason) => typeof reason === "string") &&
    (r.ts === undefined || typeof r.ts === "string") && (r.choice === undefined || typeof r.choice === "string") &&
    (r.event === undefined || typeof r.event === "string") && (r.final === undefined || r.final === "run" || r.final === "blocked");
}

export function audit(rec: AuditRecord): boolean {
  let fd: number | undefined;
  let success = false;
  let locked = false;
  try {
    mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    const deadline = performance.now() + 500;
    for (;;) {
      try {
        mkdirSync(`${FILE}.lock`, { mode: 0o700 });
        locked = true;
        break;
      } catch (e: any) {
        if (e?.code !== "EEXIST" || performance.now() >= deadline) throw e;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
      }
    }
    try {
      // Keep one rotated file so the log cannot grow without bound
      const st = lstatSync(FILE);
      if (st.isFile() && st.nlink === 1 && st.size > MAX_BYTES) renameSync(FILE, `${FILE}.1`);
    } catch (e: any) {
      if (e?.code !== "ENOENT") throw e;
    }
    fd = openSync(FILE, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NONBLOCK | constants.O_NOFOLLOW, 0o600);
    const st = fstatSync(fd);
    if (st.isFile() && st.nlink === 1) {
      appendFileSync(fd, JSON.stringify(redact({ ts: new Date().toISOString(), ...rec })) + "\n");
      success = true;
    }
  } catch {
    /* a failing audit log must not stop the judgement */
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { success = false; }
    if (locked) try { rmdirSync(`${FILE}.lock`); } catch { success = false; }
  }
  return success;
}

/** The last n records, reading only the end of the file. */
export function tail(n: number): AuditRecord[] {
  if (!Number.isSafeInteger(n) || n <= 0) return [];
  const limit = Math.min(n, 1000);
  let fd: number | undefined;
  try {
    fd = openSync(FILE, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1) return [];
    const size = st.size;
    const len = Math.min(size, 256 * 1024);
    const prefix = size > len ? 1 : 0;
    const buf = Buffer.alloc(len + prefix);
    let read = 0;
    while (read < buf.length) {
      const count = readSync(fd, buf, read, buf.length - read, size - len - prefix + read);
      if (count === 0) break;
      read += count;
    }
    const lines: Buffer[] = [];
    let start = 0;
    for (let i = 0; i <= read; i++) {
      if (i === read || buf[i] === 10) {
        lines.push(buf.subarray(start, i));
        start = i + 1;
      }
    }
    if (prefix) lines.shift(); // discard the preceding byte and any partial first line
    return lines.flatMap((line) => {
      try {
        const record: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(line));
        return isAuditRecord(record) ? [record] : [];
      } catch { return []; }
    }).slice(-limit);
  } catch {
    return [];
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* a failing log read returns no records */ }
  }
}
