import { appendFileSync, closeSync, fstatSync, mkdirSync, openSync, readSync, renameSync, statSync } from "node:fs";
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

export function audit(rec: AuditRecord) {
  try {
    mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    try {
      // Keep one rotated file so the log cannot grow without bound
      if (statSync(FILE).size > MAX_BYTES) renameSync(FILE, `${FILE}.1`);
    } catch { /* no log yet */ }
    appendFileSync(FILE, JSON.stringify(redact({ ts: new Date().toISOString(), ...rec })) + "\n", { mode: 0o600 });
  } catch {
    /* a failing audit log must not stop the judgement */
  }
}

/** The last n records, reading only the end of the file. */
export function tail(n: number): AuditRecord[] {
  let fd: number | undefined;
  try {
    fd = openSync(FILE, "r");
    const size = fstatSync(fd).size;
    const len = Math.min(size, 256 * 1024);
    const buf = Buffer.alloc(len);
    readSync(fd, buf, 0, len, size - len);
    const lines = buf.toString("utf8").split("\n").filter(Boolean);
    if (len < size) lines.shift(); // the first line may be cut off
    return lines.slice(-n).flatMap((l) => {
      try { return [JSON.parse(l)]; } catch { return []; }
    });
  } catch {
    return [];
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
