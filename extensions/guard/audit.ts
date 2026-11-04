import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DATA_DIR } from "./config.ts";
import { redact } from "./redact.ts";

const FILE = join(DATA_DIR, "audit.jsonl");

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
    mkdirSync(DATA_DIR, { recursive: true });
    appendFileSync(FILE, JSON.stringify(redact({ ts: new Date().toISOString(), ...rec })) + "\n", { mode: 0o600 });
  } catch {
    /* 監査ログの失敗で判定を止めない */
  }
}

export function tail(n: number): AuditRecord[] {
  try {
    return readFileSync(FILE, "utf8").trim().split("\n").slice(-n).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}
