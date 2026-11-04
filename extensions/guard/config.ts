import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

export const AGENT_DIR = getAgentDir();
export const DATA_DIR = join(AGENT_DIR, "guard");

export type Config = {
  /** Explicit opt-out: turns guard off completely. */
  disabled: boolean;
  model: string;
  baseUrl: string;
  timeoutMs: number;
  /** Tools that skip the model. Sensitive-path and protected-path checks still run. */
  skipModelTools: string[];
  thresholds: {
    /** Confirm when the weighted score (0-4) reaches this. */
    confirmScore: number;
    /** Block when the probability of level 4 (catastrophic) reaches this. */
    blockPCatastrophic: number;
    /** Block when the probability of level 3 or above reaches this. */
    blockPHigh: number;
    /** Confirm when the probability of level 3 or above reaches this. */
    confirmPHigh: number;
    blockExfil: number;
    confirmExfil: number;
    confirmIrreversible: number;
    confirmUntrustedCode: number;
    confirmOutsideIntent: number;
    confirmAddressesEvaluator: number;
    /** Confirm when score >= 1 and confidence is below this. */
    lowConfidence: number;
    /** A past approval may lower confirm to allow when this probability is reached. */
    pastApprovalCovered: number;
    pastDenialCovered: number;
  };
  /** Days a project or global allow rule stays valid. */
  allowRuleTtlDays: number;
  /** Maximum length of each string sent to the judge (head and tail are kept). */
  maxFieldChars: number;
  contextUserMessages: number;
  contextToolCalls: number;
  escalateConsecutive: number;
  escalateTotal: number;
  /** How long the approval dialog waits before it counts as a deny. */
  dialogTimeoutMs: number;
  /** How long an "allow" verdict from the model is reused for an identical call. */
  verdictCacheMs: number;
};

const DEFAULTS: Config = {
  disabled: false,
  model: "gpt-6-luna",
  baseUrl: "https://api.openai.com/v1",
  timeoutMs: 6000,
  skipModelTools: ["read", "grep", "find", "ls"],
  thresholds: {
    confirmScore: 1.5,
    blockPCatastrophic: 0.25,
    blockPHigh: 0.6,
    confirmPHigh: 0.15,
    blockExfil: 0.8,
    confirmExfil: 0.3,
    confirmIrreversible: 0.5,
    confirmUntrustedCode: 0.5,
    confirmOutsideIntent: 0.6,
    confirmAddressesEvaluator: 0.5,
    lowConfidence: 0.4,
    pastApprovalCovered: 0.8,
    pastDenialCovered: 0.5,
  },
  allowRuleTtlDays: 30,
  maxFieldChars: 12000,
  contextUserMessages: 3,
  contextToolCalls: 8,
  escalateConsecutive: 3,
  escalateTotal: 20,
  dialogTimeoutMs: 10 * 60_000,
  verdictCacheMs: 10 * 60_000,
};

const RANGES: Partial<Record<keyof Config, [number, number]>> = {
  timeoutMs: [500, 120_000],
  allowRuleTtlDays: [1, 3650],
  maxFieldChars: [500, 200_000],
  contextUserMessages: [0, 50],
  contextToolCalls: [0, 100],
  escalateConsecutive: [1, 1000],
  escalateTotal: [1, 100_000],
  dialogTimeoutMs: [5_000, 24 * 3600_000],
  verdictCacheMs: [0, 24 * 3600_000],
};

/**
 * Defaults ← ~/.pi/agent/guard/config.json ← environment variables.
 * Invalid numbers fall back to the default and are reported in `warnings`, instead of silently disabling a check.
 */
export function loadConfig(): Config & { warnings: string[] } {
  const warnings: string[] = [];
  let file: any = {};
  try {
    file = JSON.parse(readFileSync(join(DATA_DIR, "config.json"), "utf8"));
  } catch (e: any) {
    if (e?.code !== "ENOENT") warnings.push(`config.json ignored: ${e.message}`);
  }
  const c: Config = { ...DEFAULTS, ...file, thresholds: { ...DEFAULTS.thresholds, ...(file.thresholds ?? {}) } };
  const env = process.env;
  if (env.RISK_DISABLE === "1") c.disabled = true;
  if (env.RISK_MODEL) c.model = env.RISK_MODEL;
  if (env.OPENAI_BASE_URL) c.baseUrl = env.OPENAI_BASE_URL;
  if (env.RISK_TIMEOUT_MS) (c as any).timeoutMs = env.RISK_TIMEOUT_MS;
  if (env.RISK_CONFIRM_AT) (c.thresholds as any).confirmScore = env.RISK_CONFIRM_AT;
  if (env.RISK_SKIP_TOOLS !== undefined) c.skipModelTools = env.RISK_SKIP_TOOLS.split(",").map((s) => s.trim()).filter(Boolean);

  const num = (v: unknown, def: number, [lo, hi]: [number, number], name: string) => {
    const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
    if (Number.isFinite(n) && n >= lo && n <= hi) return n;
    warnings.push(`${name}=${JSON.stringify(v)} is invalid (expected ${lo}..${hi}); using ${def}`);
    return def;
  };
  for (const [k, range] of Object.entries(RANGES) as [keyof Config, [number, number]][]) (c as any)[k] = num(c[k], DEFAULTS[k] as number, range, k);
  for (const k of Object.keys(DEFAULTS.thresholds) as (keyof Config["thresholds"])[])
    c.thresholds[k] = num(c.thresholds[k], DEFAULTS.thresholds[k], k === "confirmScore" ? [0, 4] : [0, 1], `thresholds.${k}`);
  if (!Array.isArray(c.skipModelTools)) c.skipModelTools = DEFAULTS.skipModelTools;
  c.baseUrl = String(c.baseUrl).replace(/\/+$/, "");
  return { ...c, warnings };
}
