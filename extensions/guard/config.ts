import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { readRegularText } from "./files.ts";

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
    confirmScore: 2.5,
    blockPCatastrophic: 0.25,
    blockPHigh: 0.7,
    confirmPHigh: 0.3,
    blockExfil: 0.8,
    confirmExfil: 0.3,
    confirmIrreversible: 0.7,
    confirmUntrustedCode: 0.5,
    confirmOutsideIntent: 0.7,
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
const INTEGER_SETTINGS = new Set<keyof Config>([
  "timeoutMs", "maxFieldChars", "contextUserMessages", "contextToolCalls",
  "escalateConsecutive", "escalateTotal", "dialogTimeoutMs", "verdictCacheMs",
]);

/** A base URL must identify an HTTP endpoint, without embedded credentials or a query. */
export function validBaseUrl(value: unknown): value is string {
  if (typeof value !== "string" || !value.trim() || /[?#]/.test(value)) return false;
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") && !url.username && !url.password && !url.search && !url.hash;
  } catch { return false; }
}

/**
 * Defaults ← ~/.pi/agent/guard/config.json ← environment variables.
 * Invalid file numbers fall back to defaults; invalid environment overrides retain the validated file value.
 * Both are reported in `warnings` instead of silently disabling a check.
 */
export function loadConfig(): Config & { warnings: string[] } {
  const warnings: string[] = [];
  let file: any = {};
  try {
    const contents = readRegularText(join(DATA_DIR, "config.json"));
    try {
      file = JSON.parse(contents);
    } catch {
      warnings.push("config.json ignored: invalid JSON");
    }
  } catch (e: any) {
    if (e?.code !== "ENOENT") warnings.push(`config.json ignored: ${e.message}`);
  }
  if (!file || typeof file !== "object" || Array.isArray(file)) {
    warnings.push("config.json must contain an object; using defaults");
    file = {};
  }
  if (Object.keys(file).some((key) => !Object.hasOwn(DEFAULTS, key)))
    warnings.push("config.json contains unknown fields; check field names");
  let thresholds = file.thresholds;
  if (thresholds === undefined) thresholds = {};
  else if (!thresholds || typeof thresholds !== "object" || Array.isArray(thresholds)) {
    warnings.push("thresholds must be an object; using defaults");
    thresholds = {};
  }
  if (Object.keys(thresholds).some((key) => !Object.hasOwn(DEFAULTS.thresholds, key)))
    warnings.push("thresholds contains unknown fields; check field names");
  const c: Config = { ...DEFAULTS, ...file, thresholds: { ...DEFAULTS.thresholds, ...thresholds } };
  const env = process.env;
  if (env.RISK_DISABLE === "1") c.disabled = true;
  if (env.OPENAI_BASE_URL !== undefined) c.baseUrl = env.OPENAI_BASE_URL;
  if (env.RISK_SKIP_TOOLS !== undefined) c.skipModelTools = env.RISK_SKIP_TOOLS.split(",").map((s) => s.trim()).filter(Boolean);

  const num = (v: unknown, def: number, [lo, hi]: [number, number], name: string, integer = false) => {
    const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
    if (Number.isFinite(n) && n >= lo && n <= hi && (!integer || Number.isInteger(n))) return n;
    warnings.push(`${name} is invalid (expected ${integer ? "an integer " : ""}${lo}..${hi}); using ${def}`);
    return def;
  };
  for (const [k, range] of Object.entries(RANGES) as [keyof Config, [number, number]][]) (c as any)[k] = num(c[k], DEFAULTS[k] as number, range, k, INTEGER_SETTINGS.has(k));
  for (const k of Object.keys(DEFAULTS.thresholds) as (keyof Config["thresholds"])[])
    c.thresholds[k] = num(c.thresholds[k], DEFAULTS.thresholds[k], k === "confirmScore" ? [0, 4] : [0, 1], `thresholds.${k}`);
  if (env.RISK_TIMEOUT_MS !== undefined) c.timeoutMs = num(env.RISK_TIMEOUT_MS, c.timeoutMs, RANGES.timeoutMs!, "RISK_TIMEOUT_MS", true);
  if (env.RISK_CONFIRM_AT !== undefined) c.thresholds.confirmScore = num(env.RISK_CONFIRM_AT, c.thresholds.confirmScore, [0, 4], "RISK_CONFIRM_AT");
  if (c.thresholds.confirmPHigh >= c.thresholds.blockPHigh)
    warnings.push("thresholds.confirmPHigh equals or exceeds blockPHigh; the confirmation threshold cannot be reached before blocking");
  if (c.thresholds.confirmExfil >= c.thresholds.blockExfil)
    warnings.push("thresholds.confirmExfil equals or exceeds blockExfil; the confirmation threshold cannot be reached before blocking");
  if (typeof c.disabled !== "boolean") {
    warnings.push("disabled must be a boolean; using false");
    c.disabled = false;
  }
  if (!Array.isArray(c.skipModelTools) || !c.skipModelTools.every((tool) => typeof tool === "string")) {
    warnings.push("skipModelTools must be an array of strings; using defaults");
    c.skipModelTools = DEFAULTS.skipModelTools;
  }
  if (typeof c.model !== "string" || !c.model.trim()) {
    warnings.push("model must be a non-empty string; using default");
    c.model = DEFAULTS.model;
  }
  if (env.RISK_MODEL !== undefined) {
    if (env.RISK_MODEL.trim()) c.model = env.RISK_MODEL;
    else warnings.push("RISK_MODEL must be a non-empty string; using configured model");
  }
  if (!validBaseUrl(c.baseUrl)) {
    warnings.push("baseUrl is invalid; model judgement is unavailable until it is corrected");
    c.baseUrl = "";
  } else c.baseUrl = c.baseUrl.trim().replace(/\/+$/, "");
  return { ...c, warnings };
}
