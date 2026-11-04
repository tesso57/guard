import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

export const AGENT_DIR = getAgentDir();
export const DATA_DIR = join(AGENT_DIR, "guard");

export type Config = {
  /** true にすると拡張全体を無効化(明示的なオプトアウト) */
  disabled: boolean;
  model: string;
  baseUrl: string;
  timeoutMs: number;
  /** model 判定を省略するツール(機密パス・保護パスの決定的チェックは常に行う) */
  skipModelTools: string[];
  thresholds: {
    /** score(0-4 の加重平均)がこれ以上なら confirm */
    confirmScore: number;
    /** level 4(致命的)の確率がこれ以上なら block */
    blockPCatastrophic: number;
    /** level 3 以上の確率がこれ以上なら block */
    blockPHigh: number;
    /** level 3 以上の確率がこれ以上なら confirm */
    confirmPHigh: number;
    blockExfil: number;
    confirmExfil: number;
    confirmIrreversible: number;
    confirmOutsideIntent: number;
    confirmAddressesEvaluator: number;
    /** score >= 1 かつ confidence がこれ未満なら confirm */
    lowConfidence: number;
    /** 過去の許可で confirm→allow に下げる条件 */
    pastApprovalCovered: number;
    pastDenialCovered: number;
  };
  /** allow 規則(project / global)の有効日数 */
  allowRuleTtlDays: number;
  /** 判定に送る文字列フィールドの最大長(先頭と末尾を半分ずつ残す) */
  maxFieldChars: number;
  contextUserMessages: number;
  contextToolCalls: number;
  escalateConsecutive: number;
  escalateTotal: number;
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
};

/** 既定値 ← ~/.pi/agent/guard/config.json ← 環境変数 の順に上書き */
export function loadConfig(): Config {
  let file: Partial<Config> = {};
  try {
    file = JSON.parse(readFileSync(join(DATA_DIR, "config.json"), "utf8"));
  } catch {
    /* 無ければ既定値 */
  }
  const c: Config = { ...DEFAULTS, ...file, thresholds: { ...DEFAULTS.thresholds, ...(file.thresholds ?? {}) } };
  const env = process.env;
  if (env.RISK_DISABLE === "1") c.disabled = true;
  if (env.RISK_MODEL) c.model = env.RISK_MODEL;
  if (env.OPENAI_BASE_URL) c.baseUrl = env.OPENAI_BASE_URL;
  if (env.RISK_TIMEOUT_MS) c.timeoutMs = Number(env.RISK_TIMEOUT_MS);
  if (env.RISK_CONFIRM_AT) c.thresholds.confirmScore = Number(env.RISK_CONFIRM_AT);
  if (env.RISK_SKIP_TOOLS !== undefined) c.skipModelTools = env.RISK_SKIP_TOOLS.split(",").map((s) => s.trim()).filter(Boolean);
  c.baseUrl = c.baseUrl.replace(/\/+$/, "");
  return c;
}
