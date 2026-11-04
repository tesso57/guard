/** 判定 API と監査ログに送る前に、秘密らしき文字列を伏せる */
const PATTERNS: [RegExp, string][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[REDACTED PRIVATE KEY]"],
  [/\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}/g, "[REDACTED sk-…]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, "[REDACTED gh_…]"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, "[REDACTED github_pat_…]"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED AWS key id]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, "[REDACTED slack token]"],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, "[REDACTED google key]"],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "[REDACTED jwt]"],
  [/\b(npm_[A-Za-z0-9]{30,}|glpat-[A-Za-z0-9_-]{20,})/g, "[REDACTED token]"],
  [/((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|auth)["']?\s*[:=]\s*["']?)[^\s"'&;|]{6,}/gi, "$1[REDACTED]"],
  [/(Authorization:\s*(?:Bearer|Basic|token)\s+)[^\s"']+/gi, "$1[REDACTED]"],
  [/(:\/\/[^\s:/@]+:)[^\s@/]+@/g, "$1[REDACTED]@"],
];

export function redactString(s: string): string {
  let out = s;
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
  return out;
}

export function redact<T>(v: T): T {
  if (typeof v === "string") return redactString(v) as T;
  if (Array.isArray(v)) return v.map(redact) as T;
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, redact(x)])) as T;
  return v;
}

/** 先頭と末尾を半分ずつ残して切り詰める。末尾に隠した攻撃を見落とさないため */
export function clip(v: unknown, max: number, state: { truncated: boolean }): unknown {
  if (typeof v === "string") {
    if (v.length <= max) return v;
    state.truncated = true;
    const half = Math.floor(max / 2);
    return `${v.slice(0, half)}\n…[${v.length - max} chars omitted]…\n${v.slice(-half)}`;
  }
  if (Array.isArray(v)) return v.map((x) => clip(x, max, state));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, clip(x, max, state)]));
  return v;
}
