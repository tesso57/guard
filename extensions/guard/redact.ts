/** Masks strings that look like secrets before they reach the judge or the audit log. */
const PATTERNS: [RegExp, string][] = [
  [/-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?(-----END PGP PRIVATE KEY BLOCK-----|$)/g, "[REDACTED PGP PRIVATE KEY]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[REDACTED PRIVATE KEY]"],
  [/AGE-SECRET-KEY-(?:PQ-)?1[A-Z0-9]{20,}/gi, "[REDACTED age identity]"],
  [/\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}/g, "[REDACTED sk-…]"],
  [/gh[pousr]_[A-Za-z0-9]{20,}/g, "[REDACTED gh_…]"],
  [/github_pat_[A-Za-z0-9_]{20,}/g, "[REDACTED github_pat_…]"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED AWS key id]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, "[REDACTED slack token]"],
  [/AIza[0-9A-Za-z_-]{35}/g, "[REDACTED google key]"],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "[REDACTED jwt]"],
  [/\b(npm_[A-Za-z0-9]{30,}|glpat-[A-Za-z0-9_-]{20,})/g, "[REDACTED token]"],
  // A shell argument can concatenate quoted, unquoted and escaped segments without whitespace.
  [/((?:^|[\s;&|])(?:[a-z_][a-z0-9_]*)?(?:password|passwd|passphrase|secret|token|api_?key|access_?key|private_?key|credentials?|authorization|auth)(?:_(?:value|hash|digest))?=)(?:\\[\s\S]|"(?:\\[\s\S]|[^"\\])*(?:"|$)|'(?:\\[\s\S]|[^'\\])*(?:'|$)|[^\s"'\\&;|])+/gi, "$1[REDACTED]"],
  [/(--(?:[a-z0-9]+[-_])*(?:password|passwd|passphrase|pass|token|secret|api-?key|access-?key|private-?key|credentials?|authorization|auth)(?:[-_](?:value|hash|digest))?(?:=|\s+))(?:\\[\s\S]|"(?:\\[\s\S]|[^"\\])*(?:"|$)|'(?:\\[\s\S]|[^'\\])*(?:'|$)|[^\s"'\\&;|])+/gi, "$1[REDACTED]"],
  [/(authorization(?:[_-](?:value|hash|digest))?["']?\s*=\s*)(?:\\[\s\S]|"(?:\\[\s\S]|[^"\\])*(?:"|$)|'(?:\\[\s\S]|[^'\\])*(?:'|$)|[^\s"'\\&;|])+/gi, "$1[REDACTED]"],
  [/((?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|auth)(?:[_-](?:value|hash|digest))?["']?\s*[:=]\s*)("(?:\\[\s\S]|[^"\\])*(?:"|$)|'(?:\\[\s\S]|[^'\\])*(?:'|$))/gi, '$1"[REDACTED]"'],
  [/((?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?|auth)(?:[_-](?:value|hash|digest))?["']?\s*[:=]\s*["']?)(?:\\[\s\S]|[^\s"'\\&;|])+/gi, "$1[REDACTED]"],
  [/\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}/g, "[REDACTED stripe key]"],
  [/\bhf_[A-Za-z0-9]{20,}/g, "[REDACTED hf token]"],
  [/(aws_secret_access_key\s*[=: ]\s*)[^\s"']+/gi, "$1[REDACTED]"],
  [/(:\/\/[^\s:/@]+:)[^\s@/]+@/g, "$1[REDACTED]@"],
];

// A structured value such as { password: "..." } does not contain its key in the value itself.
const SECRET_FIELD = /^(?:[a-z0-9]+_)*(?:password|passwd|passphrase|secret|token|api_?key|access_?key|private_?key|authorization|auth|credential|credentials)(?:_(?:value|hash|digest))?$/i;

const normalizeField = (key: string) => key.trim().replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[-.\s]+/g, "_");
const isSecretField = (key: string) => SECRET_FIELD.test(normalizeField(key));
const DESCRIPTOR_FIELD = /^(?:name|key|field|header|(?:header|field|parameter|param|key)_name)$/i;
const VALUE_FIELD = /^(?:(?:header|field|parameter|param|key)_)?(?:value|values|content|data|raw)(?:_value)?$/i;

function yamlKey(double: string | undefined, single: string | undefined, plain: string | undefined): string | undefined {
  if (double !== undefined) {
    try { return JSON.parse(`"${double}"`); } catch { return undefined; }
  }
  return single !== undefined ? single.replace(/''/g, "'") : plain;
}

/** Identify a secret-name sibling; an undecodable descriptor is treated conservatively. */
function yamlDescriptorIsSecret(line: string): boolean | undefined {
  const match = /^(?:\?[ \t]+)?(?:(?:(?:!<[^>\r\n]+>|![^\s,\[\]{}]+)|&[a-z0-9_-]+)(?:[ \t\r\n]|#[^\r\n]*(?:\r?\n|$))+)*(?:"((?:\\[^\r\n]|[^"\\\r\n])*)"|'((?:''|[^'\r\n])*)'|([a-z0-9_.-]+(?:[ \t]+[a-z0-9_.-]+)*))(?:[ \t\r\n]|#[^\r\n]*(?:\r?\n|$))*:[ \t]*([\s\S]*?)\r?$/i.exec(line);
  if (!match) return undefined;
  const key = yamlKey(match[1], match[2], match[3]);
  if (key === undefined) return true;
  if (!DESCRIPTOR_FIELD.test(normalizeField(key))) return undefined;
  const raw = match[4].replace(/[ \t]+#.*$/, "").trim();
  let value: string | undefined;
  if (raw.startsWith('"')) {
    try { value = JSON.parse(raw); } catch { /* unknown YAML escape */ }
  } else if (raw.startsWith("'") && raw.endsWith("'")) value = raw.slice(1, -1).replace(/''/g, "'");
  else if (/^[a-z0-9_. -]+$/i.test(raw)) value = raw;
  return value === undefined || isSecretField(value);
}

function namedYamlValueIsSecret(lines: string[], start: number, end: number, baseIndent: number, beginsItem: boolean, budget: { remaining: number }): boolean {
  const scan = (position: number, direction: -1 | 1): boolean => {
    for (let i = position; i >= 0 && i < lines.length; i += direction) {
      if (--budget.remaining < 0) return true;
      const line = lines[i];
      if (/^[ \t]*(?:#.*)?\r?$/.test(line)) continue;
      const indent = /^[ \t]*/.exec(line)![0].length;
      const rest = line.slice(indent);
      const item = /^-[ \t]+/.exec(rest);
      if (item && indent < baseIndent) {
        if (direction > 0 || indent + item[0].length !== baseIndent) break;
        return yamlDescriptorIsSecret(rest.slice(item[0].length)) === true;
      }
      if (indent < baseIndent || (item && indent <= baseIndent)) break;
      if (indent > baseIndent) continue;
      if (yamlDescriptorIsSecret(rest) === true) return true;
    }
    return false;
  };
  return (!beginsItem && scan(start - 1, -1)) || scan(end + 1, 1);
}

/** Find secret value ranges in YAML/JSON flow mappings. */
function flowRedactionRanges(text: string): [number, number][] {
  if (!text.includes("{")) return [];
  type Frame = { start: number; fieldStart: number; fields: [number, number][]; brackets: number; tokenStart: boolean; colonSeen: boolean[]; quotedKey: boolean[] };
  const stack: Frame[] = [];
  const ranges: [number, number][] = [];
  let quote: "'" | '"' | undefined;
  let comment = false;
  let fieldsSeen = 0;
  const inspect = (frame: Frame, end: number) => {
    frame.fields.push([frame.fieldStart, end]);
    const values: [number, number][] = [];
    let secretName = false;
    for (const [start, stop] of frame.fields) {
      if (++fieldsSeen > 50_000) { ranges.push([stack[0]?.start ?? frame.start, text.length]); return false; }
      const raw = text.slice(start, stop);
      const field = /^((?:(?:[ \t\r\n]+)|(?:#[^\r\n]*(?:\r?\n|$)))*)(?:\?[ \t]+)?(?:(?:(?:!<[^>\r\n]+>|![^\s,\[\]{}]+)|&[a-z0-9_-]+)(?:[ \t\r\n]|#[^\r\n]*(?:\r?\n|$))+)*(?:"((?:\\[^\r\n]|[^"\\\r\n])*)"|'((?:''|[^'\r\n])*)'|([a-z0-9_.-]+(?:[ \t]+[a-z0-9_.-]+)*))((?:[ \t\r\n]|#[^\r\n]*(?:\r?\n|$))*:[ \t\r\n]*)([\s\S]*)$/i.exec(raw);
      if (!field) continue;
      const key = yamlKey(field[2], field[3], field[4]);
      if (key === undefined) { ranges.push([frame.start, Math.min(end + 1, text.length)]); return true; }
      const valueStart = stop - field[6].length;
      if (valueStart === stop) continue;
      if (isSecretField(key)) ranges.push([valueStart, stop]);
      if (VALUE_FIELD.test(normalizeField(key))) values.push([valueStart, stop]);
      if (DESCRIPTOR_FIELD.test(normalizeField(key)) && yamlDescriptorIsSecret(raw.slice(field[1].length).trim()) === true) secretName = true;
    }
    if (secretName) ranges.push(...values);
    return true;
  };
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (!stack.length) {
      if (char === "{") stack.push({ start: i, fieldStart: i + 1, fields: [], brackets: 0, tokenStart: true, colonSeen: [false], quotedKey: [false] });
      continue;
    }
    if (comment) { if (char === "\n") comment = false; continue; }
    if (quote) {
      if (quote === '"' && char === "\\") { i++; continue; }
      if (quote === "'" && char === "'" && text[i + 1] === "'") { i++; continue; }
      if (char === quote) quote = undefined;
      continue;
    }
    const frame = stack.at(-1)!;
    if ((char === '"' || char === "'") && frame.tokenStart) {
      if (!frame.colonSeen[frame.brackets]) frame.quotedKey[frame.brackets] = true;
      quote = char;
      frame.tokenStart = false;
      continue;
    }
    if (char === "#" && /\s/.test(text[i - 1] ?? "")) { comment = true; continue; }
    if (frame.tokenStart && (char === "!" || char === "&")) {
      if (char === "!" && text[i + 1] === "<") {
        const end = text.indexOf(">", i + 2);
        if (end < 0) { ranges.push([stack[0].start, text.length]); stack.length = 0; break; }
        i = end;
        continue;
      }
      while (i + 1 < text.length && !/[\s,\[\]{}]/.test(text[i + 1])) i++;
      continue;
    }
    if (char === "{") {
      if (stack.length >= 32) { ranges.push([stack[0].start, text.length]); stack.length = 0; break; }
      frame.tokenStart = false;
      stack.push({ start: i, fieldStart: i + 1, fields: [], brackets: 0, tokenStart: true, colonSeen: [false], quotedKey: [false] });
      continue;
    }
    if (char === "}") {
      stack.pop();
      if (!inspect(frame, i)) { stack.length = 0; break; }
    } else if (char === "[") { frame.brackets++; frame.colonSeen.push(false); frame.quotedKey.push(false); frame.tokenStart = true; }
    else if (char === "]") {
      if (frame.brackets > 0) { frame.brackets--; frame.colonSeen.pop(); frame.quotedKey.pop(); }
      frame.tokenStart = false;
    }
    else if (char === ",") {
      if (frame.brackets === 0) { frame.fields.push([frame.fieldStart, i]); frame.fieldStart = i + 1; }
      frame.colonSeen[frame.brackets] = false;
      frame.quotedKey[frame.brackets] = false;
      frame.tokenStart = true;
    } else if (char === ":") {
      const next = text[i + 1] ?? "";
      if (!frame.colonSeen[frame.brackets] && (frame.quotedKey[frame.brackets] || !next || /[\s,\[\]{}]/.test(next))) {
        frame.colonSeen[frame.brackets] = true;
        frame.tokenStart = true;
      } else frame.tokenStart = false;
    }
    else if (!/\s/.test(char)) frame.tokenStart = false;
  }
  while (stack.length) if (!inspect(stack.pop()!, text.length)) break;
  if (!ranges.length) return [];
  ranges.sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const [start, end] of ranges) {
    const previous = merged.at(-1);
    if (previous && start <= previous[1]) previous[1] = Math.max(previous[1], end);
    else merged.push([start, end]);
  }
  return merged;
}

/** Mask secret values in YAML/JSON flow mappings, preserving unrelated fields. */
function redactFlowMappings(text: string): string {
  const ranges = flowRedactionRanges(text);
  let result = "", cursor = 0;
  for (const [start, end] of ranges) {
    result += `${text.slice(cursor, start)}"[REDACTED]"`;
    cursor = end;
  }
  return result + text.slice(cursor);
}

function yamlValueEnd(lines: string[], start: number, baseIndent: number, budget: { remaining: number }, allowIndentlessSequence = false): number {
  let end = start;
  while (end + 1 < lines.length) {
    if (--budget.remaining < 0) break;
    const next = lines[end + 1];
    if (!/^[ \t]*\r?$/.test(next)) {
      const indent = /^[ \t]*/.exec(next)![0].length;
      if (indent < baseIndent || (indent === baseIndent && !(allowIndentlessSequence && /^-(?:[ \t]|\r?$)/.test(next.slice(indent))))) break;
    }
    end++;
  }
  return end;
}

/** Mask indented YAML block scalars for secret-named keys without consuming sibling fields. */
function redactYamlBlocks(text: string, flowRanges: [number, number][]): string {
  if (!text.includes("\n") || !text.includes(":")) return text;
  const lines = text.split("\n");
  let offset = 0;
  const lineOffsets = lines.map((line) => { const current = offset; offset += line.length + 1; return current; });
  const coveredByFlow = (position: number) => {
    let lo = 0, hi = flowRanges.length;
    while (lo < hi) {
      const mid = Math.floor((lo + hi) / 2);
      if (flowRanges[mid][0] <= position) lo = mid + 1;
      else hi = mid;
    }
    return lo > 0 && position < flowRanges[lo - 1][1];
  };
  const result: string[] = [];
  const budget = { remaining: 50_000 };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    result.push(line);
    const header = /^([ \t]*)(?:-([ \t]+))?(?:(?:(?:!<[^>\r\n]+>|![^\s,\[\]{}]+)|&[a-z0-9_-]+)[ \t]+)*(?:"((?:\\[^\r\n]|[^"\\\r\n])*)"|'((?:''|[^'\r\n])*)'|([a-z0-9_.-]+(?:[ \t]+[a-z0-9_.-]+)*))[ \t]*:[ \t]*(?:(?:![^ \t\r\n]+|&[a-z0-9_-]+)[ \t]+)*[|>](?:[+-]?[1-9]?|[1-9][+-]?)[ \t]*(?:#[^\r\n]*)?\r?$/i.exec(line);
    if (!header) {
      const scalar = /^([ \t]*)(?:-([ \t]+))?(?:(?:(?:!<[^>\r\n]+>|![^\s,\[\]{}]+)|&[a-z0-9_-]+)[ \t]+)*(?:"((?:\\[^\r\n]|[^"\\\r\n])*)"|'((?:''|[^'\r\n])*)'|([a-z0-9_.-]+(?:[ \t]+[a-z0-9_.-]+)*))([ \t]*:[ \t]*)(.*?)(\r?)$/i.exec(line);
      if (!scalar) continue;
      const valuePosition = lineOffsets[i] + line.length - scalar[7].length - scalar[8].length;
      // A flow value is masked by the flow pass; treating its comma as block content
      // would remove the separator and merge it with the next field.
      if (coveredByFlow(valuePosition)) continue;
      const key = yamlKey(scalar[3], scalar[4], scalar[5]);
      const secretKey = key === undefined || isSecretField(key);
      if (!secretKey && !VALUE_FIELD.test(normalizeField(key))) continue;
      const baseIndent = scalar[1].length + (scalar[2] === undefined ? 0 : 1 + scalar[2].length);
      const noInlineValue = !scalar[7].trim() || scalar[7].trimStart().startsWith("#");
      const end = yamlValueEnd(lines, i, baseIndent, budget, noInlineValue);
      if (noInlineValue && budget.remaining >= 0 && !lines.slice(i + 1, end + 1).some((part) => !/^[ \t]*\r?$/.test(part))) continue;
      if (!secretKey && budget.remaining >= 0 && !namedYamlValueIsSecret(lines, i, end, baseIndent, scalar[2] !== undefined, budget)) continue;
      const prefix = line.slice(0, line.length - scalar[7].length - scalar[8].length);
      result[result.length - 1] = `${prefix}${/[ \t]$/.test(prefix) ? "" : " "}[REDACTED]${scalar[8]}`;
      while (i + 1 < lines.length) {
        const next = lines[i + 1];
        if (/^[ \t]*\r?$/.test(next)) { result.push(next); i++; continue; }
        const indent = /^[ \t]*/.exec(next)![0].length;
        if (indent < baseIndent || (indent === baseIndent && !(noInlineValue && /^-(?:[ \t]|\r?$)/.test(next.slice(indent))))) break;
        i++;
      }
      continue;
    }
    const key = yamlKey(header[3], header[4], header[5]);
    const baseIndent = header[1].length + (header[2] === undefined ? 0 : 1 + header[2].length);
    if (key !== undefined && !isSecretField(key)) {
      if (!VALUE_FIELD.test(normalizeField(key))) continue;
      const end = yamlValueEnd(lines, i, baseIndent, budget);
      if (budget.remaining >= 0 && !namedYamlValueIsSecret(lines, i, end, baseIndent, header[2] !== undefined, budget)) continue;
    }
    let masked = false;
    while (i + 1 < lines.length) {
      const next = lines[i + 1];
      if (/^[ \t]*\r?$/.test(next)) {
        result.push(next);
        i++;
        continue;
      }
      const indent = /^[ \t]*/.exec(next)![0];
      if (indent.length <= baseIndent) break;
      if (!masked) {
        result.push(`${indent}[REDACTED]${next.endsWith("\r") ? "\r" : ""}`);
        masked = true;
      }
      i++;
    }
  }
  return result.join("\n");
}

function yamlReferences(text: string): { anchors: Set<string>; aliases: Map<string, number> } {
  const anchors = new Set<string>();
  const aliases = new Map<string, number>();
  for (const match of text.matchAll(/(?:^|[\s:[,{])([&*])([^\s,\[\]{}#]+)/g)) {
    if (match[1] === "&") anchors.add(match[2]);
    else aliases.set(match[2], (aliases.get(match[2]) ?? 0) + 1);
  }
  return { anchors, aliases };
}

export function redactString(s: string): string {
  // YAML merges can supply secret values indirectly from another mapping.
  // The line and flow scanners do not resolve those inherited fields.
  if (/(?:^|[\r\n{,])[ \t]*(?:-[ \t]+)?(?:\?[ \t]+)?(?:(?:(?:!<[^>\r\n]+>|![^\s,\[\]{}]+)|&[a-z0-9_-]+)[ \t]+)*(?:<<|"<<"|'<<')(?:[ \t\r\n]|#[^\r\n]*(?:\r?\n|$))*:(?=[ \t\r\n\[\]{},]|$)/im.test(s)) {
    return "[REDACTED YAML merge]";
  }
  // Explicit block keys can split a key and value across lines. The normal
  // line-oriented scanner cannot associate their siblings reliably.
  if (/^[ \t]*(?:-[ \t]+)?\?[ \t]+[^\r\n]+\r?\n(?:[ \t]*(?:#[^\r\n]*)?\r?\n)*[ \t]*:(?:[ \t]|\r?$)/m.test(s)) {
    return "[REDACTED explicit YAML mapping]";
  }
  // Preserve argument boundaries: adjacent shell quotes and bare text form a single word.
  let out = redactFlowMappings(redactYamlBlocks(s, flowRedactionRanges(s))).replace(/'(\s*(?:proxy-)?authorization[\t ]*:[\t ]*)(?:\\[\s\S]|[^'\\])*(?:'|$)|"(\s*(?:proxy-)?authorization[\t ]*:[\t ]*)(?:\\[\s\S]|[^"\\])*(?:"|$)|(\b(?:proxy-)?authorization["']?[\t ]*:)[\t ]*[^\r\n]+/gi,
    (_whole, single: string | undefined, double: string | undefined, raw: string | undefined) =>
      single !== undefined ? `'${single}[REDACTED]'` : double !== undefined ? `"${double}[REDACTED]"` : `${raw} [REDACTED]`);
  out = out.replace(/((?:^|\s)(?:-[uU]\s*|--(?:proxy-)?user(?:=|\s+)))((?:\\[\s\S]|"(?:\\[\s\S]|[^"\\])*(?:"|$)|'(?:\\[\s\S]|[^'\\])*(?:'|$)|[^\s"'\\&;|])+)/g,
    (whole, option: string, value: string) => /[:"']/.test(value) ? `${option}[REDACTED]` : whole);
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
  if (s.includes("&") && s.includes("*")) {
    const before = yamlReferences(s);
    const after = yamlReferences(out);
    for (const [name, count] of before.aliases) {
      // A redacted alias may point to a secret still visible at its definition.
      if (before.anchors.has(name) && (after.aliases.get(name) ?? 0) < count) return "[REDACTED YAML alias]";
    }
  }
  return out;
}

/** Keep all entries even if masking makes two different keys identical. */
export function uniqueKey(obj: Record<string, unknown>, key: string, nextIndexes?: Map<string, number>): string {
  let index = nextIndexes?.get(key) ?? 1;
  let candidate = index === 1 ? key : `${key} [${index}]`;
  while (Object.hasOwn(obj, candidate)) candidate = `${key} [${++index}]`;
  nextIndexes?.set(key, index + 1);
  return candidate;
}

export function redact<T>(v: T): T {
  if (typeof v === "string") return redactString(v) as T;
  if (Array.isArray(v)) return v.map(redact) as T;
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = Object.create(null);
    const nextIndexes = new Map<string, number>();
    const entries = Object.entries(v);
    const secretDescriptor = entries.some(([k, x]) => DESCRIPTOR_FIELD.test(normalizeField(k)) && typeof x === "string" && isSecretField(x));
    for (const [k, x] of entries) {
      const secretValue = isSecretField(k) || (secretDescriptor && VALUE_FIELD.test(normalizeField(k)));
      out[uniqueKey(out, redactString(k), nextIndexes)] = secretValue && x != null ? "[REDACTED]" : redact(x);
    }
    return out as T;
  }
  return v;
}

/** Truncates long strings, keeping both the head and the tail so content hidden at the end is still seen. */
export function clip(v: unknown, max: number, state: { truncated: boolean }): unknown {
  if (typeof v === "string") {
    if (v.length <= max) return v;
    state.truncated = true;
    const half = Math.floor(max / 2);
    return `${v.slice(0, half)}\n…[${v.length - max} chars omitted]…\n${v.slice(-half)}`;
  }
  if (Array.isArray(v)) return v.map((x) => clip(x, max, state));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = Object.create(null);
    const nextIndexes = new Map<string, number>();
    for (const [k, x] of Object.entries(v)) out[uniqueKey(out, clip(k, max, state) as string, nextIndexes)] = clip(x, max, state);
    return out;
  }
  return v;
}
