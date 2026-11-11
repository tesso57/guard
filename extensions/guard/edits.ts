export type TextEdit = { oldText: string; newText: string };

/** Match Pi's fuzzy equivalence when checking whether an exact edit is unique. */
function fuzzyComparable(text: string): string {
  return text.normalize("NFKC").split("\n").map((line) => line.trimEnd()).join("\n")
    .replace(/[\u2018\u2019\u201A\u201B]/g, "'")
    .replace(/[\u201C\u201D\u201E\u201F]/g, '"')
    .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]/g, "-")
    .replace(/[\u00A0\u2002-\u200A\u202F\u205F\u3000]/g, " ");
}

/** Mirror pi's accepted edit argument forms without mutating tool input. */
export function extractEdits(input: any): TextEdit[] | undefined {
  let value = input?.edits;
  if (typeof value === "string") {
    try { value = JSON.parse(value); } catch { return undefined; }
  }
  if (value && !Array.isArray(value) && typeof value === "object") value = [value];
  const edits = Array.isArray(value) ? [...value] : [];
  if (typeof input?.oldText === "string" && typeof input?.newText === "string") edits.push(input);
  if (!edits.length || !edits.every((e) => typeof e?.oldText === "string" && typeof e?.newText === "string")) return undefined;
  return edits.map((e) => ({ oldText: e.oldText, newText: e.newText }));
}

/** Predict only unique, non-overlapping exact matches. Fuzzy matches must be confirmed by the user. */
export function predictEdits(content: string, input: any): string | undefined {
  const edits = extractEdits(input);
  if (!edits) return undefined;
  const normalize = (s: string) => s.replace(/\r\n?/g, "\n");
  const bom = content.startsWith("\uFEFF") ? "\uFEFF" : "";
  const raw = bom ? content.slice(1) : content;
  const crlf = raw.indexOf("\r\n") >= 0 && raw.indexOf("\r\n") === raw.indexOf("\n") - 1;
  const base = normalize(raw);
  const fuzzyBase = fuzzyComparable(base);
  const replacements: { start: number; end: number; text: string }[] = [];
  for (const edit of edits) {
    const oldText = normalize(edit.oldText);
    if (!oldText) return undefined;
    const start = base.indexOf(oldText);
    if (start < 0 || base.indexOf(oldText, start + 1) >= 0) return undefined;
    const fuzzyOld = fuzzyComparable(oldText);
    const fuzzyStart = fuzzyBase.indexOf(fuzzyOld);
    if (!fuzzyOld || fuzzyStart < 0 || fuzzyBase.indexOf(fuzzyOld, fuzzyStart + 1) >= 0) return undefined;
    replacements.push({ start, end: start + oldText.length, text: normalize(edit.newText) });
  }
  replacements.sort((a, b) => a.start - b.start);
  if (replacements.some((r, i) => i > 0 && replacements[i - 1].end > r.start)) return undefined;
  let result = base;
  for (const r of replacements.reverse()) result = result.slice(0, r.start) + r.text + result.slice(r.end);
  return bom + (crlf ? result.replace(/\n/g, "\r\n") : result);
}
