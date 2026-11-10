export type TextEdit = { oldText: string; newText: string };

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
  const replacements: { start: number; end: number; text: string }[] = [];
  for (const edit of edits) {
    const oldText = normalize(edit.oldText);
    if (!oldText) return undefined;
    const start = base.indexOf(oldText);
    if (start < 0 || base.indexOf(oldText, start + 1) >= 0) return undefined;
    replacements.push({ start, end: start + oldText.length, text: normalize(edit.newText) });
  }
  replacements.sort((a, b) => a.start - b.start);
  if (replacements.some((r, i) => i > 0 && replacements[i - 1].end > r.start)) return undefined;
  let result = base;
  for (const r of replacements.reverse()) result = result.slice(0, r.start) + r.text + result.slice(r.end);
  return bom + (crlf ? result.replace(/\n/g, "\r\n") : result);
}
