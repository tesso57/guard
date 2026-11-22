import { closeSync, constants, fstatSync, openSync, opendirSync, readSync } from "node:fs";
import { extname, join } from "node:path";
import { tail, type AuditRecord } from "./audit.ts";
import { projectKey } from "./rules.ts";

// Older audit rows lack a project key. Match both the session ID and cwd
// in the header because Pi can use a shared session directory.
function matchesHeader(path: string, id: string, cwd: string): boolean {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (!fstatSync(fd).isFile()) return false;
    const buf = Buffer.alloc(8192);
    const bytes = readSync(fd, buf, 0, buf.length, 0);
    const end = buf.subarray(0, bytes).indexOf(10);
    if (end < 0) return false;
    const header = JSON.parse(buf.toString("utf8", 0, end));
    return header?.type === "session" && header.id === id && header.cwd === cwd;
  } catch { return false; }
  finally { if (fd !== undefined) closeSync(fd); }
}

function legacyProjectSessions(cwd: string, dir: string, candidates: Set<string>): Set<string> {
  const matches = new Set<string>();
  if (!candidates.size || !dir) return matches;
  try {
    const entries = opendirSync(dir);
    try {
      let inspected = 0;
      for (let i = 0; i < 2048 && inspected < 32 && matches.size < candidates.size; i++) {
        const entry = entries.readSync();
        if (!entry) break;
        const id = /_([\da-f-]{36})\.jsonl$/i.exec(entry.name)?.[1];
        if (!id || !candidates.has(id) || !entry.isFile()) continue;
        inspected++;
        if (matchesHeader(join(dir, entry.name), id, cwd)) matches.add(id);
      }
    } finally { entries.closeSync(); }
  } catch { /* Project-tagged audit rows still work without session files. */ }
  return matches;
}

const sourceExtensions = new Set([".c", ".cpp", ".cs", ".css", ".go", ".h", ".html", ".java", ".js", ".jsx", ".kt", ".md", ".py", ".rb", ".rs", ".sql", ".swift", ".tf", ".ts", ".tsx", ".vue", ".yaml", ".yml"]);

function hintFor(r: AuditRecord): "batch" | "search" | undefined {
  if (r.action !== "confirm" || r.final !== "run" || !/^allow:(once|session|project|global)$/.test(r.choice ?? "")) return;
  if (r.source === "concurrent" && (r.tool === "read" || r.tool === "bash")) return "batch";
  if (r.source === "sensitive" && ["bash", "grep"].includes(r.tool)
    && r.reasons.some(reason => reason.startsWith("may expose secrets: the search would include "))) return "search";
}

export function projectGuidance(cwd: string, sessionDir: string): string {
  const key = projectKey(cwd);
  const rows = tail(1000).flatMap(r => {
    const hint = hintFor(r);
    return hint && (r.project === key || (r.project === undefined && typeof r.session === "string")) ? [{ r, hint }] : [];
  });
  const legacy = legacyProjectSessions(cwd, sessionDir, new Set(rows.flatMap(({ r }) => !r.project && r.session ? [r.session] : [])));
  const counts = { batch: 0, search: 0 };
  const extensions = new Map<string, number>();
  for (const { r, hint } of rows) {
    if (r.project !== key && !(r.session && legacy.has(r.session))) continue;
    counts[hint]++;
    if (r.tool === "read" && r.preview.startsWith("read ")) {
      const ext = extname(r.preview);
      if (sourceExtensions.has(ext)) extensions.set(ext, (extensions.get(ext) ?? 0) + 1);
    }
  }
  const globs = [...extensions].filter(([, n]) => n >= 2).sort((a, b) => b[1] - a[1]).slice(0, 3)
    .map(([ext]) => `-g '*${ext}'`).join(", ");
  return [
    counts.batch >= 2 && "Group independent file reads together. Run shell commands and other tools that may change files in a separate message, waiting for results between batches.",
    counts.search >= 2 && `For source searches, start with the relevant source directories and simple inclusion globs.${globs ? ` Previously read file types in this project include ${globs}. Use the ones relevant to the current task.` : ""} If the location is unknown, list filenames first, then search the relevant files. Access secret files only when the current request needs them.`,
  ].filter(Boolean).join("\n");
}
