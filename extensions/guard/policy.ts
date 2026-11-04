/**
 * Deterministic checks that run before the model.
 *   hardDeny  : blocks that nothing can override (no rule, no dialog)
 *   sensitive : access to paths that likely hold secrets, or to guard's own state → confirm
 *   safeAllow : obviously safe → allow without calling the model
 */
import { basename } from "node:path";
import { isReadOnlyArgv, normalizeArgv, type Parsed } from "./shell.ts";
import { isHomeOrAncestor, isInside, isRiskyProjectFile, pathLikeTokens, protectedReason, realPath, resolvePath, sensitiveReason } from "./paths.ts";

const HARD_DENY_BASH: [RegExp, string][] = [
  [/\bmkfs(?:\.\w+)?\b/, "creates a file system"],
  [/\bdd\b[^;&|]*\bof=\/dev\/(?:sd|nvme|disk|hd|xvd|vd|mmcblk)/, "writes directly to a block device"],
  [/\b(?:curl|wget|fetch)\b[^;&]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:ba|z|da|k|fi)?sh\b/, "pipes a download straight into a shell"],
  [/\b(?:curl|wget)\b[^;&]*\|\s*(?:sudo\s+)?(?:python[23]?|node|perl|ruby)\b/, "pipes a download straight into an interpreter"],
  [/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, "fork bomb"],
  [/\bchmod\s+(?:-[A-Za-z]+\s+)*-R\s+(?:0?777|a\+rwx)\s+(?:\/|~|\$HOME)(?=\s|$)/, "opens permissions on / or ~"],
  [/\b(?:history\s+-c|unset\s+HISTFILE)\b/, "erases shell history"],
  // Fallback for forms the argv check below cannot see (e.g. inside quotes or substitutions)
  [/\brm\s+(?:-[A-Za-z]*\s+)*-[A-Za-z]*[rR][A-Za-z]*\s+(?:-[A-Za-z-]+\s+)*(?:"|')?(?:\/|~|\$HOME|\$\{HOME\})\/?\*?(?:"|')?(?=\s|$|;|&|\|)/, "recursive deletion of / or ~"],
];

/** Top-level system directories; deleting them recursively is never intended. */
const SYSTEM_DIRS = ["/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/opt", "/proc", "/sbin", "/sys", "/usr", "/var", "/System", "/Library", "/Applications", "/Users", "/home"];

const nonFlags = (a: string[]) => a.slice(1).filter((t) => !t.startsWith("-"));
const optionValue = (a: string[], names: string[]) => {
  const out: string[] = [];
  a.forEach((t, i) => {
    for (const n of names) {
      if (t === n && a[i + 1]) out.push(a[i + 1]);
      else if (n.startsWith("--") && t.startsWith(`${n}=`)) out.push(t.slice(n.length + 1));
    }
  });
  return out;
};

/** Paths a bash subcommand writes to, beyond `>` redirects. */
function bashWriteTargets(raw: string[]): string[] {
  const { argv: a } = normalizeArgv(raw);
  const head = a[0];
  const args = nonFlags(a);
  const out = optionValue(a, ["--output"]);
  switch (head) {
    case "tee": case "truncate": case "touch": case "rm": case "rmdir": case "mkdir": case "chmod": case "chown": case "shred": case "unlink":
      out.push(...args);
      break;
    case "cp": case "mv": case "install": case "ln": case "rsync": case "scp":
      if (args.length) out.push(args[args.length - 1]);
      out.push(...optionValue(a, ["-t", "--target-directory"]));
      break;
    case "sed": case "perl":
      if (a.some((t) => /^-[A-Za-z]*i/.test(t) || t.startsWith("--in-place"))) out.push(...args);
      break;
    case "dd":
      out.push(...a.filter((t) => t.startsWith("of=")).map((t) => t.slice(3)));
      break;
    case "sort": case "tree": case "curl":
      out.push(...optionValue(a, ["-o"]));
      break;
    case "wget":
      out.push(...optionValue(a, ["-O", "-o", "--output-document"]));
      break;
    case "find":
      out.push(...optionValue(a, ["-fprint", "-fprint0", "-fprintf", "-fls"]));
      break;
    case "uniq":
      if (args.length > 1) out.push(args[1]);
      break;
  }
  return out;
}

/** The paths a tool call reads and writes, as absolute paths. */
export function inputPaths(tool: string, input: any, cwd: string, parsed?: Parsed): { reads: string[]; writes: string[] } {
  if (tool === "bash" && parsed) {
    const tokens = parsed.subcommands.flatMap((a) => a.slice(1));
    const writes = [...parsed.writes, ...parsed.subcommands.flatMap(bashWriteTargets)].map((w) => resolvePath(cwd, w));
    return { reads: pathLikeTokens(cwd, tokens, parsed.globs), writes };
  }
  const p: string[] = [];
  for (const k of ["path", "file_path", "filePath", "file", "dir", "directory"]) if (typeof input?.[k] === "string") p.push(resolvePath(cwd, input[k]));
  if (tool === "edit" || tool === "write") return { reads: [], writes: p };
  return { reads: p, writes: [] };
}

function isRecursiveRm(a: string[]): boolean {
  return a[0] === "rm" && a.slice(1).some((t) => t === "--recursive" || (/^-[A-Za-z]+$/.test(t) && /[rR]/.test(t)));
}

function isDangerousDeleteTarget(cwd: string, t: string): boolean {
  const p = resolvePath(cwd, t);
  const r = realPath(p);
  return [p, r].some((x) => isHomeOrAncestor(x) || SYSTEM_DIRS.some((d) => x.toLowerCase() === d.toLowerCase()));
}

export function hardDeny(tool: string, input: any, cwd: string, roots: string[], parsed?: Parsed): string | undefined {
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  for (const w of writes) {
    const r = protectedReason(w, roots);
    if (r) return `writes to a ${r}`;
    if (basename(w) === "authorized_keys" || basename(realPath(w)) === "authorized_keys") return "writes to authorized_keys";
  }
  if (tool !== "bash") return undefined;
  const cmd = String(input?.command ?? "");
  for (const [re, why] of HARD_DENY_BASH) if (re.test(cmd)) return why;
  if (parsed) {
    for (const raw of parsed.subcommands) {
      const { argv: a } = normalizeArgv(raw);
      if (isRecursiveRm(a) && nonFlags(a).some((t) => isDangerousDeleteTarget(cwd, t))) return "recursive deletion of /, ~ or a system directory";
    }
  }
  // Reading guard's or pi's state with a strictly read-only command only needs confirmation (see sensitive);
  // anything else that touches it is blocked.
  const touchesProtected = reads.some((p) => protectedReason(p, roots)) || roots.some((r) => cmd.toLowerCase().includes(r.toLowerCase()));
  const strictlyReadOnly = !!parsed && parsed.ok && !parsed.dynamic.length && !writes.length && parsed.subcommands.every(isReadOnlyArgv);
  if (touchesProtected && !strictlyReadOnly) return "may modify a protected path (guard rules, pi sessions, extensions or settings)";
  return undefined;
}

const CONTENT_SEARCH = new Set(["rg", "ag", "ack", "grep", "egrep", "fgrep"]);

export function sensitive(tool: string, input: any, cwd: string, roots: string[], parsed?: Parsed): string | undefined {
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  for (const p of [...reads, ...writes]) {
    const r = sensitiveReason(p);
    if (r) return r;
    if (protectedReason(p, roots)) return "reads guard or pi internal state";
  }
  if (tool === "bash" && parsed) {
    const cmd = String(input?.command ?? "");
    if (/(?:^|[\s"'/])\.env(?:\.[\w.-]+)?(?=$|[\s"';|&])/.test(cmd) && !/\.env\.(?:example|sample|template)/.test(cmd)) return ".env file";
    for (const raw of parsed.subcommands) {
      const { argv: a } = normalizeArgv(raw);
      const head = a[0];
      const args = a.slice(1);
      if ((head === "env" || head === "printenv") && args.every((t) => t.startsWith("-"))) return "prints all environment variables";
      if ((head === "export" && (args.length === 0 || args.includes("-p"))) || (head === "set" && args.length === 0) || (head === "declare" && args.some((t) => /^-[a-z]*[xp]/.test(t)))) return "prints the environment";
      if (head === "jq" && args.some((t) => t.includes("$ENV") || /\benv\b/.test(t))) return "reads environment variables";
      // Searching file contents across ~ or / reaches every secret in the home directory
      if (CONTENT_SEARCH.has(head) && (head !== "grep" && head !== "egrep" && head !== "fgrep" || args.some((t) => /^-[A-Za-z]*[rR]/.test(t) || t === "--recursive"))) {
        const targets = nonFlags(a).slice(1).map((t) => resolvePath(cwd, t));
        if ((targets.length ? targets : [cwd]).some(isHomeOrAncestor)) return "searches file contents across the home directory";
      }
    }
  }
  return undefined;
}

export function safeAllow(tool: string, input: any, cwd: string, parsed?: Parsed): boolean {
  if (tool === "bash") {
    if (!parsed || !parsed.ok || parsed.dynamic.length || parsed.writes.length || !parsed.subcommands.length) return false;
    if (parsed.subcommands.some((a) => bashWriteTargets(a).length)) return false;
    return parsed.subcommands.every(isReadOnlyArgv);
  }
  if (tool === "edit" || tool === "write") {
    const { writes } = inputPaths(tool, input, cwd);
    if (!writes.length) return false;
    const realCwd = realPath(cwd);
    return writes.every((w) => {
      const r = realPath(w);
      // Symlinks that leave the project (docs/notes.md -> ~/.bashrc) are not plain project edits
      if (!isInside(r, realCwd) || r.toLowerCase() === realCwd.toLowerCase()) return false;
      return !isRiskyProjectFile(r.slice(realCwd.length + 1)) && !isRiskyProjectFile(w.slice(cwd.length + 1));
    });
  }
  return false;
}
