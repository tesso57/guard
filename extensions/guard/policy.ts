/**
 * Deterministic checks that run before the model.
 *   hardDeny  : blocks that nothing can override (no rule, no dialog)
 *   sensitive : access to paths that likely hold secrets, or to guard's own state → confirm
 *   safeAllow : obviously safe → allow without calling the model
 */
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { isLongOption, isReadOnlyArgv, nonFlags, normalizeArgv, type Parsed } from "./shell.ts";
import { containsProtectedRoot, expandGlobFully, gitConfigIsSafe, isFreelyReadable, isHomeOrAncestor, isInside, isRiskyProjectFile, memo, pathLikeTokens, pathVariants, protectedReason, realPath, resolvePath, secretFilesUnder, sensitiveReason } from "./paths.ts";

const BUILTIN_TOOLS = new Set(["bash", "edit", "write", "read", "grep", "find", "ls"]);

const HARD_DENY_BASH: [RegExp, string][] = [
  [/\bmkfs(?:\.\w+)?\b/, "creates a file system"],
  [/\bdd\b[^;&|]*\bof=\/dev\/(?:sd|nvme|disk|hd|xvd|vd|mmcblk)/, "writes directly to a block device"],
  [/\b(?:curl|wget|fetch)\b[^;&]*\|&?\s*(?:sudo\s+)?(?:env\s+)?(?:\S*\/)?(?:ba|z|da|k|fi)?sh\b/, "pipes a download straight into a shell"],
  [/\b(?:curl|wget)\b[^;&]*\|&?\s*(?:sudo\s+)?(?:\S*\/)?(?:python[23]?|node|perl|ruby)\b/, "pipes a download straight into an interpreter"],
  [/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, "fork bomb"],
  [/\bchmod\s+(?:-[A-Za-z]+\s+)*-R\s+(?:0?777|a\+rwx)\s+(?:\/|~|\$HOME)(?=\s|$)/, "opens permissions on / or ~"],
  [/\b(?:history\s+-c|unset\s+HISTFILE)\b/, "erases shell history"],
  // Fallback for forms the argv check cannot see (e.g. inside substitutions)
  [/\brm\s+(?:-[A-Za-z]*\s+)*-[A-Za-z]*[rR][A-Za-z]*\s+(?:-[A-Za-z-]+\s+)*(?:"|')?(?:\/|~|\$HOME|\$\{HOME\})\/?\*?(?:"|')?(?=\s|$|;|&|\|)/, "recursive deletion of / or ~"],
];

/** Spellings of guard's and pi's state that can appear in commands without resolving to a known path. */
const PROTECTED_MARKERS = ["~/.pi", "$home/.pi", "${home}/.pi", ".pi/agent"];

/** Commands that delete their arguments. */
const DELETERS = new Set(["rm", "rmdir", "shred", "unlink"]);
/** Commands that put their sources into a destination (the last argument). */
const PLACERS = new Set(["mv", "cp", "rsync", "ln", "install", "scp"]);
const isRecursiveCopy = (a: string[]) => a[0] === "rsync" || a[0] === "mv" || a.some((t) => t === "--recursive" || t === "--archive" || (/^-[A-Za-z]+$/.test(t) && /[rRa]/.test(t)));
const hasGlob = (t: string) => /[*?[]/.test(t);

/** Top-level system directories; deleting them recursively is never intended. */
const SYSTEM_DIRS = ["/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/opt", "/proc", "/sbin", "/sys", "/usr", "/var", "/System", "/Library", "/Applications", "/Users", "/home"];

/**
 * Removes the text inside quotes so hard-deny patterns do not fire on commit messages or search strings.
 * Double-quoted text that contains a command substitution still runs, so it is kept.
 */
function stripQuoted(cmd: string): string {
  return cmd.replace(/'[^']*'/g, "''").replace(/"((?:[^"\\]|\\.)*)"/g, (m, inner: string) => (/\$\(|`/.test(inner) ? m : '""'));
}

const optionValue = (a: string[], names: string[]) => {
  const out: string[] = [];
  a.forEach((t, i) => {
    for (const n of names) {
      if (t === n && a[i + 1]) out.push(a[i + 1]);
      else if (n.startsWith("--") && isLongOption(t, n)) {
        // --output=x, and the abbreviations GNU tools accept (--outp=x, --outp x)
        const eq = t.indexOf("=");
        if (eq > 0) out.push(t.slice(eq + 1));
        else if (a[i + 1]) out.push(a[i + 1]);
      }
    }
  });
  return out;
};

/** Paths a bash subcommand writes to, beyond redirects. */
function bashWriteTargets(raw: string[]): string[] {
  const { argv: a } = normalizeArgv(raw, "deny");
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
    case "tar":
      out.push(...optionValue(a, ["-C", "--directory", "-f", "--file"]));
      break;
  }
  return out;
}

/** Every string in a nested value, for tools whose argument names we do not know. */
function allStrings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => allStrings(x, out));
  else if (v && typeof v === "object") Object.values(v).forEach((x) => allStrings(x, out));
  return out;
}

/**
 * The paths a tool call reads and writes, as absolute paths.
 * For bash, `cd` is followed so `cd ~/.pi && printf x >> agent/guard/rules.jsonl` resolves correctly.
 * For tools other than the built-ins, every path-like string counts as both read and written.
 */
export function inputPaths(tool: string, input: any, cwd: string, parsed?: Parsed): { reads: string[]; writes: string[] } {
  return memo(`inputPaths:${tool}:${cwd}:${JSON.stringify(input)}`, () => computeInputPaths(tool, input, cwd, parsed));
}

function computeInputPaths(tool: string, input: any, cwd: string, parsed?: Parsed): { reads: string[]; writes: string[] } {
  if (tool === "bash" && parsed) {
    const reads: string[] = [];
    const writes: string[] = [];
    let dir = cwd;
    for (const s of parsed.subs) {
      const { argv: a } = normalizeArgv(s.argv, "deny");
      // The shell may not be where we think (a failed cd, cd inside a pipeline, popd), so paths are resolved
      // against both the tracked directory and the original cwd, and the tracked directory itself counts as read.
      for (const base of dir === cwd ? [cwd] : [dir, cwd]) {
        reads.push(...pathLikeTokens(base, a.slice(1)), ...s.reads.flatMap((r) => pathVariants(base, r)));
        // Wildcards in write targets are expanded: `>> ~/.p?/a????/guard/rules.jsonl` writes to the real file
        writes.push(...[...s.writes, ...bashWriteTargets(s.argv)].flatMap((w) => [...pathVariants(base, w), ...(hasGlob(w) ? expandGlobFully(base, w) : [])]));
      }
      if (a[0] === "cd" || a[0] === "pushd") {
        const target = nonFlags(a)[0];
        dir = target && target !== "-" ? resolvePath(dir, target) : homedir();
      } else if (a[0] === "popd") dir = cwd;
      if (dir !== cwd) reads.push(dir);
    }
    reads.push(...pathLikeTokens(cwd, [], parsed.globs));
    return { reads, writes };
  }
  if (!BUILTIN_TOOLS.has(tool)) {
    const ps = pathLikeTokens(cwd, allStrings(input).filter((s) => s.length < 4096 && !/\s/.test(s.trim())));
    return { reads: ps, writes: ps };
  }
  const p: string[] = [];
  for (const k of ["path", "file_path", "filePath", "file", "dir", "directory"]) if (typeof input?.[k] === "string") p.push(...pathVariants(cwd, input[k]));
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

function strictlyReadOnly(parsed: Parsed | undefined, writes: string[]): boolean {
  return !!parsed && parsed.ok && !parsed.dynamic.length && !writes.length && parsed.subcommands.every(isReadOnlyArgv);
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
  const scan = parsed && parsed.ok && !parsed.dynamic.length ? stripQuoted(cmd) : cmd;
  // Very long commands are not scanned (bounded work); they cannot be parsed either and go to the model
  if (scan.length <= 16 * 1024) for (const [re, why] of HARD_DENY_BASH) if (re.test(scan)) return why;
  if (parsed) {
    let dir = cwd;
    for (const s of parsed.subs) {
      const { argv: a } = normalizeArgv(s.argv, "deny");
      const bases = dir === cwd ? [cwd] : [dir, cwd];
      if (isRecursiveRm(a) && nonFlags(a).some((t) => bases.some((b) => isDangerousDeleteTarget(b, t)))) return "recursive deletion of /, ~ or a system directory";
      // Deleting or moving away a directory that contains guard's state (`rm -rf ~/.p*`, `mv ~/.pi x`)
      const args = nonFlags(a);
      const resolveAll = (b: string, t: string) => [...pathVariants(b, t), ...(hasGlob(t) ? expandGlobFully(b, t) : [])];
      const removes = DELETERS.has(a[0]) ? args : a[0] === "mv" ? args.slice(0, -1) : [];
      if (removes.some((t) => bases.some((b) => resolveAll(b, t).some((p) => containsProtectedRoot(p, roots)))))
        return "deletes or moves a directory that contains guard's or pi's state";
      // Placing something where guard's state lives (`cp -r payload/.pi ~/`, `rsync -a payload/ ~/`, `ln -sf x ~/.pi/agent`)
      if (PLACERS.has(a[0]) && args.length >= 2) {
        const dest = args[args.length - 1];
        for (const b of bases)
          for (const src of args.slice(0, -1))
            for (const d of resolveAll(b, dest)) {
              const into = [join(d, basename(src)), ...(a[0] === "rsync" && src.endsWith("/") ? [d] : [])];
              if (into.some((p) => protectedReason(p, roots) || (isRecursiveCopy(a) && containsProtectedRoot(p, roots))))
                return "copies, moves or links into guard's or pi's state";
            }
      }
      if (a[0] === "cd" || a[0] === "pushd") dir = nonFlags(a)[0] ? resolvePath(dir, nonFlags(a)[0]) : homedir();
      else if (a[0] === "popd") dir = cwd;
    }
  }
  // Reading guard's or pi's state with a strictly read-only command only needs confirmation (see sensitive);
  // anything else that touches it, by path or by name (interpreters, cd + relative paths), is blocked.
  const lower = cmd.toLowerCase();
  const touchesProtected =
    reads.some((p) => protectedReason(p, roots)) || roots.some((r) => lower.includes(r.toLowerCase())) || PROTECTED_MARKERS.some((m) => lower.includes(m));
  if (touchesProtected && !strictlyReadOnly(parsed, writes)) return "may modify a protected path (guard rules, pi state, extensions or settings)";
  return undefined;
}

const CONTENT_SEARCH = new Set(["rg", "ag", "ack", "grep", "egrep", "fgrep"]);
const isGrepFamily = (h: string) => h === "grep" || h === "egrep" || h === "fgrep";
const recursiveGrep = (args: string[]) => args.some((t) => /^-[A-Za-z]*[rR]/.test(t) || t === "--recursive" || t === "--directories=recurse" || t === "recurse");

export function sensitive(tool: string, input: any, cwd: string, roots: string[], parsed?: Parsed): string | undefined {
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  for (const p of [...reads, ...writes]) {
    const r = sensitiveReason(p);
    if (r) return r;
    if (protectedReason(p, roots)) return "reads guard or pi internal state";
  }
  // pi's grep tool searches hidden files recursively
  if (tool === "grep" && reads.concat(reads.length ? [] : [cwd]).some((p) => isHomeOrAncestor(p) || isHomeOrAncestor(realPath(p)))) return "searches file contents across the home directory";
  // Recursive content searches print matching lines of every file they reach, including .env files and keys
  if (tool === "grep") {
    const roots0 = reads.length ? reads : [cwd];
    const hit = roots0.flatMap((r) => secretFilesUnder(realPath(r)))[0];
    if (hit) return `the search would include ${hit}`;
  }
  if (tool === "bash" && parsed) {
    const cmd = String(input?.command ?? "");
    if (/(?:^|[\s"'/])\.env(?:\.[\w.-]+)?(?=$|[\s"';|&])/.test(cmd) && !/\.env\.(?:example|sample|template)/.test(cmd)) return ".env file";
    for (const raw of parsed.subcommands) {
      const { argv: a } = normalizeArgv(raw, "deny");
      const recursiveSearch =
        (isGrepFamily(a[0]) && recursiveGrep(a.slice(1))) ||
        (a[0] === "rg" && a.slice(1).some((t) => /^-[A-Za-z]*u/.test(t) || ["--hidden", "--no-ignore", "--glob", "-g", "--iglob"].some((o) => t === o || t.startsWith(`${o}=`))));
      if (recursiveSearch) {
        const given = pathLikeTokens(cwd, nonFlags(a).slice(1));
        const targets = given.length ? given : [cwd];
        const hit = targets.flatMap((r) => secretFilesUnder(realPath(r)))[0];
        if (hit) return `the search would include ${hit}`;
      }
      // Extracting archives or changing permissions recursively where guard's state lives
      const extracts = (a[0] === "tar" && /^-?[A-Za-z]*x/.test(a[1] ?? "")) || a[0] === "unzip" || a[0] === "7z" || a[0] === "bsdtar";
      const recursivePerms = ["chmod", "chown", "chattr", "chgrp"].includes(a[0]) && a.some((t) => /^-[A-Za-z]*R/.test(t) || t === "--recursive");
      if (extracts || recursivePerms) {
        const dests = extracts ? [...optionValue(a, ["-C", "--directory", "-d"]), ...(optionValue(a, ["-C", "--directory", "-d"]).length ? [] : ["."])] : nonFlags(a).slice(1);
        if (dests.some((t) => pathVariants(cwd, t).some((p) => containsProtectedRoot(p, roots))))
          return extracts ? "extracts an archive where guard's or pi's state lives" : "changes permissions recursively where guard's or pi's state lives";
      }
    }
    const lower = cmd.toLowerCase();
    if (PROTECTED_MARKERS.some((m) => lower.includes(m))) return "reads guard or pi internal state";
    for (const raw of parsed.subcommands) {
      // `env` alone prints the environment; it is only a wrapper when a command follows
      const rawHead = basename(raw[0] ?? "");
      if ((rawHead === "env" || rawHead === "printenv") && raw.slice(1).every((t) => t.startsWith("-") || /^[A-Za-z_]\w*=/.test(t))) return "prints all environment variables";
      const { argv: a } = normalizeArgv(raw, "deny");
      const head = a[0];
      const args = a.slice(1);
      if ((head === "export" && (args.length === 0 || args.includes("-p"))) || (head === "set" && args.length === 0) || (head === "declare" && args.some((t) => /^-[a-z]*[xp]/.test(t)))) return "prints the environment";
      if (head === "jq" && args.some((t) => t.includes("$ENV") || /\benv\b/.test(t))) return "reads environment variables";
      // Searching file contents across ~ or / reaches every secret in the home directory
      if (CONTENT_SEARCH.has(head) && (!isGrepFamily(head) || recursiveGrep(args))) {
        // Any directory this command may search, after cd and symlinks
        if ([cwd, ...reads].some((p) => isHomeOrAncestor(p) || isHomeOrAncestor(realPath(p)))) return "searches file contents across the home directory";
      }
    }
  }
  return undefined;
}

/** Commands that only create empty files or directories; safe when every target is a plain project path. */
const PLAIN_CREATORS = new Set(["mkdir", "touch"]);

export function safeAllow(tool: string, input: any, cwd: string, opts: { trusted: boolean; touched: Set<string> }, parsed?: Parsed): boolean {
  if (tool === "bash") {
    if (!parsed || !parsed.ok || parsed.dynamic.length || parsed.writes.length || !parsed.subcommands.length) return false;
    let creates = false;
    for (const a of parsed.subcommands) {
      const head = normalizeArgv(a).argv[0];
      if (PLAIN_CREATORS.has(head)) creates = true;
      else if (bashWriteTargets(a).length || !isReadOnlyArgv(a)) return false;
    }
    if (creates && !writesStayPlain(tool, input, cwd, parsed)) return false;
    // Only reads inside the project or in public system directories happen without asking
    if (!inputPaths(tool, input, cwd, parsed).reads.every((p) => isFreelyReadable(p, cwd))) return false;
    const heads = parsed.subcommands.map((a) => normalizeArgv(a).argv[0]);
    // Read-only git still runs commands configured in .git/config, so it needs a trusted repo with a clean config,
    // must run in the project itself (no cd anywhere in the command), and nothing this session may have planted a
    // repository-like directory (HEAD, config, objects/, refs/)
    if (heads.includes("git")) {
      if (heads.some((h) => h === "cd" || h === "pushd" || h === "popd")) return false;
      if (!opts.trusted || !gitConfigIsSafe(cwd)) return false;
      if ([...opts.touched].some((p) => /(^|\/)(\.git|objects|refs)(\/|$)/i.test(p) || /^(HEAD|config|packed-refs|config\.worktree)$/.test(basename(p)))) return false;
    }
    return true;
  }
  if (tool === "edit" || tool === "write") {
    const { writes } = inputPaths(tool, input, cwd);
    if (!writes.length) return false;
    // When pi runs in ~ (or above), "the project" would be the whole home directory
    if (isHomeOrAncestor(cwd)) return false;
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

/** True if every write target stays inside the project and avoids files that tools run later. */
export function writesStayPlain(tool: string, input: any, cwd: string, parsed?: Parsed): boolean {
  if (isHomeOrAncestor(cwd)) return false;
  const { writes } = inputPaths(tool, input, cwd, parsed);
  const realCwd = realPath(cwd);
  return writes.every((w) => {
    const r = realPath(w);
    return isInside(r, realCwd) && r.toLowerCase() !== realCwd.toLowerCase() && !isRiskyProjectFile(r.slice(realCwd.length + 1));
  });
}
