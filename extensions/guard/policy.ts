/**
 * Deterministic checks that run before the model.
 *   hardDeny  : blocks that nothing can override (no rule, no dialog)
 *   sensitive : access to paths that likely hold secrets, or to guard's own state → confirm
 *   safeAllow : obviously safe → allow without calling the model
 */
import { homedir, userInfo } from "node:os";
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { hasGluedPathValue, innerCommands, INTERPRETER_NAMES, isLongOption, isReadOnlyArgv, isShell, nonFlags, normalizeArgv, type Parsed, parseShell } from "./shell.ts";
import { containsProtectedRoot, expandGlobFully, gitConfigIsSafe, globHitsOptionLikeName, globMayReach, ignoreFilesReinclude, isFreelyReadable, isHardLinked, isHomeOrAncestor, isInside, isRiskyProjectFile, memo, pathLikeTokens, pathVariants, protectedReason, protectedRoots, realPath, resolvePath, secretFilesUnder, sensitiveReason } from "./paths.ts";

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

/**
 * The command text to scan for protected names: here-document bodies the parser recognized (also inside $(…)) are
 * data such as commit messages or docs, and quoted text is left out when the command is static. Bodies fed to a
 * shell are hard-denied separately as scripts, and bodies fed to other interpreters are scanned on their own.
 */
function nameScanText(cmd: string, parsed: Parsed | undefined): string {
  let text = cmd;
  for (const body of parsed?.heredocBodies ?? []) if (body) text = text.replace(body, "");
  return parsed && parsed.ok && !parsed.dynamic.length ? stripQuoted(text) : text;
}

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
      // -C../x, -t../x: a value glued to a short option
      else if (n.length === 2 && n.startsWith("-") && t.startsWith(n) && t.length > 2 && !t.startsWith("--")) out.push(t.slice(2));
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
    for (const { s, a, bases, dirs } of subsWithBases(parsed, cwd)) {
      // cd/pushd/popd only move; what runs in the new directory is accounted for by the following subcommands.
      // basename/dirname only transform strings.
      const moves = ["cd", "pushd", "popd", "basename", "dirname"].includes(a[0]);
      for (const base of bases) {
        // Both the normalized and the raw argv: normalization drops location values (git -C x, npm --prefix x)
        if (!moves) reads.push(...pathLikeTokens(base, a.slice(1)), ...pathLikeTokens(base, s.argv.slice(1)));
        reads.push(...s.reads.flatMap((r) => pathVariants(base, r)));
        // Wildcards in write targets are expanded: `>> ~/.p?/a????/guard/rules.jsonl` writes to the real file
        writes.push(...[...s.writes, ...bashWriteTargets(s.argv)].flatMap((w) => [...pathVariants(base, w), ...(hasGlob(w) ? globTargets(base, w) : [])]));
      }
      if (!moves) for (const d of dirs) if (d !== cwd) reads.push(d);
    }
    reads.push(...pathLikeTokens(cwd, [], parsed.globs));
    return { reads, writes };
  }
  if (!BUILTIN_TOOLS.has(tool)) {
    // Unknown tools: every path-like string counts, including words inside command-like strings
    const strs = allStrings(input).filter((x) => x.length < 16 * 1024);
    const words = strs.flatMap((x) => (/\s/.test(x.trim()) ? parseShell(x).subcommands.flat() : [x]));
    const ps = pathLikeTokens(cwd, words);
    return { reads: ps, writes: ps };
  }
  const p: string[] = [];
  for (const k of ["path", "file_path", "filePath", "file", "dir", "directory"]) if (typeof input?.[k] === "string") p.push(...pathVariants(cwd, input[k]));
  if (tool === "edit" || tool === "write") return { reads: [], writes: p };
  return { reads: p, writes: [] };
}

/** Files a `git apply`, `git am` or `patch` would change, read from the patch file itself (undefined if unreadable). */
function patchFiles(a: string[], s: Parsed["subs"][number], bases: string[]): { files: string[]; readable: boolean } | undefined {
  const sub = a.find((t, i) => i > 0 && !t.startsWith("-"));
  const isPatch = a[0] === "patch" || (a[0] === "git" && (sub === "apply" || sub === "am"));
  if (!isPatch) return undefined;
  const sources = [...s.reads, ...optionValue(a, ["-i", "--input"]), ...(a[0] === "git" ? nonFlags(a).slice(1) : [])];
  const strip = Number(optionValue(a, ["-p"])[0] ?? (a[0] === "git" ? 1 : 0)) || 0;
  const files: string[] = [];
  let readable = sources.length > 0;
  for (const src of sources) {
    const path = resolvePath(bases[0], src);
    let text: string;
    try {
      if (statSync(path).size > 2_000_000) throw new Error("too large");
      text = readFileSync(path, "utf8");
    } catch {
      readable = false;
      continue;
    }
    for (const m of text.matchAll(/^(?:\+\+\+ |--- |rename to |copy to |diff --git a\/\S+ b\/)(\S+)/gm)) {
      const name = m[1].split("/").slice(m[0].startsWith("diff --git") ? 0 : strip).join("/");
      if (name && name !== "/dev/null") for (const b of bases) files.push(resolvePath(b, name));
    }
  }
  return { files, readable };
}

function patchTargets(a: string[], s: Parsed["subs"][number], bases: string[]): string[] {
  return patchFiles(a, s, bases)?.files ?? [];
}

/** Existing matches of a wildcard target, or its static base when it was too costly to expand. */
function globTargets(base: string, t: string): string[] {
  const e = expandGlobFully(base, t);
  return e.complete ? e.matches : [e.base];
}

function safeUser(): string {
  try {
    return userInfo().username;
  } catch {
    return "";
  }
}

/** Where `cd target` may lead from each of the current candidates (globs, CDPATH, a failed cd). */
function cdTargets(dirs: string[], target: string | undefined, assigns: string[], roots: string[]): { dirs: string[]; unknown: boolean } {
  const home = assigns.find((x) => x.startsWith("HOME="))?.slice(5);
  if (!target || target === "-") return { dirs: [home ? resolvePath(dirs[0], home) : homedir()], unknown: false };
  // ~user: the current user's home is ~; anyone else's home is somewhere guard does not track
  const tilde = /^~([^/]+)(.*)$/.exec(target);
  if (tilde) {
    if (tilde[1] !== safeUser()) return { dirs, unknown: true };
    target = `~${tilde[2]}`;
  }
  const cdpath = assigns.find((x) => x.startsWith("CDPATH="))?.slice(7) ?? process.env.CDPATH;
  const out: string[] = [];
  let unknown = false;
  for (const d of dirs) {
    if (hasGlob(target)) {
      const e = expandGlobFully(d, target);
      if (!e.complete) unknown = true;
      out.push(...e.matches);
      // A pattern that can reach guard's state adds that place, whatever is on disk now
      for (const r of roots) for (let x = r; x !== dirname(x); x = dirname(x)) if (globMayReach(d, target, [x]).into && globMayReach(d, target, [x]).around) out.push(x);
    } else out.push(resolvePath(d, target));
    // With CDPATH set, a relative cd may go to <entry>/<target> instead
    if (cdpath && !/^(\/|\.\.?(\/|$)|~)/.test(target))
      for (const e of cdpath.split(":").filter(Boolean)) out.push(resolvePath(e, target));
  }
  const all = [...new Set(out)];
  return { dirs: all.slice(0, 16), unknown: unknown || all.length > 16 };
}

/**
 * Subcommands with every directory they may run in. The shell may not be where we think (a failed cd, cd inside a
 * pipeline, popd, CDPATH), so each subcommand is resolved against all candidates plus the original cwd.
 */
function subsWithBases(parsed: Parsed, cwd: string) {
  return memo(`subs:${cwd}:${JSON.stringify(parsed.subs)}`, () => computeSubsWithBases(parsed, cwd));
}

function computeSubsWithBases(parsed: Parsed, cwd: string) {
  const out: { s: Parsed["subs"][number]; a: string[]; bases: string[]; dirs: string[]; unknown: boolean }[] = [];
  const roots = protectedRoots(cwd);
  // Once the shell's directory cannot be pinned down, it stays unknown for the rest of the command
  let unknown = false;
  const union = (...xs: string[][]) => {
    const all = [...new Set(xs.flat())];
    if (all.length > 16) unknown = true;
    return all.slice(0, 16);
  };
  const cd = (from: string[], target: string | undefined, assigns: string[]) => {
    const r = cdTargets(from, target, assigns, roots);
    if (r.unknown) unknown = true;
    return r.dirs;
  };
  // Options that make a command act in another directory: their values are extra bases for that command
  const locationDirs = (raw: string[], from: string[]) =>
    LOCATION_VALUE_OPTIONS.flatMap((o) => optionValue(raw, [o])).flatMap((v) => from.map((d) => resolvePath(d, v)));
  let dirs = [cwd];
  let previous = [cwd]; // OLDPWD
  const stack: string[][] = []; // pushd/popd directory stack
  const visited = new Set([cwd]);
  for (const s of parsed.subs) {
    const { argv: a } = normalizeArgv(s.argv, "deny");
    const loc = locationDirs(s.argv, [...new Set([...dirs, cwd])]);
    out.push({ s, a, bases: union(dirs, [cwd], loc), dirs, unknown });
    // `cd -` names OLDPWD; a bare `-` is not an option here
    const arg = a[1] === "-" ? "-" : nonFlags(a)[0];
    const before = dirs;
    const oldpwd = s.assigns.find((x) => x.startsWith("OLDPWD="))?.slice(7);
    if (a[0] === "cd") dirs = arg === "-" ? (oldpwd ? cd(dirs, oldpwd, s.assigns) : previous) : cd(dirs, arg, s.assigns);
    else if (a[0] === "pushd" && s.argv.includes("-n")) {
      // pushd -n adds to the stack without changing directory; a later `pushd` swaps it in
      if (arg) stack.push(cd(dirs, arg, s.assigns));
    } else if (a[0] === "pushd") {
      if (arg && /^[+-]\d+$/.test(arg)) dirs = union([...visited]); // rotating the stack: any directory seen so far
      else if (!arg) {
        // pushd without an argument swaps the top two entries
        const top = stack.pop();
        stack.push(dirs);
        dirs = top ?? dirs;
      } else {
        stack.push(dirs);
        dirs = cd(dirs, arg, s.assigns);
      }
    } else if (a[0] === "popd") {
      // popd returns to the directory before the last pushd; if that pushd failed, the shell may stay put
      dirs = arg && /^[+-]\d+$/.test(arg) ? union([...visited]) : union(stack.pop() ?? [...visited], dirs);
    }
    if (dirs !== before) previous = before;
    for (const d of dirs) visited.add(d);
  }
  return out;
}

const LOCATION_VALUE_OPTIONS = ["-C", "--git-dir", "--work-tree", "--prefix", "--dir", "--cwd", "--directory", "--manifest-path"];

/** Shell keywords and wrappers that run the command after them. */
const RUNS_NEXT = new Set([
  "time", "nice", "nohup", "setsid", "timeout", "sudo", "doas", "env", "stdbuf", "ionice", "chrt", "taskset", "flock", "unbuffer",
  "fakeroot", "setarch", "unshare", "strace", "ltrace", "busybox", "command", "builtin", "exec", "xargs", "parallel", "watch", "eval",
  "nsenter", "chroot", "proot", "firejail", "systemd-run", "caffeinate", "arch", "npx", "bunx", "pnpx", "uvx",
]);

/**
 * argv positions that may be the command actually run: 0, and the word after a wrapper and its options
 * (plus one positional such as a duration or architecture). `echo rm -rf /` has no such position at `rm`.
 */
function commandPositions(a: string[]): number[] {
  const out = [0];
  for (let i = 0; i < a.length; i++) {
    if (!RUNS_NEXT.has(basename(a[i]))) continue;
    let j = i + 1;
    while (j < a.length && (a[j].startsWith("-") || /^[A-Za-z_]\w*=/.test(a[j]))) j++;
    out.push(j);
    if (j + 1 < a.length) out.push(j + 1);
  }
  return [...new Set(out)].filter((i) => i < a.length);
}

const ANSI_ESCAPES: Record<string, string> = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v" };

function decodeAnsiC(s: string): string {
  return s.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c.|.)/g, (_m, e: string) => {
    if (e[0] === "x") return String.fromCharCode(parseInt(e.slice(1), 16));
    if (e[0] === "u" || e[0] === "U") return String.fromCodePoint(Math.min(parseInt(e.slice(1), 16), 0x10ffff));
    if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8) & 0xff);
    if (e[0] === "c") return String.fromCharCode(e.charCodeAt(1) & 31);
    return ANSI_ESCAPES[e] ?? e;
  });
}

/** Alternatives of one brace group: a comma list (quotes respected) or a sequence {a..e} / {1..9}. */
function braceAlternatives(inner: string): string[] | undefined {
  const seq = /^(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])(?:\.\.-?\d+)?$/.exec(inner);
  if (seq) {
    const num = /^-?\d/.test(seq[1]);
    const from = num ? Number(seq[1]) : seq[1].charCodeAt(0);
    const to = num ? Number(seq[2]) : seq[2].charCodeAt(0);
    const out: string[] = [];
    for (let x = from; out.length < 16; x += from <= to ? 1 : -1) {
      out.push(num ? String(x) : String.fromCharCode(x));
      if (x === to) break;
    }
    return out;
  }
  const parts: string[] = [];
  let cur = "";
  let q: string | null = null;
  for (const ch of inner) {
    if (q) {
      if (ch === q) q = null;
      cur += ch;
    } else if (ch === "'" || ch === '"') {
      q = ch;
      cur += ch;
    } else if (ch === ",") {
      parts.push(cur);
      cur = "";
    } else cur += ch;
  }
  parts.push(cur);
  return parts.length > 1 ? parts.slice(0, 8) : undefined;
}

/**
 * Static expansions of brace lists and sequences, $'…' (all escapes) and $"…", so hard-deny also sees `.{p,q}i`,
 * `.p{i..i}` and `$'\056pi'`. A last variant replaces whatever is left with `*`, which the wildcard checks then
 * match against guard's state by pattern.
 */
function staticVariants(cmd: string): string[] {
  const unquoted = cmd
    .replace(/\$'((?:[^'\\]|\\.)*)'/g, (_m, x: string) => `'${decodeAnsiC(x).replace(/'/g, "")}'`)
    .replace(/\$"((?:[^"\\]|\\.)*)"/g, (_m, x: string) => `"${x}"`);
  let variants = [unquoted];
  for (let round = 0; round < 3; round++) {
    const next: string[] = [];
    for (const v of variants) {
      const m = /\{([^{}]*)\}/.exec(v);
      const alts = m ? braceAlternatives(m[1]) : undefined;
      if (!m || !alts) next.push(v);
      else for (const alt of alts) next.push(v.slice(0, m.index) + alt + v.slice(m.index + m[0].length));
    }
    variants = next.slice(0, 32);
  }
  const wild = cmd.replace(/\$'(?:[^'\\]|\\.)*'|\$"(?:[^"\\]|\\.)*"|\{[^{}\s]*\}/g, "*");
  return [...new Set([...variants, wild])].filter((v) => v !== cmd);
}

const isLinking = (a: string[]) =>
  a[0] === "ln" || (a[0] === "cp" && a.some((t) => /^-[A-Za-z]*[ls]/.test(t) || isLongOption(t, "--link") || isLongOption(t, "--symbolic-link")));

const PATH_VARS = /^(HOME|CDPATH|OLDPWD|PWD)(\+?=|$)/;

/** Whether a subcommand changes HOME, CDPATH, OLDPWD or PWD for the commands after it. */
function setsPathVars(s: Parsed["subs"][number], a: string[]): boolean {
  if (s.argv.length === 0 && s.assigns.some((x) => PATH_VARS.test(x))) return true;
  const head = a[0];
  const names = (xs: string[]) => xs.some((t) => PATH_VARS.test(t));
  if (["export", "declare", "typeset", "readonly", "local", "unset", "read", "mapfile", "readarray", "getopts"].includes(head) && names(a.slice(1))) return true;
  if (head === "printf") {
    const i = a.findIndex((t) => /^-[A-Za-z]*v/.test(t));
    if (i > 0 && names([a[i].replace(/^-[A-Za-z]*v/, "") || a[i + 1] || ""])) return true;
  }
  return head === "shopt" && a.includes("cdable_vars");
}

/** Whether text names guard's or pi's state (a root path or a marker such as ~/.pi). */
function namesProtected(text: string, roots: string[]): boolean {
  const lower = text.toLowerCase();
  return roots.some((r) => lower.includes(r.toLowerCase())) || PROTECTED_MARKERS.some((m) => lower.includes(m));
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

export function hardDeny(tool: string, input: any, cwd: string, roots: string[], parsed?: Parsed, depth = 0): string | undefined {
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  for (const w of writes) {
    const r = protectedReason(w, roots);
    if (r) return `writes to a ${r}`;
    if (basename(w) === "authorized_keys" || basename(realPath(w)) === "authorized_keys") return "writes to authorized_keys";
  }
  if (tool !== "bash") {
    // Built-in tools take data (file contents, search patterns), not commands; running such data later is judged then
    if (BUILTIN_TOOLS.has(tool)) return undefined;
    // Command-like strings in other tools (powershell, MCP shells) get the same hard-deny as bash
    for (const x of allStrings(input)) {
      if (x.length > 16 * 1024 || !/\s/.test(x.trim())) continue;
      const r = hardDeny("bash", { command: x }, cwd, roots, parseShell(x), depth + 1);
      if (r) return `${r} (in ${tool})`;
    }
    return undefined;
  }
  const cmd = String(input?.command ?? "");
  if (depth < 3 && cmd.length <= 16 * 1024 && /[{]|\$['"]/.test(cmd))
    for (const v of staticVariants(cmd)) {
      const r = hardDeny("bash", { command: v }, cwd, roots, parseShell(v), depth + 1);
      if (r) return r;
    }
  const scan = parsed && parsed.ok && !parsed.dynamic.length ? stripQuoted(cmd) : cmd;
  // Very long commands are not scanned (bounded work); they cannot be parsed either and go to the model
  if (scan.length <= 16 * 1024) for (const [re, why] of HARD_DENY_BASH) if (re.test(scan)) return why;
  if (parsed) {
    // Commands inside $(…) run too
    if (depth < 3)
      for (const x of parsed.substitutions) {
        const r = hardDeny("bash", { command: x }, cwd, roots, parseShell(x), depth + 1);
        if (r) return r;
      }
    const resolveAll = (b: string, t: string) => [...pathVariants(b, t), ...(hasGlob(t) ? globTargets(b, t) : [])];
    const outerRoots = roots.filter((r) => !isInside(r, cwd));
    // Wildcards are checked against guard's state by pattern, so a skipped or truncated expansion cannot hide them
    const globInto = (b: string, t: string, rs: string[]) => hasGlob(t) && globMayReach(b, t, rs).into;
    const globAround = (b: string, t: string, rs: string[]) => hasGlob(t) && globMayReach(b, t, rs).around;
    for (const { s, a: a0, bases, unknown } of subsWithBases(parsed, cwd)) {
      // Changing HOME, CDPATH or OLDPWD for later commands changes what ~, cd and cd - mean
      if (setsPathVars(s, a0)) return "changes HOME, CDPATH or OLDPWD, which decide where later paths point";
      // pi's own CLI changes which packages and extensions pi loads
      for (const i of commandPositions(a0)) {
        if (basename(a0[i]) !== "pi") continue;
        const sub = a0.slice(i + 1).find((t) => !t.startsWith("-"));
        if (sub && ["install", "remove", "uninstall", "update", "config", "link"].includes(sub)) return "changes pi's packages or configuration (pi install/remove/update/config)";
      }
      // Commands run by this one (sh -c '…', eval, trap, su -c) and scripts fed to a shell's stdin
      if (depth < 3) {
        const head = basename(a0[0] ?? "");
        const scripts = [...innerCommands(s.argv), ...(isShell(head) ? s.heredocs : [])];
        for (const x of scripts) {
          const r = hardDeny("bash", { command: x }, cwd, roots, parseShell(x), depth + 1);
          if (r) return r;
        }
        // Other interpreters reading a here-document: their code naming guard's state is blocked
        if (INTERPRETER_NAMES.has(head) && s.heredocs.some((b) => namesProtected(b, roots))) return "an interpreter script names guard's or pi's state";
      }
      // Redirects make even `echo` a writing command
      const changing = (!isReadOnlyArgv(s.argv) || s.writes.length > 0) && !["cd", "pushd", "popd"].includes(a0[0]);
      if (unknown && changing) return "runs a changing command in a directory guard cannot determine";
      for (const t of [...s.writes, ...bashWriteTargets(s.argv)]) if (bases.some((b) => globInto(b, t, roots))) return "a wildcard write target can reach guard's or pi's state";
      // Patches name their targets inside the patch file
      for (const target of patchTargets(a0, s, bases)) if (protectedReason(target, roots)) return "applies a patch to guard's or pi's state";
      // Check the command after every wrapper too (time -p, setarch x86_64, fakeroot), not just position 0
      for (const i of commandPositions(a0)) {
        const a = [basename(a0[i]), ...a0.slice(i + 1)];
        const args = nonFlags(a);
        if (isRecursiveRm(a) && args.some((t) => bases.some((b) => isDangerousDeleteTarget(b, t)))) return "recursive deletion of /, ~ or a system directory";
        // Deleting or moving away a directory that contains guard's state (`rm -rf ~/.p*`, `mv ~/.pi x`)
        const removes = DELETERS.has(a[0]) ? args : a[0] === "mv" ? args.slice(0, -1) : [];
        if (removes.some((t) => bases.some((b) => globInto(b, t, roots) || globAround(b, t, roots) || resolveAll(b, t).some((p) => containsProtectedRoot(p, roots)))))
          return "deletes or moves a directory that contains guard's or pi's state";
        if (!PLACERS.has(a[0]) || args.length < 2) continue;
        const dest = args[args.length - 1];
        const srcs = args.slice(0, -1);
        // Links to guard's state let later plain-looking writes change it (`ln ~/.pi/…/rules.jsonl notes.txt`, `cp -al ~/.pi bk`)
        if (isLinking(a) && srcs.some((t) => bases.some((b) => resolveAll(b, t).some((p) => protectedReason(p, roots) || containsProtectedRoot(p, roots)))))
          return "links to guard's or pi's state";
        // Placing something where guard's state lives, or creating .pi/.agents in a parent of it
        for (const b of bases)
          for (const src of srcs)
            for (const d of resolveAll(b, dest)) {
              const contents = src === "." || src.endsWith("/.") || (a[0] === "rsync" && src.endsWith("/"));
              const into = contents ? d : join(d, basename(src));
              const srcPath = resolvePath(b, src);
              const created = [into, ...(isRecursiveCopy(a) ? [".pi", ".agents"].filter((n) => existsSync(join(srcPath, n))).map((n) => join(into, n)) : [])];
              if (created.some((p) => protectedReason(p, roots) || (isRecursiveCopy(a) && containsProtectedRoot(p, roots))))
                return "copies, moves or links into guard's or pi's state";
            }
      }
      // Any other command that changes things and names a directory containing guard's state (find ~/.p? -delete,
      // chmod -R 000 ~/.p?, tar -xf x -C ~/.p?) is blocked; copy destinations and cd targets are handled above
      const a = a0;
      // Staging or unstaging (git add .pi/x, git rm --cached) does not change files
      const gitSub = a[0] === "git" ? a.find((t, k) => k > 0 && !t.startsWith("-")) : undefined;
      const indexOnly = gitSub === "add" || gitSub === "stage" || (gitSub === "rm" && a.includes("--cached"));
      if (changing && !indexOnly) {
        // Raw argv too, so location values (git -C x, npm --prefix x) are seen; a copy's destination is checked above
        const named = [...new Set([...nonFlags(a), ...nonFlags(s.argv)])].filter((t) => !(PLACERS.has(a[0]) && t === nonFlags(a).at(-1)));
        // The project's own .pi/.agents are guarded by the explicit write checks; counting the project as their
        // parent would block every `git add .` or `prettier --write .` in projects that have .pi/guard.json
        const hits = (p: string) => containsProtectedRoot(p, outerRoots) || (protectedReason(p, roots) && !isInside(p, cwd));
        if (named.some((t) => bases.some((b) => globInto(b, t, outerRoots) || globAround(b, t, outerRoots) || resolveAll(b, t).some(hits))))
          return "changes guard's or pi's state, or a directory that contains it";
        // Values glued to options (-C../../.pi, -t../x, --directory=../x)
        const optionPaths = bases.flatMap((b) => pathLikeTokens(b, s.argv.slice(1).filter((t) => t.startsWith("-"))));
        if (optionPaths.some(hits)) return "changes guard's or pi's state, or a directory that contains it";
      }
    }
  }
  // Reading guard's or pi's state with a strictly read-only command only needs confirmation (see sensitive);
  // anything else that touches it, by path or by name (interpreters, cd + relative paths), is blocked.
  // Names in quoted text and in here-documents fed to cat (commit messages, docs) are not paths
  const lower = nameScanText(cmd, parsed).toLowerCase();
  // The project's own .pi/ is covered by the write checks above; naming it (git add .pi/x) is not a change to it
  const outer = roots.filter((r) => !isInside(r, cwd));
  const touchesProtected =
    reads.some((p) => protectedReason(p, outer)) || outer.some((r) => lower.includes(r.toLowerCase())) || PROTECTED_MARKERS.some((m) => lower.includes(m));
  if (touchesProtected && !strictlyReadOnly(parsed, writes)) return "may modify a protected path (guard rules, pi state, extensions or settings)";
  return undefined;
}

const CONTENT_SEARCH = new Set(["rg", "ag", "ack", "grep", "egrep", "fgrep"]);
const isGrepFamily = (h: string) => h === "grep" || h === "egrep" || h === "fgrep";
const recursiveGrep = (args: string[]) =>
  args.some((t, i) =>
    (/^-[A-Za-z0-9]*[rR]/.test(t) && !t.startsWith("--")) ||
    isLongOption(t, "--recursive") ||
    isLongOption(t, "--dereference-recursive") ||
    (isLongOption(t, "--directories") && /recurse/.test(t + (args[i + 1] ?? ""))) ||
    (t === "-d" && args[i + 1] === "recurse"),
  );
/** rg skips hidden and ignored files unless told otherwise. */
const rgSeesHidden = (args: string[]) =>
  args.some((t) => (/^-[A-Za-z0-9.]*[u.]/.test(t) && !t.startsWith("--")) || ["--hidden", "--no-ignore", "--no-ignore-vcs", "--no-ignore-dot", "--glob", "--iglob"].some((o) => isLongOption(t, o)) || t === "-g");

/**
 * What a recursive content search may print: the first secret file it would reach, and whether the search tree was
 * too large to check (then the call is not treated as safe).
 */
function searchExposure(tool: string, input: any, cwd: string, parsed?: Parsed): { hit?: string; unknown: boolean } {
  const check = (roots0: string[], hidden: boolean) => {
    let unknown = false;
    for (const r of roots0) {
      const real = realPath(r);
      const { files, complete } = secretFilesUnder(real);
      if (!complete) unknown = true;
      const hit = files.find((f) => hidden || !relativeHasHidden(real, f));
      if (hit) return { hit, unknown };
    }
    return { unknown };
  };
  if (tool === "grep") {
    const { reads } = inputPaths(tool, input, cwd);
    return check(reads.length ? reads : [cwd], true);
  }
  if (tool !== "bash" || !parsed) return { unknown: false };
  let unknown = false;
  for (const { a, bases } of subsWithBases(parsed, cwd)) {
    const args = a.slice(1);
    const gitGrep = a[0] === "git" && a.includes("grep");
    if (!((isGrepFamily(a[0]) && recursiveGrep(args)) || a[0] === "rg" || a[0] === "ag" || a[0] === "ack" || gitGrep)) continue;
    const given = bases.flatMap((b) => pathLikeTokens(b, nonFlags(a).slice(1)));
    // rg skips hidden files unless told otherwise, or unless an ignore file re-includes them (`!.env`)
    const roots0 = given.length ? given : bases;
    const r = check(roots0, a[0] !== "rg" || rgSeesHidden(args) || roots0.some((x) => ignoreFilesReinclude(realPath(x))));
    if (r.hit) return r;
    unknown ||= r.unknown;
  }
  return { unknown };
}

function relativeHasHidden(root: string, file: string): boolean {
  return file.slice(root.length).split("/").some((seg) => seg.startsWith("."));
}

export function sensitive(tool: string, input: any, cwd: string, roots: string[], parsed?: Parsed): string | undefined {
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  // The project's own .pi/ holds project files (prompts, guard.json); reading them is fine
  const outerRoots = roots.filter((r) => !isInside(r, cwd));
  for (const p of [...reads, ...writes]) {
    const r = sensitiveReason(p);
    if (r) return r;
    if (protectedReason(p, outerRoots)) return "reads guard or pi internal state";
  }
  // pi's grep tool searches hidden files recursively
  if (tool === "grep" && reads.concat(reads.length ? [] : [cwd]).some((p) => isHomeOrAncestor(p) || isHomeOrAncestor(realPath(p)))) return "searches file contents across the home directory";
  // Recursive content searches print matching lines of every file they reach, including .env files and keys
  const exposure = searchExposure(tool, input, cwd, parsed);
  if (exposure.hit) return `the search would include ${exposure.hit}`;
  if (tool === "bash" && parsed) {
    const cmd = String(input?.command ?? "");
    if (/(?:^|[\s"'/:])\.env(?:\.[\w.-]+)?(?=$|[\s"';|&])/.test(cmd) && !/\.env\.(?:example|sample|template)/.test(cmd)) return ".env file";
    // cd to a computed path ($(…), $VAR) and then changing files: guard cannot tell where that happens
    const subs = subsWithBases(parsed, cwd);
    const computedCd = subs.findIndex((x) => ["cd", "pushd"].includes(x.a[0]) && /[$`]/.test(x.s.argv.slice(1).join(" ")));
    if (computedCd >= 0 && subs.slice(computedCd + 1).some((x) => !isReadOnlyArgv(x.s.argv) || x.s.writes.length)) return "changes files after cd to a computed directory";
    for (const { s: sub, a, bases } of subs) {
      // Extracting an archive where .pi/ or .agents/ could appear (pi loads them), or recursive permission changes
      const extracts =
        ((a[0] === "tar" || a[0] === "bsdtar") && a.slice(1).some((t, i) => (i === 0 && /^[A-Za-z]*x/.test(t)) || (/^-[A-Za-z]*x/.test(t) && !t.startsWith("--")) || isLongOption(t, "--extract") || isLongOption(t, "--get"))) ||
        a[0] === "unzip" || a[0] === "7z";
      const patch = patchFiles(a, sub, bases);
      if (patch && !patch.readable) return "applies a patch guard cannot read";
      const recursivePerms = ["chmod", "chown", "chattr", "chgrp"].includes(a[0]) && a.some((t) => /^-[A-Za-z]*R/.test(t) || t === "--recursive");
      if (extracts || recursivePerms) {
        const given = extracts ? optionValue(a, ["-C", "--directory", "-d"]) : nonFlags(a).slice(1);
        const dests = bases.flatMap((b) => (given.length ? given.flatMap((t) => [...pathVariants(b, t), ...(hasGlob(t) ? globTargets(b, t) : [])]) : [b]));
        const parentOfRoot = (p: string) => roots.some((r) => isInside(r, p) || isInside(r, realPath(p)));
        if (dests.some((p) => (extracts ? parentOfRoot(p) : containsProtectedRoot(p, roots))))
          return extracts ? "extracts an archive where .pi/ or .agents/ could be created" : "changes permissions recursively where guard's or pi's state lives";
      }
    }
    const lower = nameScanText(cmd, parsed).toLowerCase();
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
    // Glued option values (-f/etc/x, -bf~/x) are easy to misread; such commands always get a judgement
    if (parsed.subcommands.some(hasGluedPathValue)) return false;
    // A wildcard that expands to a name like `--pre=sh` hands the command an option
    if (parsed.globs.some((g) => globHitsOptionLikeName(cwd, g))) return false;
    // Here-documents hide text from the parser on purpose; if guard and bash ever disagree on where a body ends,
    // the difference is a hidden command. Commands with them are always judged (they are almost always writes anyway)
    if (parsed.heredocBodies.length || parsed.subs.some((x) => x.heredocs.length)) return false;
    // The directory stack (pushd -n, rotations) is too easy to get wrong; never a shortcut
    if (parsed.subcommands.some((a) => ["pushd", "popd", "dirs"].includes(normalizeArgv(a).argv[0]))) return false;
    if (searchExposure(tool, input, cwd, parsed).unknown) return false;
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
      if (isHardLinked(w)) return false;
      // Symlinks that leave the project (docs/notes.md -> ~/.bashrc) are not plain project edits
      if (!isInside(r, realCwd) || r.toLowerCase() === realCwd.toLowerCase()) return false;
      return !isRiskyProjectFile(r.slice(realCwd.length + 1)) && !isRiskyProjectFile(w.slice(cwd.length + 1));
    });
  }
  return false;
}

/** True if every write target stays inside the project and avoids files that tools run later. */
/** True if every path the call names (read or written) is inside the project. */
export function pathsStayInProject(tool: string, input: any, cwd: string, parsed?: Parsed): boolean {
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  const realCwd = realPath(cwd);
  return !isHomeOrAncestor(cwd) && [...reads, ...writes].every((p) => isInside(realPath(p), realCwd));
}

export function writesStayPlain(tool: string, input: any, cwd: string, parsed?: Parsed): boolean {
  if (isHomeOrAncestor(cwd)) return false;
  const { writes } = inputPaths(tool, input, cwd, parsed);
  // A hard-linked file may be the same file as something outside the project
  if (writes.some(isHardLinked)) return false;
  const realCwd = realPath(cwd);
  return writes.every((w) => {
    const r = realPath(w);
    return isInside(r, realCwd) && r.toLowerCase() !== realCwd.toLowerCase() && !isRiskyProjectFile(r.slice(realCwd.length + 1));
  });
}
