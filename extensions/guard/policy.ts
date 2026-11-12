/**
 * Deterministic checks that run before the model.
 *   hardDeny  : blocks without a rule shortcut; a repeated call may receive explicit one-time approval
 *   sensitive : access to paths that likely hold secrets, or to guard's own state → confirm
 *   safeAllow : obviously safe → allow without calling the model
 */
import { homedir, tmpdir, userInfo } from "node:os";
import { createHash } from "node:crypto";
import { isUtf8 } from "node:buffer";
import { accessSync, closeSync, constants, existsSync, fstatSync, openSync, opendirSync, readSync, statSync, type Stats } from "node:fs";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import * as piSdk from "@earendil-works/pi-coding-agent";
import { grepExplicitPaths, hasGluedPathValue, innerCommands, INTERPRETER_NAMES, isLongOption, isReadOnlyArgv, isShell, nonFlags, normalizeArgv, type Parsed, parseShell, rgDisablesConfig, rgExplicitPaths, rgInfoOnly, rgListsFiles, rgListsTypes, rgSimpleIncludeSuffixes, rgVisibility, unwrapCommandWrappers } from "./shell.ts";
import { readRegularText } from "./files.ts";
import { AGENT_DIR } from "./config.ts";
import { containsProtectedRoot, expandGlobFully, trustedDirFor, trustedDirRelative, type TrustedDir, type TrustedDirState, isPiCodePath, PI_CODE_DIRS, gitConfigIsSafe, globHitsOptionLikeName, globMayReach, ignoreFilesReinclude, isFreelyReadable, isHardLinked, isHomeOrAncestor, isInside, isInsideExact, isProjectPath, isProjectHardlinkSafe, isProtectedHardLink, isRiskyProjectFile, memo, pathLikeTokens, pathVariants, protectedReason, protectedRoots, readFallbackVariants, realPath, resolvePath, secretFilesUnder, sensitiveReason, UNKNOWN_PATH } from "./paths.ts";

export const BUILTIN_TOOLS = new Set(["bash", "edit", "write", "read", "grep", "find", "ls"]);
const INCOMPLETE_DIRECTORY_COMPARISON = "/__guard_incomplete_directory_comparison__";

/** An unmodifiable root-owned system binary cannot be rewritten through a project hard link. */
function immutableSystemExecutable(candidate: string, actual: string, st: Stats): boolean {
  const roots = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"];
  if (!st.isFile() || st.uid !== 0 || (st.mode & 0o022) !== 0 ||
      !roots.some((root) => isInsideExact(candidate, root)) || !roots.some((root) => isInsideExact(actual, root))) return false;
  const unwritable = (path: string) => {
    try { accessSync(path, constants.W_OK); return false; }
    catch (error: any) { return ["EACCES", "EPERM", "EROFS"].includes(error?.code); }
  };
  if (!unwritable(actual)) return false;
  for (const path of [candidate, actual]) for (let dir = dirname(path); ; dir = dirname(dir)) {
    if (!unwritable(dir)) return false;
    if (dirname(dir) === dir) break;
  }
  return true;
}

/** Read a bounded prefix only while the opened file remains the inspected regular file. */
function executablePrefix(path: string, expected: Stats, limit: number): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.dev !== expected.dev || before.ino !== expected.ino || before.size !== expected.size || before.mtimeMs !== expected.mtimeMs || before.ctimeMs !== expected.ctimeMs) throw new Error("executable changed");
    const bytes = Buffer.alloc(limit);
    const length = readSync(fd, bytes, 0, limit, 0);
    const after = fstatSync(fd);
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw new Error("executable changed during inspection");
    return bytes.subarray(0, length);
  } finally { closeSync(fd); }
}

/** Recognize structurally plausible native headers without executing the file. */
function hasNativeExecutableHeader(header: Buffer): boolean {
  if (header.length < 4) return false;
  const magic = header.subarray(0, 4).toString("hex");
  if (["linux", "freebsd", "openbsd", "netbsd", "sunos"].includes(process.platform)) {
    if (magic !== "7f454c46" || header.length < 52 || ![1, 2].includes(header[4]) || ![1, 2].includes(header[5]) || header[6] !== 1) return false;
    if (header[4] === 2 && header.length < 64) return false;
    const type = header[5] === 1 ? header.readUInt16LE(16) : header.readUInt16BE(16);
    return type === 2 || type === 3;
  }
  if (process.platform !== "darwin") return false;
  if (["feedface", "cefaedfe", "feedfacf", "cffaedfe"].includes(magic)) {
    if (header.length < (["feedfacf", "cffaedfe"].includes(magic) ? 32 : 28)) return false;
    const littleEndian = magic === "cefaedfe" || magic === "cffaedfe";
    return (littleEndian ? header.readUInt32LE(12) : header.readUInt32BE(12)) === 2;
  }
  const fat = ["cafebabe", "bebafeca", "cafebabf", "bfbafeca"].includes(magic);
  if (!fat || header.length < 8) return false;
  const littleEndian = magic === "bebafeca" || magic === "bfbafeca";
  const count = littleEndian ? header.readUInt32LE(4) : header.readUInt32BE(4);
  const entrySize = magic === "cafebabf" || magic === "bfbafeca" ? 32 : 20;
  return count > 0 && count <= Math.floor((header.length - 8) / entrySize);
}
const BASH_BUILTINS = new Set(["echo", "printf", "pwd", "cd", "pushd", "popd", "dirs", "true", "false", "test", "[", "type", "command", "builtin", "enable", "export", "set", "declare", "unset", "read", "history", "help", "alias", "unalias", "hash", ":"]);

function printfChanges(args: string[], matches: (name: string) => boolean): boolean {
  return args.some((arg, i) => arg === "-v" ? matches(args[i + 1] ?? "") : arg.startsWith("-v") && arg.length > 2 && matches(arg.slice(2)));
}

function usesShellNameref(parsed: Parsed): boolean {
  return parsed.subs.some((s) => {
    let found = false;
    unwrapCommandWrappers(s.argv, (argv, start, end) => {
      const head = basename(argv[start] ?? "");
      if (["declare", "typeset", "local"].includes(head) && argv.slice(start + 1, end).some((arg) => /^-[A-Za-z]*n/.test(arg))) found = true;
    });
    return found;
  });
}

function usesBuiltinControl(parsed: Parsed): boolean {
  return parsed.subs.some((s) => {
    let found = false;
    unwrapCommandWrappers(s.argv, (argv, start) => { if (basename(argv[start] ?? "") === "enable") found = true; });
    return found;
  });
}

function changesShellStartup(parsed: Parsed): boolean {
  const relevant = /^(?:(?:BASH_ENV|ENV|BASHOPTS|SHELLOPTS|PS4)(?:\[[^\]]*\])?(?:\+?=|$)|BASH_FUNC_.*%%=)/;
  return parsed.subs.some((s) => {
    if (s.assigns.some((assignment) => relevant.test(assignment)) || ((s.argv[0] ?? "").includes("=") && relevant.test(s.argv[0]))) return true;
    let changes = false;
    unwrapCommandWrappers(s.argv, (argv, start, end) => {
      const head = basename(argv[start] ?? "");
      if (!["env", "export", "declare", "typeset", "local", "readonly", "unset", "read", "printf"].includes(head)) return;
      const args = argv.slice(start + 1, end);
      if (["env", "export", "declare", "typeset", "local", "readonly", "unset", "read"].includes(head) && args.some((arg) => relevant.test(arg) || (head === "env" && /^--unset=(?:BASH_ENV|ENV|BASHOPTS|SHELLOPTS|PS4)$/.test(arg)))) changes = true;
      if (head === "printf" && printfChanges(args, (name) => relevant.test(name))) changes = true;
    });
    return changes;
  });
}

function changesExecutableSearch(parsed: Parsed): boolean {
  const pathVariable = /^PATH(?:\[[^\]]*\])?(?:\+?=|$)/;
  return parsed.subs.some((s) => {
    if (s.assigns.some((assignment) => pathVariable.test(assignment)) || ((s.argv[0] ?? "").includes("=") && pathVariable.test(s.argv[0]))) return true;
    let changes = false;
    unwrapCommandWrappers(s.argv, (argv, start, end) => {
      const head = basename(argv[start] ?? "");
      if (!["env", "export", "declare", "typeset", "local", "readonly", "hash", "unset", "read", "printf"].includes(head)) return;
      const args = argv.slice(start + 1, end);
      if (["export", "declare", "typeset", "local", "readonly", "env"].includes(head))
        changes ||= args.some((arg) => pathVariable.test(arg) || (head === "env" && (arg === "--unset=PATH" || /^-[^-]*i/.test(arg) || /^-S/.test(arg) || isLongOption(arg, "--ignore-environment") || isLongOption(arg, "--split-string"))));
      if (head === "hash" && args.some((arg) => /^-[^-]*p/.test(arg))) changes = true;
      if ((head === "unset" || head === "read") && args.some((arg) => pathVariable.test(arg))) changes = true;
      if (head === "printf" && printfChanges(args, (name) => pathVariable.test(name))) changes = true;
    });
    return changes;
  });
}

function enablesShellTracing(parsed: Parsed): boolean {
  return parsed.subs.some((s) => {
    const [head, ...args] = normalizeArgv(s.argv, "deny").argv;
    if (head !== "set" && !isShell(basename(head ?? ""))) return false;
    return args.some((arg, i) => /^-[^-]*x/.test(arg) || (arg === "-o" && args[i + 1] === "xtrace"));
  });
}

/** Find the nearest repository root without running Git or loading its configuration. */
export function enclosingRepository(cwd: string): string | undefined {
  for (let dir = resolve(cwd); ; dir = dirname(dir)) {
    if (existsSync(join(dir, ".git"))) return dir;
    if (dirname(dir) === dir) return undefined;
  }
}

/** Pi prepends its bin directory to PATH. Project or temporary executables must not masquerade as safe commands. */
export function inspectExecutablePath(parsed: Parsed, cwd: string, platform: NodeJS.Platform = process.platform): { risk?: string; fingerprint?: string } {
  // Git Bash may use POSIX paths and Windows executable suffixes that Node's native PATH lookup cannot reproduce.
  if (platform === "win32") {
    const risky = parsed.subs.some((s) => {
      const rawHead = s.argv[0];
      if (!rawHead) return false;
      const head = normalizeArgv(s.argv, "deny").argv[0];
      return rawHead.includes("/") || rawHead.includes("\\") || (!!head && !BASH_BUILTINS.has(head));
    });
    return risky ? { risk: "cannot verify executable lookup for an external command on Windows" } : {};
  }
  // Pi updates the first case-insensitive PATH key, but Unix shells read only the uppercase key.
  const pathKey = Object.keys(process.env).find((key) => key.toLowerCase() === "path") ?? "PATH";
  const agentDir = getAgentDir();
  const agentBin = join(agentDir, "bin");
  const piPath = process.env[pathKey] ?? "";
  const updatedPiPath = piPath.split(delimiter).filter(Boolean).includes(agentBin) ? piPath : [agentBin, piPath].filter(Boolean).join(delimiter);
  const shellPath = pathKey === "PATH" ? updatedPiPath : process.env.PATH;
  const pathEntries = shellPath?.split(delimiter) ?? [];
  const physicalCwd = realPath(cwd);
  const repos = [enclosingRepository(cwd), enclosingRepository(physicalCwd)].filter((root): root is string => root !== undefined);
  const unsafeRoots = [cwd, physicalCwd, ...repos, agentDir, realPath(agentDir), "/tmp", "/private/tmp", tmpdir(), realPath(tmpdir())];
  let probes = 0;
  let risk: string | undefined;
  const selected: unknown[] = [];
  for (const { s, a, bases, unknown } of subsWithBases(parsed, cwd)) {
    const head = a[0];
    if (!head || s.argv[0]?.includes("/") || BASH_BUILTINS.has(head)) continue;
    if (shellPath === undefined) return { risk: "cannot determine the shell executable search path" };
    if (unknown && pathEntries.some((entry) => !entry || !isAbsolute(entry))) return { risk: "cannot determine the executable search directory" };
    // egrep/fgrep can be shell wrappers that resolve grep through PATH.
    const executables = head === "egrep" || head === "fgrep" ? [head, "grep"] : [head];
    for (const executable of executables) for (const base of bases) {
      let found = false;
      for (const entry of pathEntries) {
        if (++probes > 512) return { risk: "executable search exceeds the inspection limit" };
        const candidate = join(resolve(base, entry || "."), executable);
        let st;
        try {
          accessSync(candidate, constants.X_OK);
          st = statSync(candidate);
          if (!st.isFile()) continue;
        } catch (error: any) {
          if (["ENOENT", "ENOTDIR", "EACCES"].includes(error?.code)) continue;
          return { risk: "cannot inspect the executable search path" };
        }
        const actual = realPath(candidate);
        selected.push([executable, base, candidate, actual, st.dev, st.ino, st.mode, st.nlink, st.size, st.mtimeMs, st.ctimeMs]);
        if (st.nlink > 1 && !immutableSystemExecutable(candidate, actual, st)) risk ??= "a command resolves to a hard-linked executable";
        if ([candidate, actual].some((path) => unsafeRoots.some((root) => isInside(path, root)))) risk ??= "a command resolves to a project, temporary or Pi-managed executable";
        found = true;
        break; // Bash uses the first executable it finds.
      }
      if (!found) selected.push([executable, base, null]);
    }
  }
  return { risk, fingerprint: createHash("sha256").update(JSON.stringify(selected)).digest("hex") };
}

export function executablePathRisk(parsed: Parsed, cwd: string, platform: NodeJS.Platform = process.platform): string | undefined {
  return inspectExecutablePath(parsed, cwd, platform).risk;
}

/** Pi's grep/find resolve and may download executables before running the search. */
export function inspectBuiltinSearchExecutable(tool: string, cwd: string, piVersion = piSdk.VERSION ?? ""): { risk?: string; fingerprint?: string; available?: boolean } {
  if (tool !== "grep" && tool !== "find") return {};
  if (process.platform === "win32") return { risk: "cannot verify the executable used by the built-in search tool on Windows" };
  const names = tool === "grep" ? ["rg"] : ["fd", "fdfind"];
  const local = join(AGENT_DIR, "bin", names[0]);
  const path = process.env.PATH;
  if (path === undefined) return { risk: "cannot determine the built-in search executable path" };
  const offline = process.env.PI_OFFLINE ?? "";
  const physicalCwd = realPath(cwd);
  const roots = [cwd, physicalCwd, enclosingRepository(cwd), enclosingRepository(physicalCwd), AGENT_DIR, realPath(AGENT_DIR), "/tmp", "/private/tmp", tmpdir(), realPath(tmpdir())].filter((root): root is string => !!root);
  const selected: unknown[] = [tool, local, path, offline, piVersion, process.cwd()];
  let multipleLinks = false;
  let interpreterRisk: string | undefined;
  const inspect = (candidate: string, requireExecutable: boolean): boolean => {
    try {
      if (requireExecutable) accessSync(candidate, constants.X_OK);
      const st = statSync(candidate);
      if (requireExecutable && !st.isFile()) return false;
      const actual = realPath(candidate);
      multipleLinks = st.isFile() && st.nlink > 1 && !immutableSystemExecutable(candidate, actual, st);
      selected.push([candidate, actual, st.dev, st.ino, st.mode, st.nlink, st.size, st.mtimeMs, st.ctimeMs]);
      interpreterRisk = undefined;
      if (st.isFile()) {
        try {
          const header = executablePrefix(candidate, st, 512);
          const length = header.length;
          if (length >= 2 && header[0] === 35 && header[1] === 33) {
            const end = header.indexOf(10, 2);
            if (end < 0) throw new Error("interpreter line is incomplete");
            const lineBytes = header.subarray(2, end);
            if (!isUtf8(lineBytes)) throw new Error("interpreter path is not UTF-8");
            const line = lineBytes.toString("utf8");
            const interpreter = line.match(/^[ \t]*([^ \t\r]+)(?:[ \t]|$)/)?.[1];
            if (!interpreter || line.includes("\r") || !isAbsolute(interpreter)) throw new Error("interpreter path is not verifiable");
            accessSync(interpreter, constants.X_OK);
            const interpreterStat = statSync(interpreter);
            const resolved = realPath(interpreter);
            if (!interpreterStat.isFile()) throw new Error("interpreter is not a file");
            selected.push([interpreter, resolved, interpreterStat.dev, interpreterStat.ino, interpreterStat.mode, interpreterStat.nlink, interpreterStat.size, interpreterStat.mtimeMs, interpreterStat.ctimeMs]);
            const prefix = executablePrefix(interpreter, interpreterStat, 512);
            if (prefix.length >= 2 && prefix[0] === 35 && prefix[1] === 33) interpreterRisk = "the built-in search executable uses a nested script interpreter";
            else if (!hasNativeExecutableHeader(prefix))
              interpreterRisk = "the built-in search interpreter's executable format cannot be verified";
            if (basename(resolved) === "env" || [interpreter, resolved].some((p) => roots.some((root) => isInside(p, root))) ||
                (interpreterStat.nlink > 1 && !immutableSystemExecutable(interpreter, resolved, interpreterStat)))
              interpreterRisk ??= "the built-in search executable uses an unverified interpreter";
          } else if (!hasNativeExecutableHeader(header)) interpreterRisk = "the built-in search executable's format cannot be verified";
        } catch { interpreterRisk = "cannot verify the built-in search executable's interpreter"; }
      }
      return true;
    } catch (error: any) {
      if (["ENOENT", "ENOTDIR", "EACCES"].includes(error?.code)) return false;
      throw error;
    }
  };
  try {
    let found = false;
    let risk: string | undefined;
    let probes = 0;
    const inspectCandidate = (candidate: string, relativeLookup: boolean, requireExecutable: boolean) => {
      if (!inspect(candidate, requireExecutable)) return;
      found = true;
      if (interpreterRisk) risk ??= interpreterRisk;
      else if (multipleLinks) risk ??= "the built-in search executable has multiple hard links";
      else if (relativeLookup) risk ??= "the built-in search executable resolves through a relative PATH entry";
      else if ([candidate, realPath(candidate)].some((p) => roots.some((root) => isInside(p, root))))
        risk ??= "the built-in search tool resolves to a project, temporary or Pi-managed executable";
    };
    if (existsSync(local)) {
      inspectCandidate(local, false, false);
      // Pi chooses a present managed path without probing PATH, even if it cannot run.
      if (!found) risk = "cannot inspect the Pi-managed search executable";
    }
    else for (const name of names) {
      for (const entry of path.split(delimiter)) {
        if (++probes > 512) return { risk: "built-in search executable lookup exceeds the inspection limit" };
        const next = join(resolve(process.cwd(), entry || "."), name);
        // An executable may fail to start (for example, its interpreter is missing), so Node can try later entries.
        inspectCandidate(next, !isAbsolute(entry), true);
      }
    }
    const fingerprint = createHash("sha256").update(JSON.stringify(selected)).digest("hex");
    // Pi 1.5.0 checks PI_OFFLINE before downloading a missing search tool; do not assume that for other versions.
    const offlinePreventsDownload = piVersion === "1.5.0" && ["1", "true", "yes"].includes(offline.toLowerCase());
    if (!found && !risk && !offlinePreventsDownload) risk = "the built-in search tool may download an executable";
    return { risk, fingerprint, available: found };
  } catch { return { risk: "cannot inspect the built-in search executable" }; }
}

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
const PI_CODE_MENTION = new RegExp(`[^\\s'"]*\\.pi/agent/(?:${PI_CODE_DIRS.join("|")})(?:/[^\\s'"]*)?(?=$|[\\s'"])`, "g");
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

/** Keys and string values may both carry paths or commands in tools with unknown schemas. */
function allStrings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => allStrings(x, out));
  else if (v && typeof v === "object") for (const [key, value] of Object.entries(v)) { out.push(key); allStrings(value, out); }
  return out;
}

/** Unknown tools may treat any string as a command or path; long strings exceed deterministic parsing limits. */
export function hasUninspectedToolInput(tool: string, input: unknown): boolean {
  return !BUILTIN_TOOLS.has(tool) && allStrings(input).some((value) => value.length >= 16 * 1024);
}

/** Pi's validator coerces JSON primitives for required string arguments. */
export function piString(value: unknown): string | undefined {
  if (value === null || typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) return String(value);
  return undefined;
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
      // basename/dirname/echo/printf only handle strings (wildcards they expand are counted below).
      const moves = ["cd", "pushd", "popd", "basename", "dirname", "echo", "printf"].includes(a[0]);
      for (const base of bases) {
        // Both the normalized and the raw argv: normalization drops location values (git -C x, npm --prefix x).
        // Operands after `--` are paths even when they start with `-` (`cat -- --d/../../.ssh/key`).
        const afterDashes = (xs: string[]) => (xs.includes("--") ? xs.slice(xs.indexOf("--") + 1).map((t) => (t.startsWith("-") ? `./${t}` : t)) : []);
        const explicit = !parsed.dynamic.length && !parsed.globs.length ? s.argv[0] === "rg" ? rgExplicitPaths(s.argv) : isGrepFamily(s.argv[0]) ? grepExplicitPaths(s.argv) : undefined : undefined;
        if (explicit) {
          const files = [...explicit, ...(s.argv[0] === "rg" ? optionValue(s.argv, ["--file"]) : [])].filter((path) => path !== "-");
          reads.push(...files.flatMap((path) => pathVariants(base, path.startsWith("-") ? `./${path}` : path)));
        } else if (!moves) reads.push(...pathLikeTokens(base, a.slice(1)), ...pathLikeTokens(base, s.argv.slice(1)), ...pathLikeTokens(base, afterDashes(s.argv.slice(1))));
        reads.push(...s.reads.flatMap((r) => pathVariants(base, r)));
        // Wildcards in write targets are expanded: `>> ~/.p?/a????/guard/rules.jsonl` writes to the real file
        writes.push(...[...s.writes, ...bashWriteTargets(s.argv)].flatMap((w) => [...pathVariants(base, w.startsWith("-") ? `./${w}` : w), ...(hasGlob(w) ? globTargets(base, w) : [])]));
      }
      if (!moves) for (const d of dirs) if (d !== cwd) reads.push(d);
      // diff of two directories compares (and prints) every file directly inside them, following symlinks
      if (a[0] === "diff") for (const base of bases) reads.push(...dirChildren(pathLikeTokens(base, nonFlags(a))));
      // git show REV:path and git cat-file -p REV:path print a committed file
      if (a[0] === "git") for (const t of nonFlags(a).slice(1)) { const m = /^[^:\s]*:(?!\/\/)(.+)$/.exec(t); if (m) reads.push(...pathVariants(cwd, m[1])); }
    }
    reads.push(...pathLikeTokens(cwd, [], parsed.globs));
    return { reads, writes };
  }
  if (!BUILTIN_TOOLS.has(tool)) {
    // Unknown tools: every path-like string counts, including words inside command-like strings
    const strs = allStrings(input).filter((x) => x.length < 16 * 1024);
    const words = strs.flatMap((x) => (/\s/.test(x.trim()) ? [x, ...parseShell(x).subcommands.flat()] : [x]));
    // Unknown schemas may carry a literal path with whitespace or '=' rather than a shell command.
    const literals = strs.filter((x) => !/[\r\n]/.test(x) && !/^https?:\/\//i.test(x) && (/^(?:\/|~\/|\.{1,2}\/|\$HOME\/|file:\/\/)/i.test(x) || x.includes("/")));
    const ps = [...pathLikeTokens(cwd, words), ...literals.flatMap((x) => pathVariants(cwd, x))];
    return { reads: ps, writes: ps };
  }
  const p: string[] = [];
  for (const k of ["path", "file_path", "filePath", "file", "dir", "directory"]) {
    const value = k === "path" && (tool === "write" || tool === "edit") ? piString(input?.[k]) : typeof input?.[k] === "string" ? input[k] : undefined;
    if (value === undefined) continue;
    p.push(...pathVariants(cwd, value));
    if (tool === "read") p.push(...readFallbackVariants(cwd, value));
  }
  if (tool === "edit" || tool === "write") return { reads: [], writes: p };
  return { reads: p, writes: [] };
}

/** Entries directly inside the given directories; an incomplete scan gets a sentinel. */
function dirChildren(paths: string[]): string[] {
  const out: string[] = [];
  for (const p of paths) {
    let directory: import("node:fs").Dir;
    try {
      if (!statSync(p).isDirectory()) continue;
      directory = opendirSync(p);
    } catch (error: any) {
      if (error?.code === "ENOENT" || error?.code === "ENOTDIR") continue;
      return [INCOMPLETE_DIRECTORY_COMPARISON];
    }
    try {
      for (;;) {
        const entry = directory.readSync();
        if (!entry) break;
        if (out.length >= 2000) return [INCOMPLETE_DIRECTORY_COMPARISON];
        out.push(join(p, entry.name));
      }
    } catch {
      return [INCOMPLETE_DIRECTORY_COMPARISON];
    } finally {
      try { directory.closeSync(); } catch { return [INCOMPLETE_DIRECTORY_COMPARISON]; }
    }
  }
  return out;
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
      text = readRegularText(path, 2_000_001);
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
  const unlinkOnly = tool === "bash" && !!parsed && parsed.ok && !parsed.dynamic.length && !parsed.writes.length && parsed.subcommands.length > 0 && parsed.subcommands.every((a) => ["rm", "unlink"].includes(normalizeArgv(a, "deny").argv[0]));
  for (const w of writes) {
    const r = protectedReason(w, roots);
    if (r) return `writes to a ${r}`;
    if (basename(w).toLowerCase() === "authorized_keys" || basename(realPath(w)).toLowerCase() === "authorized_keys") return "writes to authorized_keys";
    if (!unlinkOnly && isProtectedHardLink(w, roots)) return "writes through a hard link to protected state";
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
    const outerRoots = roots.filter((r) => !isInsideExact(realPath(r), realPath(cwd)));
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
      const indexOnly =
        gitSub === "add" || gitSub === "stage" || gitSub === "commit" ||
        (gitSub === "rm" && a.includes("--cached")) ||
        (gitSub === "restore" && a.some((t) => t === "--staged" || /^-[A-Za-z]*S/.test(t)) && !a.some((t) => t === "--worktree" || /^-[A-Za-z]*W/.test(t))) ||
        (gitSub === "reset" && !a.some((t) => ["--hard", "--merge", "--keep"].includes(t)));
      if (changing && !indexOnly) {
        // Raw argv too, so location values (git -C x, npm --prefix x) are seen; a copy's destination is checked above
        const named = [...new Set([...nonFlags(a), ...nonFlags(s.argv)])].filter((t) => !(PLACERS.has(a[0]) && t === nonFlags(a).at(-1)));
        // The project's own .pi/.agents are guarded by the explicit write checks; counting the project as their
        // parent would block every `git add .` or `prettier --write .` in projects that have .pi/guard.json
        const hits = (p: string) => containsProtectedRoot(p, outerRoots) || (protectedReason(p, roots) && !isInsideExact(realPath(p), realPath(cwd)));
        if (named.some((t) => bases.some((b) => globInto(b, t, outerRoots) || globAround(b, t, outerRoots) || resolveAll(b, t).some(hits))))
          return "changes guard's or pi's state, or a directory that contains it";
        // Values glued to options (-C../../.pi, -t../x, --directory=../x)
        const optionPaths = bases.flatMap((b) => pathLikeTokens(b, s.argv.slice(1).filter((t) => t.startsWith("-"))));
        if (optionPaths.some(hits)) return "changes guard's or pi's state, or a directory that contains it";
        // The project's own .pi/.agents (code pi loads): any changing command naming a path inside them
        // (git mv x .pi/extensions/, git checkout -- .pi/x, npm i --prefix .pi/extensions). Directories that merely
        // contain them (`.`, `src/..`) stay allowed.
        // Read-only commands that change files only through redirects are covered by the redirect-target checks
        const innerRoots = isReadOnlyArgv(s.argv) ? [] : roots.filter((r) => isInsideExact(realPath(r), realPath(cwd)));
        const inInner = (p: string) => !!protectedReason(p, innerRoots);
        if (named.some((t) => bases.some((b) => globInto(b, t, innerRoots) || resolveAll(b, t).some(inInner))) || optionPaths.some(inInner))
          return "changes the project's .pi/ or .agents/ (code and settings pi loads)";
        // Interpreter code naming them (python3 -c "open('.pi/extensions/e.ts','w')")
        if (INTERPRETER_NAMES.has(basename(a[0] ?? "")) && a.slice(1).some((t) => INNER_NAME.test(t) || innerRoots.some((r) => t.includes(r))))
          return "an interpreter command names the project's .pi/ or .agents/";
      }
    }
  }
  // Reading guard's or pi's state with a strictly read-only command only needs confirmation (see sensitive);
  // anything else that touches it, by path or by name (interpreters, cd + relative paths), is blocked.
  // Names in quoted text and in here-documents fed to cat (commit messages, docs) are not paths
  const lower = nameScanText(cmd, parsed).toLowerCase();
  // The project's own .pi/ is covered by the write checks above; naming it (git add .pi/x) is not a change to it
  const outer = roots.filter((r) => !isInsideExact(realPath(r), realPath(cwd)));
  const touchesProtected =
    reads.some((p) => protectedReason(p, outer)) || outer.some((r) => lower.includes(r.toLowerCase())) || PROTECTED_MARKERS.some((m) => lower.includes(m));
  if (touchesProtected && !strictlyReadOnly(parsed, writes)) return "may modify a protected path (guard rules, pi state, extensions or settings)";
  return undefined;
}

const INNER_NAME = /(?:^|[^\w.-])\.(?:pi|agents)(?:[/\\'"\s)]|$)/;

/** Commands whose operands are all files (or a search pattern), so a wildcard expanding to any name only names files. */
const GLOB_FILE_COMMANDS = new Set(["cat", "head", "tail", "wc", "ls", "grep", "egrep", "fgrep", "rg", "nl", "stat", "file", "md5sum", "sha256sum", "shasum", "du", "sort", "echo", "basename", "dirname", "realpath", "readlink"]);

const CONTENT_SEARCH = new Set(["rg", "ag", "ack", "grep", "egrep", "fgrep"]);
const isGrepFamily = (h: string) => h === "grep" || h === "egrep" || h === "fgrep";
const recursiveGrep = (args: string[]) => {
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "--") break;
    // A separate regexp value is data, even when it looks like a recursive option.
    if (t === "-e" || (isLongOption(t, "--regexp") && !t.includes("="))) { i++; continue; }
    if ((/^-[A-Za-z0-9]*[rR]/.test(t) && !t.startsWith("--")) ||
      isLongOption(t, "--recursive") || isLongOption(t, "--dereference-recursive") ||
      (isLongOption(t, "--directories") && /recurse/.test(t + (args[i + 1] ?? ""))) ||
      (t === "-d" && args[i + 1] === "recurse")) return true;
  }
  return false;
};
/**
 * What a recursive content search may print: the first secret file it would reach, and whether the search tree was
 * too large to check (then the call is not treated as safe).
 */
function searchExposure(tool: string, input: any, cwd: string, parsed?: Parsed): { hit?: string; unknown: boolean } {
  const projectRead = tool === "bash" && !!parsed && parsed.ok && !parsed.dynamic.length && !parsed.writes.length && parsed.subcommands.every(isReadOnlyArgv);
  const check = (roots0: string[], hidden: boolean, suffixes?: string[]) => {
    let unknown = false;
    for (const r of roots0) {
      const real = realPath(r);
      try {
        if (statSync(real).isFile()) {
          if (sensitiveReason(real)) return { hit: real, unknown };
          if (isHardLinked(real) && !(projectRead && isProjectHardlinkSafe(real, cwd))) unknown = true;
          continue;
        }
      } catch (error: any) {
        // A missing explicit operand causes the search tool to report an error; it does not expose file contents.
        if (error?.code !== "ENOENT" && error?.code !== "ENOTDIR") unknown = true;
        continue;
      }
      const { files, complete } = secretFilesUnder(real, projectRead && isProjectPath(real, cwd) ? cwd : undefined, suffixes, hidden);
      if (!complete) unknown = true;
      const hit = files[0];
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
  for (const { s, a, bases } of subsWithBases(parsed, cwd)) {
    const args = a.slice(1);
    const gitGrep = a[0] === "git" && a.includes("grep");
    if (!((isGrepFamily(a[0]) && recursiveGrep(args)) || a[0] === "rg" || a[0] === "ag" || a[0] === "ack" || gitGrep)) continue;
    if (rgInfoOnly(a) || rgListsFiles(a) || rgListsTypes(a)) continue;
    const explicit = !parsed.dynamic.length && !parsed.globs.length ? s.argv[0] === "rg" ? rgExplicitPaths(s.argv) : isGrepFamily(s.argv[0]) ? grepExplicitPaths(s.argv) : undefined : undefined;
    const given = explicit ? bases.flatMap((b) => explicit.filter((path) => path !== "-").flatMap((path) => pathVariants(b, path.startsWith("-") ? `./${path}` : path))) : bases.flatMap((b) => pathLikeTokens(b, nonFlags(a).slice(1)));
    // rg skips hidden files unless told otherwise, or unless an ignore file re-includes them (`!.env`)
    const roots0 = given.length ? given : bases;
    const suffixes = a[0] === "rg" && !parsed.dynamic.length && !parsed.globs.length ? rgSimpleIncludeSuffixes(a) : undefined;
    const visibility = rgVisibility(a);
    const r = check(roots0, a[0] !== "rg" || visibility.hidden || (!visibility.ignoresRules && roots0.some((x) => ignoreFilesReinclude(realPath(x), visibility.ignoresVcs, visibility.ignoresDot))), suffixes);
    if (r.hit) return r;
    unknown ||= r.unknown;
  }
  return { unknown };
}

/** True if a content search's reachable files could not be checked completely. */
export function searchNeedsJudgement(tool: string, input: any, cwd: string, parsed?: Parsed): boolean {
  return searchExposure(tool, input, cwd, parsed).unknown;
}

function shellVariableAssigned(parsed: Parsed, name: string): boolean {
  return parsed.subs.some((sub) => {
    const a = normalizeArgv(sub.argv, "deny").argv;
    const commandIndex = sub.argv.findIndex((word) => basename(word) === a[0]);
    const prefix = commandIndex > 0 ? sub.argv.slice(0, commandIndex) : [];
    const declarations = ["export", "declare", "typeset", "readonly"].includes(sub.argv[0]) ? sub.argv.slice(1) : [];
    return [...sub.assigns, ...prefix, ...declarations].some((word) => word.startsWith(`${name}=`));
  });
}

/** An ambient ripgrep config may inject options such as --pre and --follow. */
export function usesRipgrepConfig(parsed?: Parsed): boolean {
  if (!parsed) return false;
  const configured = !!process.env.RIPGREP_CONFIG_PATH || shellVariableAssigned(parsed, "RIPGREP_CONFIG_PATH");
  return configured && parsed.subcommands.some((raw) => {
    const a = normalizeArgv(raw, "deny").argv;
    return a[0] === "rg" && !rgInfoOnly(a) && !rgDisablesConfig(a);
  });
}

/** Some grep implementations still honor GREP_OPTIONS, including recursive flags. */
export function usesGrepOptions(parsed?: Parsed): boolean {
  if (!parsed || !(process.env.GREP_OPTIONS || shellVariableAssigned(parsed, "GREP_OPTIONS"))) return false;
  return parsed.subcommands.some((raw) => ["grep", "egrep", "fgrep"].includes(normalizeArgv(raw, "deny").argv[0]));
}

export function sensitive(tool: string, input: any, cwd: string, roots: string[], parsed?: Parsed): string | undefined {
  if (tool === "bash" && (process.env.BASH_ENV || process.env.ENV || process.env.BASHOPTS || process.env.SHELLOPTS || Object.keys(process.env).some((key) => key.startsWith("BASH_FUNC_") && key.endsWith("%%"))))
    return "shell startup settings, options or imported functions may run code or alter parsing";
  if (tool === "bash" && parsed && changesShellStartup(parsed))
    return "the command changes shell startup or tracing settings";
  if (tool === "bash" && parsed && usesShellNameref(parsed))
    return "indirect shell variable references may change execution settings";
  if (tool === "bash" && parsed && usesBuiltinControl(parsed))
    return "shell builtin controls may change command resolution or load code";
  if (tool === "bash" && parsed && changesExecutableSearch(parsed))
    return "the command changes executable search paths or command lookup";
  if (tool === "bash" && parsed && enablesShellTracing(parsed))
    return "shell tracing may run PS4 expansions or expose command data";
  if (tool === "bash" && parsed) {
    const executableRisk = executablePathRisk(parsed, cwd);
    if (executableRisk) return executableRisk;
  }
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  const projectRead = tool === "bash" && !!parsed && parsed.ok && !parsed.dynamic.length && !parsed.writes.length && parsed.subcommands.every(isReadOnlyArgv);
  if (reads.includes(INCOMPLETE_DIRECTORY_COMPARISON)) return "directory comparison could not be inspected completely";
  if (reads.includes(UNKNOWN_PATH)) return "some wildcard read paths could not be inspected completely";
  // The project's own .pi/ holds project files (prompts, guard.json); reading them is fine
  const outerRoots = roots.filter((r) => !isInsideExact(realPath(r), realPath(cwd)));
  for (const p of [...reads, ...writes]) {
    const r = sensitiveReason(p);
    if (r) return r;
    if (protectedReason(p, outerRoots) && !(isPiCodePath(p) && !writes.includes(p))) return "reads guard or pi internal state";
    if (isHardLinked(p) && !(projectRead && !writes.includes(p) && isProjectHardlinkSafe(p, cwd))) return "a hard-linked file may share contents with a path outside the project";
  }
  // pi's grep tool searches hidden files recursively
  if (tool === "grep" && reads.concat(reads.length ? [] : [cwd]).some((p) => isHomeOrAncestor(p) || isHomeOrAncestor(realPath(p)))) return "searches file contents across the home directory";
  // Recursive content searches print matching lines of every file they reach, including .env files and keys
  const exposure = searchExposure(tool, input, cwd, parsed);
  if (exposure.hit) return `the search would include ${exposure.hit}`;
  if (tool === "bash" && parsed) {
    const cmd = String(input?.command ?? "");
    // Static commands are matched without quoted text (echo '.env' >> .gitignore names no file)
    const envScan = parsed.ok && !parsed.dynamic.length ? stripQuoted(cmd) : cmd;
    const inspectedSearchOnly = parsed.ok && !parsed.dynamic.length && !parsed.globs.length && parsed.subs.length > 0 && parsed.subs.every((sub) =>
      !sub.assigns.length && !sub.heredocs.length && (sub.argv[0] === "rg" ? rgExplicitPaths(sub.argv) !== undefined : isGrepFamily(sub.argv[0]) && grepExplicitPaths(sub.argv) !== undefined));
    if (!inspectedSearchOnly && /(?:^|[\s"'/:])\.env(?:\.[\w.-]+)?(?=$|[\s"';|&])/.test(envScan) && !/\.env\.(?:example|sample|template)/.test(envScan)) return ".env file";
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
    // Mentions of pi's code directories (~/.pi/agent/install/…, git/…, without `..`) are not its internal state; the paths
    // themselves were resolved and checked above
    const lower = nameScanText(cmd, parsed).toLowerCase().replace(PI_CODE_MENTION, (w) => (w.includes("..") ? w : ""));
    if (PROTECTED_MARKERS.some((m) => lower.includes(m))) return "reads guard or pi internal state";
    for (const [si, raw] of parsed.subcommands.entries()) {
      // `env` alone prints the environment; it is only a wrapper when a command follows
      const rawHead = basename(raw[0] ?? "");
      if ((rawHead === "env" || rawHead === "printenv") && raw.slice(1).every((t) => t.startsWith("-") || /^[A-Za-z_]\w*=/.test(t))) return "prints all environment variables";
      const { argv: a } = normalizeArgv(raw, "deny");
      const head = a[0];
      const args = a.slice(1);
      if ((head === "export" && (args.length === 0 || args.includes("-p"))) || (head === "set" && args.length === 0) || (head === "declare" && args.some((t) => /^-[a-z]*[xp]/.test(t)))) return "prints the environment";
      if (head === "jq" && args.some((t) => t.includes("$ENV") || /\benv\b/.test(t))) return "reads environment variables";
      if ((head === "jq" || head === "ps") && parsed.subs[si]?.globArgs?.length) return "a wildcard argument may make it print environment variables";
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

export function safeAllow(tool: string, input: any, cwd: string, opts: { trusted: boolean; touched: Set<string>; trustedDirs?: TrustedDirState }, parsed?: Parsed): boolean {
  if (tool === "bash") {
    if (!parsed || !parsed.ok || parsed.dynamic.length || parsed.writes.length || !parsed.subcommands.length) return false;
    if (usesRipgrepConfig(parsed) || usesGrepOptions(parsed)) return false;
    // Glued option values (-f/etc/x, -bf~/x) are easy to misread; such commands always get a judgement.
    // So are words that start with `-` and contain a path (`-- --d/../../x`, `--x/y`).
    if (parsed.subcommands.some(hasGluedPathValue)) return false;
    if (parsed.subcommands.some((x) => x.slice(1).some((t) => t.startsWith("-") && t.includes("/")))) return false;
    // A wildcard that expands to a word like `--pre=sh` hands the command an option. Wildcards after cd/pushd
    // expand somewhere guard would have to re-derive, so that combination is never a shortcut
    if (parsed.globs.length && parsed.subcommands.some((x) => ["cd", "pushd", "popd"].includes(normalizeArgv(x).argv[0]))) return false;
    if (parsed.globs.some((g) => globHitsOptionLikeName(cwd, g))) return false;
    // Wildcards expand to file names the agent can choose (`touch 'y[$(sh<p)]'` then `[ -v y* ]`), so they are only a
    // shortcut where every operand is a file anyway; elsewhere a name can become a program, a format or a subscript
    if (parsed.subs.some((x) => x.globArgs?.length && !GLOB_FILE_COMMANDS.has(normalizeArgv(x.argv).argv[0]))) return false;
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
    if (creates && !writesStayPlain(tool, input, cwd, parsed, opts.trustedDirs)) return false;
    // Only reads inside the project or in public system directories happen without asking
    if (!inputPaths(tool, input, cwd, parsed).reads.every((p) => isFreelyReadable(p, cwd, opts.trustedDirs) || (!creates && isProjectHardlinkSafe(p, cwd)))) return false;
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
    const realCwd = realPath(cwd);
    return writes.every((w) => {
      const r = realPath(w);
      if (isHardLinked(w)) return false;
      // Folders another extension vouched for (guard:trust-dir) take plain edits like the project
      const td = trustedDirFor(w, true, opts.trustedDirs);
      if (td) return plainInTrustedDir(w, td, opts.trustedDirs);
      // When pi runs in ~ (or above), "the project" would be the whole home directory
      if (isHomeOrAncestor(cwd)) return false;
      // Symlinks that leave the project (docs/notes.md -> ~/.bashrc) are not plain project edits
      if (!isInsideExact(r, realCwd) || r.toLowerCase() === realCwd.toLowerCase()) return false;
      const lexicalBase = isInsideExact(w, cwd) ? cwd : realCwd;
      return !isRiskyProjectFile(relative(realCwd, r)) && !isRiskyProjectFile(relative(lexicalBase, w));
    });
  }
  return false;
}

/** True if every write target stays inside the project and avoids files that tools run later. */
/** True if every path the call names (read or written) is inside the project. */
export function pathsStayInProject(tool: string, input: any, cwd: string, parsed?: Parsed): boolean {
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  const realCwd = realPath(cwd);
  return !isHomeOrAncestor(cwd) && [...reads, ...writes].every((p) => isInsideExact(realPath(p), realCwd));
}

function plainInTrustedDir(w: string, dir: TrustedDir, state?: TrustedDirState): boolean {
  const r = realPath(w);
  const realDir = realPath(dir.path);
  const lexicalPath = trustedDirRelative(w, dir, state);
  return lexicalPath !== undefined && isInsideExact(r, realDir) && r.toLowerCase() !== realDir.toLowerCase() && !isRiskyProjectFile(relative(realDir, r)) && !isRiskyProjectFile(lexicalPath);
}

export function writesStayPlain(tool: string, input: any, cwd: string, parsed?: Parsed, state?: TrustedDirState): boolean {
  const { writes } = inputPaths(tool, input, cwd, parsed);
  // A hard-linked file may be the same file as something outside the project
  if (writes.some(isHardLinked)) return false;
  const realCwd = realPath(cwd);
  return writes.every((w) => {
    const r = realPath(w);
    const trusted = trustedDirFor(w, true, state);
    if (trusted) return plainInTrustedDir(w, trusted, state);
    return !isHomeOrAncestor(cwd) && isInsideExact(r, realCwd) && r.toLowerCase() !== realCwd.toLowerCase() && !isRiskyProjectFile(r.slice(realCwd.length + 1));
  });
}
