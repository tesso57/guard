/**
 * A conservative shell splitter.
 * It is not a full parser: it only decides whether rules and the safe list can be applied safely.
 * Anything dynamic (command substitution, variable expansion, interpreters, control flow, ...) is recorded in
 * `dynamic`, and callers then skip allow rules and the safe list and send the call to the model instead.
 */
import { basename } from "node:path";

type Sub = {
  argv: string[];
  /** Targets of output redirects (>, >>, >|, &>, >&file, <>). */
  writes: string[];
  /** Targets of input redirects (<). */
  reads: string[];
};

export type Parsed = {
  /** Tokenizing succeeded (quotes closed, no dangling redirect). */
  ok: boolean;
  /** Subcommands split on && || ; | & and newlines, without leading VAR=..., reserved words, or redirects. */
  subs: Sub[];
  /** argv of every subcommand (same order as subs). */
  subcommands: string[][];
  /** All output redirect targets, except /dev/null and friends. */
  writes: string[];
  /** Tokens that contain unquoted glob characters (* ? [). */
  globs: string[];
  /** Why the command is dynamic. Empty means static. */
  dynamic: string[];
};

/** If argv[0] is one of these, the arguments can be arbitrary code, so rules are never applied. */
const INTERPRETERS = new Set([
  "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
  "python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php", "lua", "awk", "gawk",
  "eval", "exec", "source", ".", "sudo", "su", "doas", "env", "xargs", "nohup", "time", "timeout",
  "nice", "watch", "command", "builtin", "osascript", "pwsh", "powershell", "parallel", "script", "stdbuf",
]);
/** Shell keywords that may lead a subcommand (`if x; then git push; fi`). */
const RESERVED = new Set(["then", "do", "else", "elif", "if", "while", "until", "!", "{", "}", "fi", "done", "esac", "time"]);
const HARMLESS_DEVICES = /^\/dev\/(null|stdout|stderr|tty|fd\/[0-2])$/;

const UNUSUAL_CHAR = new RegExp("[\\u0000-\\u0008\\u000b-\\u001f\\u007f\\u00a0\\u1680\\u2000-\\u200f\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]");

export function parseShell(cmd: string): Parsed {
  const dynamic: string[] = [];
  const globs: string[] = [];
  const subs: Sub[] = [];
  let cur: Sub = { argv: [], writes: [], reads: [] };
  let tok = "";
  let inTok = false;
  let globbed = false;
  let quote: "'" | '"' | null = null;
  let pendingRedirect: "write" | "read" | null = null;

  const endTok = () => {
    if (!inTok) return;
    if (pendingRedirect === "write") cur.writes.push(tok);
    else if (pendingRedirect === "read") cur.reads.push(tok);
    else cur.argv.push(tok);
    if (globbed && tok !== "[" && tok !== "]") globs.push(tok);
    pendingRedirect = null;
    tok = "";
    inTok = false;
    globbed = false;
  };
  const endCmd = () => {
    endTok();
    if (cur.argv.length || cur.writes.length || cur.reads.length) subs.push(cur);
    cur = { argv: [], writes: [], reads: [] };
  };
  const dyn = (why: string) => {
    if (!dynamic.includes(why)) dynamic.push(why);
  };

  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    const n = cmd[i + 1];
    if (quote === "'") {
      if (c === "'") quote = null;
      else tok += c;
      continue;
    }
    if (c === "\\") {
      if (n === undefined) break;
      if (n !== "\n") tok += n;
      inTok = true;
      i++;
      continue;
    }
    if (c === "$") {
      if (n === "(") dyn("command substitution $()");
      else if (n === "{" || (n && /[A-Za-z_0-9@*#?!$-]/.test(n))) dyn("variable expansion");
      else if (n === "'" || n === '"') dyn("ANSI-C / locale quoting");
      tok += c;
      inTok = true;
      continue;
    }
    if (c === "`") {
      dyn("command substitution ``");
      tok += c;
      inTok = true;
      continue;
    }
    if (quote === '"') {
      if (c === '"') quote = null;
      else tok += c;
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      inTok = true;
      continue;
    }
    if (c === "#" && !inTok) {
      while (i < cmd.length && cmd[i] !== "\n") i++;
      endCmd();
      continue;
    }
    if (c === " " || c === "\t") {
      endTok();
      continue;
    }
    if (c === "\n" || c === ";") {
      endCmd();
      continue;
    }
    if (c === "&" || c === "|") {
      if (c === "&" && n === ">") {
        // &> file and &>> file
        endTok();
        i += cmd[i + 2] === ">" ? 2 : 1;
        pendingRedirect = "write";
        continue;
      }
      endCmd();
      if (n === c || (c === "|" && n === "&")) i++;
      continue;
    }
    if ((c === "<" || c === ">") && n === "(") {
      dyn("process substitution");
      endCmd();
      continue;
    }
    if (c === "<") {
      if (inTok && /^\d+$/.test(tok)) { tok = ""; inTok = false; }
      endTok();
      if (n === "<") {
        dyn("heredoc / herestring");
        i++;
        if (cmd[i + 1] === "<") i++;
        pendingRedirect = "read";
        continue;
      }
      if (n === "&") {
        // <&3 duplicates an input descriptor
        i++;
        const m = /^(\d+|-)/.exec(cmd.slice(i + 1));
        if (m) i += m[0].length;
        continue;
      }
      if (n === ">") {
        // <> opens the file for reading and writing
        i++;
        pendingRedirect = "write";
        continue;
      }
      pendingRedirect = "read";
      continue;
    }
    if (c === ">") {
      if (inTok && /^\d+$/.test(tok)) { tok = ""; inTok = false; }
      endTok();
      if (n === ">" || n === "|") i++;
      if (cmd[i + 1] === "&") {
        i++;
        // >&2, >&- and 2>&1 duplicate descriptors; any other word (>&file) is a file that receives stdout and stderr
        const m = /^(\d+|-)(?=$|[\s;&|<>()])/.exec(cmd.slice(i + 1));
        if (m) {
          i += m[0].length;
          continue;
        }
      }
      pendingRedirect = "write";
      continue;
    }
    if (c === "(" || c === ")") {
      dyn("subshell / grouping");
      endCmd();
      continue;
    }
    if (c === "{" && !inTok && (n === " " || n === "\n")) {
      dyn("subshell / grouping");
      continue;
    }
    if (c === "{") {
      const close = cmd.indexOf("}", i);
      if (close > i && /,|\.\./.test(cmd.slice(i, close))) dyn("brace expansion");
    }
    if (c === "*" || c === "?" || c === "[") globbed = true;
    // Non-ASCII whitespace and control characters can hide tokens from a human reviewer
    if (UNUSUAL_CHAR.test(c)) dyn("unusual whitespace or control character");
    tok += c;
    inTok = true;
  }
  endTok();
  const ok = quote === null && pendingRedirect === null;
  endCmd();

  for (const s of subs) {
    const a = s.argv;
    for (;;) {
      // A leading VAR=value can change what the command does (PATH=..., GIT_SSH_COMMAND=..., ...)
      if (a.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(a[0])) {
        a.shift();
        dyn("environment assignment prefix");
      } else if (a.length && RESERVED.has(a[0])) a.shift();
      else break;
    }
    const head = a[0];
    if (!head) continue;
    const base = basename(head);
    const versionQuery = a.length === 2 && /^(--version|-V|-v|--help|-h)$/.test(a[1]);
    if (["for", "case", "select", "function", "coproc"].includes(base) || /\(\)$/.test(head)) dyn("control flow or function definition");
    else if (INTERPRETERS.has(base) && !versionQuery && !(base === "command" && /^-[vV]$/.test(a[1] ?? ""))) dyn(`interpreter or wrapper: ${base}`);
    if (head.includes("/")) dyn("command given by path");
    if (base === "find" && a.some((t) => /^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/.test(t))) dyn("find action that runs or writes");
    if (base === "git" && a.some((t, i) => i > 0 && (t === "-c" || t.startsWith("--config") || t === "--exec-path" || t.startsWith("--exec-path=")))) dyn("git config override");
  }
  const kept = subs.filter((s) => s.argv.length || s.writes.length || s.reads.length);
  for (const s of kept) s.writes = s.writes.filter((w) => !HARMLESS_DEVICES.test(w));
  return { ok, subs: kept, subcommands: kept.map((s) => s.argv), writes: kept.flatMap((s) => s.writes), globs, dynamic };
}

/** Options of multi-command tools. `location` options change which project the command acts on. */
const GLOBAL_OPTIONS: Record<string, { flags: string[]; withValue: string[]; location: string[] }> = {
  git: { flags: ["--no-pager", "-P", "-p", "--paginate", "--no-optional-locks", "--literal-pathspecs", "--no-replace-objects"], withValue: [], location: ["-C", "--git-dir", "--work-tree", "-c"] },
  npm: { flags: ["--silent", "-s", "--quiet", "-q", "--no-color"], withValue: ["-w", "--workspace"], location: ["--prefix", "-C"] },
  pnpm: { flags: ["--silent", "-s", "-r", "--recursive"], withValue: ["--filter", "-F"], location: ["-C", "--dir"] },
  yarn: { flags: ["--silent", "-s"], withValue: [], location: ["--cwd"] },
  bun: { flags: ["--silent"], withValue: [], location: ["--cwd"] },
  cargo: { flags: ["-q", "--quiet", "-v", "--verbose", "--locked", "--frozen", "--offline"], withValue: [], location: ["--manifest-path", "-Z", "--config"] },
};

/** Wrappers that run another command, and their options that take a value. */
const WRAPPERS: Record<string, string[]> = {
  timeout: ["-s", "--signal", "-k", "--kill-after"],
  env: ["-u", "--unset", "-C", "--chdir", "-S", "--split-string"],
  sudo: ["-u", "-g", "-h", "-p", "-U", "-C", "-D", "-r", "-t"],
  doas: ["-u", "-C"],
  nohup: [],
  command: [],
  builtin: [],
  exec: ["-a"],
  nice: ["-n", "--adjustment"],
  time: ["-f", "--format", "-o", "--output"],
  stdbuf: ["-i", "-o", "-e"],
  xargs: ["-I", "-i", "-n", "-P", "-L", "-l", "-s", "-d", "-E", "-a", "--arg-file", "--delimiter", "--max-args", "--max-procs"],
};

/**
 * Normalizes argv for matching: basename of the command, without leading global options.
 *
 * mode "allow": location options (git -C, npm --prefix, yarn --cwd, ...) are NOT stripped and set unknownOption,
 *   because a rule approved for this project must not run another project's scripts.
 * mode "deny": wrappers (timeout, env, sudo, xargs, ...) and all global options including their values are stripped,
 *   so `timeout 9 git -C x -c k=v push` is seen as `git push`.
 */
export function normalizeArgv(a: string[], mode: "allow" | "deny" = "allow"): { argv: string[]; unknownOption: boolean } {
  let rest = [...a];
  if (mode === "deny") {
    for (;;) {
      const w = WRAPPERS[basename(rest[0] ?? "")];
      if (!w) break;
      const head = basename(rest.shift()!);
      while (rest.length && (rest[0].startsWith("-") || (head === "env" && /^[A-Za-z_]\w*=/.test(rest[0])))) {
        const t = rest.shift()!;
        if (w.includes(t)) rest.shift();
      }
      if (head === "timeout" && rest.length) rest.shift(); // the duration
    }
  }
  if (!rest.length) return { argv: [], unknownOption: false };
  const head = basename(rest[0]);
  rest = rest.slice(1);
  const g = GLOBAL_OPTIONS[head];
  let unknownOption = false;
  if (g) {
    while (rest.length) {
      const t = rest[0];
      const eq = t.indexOf("=");
      const name = eq > 0 ? t.slice(0, eq) : t;
      if (g.flags.includes(t)) { rest.shift(); continue; }
      const isLocation = g.location.includes(name);
      if (g.withValue.includes(name) || (isLocation && mode === "deny")) {
        rest.splice(0, eq > 0 ? 1 : 2);
        continue;
      }
      if (head === "cargo" && t.startsWith("+")) { rest.shift(); continue; }
      if (t.startsWith("-")) unknownOption = true;
      break;
    }
  }
  return { argv: [head, ...rest], unknownOption };
}

export const nonFlags = (a: string[]) => a.slice(1).filter((t) => !t.startsWith("-"));
const flags = (a: string[]) => a.slice(1).filter((t) => t.startsWith("-"));
/** True if a short-option cluster such as `-uo` contains the letter. */
const hasShort = (a: string[], letter: string) => flags(a).some((t) => !t.startsWith("--") && t.slice(1).includes(letter));
const hasLong = (a: string[], ...names: string[]) => flags(a).some((t) => names.some((n) => t === n || t.startsWith(`${n}=`)));
const onlyFlagsFrom = (a: string[], allowed: string[]) => a.slice(2).every((t) => allowed.includes(t));

const READ_ONLY = new Set([
  "ls", "pwd", "echo", "printf", "cat", "head", "tail", "wc", "which", "whoami", "uname", "stat", "cd", "pushd", "popd",
  "du", "df", "grep", "egrep", "fgrep", "cut", "tr", "basename", "dirname", "realpath", "readlink", "ps", "less", "more",
  "true", "false", "test", "[", "nl", "column", "diff", "cmp", "comm", "id", "groups", "jq", "type", "file", "md5sum", "sha256sum", "shasum",
]);
const GIT_READ_ONLY = new Set(["status", "diff", "log", "show", "blame", "ls-files", "rev-parse", "describe", "shortlog", "grep", "ls-tree", "cat-file", "reflog"]);
const NPM_READ_ONLY = new Set(["ls", "list", "view", "outdated", "explain", "why", "config"]);

/**
 * True only if the command cannot write files, run other programs, or change system state,
 * judging by its name AND its options. Path sensitivity and git config safety are checked separately.
 */
export function isReadOnlyArgv(raw: string[]): boolean {
  const { argv: a, unknownOption } = normalizeArgv(raw);
  const head = a[0];
  if (!head) return true;
  if (a.length === 2 && /^(--version|-V|--help)$/.test(a[1])) return true;
  switch (head) {
    case "sort":
      return !hasShort(a, "o") && !hasLong(a, "--output", "--compress-program");
    case "uniq":
      return nonFlags(a).length <= 1;
    case "tree":
      return !hasShort(a, "o") && !hasLong(a, "--output");
    case "find":
      return !a.some((t) => /^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/.test(t));
    case "rg":
      return !hasLong(a, "--pre", "--pre-glob");
    case "fd":
    case "fdfind":
      return !hasShort(a, "x") && !hasShort(a, "X") && !hasLong(a, "--exec", "--exec-batch");
    case "file":
      return !hasShort(a, "C") && !hasLong(a, "--compile");
    case "sed": {
      // Only printing line ranges (`sed -n 1,80p f`); other scripts can write files (w) or run commands (e)
      if (!a.slice(1).every((t) => !t.startsWith("-") || t === "-n" || t === "-E" || t === "-r")) return false;
      const script = nonFlags(a)[0] ?? "";
      return /^(\d+|\$)(,(\d+|\$))?p$/.test(script);
    }
    case "date": {
      // `date MMDDhhmm` and `date -s` set the clock; only +FORMAT and values of -d/-r/-f are allowed
      if (hasShort(a, "s") || hasLong(a, "--set")) return false;
      for (let i = 1; i < a.length; i++) {
        const t = a[i];
        if (t.startsWith("-")) {
          if (["-d", "--date", "-r", "--reference", "-f", "--file"].includes(t)) i++;
          continue;
        }
        if (!t.startsWith("+")) return false;
      }
      return true;
    }
    case "hostname":
      return nonFlags(a).length === 0 && !hasShort(a, "F") && !hasShort(a, "b") && !hasLong(a, "--file", "--boot");
    case "npm":
      return !unknownOption && NPM_READ_ONLY.has(a[1] ?? "") && (a[1] !== "config" || ["get", "list", "ls"].includes(a[2] ?? ""));
    case "git": {
      if (unknownOption) return false;
      const sub = a[1];
      if (sub === "branch") return onlyFlagsFrom(a, ["-a", "-r", "-v", "-vv", "--all", "--remotes", "--list", "--show-current", "--verbose"]);
      if (sub === "remote") return onlyFlagsFrom(a, ["-v", "--verbose"]);
      if (sub === "tag") return onlyFlagsFrom(a, ["-l", "--list"]);
      if (sub === "stash") return a[2] === "list" && a.length <= 4;
      if (sub === "config") return ["--get", "--get-all", "--list", "-l"].includes(a[2] ?? "") && !hasLong(a, "--global", "--system", "--file");
      if (!sub || !GIT_READ_ONLY.has(sub)) return false;
      // --output writes files; ext-diff, textconv and open-files-in-pager can run configured programs
      return !hasLong(a, "--output", "--ext-diff", "--textconv", "--open-files-in-pager", "--exec", "--upload-pack") && !(sub === "grep" && hasShort(a, "O"));
    }
  }
  return READ_ONLY.has(head);
}
