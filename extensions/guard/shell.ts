/**
 * A conservative shell splitter.
 * It is not a full parser: it only decides whether rules and the safe list can be applied safely.
 * Anything dynamic (command substitution, variable expansion, interpreters, control flow, ...) is recorded in
 * `dynamic`, and callers then skip allow rules and the safe list and send the call to the model instead.
 */
import { basename } from "node:path";

type Sub = {
  argv: string[];
  /** Leading VAR=value assignments (removed from argv). */
  assigns: string[];
  /** Targets of output redirects (>, >>, >|, &>, >&file, <>). */
  writes: string[];
  /** Targets of input redirects (<). */
  reads: string[];
  /** Bodies of here-documents fed to this command's stdin. */
  heredocs: string[];
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
export const INTERPRETER_NAMES = new Set(["python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php", "lua", "awk", "gawk", "osascript", "pwsh", "powershell"]);
const INTERPRETERS = new Set([
  "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
  "python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php", "lua", "awk", "gawk",
  "eval", "exec", "source", ".", "sudo", "su", "doas", "env", "xargs", "nohup", "time", "timeout",
  "nice", "watch", "command", "builtin", "osascript", "pwsh", "powershell", "parallel", "script", "stdbuf",
  "npx", "bunx", "pnpx", "uvx", "busybox", "strace", "ltrace", "setsid", "ionice", "chrt", "taskset", "flock", "unbuffer",
]);
/** Shell keywords that may lead a subcommand (`if x; then git push; fi`). */
const RESERVED = new Set(["then", "do", "else", "elif", "if", "while", "until", "!", "{", "}", "fi", "done", "esac", "time"]);
const HARMLESS_DEVICES = /^\/dev\/(null|stdout|stderr|tty|fd\/[0-2])$/;

const UNUSUAL_CHAR = new RegExp("[\\u0000-\\u0008\\u000b-\\u001f\\u007f\\u00a0\\u1680\\u2000-\\u200f\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]");

/** Longer commands are not analyzed (they go to the model), which also bounds the parser's work. */
const MAX_COMMAND = 16 * 1024;
const FD_DUP = /(\d+|-)(?=$|[\s;&|<>()])/y;
const FD_DIGITS = /(\d+|-)/y;

export function parseShell(cmd: string): Parsed {
  if (cmd.length > MAX_COMMAND) return { ok: false, subs: [], subcommands: [], writes: [], globs: [], dynamic: ["command too long to analyze"] };
  const dynamic: string[] = [];
  const globs: string[] = [];
  const subs: Sub[] = [];
  let cur: Sub = { argv: [], assigns: [], writes: [], reads: [], heredocs: [] };
  /** Here-documents whose bodies start after the current line. */
  const pendingDocs: { sub: Sub; delim: string; stripTabs: boolean; quoted: boolean }[] = [];
  let tok = "";
  let inTok = false;
  let globbed = false;
  let tildeStart = false;
  let quote: "'" | '"' | null = null;
  let pendingRedirect: "write" | "read" | "data" | null = null;

  const endTok = () => {
    if (!inTok) return;
    if (pendingRedirect === "write") cur.writes.push(tok);
    else if (pendingRedirect === "read") cur.reads.push(tok);
    else if (pendingRedirect === "data") {
      /* here-string word: data, not a path */
    }
    else cur.argv.push(tok);
    if (globbed && tok !== "[" && tok !== "]") globs.push(tok);
    // ~user, ~+ and ~- are expanded by the shell to other directories
    if (tildeStart && !/^~(\/|$)/.test(tok)) dyn("tilde expansion");
    pendingRedirect = null;
    tok = "";
    inTok = false;
    globbed = false;
    tildeStart = false;
  };
  const endCmd = () => {
    endTok();
    if (cur.argv.length || cur.writes.length || cur.reads.length) subs.push(cur);
    cur = { argv: [], assigns: [], writes: [], reads: [], heredocs: [] };
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
      // Skip to just before the newline, so the newline branch ends the command and reads pending here-documents
      const nl = cmd.indexOf("\n", i);
      i = (nl === -1 ? cmd.length : nl) - 1;
      continue;
    }
    if (c === " " || c === "\t") {
      endTok();
      continue;
    }
    if (c === "\n" || c === ";") {
      endCmd();
      if (c === "\n" && pendingDocs.length) {
        // Here-document bodies follow the line that opened them; they are data for the command, not words
        let pos = i + 1;
        for (const d of pendingDocs.splice(0)) {
          const lines: string[] = [];
          let closed = false;
          while (pos <= cmd.length) {
            const nl = cmd.indexOf("\n", pos);
            const end = nl === -1 ? cmd.length : nl;
            const line = cmd.slice(pos, end);
            pos = end + 1;
            if ((d.stripTabs ? line.replace(/^\t+/, "") : line) === d.delim) {
              closed = true;
              break;
            }
            lines.push(line);
            if (nl === -1) break;
          }
          const body = lines.join("\n");
          d.sub.heredocs.push(body);
          if (!closed) dyn("unterminated here-document");
          if (!d.quoted && /[$`]/.test(body)) dyn("expansion inside a here-document");
        }
        i = pos - 1;
      }
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
      if (n === "<" && cmd[i + 2] === "<") {
        // <<< word: a here-string, the word is data
        i += 2;
        pendingRedirect = "data";
        continue;
      }
      if (n === "<") {
        // << DELIM or <<- DELIM: the body is read after the end of this line
        i++;
        let stripTabs = false;
        if (cmd[i + 1] === "-") {
          stripTabs = true;
          i++;
        }
        while (cmd[i + 1] === " " || cmd[i + 1] === "\t") i++;
        let delim = "";
        let quoted = false;
        while (i + 1 < cmd.length && !/[\s;&|<>()]/.test(cmd[i + 1])) {
          const ch = cmd[++i];
          if (ch === "'" || ch === '"' || ch === "\\") quoted = true;
          else delim += ch;
        }
        if (!delim) dyn("malformed here-document");
        pendingDocs.push({ sub: cur, delim, stripTabs, quoted });
        continue;
      }
      if (n === "&") {
        // <&3 duplicates an input descriptor
        i++;
        FD_DIGITS.lastIndex = i + 1;
        const m = FD_DIGITS.exec(cmd);
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
        FD_DUP.lastIndex = i + 1;
        const m = FD_DUP.exec(cmd);
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
      if (close > i && /,|\.\./.test(cmd.slice(i, Math.min(close, i + 512)))) dyn("brace expansion");
    }
    if (c === "~" && !inTok) tildeStart = true;
    if (c === "*" || c === "?" || c === "[") globbed = true;
    // Non-ASCII whitespace and control characters can hide tokens from a human reviewer
    if (UNUSUAL_CHAR.test(c)) dyn("unusual whitespace or control character");
    tok += c;
    inTok = true;
  }
  endTok();
  if (pendingDocs.length) dyn("unterminated here-document");
  const ok = quote === null && pendingRedirect === null;
  endCmd();

  for (const s of subs) {
    const a = s.argv;
    for (;;) {
      // A leading VAR=value (or VAR+=value) can change what the command does (PATH=..., GIT_SSH_COMMAND=..., ...)
      if (a.length && /^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(a[0])) {
        s.assigns.push(a.shift()!);
        dyn("environment assignment prefix");
      } else if (a.length && RESERVED.has(a[0])) {
        // `time -p cmd` and `time -- cmd`: the options belong to the keyword
        const kw = a.shift();
        while (kw === "time" && (a[0] === "-p" || a[0] === "--")) a.shift();
      } else break;
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
  // Bare assignments (`HOME=x;`) are kept: they change what later commands mean
  const kept = subs.filter((s) => s.argv.length || s.assigns.length || s.writes.length || s.reads.length);
  if (kept.length > 128) dyn("too many subcommands to analyze");
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
  eval: [],
  setsid: [],
  unbuffer: [],
  ionice: ["-c", "-n", "-p", "-t"],
  chrt: [],
  taskset: [],
  flock: ["-w", "--timeout", "-E", "--conflict-exit-code"],
  strace: ["-o", "-e", "-p", "-s", "-u", "-E", "-P", "-I", "-b"],
  ltrace: ["-o", "-e", "-p", "-s", "-u", "-n"],
  busybox: [],
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
      const name = basename(rest[0] ?? "");
      const w = Object.hasOwn(WRAPPERS, name) ? WRAPPERS[name] : undefined;
      if (!w) break;
      const head = basename(rest.shift()!);
      while (rest.length && (rest[0].startsWith("-") || (head === "env" && /^[A-Za-z_]\w*=/.test(rest[0])))) {
        const t = rest.shift()!;
        if (w.includes(t)) rest.shift();
      }
      // Wrappers with a positional argument before the command (duration, priority, CPU mask, lock file)
      if (["timeout", "chrt", "taskset", "flock"].includes(head) && rest.length) rest.shift();
    }
  }
  if (!rest.length) return { argv: [], unknownOption: false };
  const head = basename(rest[0]);
  rest = rest.slice(1);
  const g = Object.hasOwn(GLOBAL_OPTIONS, head) ? GLOBAL_OPTIONS[head] : undefined;
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
  // A location option anywhere (`npm test --prefix /tmp/x`, `make test -C ../x`) makes the call act on another project
  if (
    mode === "allow" &&
    Object.hasOwn(LOCATION_ANYWHERE, head) &&
    rest.some((t) =>
      LOCATION_ANYWHERE[head].some(
        (o) =>
          t === o ||
          t.startsWith(`${o}=`) ||
          (o.startsWith("--") && isLongOption(t, o)) ||
          // -C inside a cluster of short options (make -sC ../x)
          (o.length === 2 && !t.startsWith("--") && t.startsWith("-") && t.slice(1).includes(o[1])),
      ),
    )
  )
    unknownOption = true;
  // make VAR=value overrides variables used in recipes (SHELL=./x, .SHELLFLAGS=...)
  if (mode === "allow" && (head === "make" || head === "gmake") && rest.some((t) => /^[A-Za-z_.][\w.]*=/.test(t))) unknownOption = true;
  return { argv: canonicalScripts([head, ...rest]), unknownOption };
}

/** Options that point a tool at another project, wherever they appear in argv. */
const LOCATION_ANYWHERE: Record<string, string[]> = {
  npm: ["--prefix", "-C", "--userconfig", "--globalconfig", "--script-shell", "--node-options", "--shell"],
  pnpm: ["-C", "--dir"],
  yarn: ["--cwd"],
  bun: ["--cwd", "--config"],
  cargo: ["--manifest-path", "--config", "-Z"],
  make: ["-C", "--directory", "-f", "--file", "--makefile", "--eval", "-I", "--include-dir"],
  gmake: ["-C", "--directory", "-f", "--file", "--makefile", "--eval", "-I", "--include-dir"],
  go: ["-C", "-modfile", "-exec", "-toolexec"],
  just: ["-f", "--justfile", "-d", "--working-directory", "--shell", "--shell-arg"],
  deno: ["--config", "-c"],
  uv: ["--directory", "--project", "--config-file"],
  poetry: ["-C", "--directory", "-P", "--project"],
};

/** Builtin commands of package managers that also run package.json scripts by name (`yarn deploy`). */
const PM_BUILTINS: Record<string, Set<string>> = {
  yarn: new Set(["add", "audit", "autoclean", "bin", "cache", "check", "config", "create", "dedupe", "dlx", "exec", "explain", "generate-lock-entry", "global", "help", "import", "info", "init", "install", "licenses", "link", "list", "login", "logout", "node", "npm", "outdated", "owner", "pack", "patch", "plugin", "policies", "publish", "rebuild", "remove", "run", "set", "stage", "tag", "team", "test", "unlink", "unplug", "up", "upgrade", "upgrade-interactive", "version", "versions", "why", "workspace", "workspaces"]),
  pnpm: new Set(["add", "audit", "bin", "config", "create", "dedupe", "deploy", "dlx", "env", "exec", "fetch", "i", "import", "init", "install", "licenses", "link", "list", "ls", "outdated", "pack", "patch", "prune", "publish", "rebuild", "recursive", "remove", "rm", "root", "run", "server", "setup", "start", "store", "test", "unlink", "up", "update", "why"]),
  bun: new Set(["add", "build", "create", "init", "install", "link", "outdated", "patch", "pm", "publish", "remove", "run", "test", "update", "upgrade", "why", "x"]),
};

/** `npm run-script x`, `npm rum x` and `yarn x` all run the script x; they become `<pm> run x`. */
function canonicalScripts(a: string[]): string[] {
  const [head, sub] = a;
  if (!sub) return a;
  if (head === "npm" && ["run-script", "rum", "urn"].includes(sub)) return [head, "run", ...a.slice(2)];
  if (Object.hasOwn(PM_BUILTINS, head) && !sub.startsWith("-") && !PM_BUILTINS[head].has(sub) && !sub.includes("/") && !sub.includes(".")) return [head, "run", ...a.slice(1)];
  return a;
}

export const nonFlags = (a: string[]) => a.slice(1).filter((t) => !t.startsWith("-"));

const SHELL_NAMES = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"]);

/** True for shells (whose stdin or -c argument is a script). */
export const isShell = (head: string) => SHELL_NAMES.has(head);

/** Command strings run by this subcommand: sh -c '…', eval …, trap '…', su -c, script -c, watch, env -S, find -exec. */
export function innerCommands(raw: string[]): string[] {
  const out: string[] = [];
  const head = basename(raw[0] ?? "");
  const a = normalizeArgv(raw, "deny").argv;
  if (head === "eval" || head === "watch" || head === "parallel") out.push(raw.slice(1).filter((t) => !t.startsWith("-")).join(" "));
  if (head === "trap" && raw[1] && !raw[1].startsWith("-")) out.push(raw[1]);
  const c = a.findIndex((t, i) => i > 0 && /^-[a-z]*c[a-z]*$/.test(t));
  if ((SHELL_NAMES.has(a[0]) || a[0] === "su" || a[0] === "runuser" || a[0] === "script") && c > 0) {
    const next = a[c + 1] === "--" ? a[c + 2] : a[c + 1];
    if (next !== undefined) out.push(next);
  }
  if (head === "env") raw.forEach((t, i) => (t === "-S" || t === "--split-string") && raw[i + 1] && out.push(raw[i + 1]));
  raw.forEach((t, i) => {
    if (!/^-(exec|execdir|ok|okdir)$/.test(t)) return;
    const end = raw.findIndex((x, j) => j > i && (x === ";" || x === "+"));
    out.push(raw.slice(i + 1, end === -1 ? undefined : end).join(" "));
  });
  return out.filter(Boolean);
}

/**
 * True if a short option carries a glued value that looks like a path (`-f/etc/x`, `-bf~/.aws/x`, `-L$HOME`).
 * Such values are easy to misparse, so commands using them are never treated as safe.
 */
export const hasGluedPathValue = (a: string[]) => a.slice(1).some((t) => t.startsWith("-") && !t.startsWith("--") && /[/~$]|\.\./.test(t.slice(2)));
const flags = (a: string[]) => a.slice(1).filter((t) => t.startsWith("-"));
/** True if a short-option cluster such as `-uo` contains the letter. */
const hasShort = (a: string[], letter: string) => flags(a).some((t) => !t.startsWith("--") && t.slice(1).includes(letter));
/**
 * True if a long option is present. GNU getopt_long and git accept any unambiguous prefix (`--outp` for `--output`),
 * so every prefix of at least three characters (`--o`) counts.
 */
export const isLongOption = (t: string, name: string) => {
  const n = t.split("=")[0];
  return n.startsWith("--") && n.length >= 3 && name.startsWith(n);
};
const hasLong = (a: string[], ...names: string[]) => flags(a).some((t) => names.some((n) => isLongOption(t, n)));
const onlyFlagsFrom = (a: string[], allowed: string[]) => a.slice(2).every((t) => allowed.includes(t));

const READ_ONLY = new Set([
  "ls", "pwd", "echo", "printf", "cat", "head", "tail", "wc", "which", "whoami", "uname", "stat", "cd", "pushd", "popd",
  "du", "df", "grep", "egrep", "fgrep", "cut", "tr", "basename", "dirname", "realpath", "readlink", "ps", "less", "more",
  "true", "false", "test", "[", "nl", "column", "diff", "cmp", "comm", "id", "groups", "jq", "type", "file", "md5sum", "sha256sum", "shasum",
]);
const GIT_READ_ONLY = new Set(["status", "diff", "log", "show", "blame", "ls-files", "rev-parse", "describe", "shortlog", "grep", "ls-tree", "cat-file"]);
const NPM_READ_ONLY = new Set(["ls", "list", "explain", "why"]);

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
    case "printf":
      // printf -v NAME assigns a shell variable (CDPATH, PATH, HOME, ...)
      return !a.slice(1).some((t) => /^-[A-Za-z]*v/.test(t) && !t.startsWith("--"));
    case "less":
    case "more":
      // +cmd runs less/more commands, including shell escapes
      return !a.slice(1).some((t) => t.startsWith("+") || isLongOption(t, "--lesskey-file"));
    case "sort":
      // --files0-from reads a list of file names from a file, which can point anywhere
      return !hasShort(a, "o") && !hasLong(a, "--output", "--compress-program", "--files0-from");
    case "wc":
    case "du":
      return !hasLong(a, "--files0-from");
    case "diff":
      // diff -r follows symlinks inside the trees and prints the contents they point at
      return !hasShort(a, "r") && !hasLong(a, "--recursive");
    case "uniq":
      return nonFlags(a).length <= 1;
    case "tree":
      return !hasShort(a, "o") && !hasLong(a, "--output");
    case "find":
      return !a.some((t) => /^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/.test(t));
    case "rg":
      // --follow / -L walks symlinks out of the project
      return !hasLong(a, "--pre", "--pre-glob", "--follow") && !hasShort(a, "L");
    case "grep":
    case "egrep":
    case "fgrep":
      // -R and --dereference-recursive follow symlinks out of the project
      return !hasShort(a, "R") && !hasLong(a, "--dereference-recursive");
    case "ps":
      // BSD-style `e` (ps e, ps axeww) prints every process's environment, including API keys
      return !nonFlags(a).some((t) => t.includes("e")) && !a.some((t) => /environ/i.test(t));
    case "fd":
    case "fdfind":
      return !hasShort(a, "x") && !hasShort(a, "X") && !hasLong(a, "--exec", "--exec-batch");
    case "file":
      return !hasShort(a, "C") && !hasLong(a, "--compile");
    case "jq":
      // import/include and -L load modules from arbitrary paths
      return !a.some((t) => /\b(import|include)\b/.test(t)) && !hasShort(a, "L") && !hasLong(a, "--rawfile", "--slurpfile");
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
      return !unknownOption && NPM_READ_ONLY.has(a[1] ?? "") && !hasLong(a, "--registry");
    case "git": {
      if (unknownOption) return false;
      const sub = a[1];
      if (sub === "branch") return onlyFlagsFrom(a, ["-a", "-r", "-v", "-vv", "--all", "--remotes", "--list", "--show-current", "--verbose"]);
      if (sub === "remote") return onlyFlagsFrom(a, ["-v", "--verbose"]);
      if (sub === "tag") return onlyFlagsFrom(a, ["-l", "--list"]);
      if (sub === "stash") return a[2] === "list" && a.length <= 4;
      // `reflog expire` and `reflog delete` rewrite history; only showing it is read-only
      if (sub === "reflog") return (a[2] === undefined || a[2] === "show" || a[2].startsWith("-")) && !["expire", "delete"].some((x) => a.includes(x));
      if (!sub || !GIT_READ_ONLY.has(sub)) return false;
      // --output writes files; ext-diff, textconv and open-files-in-pager can run configured programs
      return !hasLong(a, "--output", "--ext-diff", "--textconv", "--open-files-in-pager", "--exec", "--upload-pack") && !(sub === "grep" && hasShort(a, "O"));
    }
  }
  return READ_ONLY.has(head);
}
