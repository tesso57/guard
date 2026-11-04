/**
 * A conservative shell splitter.
 * It is not a full parser: it only decides whether rules and the safe list can be applied safely.
 * Anything dynamic (command substitution, variable expansion, interpreters, ...) is recorded in `dynamic`,
 * and callers then skip allow rules and the safe list and send the call to the model instead.
 */
export type Parsed = {
  /** Tokenizing succeeded (quotes closed, no dangling redirect). */
  ok: boolean;
  /** argv per subcommand, split on && || ; | & and newlines. Redirects and leading VAR=... are removed. */
  subcommands: string[][];
  /** Targets of > and >> redirects. */
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

const UNUSUAL_CHAR = new RegExp("[\\u0000-\\u0008\\u000b-\\u001f\\u007f\\u00a0\\u1680\\u2000-\\u200f\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]");

export function parseShell(cmd: string): Parsed {
  const dynamic: string[] = [];
  const writes: string[] = [];
  const globs: string[] = [];
  const subcommands: string[][] = [];
  let argv: string[] = [];
  let tok = "";
  let inTok = false;
  let globbed = false;
  let quote: "'" | '"' | null = null;
  let pendingRedirect: "write" | "read" | null = null;

  const endTok = () => {
    if (!inTok) return;
    if (pendingRedirect === "write") writes.push(tok);
    else if (pendingRedirect !== "read") argv.push(tok);
    if (globbed && tok !== "[" && tok !== "]") globs.push(tok);
    pendingRedirect = null;
    tok = "";
    inTok = false;
    globbed = false;
  };
  const endCmd = () => {
    endTok();
    if (argv.length) subcommands.push(argv);
    argv = [];
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
      if (n === "<") {
        dyn("heredoc / herestring");
        i++;
        if (cmd[i + 1] === "<") i++;
        endTok();
        pendingRedirect = "read";
        continue;
      }
      if (inTok && /^\d+$/.test(tok)) { tok = ""; inTok = false; }
      endTok();
      pendingRedirect = "read";
      continue;
    }
    if (c === ">") {
      if (inTok && /^\d+$/.test(tok)) { tok = ""; inTok = false; }
      endTok();
      if (n === ">" || n === "|") i++;
      if (cmd[i + 1] === "&") {
        // >&2 and 2>&1 duplicate file descriptors; they are not write targets
        i++;
        while (/\d|-/.test(cmd[i + 1] ?? "")) i++;
        continue;
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
  const ok = quote === null && pendingRedirect === null;
  endCmd();

  for (const a of subcommands) {
    // A leading VAR=value can change what the command does (PATH=..., GIT_SSH_COMMAND=..., ...)
    while (a.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(a[0])) {
      a.shift();
      dyn("environment assignment prefix");
    }
    const head = a[0];
    if (!head) continue;
    const base = basename(head);
    if (INTERPRETERS.has(base)) dyn(`interpreter or wrapper: ${base}`);
    if (head.includes("/")) dyn("command given by path");
    if (base === "find" && a.some((t) => /^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/.test(t))) dyn("find action that runs or writes");
    if (base === "git" && a.some((t, i) => i > 0 && (t === "-c" || t.startsWith("--config") || t === "--exec-path" || t.startsWith("--exec-path=")))) dyn("git config override");
  }
  if (!ok) dyn("unterminated quote or redirect");
  return { ok, subcommands, writes, globs, dynamic };
}

function basename(p: string): string {
  return p.split("/").pop() ?? p;
}

/**
 * Leading options that only select where or how a tool runs. They are stripped before
 * rules are derived or matched, so `git -C . push` is treated as `git push`.
 */
const GLOBAL_OPTIONS: Record<string, { flags: string[]; withValue: string[] }> = {
  git: { flags: ["--no-pager", "-P", "-p", "--paginate", "--no-optional-locks", "--literal-pathspecs", "--no-replace-objects"], withValue: ["-C"] },
  npm: { flags: ["--silent", "-s", "--quiet", "-q", "--no-color"], withValue: ["--prefix", "-w", "--workspace"] },
  pnpm: { flags: ["--silent", "-s", "-r", "--recursive"], withValue: ["-C", "--dir", "--filter", "-F"] },
  yarn: { flags: ["--silent", "-s"], withValue: ["--cwd"] },
  bun: { flags: ["--silent"], withValue: ["--cwd"] },
  cargo: { flags: ["-q", "--quiet", "-v", "--verbose", "--locked", "--frozen", "--offline"], withValue: [] },
};

/**
 * Normalizes argv for matching: basename of the command, without leading global options.
 * `unknownOption` is true when an option we do not understand comes before the subcommand,
 * in which case the subcommand cannot be identified reliably.
 */
export function normalizeArgv(a: string[]): { argv: string[]; unknownOption: boolean } {
  if (!a.length) return { argv: [], unknownOption: false };
  const head = basename(a[0]);
  const rest = a.slice(1);
  const g = GLOBAL_OPTIONS[head];
  if (g) {
    while (rest.length) {
      const t = rest[0];
      if (g.flags.includes(t)) { rest.shift(); continue; }
      const eq = t.indexOf("=");
      if (eq > 0 && g.withValue.includes(t.slice(0, eq))) { rest.shift(); continue; }
      if (g.withValue.includes(t)) { rest.splice(0, 2); continue; }
      if (head === "cargo" && t.startsWith("+")) { rest.shift(); continue; }
      break;
    }
  }
  return { argv: [head, ...rest], unknownOption: !!rest[0]?.startsWith("-") && !!g };
}

const READ_ONLY = new Set([
  "ls", "pwd", "echo", "printf", "cat", "head", "tail", "wc", "which", "whoami", "uname", "stat",
  "du", "df", "grep", "egrep", "fgrep", "cut", "tr", "basename", "dirname", "realpath", "readlink",
  "true", "false", "test", "[", "nl", "column", "diff", "cmp", "comm", "id", "groups", "jq",
]);
const GIT_READ_ONLY = new Set(["status", "diff", "log", "show", "blame", "ls-files", "rev-parse", "describe", "shortlog", "grep"]);

const flags = (a: string[]) => a.slice(1).filter((t) => t.startsWith("-"));
const positionals = (a: string[]) => a.slice(1).filter((t) => !t.startsWith("-"));
/** True if a short-option cluster such as `-uo` contains the letter. */
const hasShort = (a: string[], letter: string) => flags(a).some((t) => !t.startsWith("--") && t.slice(1).includes(letter));
const hasLong = (a: string[], ...names: string[]) => flags(a).some((t) => names.some((n) => t === n || t.startsWith(`${n}=`)));

/**
 * True only if the command cannot write files, run other programs, or change system state,
 * judging by its name AND its options. Path sensitivity is checked separately.
 */
export function isReadOnlyArgv(raw: string[]): boolean {
  const { argv: a, unknownOption } = normalizeArgv(raw);
  const head = a[0];
  if (!head) return true;
  switch (head) {
    case "sort":
      return !hasShort(a, "o") && !hasLong(a, "--output", "--compress-program");
    case "uniq":
      return positionals(a).length <= 1;
    case "tree":
      return !hasShort(a, "o") && !hasLong(a, "--output");
    case "find":
      return !a.some((t) => /^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/.test(t));
    case "rg":
      return !hasLong(a, "--pre", "--pre-glob");
    case "fd":
    case "fdfind":
      return !hasShort(a, "x") && !hasShort(a, "X") && !hasLong(a, "--exec", "--exec-batch");
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
      return positionals(a).length === 0 && !hasShort(a, "F") && !hasShort(a, "b") && !hasLong(a, "--file", "--boot");
    case "file":
      return !hasShort(a, "C") && !hasLong(a, "--compile");
    case "git": {
      // Another repository's .git/config can run commands even on `git status` (core.fsmonitor), so only the current one counts
      if (unknownOption || raw.some((t) => t === "-C" || t.startsWith("--git-dir") || t.startsWith("--work-tree"))) return false;
      const sub = a[1];
      if (!sub || !GIT_READ_ONLY.has(sub)) return false;
      // --output writes files; ext-diff, textconv and open-files-in-pager can run configured programs
      return !hasLong(a, "--output", "--ext-diff", "--textconv", "--open-files-in-pager", "--exec", "--upload-pack") && !(sub === "grep" && hasShort(a, "O"));
    }
  }
  return READ_ONLY.has(head);
}
