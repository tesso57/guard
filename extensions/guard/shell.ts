import { basename } from "node:path";

type Sub = {
  argv: string[];
  assigns: string[];
  writes: string[];
  reads: string[];
  heredocs: string[];
  globArgs?: number[];
};

export type Parsed = {
  ok: boolean;
  subs: Sub[];
  subcommands: string[][];
  operators: string[];
  writes: string[];
  globs: string[];
  dynamic: string[];
  substitutions: string[];
  heredocBodies: string[];
};

export const INTERPRETER_NAMES = new Set(["python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php", "lua", "awk", "gawk", "osascript", "pwsh", "powershell"]);
const INTERPRETERS = new Set([
  "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
  "python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php", "lua", "awk", "gawk",
  "eval", "exec", "source", ".", "sudo", "su", "doas", "env", "xargs", "nohup", "time", "timeout",
  "nice", "watch", "command", "builtin", "osascript", "pwsh", "powershell", "parallel", "script", "stdbuf",
  "npx", "bunx", "pnpx", "uvx", "busybox", "strace", "ltrace", "setsid", "ionice", "chrt", "taskset", "flock", "unbuffer",
]);
const RESERVED = new Set(["then", "do", "else", "elif", "if", "while", "until", "!", "{", "}", "fi", "done", "esac", "time"]);
const HARMLESS_DEVICES = /^\/dev\/(null|stdout|stderr|tty|fd\/[0-2])$/;

const UNUSUAL_CHAR = new RegExp("[\\u0000-\\u0008\\u000b-\\u001f\\u007f\\u00a0\\u1680\\u2000-\\u200f\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]");

const MAX_COMMAND = 16 * 1024;
const FD_DUP = /(\d+|-)(?=$|[\s;&|<>()])/y;
const FD_DIGITS = /(\d+|-)/y;

export function parseShell(cmd: string, depth = 0): Parsed {
  if (cmd.length > MAX_COMMAND) return { ok: false, subs: [], subcommands: [], operators: [], writes: [], globs: [], dynamic: ["command too long to analyze"], substitutions: [], heredocBodies: [] };
  const substitutions: string[] = [];
  const nestedBodies: string[] = [];
  const arithDepth = new Int32Array(cmd.length + 1);
  for (let k = 0, d = 0, brackets = 0; k < cmd.length; k++) {
    arithDepth[k] = d;
    if (cmd[k] === "(" && cmd[k + 1] === "(") { d++; arithDepth[k + 1] = d; k++; }
    else if (cmd[k] === ")" && cmd[k + 1] === ")") { d = Math.max(0, d - 1); arithDepth[k + 1] = d; k++; }
    else if (cmd[k] === "$" && cmd[k + 1] === "[") { d++; brackets++; arithDepth[k + 1] = d; k++; }
    else if (cmd[k] === "]" && brackets > 0) { d = Math.max(0, d - 1); brackets--; }
  }
  arithDepth[cmd.length] = 0;
  const dynamic: string[] = [];
  const globs: string[] = [];
  const subs: Sub[] = [];
  const operators: string[] = [];
  let cur: Sub = { argv: [], assigns: [], writes: [], reads: [], heredocs: [] };
  const pendingDocs: { sub: Sub; delim: string; stripTabs: boolean; quoted: boolean }[] = [];
  let tok = "";
  let inTok = false;
  let globbed = false;
  let tildeStart = false;
  let tokQuoted = false;
  let tokEscaped = false;
  let quote: "'" | '"' | null = null;
  let pendingRedirect: "write" | "read" | "data" | null = null;

  const endTok = () => {
    if (!inTok) return;
    if (pendingRedirect === "write") cur.writes.push(tok);
    else if (pendingRedirect === "read") cur.reads.push(tok);
    else if (pendingRedirect === "data") {
    }
    else if (tok !== "" || tokQuoted) cur.argv.push(tok);
    if (globbed && tok !== "[" && tok !== "]") {
      if (!pendingRedirect) (cur.globArgs ??= []).push(cur.argv.length - 1);
      globs.push(tok);
      if (/\[[=.:]/.test(tok)) dyn("character class or equivalence class in a wildcard");
      if (tokEscaped) dyn("quoted characters in a wildcard");
    }
    if (tildeStart && !/^~(\/|$)/.test(tok)) dyn("tilde expansion");
    pendingRedirect = null;
    tok = "";
    inTok = false;
    globbed = false;
    tildeStart = false;
    tokQuoted = false;
    tokEscaped = false;
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
      i++;
      if (n === "\n") continue;
      tok += n;
      inTok = true;
      tokEscaped = true;
      continue;
    }
    if (c === "$") {
      if (n === "(") {
        dyn("command substitution $()");
        if (depth < 3 && cmd[i + 2] !== "(") {
          for (let close = cmd.indexOf(")", i + 2), tries = 0; close !== -1 && tries < 64; close = cmd.indexOf(")", close + 1), tries++) {
            const inner = parseShell(cmd.slice(i + 2, close), depth + 1);
            if (!inner.ok || inner.dynamic.includes("unterminated here-document")) continue;
            substitutions.push(cmd.slice(i + 2, close));
            nestedBodies.push(...inner.heredocBodies);
            break;
          }
        }
      }
      else if (n === "{" || (n && /[A-Za-z_0-9@*#?!$-]/.test(n))) dyn("variable expansion");
      else if (n === "'" || n === '"') dyn("ANSI-C / locale quoting");
      else if (n === "[") dyn("arithmetic expansion $[ ]");
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
      tokQuoted = true;
      tokEscaped = true;
      continue;
    }
    if (c === "#" && !inTok) {
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
      operators.push(c);
      if (c === "\n" && pendingDocs.length) {
        let pos = i + 1;
        for (const d of pendingDocs.splice(0)) {
          const lines: string[] = [];
          let closed = false;
          while (pos <= cmd.length) {
            const nl = cmd.indexOf("\n", pos);
            const end = nl === -1 ? cmd.length : nl;
            let line = cmd.slice(pos, end);
            pos = end + 1;
            while (!d.quoted && /(^|[^\\])(\\\\)*\\$/.test(line) && pos <= cmd.length) {
              dyn("line continuation in a here-document");
              const nl2 = cmd.indexOf("\n", pos);
              const end2 = nl2 === -1 ? cmd.length : nl2;
              line = line.slice(0, -1) + cmd.slice(pos, end2);
              pos = end2 + 1;
              if (nl2 === -1) break;
            }
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
        endTok();
        i += cmd[i + 2] === ">" ? 2 : 1;
        pendingRedirect = "write";
        continue;
      }
      endCmd();
      operators.push(n === c ? c + n : c === "|" && n === "&" ? "|&" : c);
      if (n === c || (c === "|" && n === "&")) i++;
      continue;
    }
    if ((c === "<" || c === ">") && n === "(") {
      dyn("process substitution");
      endCmd();
      continue;
    }
    if (c === "<") {
      const arith = arithDepth[i] > 0;
      if (n === "<" && (arith || /^[A-Za-z_]\w*\[[^\]]*$/.test(tok))) {
        dyn("arithmetic or array subscript");
        tok += "<<";
        inTok = true;
        i++;
        continue;
      }
      if (inTok && /^\d+$/.test(tok) && !tokQuoted) { tok = ""; inTok = false; }
      endTok();
      if (n === "<" && cmd[i + 2] === "<") {
        i += 2;
        pendingRedirect = "data";
        continue;
      }
      if (n === "<") {
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
          if (ch === "\\") {
            const nx = cmd[i + 1];
            if (nx === undefined) break;
            i++;
            if (nx === "\n") continue;
            quoted = true;
            delim += nx;
          } else if (ch === "'") {
            quoted = true;
            const end = cmd.indexOf("'", i + 1);
            if (end === -1) {
              dyn("malformed here-document");
              i = cmd.length;
              break;
            }
            delim += cmd.slice(i + 1, end);
            i = end;
          } else if (ch === '"') {
            quoted = true;
            let j = i + 1;
            for (; j < cmd.length && cmd[j] !== '"'; j++) {
              if (cmd[j] === "\\" && /[$`"\\\n]/.test(cmd[j + 1] ?? "")) {
                if (cmd[j + 1] !== "\n") delim += cmd[j + 1];
                j++;
              } else delim += cmd[j];
            }
            if (j >= cmd.length) dyn("malformed here-document");
            i = j;
          } else if (ch === "$" || ch === "`") {
            dyn("expansion in a here-document delimiter");
            delim += ch;
          } else delim += ch;
        }
        if (!delim) dyn("malformed here-document");
        if (/[\s\\]/.test(delim)) dyn("unusual here-document delimiter");
        pendingDocs.push({ sub: cur, delim, stripTabs, quoted });
        continue;
      }
      if (n === "&") {
        i++;
        FD_DIGITS.lastIndex = i + 1;
        const m = FD_DIGITS.exec(cmd);
        if (m) i += m[0].length;
        continue;
      }
      if (n === ">") {
        i++;
        pendingRedirect = "write";
        continue;
      }
      pendingRedirect = "read";
      continue;
    }
    if (c === ">") {
      if (inTok && /^\d+$/.test(tok) && !tokQuoted) { tok = ""; inTok = false; }
      endTok();
      if (n === ">" || n === "|") i++;
      if (cmd[i + 1] === "&") {
        i++;
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
      if (a.length && /^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(a[0])) {
        s.assigns.push(a.shift()!);
        dyn("environment assignment prefix");
      } else if (a.length && RESERVED.has(a[0])) {
        const kw = a.shift();
        while (kw === "time" && (a[0] === "-p" || a[0] === "--")) a.shift();
      } else break;
    }
    if (a.some((t) => /\$\(|`|\$\[/.test(t))) dyn("substitution text in a word");
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
  const kept = subs.filter((s) => s.argv.length || s.assigns.length || s.writes.length || s.reads.length);
  if (kept.length > 128) dyn("too many subcommands to analyze");
  while (operators.length >= kept.length && (operators.at(-1) === ";" || operators.at(-1) === "\n")) operators.pop();
  for (const s of kept) s.writes = s.writes.filter((w) => !HARMLESS_DEVICES.test(w));
  return {
    ok,
    subs: kept,
    subcommands: kept.map((s) => s.argv),
    operators,
    writes: kept.flatMap((s) => s.writes),
    globs,
    dynamic,
    substitutions,
    heredocBodies: [...kept.flatMap((s) => s.heredocs), ...nestedBodies],
  };
}

const GLOBAL_OPTIONS: Record<string, { flags: string[]; withValue: string[]; location: string[] }> = {
  git: { flags: ["--no-pager", "-P", "-p", "--paginate", "--no-optional-locks", "--literal-pathspecs", "--no-replace-objects"], withValue: [], location: ["-C", "--git-dir", "--work-tree", "-c"] },
  npm: { flags: ["--silent", "-s", "--quiet", "-q", "--no-color"], withValue: ["-w", "--workspace"], location: ["--prefix", "-C"] },
  pnpm: { flags: ["--silent", "-s", "-r", "--recursive"], withValue: ["--filter", "-F"], location: ["-C", "--dir"] },
  yarn: { flags: ["--silent", "-s"], withValue: [], location: ["--cwd"] },
  bun: { flags: ["--silent"], withValue: [], location: ["--cwd"] },
  cargo: { flags: ["-q", "--quiet", "-v", "--verbose", "--locked", "--frozen", "--offline"], withValue: [], location: ["--manifest-path", "-Z", "--config"] },
};

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

export function unwrapCommandWrappers(a: string[], observe?: (argv: string[], start: number, end: number) => void): string[] {
  let start = 0;
  for (;;) {
    const name = basename(a[start] ?? "");
    const w = Object.hasOwn(WRAPPERS, name) ? WRAPPERS[name] : undefined;
    if (!w) {
      observe?.(a, start, a.length);
      return a.slice(start);
    }
    let next = start + 1;
    while (next < a.length && (a[next].startsWith("-") || (name === "env" && /^[^=]+=/.test(a[next])))) {
      const option = a[next++];
      if (w.includes(option) && next < a.length) next++;
    }
    if (["timeout", "chrt", "taskset", "flock"].includes(name) && next < a.length) next++;
    observe?.(a, start, next);
    start = next;
  }
}

export function normalizeArgv(a: string[], mode: "allow" | "deny" = "allow"): { argv: string[]; unknownOption: boolean } {
  let rest = mode === "deny" ? unwrapCommandWrappers(a) : [...a];
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
  if (
    mode === "allow" &&
    Object.hasOwn(LOCATION_ANYWHERE, head) &&
    rest.some((t) =>
      LOCATION_ANYWHERE[head].some(
        (o) =>
          t === o ||
          t.startsWith(`${o}=`) ||
          (o.startsWith("--") && isLongOption(t, o)) ||
          (o.length === 2 && !t.startsWith("--") && t.startsWith("-") && t.slice(1).includes(o[1])),
      ),
    )
  )
    unknownOption = true;
  if (mode === "allow" && (head === "make" || head === "gmake") && rest.some((t) => /^[A-Za-z_.][\w.]*=/.test(t))) unknownOption = true;
  return { argv: canonicalScripts([head, ...rest]), unknownOption };
}

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

const PM_BUILTINS: Record<string, Set<string>> = {
  yarn: new Set(["add", "audit", "autoclean", "bin", "cache", "check", "config", "create", "dedupe", "dlx", "exec", "explain", "generate-lock-entry", "global", "help", "import", "info", "init", "install", "licenses", "link", "list", "login", "logout", "node", "npm", "outdated", "owner", "pack", "patch", "plugin", "policies", "publish", "rebuild", "remove", "run", "set", "stage", "tag", "team", "test", "unlink", "unplug", "up", "upgrade", "upgrade-interactive", "version", "versions", "why", "workspace", "workspaces"]),
  pnpm: new Set(["add", "audit", "bin", "config", "create", "dedupe", "deploy", "dlx", "env", "exec", "fetch", "i", "import", "init", "install", "licenses", "link", "list", "ls", "outdated", "pack", "patch", "prune", "publish", "rebuild", "recursive", "remove", "rm", "root", "run", "server", "setup", "start", "store", "test", "unlink", "up", "update", "why"]),
  bun: new Set(["add", "build", "create", "init", "install", "link", "outdated", "patch", "pm", "publish", "remove", "run", "test", "update", "upgrade", "why", "x"]),
};

function canonicalScripts(a: string[]): string[] {
  const [head, sub] = a;
  if (!sub) return a;
  if (head === "npm" && ["run-script", "rum", "urn"].includes(sub)) return [head, "run", ...a.slice(2)];
  if (Object.hasOwn(PM_BUILTINS, head) && !sub.startsWith("-") && !PM_BUILTINS[head].has(sub) && !sub.includes("/") && !sub.includes(".")) return [head, "run", ...a.slice(1)];
  return a;
}

export const nonFlags = (a: string[]) => {
  const rest = a.slice(1);
  const dd = rest.indexOf("--");
  return dd < 0 ? rest.filter((t) => !t.startsWith("-")) : [...rest.slice(0, dd).filter((t) => !t.startsWith("-")), ...rest.slice(dd + 1)];
};

const SHELL_NAMES = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"]);

export const isShell = (head: string) => SHELL_NAMES.has(head);

export function innerCommands(raw: string[]): string[] {
  const out: string[] = [];
  const head = basename(raw[0] ?? "");
  const a = normalizeArgv(raw, "deny").argv;
  if (head === "eval" || head === "watch" || head === "parallel") out.push(raw.slice(1).filter((t) => !t.startsWith("-")).join(" "));
  if (head === "trap" && raw[1] && !raw[1].startsWith("-")) out.push(raw[1]);
  if (head === "alias") for (const t of raw.slice(1)) if (t.includes("=")) out.push(t.slice(t.indexOf("=") + 1));
  if (a[0] === "git" && a.includes("config")) {
    const k = a.findIndex((t) => /^alias\./i.test(t));
    const v = k > 0 ? a[k + 1] : undefined;
    if (v) out.push(v.startsWith("!") ? v.slice(1) : `git ${v}`);
  }
  if (a[0] === "npm" || a[0] === "pnpm" || a[0] === "yarn" || a[0] === "bun") {
    if (a[1] === "pkg" && a[2] === "set") for (const t of a.slice(3)) if (/^scripts\./.test(t) && t.includes("=")) out.push(t.slice(t.indexOf("=") + 1));
    if (a[1] === "set-script" && a[3]) out.push(a[3]);
  }
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

export const hasGluedPathValue = (a: string[]) => a.slice(1).some((t) => t.startsWith("-") && !t.startsWith("--") && /[/~$]|\.\./.test(t.slice(2)));
const flags = (a: string[]) => a.slice(1).filter((t) => t.startsWith("-"));
const hasShort = (a: string[], letter: string) => flags(a).some((t) => !t.startsWith("--") && t.slice(1).includes(letter));
export const isLongOption = (t: string, name: string) => {
  const n = t.split("=")[0];
  return n.startsWith("--") && n.length >= 3 && name.startsWith(n);
};
const hasLong = (a: string[], ...names: string[]) => flags(a).some((t) => names.some((n) => isLongOption(t, n)));
const onlyFlagsFrom = (a: string[], allowed: string[]) => a.slice(2).every((t) => allowed.includes(t));

const GREP_FLAGS = new Set(["E", "F", "G", "P", "i", "v", "w", "x", "c", "l", "L", "n", "H", "h", "o", "q", "s", "r", "a", "I", "z"]);
const GREP_VALUES = new Set(["e", "A", "B", "C", "m"]);
const GREP_LONG_FLAGS = new Set(["extended-regexp", "fixed-strings", "basic-regexp", "perl-regexp", "ignore-case", "invert-match", "word-regexp", "line-regexp", "count", "files-with-matches", "files-without-match", "line-number", "with-filename", "no-filename", "only-matching", "quiet", "silent", "no-messages", "recursive", "text", "null-data"]);
const GREP_LONG_VALUES = new Set(["regexp", "after-context", "before-context", "context", "max-count"]);

export function grepExplicitPaths(argv: string[], allowStdin = false): string[] | undefined {
  if (!["grep", "egrep", "fgrep"].includes(argv[0])) return undefined;
  const operands: string[] = [];
  let patternProvided = false;
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") { operands.push(...argv.slice(i + 1)); break; }
    if (arg === "-") return undefined;
    if (!arg.startsWith("-")) { operands.push(arg); continue; }
    if (arg.startsWith("--")) {
      const equal = arg.indexOf("=");
      const name = arg.slice(2, equal < 0 ? undefined : equal);
      if (GREP_LONG_FLAGS.has(name) && equal < 0) continue;
      if (!GREP_LONG_VALUES.has(name)) return undefined;
      if (name === "regexp") patternProvided = true;
      if (equal < 0 && ++i >= argv.length) return undefined;
      continue;
    }
    for (let j = 1; j < arg.length; j++) {
      const flag = arg[j];
      if (GREP_VALUES.has(flag)) {
        if (flag === "e") patternProvided = true;
        if (j === arg.length - 1 && ++i >= argv.length) return undefined;
        break;
      }
      if (!GREP_FLAGS.has(flag)) return undefined;
    }
  }
  if (!patternProvided && operands.length === 0) return undefined;
  const paths = patternProvided ? operands : operands.slice(1);
  return !paths.includes("-") && (paths.length > 0 || allowStdin) ? paths : undefined;
}

const RG_SHORT_FLAGS = new Set([..."abcFhHiIlnNoOpqsSuUvwxy0".split(""), "."]);
const RG_SHORT_VALUES = new Set([..."ABCdeEgjmMrtT".split("")]);
const RG_LONG_FLAGS = new Set([
  "binary", "byte-offset", "case-sensitive", "column", "count", "count-matches", "crlf", "files", "files-with-matches",
  "files-without-match", "fixed-strings", "glob-case-insensitive", "heading", "hidden", "ignore-case", "include-zero", "invert-match",
  "json", "line-number", "line-regexp", "max-columns-preview", "multiline", "multiline-dotall", "no-filename", "no-heading", "no-ignore",
  "no-ignore-dot", "no-ignore-exclude", "no-ignore-files", "no-ignore-global", "no-ignore-parent", "no-ignore-vcs", "no-line-number",
  "no-messages", "no-column", "no-unicode", "null", "null-data", "one-file-system", "only-matching", "passthru", "pcre2", "pretty",
  "quiet", "smart-case", "stats", "text", "trim", "type-list", "unrestricted", "vimgrep", "with-filename", "word-regexp", "no-hidden",
  "no-follow", "no-binary", "no-text", "no-trim", "no-pcre2", "no-stats", "no-multiline", "no-crlf", "no-fixed-strings", "no-invert-match", "no-config",
]);
const RG_LONG_VALUES = new Set([
  "after-context", "before-context", "context", "color", "colors", "context-separator", "field-context-separator", "field-match-separator",
  "encoding", "engine", "file", "glob", "iglob", "max-columns", "max-count", "max-depth", "maxdepth", "max-filesize", "path-separator", "regexp",
  "replace", "sort", "sortr", "threads", "type", "type-not", "type-add", "type-clear", "dfa-size-limit", "regex-size-limit",
]);
function inspectRgOptions(a: string[]): { known: boolean; listsFiles: boolean; listsTypes: boolean; noConfig: boolean; noIgnore: boolean; noIgnoreVcs: boolean; noIgnoreDot: boolean; hidden: boolean; unrestricted: number; patternProvided: boolean; patternFile: boolean; fileTypes: boolean; operands: string[]; globs: string[] } {
  let listsFiles = false;
  let listsTypes = false;
  let noConfig = false;
  let noIgnore = false;
  let noIgnoreVcs = false, noIgnoreDot = false;
  let hidden = false;
  let unrestricted = 0;
  let patternProvided = false;
  let patternFile = false;
  let fileTypes = false;
  const operands: string[] = [];
  const globs: string[] = [];
  const invalid = () => ({ known: false, listsFiles: false, listsTypes: false, noConfig: false, noIgnore: false, noIgnoreVcs: false, noIgnoreDot: false, hidden: false, unrestricted: 0, patternProvided: false, patternFile: false, fileTypes: false, operands: [], globs: [] });
  for (let i = 1; i < a.length; i++) {
    const t = a[i];
    if (t === "--") { operands.push(...a.slice(i + 1)); break; }
    if (!t.startsWith("-") || t === "-") { operands.push(t); continue; }
    if (t.startsWith("--")) {
      const eq = t.indexOf("=");
      const name = t.slice(2, eq < 0 ? undefined : eq);
      if (RG_LONG_FLAGS.has(name) && eq < 0) {
        if (name === "files") listsFiles = true;
        if (name === "type-list") listsTypes = true;
        if (name === "no-config") noConfig = true;
        if (name === "no-ignore") noIgnore = true;
        if (name === "no-ignore-vcs") noIgnoreVcs = true;
        if (name === "no-ignore-dot") noIgnoreDot = true;
        if (name === "hidden") hidden = true;
        if (name === "unrestricted") unrestricted++;
        continue;
      }
      if (!RG_LONG_VALUES.has(name)) return invalid();
      if (name === "regexp" || name === "file") patternProvided = true;
      if (name === "file") patternFile = true;
      if (["type", "type-not", "type-add", "type-clear"].includes(name)) fileTypes = true;
      if (eq < 0 && i + 1 >= a.length) return invalid();
      const value = eq < 0 ? a[++i] : t.slice(eq + 1);
      if (name === "glob" || name === "iglob") globs.push(value);
      continue;
    }
    for (let k = 1; k < t.length; k++) {
      const c = t[k];
      if (RG_SHORT_VALUES.has(c)) {
        if (c === "e") patternProvided = true;
        if (c === "t" || c === "T") fileTypes = true;
        if (k === t.length - 1 && i + 1 >= a.length) return invalid();
        const value = k === t.length - 1 ? a[++i] : t.slice(k + 1);
        if (c === "g") globs.push(value);
        break;
      }
      if (!RG_SHORT_FLAGS.has(c)) return invalid();
      if (c === "u") unrestricted++;
      if (c === ".") hidden = true;
    }
  }
  return { known: true, listsFiles, listsTypes, noConfig, noIgnore, noIgnoreVcs, noIgnoreDot, hidden, unrestricted, patternProvided, patternFile, fileTypes, operands, globs };
}

export function rgUsesPatternFile(a: string[]): boolean {
  const options = inspectRgOptions(a);
  return a[0] === "rg" && options.known && options.patternFile;
}

export function rgListsFiles(a: string[]): boolean {
  if (a[0] !== "rg") return false;
  const options = inspectRgOptions(a);
  return options.known && options.listsFiles;
}

export function rgListsTypes(a: string[]): boolean {
  if (a[0] !== "rg") return false;
  const options = inspectRgOptions(a);
  return options.known && options.listsTypes && !options.patternProvided && options.operands.length === 0 && options.globs.length === 0;
}

export function rgInfoOnly(a: string[]): boolean {
  return a.length === 2 && a[0] === "rg" && ["--version", "-V", "--help", "-h"].includes(a[1]);
}

export function rgDisablesConfig(a: string[]): boolean {
  if (a[0] !== "rg") return false;
  const options = inspectRgOptions(a);
  return options.known && options.noConfig;
}

export function rgExplicitPaths(a: string[]): string[] | undefined {
  if (a[0] !== "rg") return undefined;
  const options = inspectRgOptions(a);
  if (!options.known) return undefined;
  return options.listsFiles || options.patternProvided ? options.operands : options.operands.slice(1);
}

export function rgReadsStdin(a: string[]): boolean {
  if (a[0] !== "rg") return false;
  const options = inspectRgOptions(a);
  if (!options.known || options.listsFiles || options.listsTypes) return false;
  return options.patternProvided ? options.operands.length === 0 : options.operands.length === 1;
}

export function rgSimpleIncludeSuffixes(a: string[]): string[] | undefined {
  if (a[0] !== "rg") return undefined;
  const options = inspectRgOptions(a);
  if (!options.known || !options.globs.length || options.globs.some((glob) => !/^\*\.[a-z0-9_+-]{1,32}$/i.test(glob))) return undefined;
  return options.globs.map((glob) => glob.slice(1).toLowerCase());
}

export function rgVisibility(a: string[]): { hidden: boolean; ignoresRules: boolean; ignoresVcs: boolean; ignoresDot: boolean } {
  const options = inspectRgOptions(a);
  if (a[0] !== "rg" || !options.known) return { hidden: true, ignoresRules: false, ignoresVcs: false, ignoresDot: false };
  return {
    hidden: options.hidden || options.unrestricted >= 2 || options.fileTypes || options.globs.length > 0,
    ignoresRules: options.noIgnore || options.unrestricted >= 1,
    ignoresVcs: options.noIgnoreVcs,
    ignoresDot: options.noIgnoreDot,
  };
}

const READ_ONLY = new Set([
  "ls", "pwd", "echo", "printf", "cat", "head", "tail", "wc", "which", "whoami", "uname", "stat", "cd", "pushd", "popd",
  "du", "df", "grep", "egrep", "fgrep", "cut", "tr", "basename", "dirname", "realpath", "readlink", "ps",
  "true", "false", "test", "[", "nl", "column", "diff", "cmp", "comm", "id", "groups", "jq", "type", "file", "md5sum", "sha256sum", "shasum",
]);
const GIT_READ_ONLY = new Set(["status", "diff", "log", "show", "blame", "ls-files", "rev-parse", "describe", "shortlog", "grep", "ls-tree", "cat-file"]);
const NPM_READ_ONLY = new Set(["ls", "list", "explain", "why"]);
const VERSION_TOOLS = new Set([...READ_ONLY, "git", "npm", "node", "python", "python3", "ruby", "perl", "php", "sh", "bash", "zsh"]);

export function isReadOnlyArgv(raw: string[]): boolean {
  if (raw.length === 0) return true;
  const { argv: a, unknownOption } = normalizeArgv(raw);
  const head = a[0];
  if (!head) return false;
  if (rgInfoOnly(a)) return true;
  if (a.length === 2 && /^(--version|-V|--help)$/.test(a[1])) return VERSION_TOOLS.has(head);
  switch (head) {
    case "test":
    case "[":
      return !a.slice(1).some((t) => /^[A-Za-z_]\w*\[.*\]$/.test(t));
    case "printf":
      return !a.slice(1).some((t) => /^-[A-Za-z]*v/.test(t) && !t.startsWith("--"));
    case "tail": {
      const end = a.indexOf("--");
      const options = end < 0 ? a : a.slice(0, end);
      return !hasShort(options, "f") && !hasShort(options, "F") && !hasLong(options, "--follow");
    }
    case "less":
    case "more":
      return false;
    case "sort":
      return !hasShort(a, "o") && !hasLong(a, "--output", "--compress-program", "--files0-from");
    case "wc":
    case "du":
      return !hasLong(a, "--files0-from");
    case "diff":
      return !hasShort(a, "r") && !hasLong(a, "--recursive");
    case "uniq":
      return nonFlags(a).length <= 1;
    case "tree":
      return !hasShort(a, "o") && !hasLong(a, "--output", "--html", "--follow") && !hasShort(a, "H") && !hasShort(a, "R") && !hasShort(a, "l");
    case "find":
      return !a.some((t) => /^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/.test(t));
    case "rg":
      if (process.env.RIPGREP_CONFIG_PATH && !rgDisablesConfig(a)) return false;
      return inspectRgOptions(a).known;
    case "grep":
    case "egrep":
    case "fgrep":
      if (grepExplicitPaths(["grep", ...a.slice(1)], true) !== undefined) return true;
      return !hasShort(a, "R") && !hasLong(a, "--dereference-recursive");
    case "ps":
      return !nonFlags(a).some((t) => t.includes("e")) && !a.some((t) => /environ/i.test(t));
    case "fd":
    case "fdfind":
      return !hasShort(a, "x") && !hasShort(a, "X") && !hasLong(a, "--exec", "--exec-batch");
    case "file":
      return !hasShort(a, "C") && !hasLong(a, "--compile");
    case "jq":
      return !a.some((t) => /\b(import|include)\b/.test(t)) && !hasShort(a, "L") && !hasShort(a, "f") && !hasLong(a, "--rawfile", "--slurpfile", "--from-file");
    case "sed": {
      if (!a.slice(1).every((t) => !t.startsWith("-") || t === "-n" || t === "-E" || t === "-r")) return false;
      const script = nonFlags(a)[0] ?? "";
      return /^(\d+|\$)(,(\d+|\$))?p$/.test(script);
    }
    case "date": {
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
    case "md5sum":
    case "sha256sum":
    case "shasum":
      return !hasShort(a, "c") && !hasLong(a, "--check");
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
      if (sub === "reflog") return (a[2] === undefined || a[2] === "show" || a[2].startsWith("-")) && !["expire", "delete"].some((x) => a.includes(x));
      if (!sub || !GIT_READ_ONLY.has(sub)) return false;
      return !hasLong(a, "--output", "--ext-diff", "--textconv", "--open-files-in-pager", "--exec", "--upload-pack") && !(sub === "grep" && hasShort(a, "O"));
    }
  }
  return READ_ONLY.has(head);
}
