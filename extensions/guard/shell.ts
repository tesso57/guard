/**
 * 保守的なシェル分割器。
 * 完全なパーサではなく、「規則を安全に当てられるか」を判断するためのもの。
 * 少しでも動的な要素(コマンド置換・変数展開・インタプリタ等)があれば dynamic に理由を積み、
 * 呼び出し側はその場合 allow 規則と安全リストを適用しない(= model 判定に回す)。
 */
export type Parsed = {
  /** クォートが閉じている等、トークン化に成功したか */
  ok: boolean;
  /** && || ; | & 改行 で分割したサブコマンドごとの argv(リダイレクトと先頭の VAR=... は除去済み) */
  subcommands: string[][];
  /** > >> の書き込み先 */
  writes: string[];
  /** 動的要素の理由。空なら静的 */
  dynamic: string[];
};

/** argv[0] がこれなら中身が任意コードになりうるので規則を当てない */
const INTERPRETERS = new Set([
  "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
  "python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php", "lua", "awk", "gawk",
  "eval", "exec", "source", ".", "sudo", "su", "doas", "env", "xargs", "nohup", "time", "timeout",
  "nice", "watch", "command", "builtin", "osascript", "pwsh", "powershell", "parallel", "script",
]);

export function parseShell(cmd: string): Parsed {
  const dynamic: string[] = [];
  const writes: string[] = [];
  const subcommands: string[][] = [];
  let argv: string[] = [];
  let tok = "";
  let inTok = false;
  let quote: "'" | '"' | null = null;
  let pendingRedirect: "write" | "read" | null = null;

  const endTok = () => {
    if (!inTok) return;
    if (pendingRedirect === "write") writes.push(tok);
    else if (pendingRedirect === "read") {
      /* 入力リダイレクトの対象は捨てる */
    } else argv.push(tok);
    pendingRedirect = null;
    tok = "";
    inTok = false;
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
      // コメント: 行末まで読み飛ばす
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
        // &> file / &>> file
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
        // >&2 / 2>&1 は fd 複製なので書き込み先ではない
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
      // ブレース展開 {a,b} / {1..3}
      const close = cmd.indexOf("}", i);
      if (close > i && /,|\.\./.test(cmd.slice(i, close))) dyn("brace expansion");
    }
    tok += c;
    inTok = true;
  }
  const ok = quote === null && pendingRedirect === null;
  endCmd();

  for (const a of subcommands) {
    // 先頭の VAR=value はコマンドの挙動を変えられる(PATH=... など)
    while (a.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(a[0])) {
      a.shift();
      dyn("environment assignment prefix");
    }
    const head = a[0];
    if (!head) continue;
    const base = head.split("/").pop()!;
    if (INTERPRETERS.has(base)) dyn(`interpreter or wrapper: ${base}`);
    if (head.includes("/")) dyn("command given by path");
    if (base === "find" && a.some((t) => /^-(exec|execdir|ok|okdir|delete)$/.test(t))) dyn("find -exec/-delete");
    if (base === "git" && a.some((t, i) => i > 0 && (t === "-c" || t.startsWith("--config") || t === "--exec-path"))) dyn("git -c config override");
  }
  if (!ok) dyn("unterminated quote or redirect");
  return { ok, subcommands, writes, dynamic };
}

/** 読み取り専用とみなせるコマンド(パス自体の機密判定は別途行う) */
const READ_ONLY = new Set([
  "ls", "pwd", "echo", "printf", "cat", "head", "tail", "wc", "which", "whoami", "date", "uname", "file", "stat",
  "du", "df", "tree", "grep", "egrep", "fgrep", "rg", "fd", "find", "sort", "uniq", "diff", "cut", "tr", "basename",
  "dirname", "realpath", "readlink", "true", "false", "test", "[", "less", "more", "jq", "column", "nl", "hostname",
]);
const GIT_READ_ONLY = new Set(["status", "diff", "log", "show", "blame", "ls-files", "rev-parse", "describe", "shortlog", "reflog"]);

export function isReadOnlyArgv(a: string[]): boolean {
  const head = a[0];
  if (!head) return true;
  if (READ_ONLY.has(head)) return true;
  if (head === "git") {
    const sub = a.find((t, i) => i > 0 && !t.startsWith("-"));
    if (!sub) return false;
    if (GIT_READ_ONLY.has(sub)) return true;
    // 引数なしの一覧表示だけ
    if ((sub === "branch" || sub === "remote" || sub === "tag" || sub === "stash") && a.length <= 3 && a.every((t) => !/^-[dDmMfu]|^--(delete|force|move)/.test(t)))
      return sub === "stash" ? a.includes("list") : true;
  }
  return false;
}
