/**
 * model を呼ぶ前の決定的なチェック。
 *   hardDeny  : 上書き不可のブロック(規則でもダイアログでも解除できない)
 *   sensitive : 秘密情報を含みやすいパスへのアクセス → 確認
 *   safeAllow : 明らかに安全 → model を呼ばずに許可
 */
import { basename } from "node:path";
import { type Parsed, isReadOnlyArgv } from "./shell.ts";
import { isInside, pathLikeTokens, protectedReason, resolvePath, sensitiveReason } from "./paths.ts";

const HARD_DENY_BASH: [RegExp, string][] = [
  [/\brm\s+(?:-[A-Za-z]*\s+)*-[A-Za-z]*[rR][A-Za-z]*\s+(?:-[A-Za-z]+\s+)*(?:--no-preserve-root\s+)?(?:"|')?(?:\/|~|\$HOME|\$\{HOME\}|\/\*|~\/\*|\$HOME\/\*)(?:"|')?(?=\s|$|;|&|\|)/, "ルートまたはホームの再帰削除"],
  [/\brm\s+(?:-[A-Za-z]+\s+)*--recursive\b[^;&|]*\s(?:\/|~|\$HOME)(?=\s|$)/, "ルートまたはホームの再帰削除"],
  [/\bmkfs(?:\.\w+)?\b/, "ファイルシステムの作成"],
  [/\bdd\b[^;&|]*\bof=\/dev\/(?:sd|nvme|disk|hd|xvd|vd|mmcblk)/, "ブロックデバイスへの直接書き込み"],
  [/\b(?:curl|wget|fetch)\b[^;&]*\|\s*(?:sudo\s+)?(?:env\s+)?(?:ba|z|da|k|fi)?sh\b/, "ダウンロードしたスクリプトを直接実行"],
  [/\b(?:curl|wget)\b[^;&]*\|\s*(?:sudo\s+)?(?:python[23]?|node|perl|ruby)\b/, "ダウンロードしたコードを直接実行"],
  [/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, "fork bomb"],
  [/>>?\s*\S*authorized_keys\b/, "authorized_keys への書き込み"],
  [/\bchmod\s+(?:-[A-Za-z]+\s+)*-R\s+(?:0?777|a\+rwx)\s+(?:\/|~|\$HOME)(?=\s|$)/, "ルート/ホームの権限全開放"],
  [/\b(?:history\s+-c|unset\s+HISTFILE)\b/, "履歴の消去"],
];

/** ツール入力から触るパスを取り出す(組み込みツールの引数名に合わせる) */
export function inputPaths(tool: string, input: any, cwd: string, parsed?: Parsed): { reads: string[]; writes: string[] } {
  if (tool === "bash" && parsed) {
    const tokens = parsed.subcommands.flatMap((a) => a.slice(1));
    return { reads: pathLikeTokens(cwd, tokens), writes: parsed.writes.map((w) => resolvePath(cwd, w)) };
  }
  const p: string[] = [];
  for (const k of ["path", "file_path", "filePath", "file", "dir", "directory"]) if (typeof input?.[k] === "string") p.push(resolvePath(cwd, input[k]));
  if (tool === "edit" || tool === "write") return { reads: [], writes: p };
  return { reads: p, writes: [] };
}

export function hardDeny(tool: string, input: any, cwd: string, roots: string[], parsed?: Parsed): string | undefined {
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  for (const w of writes) {
    const r = protectedReason(w, roots);
    if (r) return `${r} への書き込み`;
    if (basename(w) === "authorized_keys") return "authorized_keys への書き込み";
  }
  if (tool === "bash") {
    const cmd = String(input?.command ?? "");
    for (const [re, why] of HARD_DENY_BASH) if (re.test(cmd)) return why;
    // 保護パスに触れる bash は、読み取り専用コマンドだけで構成されていない限り拒否
    const touchesProtected = reads.some((p) => protectedReason(p, roots)) || roots.some((r) => cmd.includes(r));
    if (touchesProtected && (!parsed || parsed.dynamic.length || parsed.writes.length || !parsed.subcommands.every(isReadOnlyArgv)))
      return "保護されたパス(規則・セッション記録・拡張・pi 設定)を変更しうる bash";
  }
  return undefined;
}

export function sensitive(tool: string, input: any, cwd: string, parsed?: Parsed): string | undefined {
  const { reads, writes } = inputPaths(tool, input, cwd, parsed);
  for (const p of [...reads, ...writes]) {
    const r = sensitiveReason(p);
    if (r) return r;
  }
  if (tool === "bash") {
    const cmd = String(input?.command ?? "");
    if (/\b(?:printenv|env)\s*(?:$|[|;&>])/.test(cmd)) return "環境変数の全出力";
    if (/(?:^|[\s"'/])\.env(?:\.[\w.-]+)?(?=$|[\s"';|&])/.test(cmd) && !/\.env\.(?:example|sample|template)/.test(cmd)) return ".env ファイル";
  }
  return undefined;
}

const RISKY_PROJECT_FILES = [/^\.git(\/|$)/, /^\.github\/workflows\//, /^\.gitlab-ci\.yml$/, /^\.husky\//, /^\.envrc$/, /^\.npmrc$/, /^\.pi\//, /^\.vscode\/tasks\.json$/, /^Makefile$/, /^package\.json$/];

export function safeAllow(tool: string, input: any, cwd: string, parsed?: Parsed): boolean {
  if (tool === "bash") {
    if (!parsed || !parsed.ok || parsed.dynamic.length || parsed.writes.length) return false;
    return parsed.subcommands.length > 0 && parsed.subcommands.every(isReadOnlyArgv);
  }
  if (tool === "edit" || tool === "write") {
    const { writes } = inputPaths(tool, input, cwd);
    if (!writes.length) return false;
    return writes.every((w) => {
      if (!isInside(w, cwd) || w === cwd) return false;
      const rel = w.slice(cwd.length + 1);
      // CI・フック・ビルドスクリプトなど、後で自動実行されるファイルは model に回す
      return !RISKY_PROJECT_FILES.some((re) => re.test(rel));
    });
  }
  return false;
}
