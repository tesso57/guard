import { homedir } from "node:os";
import { basename, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { AGENT_DIR } from "./config.ts";

const HOME = homedir();

function expandHome(p: string): string {
  if (p === "~") return HOME;
  if (p.startsWith("~/")) return join(HOME, p.slice(2));
  return p.replace(/^\$HOME(?=\/|$)/, HOME).replace(/^\$\{HOME\}(?=\/|$)/, HOME);
}

/** 先頭の @ を除去し、~ を展開して cwd 基準の絶対パスにする */
export function resolvePath(cwd: string, p: string): string {
  const q = expandHome(p.replace(/^@/, ""));
  return normalize(isAbsolute(q) ? q : resolve(cwd, q));
}

export function isInside(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/** 秘密情報を含みやすいパス。読み取りでも確認に回す */
export function sensitiveReason(abs: string): string | undefined {
  const rel = isInside(abs, HOME) ? relative(HOME, abs) : undefined;
  const first = rel?.split(sep)[0];
  if (rel !== undefined) {
    if ([".ssh", ".aws", ".gnupg", ".gpg", ".kube", ".docker", ".azure", ".password-store"].includes(first!)) return `~/${first} 以下`;
    if (rel.startsWith(join(".config", "gh")) || rel.startsWith(join(".config", "gcloud"))) return `~/${rel.split(sep).slice(0, 2).join("/")} 以下`;
    if ([".netrc", ".npmrc", ".pypirc", ".git-credentials", ".bash_history", ".zsh_history"].includes(rel)) return `~/${rel}`;
  }
  const b = basename(abs);
  if (/^\.env(\..+)?$/.test(b) && !/\.(example|sample|template)$/.test(b)) return `.env ファイル (${b})`;
  if (/\.(pem|key|p12|pfx|keystore|jks)$/.test(b)) return `鍵ファイル (${b})`;
  if (/^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/.test(b)) return `SSH 鍵 (${b})`;
  if (b === "auth.json" && isInside(abs, AGENT_DIR)) return "pi の認証情報";
  return undefined;
}

/** エージェントが書き換えてはいけない場所(規則・セッション記録・拡張・pi 設定) */
export function protectedRoots(cwd: string, sessionDir?: string): string[] {
  const roots = [AGENT_DIR, join(cwd, ".pi", "extensions"), join(cwd, ".pi", "settings.json"), join(cwd, ".pi", "guard.json")];
  if (sessionDir) roots.push(sessionDir);
  return roots.map((r) => normalize(r));
}

export function protectedReason(abs: string, roots: string[]): string | undefined {
  const hit = roots.find((r) => isInside(abs, r));
  return hit ? `保護されたパス (${hit})` : undefined;
}

/** トークンのうちパスらしいものを絶対パスにして返す */
export function pathLikeTokens(cwd: string, tokens: string[]): string[] {
  const out: string[] = [];
  for (const t of tokens) {
    if (!t || t.startsWith("-") && !t.includes("=")) continue;
    // --file=path / of=path 形式
    const v = t.includes("=") ? t.slice(t.indexOf("=") + 1) : t;
    if (!v) continue;
    if (v.startsWith("~") || v.startsWith("/") || v.startsWith(".") || v.includes("/") || v.startsWith("$HOME") || /^\.?[\w-]*\.(env|pem|key)$/.test(v) || v.startsWith(".env"))
      out.push(resolvePath(cwd, v));
  }
  return out;
}
