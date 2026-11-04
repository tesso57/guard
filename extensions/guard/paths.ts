import { existsSync, globSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, normalize, relative, resolve, sep } from "node:path";
import { AGENT_DIR } from "./config.ts";

const HOME = normalize(homedir());

function expandHome(p: string): string {
  if (p === "~") return HOME;
  if (p.startsWith("~/")) return join(HOME, p.slice(2));
  return p.replace(/^\$HOME(?=\/|$)/, HOME).replace(/^\$\{HOME\}(?=\/|$)/, HOME);
}

/** Strips a leading @, expands ~ and $HOME, and resolves against cwd. Trailing slashes are removed. */
export function resolvePath(cwd: string, p: string): string {
  const q = expandHome(p.replace(/^@/, ""));
  return normalize(isAbsolute(q) ? q : resolve(cwd, q)).replace(/(.)\/+$/, "$1");
}

/**
 * Resolves `..` physically: each `..` is applied after the symlinks before it are resolved, as the kernel does.
 * `/proc/self/cwd/../.aws` or `link/../x` therefore end up where the system would really open them.
 */
function physicalPath(cwd: string, p: string): string {
  const q = expandHome(p.replace(/^@/, ""));
  let cur = isAbsolute(q) ? "/" : cwd;
  for (const seg of q.split("/")) {
    if (!seg || seg === ".") continue;
    cur = seg === ".." ? dirname(realPath(cur)) : join(cur, seg);
  }
  return realPath(cur);
}

/** Every way a path token may be interpreted: lexically, and physically when symlinks or .. can change the result. */
export function pathVariants(cwd: string, p: string): string[] {
  const lexical = resolvePath(cwd, p);
  if (!/(^|\/)\.\.(\/|$)/.test(p) && !p.includes("/proc/")) return [lexical];
  const physical = physicalPath(cwd, p);
  const out = physical === lexical ? [lexical] : [lexical, physical];
  // Keep /proc/<pid>/{root,cwd,fd} visible: normalizing `..` away would hide that the path goes through them
  if (/^\/proc\/[^/]+\/(root|cwd|fd)(\/|$)/.test(p)) out.push(p);
  return out;
}

/** Resolves symlinks. For paths that do not exist yet, resolves the deepest existing parent. */
export function realPath(p: string): string {
  let cur = p;
  const tail: string[] = [];
  for (;;) {
    try {
      return join(realpathSync(cur), ...tail.reverse());
    } catch {
      const parent = dirname(cur);
      if (parent === cur) return p;
      tail.push(basename(cur));
      cur = parent;
    }
  }
}

/** Case-insensitive containment, so `.PI/extensions` is caught on case-insensitive file systems. */
export function isInside(child: string, parent: string): boolean {
  const rel = relative(parent.toLowerCase(), child.toLowerCase());
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/** True for `/`, the home directory and every directory between them. */
export function isHomeOrAncestor(p: string): boolean {
  return isInside(HOME, p);
}

function sensitiveOne(abs: string): string | undefined {
  const rel = isInside(abs, HOME) ? relative(HOME, abs) : undefined;
  const first = rel?.split(sep)[0];
  if (rel !== undefined && first) {
    if ([".ssh", ".aws", ".gnupg", ".gpg", ".kube", ".docker", ".azure", ".password-store", ".terraform.d", ".m2", ".gradle"].includes(first)) return `~/${first}`;
    const two = rel.split(sep).slice(0, 2).join("/");
    if ([".config/gh", ".config/gcloud", ".config/op", ".config/hub", ".config/rclone", ".config/sops", ".cargo/credentials", ".cargo/credentials.toml", ".claude/.credentials.json", ".codex/auth.json"].includes(two))
      return `~/${two}`;
    if ([".netrc", ".npmrc", ".pypirc", ".git-credentials", ".bash_history", ".zsh_history", ".vault-token", ".pgpass", ".my.cnf", ".terraformrc", ".yarnrc.yml", ".claude.json", ".s3cfg"].includes(rel)) return `~/${rel}`;
  }
  if (/^\/proc\/.*\/environ$/.test(abs)) return "process environment";
  if (/^\/proc\/[^/]+\/(root|cwd)(\/|$)/.test(abs)) return "another view of the file system through /proc";
  const b = basename(abs);
  if (/^\.env(\..+)?$/i.test(b) && !/\.(example|sample|template)$/i.test(b)) return `.env file (${b})`;
  if (/\.(pem|key|p12|pfx|keystore|jks)$/i.test(b)) return `key file (${b})`;
  if (/^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/.test(b)) return `SSH key (${b})`;
  if (b === "auth.json" && isInside(abs, AGENT_DIR)) return "pi credentials";
  return undefined;
}

/** Paths that are likely to hold secrets. Checked on both the literal and the symlink-resolved path. */
export function sensitiveReason(abs: string): string | undefined {
  return sensitiveOne(abs) ?? sensitiveOne(realPath(abs));
}

/**
 * Places the agent must never modify: guard's rules and pi's state, pi session logs,
 * and every project resource pi loads after project trust (.pi/*, .agents/skills).
 */
export function protectedRoots(cwd: string, sessionDir?: string): string[] {
  const roots = [AGENT_DIR, join(cwd, ".pi")];
  for (let d = cwd; ; d = dirname(d)) {
    roots.push(join(d, ".agents"));
    if (dirname(d) === d) break;
  }
  if (sessionDir) roots.push(sessionDir);
  return roots.map((r) => normalize(r));
}

export function protectedReason(abs: string, roots: string[]): string | undefined {
  const real = realPath(abs);
  const hit = roots.find((r) => isInside(abs, r) || isInside(real, r) || isInside(real, realPath(r)));
  return hit ? `protected path (${hit})` : undefined;
}

/**
 * Files that tools run or load later (build scripts, test hooks, CI, editor and agent settings).
 * Editing them is never treated as a plain project edit. Matched case-insensitively at any depth.
 */
const RISKY_DIRS = new Set([
  ".git", ".github", ".gitlab", ".husky", ".pi", ".agents", ".vscode", ".idea", ".claude", ".cursor", ".cargo", ".devcontainer", ".circleci", ".buildkite", ".yarn",
  // Code that package managers and interpreters load implicitly
  "node_modules", ".venv", "venv", "site-packages", "dist-packages", ".tox", ".nox", "__pypackages__", "vendor",
]);
const RISKY_FILES = new Set([
  "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock", "npm-shrinkwrap.json",
  "conftest.py", "setup.py", "setup.cfg", "pyproject.toml", "tox.ini", "noxfile.py", "pytest.ini", "sitecustomize.py", "usercustomize.py",
  ".pre-commit-config.yaml", ".yarnrc", ".yarnrc.yml", ".npmrc", ".envrc", "makefile", "gnumakefile", "justfile", "build.rs",
  "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew", "pom.xml", "dockerfile", "containerfile",
  "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", ".gitattributes", ".gitmodules", "agents.md", "claude.md",
  ".cursorrules", "rakefile", "gemfile", ".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile", "mise.toml", ".mise.toml",
  ".tool-versions", "deno.json", "deno.jsonc", "turbo.json", "cargo.toml", "composer.json", "cmakelists.txt", "lefthook.yml", "lefthook.yaml",
  ".lefthook.yml", "go.mod", "nx.json", "project.json", "vitest.workspace.ts", "jest.setup.js", "jest.setup.ts", "babel.config.json",
]);

export function isRiskyProjectFile(rel: string): boolean {
  const parts = rel.toLowerCase().split(sep);
  const b = parts[parts.length - 1];
  return (
    parts.slice(0, -1).some((d) => RISKY_DIRS.has(d)) ||
    RISKY_FILES.has(b) ||
    /^\.env(\..+)?$/.test(b) ||
    /\.config\.(js|cjs|mjs|ts|mts|cts)$/.test(b) ||
    /^\.(babelrc|eslintrc|prettierrc)\.(js|cjs|mjs)$/.test(b) ||
    /^\.mocharc/.test(b) ||
    /\.pth$/.test(b)
  );
}

/** Tokens that look like paths, resolved to absolute paths. Globs are expanded when possible. */
export function pathLikeTokens(cwd: string, tokens: string[], globs: string[] = []): string[] {
  const out: string[] = [];
  for (const t of tokens) {
    if (!t || (t.startsWith("-") && !t.includes("="))) continue;
    const v = t.includes("=") ? t.slice(t.indexOf("=") + 1) : t;
    if (!v) continue;
    // Bare names count when they look secret (id_rsa, cert.p12) or name an existing file in cwd
    if (v.startsWith("~") || v.startsWith("/") || v.startsWith(".") || v.includes("/") || v.startsWith("$HOME") || /\.(env|pem|key|p12|pfx)$/i.test(v) || /^id_[a-z0-9]+/.test(v) || (v.length < 256 && existsSync(resolve(cwd, v))))
      out.push(...pathVariants(cwd, v));
  }
  for (const g of globs) out.push(...expandGlob(cwd, g));
  return out;
}

/** Expands a glob against the file system. Returns [] when it matches nothing or cannot be expanded. */
function expandGlob(cwd: string, pattern: string): string[] {
  try {
    const p = expandHome(pattern);
    return globSync(p, { cwd }).slice(0, 500).map((m) => resolvePath(cwd, String(m)));
  } catch {
    return [];
  }
}

/**
 * Git runs commands named in a repository's config even for read-only subcommands (core.fsmonitor on `git status`,
 * diff drivers and textconv on `git diff`/`git log -p`, filters, gpg, hooks). Read-only git is only safe when the
 * repository's config (including config.worktree) sets none of them. Keys are parsed, so branch names or URLs that
 * merely contain such words do not count.
 */
const DANGEROUS_GIT_KEY = [
  /^core\.(fsmonitor|hookspath|sshcommand|askpass|gitproxy|alternaterefscommand)$/,
  /^diff\.external$/,
  /^(filter|diff|merge|gpg|credential|uploadpack|receive|remote|url)\..*\.(clean|smudge|process|command|textconv|program|driver|uploadpack|receivepack|helper)$/,
  /^gpg\.program$/,
  /\.(command|program|textconv|cmd)$/,
  /^include\.path$/,
  /^includeif\..*\.path$/,
  /^extensions\.worktreeconfig$/,
];

function gitConfigKeys(text: string): string[] {
  const keys: string[] = [];
  let section = "";
  for (const raw of text.split("\n")) {
    const line = raw.replace(/^\s+/, "");
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = /^\[\s*([^\]\s"]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]/.exec(line);
    if (sec) {
      // [section "sub"] and the legacy [section.sub] both become section.sub
      section = (sec[2] !== undefined ? `${sec[1]}.${sec[2]}` : sec[1]).toLowerCase();
      continue;
    }
    const key = /^([A-Za-z][\w-]*)/.exec(line);
    if (key && section) keys.push(`${section}.${key[1].toLowerCase()}`);
  }
  return keys;
}

function configIsClean(file: string): boolean {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (e: any) {
    return e?.code === "ENOENT";
  }
  return !gitConfigKeys(text).some((k) => DANGEROUS_GIT_KEY.some((re) => re.test(k)));
}

/** A directory git would use as a repository by itself (HEAD, objects/ and refs/). */
function looksLikeGitDir(d: string): boolean {
  return existsSync(join(d, "HEAD")) && existsSync(join(d, "objects")) && existsSync(join(d, "refs"));
}

export function gitConfigIsSafe(cwd: string): boolean {
  for (let d = cwd; ; d = dirname(d)) {
    if (looksLikeGitDir(d)) return configIsClean(join(d, "config")) && configIsClean(join(d, "config.worktree"));
    const dotgit = join(d, ".git");
    if (existsSync(dotgit)) {
      try {
        let gitdir = dotgit;
        if (!statSync(dotgit).isDirectory()) {
          // worktrees and submodules: ".git" is a file pointing at the real git directory
          const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(dotgit, "utf8"));
          if (!m) return false;
          gitdir = resolve(d, m[1].trim());
        }
        const common = existsSync(join(gitdir, "commondir")) ? resolve(gitdir, readFileSync(join(gitdir, "commondir"), "utf8").trim()) : gitdir;
        return configIsClean(join(common, "config")) && configIsClean(join(gitdir, "config.worktree")) && configIsClean(join(common, "config.worktree"));
      } catch {
        return false;
      }
    }
    if (dirname(d) === d) return true; // not a git repository
  }
}
