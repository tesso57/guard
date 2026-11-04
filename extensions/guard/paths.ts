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
    if ([".ssh", ".aws", ".gnupg", ".gpg", ".kube", ".docker", ".azure", ".password-store", ".terraform.d"].includes(first)) return `~/${first}`;
    const two = rel.split(sep).slice(0, 2).join("/");
    if ([".config/gh", ".config/gcloud", ".config/op", ".config/hub", ".cargo/credentials", ".cargo/credentials.toml", ".claude/.credentials.json", ".codex/auth.json"].includes(two))
      return `~/${two}`;
    if ([".netrc", ".npmrc", ".pypirc", ".git-credentials", ".bash_history", ".zsh_history", ".vault-token", ".pgpass", ".my.cnf"].includes(rel)) return `~/${rel}`;
  }
  if (/^\/proc\/[^/]+\/environ$/.test(abs)) return "process environment";
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
      out.push(resolvePath(cwd, v));
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
 * diff.external and textconv on `git diff`/`git log -p`, hooks, includes). Read-only git is only safe when the
 * repository's config sets none of them.
 */
export function gitConfigIsSafe(cwd: string): boolean {
  for (let d = cwd; ; d = dirname(d)) {
    const dotgit = join(d, ".git");
    if (existsSync(dotgit)) {
      try {
        if (!statSync(dotgit).isDirectory()) return false; // worktree or submodule pointer: config lives elsewhere
        const cfg = readFileSync(join(dotgit, "config"), "utf8").toLowerCase();
        return !/fsmonitor|external|textconv|hookspath|\binclude|sshcommand|askpass|editor|pager|alias\]|\bfilter /.test(cfg);
      } catch {
        return false;
      }
    }
    if (dirname(d) === d) return true; // not a git repository
  }
}
