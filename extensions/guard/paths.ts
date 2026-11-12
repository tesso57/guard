import { existsSync, lstatSync, opendirSync, readlinkSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, matchesGlob, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { AGENT_DIR } from "./config.ts";
import { readRegularText } from "./files.ts";

const HOME = normalize(homedir());
/** Same set pi normalizes to a plain space before resolving tool paths. */
const UNICODE_SPACES = /[   -​  　﻿]/g;

function expandHome(p: string): string {
  if (p === "~") return HOME;
  if (p.startsWith("~/")) return join(HOME, p.slice(2));
  return p.replace(/^\$HOME(?=\/|$)/, HOME).replace(/^\$\{HOME\}(?=\/|$)/, HOME);
}

/**
 * Mirrors pi's own path handling for tool arguments (utils/paths normalizePath): unicode spaces, a leading @, ~,
 * and file:// URLs (with percent-decoding). An unparseable file URL keeps a `file:` marker that is treated as sensitive.
 */
function normalizeInput(p: string): string {
  let q = p.replace(UNICODE_SPACES, " ");
  if (q.startsWith("@")) q = q.slice(1);
  q = expandHome(q);
  if (/^file:\/\//i.test(q)) {
    try {
      q = fileURLToPath(q);
    } catch {
      return `/__guard_unparseable_file_url__/${q}`;
    }
  }
  return q;
}

/** Resolves a path against cwd the way pi does, then normalizes it lexically. Trailing slashes are removed. */
export function resolvePath(cwd: string, p: string): string {
  const q = normalizeInput(p);
  return normalize(isAbsolute(q) ? q : resolve(cwd, q)).replace(/(.)\/+$/, "$1");
}

const realCache = new Map<string, string>();
const memoCache = new Map<string, unknown>();
let globBudget = 8;
/** Milliseconds spent expanding globs in the current judgement. */
let globSpent = 0;
const GLOB_TIME_BUDGET = 300;

/** Clears per-judgement caches, so every judgement sees the current file system. */
export function clearPathCache() {
  realCache.clear();
  memoCache.clear();
  globBudget = 8;
  globSpent = 0;
}

/**
 * Expands a pattern the way bash does: segment by segment, following symlinked directories (node's globSync does
 * not descend into them), with dotfiles matched only by patterns that start with a dot. Its time is charged to the
 * per-judgement budget; `truncated` when there were more than 500 matches or too many entries to look at.
 */
function timedGlob(pattern: string, cwd: string): { list: string[]; truncated: boolean } {
  const t = Date.now();
  const p = simplifyBrackets(pattern);
  try {
    const abs = isAbsolute(p);
    let current = [abs ? "/" : cwd];
    let seen = 0;
    let truncated = false;
    for (const seg of p.split("/").filter((x) => x && x !== ".")) {
      const next: string[] = [];
      if (!/[*?[]/.test(seg)) {
        for (const d of current) next.push(join(d, seg));
      } else {
        for (const d of current) {
          let directory: import("node:fs").Dir;
          try {
            directory = opendirSync(d);
          } catch (error: any) {
            if (error?.code !== "ENOENT" && error?.code !== "ENOTDIR") truncated = true;
            continue;
          }
          try {
            for (;;) {
              let entry: import("node:fs").Dirent | null;
              try { entry = directory.readSync(); } catch { truncated = true; break; }
              if (!entry) break;
              if (++seen > 20_000 || globSpent + Date.now() - t > GLOB_TIME_BUDGET) {
                truncated = true;
                break;
              }
              const name = entry.name;
              if (name.startsWith(".") && !seg.startsWith(".")) continue;
              let hit = false;
              try {
                hit = matchesGlob(name, seg);
              } catch {
                hit = true;
              }
              if (hit) next.push(join(d, name));
              if (next.length > 5000) { truncated = true; break; }
            }
          } finally {
            try { directory.closeSync(); } catch { truncated = true; }
          }
          if (truncated) break;
        }
      }
      if (truncated) return { list: [], truncated: true };
      current = next;
      if (current.length > 5000) {
        truncated = true;
        current = current.slice(0, 5000);
      }
    }
    const existing = current.filter((x) => {
      try {
        lstatSync(x);
        return true;
      } catch {
        return false;
      }
    });
    return { list: existing.slice(0, 500).map((x) => (abs ? x : relative(cwd, x) || ".")), truncated: truncated || existing.length > 500 };
  } finally {
    globSpent += Date.now() - t;
  }
}

/**
 * Whether a wildcard can hand the command a word starting with `-` (an option): the expanded word is checked as
 * bash passes it (a pattern like dir-star/star.md can expand to --pre=./hit.md), and anything guard cannot
 * enumerate counts as such a word.
 */
export function globHitsOptionLikeName(cwd: string, pattern: string): boolean {
  const p = normalizeInput(pattern).replace(/\*\*+/g, "*");
  if (globTooCostly(p, 3)) return true;
  const g = timedGlob(p, cwd);
  return g.truncated || g.list.some((w) => w.startsWith("-"));
}

/** Resolve a repository's Git directory and its shared worktree directory. */
function gitDirectories(root: string): { gitdir: string; common: string } {
  const dotgit = join(root, ".git");
  let gitdir = dotgit;
  if (!statSync(dotgit).isDirectory()) {
    const match = /^gitdir:\s*(.+)$/m.exec(readRegularText(dotgit));
    if (!match) throw new Error("invalid git directory reference");
    gitdir = resolve(root, match[1].trim());
  }
  const commonFile = join(gitdir, "commondir");
  const common = existsSync(commonFile) ? resolve(gitdir, readRegularText(commonFile).trim()) : gitdir;
  return { gitdir, common };
}

/**
 * Whether ripgrep may search hidden files under root although it skips them by default: ignore files can
 * re-include them with `!` patterns.
 */
export function ignoreFilesReinclude(root: string, ignoreVcs = false, ignoreDot = false): boolean {
  return memo(`reinclude:${JSON.stringify([root, ignoreVcs, ignoreDot])}`, () => {
    if (ignoreVcs && ignoreDot) return false;
    let found = false;
    const check = (p: string) => {
      try {
        const text = readRegularText(p);
        if (text.split("\n").some((line) => /^\s*!/.test(line) && !/^\s*![A-Za-z0-9_][A-Za-z0-9._-]*\s*$/.test(line))) found = true;
      } catch (e: any) { if (e?.code !== "ENOENT" && e?.code !== "ENOTDIR") found = true; }
    };
    // An unknown Git configuration may redirect core.excludesFile to an arbitrary ignore file.
    if (!ignoreVcs && !gitConfigIsSafe(root)) return true;
    const home = process.env.HOME;
    if (!ignoreVcs && home) check(join(process.env.XDG_CONFIG_HOME || join(home, ".config"), "git", "ignore"));
    for (let d = root; ; d = dirname(d)) {
      for (const n of [...(ignoreDot ? [] : [".ignore", ".rgignore"]), ...(ignoreVcs ? [] : [".gitignore"])]) check(join(d, n));
      if (!ignoreVcs) {
        try {
          const { common } = gitDirectories(d);
          check(join(common, "info", "exclude"));
        } catch (e: any) { if (e?.code !== "ENOENT" && e?.code !== "ENOTDIR") found = true; }
      }
      if (dirname(d) === d || isHomeOrAncestor(d)) break;
    }
    const complete = walkBounded(root, (p, name) => {
      if (!found && ((!ignoreDot && (name === ".ignore" || name === ".rgignore")) || (!ignoreVcs && name === ".gitignore"))) check(p);
    }, 12, 20_000, new Set([".git"]), (_path, name) => !name.startsWith("."));
    return found || !complete;
  });
}

/**
 * Whether a wildcard pattern can reach a protected root, decided from the pattern alone (no file system access), so
 * an expansion that was skipped or cut short cannot hide it. `into`: some match may lie inside a root;
 * `around`: some match may be a root or one of its parents (deleting or moving it affects the root).
 */
export function globMayReach(cwd: string, pattern: string, roots: string[]): { into: boolean; around: boolean } {
  const raw = normalizeInput(pattern).replace(/\*\*+/g, "*");
  if (!roots.length) return { into: false, around: false };
  if (globSyntaxTooCostly(raw) || roots.some((root) => root.length > 4096 || root.split("/").some((segment) => segment.length > 255))) return { into: true, around: true };
  const q = simplifyBrackets(raw);
  const abs = normalize(isAbsolute(q) ? q : `${cwd}/${q}`);
  if (globStructureTooCostly(abs)) return { into: true, around: true };
  const pSegs = abs.split("/").filter(Boolean);
  let into = false;
  let around = false;
  const test = (path: string, pat: string[]) => {
    try {
      return matchesGlob(path, `/${pat.join("/")}`);
    } catch {
      return true; // a pattern we cannot evaluate counts as reaching
    }
  };
  for (const r of roots) {
    const rSegs = r.split("/").filter(Boolean);
    if (pSegs.length >= rSegs.length && test(`/${rSegs.join("/")}`, pSegs.slice(0, rSegs.length))) into = true;
    if (pSegs.length <= rSegs.length && test(`/${rSegs.slice(0, pSegs.length).join("/")}`, pSegs)) around = true;
  }
  return { into, around };
}

/**
 * Replaces bracket expressions that node's matcher does not understand ([[=c=]], [[.c.]], [[:print:]]) with `?`,
 * which matches at least as much: wider matches are the safe side for every check that uses them.
 */
function simplifyBrackets(p: string): string {
  let out = "";
  for (let i = 0; i < p.length; i++) {
    if (p[i] !== "[") {
      out += p[i];
      continue;
    }
    let j = i + 1;
    if (p[j] === "!" || p[j] === "^") j++;
    if (p[j] === "]") j++;
    let special = false;
    while (j < p.length && p[j] !== "]") {
      if (p[j] === "[" && /[=.:]/.test(p[j + 1] ?? "")) {
        special = true;
        const close = p.indexOf(`${p[j + 1]}]`, j + 2);
        j = close === -1 ? p.length : close + 2;
      } else j++;
    }
    if (special && j < p.length) {
      out += "?";
      i = j;
    } else out += p[i];
  }
  return out;
}

/** Avoid feeding potentially exponential patterns to Node's synchronous glob matcher. */
function globStructureTooCostly(p: string): boolean {
  return (p.match(/\[/g)?.length ?? 0) > 16 || /[?*+@!]\(|[{}]/.test(p) || p.split("/").some((segment) => segment.length > 255 || (segment.match(/\*+/g)?.length ?? 0) > 2);
}

function globSyntaxTooCostly(p: string): boolean {
  return p.length > 256 || globStructureTooCostly(p);
}

/** Patterns node's glob may take super-linear time on, or that the per-judgement time budget no longer allows. */
function globTooCostly(p: string, maxWildSegments: number): boolean {
  const wild = p.split("/").filter((s) => /[*?[]/.test(s)).length;
  return globSyntaxTooCostly(p) || wild > maxWildSegments || globSpent > GLOB_TIME_BUDGET;
}

/** Memoizes work within one judgement (cleared by clearPathCache). */
export function memo<T>(key: string, fn: () => T): T {
  if (memoCache.has(key)) return memoCache.get(key) as T;
  const v = fn();
  if (memoCache.size > 1000) memoCache.clear();
  memoCache.set(key, v);
  return v;
}

/** Stands for paths guard did not enumerate (glob limits); never freely readable, never sensitive. */
export const UNKNOWN_PATH = "/__guard_unexpanded__";

/**
 * Resolves a path the way the kernel would open it: component by component, following symlinks (also dangling
 * ones, whose target does not exist yet) and applying `..` after the symlinks before it. Parts that do not exist
 * are kept as written.
 */
export function realPath(p: string): string {
  const cached = realCache.get(p);
  if (cached !== undefined) return cached;
  let parts = p.split("/").filter(Boolean);
  let cur = "/";
  let hops = 0;
  let missing = false;
  while (parts.length) {
    const seg = parts.shift()!;
    if (seg === ".") continue;
    if (seg === "..") {
      cur = dirname(cur);
      continue;
    }
    const next = join(cur, seg);
    if (!missing) {
      try {
        const st = lstatSync(next);
        if (st.isSymbolicLink() && hops++ < 40) {
          const target = readlinkSync(next);
          parts = [...target.split("/").filter(Boolean), ...parts];
          if (isAbsolute(target)) cur = "/";
          continue;
        }
      } catch {
        missing = true;
      }
    }
    cur = next;
  }
  if (realCache.size > 10_000) realCache.clear();
  realCache.set(p, cur);
  return cur;
}

/** Every way a path token may be interpreted: lexically, and physically (symlinks and `..` resolved in order). */
export function pathVariants(cwd: string, p: string): string[] {
  const q = normalizeInput(p);
  const lexical = resolvePath(cwd, p);
  const physical = realPath(isAbsolute(q) ? q : `${cwd}/${q}`);
  const out = physical === lexical ? [lexical] : [lexical, physical];
  // Keep /proc/<pid>/{root,cwd,fd} visible: normalizing `..` away would hide that the path goes through them
  if (/^\/proc\/[^/]+\/(root|cwd|fd)(\/|$)/.test(q)) out.push(q);
  return out;
}

/** Extra spellings pi's read tool tries, in its lookup order, when the requested path is absent. */
export function readFallbackVariants(cwd: string, p: string): string[] {
  const original = resolvePath(cwd, p);
  if (existsSync(original)) return [];
  const nfd = original.normalize("NFD");
  const candidates = [
    original.replace(/ (AM|PM)\./gi, "\u202F$1."),
    nfd,
    original.replace(/'/g, "\u2019"),
    nfd.replace(/'/g, "\u2019"),
  ];
  for (const candidate of candidates) {
    if (candidate !== original && existsSync(candidate)) return [candidate, realPath(candidate)];
  }
  return [];
}

function containsPath(child: string, parent: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/** Case-insensitive containment for protective checks, including case-insensitive file systems. */
export function isInside(child: string, parent: string): boolean {
  return containsPath(child.toLowerCase(), parent.toLowerCase());
}

/** Permission shortcuts require an exact match; case folding can join distinct directories on Linux. */
export function isInsideExact(child: string, parent: string): boolean {
  return containsPath(child, parent);
}

/** True for `/`, the home directory and every directory between them. */
export function isHomeOrAncestor(p: string): boolean {
  return isInside(HOME, p) || isInside(realPath(HOME), realPath(p));
}

/** System locations whose contents are public on a normal machine. */
const PUBLIC_DIRS = [
  "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/opt/homebrew", "/System", "/Library/Developer", "/dev/null",
  "/etc/os-release", "/etc/lsb-release", "/etc/hosts", "/etc/timezone", "/etc/debian_version", "/etc/alpine-release",
];

/**
 * Code under the agent directory: pi's own releases and the packages, extensions, skills, prompts and themes it
 * loads. Reading it is like reading /usr (writing stays hard-denied). Credentials, settings, sessions and guard's
 * own state live elsewhere in the agent directory and stay protected.
 */
export const PI_CODE_DIRS = ["install", "git", "npm", "extensions", "skills", "prompts", "themes"];
export function isPiCodePath(p: string): boolean {
  const real = realPath(p);
  return PI_CODE_DIRS.some((d) => {
    const base = join(AGENT_DIR, d);
    const realBase = realPath(base);
    return (isInsideExact(p, base) || isInsideExact(p, realBase)) && isInsideExact(real, realBase);
  });
}

/** Folders another extension vouched for (guard:trust-dir), e.g. an artifacts extension's output folder. */
export type TrustedDir = { path: string; write: boolean; by: string; ignored?: string };
export type TrustedDirState = {
  trustedDirs: TrustedDir[];
  trustedDirTargets: Map<string, string>;
  trustedDirAliases: Map<string, Set<string>>;
  version: number;
};
export const createTrustedDirState = (): TrustedDirState => ({ trustedDirs: [], trustedDirTargets: new Map(), trustedDirAliases: new Map(), version: 0 });
const defaultTrustedDirState = createTrustedDirState();
// Home-level folders that hold credentials, tool configuration or executables on PATH
const UNTRUSTABLE_HOME_DIRS = new Set([".ssh", ".gnupg", ".aws", ".azure", ".gcloud", ".kube", ".docker", ".config", ".local", ".npm", ".cargo", ".rustup", ".gem", ".bun", ".deno", ".volta", ".nvm", ".pyenv", ".rbenv", "library", "bin"]);

/** Registers a folder; returns why it was refused, if it was. Only folders inside the home directory (or tmp) qualify. */
export function trustDir(raw: string, write: boolean, by: string, state: TrustedDirState): string | undefined {
  const { trustedDirs, trustedDirTargets, trustedDirAliases } = state;
  state.version++;
  // Trust events may arrive after a path or symlink changed since the last call.
  realCache.clear();
  memoCache.clear();
  const reason = ((): string | undefined => {
    if (!isAbsolute(raw) && !raw.startsWith("~")) return "not an absolute path";
    const abs = resolvePath(HOME, raw);
    const real = realPath(abs);
    const tmp = normalize(tmpdir());
    if (isHomeOrAncestor(abs) || isHomeOrAncestor(real)) return "the home directory or above is too broad";
    const underHome = isInsideExact(abs, HOME) && isInsideExact(real, realPath(HOME));
    const underTemp = isInsideExact(abs, tmp) && abs !== tmp && isInsideExact(real, realPath(tmp));
    if (!underHome && !underTemp) return "only folders inside the home or temporary directory can be trusted";
    const first = relative(underHome ? HOME : tmp, abs).split(sep)[0].toLowerCase();
    if (UNTRUSTABLE_HOME_DIRS.has(first) || sensitiveReason(abs) || sensitiveReason(real)) return "holds credentials, tool configuration or programs";
    for (const x of [abs, real]) if (isInside(x, AGENT_DIR) || isInside(AGENT_DIR, x) || isInside(realPath(AGENT_DIR), x)) return "overlaps pi's agent directory";
    return undefined;
  })();
  const entry: TrustedDir = { path: raw.startsWith("~") || isAbsolute(raw) ? resolvePath(HOME, raw) : raw, write, by, ignored: reason };
  const target = realPath(entry.path);
  const aliases = new Set([entry.path, target]);
  // A new grant for the same physical folder replaces its old permissions,
  // even if an extension used a different symlink or canonical spelling.
  for (let i = trustedDirs.length - 1; i >= 0; i--) {
    const previous = trustedDirs[i];
    if (previous.path === entry.path || (!entry.ignored && !previous.ignored && trustedDirTargets.get(previous.path) === target)) {
      if (!entry.ignored && !previous.ignored && trustedDirTargets.get(previous.path) === target) {
        for (const alias of trustedDirAliases.get(previous.path) ?? []) aliases.add(alias);
      }
      trustedDirTargets.delete(previous.path);
      trustedDirAliases.delete(previous.path);
      trustedDirs.splice(i, 1);
    }
  }
  trustedDirTargets.set(entry.path, target);
  trustedDirAliases.set(entry.path, aliases);
  trustedDirs.push(entry);
  return reason;
}
export const listTrustedDirs = (state: TrustedDirState): readonly TrustedDir[] => state.trustedDirs;

/** Return the path relative to a registered spelling of the trusted folder. */
export function trustedDirRelative(p: string, dir: TrustedDir, state: TrustedDirState = defaultTrustedDirState): string | undefined {
  const base = [...(state.trustedDirAliases.get(dir.path) ?? [])].find((alias) => isInsideExact(p, alias));
  return base === undefined ? undefined : relative(base, p);
}

/** The trusted folder p is in (literally and after resolving symlinks), if any; `write` requires write access. */
export function trustedDirFor(p: string, write: boolean, state: TrustedDirState = defaultTrustedDirState): TrustedDir | undefined {
  if (p === UNKNOWN_PATH) return undefined;
  const real = realPath(p);
  return state.trustedDirs.find((d) => {
    const realBase = realPath(d.path);
    const matchesAlias = trustedDirRelative(p, d, state) !== undefined;
    return !d.ignored && state.trustedDirTargets.get(d.path) === realBase && (!write || d.write) && matchesAlias && isInsideExact(real, realBase);
  });
}

/** A regular file with more than one hard link may be the same file as something outside the project. */
export function isHardLinked(p: string): boolean {
  try {
    // A symlink can point to an in-project hard link whose other name is outside the project.
    const st = statSync(p);
    return st.isFile() && st.nlink > 1;
  } catch {
    return false;
  }
}

/** Find an existing hard link to protected state without following directory links or scanning indefinitely. */
export function isProtectedHardLink(p: string, roots: string[]): boolean {
  let target: import("node:fs").BigIntStats;
  try {
    target = statSync(p, { bigint: true });
    if (!target.isFile() || target.nlink < 2n) return false;
  } catch { return false; }
  const protectedFiles = memo(`protected-hardlinks:${JSON.stringify(roots)}`, () => {
    const ids = new Set<string>();
    const queue = [...new Set(roots)];
    const deadline = Date.now() + 200;
    let cursor = 0;
    while (cursor < queue.length && cursor < 10_000 && Date.now() < deadline) {
      const item = queue[cursor++];
      try {
        const entry = lstatSync(item, { bigint: true });
        const st = entry.isSymbolicLink() ? statSync(item, { bigint: true }) : entry;
        if (st.isFile() && st.nlink > 1n) ids.add(`${st.dev}:${st.ino}`);
        if (entry.isDirectory()) {
          const directory = opendirSync(item);
          try {
            while (queue.length < 10_000 && Date.now() < deadline) {
              const child = directory.readSync();
              if (!child) break;
              queue.push(join(item, child.name));
            }
          } finally {
            directory.closeSync();
          }
        }
      } catch { /* unavailable paths cannot establish identity */ }
    }
    return ids;
  });
  return protectedFiles.has(`${target.dev}:${target.ino}`);
}

/** A project path must remain in the project after resolving symlinks. */
export function isProjectPath(p: string, cwd: string): boolean {
  const real = realPath(p);
  return p !== UNKNOWN_PATH && !isHomeOrAncestor(cwd) &&
    (isInsideExact(p, cwd) || isInsideExact(p, realPath(cwd))) && isInsideExact(real, realPath(cwd));
}

/** Whether all links to a project file are visible inside the project and none has a sensitive name. */
export function isProjectHardlinkSafe(p: string, cwd: string): boolean {
  if (!isProjectPath(p, cwd)) return false;
  try {
    const target = statSync(p, { bigint: true });
    if (!target.isFile() || target.nlink < 2n) return false;
    const scan = memo(`project-hardlinks:${cwd}`, () => {
      const links = new Map<string, { count: bigint; sensitive: boolean }>();
      let uncertain = false;
      const complete = walkBounded(cwd, (path) => {
        try {
          const st = lstatSync(path, { bigint: true });
          if (!st.isFile() || st.nlink < 2n) return;
          const key = `${st.dev}:${st.ino}`;
          const item = links.get(key) ?? { count: 0n, sensitive: false };
          item.count++;
          item.sensitive ||= !!sensitiveReason(path);
          links.set(key, item);
        } catch { uncertain = true; }
      }, 12, 20_000, new Set());
      return { links, complete: complete && !uncertain };
    });
    const entry = scan.links.get(`${target.dev}:${target.ino}`);
    return scan.complete && !!entry && !entry.sensitive && entry.count >= target.nlink;
  } catch { return false; }
}

/** Reads inside the project or public directories, without hard-linked files, may skip judgement. */
export function isFreelyReadable(p: string, cwd: string, state?: TrustedDirState): boolean {
  if (p === UNKNOWN_PATH) return false;
  const real = realPath(p);
  const project = isProjectPath(p, cwd);
  const publicPath = PUBLIC_DIRS.some((d) => isInsideExact(p, d) && isInsideExact(real, realPath(d))) || isPiCodePath(p) || !!trustedDirFor(p, false, state);
  return (project || publicPath) && !isHardLinked(p);
}

function sensitiveOne(abs: string): string | undefined {
  if (abs.startsWith("/__guard_unparseable_file_url__/")) return "unparseable file:// URL";
  if (abs === UNKNOWN_PATH) return undefined;
  const home = isInside(abs, HOME) ? HOME : realPath(HOME);
  // Containment is case-insensitive for protection, so compute the relative path the same way.
  const rel = isInside(abs, home) ? relative(home.toLowerCase(), abs.toLowerCase()) : undefined;
  const first = rel?.split(sep)[0];
  if (rel !== undefined && first) {
    if ([".ssh", ".aws", ".gnupg", ".gpg", ".kube", ".docker", ".azure", ".password-store", ".terraform.d", ".m2", ".gradle"].includes(first)) return `~/${first}`;
    const two = rel.split(sep).slice(0, 2).join("/");
    if ([".config/gh", ".config/gcloud", ".config/op", ".config/hub", ".config/rclone", ".config/sops", ".config/github-copilot", ".cargo/credentials", ".cargo/credentials.toml", ".claude/.credentials.json", ".codex/auth.json", ".gem/credentials"].includes(two))
      return `~/${two}`;
    if ([".netrc", ".npmrc", ".pypirc", ".git-credentials", ".bash_history", ".zsh_history", ".python_history", ".psql_history", ".vault-token", ".pgpass", ".my.cnf", ".terraformrc", ".yarnrc.yml", ".claude.json", ".s3cfg"].includes(rel)) return `~/${rel}`;
    if (rel.startsWith(join(".cache", "huggingface")) || rel.startsWith(join(".local", "share", "fish"))) return `~/${two}`;
  }
  if (/^\/proc\/.*\/environ$/.test(abs)) return "process environment";
  if (/^\/proc\/[^/]+\/(root|cwd)(\/|$)/.test(abs)) return "another view of the file system through /proc";
  const b = basename(abs);
  if (/^\.env(\..+)?$/i.test(b) && !/\.(example|sample|template)$/i.test(b)) return `.env file (${b})`;
  if (/\.(pem|key|p12|pfx|keystore|jks)$/i.test(b)) return `key file (${b})`;
  if (/^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i.test(b)) return `SSH key (${b})`;
  if (b.toLowerCase() === "auth.json" && isInside(abs, AGENT_DIR)) return "pi credentials";
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

/** True if moving, deleting or overwriting p would also affect a protected root (p is the root or one of its parents). */
export function containsProtectedRoot(p: string, roots: string[]): boolean {
  const real = realPath(p);
  // Only roots that exist can be moved or deleted along with a parent; this keeps `mv build ..` usable
  return roots.some((r) => existsSync(r) && (isInside(r, p) || isInside(realPath(r), real)));
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
  "gulpfile.js", "gruntfile.js", "karma.conf.js", "bunfig.toml", ".pnpmfile.cjs", ".gitlab-ci.yml", "jenkinsfile", "taskfile.yml",
  "taskfile.yaml", "flake.nix", "shell.nix", "default.nix", "vagrantfile", "workspace", "workspace.bazel", ".bazelrc", "meson.build",
  "build.ninja", "procfile", ".npmignore", "tsconfig.json", ".git",
]);

export function isRiskyProjectFile(rel: string): boolean {
  const parts = rel.toLowerCase().split(sep);
  const b = parts[parts.length - 1];
  return (
    // Names that look like options (--pre=sh) turn into options when a wildcard expands to them
    parts.some((x) => x.startsWith("-")) ||
    // Names carrying shell syntax become code when a wildcard hands them to something that evaluates them
    /\$\(|`|[\n\r]/.test(rel) ||
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
    if (!t || t.length > 4096) continue;
    let v: string;
    if (t.startsWith("--")) v = t.includes("=") ? t.slice(t.indexOf("=") + 1) : "";
    else if (t.startsWith("-")) {
      // A value glued to a cluster of short options (-m/path, -bf/etc/x, -f~/x): the tail from the first
      // path-like character counts, however many option letters come before it
      const m = /[/~.$]/.exec(t.slice(1));
      v = m ? t.slice(1 + m.index) : "";
    } else v = t.includes("=") ? t.slice(t.indexOf("=") + 1) : t;
    if (!v) continue;
    // Bare names count when they look secret (id_rsa, cert.p12) or name an existing file in cwd
    if (/^(~|\/|\.|\$HOME|file:)/i.test(v) || v.includes("/") || /\.(env|pem|key|p12|pfx)$/i.test(v) || /^id_[a-z0-9]+/.test(v) || existsSync(resolve(cwd, v)))
      out.push(...pathVariants(cwd, v));
  }
  for (const g of globs) out.push(...expandGlob(cwd, g));
  return out;
}

/** The directory a glob starts from (the part before the first wildcard). */
function globBase(cwd: string, pattern: string): string {
  const p = normalizeInput(pattern);
  const segs = p.split("/");
  const firstGlob = segs.findIndex((s) => /[*?[]/.test(s));
  return resolvePath(cwd, segs.slice(0, Math.max(firstGlob, 0)).join("/") || (isAbsolute(p) ? "/" : "."));
}

/**
 * The static directory a glob starts from, plus its matches.
 * Returns UNKNOWN_PATH as well when the shell might match more than guard can enumerate: hidden-file patterns
 * (bash 3.2 lets `.*` match `..`), more than three wildcard segments, or the per-judgement expansion budget.
 * `**` is not recursive in bash without globstar, so it is treated as `*`.
 */
function expandGlob(cwd: string, pattern: string): string[] {
  const p = normalizeInput(pattern).replace(/\*\*+/g, "*");
  const segs = p.split("/");
  const out = [globBase(cwd, pattern)];
  const wild = segs.filter((s) => /[*?[]/.test(s));
  if (globTooCostly(p, 3) || globBudget-- <= 0) return [...out, UNKNOWN_PATH];
  // bash 3.2 lets `.*` match `..` and node's glob does not, so hidden-file patterns may reach more than we see
  if (wild.some((s) => s.startsWith("."))) out.push(UNKNOWN_PATH);
  try {
    const g = timedGlob(p, cwd);
    out.push(...g.list.map((m) => resolvePath(cwd, m)));
    if (g.truncated) out.push(UNKNOWN_PATH);
  } catch {
    out.push(UNKNOWN_PATH);
  }
  return out;
}

/**
 * Existing matches of a write or delete target pattern, plus its static base directory.
 * `complete` is false when the pattern was too costly to expand; callers then treat the base as the target.
 */
export function expandGlobFully(cwd: string, pattern: string): { matches: string[]; base: string; complete: boolean } {
  const p = normalizeInput(pattern).replace(/\*\*+/g, "*");
  const base = globBase(cwd, pattern);
  if (globTooCostly(p, 6)) return { matches: [], base, complete: false };
  try {
    const g = timedGlob(p, cwd);
    return { matches: g.list.map((m) => resolvePath(cwd, m)), base, complete: !g.truncated };
  } catch {
    return { matches: [], base, complete: false };
  }
}

const SKIP_WALK = new Set(["node_modules", ".git", ".hg", ".svn", "dist", "build", "target", ".venv", "venv", "__pycache__"]);

/** Walks a directory tree with bounded depth and entry count, calling fn for each file. Returns false if cut short. */
export function walkBounded(root: string, fn: (path: string, name: string) => void, maxDepth = 6, maxEntries = 5000, skip = SKIP_WALK, descend?: (path: string, name: string) => boolean): boolean {
  let seen = 0;
  let complete = true;
  const visit = (dir: string, depth: number) => {
    if (depth > maxDepth || seen > maxEntries) {
      complete = false;
      return;
    }
    let directory: import("node:fs").Dir;
    try {
      directory = opendirSync(dir);
    } catch {
      complete = false;
      return;
    }
    try {
      for (;;) {
        let entry: import("node:fs").Dirent | null;
        try { entry = directory.readSync(); } catch { complete = false; return; }
        if (!entry) return;
        if (++seen > maxEntries) {
          complete = false;
          return;
        }
        const p = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!skip.has(entry.name) && (!descend || descend(p, entry.name))) visit(p, depth + 1);
        } else fn(p, entry.name);
      }
    } finally {
      try { directory.closeSync(); } catch { complete = false; }
    }
  };
  visit(root, 0);
  return complete;
}

/**
 * Files under root that likely hold secrets (.env, keys), for recursive content searches.
 * `complete` is false when the tree was too large or deep to check; build and dependency directories are included,
 * because `grep -r` reads them too.
 */
export function secretFilesUnder(root: string, projectRoot?: string, suffixes?: readonly string[], includeHidden = true): { files: string[]; complete: boolean } {
  return memo(`secrets:${JSON.stringify([root, projectRoot, suffixes, includeHidden])}`, () => {
    const files: string[] = [];
    if (isHomeOrAncestor(root)) return { files: [root], complete: true };
    let uncertain = false;
    const complete = walkBounded(root, (p) => {
      if (!includeHidden && relative(root, p).split(sep).some((part) => part.startsWith("."))) return;
      if (suffixes && !suffixes.some((suffix) => basename(p).toLowerCase().endsWith(suffix))) return;
      try {
        const st = lstatSync(p);
        if (st.isSymbolicLink()) {
          if (sensitiveReason(p)) files.push(p);
        } else {
          if (sensitiveOne(p)) files.push(p);
          // A hard link can expose a secret through an innocuous name; its other paths are unknown.
          if (st.isFile() && st.nlink > 1 && !(projectRoot && isProjectHardlinkSafe(p, projectRoot))) uncertain = true;
        }
      } catch { uncertain = true; }
    }, 12, 20_000, new Set(), (_path, name) => includeHidden || !name.startsWith("."));
    return { files, complete: complete && !uncertain };
  });
}

/** Project files changed in the last day, which a test runner may load (also from earlier sessions). */
export function recentlyChangedFiles(root: string, limit = 20): string[] {
  return memo(`recent:${root}`, () => {
    const out: { p: string; m: number }[] = [];
    const since = Date.now() - 24 * 3600_000;
    walkBounded(root, (p) => {
      try {
        const st = statSync(p);
        if (st.mtimeMs > since && st.size < 200_000) out.push({ p, m: st.mtimeMs });
      } catch { /* vanished */ }
    });
    return out.sort((a, b) => b.m - a.m).slice(0, limit).map((x) => x.p);
  });
}

/**
 * Git runs commands named in a repository's config even for read-only subcommands (core.fsmonitor on `git status`,
 * diff drivers and textconv on `git diff`/`git log -p`, filters, gpg, hooks). Read-only git is only safe when the
 * repository's config (including config.worktree) sets none of them. Keys are parsed, so branch names or URLs that
 * merely contain such words do not count; anything the parser cannot read counts as unsafe.
 */
const DANGEROUS_GIT_KEY = [
  /^core\.(fsmonitor|hookspath|sshcommand|askpass|gitproxy|alternaterefscommand|worktree|excludesfile)$/,
  /^diff\.external$/,
  // Credential helpers and lazy fetches (partial clones) can run programs during read-only git commands
  /^credential\.(.*\.)?helper$/,
  /^extensions\.partialclone$/,
  /^remote\..*\.(promisor|partialclonefilter)$/,
  /^(filter|diff|merge|gpg|credential|uploadpack|receive|remote|url)\..*\.(clean|smudge|process|command|textconv|program|driver|uploadpack|receivepack|helper)$/,
  /^gpg\.program$/,
  /\.(command|program|textconv|cmd)$/,
  /^include\.path$/,
  /^includeif\..*\.path$/,
  /^extensions\.worktreeconfig$/,
];

/** Parsed keys, or undefined when a line cannot be understood. */
function gitConfigKeys(text: string): string[] | undefined {
  // git's continuation and escaping rules (even inside comments) are subtle; any line ending in a backslash is unsafe
  if (/\\\r?$/m.test(text)) return undefined;
  const lines = text.split(/\r?\n/);
  const keys: string[] = [];
  let section = "";
  for (const raw of lines) {
    let line = raw.trim();
    while (line) {
      if (line.startsWith("#") || line.startsWith(";")) break;
      const sec = /^\[\s*([^\]\s"]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]/.exec(line);
      if (sec) {
        // [section "sub"] and the legacy [section.sub] both become section.sub; a key may follow on the same line
        section = (sec[2] !== undefined ? `${sec[1]}.${sec[2]}` : sec[1]).toLowerCase();
        line = line.slice(sec[0].length).trim();
        continue;
      }
      const key = /^([A-Za-z][\w-]*)\s*(=|$)/.exec(line);
      if (!key || !section) return undefined;
      keys.push(`${section}.${key[1].toLowerCase()}`);
      break;
    }
  }
  return keys;
}

function configIsClean(file: string): boolean {
  // Git documents /dev/null as a way to disable configuration; it cannot supply executable settings.
  if (file === "/dev/null") {
    try { return statSync(file).isCharacterDevice(); } catch { return false; }
  }
  let text: string;
  try {
    text = readRegularText(file);
  } catch (e: any) {
    return e?.code === "ENOENT";
  }
  const keys = gitConfigKeys(text);
  return !!keys && !keys.some((k) => DANGEROUS_GIT_KEY.some((re) => re.test(k)));
}

/** A directory git would use as a repository by itself (HEAD, objects/ and refs/). */
function looksLikeGitDir(d: string): boolean {
  return existsSync(join(d, "HEAD")) && existsSync(join(d, "objects")) && existsSync(join(d, "refs"));
}

function gitHooksAreSafe(dir: string): boolean {
  let directory: import("node:fs").Dir;
  try {
    directory = opendirSync(join(dir, "hooks"));
  } catch (e: any) {
    return e?.code === "ENOENT";
  }
  let safe = false;
  try {
    let seen = 0;
    for (;;) {
      const entry = directory.readSync();
      if (!entry) { safe = true; break; }
      if (++seen > 1000 || !entry.name.endsWith(".sample")) break;
    }
  } catch {
    safe = false;
  } finally {
    try { directory.closeSync(); } catch { safe = false; }
  }
  return safe;
}

/** Git can load executable settings outside the repository and redirect discovery through its environment. */
function gitEnvironmentIsSafe(cwd: string): boolean {
  const env = process.env;
  if (["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_EXTERNAL_DIFF"].some((key) => !!env[key])) return false;
  if (env.GIT_PAGER && env.GIT_PAGER !== "cat") return false;
  const home = env.HOME;
  const globalConfigs = env.GIT_CONFIG_GLOBAL !== undefined
    ? [resolve(cwd, env.GIT_CONFIG_GLOBAL)]
    : home ? [join(env.XDG_CONFIG_HOME || join(home, ".config"), "git", "config"), join(home, ".gitconfig")] : [];
  if (!home && env.GIT_CONFIG_GLOBAL === undefined) return false;
  // Git's compiled-in system config location varies by installation; do not guess it or run git
  // before approval. A shortcut is safe only when system config is disabled or its path is explicit.
  if (!/^(1|true|yes|on)$/i.test(env.GIT_CONFIG_NOSYSTEM ?? "")) {
    if (!env.GIT_CONFIG_SYSTEM || !configIsClean(resolve(cwd, env.GIT_CONFIG_SYSTEM))) return false;
  }
  return globalConfigs.every(configIsClean);
}

/** Follows git's discovery order: `<dir>/.git` first, then `<dir>` itself as a git directory, then the parent. */
export function gitConfigIsSafe(cwd: string): boolean {
  if (!gitEnvironmentIsSafe(cwd)) return false;
  for (let d = cwd; ; d = dirname(d)) {
    const dotgit = join(d, ".git");
    if (existsSync(dotgit)) {
      try {
        const { gitdir, common } = gitDirectories(d);
        // Submodules have their own configs, which `git status` in the parent also honors
        if (existsSync(join(common, "modules")) || existsSync(join(d, ".gitmodules"))) return false;
        // Some hooks run on read-only commands (post-index-change on `git status`); any real hook makes git unsafe
        if (!gitHooksAreSafe(common)) return false;
        return configIsClean(join(common, "config")) && configIsClean(join(gitdir, "config.worktree")) && configIsClean(join(common, "config.worktree"));
      } catch {
        return false;
      }
    }
    if (looksLikeGitDir(d)) return gitHooksAreSafe(d) && configIsClean(join(d, "config")) && configIsClean(join(d, "config.worktree"));
    if (dirname(d) === d) return true; // not a git repository
  }
}
