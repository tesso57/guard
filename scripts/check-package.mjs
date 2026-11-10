import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { posix } from "node:path";

const manifest = JSON.parse(readFileSync("package.json", "utf8"));
if (!Array.isArray(manifest.pi?.extensions) || manifest.pi.extensions.length === 0 ||
    !manifest.pi.extensions.every((entry) => typeof entry === "string" && entry.trim())) {
  throw new Error("package.json must declare at least one non-empty pi.extensions entry");
}
const npmCli = process.env.npm_execpath;
const packArgs = ["pack", "--dry-run", "--json", "--ignore-scripts"];
const packed = JSON.parse(npmCli
  ? execFileSync(process.execPath, [npmCli, ...packArgs], { encoding: "utf8" })
  : execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", packArgs, { encoding: "utf8", shell: process.platform === "win32" }));
const files = new Set(packed[0].files.map(({ path }) => path));
function sourceFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    // npm excludes these metadata, configuration and editor files from packages.
    if ([".DS_Store", ".npmignore", ".gitignore", ".npmrc", "npm-debug.log", ".git", ".svn", ".hg", "CVS"].includes(entry.name) ||
        entry.name.startsWith("._") || /^\..*\.swp$/.test(entry.name)) return [];
    const path = posix.join(dir, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : [path];
  });
}
const required = ["package.json", "README.md", "LICENSE", ...manifest.pi.extensions.map((path) => path.replace(/^\.\//, "")), ...sourceFiles("extensions")];
const missing = [...new Set(required)].filter((path) => !files.has(path));
if (missing.length) {
  throw new Error(`Missing from npm package: ${missing.join(", ")}`);
}
console.log(`Package includes ${new Set(required).size} required files.`);
