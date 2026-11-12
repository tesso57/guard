import { statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { types as utilTypes } from "node:util";
import { AGENT_DIR } from "./config.ts";
import { clearPathCache, isInsideExact, isProjectHardlinkSafe, isProjectPath, pathVariants, realPath, resolvePath, secretFilesUnder } from "./paths.ts";
import { inputPaths, inspectBuiltinSearchExecutable, inspectExecutablePath, usesRipgrepConfig } from "./policy.ts";
import { grepExplicitPaths, isReadOnlyArgv, parseShell, rgExplicitPaths, rgListsFiles, rgReadsStdin, rgUsesPatternFile } from "./shell.ts";

export type RegisteredSkill = { path: string; target: string };

/** Only plain reads of standard skill locations or Pi-registered skill files bypass guard. */
export function isSkillRead(tool: string, input: unknown, cwd: string, registeredSkills: readonly RegisteredSkill[] = []): boolean {
  try {
    if (!input || typeof input !== "object" || utilTypes.isProxy(input)) return false;
    const key = ["read", "ls", "grep", "find"].includes(tool) ? "path" : tool === "bash" ? "command" : undefined;
    if (!key) return false;
    const field = Object.getOwnPropertyDescriptor(input, key);
    if (!field && key in input) return false;
    if (field && (!("value" in field) || (field.value !== undefined && typeof field.value !== "string"))) return false;
    if (!["ls", "grep", "find"].includes(tool) && (!field || !("value" in field) || typeof field.value !== "string")) return false;
    const value = field && "value" in field && typeof field.value === "string" ? field.value : "";
    clearPathCache();
    const roots = [join(homedir(), ".agents", "skills"), join(AGENT_DIR, "skills"), join(cwd, ".pi", "skills")];
    for (let dir = cwd; ; dir = dirname(dir)) {
      roots.push(join(dir, ".agents", "skills"));
      if (dirname(dir) === dir) break;
    }
    const inside = (path: string) => roots.some((root) => isInsideExact(realPath(path), realPath(root)) && (isInsideExact(path, root) || isInsideExact(path, realPath(root)))) ||
      registeredSkills.some((skill) => isAbsolute(skill.path) && realPath(skill.path) === skill.target && realPath(path) === skill.target);
    if (tool === "read") {
      const path = resolvePath(cwd, value);
      const stat = statSync(path);
      return inside(path) && stat.isFile() && (stat.nlink <= 1 || isProjectHardlinkSafe(path, cwd));
    }
    if (tool === "ls") {
      const path = resolvePath(cwd, value || ".");
      return inside(path) && statSync(path).isDirectory();
    }
    if (tool === "grep" || tool === "find") {
      // Older Pi versions may not suppress ripgrep's ambient configuration.
      if (tool === "grep" && process.env.RIPGREP_CONFIG_PATH) return false;
      const fields = tool === "grep" ? { pattern: "string", glob: "string", ignoreCase: "boolean", literal: "boolean", context: "number", limit: "number" } : { pattern: "string", limit: "number" };
      for (const [name, type] of Object.entries(fields)) {
        const descriptor = Object.getOwnPropertyDescriptor(input, name);
        if (!descriptor && name in input) return false;
        if (!descriptor) { if (name === "pattern") return false; continue; }
        if (!("value" in descriptor) || (descriptor.value !== undefined && typeof descriptor.value !== type) || (name === "pattern" && typeof descriptor.value !== "string")) return false;
        if (name === "glob" && typeof descriptor.value === "string" && descriptor.value.startsWith("-")) return false;
        if (typeof descriptor.value === "number" && !Number.isFinite(descriptor.value)) return false;
      }
      const path = resolvePath(cwd, value || ".");
      const executable = inspectBuiltinSearchExecutable(tool, cwd);
      if (!inside(path) || executable.risk || !executable.available) return false;
      const stat = statSync(path);
      if (tool === "find") return stat.isDirectory();
      if (stat.isFile()) return stat.nlink <= 1 || isProjectHardlinkSafe(path, cwd);
      return stat.isDirectory() && secretFilesUnder(path, isProjectPath(path, cwd) ? cwd : undefined).complete;
    }
    if (process.env.BASH_ENV || process.env.ENV || process.env.BASHOPTS || process.env.SHELLOPTS || Object.keys(process.env).some((name) => name.startsWith("BASH_FUNC_") && name.endsWith("%%"))) return false;
    const parsed = parseShell(value);
    if (!parsed.ok || parsed.dynamic.length || parsed.globs.length || parsed.writes.length || parsed.heredocBodies.length || !parsed.subs.length) return false;
    const grepTargets: string[] = [];
    const pipeline = parsed.subs.length > 1 && parsed.operators.length === parsed.subs.length - 1 && parsed.operators.every((operator) => operator === "|");
    let pipedSearch = false;
    for (const [index, sub] of parsed.subs.entries()) {
      if (sub.assigns.length || sub.reads.length || sub.heredocs.length || !["cat", "head", "tail", "sed", "rg", "grep"].includes(sub.argv[0]) || !isReadOnlyArgv(sub.argv)) return false;
      if (!["grep", "rg"].includes(sub.argv[0]) && sub.argv.slice(1).includes("-")) return false;
      if (sub.argv[0] === "grep" && process.env.GREP_OPTIONS) return false;
      if (sub.argv[0] === "rg" && rgUsesPatternFile(sub.argv)) return false;
      if (sub.argv[0] === "grep") {
        const paths = grepExplicitPaths(sub.argv, pipeline && index > 0);
        if (!paths) return false;
        if (!paths.length) pipedSearch = true;
        grepTargets.push(...paths.flatMap((path) => pathVariants(cwd, path.startsWith("-") ? `./${path}` : path)));
      }
      if (sub.argv[0] === "rg") {
        const explicit = rgExplicitPaths(sub.argv);
        if (!explicit || explicit.includes("-")) return false;
        if (!explicit.length) {
          if (!pipeline || index === 0 || !rgReadsStdin(sub.argv)) return false;
          pipedSearch = true;
        } else if (explicit.some((path) => !inside(resolvePath(cwd, path)))) return false;
      }
    }
    if (usesRipgrepConfig(parsed) || inspectExecutablePath(parsed, cwd).risk) return false;
    if (pipedSearch) {
      const first = parsed.subs[0];
      if (!["cat", "grep", "rg"].includes(first.argv[0])) return false;
      const source = inputPaths("bash", { command: `${value}\0source` }, cwd, { ...parsed, subs: [first], subcommands: [first.argv] });
      if (!source.reads.length || source.writes.length || !source.reads.every(inside)) return false;
    }
    const otherSubs = parsed.subs.filter((sub) => sub.argv[0] !== "grep");
    const other = otherSubs.length ? inputPaths("bash", input, cwd, { ...parsed, subs: otherSubs, subcommands: otherSubs.map((sub) => sub.argv) }) : { reads: [], writes: [] };
    const paths = [...grepTargets, ...other.reads];
    const onlyFileLists = parsed.subs.every((sub) => {
      if (sub.argv[0] === "grep") return grepExplicitPaths(sub.argv, true)?.length === 0;
      if (sub.argv[0] === "rg") return rgListsFiles(sub.argv) || rgExplicitPaths(sub.argv)?.length === 0;
      return true;
    });
    // A file operand can skip hard-link inspection only if no pipeline command reads file contents.
    const nonListingSubs = parsed.subs.filter((sub) => !rgListsFiles(sub.argv));
    const nonListingPaths = nonListingSubs.length ? inputPaths("bash", { command: `${value}\0non-listing` }, cwd, { ...parsed, subs: nonListingSubs, subcommands: nonListingSubs.map((sub) => sub.argv) }) : { reads: [], writes: [] };
    const onlyListFileOperands = onlyFileLists && !nonListingPaths.reads.length && !nonListingPaths.writes.length;
    return paths.length > 0 && other.writes.length === 0 && paths.every((path) => {
      if (!inside(path)) return false;
      const stat = statSync(path);
      if (stat.isFile()) return onlyListFileOperands || stat.nlink <= 1 || isProjectHardlinkSafe(path, cwd);
      return parsed.subs.some((sub) => ["rg", "grep"].includes(sub.argv[0])) && stat.isDirectory() &&
        (onlyFileLists || secretFilesUnder(path, isProjectPath(path, cwd) ? cwd : undefined).complete);
    });
  } catch { return false; }
}
