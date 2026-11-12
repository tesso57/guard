import { statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { types as utilTypes } from "node:util";
import { AGENT_DIR } from "./config.ts";
import { clearPathCache, isInsideExact, pathVariants, realPath, resolvePath } from "./paths.ts";
import { inputPaths, inspectExecutablePath, usesRipgrepConfig } from "./policy.ts";
import { grepExplicitPaths, isReadOnlyArgv, parseShell, rgExplicitPaths } from "./shell.ts";

export type RegisteredSkill = { path: string; target: string };

/** Only plain reads of standard skill locations or Pi-registered skill files bypass guard. */
export function isSkillRead(tool: string, input: unknown, cwd: string, registeredSkills: readonly RegisteredSkill[] = []): boolean {
  try {
    if (!input || typeof input !== "object" || utilTypes.isProxy(input)) return false;
    const key = tool === "read" ? "path" : tool === "bash" ? "command" : undefined;
    if (!key) return false;
    const field = Object.getOwnPropertyDescriptor(input, key);
    if (!field || !("value" in field) || typeof field.value !== "string") return false;
    clearPathCache();
    const roots = [join(homedir(), ".agents", "skills"), join(AGENT_DIR, "skills"), join(cwd, ".pi", "skills")];
    for (let dir = cwd; ; dir = dirname(dir)) {
      roots.push(join(dir, ".agents", "skills"));
      if (dirname(dir) === dir) break;
    }
    const inside = (path: string) => roots.some((root) => isInsideExact(realPath(path), realPath(root)) && (isInsideExact(path, root) || isInsideExact(path, realPath(root)))) ||
      registeredSkills.some((skill) => isAbsolute(skill.path) && realPath(skill.path) === skill.target && realPath(path) === skill.target);
    if (tool === "read") {
      const path = resolvePath(cwd, field.value);
      return inside(path) && statSync(path).isFile();
    }
    if (process.env.BASH_ENV || process.env.ENV || process.env.BASHOPTS || process.env.SHELLOPTS || Object.keys(process.env).some((name) => name.startsWith("BASH_FUNC_") && name.endsWith("%%"))) return false;
    const parsed = parseShell(field.value);
    if (!parsed.ok || parsed.dynamic.length || parsed.globs.length || parsed.writes.length || parsed.heredocBodies.length || !parsed.subs.length) return false;
    const grepTargets: string[] = [];
    const pipeline = parsed.subs.length > 1 && parsed.operators.length === parsed.subs.length - 1 && parsed.operators.every((operator) => operator === "|");
    let pipedGrep = false;
    for (const [index, sub] of parsed.subs.entries()) {
      if (sub.assigns.length || sub.reads.length || sub.heredocs.length || !["cat", "head", "tail", "sed", "rg", "grep"].includes(sub.argv[0]) || !isReadOnlyArgv(sub.argv)) return false;
      if (sub.argv.slice(1).some((arg) => arg === "-" || /^-f/.test(arg) || /^--file(?:=|$)/.test(arg))) return false;
      if (sub.argv[0] === "grep" && (process.env.GREP_OPTIONS || sub.argv.slice(1).some((arg) => /^-[^-]*f/.test(arg)))) return false;
      if (sub.argv[0] === "grep") {
        const paths = grepExplicitPaths(sub.argv, pipeline && index > 0);
        if (!paths) return false;
        if (!paths.length) pipedGrep = true;
        grepTargets.push(...paths.flatMap((path) => pathVariants(cwd, path.startsWith("-") ? `./${path}` : path)));
      }
      if (sub.argv[0] === "rg") {
        const explicit = rgExplicitPaths(sub.argv);
        if (!explicit?.length || explicit.some((path) => !inside(resolvePath(cwd, path)))) return false;
      }
    }
    if (usesRipgrepConfig(parsed) || inspectExecutablePath(parsed, cwd).risk) return false;
    if (pipedGrep) {
      const first = parsed.subs[0];
      if (!["cat", "grep", "rg"].includes(first.argv[0])) return false;
      const source = inputPaths("bash", { command: `${field.value}\0source` }, cwd, { ...parsed, subs: [first], subcommands: [first.argv] });
      if (!source.reads.length || source.writes.length || !source.reads.every(inside)) return false;
    }
    const otherSubs = parsed.subs.filter((sub) => sub.argv[0] !== "grep");
    const other = otherSubs.length ? inputPaths("bash", input, cwd, { ...parsed, subs: otherSubs, subcommands: otherSubs.map((sub) => sub.argv) }) : { reads: [], writes: [] };
    const paths = [...grepTargets, ...other.reads];
    return paths.length > 0 && other.writes.length === 0 && paths.every((path) => {
      if (!inside(path)) return false;
      const stat = statSync(path);
      return stat.isFile() || (parsed.subs.some((sub) => ["rg", "grep"].includes(sub.argv[0])) && stat.isDirectory());
    });
  } catch { return false; }
}
