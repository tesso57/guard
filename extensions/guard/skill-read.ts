import { statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { types as utilTypes } from "node:util";
import { AGENT_DIR } from "./config.ts";
import { clearPathCache, isInsideExact, realPath, resolvePath } from "./paths.ts";
import { inputPaths, inspectExecutablePath, usesRipgrepConfig } from "./policy.ts";
import { isReadOnlyArgv, parseShell } from "./shell.ts";

/** Only plain reads of Pi's standard skill locations bypass guard. */
export function isSkillRead(tool: string, input: unknown, cwd: string): boolean {
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
    const inside = (path: string) => roots.some((root) => isInsideExact(realPath(path), realPath(root)) && (isInsideExact(path, root) || isInsideExact(path, realPath(root))));
    if (tool === "read") {
      const path = resolvePath(cwd, field.value);
      return inside(path) && statSync(path).isFile();
    }
    if (process.env.BASH_ENV || process.env.ENV || process.env.BASHOPTS || process.env.SHELLOPTS || Object.keys(process.env).some((name) => name.startsWith("BASH_FUNC_") && name.endsWith("%%"))) return false;
    const parsed = parseShell(field.value);
    if (!parsed.ok || parsed.dynamic.length || parsed.globs.length || parsed.writes.length || parsed.heredocBodies.length || parsed.subs.length !== 1) return false;
    const sub = parsed.subs[0];
    if (sub.assigns.length || sub.reads.length || sub.heredocs.length || !["cat", "head", "tail", "sed", "rg"].includes(sub.argv[0]) || !isReadOnlyArgv(sub.argv)) return false;
    if (sub.argv.slice(1).some((arg) => arg === "-" || /^-f/.test(arg) || /^--file(?:=|$)/.test(arg))) return false;
    if (usesRipgrepConfig(parsed) || inspectExecutablePath(parsed, cwd).risk) return false;
    const paths = inputPaths("bash", input, cwd, parsed);
    return paths.reads.length > 0 && paths.writes.length === 0 && paths.reads.every((path) => {
      if (!inside(path)) return false;
      const stat = statSync(path);
      return stat.isFile() || (sub.argv[0] === "rg" && stat.isDirectory());
    });
  } catch { return false; }
}
