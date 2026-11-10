import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import test from "node:test";
import { DefaultResourceLoader, SettingsManager } from "@earendil-works/pi-coding-agent";

test("Pi loads guard and registers its command", async () => {
  const dir = await mkdtemp(join(tmpdir(), "guard-pi-smoke-"));
  const previous = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = join(dir, "agent");
  try {
    const entry = resolve("extensions/index.ts");
    const loader = new DefaultResourceLoader({
      cwd: dir,
      agentDir: join(dir, "agent"),
      additionalExtensionPaths: [entry],
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
    });
    await loader.reload();
    const result = loader.getExtensions();
    assert.deepEqual(result.errors, []);
    const extension = result.extensions.find((item) => item.resolvedPath === entry);
    assert.ok(extension, "Pi did not load guard");
    assert.ok(extension.commands.has("guard"), "Pi did not register /guard");
    for (const event of ["session_start", "session_tree", "message_end", "agent_end", "tool_call", "tool_result", "tool_execution_end"]) {
      assert.ok(extension.handlers.get(event)?.length, `Pi did not register guard's ${event} handler`);
    }
  } finally {
    if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previous;
    await rm(dir, { recursive: true, force: true });
  }
});

test("Pi loads the npm-installed package through its manifest", async () => {
  const dir = await mkdtemp(join(tmpdir(), "guard-pi-package-"));
  const previous = process.env.PI_CODING_AGENT_DIR;
  const npmCli = process.env.npm_execpath;
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toLowerCase().startsWith("npm_config_")));
  Object.assign(env, {
    npm_config_cache: join(dir, "cache"),
    npm_config_userconfig: join(dir, "user.npmrc"),
    npm_config_globalconfig: join(dir, "global.npmrc"),
  });
  const npm = (args: string[], cwd: string) => npmCli
    ? execFileSync(process.execPath, [npmCli, ...args], { cwd, env, encoding: "utf8" })
    : execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", args, { cwd, env, encoding: "utf8", shell: process.platform === "win32" });
  try {
    const packed = JSON.parse(npm(["pack", "--ignore-scripts", "--json", "--pack-destination", dir], process.cwd())) as { filename: string }[];
    const project = join(dir, "project");
    await mkdir(project);
    await writeFile(join(project, "package.json"), JSON.stringify({ name: "guard-install-fixture", version: "1.0.0", private: true }));
    npm(["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--legacy-peer-deps", join(dir, packed[0].filename)], project);
    const scope = join(project, "node_modules", "@earendil-works");
    await mkdir(scope, { recursive: true });
    await symlink(resolve("node_modules/@earendil-works/pi-coding-agent"), join(scope, "pi-coding-agent"), process.platform === "win32" ? "junction" : "dir");
    const packageDir = join(project, "node_modules", "guard");
    const manifest = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8")) as { pi: { extensions: string[] } };
    process.env.PI_CODING_AGENT_DIR = join(dir, "agent");
    const loader = new DefaultResourceLoader({
      cwd: project,
      agentDir: join(dir, "agent"),
      additionalExtensionPaths: manifest.pi.extensions.map((entry) => resolve(packageDir, entry)),
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
    });
    await loader.reload();
    const result = loader.getExtensions();
    assert.deepEqual(result.errors, []);
    assert.ok(result.extensions.some((extension) => extension.commands.has("guard")), "installed package did not register /guard");
  } finally {
    if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previous;
    await rm(dir, { recursive: true, force: true });
  }
});

test("Pi installs a local package and loads it from project settings", async () => {
  const dir = await mkdtemp(join(tmpdir(), "guard-pi-install-"));
  const agentDir = join(dir, "agent");
  const previous = process.env.PI_CODING_AGENT_DIR;
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("PI_") && key !== "NODE_OPTIONS"));
  Object.assign(env, { HOME: dir, XDG_CONFIG_HOME: join(dir, "config"), PI_CODING_AGENT_DIR: agentDir });
  try {
    const cli = resolve("node_modules/@earendil-works/pi-coding-agent/dist/cli.js");
    execFileSync(process.execPath, [cli, "install", process.cwd(), "--local", "--approve"], { cwd: dir, env, encoding: "utf8" });
    process.env.PI_CODING_AGENT_DIR = agentDir;
    const loader = new DefaultResourceLoader({
      cwd: dir,
      agentDir,
      settingsManager: SettingsManager.create(dir, agentDir, { projectTrusted: true }),
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
    });
    await loader.reload();
    const result = loader.getExtensions();
    assert.deepEqual(result.errors, []);
    assert.ok(result.extensions.some((extension) => extension.commands.has("guard")), "installed local package did not register /guard");
  } finally {
    if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previous;
    await rm(dir, { recursive: true, force: true });
  }
});
