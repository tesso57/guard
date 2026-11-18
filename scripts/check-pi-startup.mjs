// Run via npm so the pack command uses the same npm CLI on Windows and Unix.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [kind, name] = process.argv.slice(2);
assert.ok(["command", "tool"].includes(kind) && name, "Expected command|tool and a registered name");
const tmp = mkdtempSync(join(tmpdir(), "pi-package-startup-"));
try {
  const [archive] = JSON.parse(execFileSync(process.execPath, [
    process.env.npm_execpath, "pack", "--ignore-scripts", "--json", "--pack-destination", tmp,
  ], { encoding: "utf8" }));
  execFileSync("tar", ["-xzf", join(tmp, archive.filename), "-C", tmp]);
  const pkg = join(tmp, "package");
  symlinkSync(resolve("node_modules"), join(pkg, "node_modules"), "junction");
  const agent = join(tmp, "agent");
  const cwd = join(tmp, "project");
  mkdirSync(agent);
  mkdirSync(cwd);
  writeFileSync(join(agent, "settings.json"), JSON.stringify({ packages: [pkg] }));
  // Inspect the live registry after Pi has bound the installed extension.
  const probe = join(tmp, "probe.mjs");
  writeFileSync(probe, `
    import { writeFileSync } from "node:fs";
    export default function (pi) {
      pi.on("session_start", () => writeFileSync(${JSON.stringify(join(tmp, "registered.json"))},
        JSON.stringify(pi.${kind === "command" ? "getCommands" : "getAllTools"}().map(item => item.name))));
    }
  `);

  const sdk = dirname(dirname(fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent"))));
  const cli = join(sdk, JSON.parse(readFileSync(join(sdk, "package.json"), "utf8")).bin.pi);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    /^(path|systemroot|comspec|pathext|temp|tmp|tmpdir|lang)$/i.test(key)));
  const child = spawnSync(process.execPath, [cli, "--offline", "--mode", "rpc", "--no-session", "-e", probe], {
    cwd, env: { ...env, HOME: tmp, USERPROFILE: tmp, XDG_CONFIG_HOME: tmp, PI_CODING_AGENT_DIR: agent,
      OPENAI_API_KEY: "local-test-only", NO_COLOR: "1" },
    input: '{"id":"startup","type":"get_state"}\n', encoding: "utf8", timeout: 30000,
  });
  if (child.error) throw child.error;
  assert.equal(child.status, 0, child.stderr);
  assert.doesNotMatch(child.stderr, /Extension package "|Failed to load extension|\[Extension issues\]/i);
  const messages = child.stdout.trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
  assert.ok(messages.some(msg => msg.id === "startup" && msg.success), "Pi did not answer get_state");
  assert.ok(JSON.parse(readFileSync(join(tmp, "registered.json"), "utf8")).includes(name),
    `Pi did not register ${kind} ${name}`);
  console.log(`Pi loaded the packed extension and registered ${kind} ${name}.`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
