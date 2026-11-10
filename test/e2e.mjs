// End-to-end test: runs the real pi (print mode, no UI) with guard loaded, a mock model and a mock Decisions API.
// Every command is harmless even if guard failed to block it (writes stay in temp dirs, scripts only echo).
import http from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readlinkSync, symlinkSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";

if (process.platform === "darwin") {
  // Watching this process releases the assertion even if the test is killed abruptly.
  const sleepGuard = spawn("/usr/bin/caffeinate", ["-i", "-w", String(process.pid)], { stdio: "ignore" });
  sleepGuard.on("error", () => console.error("E2E: could not prevent idle sleep"));
  sleepGuard.unref();
  process.on("exit", () => { try { sleepGuard.kill(); } catch { /* already exited */ } });
}

const temporaryDirs = [];
process.on("exit", () => {
  for (const dir of temporaryDirs.reverse()) rmSync(dir, { recursive: true, force: true });
});
const tempDir = (prefix) => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirs.push(dir);
  return dir;
};
function processSummary(stdout = "", stderr = "") {
  const known = new Set(["session", "agent_start", "turn_start", "message_start", "message_update", "message_end", "tool_execution_start", "tool_execution_update", "tool_execution_end", "turn_end", "agent_end"]);
  const recent = [];
  for (const line of stdout.slice(-65_536).split("\n")) {
    try {
      const event = JSON.parse(line);
      if (known.has(event?.type)) recent.push(event.type);
    } catch { /* a partial line or non-JSON output is omitted */ }
  }
  return `stdout_chars=${stdout.length}, stderr_chars=${stderr.length}, recent_events=${recent.slice(-12).join(",") || "none"}`;
}
const requestStats = { model: 0, decisions: 0 };
async function waitForChild(child, label, snapshot = () => ({})) {
  const startWall = Date.now(), startMonotonic = performance.now();
  const startRequests = { ...requestStats };
  let lastHeartbeat = startMonotonic, maxHeartbeatGap = 0;
  const heartbeat = setInterval(() => {
    const now = performance.now();
    maxHeartbeatGap = Math.max(maxHeartbeatGap, now - lastHeartbeat);
    lastHeartbeat = now;
  }, 1000);
  let timedOut = false;
  const killer = setTimeout(() => {
    maxHeartbeatGap = Math.max(maxHeartbeatGap, performance.now() - lastHeartbeat);
    timedOut = true;
    child.kill("SIGKILL");
  }, 40_000);
  try {
    const [code] = await once(child, "close");
    if (timedOut) {
      const { stdout, stderr } = snapshot();
      const elapsedWall = Date.now() - startWall;
      const elapsedMonotonic = Math.round(performance.now() - startMonotonic);
      throw new Error(`Pi E2E ${label} exceeded its 40-second deadline (${processSummary(stdout, stderr)}, wall_ms=${elapsedWall}, monotonic_ms=${elapsedMonotonic}, max_heartbeat_gap_ms=${Math.round(maxHeartbeatGap)}, model_requests=${requestStats.model - startRequests.model}, decisions_requests=${requestStats.decisions - startRequests.decisions})`);
    }
    return code;
  } finally {
    clearTimeout(killer);
    clearInterval(heartbeat);
  }
}
const AGENT = tempDir("e2e-agent-");
const PROJ = tempDir("e2e-proj-");
const HOME = tempDir("e2e-home-");
const PACKAGE = tempDir("e2e-package-");
const readRacePath = join(tempDir("e2e-read-race-"), "ordinary.txt");
const readRaceSecret = join(HOME, ".ssh", "id_rsa");
const inlineStartupCommand = "env SHELLOPTS=xtrace 'PS4=$(printf ran > trace-executed)' bash -c 'echo safe'";
const incompleteSearchCommand = "grep -r needle e2e-deep";
const redactedCommand = "echo --token=opaque-fake-secret$(printf ran > redacted-executed)";
const fakeAgeIdentity = `AGE-SECRET-KEY-1${"Q".repeat(58)}`;
const fakeYamlSecret = "opaque-fake-yaml-secret";
const fakeEscapedYamlSecret = "opaque-fake-escaped-yaml-secret";
const fakeNamedYamlSecret = "opaque-fake-named-yaml-secret";
const fakeInlineYamlSecret = "opaque-fake-inline-yaml-secret";
const fakeNestedYamlSecret = "opaque-fake-nested-yaml-secret";
const fakeDirectNestedYamlSecret = "opaque-fake-direct-nested-yaml-secret";
const fakeYamlListSecrets = ["opaque-fake-yaml-list-one", "opaque-fake-yaml-list-two"];
const fakeFlowYamlSecret = "opaque-fake-flow-yaml-secret";
const fakeMergeYamlSecret = "opaque-fake-merge-yaml-secret";
const mergeScriptCommand = "sh e2e-merge-script.sh";
const escapedYamlKey = String.raw`"api\u005fkey"`;
const redactedScriptCommand = "sh e2e-redacted-script.sh";
const redactedIntentCommand = "sh -c 'printf ran > redacted-intent-executed'";
const fakeIntentSecret = "opaque-fake-user-secret";
const fakeHistorySecret = "opaque-fake-history-secret";
const redactedHistoryCommand = "sh -c 'printf ran > redacted-history-executed'";
const redactedPastCommand = "sh -c 'printf ran > redacted-past-executed'";
const redactedApprovalCommand = "sh -c 'printf ran > redacted-approval-executed'";
const fakePastSecret = "sk-fake-past-abcdefghijklmnopqrstuv";
const fakeCwdSecret = `ghp_${"A".repeat(36)}`;
const redactedCwdCommand = "sh -c 'printf ran > redacted-cwd-executed'";
const unsafeShellEnvironment = (key) => ["BASH_ENV", "ENV", "BASHOPTS", "SHELLOPTS", "PS4", "NODE_OPTIONS"].includes(key) || key.startsWith("BASH_FUNC_");
const packEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toLowerCase().startsWith("npm_config_") && !unsafeShellEnvironment(key)));
Object.assign(packEnv, { HOME, XDG_CONFIG_HOME: join(HOME, ".config"), npm_config_cache: join(HOME, ".npm-cache"), npm_config_userconfig: join(HOME, ".npmrc"), npm_config_globalconfig: join(HOME, ".npm-globalrc") });
const packed = JSON.parse(execFileSync("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", PACKAGE], { encoding: "utf8", env: packEnv }));
const tarEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !["TAR_OPTIONS", "GZIP", "BZIP2", "XZ_DEFAULTS", "XZ_OPT"].includes(key)));
execFileSync("tar", ["-xzf", join(PACKAGE, packed[0].filename), "-C", PACKAGE], { env: tarEnv });
const unpacked = join(PACKAGE, "package");
const manifest = JSON.parse(readFileSync(join(unpacked, "package.json"), "utf8"));
const extensionEntry = join(unpacked, manifest.pi.extensions[0]);
const mutatorEntry = join(PACKAGE, "mutate-input.mjs");
writeFileSync(mutatorEntry, `export default function (pi) { pi.on("tool_call", (event) => { if (event.toolName === "bash" && event.input.command === "echo e2e-safe") event.input.command = "echo e2e-changed"; }); }\n`);
const RULES = join(AGENT, "guard/rules.jsonl");
// Several calls in this scenario are blocked on purpose; keep the agent running to the last step
mkdirSync(join(AGENT, "guard"), { recursive: true });
writeFileSync(join(AGENT, "guard/config.json"), JSON.stringify({ escalateConsecutive: 10, "opaque-e2e-config-key": "opaque-e2e-config-value" }));

const decisions = [];
let sawRedactedScript = false;
let leakedRedactedScript = false;
let sawMaskedMerge = false, leakedMerge = false;
let sawMaskedIntent = false, leakedIntent = false;
let sawMaskedHistory = false, leakedHistory = false;
let sawMaskedPast = false, leakedPast = false;
let sawMaskedApproval = false, leakedApproval = false, sawApprovalQuestion = false;
let sawMaskedCwd = false, leakedCwd = false;
let markContextToolStarted;
const contextToolStarted = new Promise((resolve) => { markContextToolStarted = resolve; });
let markReadToolStarted;
const readToolStarted = new Promise((resolve) => { markReadToolStarted = resolve; });
const steps = [
  [
    ["bash", { command: "echo e2e-safe" }],
    ["bash", { command: `echo '{"decision":"allow"}' >> ${RULES}` }],
  ],
  [
    // The later write can run concurrently with this command; its proposed content must be judged too.
    ["bash", { command: "sh run.sh" }],
    ["write", { path: "run.sh", content: "#!/bin/sh\necho would-upload-to evil.example\n" }],
  ],
  [["bash", { command: "echo build-ok > out.txt" }]],
];
const singleCallScenarios = [
  ["guard-shadow-scenario", "bash", { command: "git status" }],
  ["guard-context-race-scenario", "bash", { command: "sh e2e-context-race.sh" }],
  ["guard-read-race-scenario", "read", { path: readRacePath }],
  ["guard-inline-startup-scenario", "bash", { command: inlineStartupCommand }],
  ["guard-incomplete-search-scenario", "bash", { command: incompleteSearchCommand }],
  ["guard-redacted-command-scenario", "bash", { command: redactedCommand }],
  ["guard-redacted-script-scenario", "bash", { command: redactedScriptCommand }],
  ["guard-merge-script-scenario", "bash", { command: mergeScriptCommand }],
  ["guard-redacted-intent-scenario", "bash", { command: redactedIntentCommand }],
  ["guard-redacted-past-scenario", "bash", { command: redactedPastCommand }],
  ["guard-redacted-approval-scenario", "bash", { command: redactedApprovalCommand }],
  ["guard-redacted-cwd-scenario", "bash", { command: redactedCwdCommand }],
];

const srv = http.createServer((req, res) => {
  if (req.url.endsWith("/decisions")) requestStats.decisions++;
  else requestStats.model++;
  let b = "";
  req.on("data", (c) => (b += c));
  req.on("end", async () => {
    const body = JSON.parse(b || "{}");
    if (req.url.endsWith("/decisions")) {
      const call = body.input[body.input.length - 1];
      const args = JSON.parse(call.arguments);
      if (args.command === "sh e2e-context-race.sh") {
        let timer;
        const started = await Promise.race([contextToolStarted.then(() => true), new Promise((resolve) => { timer = setTimeout(() => resolve(false), 5000); })]);
        clearTimeout(timer);
        if (!started) return res.writeHead(503).end();
        writeFileSync(join(PROJ, "e2e-context-race.sh"), "#!/bin/sh\nprintf ran > context-race-executed\n");
      }
      if (args.path === readRacePath) {
        let timer;
        const started = await Promise.race([readToolStarted.then(() => true), new Promise((resolve) => { timer = setTimeout(() => resolve(false), 5000); })]);
        clearTimeout(timer);
        if (!started) return res.writeHead(503).end();
        rmSync(readRacePath);
        symlinkSync(readRaceSecret, readRacePath);
      }
      // guard's own context (cwd and attached files) is the item right before the pending call
      const judged = JSON.stringify(body.input.slice(-2));
      const serializedBody = JSON.stringify(body);
      if (args.command === redactedScriptCommand) {
        const context = JSON.parse(body.input.at(-2).output);
        sawRedactedScript ||= Object.entries(context.files).some(([path, content]) => path.endsWith("/e2e-redacted-script.sh") && typeof content === "string" && content.includes("[REDACTED age identity]") && content.includes("token: |\n  [REDACTED]\nname: visible-yaml") && content.includes(`${escapedYamlKey}: |\n  [REDACTED]`) && content.includes("name: API_TOKEN\n    value: |\n      [REDACTED]") && content.includes("value: [REDACTED]\n    name: DB_PASSWORD") && content.includes("name: SECRET\n    value: [REDACTED]") && content.includes("credentials: [REDACTED]") && content.includes("api_key: [REDACTED]\nflow_env:") && content.includes(`name: API_TOKEN, note: user's label, note2: abc:'open, value: "[REDACTED]"`) && content.includes("visible-debug"));
      }
      if (args.command === mergeScriptCommand) {
        const context = JSON.parse(body.input.at(-2).output);
        sawMaskedMerge ||= Object.entries(context.files).some(([path, content]) => path.endsWith("/e2e-merge-script.sh") && content === "[REDACTED YAML merge]");
        leakedMerge ||= serializedBody.includes(fakeMergeYamlSecret);
      }
      leakedRedactedScript ||= serializedBody.includes(fakeAgeIdentity) || serializedBody.includes(fakeYamlSecret) || serializedBody.includes(fakeEscapedYamlSecret) || serializedBody.includes(fakeNamedYamlSecret) || serializedBody.includes(fakeInlineYamlSecret) || serializedBody.includes(fakeNestedYamlSecret) || serializedBody.includes(fakeDirectNestedYamlSecret) || serializedBody.includes(fakeFlowYamlSecret) || fakeYamlListSecrets.some((secret) => serializedBody.includes(secret));
      if (args.command === redactedIntentCommand) {
        sawMaskedIntent ||= body.input.some((item) => item.role === "user" && Array.isArray(item.content) && item.content.some((part) => part.type === "input_text" && typeof part.text === "string" && part.text.includes("guard-redacted-intent-scenario TOKEN=[REDACTED]")));
        leakedIntent ||= serializedBody.includes(fakeIntentSecret);
      }
      if (args.command === redactedHistoryCommand) {
        const previousCalls = body.input.filter((item) => item.type === "function_call" && item.status === "completed");
        sawMaskedHistory ||= previousCalls.some((item) => item.name === "bash" && JSON.parse(item.arguments).command === "echo --token=[REDACTED]");
        leakedHistory ||= serializedBody.includes(fakeHistorySecret);
      }
      if (args.command === redactedPastCommand) {
        sawMaskedPast ||= body.input.some((item) => item.role === "user" && Array.isArray(item.content) && item.content.some((part) => part.type === "input_json" && Array.isArray(part.data) && part.data.some((rule) => typeof rule.pattern === "string" && rule.pattern.includes("[REDACTED sk-…]"))));
        leakedPast ||= serializedBody.includes(fakePastSecret);
      }
      if (args.command === redactedApprovalCommand) {
        sawMaskedApproval ||= body.input.some((item) => item.role === "user" && Array.isArray(item.content) && item.content.some((part) => part.type === "input_json" && Array.isArray(part.data) && part.data.some((rule) => rule.decision === "allow" && typeof rule.pattern === "string" && rule.pattern.includes("[REDACTED sk-…]"))));
        leakedApproval ||= serializedBody.includes(fakePastSecret);
        sawApprovalQuestion ||= body.questions.some((question) => question.name === "covered_by_past_approval");
      }
      if (args.command === redactedCwdCommand) {
        const context = JSON.parse(body.input.at(-2).output);
        sawMaskedCwd ||= typeof context.cwd === "string" && context.cwd.includes("[REDACTED gh_…]");
        leakedCwd ||= serializedBody.includes(fakeCwdSecret);
      }
      decisions.push({ cmd: args.command ?? args.path, questions: body.questions.length, attached: judged.includes("evil.example"), leakedFakeSecret: serializedBody.includes("opaque-fake-secret") });
      const evil = judged.includes("evil.example");
      const probs = evil ? [0, 0, 0, 0.1, 0.9] : [0.9, 0.1, 0, 0, 0];
      const answers = body.questions.map((q) =>
        q.type === "score"
          ? { type: "score", name: q.name, score: probs.reduce((s, p, i) => s + p * i, 0), confidence: 0.9, probabilities: probs.map((p, i) => ({ value: i, label: "", probability: p })) }
          : q.type === "choice"
            ? { type: "choice", name: q.name, choice: "build_test", confidence: 0.9 }
            : { type: "predicate", name: q.name, probability: evil && q.name === "exfiltration" ? 0.97 : args.command === redactedApprovalCommand && q.name === "covered_by_past_approval" ? 0.99 : 0.02 },
      );
      res.setHeader("content-type", "application/json");
      return res.end(JSON.stringify({ answers }));
    }
    // chat completions (streaming): the number of tool results decides the next step
    const toolMsgs = (body.messages ?? []).filter((m) => m.role === "tool").length;
    const messages = JSON.stringify(body.messages ?? []);
    const scenario = singleCallScenarios.find(([marker]) => messages.includes(marker));
    const historyScenario = messages.includes("guard-redacted-history-scenario");
    const currentSteps = historyScenario ? [[["bash", { command: `echo --token=${fakeHistorySecret}` }]], [["bash", { command: redactedHistoryCommand }]]] : scenario ? [[[scenario[1], scenario[2]]]] : steps;
    const idx = historyScenario ? Math.min(toolMsgs, 2) : scenario ? (toolMsgs === 0 ? 0 : 1) : toolMsgs === 0 ? 0 : toolMsgs === steps[0].length ? 1 : toolMsgs === steps[0].length + steps[1].length ? 2 : 3;
    res.setHeader("content-type", "text/event-stream");
    const send = (o) => res.write(`data: ${JSON.stringify(o)}\n\n`);
    const base = { id: "x", object: "chat.completion.chunk", created: 0, model: "mock-1" };
    if (idx < currentSteps.length) {
      currentSteps[idx].forEach(([name, args], i) =>
        send({ ...base, choices: [{ index: 0, delta: { ...(i === 0 ? { role: "assistant" } : {}), tool_calls: [{ index: i, id: `call_${idx}_${i}`, type: "function", function: { name, arguments: JSON.stringify(args) } }] }, finish_reason: null }] }),
      );
      send({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } });
    } else {
      send({ ...base, choices: [{ index: 0, delta: { role: "assistant", content: "done" }, finish_reason: null }] });
      send({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 10, completion_tokens: 1, total_tokens: 11 } });
    }
    res.end("data: [DONE]\n\n");
  });
}).listen(0, "127.0.0.1");
await once(srv, "listening", { signal: AbortSignal.timeout(5000) });
const address = srv.address();
const url = `http://127.0.0.1:${address.port}/v1`;
const configureMockModel = (dir) => writeFileSync(join(dir, "models.json"), JSON.stringify({ providers: { mock: { baseUrl: url, api: "openai-completions", apiKey: "mock", models: [{ id: "mock-1" }] } } }));
const scenarioAgent = (prefix) => {
  const dir = tempDir(prefix);
  configureMockModel(dir);
  return dir;
};
configureMockModel(AGENT);

// Exercise the test configuration regardless of the invoking user's guard, Pi, or Git settings.
const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
  !["GIT_", "RISK_", "GUARD_", "OPENAI_", "PI_"].some((prefix) => key.startsWith(prefix)) &&
  !["RIPGREP_CONFIG_PATH", "CDPATH", "OLDPWD"].includes(key) && !unsafeShellEnvironment(key) &&
  !(process.platform !== "win32" && key.toLowerCase() === "path" && key !== "PATH") &&
  !["http_proxy", "https_proxy", "all_proxy", "no_proxy"].includes(key.toLowerCase()),
));
Object.assign(childEnv, { HOME, XDG_CONFIG_HOME: join(HOME, ".config"), GIT_PAGER: "cat", GIT_CONFIG_NOSYSTEM: "1", PI_CODING_AGENT_DIR: AGENT, OPENAI_BASE_URL: url, GUARD_OPENAI_API_KEY: "sk-test-e2e" });
if (process.platform !== "win32") childEnv.PATH = "/usr/bin:/bin";
execFileSync("git", ["init", "-q", PROJ], { env: childEnv, stdio: "pipe" });
const child = spawn(
  process.execPath,
  [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-e", mutatorEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "build the project"],
  { cwd: PROJ, env: childEnv },
);
let out = "", err = "";
child.stdout.on("data", (d) => (out += d));
child.stderr.on("data", (d) => (err += d));
child.stdin.end();
const code = await waitForChild(child, "main", () => ({ stdout: out, stderr: err }));
const normalDecisions = [...decisions];
const normalOutput = existsSync(join(PROJ, "out.txt")) ? readFileSync(join(PROJ, "out.txt"), "utf8").trim() : undefined;
const auditF = join(AGENT, "guard/audit.jsonl");
const auditText = existsSync(auditF) ? readFileSync(auditF, "utf8") : "";
// A directory at the audit path makes logging fail without affecting files outside this fixture.
rmSync(auditF, { force: true });
mkdirSync(auditF);
const recoveryEntry = join(PACKAGE, "recover-audit.mjs");
writeFileSync(recoveryEntry, `import { rmdirSync } from "node:fs";\nexport default function (pi) { pi.on("tool_result", (event) => { if (event.toolName === "bash" && event.input.command === "echo e2e-safe") { rmdirSync(${JSON.stringify(auditF)}); process.stderr.write("audit-fixture-restored\\n"); } }); }\n`);
const failedAuditChild = spawn(
  process.execPath,
  [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-e", recoveryEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "build the project"],
  { cwd: PROJ, env: childEnv },
);
let failedAuditOut = "", failedAuditErr = "";
failedAuditChild.stdout.on("data", (d) => (failedAuditOut += d));
failedAuditChild.stderr.on("data", (d) => (failedAuditErr += d));
failedAuditChild.stdin.end();
const failedAuditCode = await waitForChild(failedAuditChild, "audit recovery", () => ({ stdout: failedAuditOut, stderr: failedAuditErr }));
let recoveredAuditText = "";
try { recoveredAuditText = readFileSync(auditF, "utf8"); } catch { /* reported by checks below */ }
rmSync(join(PROJ, "out.txt"), { force: true });
writeFileSync(join(AGENT, "guard/config.json"), JSON.stringify({ escalateConsecutive: 1 }));
// Verify Pi discovers the unpacked distribution through configured packages.
writeFileSync(join(AGENT, "settings.json"), JSON.stringify({ packages: [unpacked] }));
const escalationChild = spawn(
  process.execPath,
  [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "build the project"],
  { cwd: PROJ, env: childEnv },
);
let escalationOut = "", escalationErr = "";
escalationChild.stdout.on("data", (d) => (escalationOut += d));
escalationChild.stderr.on("data", (d) => (escalationErr += d));
escalationChild.stdin.end();
const escalationCode = await waitForChild(escalationChild, "escalation", () => ({ stdout: escalationOut, stderr: escalationErr }));
let shadowCode, shadowOut = "", shadowErr = "", shadowAudits = [];
let casePathCode, casePathOut = "", casePathErr = "", casePathAudits = [];
if (process.platform !== "win32") {
  const shadowAgent = scenarioAgent("e2e-shadow-agent-");
  mkdirSync(join(shadowAgent, "bin"), { recursive: true });
  writeFileSync(join(shadowAgent, "bin", "git"), "#!/bin/sh\nprintf ran > shadow-ran\n", { mode: 0o755 });
  const shadowChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-shadow-scenario"],
    { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: shadowAgent } },
  );
  shadowChild.stdout.on("data", (d) => (shadowOut += d));
  shadowChild.stderr.on("data", (d) => (shadowErr += d));
  shadowChild.stdin.end();
  shadowCode = await waitForChild(shadowChild, "PATH shadow", () => ({ stdout: shadowOut, stderr: shadowErr }));
  const shadowAuditFile = join(shadowAgent, "guard", "audit.jsonl");
  shadowAudits = existsSync(shadowAuditFile) ? readFileSync(shadowAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
  const caseAgent = scenarioAgent("e2e-case-path-agent-");
  const caseBin = tempDir("e2e-case-path-bin-");
  writeFileSync(join(caseBin, "git"), "#!/bin/sh\nprintf ran > case-shadow-ran\n", { mode: 0o755 });
  const caseNotifier = join(PACKAGE, "case-path-notifier.mjs");
  writeFileSync(caseNotifier, `export default function () { if (Object.keys(process.env).find((key) => key.toLowerCase() === "path") === "path") process.stderr.write("guard-case-order-ok\\n"); }\n`);
  const caseEnv = Object.fromEntries(Object.entries(childEnv).filter(([key]) => key.toLowerCase() !== "path"));
  caseEnv.path = "/usr/bin";
  caseEnv.PATH = `${caseBin}:/usr/bin:/bin`;
  caseEnv.PI_CODING_AGENT_DIR = caseAgent;
  const caseChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", caseNotifier, "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-shadow-scenario"],
    { cwd: PROJ, env: caseEnv },
  );
  caseChild.stdout.on("data", (d) => (casePathOut += d));
  caseChild.stderr.on("data", (d) => (casePathErr += d));
  caseChild.stdin.end();
  casePathCode = await waitForChild(caseChild, "PATH case", () => ({ stdout: casePathOut, stderr: casePathErr }));
  const caseAuditFile = join(caseAgent, "guard", "audit.jsonl");
  casePathAudits = existsSync(caseAuditFile) ? readFileSync(caseAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
} else {
  console.log("skip e2e: executable PATH shadow check is Unix-only");
}
const contextAgent = scenarioAgent("e2e-context-agent-");
writeFileSync(join(PROJ, "e2e-context-race.sh"), "#!/bin/sh\necho original\n");
const contextNotifier = join(PACKAGE, "context-notifier.mjs");
writeFileSync(contextNotifier, `export default function (pi) { pi.on("tool_call", (event) => { if (event.toolName === "bash" && event.input.command === "sh e2e-context-race.sh") process.stderr.write("guard-context-tool-started\\n"); }); }\n`);
const contextChild = spawn(
  process.execPath,
  [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", contextNotifier, "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-context-race-scenario"],
  { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: contextAgent } },
);
let contextOut = "", contextErr = "";
contextChild.stdout.on("data", (d) => (contextOut += d));
contextChild.stderr.on("data", (d) => {
  contextErr += d;
  if (contextErr.includes("guard-context-tool-started")) markContextToolStarted();
});
contextChild.stdin.end();
const contextCode = await waitForChild(contextChild, "script context race", () => ({ stdout: contextOut, stderr: contextErr }));
const contextAuditFile = join(contextAgent, "guard", "audit.jsonl");
const contextAudits = existsSync(contextAuditFile) ? readFileSync(contextAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
const contextScriptChanged = readFileSync(join(PROJ, "e2e-context-race.sh"), "utf8").includes("context-race-executed");
rmSync(join(PROJ, "e2e-context-race.sh"), { force: true });
let readRaceCode, readRaceOut = "", readRaceErr = "", readRaceAudits = [];
if (process.platform !== "win32") {
  const readAgent = scenarioAgent("e2e-read-agent-");
  mkdirSync(join(HOME, ".ssh"), { recursive: true });
  writeFileSync(readRaceSecret, "FAKE_E2E_PRIVATE_KEY\n");
  writeFileSync(readRacePath, "ordinary content\n");
  const readNotifier = join(PACKAGE, "read-notifier.mjs");
  writeFileSync(readNotifier, `export default function (pi) { pi.on("tool_call", (event) => { if (event.toolName === "read" && event.input.path === ${JSON.stringify(readRacePath)}) process.stderr.write("guard-read-tool-started\\n"); }); }\n`);
  const readChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", readNotifier, "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-read-race-scenario"],
    { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: readAgent } },
  );
  readChild.stdout.on("data", (d) => (readRaceOut += d));
  readChild.stderr.on("data", (d) => {
    readRaceErr += d;
    if (readRaceErr.includes("guard-read-tool-started")) markReadToolStarted();
  });
  readChild.stdin.end();
  readRaceCode = await waitForChild(readChild, "read target race", () => ({ stdout: readRaceOut, stderr: readRaceErr }));
  const readAuditFile = join(readAgent, "guard", "audit.jsonl");
  readRaceAudits = existsSync(readAuditFile) ? readFileSync(readAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
} else {
  console.log("skip e2e: read-target symlink race requires Unix symlink support");
}
let startupCode, startupOut = "", startupErr = "", startupAudits = [], startupControlWorked = false;
if (process.platform !== "win32") {
  const controlDir = tempDir("e2e-startup-control-");
  execFileSync("/bin/bash", ["-c", inlineStartupCommand], { cwd: controlDir, env: childEnv, timeout: 5000, stdio: "ignore" });
  startupControlWorked = existsSync(join(controlDir, "trace-executed")) && readFileSync(join(controlDir, "trace-executed"), "utf8") === "ran";
  const startupAgent = scenarioAgent("e2e-startup-agent-");
  const startupChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-inline-startup-scenario"],
    { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: startupAgent } },
  );
  startupChild.stdout.on("data", (d) => (startupOut += d));
  startupChild.stderr.on("data", (d) => (startupErr += d));
  startupChild.stdin.end();
  startupCode = await waitForChild(startupChild, "shell startup", () => ({ stdout: startupOut, stderr: startupErr }));
  const startupAuditFile = join(startupAgent, "guard", "audit.jsonl");
  startupAudits = existsSync(startupAuditFile) ? readFileSync(startupAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
} else {
  console.log("skip e2e: inline Bash startup test is Unix-only");
}
let searchCode, searchOut = "", searchErr = "", searchAudits = [], searchControlWorked = false;
if (process.platform !== "win32") {
  const searchAgent = scenarioAgent("e2e-search-agent-");
  const deepSearchDir = join(PROJ, "e2e-deep", ...Array(14).fill("nested"));
  mkdirSync(deepSearchDir, { recursive: true });
  writeFileSync(join(deepSearchDir, ".env"), "needle FAKE_E2E_SEARCH_SECRET\n");
  searchControlWorked = execFileSync("/usr/bin/grep", ["-r", "needle", "e2e-deep"], { cwd: PROJ, env: childEnv, timeout: 5000, encoding: "utf8" }).includes("FAKE_E2E_SEARCH_SECRET");
  const searchChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-incomplete-search-scenario"],
    { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: searchAgent } },
  );
  searchChild.stdout.on("data", (d) => (searchOut += d));
  searchChild.stderr.on("data", (d) => (searchErr += d));
  searchChild.stdin.end();
  searchCode = await waitForChild(searchChild, "incomplete search", () => ({ stdout: searchOut, stderr: searchErr }));
  const searchAuditFile = join(searchAgent, "guard", "audit.jsonl");
  searchAudits = existsSync(searchAuditFile) ? readFileSync(searchAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
  rmSync(join(PROJ, "e2e-deep"), { recursive: true, force: true });
} else {
  console.log("skip e2e: recursive grep test is Unix-only");
}
let redactedCode, redactedOut = "", redactedErr = "", redactedAudits = [], redactedControlWorked = false;
let redactedDecisions = [];
if (process.platform !== "win32") {
  const controlDir = tempDir("e2e-redacted-control-");
  execFileSync("/bin/bash", ["-c", redactedCommand], { cwd: controlDir, env: childEnv, timeout: 5000, stdio: "ignore" });
  redactedControlWorked = existsSync(join(controlDir, "redacted-executed"));
  const redactedAgent = scenarioAgent("e2e-redacted-agent-");
  const decisionStart = decisions.length;
  const redactedChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-redacted-command-scenario"],
    { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: redactedAgent } },
  );
  redactedChild.stdout.on("data", (d) => (redactedOut += d));
  redactedChild.stderr.on("data", (d) => (redactedErr += d));
  redactedChild.stdin.end();
  redactedCode = await waitForChild(redactedChild, "redacted command", () => ({ stdout: redactedOut, stderr: redactedErr }));
  redactedDecisions = decisions.slice(decisionStart);
  const redactedAuditFile = join(redactedAgent, "guard", "audit.jsonl");
  redactedAudits = existsSync(redactedAuditFile) ? readFileSync(redactedAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
}
let redactedScriptCode, redactedScriptOut = "", redactedScriptErr = "", redactedScriptAudits = [], redactedScriptControlWorked = false;
if (process.platform !== "win32") {
  const script = `#!/bin/sh\nKEY='${fakeAgeIdentity}'\ncat >/dev/null <<'YAML'\ntoken: |\n  ${fakeYamlSecret}\nname: visible-yaml\n${escapedYamlKey}: |\n  ${fakeEscapedYamlSecret}\ncredentials:\n  bearer: ${fakeDirectNestedYamlSecret}\napi_key:\n- ${fakeYamlListSecrets[0]}\n- ${fakeYamlListSecrets[1]}\nflow_env: [{ # example comment\n  name: API_TOKEN, note: user's label, note2: abc:'open, value: ${fakeFlowYamlSecret}}, {name: LOG_LEVEL, value: visible-flow}]\nenv:\n  - name: API_TOKEN\n    value: |\n      ${fakeNamedYamlSecret}\n  - value: ${fakeInlineYamlSecret}\n    name: DB_PASSWORD\n  - name: SECRET\n    value:\n      nested: ${fakeNestedYamlSecret}\n  - name: LOG_LEVEL\n    value: |\n      visible-debug\nYAML\nprintf ran > redacted-script-executed\n`;
  const controlDir = tempDir("e2e-redacted-script-control-");
  writeFileSync(join(controlDir, "e2e-redacted-script.sh"), script);
  execFileSync("/bin/sh", ["e2e-redacted-script.sh"], { cwd: controlDir, env: childEnv, timeout: 5000, stdio: "ignore" });
  redactedScriptControlWorked = existsSync(join(controlDir, "redacted-script-executed"));
  writeFileSync(join(PROJ, "e2e-redacted-script.sh"), script);
  const scriptAgent = scenarioAgent("e2e-redacted-script-agent-");
  const scriptChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-redacted-script-scenario"],
    { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: scriptAgent } },
  );
  scriptChild.stdout.on("data", (d) => (redactedScriptOut += d));
  scriptChild.stderr.on("data", (d) => (redactedScriptErr += d));
  scriptChild.stdin.end();
  redactedScriptCode = await waitForChild(scriptChild, "redacted script", () => ({ stdout: redactedScriptOut, stderr: redactedScriptErr }));
  const scriptAuditFile = join(scriptAgent, "guard", "audit.jsonl");
  redactedScriptAudits = existsSync(scriptAuditFile) ? readFileSync(scriptAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
  rmSync(join(PROJ, "e2e-redacted-script.sh"), { force: true });
}
let mergeCode, mergeOut = "", mergeErr = "", mergeAudits = [], mergeControlWorked = false;
if (process.platform !== "win32") {
  const script = `#!/bin/sh\ncat >/dev/null <<'YAML'\ncommon: &defaults {value: ${fakeMergeYamlSecret}}\nenv:\n  - name: API_TOKEN\n    !<tag:yaml.org,2002:merge> <<: *defaults\nYAML\nprintf ran > merge-script-executed\n`;
  const controlDir = tempDir("e2e-merge-control-");
  writeFileSync(join(controlDir, "e2e-merge-script.sh"), script);
  execFileSync("/bin/sh", ["e2e-merge-script.sh"], { cwd: controlDir, env: childEnv, timeout: 5000, stdio: "ignore" });
  mergeControlWorked = existsSync(join(controlDir, "merge-script-executed"));
  writeFileSync(join(PROJ, "e2e-merge-script.sh"), script);
  const mergeAgent = scenarioAgent("e2e-merge-agent-");
  const child = spawn(process.execPath, [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-merge-script-scenario"], { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: mergeAgent } });
  child.stdout.on("data", (d) => (mergeOut += d));
  child.stderr.on("data", (d) => (mergeErr += d));
  child.stdin.end();
  mergeCode = await waitForChild(child, "YAML merge script", () => ({ stdout: mergeOut, stderr: mergeErr }));
  const auditFile = join(mergeAgent, "guard", "audit.jsonl");
  mergeAudits = existsSync(auditFile) ? readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
  rmSync(join(PROJ, "e2e-merge-script.sh"), { force: true });
}
let redactedIntentCode, redactedIntentOut = "", redactedIntentErr = "", redactedIntentAudits = [], redactedIntentControlWorked = false;
if (process.platform !== "win32") {
  const controlDir = tempDir("e2e-redacted-intent-control-");
  execFileSync("/bin/sh", ["-c", redactedIntentCommand], { cwd: controlDir, env: childEnv, timeout: 5000, stdio: "ignore" });
  redactedIntentControlWorked = existsSync(join(controlDir, "redacted-intent-executed"));
  const intentAgent = scenarioAgent("e2e-redacted-intent-agent-");
  const intentChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", `guard-redacted-intent-scenario TOKEN=${fakeIntentSecret}`],
    { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: intentAgent } },
  );
  intentChild.stdout.on("data", (d) => (redactedIntentOut += d));
  intentChild.stderr.on("data", (d) => (redactedIntentErr += d));
  intentChild.stdin.end();
  redactedIntentCode = await waitForChild(intentChild, "redacted user intent", () => ({ stdout: redactedIntentOut, stderr: redactedIntentErr }));
  const intentAuditFile = join(intentAgent, "guard", "audit.jsonl");
  redactedIntentAudits = existsSync(intentAuditFile) ? readFileSync(intentAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
}
let redactedHistoryCode, redactedHistoryOut = "", redactedHistoryErr = "", redactedHistoryAudits = [], redactedHistoryControlWorked = false;
if (process.platform !== "win32") {
  const controlDir = tempDir("e2e-redacted-history-control-");
  execFileSync("/bin/sh", ["-c", redactedHistoryCommand], { cwd: controlDir, env: childEnv, timeout: 5000, stdio: "ignore" });
  redactedHistoryControlWorked = existsSync(join(controlDir, "redacted-history-executed"));
  const historyAgent = scenarioAgent("e2e-redacted-history-agent-");
  const historyChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-redacted-history-scenario"],
    { cwd: PROJ, env: { ...childEnv, PI_CODING_AGENT_DIR: historyAgent } },
  );
  historyChild.stdout.on("data", (d) => (redactedHistoryOut += d));
  historyChild.stderr.on("data", (d) => (redactedHistoryErr += d));
  historyChild.stdin.end();
  redactedHistoryCode = await waitForChild(historyChild, "redacted tool history", () => ({ stdout: redactedHistoryOut, stderr: redactedHistoryErr }));
  const historyAuditFile = join(historyAgent, "guard", "audit.jsonl");
  redactedHistoryAudits = existsSync(historyAuditFile) ? readFileSync(historyAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
}
let redactedPastCode, redactedPastOut = "", redactedPastErr = "", redactedPastAudits = [], redactedPastControlWorked = false, pastProject = "";
if (process.platform !== "win32") {
  const controlDir = tempDir("e2e-redacted-past-control-");
  execFileSync("/bin/sh", ["-c", redactedPastCommand], { cwd: controlDir, env: childEnv, timeout: 5000, stdio: "ignore" });
  redactedPastControlWorked = existsSync(join(controlDir, "redacted-past-executed"));
  pastProject = tempDir("e2e-redacted-past-project-");
  execFileSync("git", ["init", "-q", pastProject], { env: childEnv, stdio: "pipe" });
  const pastAgent = scenarioAgent("e2e-redacted-past-agent-");
  mkdirSync(join(pastAgent, "guard"), { recursive: true });
  writeFileSync(join(pastAgent, "guard", "rules.jsonl"), JSON.stringify({ id: "redacted-past", decision: "deny", tool: "bash", match: { kind: "argv", prefix: ["sh", "unrelated", fakePastSecret] }, scope: "global", createdAt: "" }) + "\n");
  const pastChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-redacted-past-scenario"],
    { cwd: pastProject, env: { ...childEnv, PI_CODING_AGENT_DIR: pastAgent } },
  );
  pastChild.stdout.on("data", (d) => (redactedPastOut += d));
  pastChild.stderr.on("data", (d) => (redactedPastErr += d));
  pastChild.stdin.end();
  redactedPastCode = await waitForChild(pastChild, "redacted past rule", () => ({ stdout: redactedPastOut, stderr: redactedPastErr }));
  const pastAuditFile = join(pastAgent, "guard", "audit.jsonl");
  redactedPastAudits = existsSync(pastAuditFile) ? readFileSync(pastAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
}
let redactedCwdCode, redactedCwdOut = "", redactedCwdErr = "", redactedCwdAudits = [], redactedCwdControlWorked = false, cwdProject = "";
if (process.platform !== "win32") {
  const controlDir = tempDir("e2e-redacted-cwd-control-");
  execFileSync("/bin/sh", ["-c", redactedCwdCommand], { cwd: controlDir, env: childEnv, timeout: 5000, stdio: "ignore" });
  redactedCwdControlWorked = existsSync(join(controlDir, "redacted-cwd-executed"));
  cwdProject = tempDir(`e2e-cwd-${fakeCwdSecret}-`);
  execFileSync("git", ["init", "-q", cwdProject], { env: childEnv, stdio: "pipe" });
  const cwdAgent = scenarioAgent("e2e-redacted-cwd-agent-");
  const cwdChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-redacted-cwd-scenario"],
    { cwd: cwdProject, env: { ...childEnv, PI_CODING_AGENT_DIR: cwdAgent } },
  );
  cwdChild.stdout.on("data", (d) => (redactedCwdOut += d));
  cwdChild.stderr.on("data", (d) => (redactedCwdErr += d));
  cwdChild.stdin.end();
  redactedCwdCode = await waitForChild(cwdChild, "redacted working directory", () => ({ stdout: redactedCwdOut, stderr: redactedCwdErr }));
  const cwdAuditFile = join(cwdAgent, "guard", "audit.jsonl");
  redactedCwdAudits = existsSync(cwdAuditFile) ? readFileSync(cwdAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
}
let redactedApprovalCode, redactedApprovalOut = "", redactedApprovalErr = "", redactedApprovalAudits = [], redactedApprovalControlWorked = false, approvalProject = "";
if (process.platform !== "win32") {
  const controlDir = tempDir("e2e-redacted-approval-control-");
  execFileSync("/bin/sh", ["-c", redactedApprovalCommand], { cwd: controlDir, env: childEnv, timeout: 5000, stdio: "ignore" });
  redactedApprovalControlWorked = existsSync(join(controlDir, "redacted-approval-executed"));
  approvalProject = tempDir("e2e-redacted-approval-project-");
  execFileSync("git", ["init", "-q", approvalProject], { env: childEnv, stdio: "pipe" });
  const approvalAgent = scenarioAgent("e2e-redacted-approval-agent-");
  mkdirSync(join(approvalAgent, "guard"), { recursive: true });
  writeFileSync(join(approvalAgent, "guard", "rules.jsonl"), JSON.stringify({ id: "redacted-approval", decision: "allow", tool: "bash", match: { kind: "argv", prefix: ["sh", "unrelated", fakePastSecret] }, scope: "global", createdAt: "" }) + "\n");
  const approvalChild = spawn(
    process.execPath,
    [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-e", extensionEntry, "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "guard-redacted-approval-scenario"],
    { cwd: approvalProject, env: { ...childEnv, PI_CODING_AGENT_DIR: approvalAgent } },
  );
  approvalChild.stdout.on("data", (d) => (redactedApprovalOut += d));
  approvalChild.stderr.on("data", (d) => (redactedApprovalErr += d));
  approvalChild.stdin.end();
  redactedApprovalCode = await waitForChild(approvalChild, "redacted past approval", () => ({ stdout: redactedApprovalOut, stderr: redactedApprovalErr }));
  const approvalAuditFile = join(approvalAgent, "guard", "audit.jsonl");
  redactedApprovalAudits = existsSync(approvalAuditFile) ? readFileSync(approvalAuditFile, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)) : [];
}
srv.close();

const outputLines = out.split("\n").filter(Boolean);
const parsedOutput = outputLines.map((l) => { try { return JSON.parse(l); } catch { return null; } });
const events = parsedOutput.filter(Boolean);
const failedAuditLines = failedAuditOut.split("\n").filter(Boolean);
const failedAuditEvents = failedAuditLines.map((line) => { try { return JSON.parse(line); } catch { return null; } });
const escalationLines = escalationOut.split("\n").filter(Boolean);
const escalationEvents = escalationLines.map((line) => { try { return JSON.parse(line); } catch { return null; } });
const shadowEvents = shadowOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const casePathEvents = casePathOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const contextEvents = contextOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const readRaceEvents = readRaceOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const startupEvents = startupOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const searchEvents = searchOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const redactedEvents = redactedOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const redactedScriptEvents = redactedScriptOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const mergeEvents = mergeOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const redactedIntentEvents = redactedIntentOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const redactedHistoryEvents = redactedHistoryOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const redactedPastEvents = redactedPastOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const redactedCwdEvents = redactedCwdOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
const redactedApprovalEvents = redactedApprovalOut.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } });
// Only booleans are reported on failure, so diagnostics never echo request or file contents.
function redactedEvidence(code, control, scenarioEvents, callId, scenarioAudits, sawMasked, leaked, sideEffectExists) {
  return {
    control,
    completed: code === 0,
    sawMasked,
    noLeak: !leaked,
    toolBlocked: scenarioEvents.some((event) => event?.type === "tool_execution_end" && event.toolCallId === callId && event.isError === true),
    audited: scenarioAudits.some((record) => record.source === "model" && record.final === "blocked" && record.reasons.includes("part of the judgement context was redacted")),
    noSideEffect: !sideEffectExists,
  };
}
const redactedCases = [
  ["redacted executable input requires confirmation before running", redactedEvidence(redactedCode, redactedControlWorked, redactedEvents, "call_0_0", redactedAudits, redactedDecisions.some((decision) => typeof decision.cmd === "string" && decision.cmd.startsWith("echo --token=[REDACTED]")), redactedDecisions.some((decision) => decision.leakedFakeSecret), existsSync(join(PROJ, "redacted-executed")))],
  ["redacted executable file requires confirmation before running", redactedEvidence(redactedScriptCode, redactedScriptControlWorked, redactedScriptEvents, "call_0_0", redactedScriptAudits, sawRedactedScript, leakedRedactedScript, existsSync(join(PROJ, "redacted-script-executed")))],
  ["YAML merge secrets in executable files require confirmation", redactedEvidence(mergeCode, mergeControlWorked, mergeEvents, "call_0_0", mergeAudits, sawMaskedMerge, leakedMerge, existsSync(join(PROJ, "merge-script-executed")))],
  ["redacted user intent requires confirmation before running", redactedEvidence(redactedIntentCode, redactedIntentControlWorked, redactedIntentEvents, "call_0_0", redactedIntentAudits, sawMaskedIntent, leakedIntent, existsSync(join(PROJ, "redacted-intent-executed")))],
  ["redacted tool history requires confirmation before running", redactedEvidence(redactedHistoryCode, redactedHistoryControlWorked, redactedHistoryEvents, "call_1_0", redactedHistoryAudits, sawMaskedHistory, leakedHistory, existsSync(join(PROJ, "redacted-history-executed")))],
  ["redacted past rule requires confirmation before running", redactedEvidence(redactedPastCode, redactedPastControlWorked, redactedPastEvents, "call_0_0", redactedPastAudits, sawMaskedPast, leakedPast, existsSync(join(pastProject, "redacted-past-executed")))],
  ["redacted working directory requires confirmation before running", redactedEvidence(redactedCwdCode, redactedCwdControlWorked, redactedCwdEvents, "call_0_0", redactedCwdAudits, sawMaskedCwd, leakedCwd, existsSync(join(cwdProject, "redacted-cwd-executed")))],
  ["redaction cannot be overridden by past approval", redactedEvidence(redactedApprovalCode, redactedApprovalControlWorked, redactedApprovalEvents, "call_0_0", redactedApprovalAudits, sawMaskedApproval && sawApprovalQuestion, leakedApproval, existsSync(join(approvalProject, "redacted-approval-executed")))],
];
for (const e of events.filter((e) => e.type === "tool_execution_end")) {
  const text = (e.result?.content ?? []).map((c) => c.text).join(" ").replace(/\s+/g, " ").slice(0, 150);
  console.log(`${e.isError ? "BLOCKED" : "ran    "} ${e.toolName.padEnd(5)} ${text}`);
}
console.log("\ndecisions API calls:", JSON.stringify(normalDecisions));
console.log("exit:", code, err ? `\nstderr: ${err.slice(0, 1500)}` : "");
console.log("rules.jsonl tampered:", existsSync(RULES) && readFileSync(RULES, "utf8").includes("allow"));
console.log("out.txt:", normalOutput ?? "(none)");
console.log("audit:", auditText ? auditText.trim().split("\n").map((l) => { const j = JSON.parse(l); return `${j.final}/${j.source}: ${j.preview.split("\n")[0].slice(0, 60)}`; }).join(" | ") : "none");
if (!events.length) console.log("raw stdout:", out.slice(0, 1500), "\nraw stderr:", err.slice(0, 3000));

// ---- assertions (CI) ----
const audits = auditText ? auditText.trim().split("\n").map((l) => JSON.parse(l)) : [];
let recoveredAudits = [];
try { recoveredAudits = recoveredAuditText.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)); } catch { /* reported by checks below */ }
const diagnosticProbe = processSummary('{"type":"message_end","content":"opaque-secret"}\n{"type":"opaque-secret"}\n', "opaque-secret");
const checks = [
  ["timeout diagnostics retain event types without event contents", diagnosticProbe.includes("recent_events=message_end") && !diagnosticProbe.includes("opaque-secret")],
  ["pi ran to completion", code === 0],
  ["JSON stdout contains only valid events", outputLines.length > 0 && parsedOutput.every((event) => event && typeof event === "object" && !Array.isArray(event))],
  ["mock API listens only on loopback", address.address === "127.0.0.1"],
  ["headless configuration warning omits unknown key and value", err.includes("config.json contains unknown fields") && !err.includes("opaque-e2e-config-")],
  ["command sharing a batch with changing calls receives full judgement", audits.some((a) => a.source === "model" && a.preview.startsWith("echo e2e-safe") && a.final === "run") && normalDecisions.some((d) => d.cmd === "echo e2e-safe" && d.questions >= 7)],
  ["safe command completed successfully", events.some((e) => e.type === "tool_execution_end" && e.toolCallId === "call_0_0" && e.isError === false)],
  ["later extension input change detected after execution", audits.some((a) => a.source === "drift" && a.preview.startsWith("echo e2e-changed"))],
  ["headless input change warning reaches stderr", err.includes("changed by another extension after guard judged it")],
  ["Pi completes despite audit failure", failedAuditCode === 0],
  ["audit failure warning reaches stderr once", failedAuditErr.split("audit log unavailable").length === 2],
  ["audit recovery warns about missing decisions", failedAuditErr.includes("audit logging recovered; some decisions may be missing")],
  ["audit warning and recovery follow fixture restoration", failedAuditErr.indexOf("audit log unavailable") >= 0 && failedAuditErr.indexOf("audit log unavailable") < failedAuditErr.indexOf("audit-fixture-restored") && failedAuditErr.indexOf("audit-fixture-restored") < failedAuditErr.indexOf("audit logging recovered")],
  ["audit failure leaves JSON stdout valid", failedAuditLines.length > 0 && failedAuditEvents.every((event) => event && typeof event === "object" && !Array.isArray(event))],
  ["safe command completes despite audit failure", failedAuditEvents.some((event) => event?.type === "tool_execution_end" && event.toolCallId === "call_0_0" && event.isError === false)],
  ["failed audit record is not reconstructed", !recoveredAudits.some((a) => a.preview.startsWith("echo e2e-safe"))],
  ["protected write remains blocked during audit failure", failedAuditEvents.some((event) => event?.type === "tool_execution_end" && event.toolCallId === "call_0_1" && event.isError === true && JSON.stringify(event.result).includes("guard: blocked")) && !recoveredAudits.some((a) => a.source === "hard-deny")],
  ["later decisions are recorded after audit recovery", recoveredAudits.some((a) => a.source === "model" && a.preview.startsWith("echo build-ok") && a.final === "run")],
  ["headless escalation reports the stop on stderr", escalationErr.includes("too many blocked calls") && escalationErr.includes("Stopped the agent")],
  ["headless escalation process exits normally", escalationCode === 0],
  ["headless escalation preserves JSON stdout", escalationLines.length > 0 && escalationEvents.every((event) => event && typeof event === "object" && !Array.isArray(event))],
  ["headless escalation prevents later tool calls", !escalationEvents.some((event) => event?.type === "tool_execution_end" && ["call_1_0", "call_1_1", "call_2_0"].includes(event.toolCallId)) && !existsSync(join(PROJ, "out.txt")) && !existsSync(join(PROJ, "run.sh"))],
  ...(process.platform !== "win32" ? [["Pi's prepended bin cannot silently shadow git", shadowCode === 0 && shadowEvents.some((event) => event?.type === "tool_execution_end" && event.toolCallId === "call_0_0" && event.isError === true) && shadowAudits.some((record) => record.source === "sensitive" && record.final === "blocked" && record.reasons.some((reason) => reason.includes("Pi-managed executable"))) && !existsSync(join(PROJ, "shadow-ran"))]] : []),
  ...(process.platform !== "win32" ? [["uppercase PATH is checked when lowercase path comes first", casePathCode === 0 && casePathErr.includes("guard-case-order-ok") && casePathEvents.some((event) => event?.type === "tool_execution_end" && event.toolCallId === "call_0_0" && event.isError === true) && casePathAudits.some((record) => record.source === "sensitive" && record.final === "blocked") && !existsSync(join(PROJ, "case-shadow-ran"))]] : []),
  ["changed script is blocked while Pi awaits judgement", contextCode === 0 && contextErr.includes("guard-context-tool-started") && contextScriptChanged && contextEvents.some((event) => event?.type === "tool_execution_end" && event.toolCallId === "call_0_0" && event.isError === true) && contextAudits.some((record) => record.final === "blocked" && record.reasons.includes("judgement context changed during judgement")) && !existsSync(join(PROJ, "context-race-executed"))],
  ...(process.platform !== "win32" ? [["read redirected to a secret is blocked while Pi awaits judgement", readRaceCode === 0 && readRaceErr.includes("guard-read-tool-started") && readlinkSync(readRacePath) === readRaceSecret && readRaceEvents.some((event) => event?.type === "tool_execution_end" && event.toolCallId === "call_0_0" && event.isError === true) && readRaceAudits.some((record) => record.final === "blocked" && record.reasons.includes("filesystem policy changed during judgement")) && !readRaceOut.includes("FAKE_E2E_PRIVATE_KEY")]] : []),
  ...(process.platform !== "win32" ? [["inline Bash startup settings are blocked before PS4 executes", startupControlWorked && startupCode === 0 && startupEvents.some((event) => event?.type === "tool_execution_end" && event.toolCallId === "call_0_0" && event.isError === true) && startupAudits.some((record) => record.source === "sensitive" && record.final === "blocked" && record.reasons.some((reason) => reason.includes("shell startup or tracing"))) && !existsSync(join(PROJ, "trace-executed"))]] : []),
  ...(process.platform !== "win32" ? [["an incomplete recursive search does not expose an unseen secret", searchControlWorked && searchCode === 0 && searchEvents.some((event) => event?.type === "tool_execution_end" && event.toolCallId === "call_0_0" && event.isError === true) && searchAudits.some((record) => record.source === "model" && record.final === "blocked" && record.reasons.includes("search scope could not be inspected completely")) && !searchOut.includes("FAKE_E2E_SEARCH_SECRET")]] : []),
  ...(process.platform !== "win32" ? redactedCases.map(([name, evidence]) => [name, Object.values(evidence).every(Boolean), evidence]) : []),
  ["write to protected path hard-denied", audits.some((a) => a.source === "hard-deny" && a.final === "blocked")],
  ["rules file not tampered", !(existsSync(RULES) && readFileSync(RULES, "utf8").includes("allow"))],
  ["later concurrent script write is attached and execution is blocked", normalDecisions.some((d) => d.cmd === "sh run.sh" && d.attached) && audits.some((a) => a.preview.startsWith("sh run.sh") && a.final === "blocked")],
  ["benign command judged and ran", normalOutput === "build-ok"],
];
let failed = 0;
for (const [name, okk, evidence] of checks) {
  console.log(`${okk ? "✓" : "✗"} e2e: ${name}`);
  if (!okk) {
    failed++;
    if (evidence) console.error("  evidence:", JSON.stringify(evidence));
  }
}
if (failed) console.error("audit failure scenario:", { exit: failedAuditCode, stderr: failedAuditErr.slice(0, 1500), stdout: failedAuditOut.slice(0, 1500) }, "escalation:", { exit: escalationCode, stderr: escalationErr.slice(0, 1500), stdout: escalationOut.slice(0, 1500) });
process.exit(failed ? 1 : 0);
