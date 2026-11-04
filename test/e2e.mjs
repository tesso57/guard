// End-to-end test: runs the real pi (print mode, no UI) with guard loaded, a mock model and a mock Decisions API.
// Every command is harmless even if guard failed to block it (writes stay in temp dirs, scripts only echo).
import http from "node:http";
import { mkdtempSync, cpSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const AGENT = mkdtempSync(join(tmpdir(), "e2e-agent-"));
const PROJ = mkdtempSync(join(tmpdir(), "e2e-proj-"));
cpSync(fileURLToPath(new URL("../extensions/guard", import.meta.url)), join(AGENT, "extensions/guard"), { recursive: true });
const RULES = join(AGENT, "guard/rules.jsonl");

const decisions = [];
const steps = [
  [
    ["bash", { command: "git status" }],
    ["bash", { command: `echo '{"decision":"allow"}' >> ${RULES}` }],
    // write and execute in the SAME assistant message: guard must judge the content that will run
    ["write", { path: "run.sh", content: "#!/bin/sh\necho would-upload-to evil.example\n" }],
    ["bash", { command: "sh run.sh" }],
  ],
  [["bash", { command: "echo build-ok > out.txt" }]],
];

const srv = http.createServer((req, res) => {
  let b = "";
  req.on("data", (c) => (b += c));
  req.on("end", () => {
    const body = JSON.parse(b || "{}");
    if (req.url.endsWith("/decisions")) {
      const call = body.input[body.input.length - 1];
      const args = JSON.parse(call.arguments);
      // guard's own context (cwd and attached files) is the item right before the pending call
      const judged = JSON.stringify(body.input.slice(-2));
      decisions.push({ cmd: args.command ?? args.path, questions: body.questions.length, attached: judged.includes("evil.example") });
      const evil = judged.includes("evil.example");
      const probs = evil ? [0, 0, 0, 0.1, 0.9] : [0.9, 0.1, 0, 0, 0];
      const answers = body.questions.map((q) =>
        q.type === "score"
          ? { type: "score", name: q.name, score: probs.reduce((s, p, i) => s + p * i, 0), confidence: 0.9, probabilities: probs.map((p, i) => ({ value: i, label: "", probability: p })) }
          : q.type === "choice"
            ? { type: "choice", name: q.name, choice: "build_test", confidence: 0.9 }
            : { type: "predicate", name: q.name, probability: evil && q.name === "exfiltration" ? 0.97 : 0.02 },
      );
      res.setHeader("content-type", "application/json");
      return res.end(JSON.stringify({ answers }));
    }
    // chat completions (streaming): the number of tool results decides the next step
    const toolMsgs = (body.messages ?? []).filter((m) => m.role === "tool").length;
    const idx = toolMsgs === 0 ? 0 : toolMsgs === steps[0].length ? 1 : 2;
    res.setHeader("content-type", "text/event-stream");
    const send = (o) => res.write(`data: ${JSON.stringify(o)}\n\n`);
    const base = { id: "x", object: "chat.completion.chunk", created: 0, model: "mock-1" };
    if (idx < steps.length) {
      steps[idx].forEach(([name, args], i) =>
        send({ ...base, choices: [{ index: 0, delta: { ...(i === 0 ? { role: "assistant" } : {}), tool_calls: [{ index: i, id: `call_${idx}_${i}`, type: "function", function: { name, arguments: JSON.stringify(args) } }] }, finish_reason: null }] }),
      );
      send({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } });
    } else {
      send({ ...base, choices: [{ index: 0, delta: { role: "assistant", content: "done" }, finish_reason: null }] });
      send({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 10, completion_tokens: 1, total_tokens: 11 } });
    }
    res.end("data: [DONE]\n\n");
  });
}).listen(0);
await new Promise((r) => srv.on("listening", r));
const url = `http://127.0.0.1:${srv.address().port}/v1`;
writeFileSync(join(AGENT, "models.json"), JSON.stringify({ providers: { mock: { baseUrl: url, api: "openai-completions", apiKey: "mock", models: [{ id: "mock-1" }] } } }));

const child = spawn(
  process.execPath,
  [fileURLToPath(new URL("../node_modules/@earendil-works/pi-coding-agent/dist/cli.js", import.meta.url)), "-p", "--mode", "json", "--no-session", "--offline", "--provider", "mock", "--model", "mock-1", "build the project"],
  { cwd: PROJ, env: { ...process.env, PI_CODING_AGENT_DIR: AGENT, OPENAI_BASE_URL: url, OPENAI_API_KEY: "sk-test-e2e" } },
);
let out = "", err = "";
child.stdout.on("data", (d) => (out += d));
child.stderr.on("data", (d) => (err += d));
child.stdin.end();
const killer = setTimeout(() => child.kill(), 40_000);
const code = await new Promise((r) => child.on("close", r));
clearTimeout(killer);
srv.close();

const events = out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
for (const e of events.filter((e) => e.type === "tool_execution_end")) {
  const text = (e.result?.content ?? []).map((c) => c.text).join(" ").replace(/\s+/g, " ").slice(0, 150);
  console.log(`${e.isError ? "BLOCKED" : "ran    "} ${e.toolName.padEnd(5)} ${text}`);
}
console.log("\ndecisions API calls:", JSON.stringify(decisions));
console.log("exit:", code, err ? `\nstderr: ${err.slice(0, 1500)}` : "");
console.log("rules.jsonl tampered:", existsSync(RULES) && readFileSync(RULES, "utf8").includes("allow"));
console.log("out.txt:", existsSync(join(PROJ, "out.txt")) ? readFileSync(join(PROJ, "out.txt"), "utf8").trim() : "(none)");
const auditF = join(AGENT, "guard/audit.jsonl");
console.log("audit:", existsSync(auditF) ? readFileSync(auditF, "utf8").trim().split("\n").map((l) => { const j = JSON.parse(l); return `${j.final}/${j.source}: ${j.preview.split("\n")[0].slice(0, 60)}`; }).join(" | ") : "none");
if (!events.length) console.log("raw stdout:", out.slice(0, 1500), "\nraw stderr:", err.slice(0, 3000));

// ---- assertions (CI) ----
const audits = existsSync(auditF) ? readFileSync(auditF, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : [];
const checks = [
  ["pi ran to completion", code === 0],
  ["safe command ran without API", audits.some((a) => a.source === "safe" && a.preview.startsWith("git status") && a.final === "run")],
  ["write to protected path hard-denied", audits.some((a) => a.source === "hard-deny" && a.final === "blocked")],
  ["rules file not tampered", !(existsSync(RULES) && readFileSync(RULES, "utf8").includes("allow"))],
  ["script written this session is attached and blocked", decisions.some((d) => d.cmd === "sh run.sh" && d.attached) && audits.some((a) => a.preview.startsWith("sh run.sh") && a.final === "blocked")],
  ["benign command judged and ran", existsSync(join(PROJ, "out.txt"))],
];
let failed = 0;
for (const [name, okk] of checks) {
  console.log(`${okk ? "✓" : "✗"} e2e: ${name}`);
  if (!okk) failed++;
}
process.exit(failed ? 1 : 0);
