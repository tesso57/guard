import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { Rule } from "../extensions/guard/rules.ts";
import { createMockPi } from "./helpers/mock-pi.ts";

type Action = "allow" | "confirm" | "block";
type Scenario = {
  name: string;
  expected: Action;
  action?: Action;
  related?: number;
  visible?: number;
  changed?: "path" | "destination" | "permission";
  authorization?: number;
  latestHold?: boolean;
  answersAfterHold?: boolean;
  withheldRule?: boolean;
  maskedArgument?: boolean;
  directDeny?: boolean;
  similarDenial?: boolean;
  exfiltration?: boolean;
  lowRisk?: boolean;
  noUserContext?: boolean;
  observeOnly?: boolean;
};

const cases: Scenario[] = [
  { name: "same scope within five", expected: "allow", related: 5, visible: 5 },
  { name: "same scope with six", expected: "allow", related: 6, visible: 6 },
  { name: "same scope with ten", expected: "allow", related: 10, visible: 10 },
  { name: "same scope above the limit", expected: "allow", action: "confirm", related: 11, visible: 10 },
  { name: "private rule leaves room for public approval", expected: "confirm", related: 6, visible: 5, withheldRule: true },
  { name: "different path", expected: "confirm", changed: "path", authorization: 0.03 },
  { name: "different destination", expected: "confirm", changed: "destination", authorization: 0.03 },
  { name: "different permission", expected: "confirm", changed: "permission", authorization: 0.03 },
  { name: "new direct instruction puts the same action on hold", expected: "confirm", latestHold: true },
  { name: "unrelated answers fill the recent window after a hold", expected: "confirm", latestHold: true, answersAfterHold: true },
  { name: "historical approval without any current request", expected: "confirm", noUserContext: true },
  { name: "direct deny takes priority", expected: "block", directDeny: true },
  { name: "strong exfiltration signal takes priority", expected: "block", exfiltration: true },
  { name: "similar past denial takes priority", expected: "confirm", similarDenial: true },
  { name: "masked arguments require confirmation", expected: "confirm", maskedArgument: true },
  { name: "authorized request with uncertain model answer", expected: "allow", action: "confirm", authorization: 0.6 },
  { name: "model calls a changed destination low risk and within intent", expected: "confirm", changed: "destination", authorization: 0.03, lowRisk: true, observeOnly: true },
];

type RequestBody = {
  input: { role?: string; call_id?: string; output?: string; content?: { text?: string; data?: { decision: string }[] }[] }[];
  questions: { type: string; name: string }[];
};

const user = (content: string) => ({ type: "message", message: { role: "user", content } });
const held = "Hold the transfer. Do not send this document yet.";
const privateName = ".env.fixture-private-rule";
const credential = "sk-test-abcdefghijklmnopqrstuv";
const baseArgs = ["fixture-transfer", "send", "reports/summary.txt", "https://team.example.invalid/inbox", "--permission=viewer"];

function answerEntries(id: number) {
  const question = `Which format should section ${id} use?`;
  const attemptId = `attempt-${id}`;
  const reply = `質問 #${id}「${question}」への回答: Markdown`;
  return [
    { type: "custom", customType: "ask-user-state-v1", data: { kind: "question", question: { id, question, options: ["Markdown", "Text"] } } },
    { type: "custom", customType: "ask-user-state-v1", data: { kind: "attempt", id, attemptId, answerDigest: createHash("sha256").update(reply).digest("hex") } },
    { type: "custom_message", customType: "ask-user-delivery-v2", details: attemptId, display: true, content: reply },
  ];
}

function mockAnswers(scenario: Scenario, request: RequestBody) {
  const holdPresent = request.input.some(item => item.role === "user" && item.content?.some(part => part.text?.includes(held)));
  const probabilities = scenario.lowRisk ? [0.9, 0.1, 0, 0, 0] : [0, 0, 0.55, 0.4, 0.05];
  const predicates: Record<string, number> = {
    covered_by_past_approval: 0.98,
    authorized_by_current_request: scenario.authorization ?? (holdPresent ? 0.02 : 0.96),
    outside_user_intent: holdPresent ? 0.95 : scenario.changed && !scenario.lowRisk ? 0.4 : 0.03,
    similar_to_past_denial: scenario.similarDenial ? 0.95 : 0.02,
    exfiltration: scenario.exfiltration ? 0.95 : 0.02,
  };
  return request.questions.map(({ type, name }) => {
    if (type === "score") return {
      type, name, confidence: 0.9, score: probabilities.reduce((sum, p, value) => sum + p * value, 0),
      probabilities: probabilities.map((probability, value) => ({ value, probability })),
    };
    if (type === "choice") return { type, name, confidence: 0.9, choice: "network" };
    return { type, name, probability: predicates[name] ?? 0.02 };
  });
}

test("Guard evaluates past coverage and current authorization using mock Decisions answers", {
  skip: process.platform === "win32" && "These fixtures exercise the POSIX shell judgement path",
}, async (t) => {
  const sandbox = mkdtempSync(join(tmpdir(), "guard-judge-quality-"));
  const cwd = join(sandbox, "project"), agentDir = join(sandbox, "agent");
  const isolated = (key: string) => /^(RISK_|GUARD_|PI_|OPENAI_)/.test(key) || ["HOME", "XDG_CONFIG_HOME"].includes(key);
  const previous = Object.entries(process.env).filter(([key]) => isolated(key));
  const previousFetch = globalThis.fetch;
  for (const [key] of previous) delete process.env[key];
  Object.assign(process.env, { HOME: sandbox, XDG_CONFIG_HOME: join(sandbox, "config"), PI_CODING_AGENT_DIR: agentDir,
    GUARD_OPENAI_API_KEY: "local-fixture", OPENAI_BASE_URL: "https://decisions.example.invalid/v1" });
  mkdirSync(cwd);
  try {
    const { default: guard } = await import("../extensions/index.ts");
    const { tail } = await import("../extensions/guard/audit.ts");
    for (const scenario of cases) {
      await t.test(scenario.name, async (t) => {
        const target = [...baseArgs];
        if (scenario.changed === "path") target[2] = "reports/detail.txt";
        if (scenario.changed === "destination") target[3] = "https://other.example.invalid/inbox";
        if (scenario.changed === "permission") target[4] = "--permission=editor";
        if (scenario.maskedArgument) target.push(`--token=${credential}`);
        const makeRule = (id: string, decision: Rule["decision"], argv: string[]): Rule => ({
          id, decision, tool: "bash", scope: "session", createdAt: "2026-01-01T00:00:00Z", match: { kind: "argv-exact", argv },
        });
        const ruleEntries = [makeRule("prior", "allow", baseArgs),
          ...Array.from({ length: (scenario.related ?? 2) - 1 }, (_, i) =>
            makeRule(`other-${i}`, "deny", ["fixture-transfer", "send", i === 0 && scenario.withheldRule ? privateName : `archive/copy-${i}.txt`]))];
        if (scenario.directDeny) ruleEntries.push(makeRule("direct", "deny", baseArgs));
        const branch: unknown[] = ruleEntries.map(rule => ({ type: "custom", customType: "guard-rule", data: { op: "add", rule } }));
        if (!scenario.noUserContext) branch.push(user("Send reports/summary.txt to https://team.example.invalid/inbox with viewer permission."));
        if (scenario.latestHold) branch.push(user(held));
        if (scenario.answersAfterHold) for (let i = 1; i <= 4; i++) branch.push(...answerEntries(i));

        const mock = createMockPi();
        Object.assign(mock.context, { cwd, hasUI: false, isProjectTrusted: () => true });
        Object.assign(mock.sessionManager, { getBranch: () => branch });
        guard(mock.pi);
        await mock.emit("session_start", { reason: "startup" });
        const requests: { body: RequestBody; bytes: number }[] = [];
        globalThis.fetch = async (url, init) => {
          assert.equal(url, "https://decisions.example.invalid/v1/decisions");
          const payload = String(init?.body);
          const body = JSON.parse(payload) as RequestBody;
          requests.push({ body, bytes: Buffer.byteLength(payload) });
          return Response.json({ answers: mockAnswers(scenario, body) });
        };
        // The extra subcommand needs its own judgement. The historical allow is not a full local rule match.
        await mock.emit("tool_call", { toolCallId: "fixture-call", toolName: "bash", input: { command: target.join(" ") + "; printf done" } });
        const verdict = tail(1)[0];
        assert.ok(verdict);
        const body = requests[0]?.body;
        const collected = body?.input.find(item => item.call_id === "guard-context" && item.output);
        const context = collected?.output ? JSON.parse(collected.output) : {};
        const past = context.pastDecisions ?? body?.input.flatMap(item => Array.isArray(item.content) ? item.content.flatMap(part => part.data ?? []) : []);
        t.diagnostic(JSON.stringify({ scenario: scenario.name, expected: scenario.expected, action: verdict.action,
          requests: requests.length, bytes: requests[0]?.bytes ?? 0, questions: body?.questions.length ?? 0, retained: past?.length ?? 0 }));

        if (!scenario.observeOnly) assert.equal(verdict.action, scenario.action ?? scenario.expected, JSON.stringify(verdict.reasons));
        assert.equal(requests.length, scenario.directDeny ? 0 : 1);
        if (scenario.visible !== undefined) assert.equal(past?.length, scenario.visible);
        if (scenario.withheldRule) {
          assert.ok(!JSON.stringify(body).includes(privateName));
          assert.ok(past?.some((rule: Rule) => rule.decision === "allow"));
          assert.ok(verdict.reasons.includes("some related decisions were omitted from judgement"));
        }
        if (scenario.maskedArgument) {
          assert.ok(!JSON.stringify(body).includes(credential));
          assert.ok(verdict.reasons.includes("part of the judgement context was redacted"));
        }
        if (body) {
          assert.ok(Array.isArray(context.pastDecisions));
          assert.ok(body.input.filter(item => item.role === "user").every(item => item.content?.every(part => part.data === undefined)));
          assert.equal(body.questions.some(question => question.name === "authorized_by_current_request"),
            !scenario.noUserContext && past?.some((rule: Rule) => rule.decision === "allow"));
        }
        if (scenario.answersAfterHold) {
          const users = body?.input.filter(item => item.role === "user").map(item => item.content?.[0].text) ?? [];
          assert.equal(users.length, 4);
          assert.ok(users[0]?.includes(held));
          assert.ok(users.slice(1).every(text => text?.startsWith("[answer scoped to its question]")));
        }
      });
    }
  } finally {
    globalThis.fetch = previousFetch;
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) if (value !== undefined) process.env[key] = value;
    rmSync(sandbox, { recursive: true, force: true });
  }
});
