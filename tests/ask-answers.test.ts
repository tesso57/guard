import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { readAskAnswers } from "../extensions/guard/ask-answers.ts";
import { loadConfig } from "../extensions/guard/config.ts";
import { buildRequest } from "../extensions/guard/judge.ts";

const question = "Which format should I use?";
const answer = "Please use Markdown";
const content = `Answer to question #1 “${question}”: ${answer}`;
const state = (data: unknown) => ({ type: "custom" as const, customType: "ask-user-state-v1", data });
const asked = state({ kind: "question", question: { id: 1, question, options: ["CSV", "Markdown"] } });
const attempt = { kind: "attempt", id: 1, attemptId: "a1" };
const answerDigest = createHash("sha256").update(content).digest("hex");
const selected = state({ ...attempt, answerDigest });
const received = { type: "custom_message" as const, customType: "ask-user-delivery-v2", details: "a1", display: true, content };

function replay(...entries: Parameters<ReturnType<typeof readAskAnswers>>[0][]) {
  const read = readAskAnswers();
  return entries.map(read).filter(value => value !== undefined);
}

test("the first matched delivery contributes the human's answer and keeps the assistant's question out of user instructions", () => {
  const answers = replay(asked, selected, received, received);
  assert.deepEqual(answers, [{ id: 1, question, answer }]);
  const { body } = buildRequest(loadConfig(), {
    tool: "read", input: { path: "example.md" }, cwd: "/project", callId: "t1", light: false,
    userMessages: ["Please write a report", ...answers], history: [], attachedFiles: {}, past: [],
  });
  const items = body.input as { role?: string; type?: string; content?: { text: string }[]; output?: string }[];
  const user = items.filter(item => item.role === "user").at(-1)!.content![0].text;
  assert.ok(user.includes(answer));
  assert.ok(!user.includes(question));
  const context = JSON.parse(items.find(item => item.type === "function_call_output")!.output!);
  assert.deepEqual(context.questionsAskedByAssistant, [{ id: 1, question }]);
});

test("saved Japanese receipts still match the original digest", () => {
  const legacy = `質問 #1「${question}」への回答: ${answer}`;
  const digest = createHash("sha256").update(legacy).digest("hex");
  const legacyAttempt = state({ ...attempt, answerDigest: digest });
  assert.deepEqual(replay(asked, legacyAttempt, { ...received, content: legacy }), [{ id: 1, question, answer }]);
  assert.deepEqual(replay(asked, legacyAttempt, received), []);
});

test("pending, unmatched, old and altered deliveries do not become user intent", () => {
  assert.deepEqual(replay(asked, selected), []);
  assert.deepEqual(replay(asked, received, selected), []);
  assert.deepEqual(replay(selected, asked, received), []);
  assert.deepEqual(replay(asked, selected, { ...received, details: "sibling" }), []);
  assert.deepEqual(replay(asked, selected, { ...received, customType: "unrelated" }), []);
  assert.deepEqual(replay(asked, selected, { ...received, display: false }), []);
  assert.deepEqual(replay(asked, selected, { ...received, content: content + " changed" }), []);
  assert.deepEqual(replay(asked, state(attempt), received), []);
  assert.deepEqual(replay(asked, state({ ...attempt, id: 2, answerDigest }), received), []);
  assert.deepEqual(replay(asked, selected, selected, received), []);
});

test("an earlier delivered dismissal or unverified response closes all attempts for the question", () => {
  const earlierAttempt = state({ ...attempt, attemptId: "older" });
  const earlierDelivery = { ...received, details: "older", content: "dismissed" };
  assert.deepEqual(replay(asked, selected, earlierAttempt, earlierDelivery, received), []);
  assert.deepEqual(replay(asked, selected, state({ kind: "delivery", id: 1, message: "legacy" }), received), []);
  assert.deepEqual(replay(asked, selected, asked, received), []);
});
