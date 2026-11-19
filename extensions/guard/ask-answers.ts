import { createHash } from "node:crypto";
import type { CustomEntry, CustomMessageEntry } from "@earendil-works/pi-coding-agent";

export type AskAnswer = { id: number; question: string; answer: string };
type Entry = Pick<CustomEntry, "type" | "customType" | "data"> |
  Pick<CustomMessageEntry, "type" | "customType" | "details" | "display" | "content">;

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

// Replay the selected branch in order. The first delivery closes a question even when
// it is a dismissal or an older attempt that did not bind the user's answer.
export function readAskAnswers() {
  const questions = new Map<number, string | null>();
  const attempts = new Map<string, { id: number; digest: unknown } | null>();
  return (entry: Entry): AskAnswer | undefined => {
    if (entry.type === "custom") {
      if (entry.customType !== "ask-user-state-v1" || !record(entry.data)) return;
      const data = entry.data;
      if (data.kind === "question" && record(data.question)) {
        const { id, question, options } = data.question;
        if (!validId(id)) return;
        const valid = typeof question === "string" && !!question.trim() && Array.isArray(options)
          && options.length >= 2 && options.length <= 6 && options.every(o => typeof o === "string" && o.trim())
          && new Set(options.map(o => o.trim())).size === options.length;
        questions.set(id, valid && !questions.has(id) ? question : null);
      } else if (data.kind === "attempt" && validId(data.id) && typeof data.attemptId === "string" && data.attemptId) {
        const known = questions.get(data.id) && !attempts.has(data.attemptId);
        attempts.set(data.attemptId, known ? { id: data.id, digest: data.answerDigest } : null);
      } else if (data.kind === "delivery" && validId(data.id)) {
        // Legacy deliveries matched ordinary user text and did not record an unambiguous receipt.
        questions.set(data.id, null);
      }
      return;
    }
    if (entry.customType !== "ask-user-delivery-v2" || typeof entry.details !== "string") return;
    const attempt = attempts.get(entry.details);
    if (!attempt) return;
    const question = questions.get(attempt.id);
    questions.set(attempt.id, null);
    if (!question || entry.display !== true || typeof entry.content !== "string" || typeof attempt.digest !== "string") return;
    const prefix = `質問 #${attempt.id}「${question}」への回答: `;
    if (!entry.content.startsWith(prefix) || createHash("sha256").update(entry.content).digest("hex") !== attempt.digest) return;
    const answer = entry.content.slice(prefix.length);
    if (answer.trim()) return { id: attempt.id, question, answer };
  };
}
