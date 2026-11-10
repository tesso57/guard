import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import type { AssistantMessage, Model, StreamFunction, TranscriptContext } from "@earendil-works/pi-ai";

type Reply = { content: AssistantMessage["content"]; stopReason?: "stop" | "toolUse" };

/** Scripted responses for real Pi sessions; it never contacts a provider. */
export function createFakeModel(script: Reply[]) {
  const replies = structuredClone(script);
  const requests: TranscriptContext[] = [];
  const model: Model<"openai-completions"> = {
    id: "fake", name: "Fake model", api: "openai-completions", provider: "fake",
    baseUrl: "http://example.invalid", reasoning: false, input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 10000, maxTokens: 1000,
  };
  const stream: StreamFunction = (requestedModel, context) => {
    const reply = replies.shift();
    if (!reply) throw new Error("Fake model script exhausted");
    requests.push(structuredClone(context));
    const stopReason = reply.stopReason ?? (reply.content.some((item) => item.type === "toolCall") ? "toolUse" : "stop");
    const message: AssistantMessage = {
      role: "assistant", content: structuredClone(reply.content), api: requestedModel.api, provider: requestedModel.provider,
      model: requestedModel.id, usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
      stopReason, timestamp: Date.now(),
    };
    const result = createAssistantMessageEventStream();
    queueMicrotask(() => {
      result.push({ type: "start", partial: message });
      result.push({ type: "done", reason: stopReason, message });
      result.end();
    });
    return result;
  };
  return { model, stream, requests };
}
