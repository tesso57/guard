import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import { fileURLToPath } from "node:url";
import { createFakeModel } from "./fake-model.ts";

const project = process.env.GUARD_TEST_PROJECT;
const agentDir = process.env.PI_CODING_AGENT_DIR;
const tool = process.env.GUARD_TEST_TOOL;
const searchPath = process.env.GUARD_TEST_PATH || ".";
if (process.env.GUARD_TEST_LOADER_KEY) process.env[process.env.GUARD_TEST_LOADER_KEY] = "/guard-test-loader";
const fake = createFakeModel([
  { content: [{ type: "toolCall", id: "search", name: tool, arguments: { path: searchPath, pattern: "needle" } }] },
  { content: [{ type: "text", text: "done" }] },
]);
const loader = new DefaultResourceLoader({
  cwd: project, agentDir,
  additionalExtensionPaths: [fileURLToPath(new URL("../../extensions/index.ts", import.meta.url))],
  noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
  extensionFactories: process.env.GUARD_TEST_DENY ? [(pi) => { pi.on("session_start", () => {
    pi.appendEntry("guard-rule", { op: "add", rule: { id: "deny-search", decision: "deny", tool, match: { kind: "path", path: searchPath }, scope: "session", cwd: project, createdAt: new Date().toISOString() } });
  }); }] : [],
});
await loader.reload();
if (loader.getExtensions().errors.length) throw new Error("extension failed to load");
const { session } = await createAgentSession({ cwd: project, agentDir, model: fake.model, sessionManager: SessionManager.inMemory(project), tools: [tool], resourceLoader: loader });
try {
  session.modelRuntime.hasConfiguredAuth = () => true;
  session.agent.streamFunction = fake.stream;
  await session.prompt("Search the project");
  const result = session.messages.find((message) => message.role === "toolResult" && message.toolCallId === "search");
  process.stdout.write(JSON.stringify({ blocked: !!result?.isError, content: result?.content }));
} finally { session.dispose(); }
