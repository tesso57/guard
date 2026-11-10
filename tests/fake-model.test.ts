import assert from "node:assert/strict";
import { existsSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { normalizeContext } from "@earendil-works/pi-ai";
import { createAgentSession, DefaultResourceLoader, SessionManager } from "@earendil-works/pi-coding-agent";
import { createFakeModel } from "./helpers/fake-model.ts";

test("guard handles project, protected and home writes in real Pi sessions", async () => {
  const dir = await mkdtemp(join(tmpdir(), "guard-fake-model-"));
  const home = join(dir, "home"), project = join(dir, "project");
  await Promise.all([mkdir(home), mkdir(project)]);
  const isolated = (key: string) => ["RISK_", "GUARD_", "OPENAI_", "PI_"].some((prefix) => key.startsWith(prefix)) || ["HOME", "XDG_CONFIG_HOME"].includes(key);
  const previous = new Map(Object.entries(process.env).filter(([key]) => isolated(key)));
  for (const key of previous.keys()) delete process.env[key];
  process.env.HOME = home;
  process.env.XDG_CONFIG_HOME = join(home, ".config");
  process.env.PI_CODING_AGENT_DIR = join(dir, "agent");
  // A Pi credential must not silently enable guard's separate Decisions API client.
  process.env.OPENAI_API_KEY = "fake-pi-only-key";
  const networkFetch = globalThis.fetch;
  let unexpectedRequests = 0;
  globalThis.fetch = (async () => {
    unexpectedRequests++;
    throw new Error("unexpected network request in fake model test");
  }) as typeof fetch;
  const fake = createFakeModel([
    { content: [{ type: "toolCall", id: "call-1", name: "write", arguments: { path: "ordinary.txt", content: "ordinary content" } }] },
    { content: [{ type: "toolCall", id: "call-check", name: "write", arguments: { path: join(dir, "outside.txt"), content: "outside content" } }] },
    { content: [{ type: "toolCall", id: "call-2", name: "write", arguments: { path: ".pi/guard.json", content: "{}" } }] },
    { content: [{ type: "text", text: "done" }] },
  ]);
  try {
    const loader = new DefaultResourceLoader({
      cwd: project,
      agentDir: join(dir, "agent"),
      additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))],
      noSkills: true,
      noPromptTemplates: true,
      noThemes: true,
      noContextFiles: true,
    });
    await loader.reload();
    assert.deepEqual(loader.getExtensions().errors, []);
    const { session } = await createAgentSession({ cwd: project, agentDir: join(dir, "agent"), model: fake.model, sessionManager: SessionManager.inMemory(project), tools: ["write"], resourceLoader: loader });
    try {
      session.modelRuntime.hasConfiguredAuth = () => true;
      session.agent.streamFunction = fake.stream;
      await session.prompt("Write an ordinary file, then try a protected file");
      assert.equal(fake.requests.length, 4);
      const results = session.messages.filter((message) => message.role === "toolResult");
      assert.equal(results.length, 3);
      const auditFile = join(dir, "agent", "guard", "audit.jsonl");
      assert.equal(results[0].isError, false, `${JSON.stringify(results[0].content)} ${existsSync(auditFile) ? readFileSync(auditFile, "utf8") : "no audit"}`);
      assert.equal(readFileSync(join(project, "ordinary.txt"), "utf8"), "ordinary content");
      assert.equal(results[1].isError, true);
      assert.equal(existsSync(join(dir, "outside.txt")), false);
      assert.match(readFileSync(auditFile, "utf8"), /GUARD_OPENAI_API_KEY is not set/);
      assert.equal(results[2].isError, true);
      assert.ok(results[2].content.some((item) => item.type === "text" && item.text.includes("guard: blocked")));
      assert.equal(existsSync(join(project, ".pi", "guard.json")), false);
    } finally {
      session.dispose();
    }
    const homeFake = createFakeModel([
      { content: [{ type: "toolCall", id: "home-call", name: "write", arguments: { path: "home-file.txt", content: "home content" } }] },
      { content: [{ type: "text", text: "done" }] },
    ]);
    const homeLoader = new DefaultResourceLoader({ cwd: home, agentDir: join(dir, "agent"), additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))], noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true });
    await homeLoader.reload();
    assert.deepEqual(homeLoader.getExtensions().errors, []);
    const { session: homeSession } = await createAgentSession({ cwd: home, agentDir: join(dir, "agent"), model: homeFake.model, sessionManager: SessionManager.inMemory(home), tools: ["write"], resourceLoader: homeLoader });
    try {
      homeSession.modelRuntime.hasConfiguredAuth = () => true;
      homeSession.agent.streamFunction = homeFake.stream;
      await homeSession.prompt("Try writing in the home directory");
      const result = homeSession.messages.find((message) => message.role === "toolResult");
      assert.ok(result && result.role === "toolResult" && result.isError);
      assert.equal(existsSync(join(home, "home-file.txt")), false);
      const audit = readFileSync(join(dir, "agent", "guard", "audit.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
      const homeRecord = audit.findLast((record) => record.preview.includes("home-file.txt"));
      assert.ok(homeRecord, "home write audit record is missing");
      assert.ok(homeRecord.reasons.some((reason: string) => reason.includes("GUARD_OPENAI_API_KEY is not set")), JSON.stringify(homeRecord));
    } finally {
      homeSession.dispose();
    }
    assert.equal(unexpectedRequests, 0, "a rules-only session attempted a network request");
    const apiFake = createFakeModel([
      { content: [{ type: "toolCall", id: "home-api-call", name: "write", arguments: { path: "home-api-file.txt", content: "home content" } }] },
      { content: [{ type: "text", text: "done" }] },
    ]);
    const apiLoader = new DefaultResourceLoader({ cwd: home, agentDir: join(dir, "agent"), additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))], noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true });
    await apiLoader.reload();
    assert.deepEqual(apiLoader.getExtensions().errors, []);
    const originalFetch = globalThis.fetch;
    let decisionRequests = 0;
    let wrongDecisionCredential = false;
    let credentialLeakedInBody = false;
    let lightRequests = 0, lightContextMasked = false, lightContextLeaked = false;
    const lightSecret = "opaque-light-context-secret";
    process.env.GUARD_OPENAI_API_KEY = "fake-key";
    globalThis.fetch = (async (input, init) => {
      if (String(input) !== "https://api.openai.com/v1/decisions") {
        unexpectedRequests++;
        throw new Error("unexpected endpoint in fake model test");
      }
      decisionRequests++;
      wrongDecisionCredential ||= new Headers(init?.headers).get("authorization") !== "Bearer fake-key";
      const body = JSON.parse(String(init?.body));
      const serialized = JSON.stringify(body);
      credentialLeakedInBody ||= serialized.includes("fake-pi-only-key") || serialized.includes("fake-key");
      if (body.questions.length === 4) {
        lightRequests++;
        lightContextMasked ||= serialized.includes("TOKEN=[REDACTED]");
        lightContextLeaked ||= serialized.includes(lightSecret);
      }
      const answers = body.questions.map((question: { type: string; name: string }) => question.type === "score"
        ? { type: "score", name: question.name, score: 4, confidence: 0.99, probabilities: [0, 1, 2, 3, 4].map((value) => ({ value, probability: value === 4 ? 1 : 0 })) }
        : question.type === "choice" ? { type: "choice", name: question.name, choice: "other", confidence: 0.99 }
          : { type: "predicate", name: question.name, probability: 0 });
      return new Response(JSON.stringify({ answers }), { status: 200 });
    }) as typeof fetch;
    try {
      const { session: apiSession } = await createAgentSession({ cwd: home, agentDir: join(dir, "agent"), model: apiFake.model, sessionManager: SessionManager.inMemory(home), tools: ["write"], resourceLoader: apiLoader });
      try {
        apiSession.modelRuntime.hasConfiguredAuth = () => true;
        apiSession.agent.streamFunction = apiFake.stream;
        await apiSession.prompt("Try another home directory write");
        const result = apiSession.messages.find((message) => message.role === "toolResult");
        assert.ok(result && result.role === "toolResult" && result.isError);
        assert.ok(decisionRequests >= 1, "the Decisions API mock was not called");
        assert.equal(wrongDecisionCredential, false, "guard did not use its dedicated API key");
        assert.equal(existsSync(join(home, "home-api-file.txt")), false);
        const audit = readFileSync(join(dir, "agent", "guard", "audit.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
        const record = audit.findLast((item) => item.preview.includes("home-api-file.txt"));
        assert.ok(record?.source === "model" && record.reasons.some((reason: string) => reason.includes("catastrophic")), JSON.stringify(record));
      } finally {
        apiSession.dispose();
      }
      const lightCwd = realpathSync(project);
      const lightTarget = join(lightCwd, "light-allowed.txt");
      const lightManager = SessionManager.inMemory(lightCwd);
      lightManager.appendCustomEntry("guard-rule", { op: "add", rule: { id: "light-allow", decision: "allow", tool: "write", match: { kind: "path", path: lightTarget }, scope: "session", cwd: lightCwd, createdAt: "" } });
      const lightLoader = new DefaultResourceLoader({ cwd: lightCwd, agentDir: join(dir, "agent"), additionalExtensionPaths: [fileURLToPath(new URL("../extensions/index.ts", import.meta.url))], noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true });
      await lightLoader.reload();
      assert.deepEqual(lightLoader.getExtensions().errors, []);
      const lightFake = createFakeModel([
        { content: [{ type: "toolCall", id: "light-control", name: "write", arguments: { path: "light-allowed.txt", content: "ordinary content" } }] },
        { content: [{ type: "text", text: "done" }] },
        { content: [{ type: "toolCall", id: "light-call", name: "write", arguments: { path: "light-allowed.txt", content: "ordinary content" } }] },
        { content: [{ type: "text", text: "done" }] },
      ]);
      const { session: lightSession } = await createAgentSession({ cwd: lightCwd, agentDir: join(dir, "agent"), model: lightFake.model, sessionManager: lightManager, tools: ["write"], resourceLoader: lightLoader });
      try {
        lightSession.modelRuntime.hasConfiguredAuth = () => true;
        lightSession.agent.streamFunction = lightFake.stream;
        await lightSession.prompt("Write the file.");
        const control = lightSession.messages.find((message) => message.role === "toolResult");
        assert.ok(control && control.role === "toolResult" && !control.isError);
        assert.ok(lightRequests >= 1, "the control did not use the light check");
        assert.equal(readFileSync(lightTarget, "utf8"), "ordinary content");
        rmSync(lightTarget);
        lightRequests = 0;
        await lightSession.prompt(`Write the file. TOKEN=${lightSecret}`);
        const result = lightSession.messages.findLast((message) => message.role === "toolResult");
        assert.ok(result && result.role === "toolResult" && result.isError);
        assert.ok(lightRequests >= 1 && lightContextMasked && !lightContextLeaked, "the light check did not receive correctly redacted context");
        assert.equal(existsSync(lightTarget), false);
        const audit = readFileSync(join(dir, "agent", "guard", "audit.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line));
        const record = audit.findLast((item) => item.preview.includes("light-allowed.txt"));
        assert.ok(record?.source === "model" && record.reasons.includes("part of the judgement context was redacted"), JSON.stringify(record));
      } finally {
        lightSession.dispose();
      }
      assert.equal(wrongDecisionCredential, false, "a Decisions API request did not use guard's dedicated key");
      assert.equal(credentialLeakedInBody, false, "an API credential appeared in a Decisions API request body");
    } finally {
      globalThis.fetch = originalFetch;
      delete process.env.GUARD_OPENAI_API_KEY;
    }
    assert.equal(unexpectedRequests, 0, "the fake model test attempted an unmocked network request");
  } finally {
    globalThis.fetch = networkFetch;
    for (const key of Object.keys(process.env)) if (isolated(key)) delete process.env[key];
    for (const [key, value] of previous) process.env[key] = value;
    await rm(dir, { recursive: true, force: true });
  }
});

test("fake model fails when its scripted responses are exhausted", () => {
  const fake = createFakeModel([]);
  assert.throws(() => fake.stream(fake.model, normalizeContext({ messages: [] })), /script exhausted/);
  assert.equal(fake.requests.length, 0);
});

test("fake model records each request before later context changes", () => {
  const fake = createFakeModel([{ content: [{ type: "text", text: "done" }] }]);
  const first = { role: "user" as const, content: [{ type: "text" as const, text: "before" }], timestamp: 0 };
  const context = normalizeContext({ messages: [first] });
  fake.stream(fake.model, context);
  first.content[0].text = "changed";
  context.messages.push({ role: "user", content: [{ type: "text", text: "later" }], timestamp: 0 });
  assert.deepEqual(fake.requests[0].messages, [{ role: "user", content: [{ type: "text", text: "before" }], timestamp: 0 }]);
});

test("fake model keeps the response script as it was supplied", async () => {
  const reply = { content: [{ type: "text" as const, text: "original" }] };
  const fake = createFakeModel([reply]);
  reply.content[0].text = "modified later";
  const message = await fake.stream(fake.model, normalizeContext({ messages: [] })).result();
  assert.deepEqual(message.content, [{ type: "text", text: "original" }]);
});

test("fake model replies remain independent when scripted content is shared", async () => {
  const shared = { type: "text" as const, text: "original" };
  const fake = createFakeModel([{ content: [shared] }, { content: [shared] }]);
  const context = normalizeContext({ messages: [] });
  const first = await fake.stream(fake.model, context).result();
  assert.ok(first.content[0].type === "text");
  first.content[0].text = "modified after delivery";
  const second = await fake.stream(fake.model, context).result();
  assert.deepEqual(second.content, [{ type: "text", text: "original" }]);
});
