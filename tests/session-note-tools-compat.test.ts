import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  AgentSession, createAgentSession, createEditTool, createEditToolDefinition,
  createWriteTool, createWriteToolDefinition, DefaultResourceLoader, SessionManager,
} from "@earendil-works/pi-coding-agent";
import { createFakeModel } from "./helpers/fake-model.ts";

test("Guard keeps file tools supplied by Pi extensions and SDK callers", async (t) => {
  const cwd = realpathSync(mkdtempSync(join(tmpdir(), "guard-note-tools-")));
  const agentDir = join(cwd, "agent");
  const previous = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  const guardPath = fileURLToPath(new URL("../extensions/index.ts", import.meta.url));
  const options = {
    cwd, agentDir, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
  };
  const model = createFakeModel([]).model;
  try {
    await t.test("another extension supplies edit and write", async () => {
      const edit = { ...createEditToolDefinition(cwd), description: "Extension edit" };
      const write = { ...createWriteToolDefinition(cwd), description: "Extension write" };
      const loader = new DefaultResourceLoader({
        ...options,
        additionalExtensionPaths: [guardPath],
        extensionFactories: [(pi) => {
          pi.registerTool(edit);
          pi.registerTool(write);
        }],
      });
      await loader.reload();
      assert.deepEqual(loader.getExtensions().errors, []);
      const { session } = await createAgentSession({
        cwd, agentDir, model, sessionManager: SessionManager.inMemory(cwd), resourceLoader: loader,
      });
      try {
        await session.bindExtensions({});
        assert.equal(session.getToolDefinition("edit"), edit);
        assert.equal(session.getToolDefinition("write"), write);
        const guard = loader.getExtensions().extensions.find((extension) => extension.commands.has("guard"));
        assert.ok(guard);
        assert.equal(guard.tools.has("edit"), false);
        assert.equal(guard.tools.has("write"), false);
      } finally {
        session.dispose();
      }
    });

    await t.test("SDK base tool overrides can share the stock parameter schemas", async () => {
      const seedLoader = new DefaultResourceLoader(options);
      await seedLoader.reload();
      const { session: seed } = await createAgentSession({
        cwd, agentDir, model, sessionManager: SessionManager.inMemory(cwd), resourceLoader: seedLoader,
      });
      seed.dispose();
      const loader = new DefaultResourceLoader({ ...options, additionalExtensionPaths: [guardPath] });
      await loader.reload();
      assert.deepEqual(loader.getExtensions().errors, []);
      const execute = async () => ({ content: [], details: undefined });
      const session = new AgentSession({
        cwd,
        agent: seed.agent,
        modelRuntime: seed.modelRuntime,
        settingsManager: seed.settingsManager,
        sessionManager: SessionManager.inMemory(cwd),
        resourceLoader: loader,
        baseToolsOverride: {
          edit: { ...createEditTool(cwd), execute },
          write: { ...createWriteTool(cwd), execute },
        },
      });
      try {
        assert.equal(session.getAllTools().find((tool) => tool.name === "write")?.sourceInfo.source, "builtin");
        const edit = session.getToolDefinition("edit");
        const write = session.getToolDefinition("write");
        assert.ok(edit && write);
        await session.bindExtensions({});
        assert.equal(session.getToolDefinition("edit"), edit);
        assert.equal(session.getToolDefinition("write"), write);
      } finally {
        session.dispose();
      }
    });
  } finally {
    if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previous;
    rmSync(cwd, { recursive: true, force: true });
  }
});
