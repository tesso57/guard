import { createEventBus, SessionManager } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI, ExtensionCommandContext, ExtensionContext } from "@earendil-works/pi-coding-agent";

type Command = Parameters<ExtensionAPI["registerCommand"]>[1];
type Tool = Parameters<ExtensionAPI["registerTool"]>[0];
type EventHandler = (event: never, context: ExtensionContext) => unknown;
type Responses = {
  confirm?: boolean[];
  input?: (string | undefined)[];
  select?: (string | undefined)[];
};

/** A deliberately partial Pi double. Unsupported APIs fail instead of silently succeeding. */
export function createMockPi(responses: Responses = {}) {
  const commands = new Map<string, Command>();
  const tools = new Map<string, Tool>();
  const events = new Map<string, EventHandler[]>();
  const sessionManager = SessionManager.inMemory(process.cwd());
  const dialogs: ({ kind: "select"; title: string; options: string[] } | { kind: "input"; title: string; placeholder?: string } | { kind: "confirm"; title: string; message: string })[] = [];
  const statuses = new Map<string, string>();
  const widgets = new Map<string, string[]>();
  const userMessages: { content: Parameters<ExtensionAPI["sendUserMessage"]>[0]; options: Parameters<ExtensionAPI["sendUserMessage"]>[1] }[] = [];
  const messages: { message: Parameters<ExtensionAPI["sendMessage"]>[0]; options: Parameters<ExtensionAPI["sendMessage"]>[1] }[] = [];
  const notifications: { message: string; type: string }[] = [];
  const queues = {
    confirm: [...(responses.confirm ?? [])],
    input: [...(responses.input ?? [])],
    select: [...(responses.select ?? [])],
  };
  function take<K extends keyof typeof queues>(kind: K): (typeof queues)[K][number] {
    const queue = queues[kind];
    if (queue.length === 0) throw new Error(`No mock response for ${kind}`);
    return queue.shift() as (typeof queues)[K][number];
  }
  const context = {
    cwd: process.cwd(),
    sessionManager,
    hasUI: true,
    mode: "tui",
    ui: {
      notify(message: string, type = "info") { notifications.push({ message, type }); },
      async confirm(title: string, message: string) { dialogs.push({ kind: "confirm", title, message }); return take("confirm"); },
      async input(title: string, placeholder?: string) { dialogs.push({ kind: "input", title, placeholder }); return take("input"); },
      async select(title: string, options: string[]) { dialogs.push({ kind: "select", title, options: [...options] }); return take("select"); },
      setStatus(key: string, text: string | undefined) { if (text === undefined) statuses.delete(key); else statuses.set(key, text); },
      setWidget(key: string, content: string[] | undefined) {
        if (content === undefined) widgets.delete(key);
        else if (Array.isArray(content)) widgets.set(key, [...content]);
        else throw new Error("Component widgets are not supported by the mock");
      },
    },
  } as unknown as ExtensionCommandContext;
  const pi = {
    events: createEventBus(),
    appendEntry(customType: string, data?: unknown) { sessionManager.appendCustomEntry(customType, data); },
    sendUserMessage(content: Parameters<ExtensionAPI["sendUserMessage"]>[0], options?: Parameters<ExtensionAPI["sendUserMessage"]>[1]) { userMessages.push({ content, options }); },
    sendMessage(message: Parameters<ExtensionAPI["sendMessage"]>[0], options?: Parameters<ExtensionAPI["sendMessage"]>[1]) { messages.push({ message, options }); },
    registerCommand(name: string, command: Command) {
      if (typeof name !== "string" || name.length === 0) throw new Error("Command must have a non-empty string name");
      if (typeof command?.handler !== "function") throw new Error(`Command "/${name}" must define handler()`);
      commands.set(name, command);
    },
    registerTool(tool: Tool) { tools.set(tool.name, tool); },
    on(name: string, handler: EventHandler) {
      const handlers = events.get(name) ?? [];
      const registered: EventHandler = (event, context) => handler(event, context);
      handlers.push(registered);
      events.set(name, handlers);
      return () => {
        const index = handlers.indexOf(registered);
        if (index !== -1) handlers.splice(index, 1);
      };
    },
  } as unknown as ExtensionAPI;
  return {
    pi, context, sessionManager, commands, tools, notifications, dialogs, statuses, widgets, userMessages, messages, responses: queues,
    async runCommand(name: string, args = "") {
      const command = commands.get(name);
      if (!command) throw new Error(`Unknown command: ${name}`);
      await command.handler(args, context);
    },
    async emit(name: string, event: unknown) {
      const results: unknown[] = [];
      for (const handler of [...(events.get(name) ?? [])]) {
        results.push(await handler(event as never, context));
      }
      return results;
    },
  };
}
