import { createHash, randomUUID } from "node:crypto";
import { constants, lstatSync, realpathSync, renameSync, type BigIntStats } from "node:fs";
import { access, mkdir, open, unlink } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { createEditToolDefinition, createWriteToolDefinition, type EditOperations, type ExtensionAPI, type ExtensionContext, type WriteOperations } from "@earendil-works/pi-coding-agent";
import { resolvePath } from "./paths.ts";

type NoteSave = {
  digest?: string;
  version?: string;
  validate: () => void;
  saved: (content: string) => void;
};
type GetNoteSave = (ctx: ExtensionContext, tool: "edit" | "write", path: string, callId: string) => NoteSave | undefined;

function revision(st: BigIntStats | undefined): string | undefined {
  return st && `${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.mode}`;
}

function readVersion(st: BigIntStats): string {
  return `${revision(st)}:${st.ctimeNs}:${st.nlink}`;
}

export function noteEditSnapshot(path: string) {
  try {
    const st = lstatSync(path, { bigint: true });
    if (st.isFile()) return { linked: st.nlink > 1n, version: readVersion(st) };
  } catch { /* A missing or unreadable file grants no access to existing text. */ }
  return undefined;
}

function noteOperations(ctx: ExtensionContext, path: string, approval: NoteSave, signal?: AbortSignal): EditOperations & WriteOperations {
  const parent = dirname(path);
  const rel = relative(ctx.cwd, parent);
  const project = realpathSync(ctx.cwd);
  const physicalParent = join(project, rel);
  let originalRead: BigIntStats | undefined;
  let originalDigest: string | undefined;

  function checkPath(candidate: string) {
    if (candidate !== path || realpathSync(parent) !== physicalParent) {
      throw new Error("The authorized session note path changed");
    }
    const st = lstatSync(path, { bigint: true, throwIfNoEntry: false });
    if (st && !st.isFile()) throw new Error("The session note must be a regular file");
    return st;
  }

  async function readNote(candidate: string) {
    const before = checkPath(candidate);
    if (!before || (approval.digest === undefined && approval.version !== readVersion(before))) {
      throw new Error("Read the session note again before saving.");
    }
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const st = await file.stat({ bigint: true });
      if (!st.isFile() || revision(st) !== revision(before)) throw new Error("The session note changed before reading");
      const data = await file.readFile();
      const after = await file.stat({ bigint: true });
      if (revision(after) !== revision(st) || revision(checkPath(candidate)) !== revision(st)) {
        throw new Error("The session note changed while reading");
      }
      const digest = createHash("sha256").update(data).digest("hex");
      if (approval.digest === undefined ? approval.version !== readVersion(after) : approval.digest !== digest) {
        throw new Error("The session note changed since the last read. Read it again before saving.");
      }
      approval.validate();
      return { data, st: after, digest };
    } finally {
      await file.close();
    }
  }

  return {
    async mkdir(dir) {
      if (dir !== parent) throw new Error("The authorized session note directory changed");
      approval.validate();
      let current = project;
      for (const segment of rel.split(sep)) {
        if (segment === "..") throw new Error("The session note must be inside its project");
        current = join(current, segment);
        try { await mkdir(current); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
        if (!lstatSync(current).isDirectory()) throw new Error("The session note directory must not be a symlink");
      }
    },
    async access(candidate) {
      approval.validate();
      checkPath(candidate);
      await access(path, constants.R_OK | constants.W_OK);
    },
    async readFile(candidate) {
      const { data, st, digest } = await readNote(candidate);
      originalRead = st;
      originalDigest = digest;
      return data;
    },
    async writeFile(candidate, content) {
      approval.validate();
      const before = checkPath(candidate);
      if (originalRead && revision(before) !== revision(originalRead)) throw new Error("The session note changed during editing. Read it again before saving.");
      if (before) await access(path, constants.W_OK);
      const tmp = join(physicalParent, `.note-${randomUUID()}.tmp`);
      const file = await open(tmp, "wx", 0o600);
      let published = false;
      try {
        try {
          await file.writeFile(content, "utf8");
          await file.chmod(before ? Number(before.mode & 0o777n) : 0o666 & ~process.umask());
        } finally {
          await file.close();
        }
        if (originalRead || (before && approval.digest !== undefined)) {
          const { digest } = await readNote(candidate);
          if (originalRead && digest !== originalDigest) throw new Error("The session note changed before saving. Read it again before editing.");
        }
        signal?.throwIfAborted();
        approval.validate();
        if (revision(checkPath(candidate)) !== revision(before)) throw new Error("The session note changed before saving. Read it again before saving.");
        renameSync(tmp, path);
        published = true;
        approval.saved(content);
      } finally {
        if (!published) await unlink(tmp).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; });
      }
    },
  };
}

export function registerNoteTools(pi: ExtensionAPI, getNoteSave: GetNoteSave): (tool: string) => boolean {
  const edit = createEditToolDefinition(process.cwd());
  const write = createWriteToolDefinition(process.cwd());
  // The SDK reuses the native schema for every instance of a built-in. Give
  // these registrations their own identity for checking the selected provider.
  const editParameters = { ...edit.parameters };
  const writeParameters = { ...write.parameters };
  pi.on("session_start", () => {
    const tools = pi.getAllTools();
    // SDK base-tool overrides also have source "builtin", but their adapted
    // definitions do not carry the native prompt guidelines.
    const isNative = (tool: typeof edit | typeof write) => tools.some(info =>
      info.name === tool.name && info.sourceInfo?.source === "builtin"
      && info.parameters === tool.parameters && info.promptGuidelines !== undefined);
    if (isNative(edit)) {
      pi.registerTool({
        ...edit,
        parameters: editParameters,
        execute(id, input, signal, update, ctx) {
          const path = resolvePath(ctx.cwd, input.path);
          const approval = getNoteSave(ctx, "edit", path, id);
          const tool = approval ? createEditToolDefinition(ctx.cwd, { operations: noteOperations(ctx, path, approval, signal) }) : edit;
          return tool.execute(id, input, signal, update, ctx);
        },
      });
    }
    if (isNative(write)) {
      pi.registerTool({
        ...write,
        parameters: writeParameters,
        execute(id, input, signal, update, ctx) {
          const path = resolvePath(ctx.cwd, input.path);
          const approval = getNoteSave(ctx, "write", path, id);
          const tool = approval ? createWriteToolDefinition(ctx.cwd, { operations: noteOperations(ctx, path, approval, signal) }) : write;
          return tool.execute(id, input, signal, update, ctx);
        },
      });
    }
  });
  return (tool) => {
    const parameters = tool === "edit" ? editParameters : tool === "write" ? writeParameters : undefined;
    return parameters !== undefined && pi.getAllTools().some((info) => info.name === tool && info.parameters === parameters);
  };
}
