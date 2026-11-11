import assert from "node:assert/strict";
import { once } from "node:events";
import http from "node:http";
import test from "node:test";
import { loadConfig } from "../extensions/guard/config.ts";
import { callDecisions } from "../extensions/guard/judge.ts";

test("judgement requests do not follow redirects", async () => {
  const previousKey = process.env.GUARD_OPENAI_API_KEY;
  process.env.GUARD_OPENAI_API_KEY = "fixture-key";
  // Node can enable an environment proxy before this test starts.
  const restoreProxy = http.setGlobalProxyFromEnv?.({ http_proxy: "http://127.0.0.1:1", https_proxy: "http://127.0.0.1:1", no_proxy: "127.0.0.1,localhost" });
  let forwarded = 0;
  const destination = http.createServer((_req, res) => { forwarded++; res.end('{"answers":[]}'); });
  let location = "";
  const source = http.createServer((req, res) => {
    if (req.url === "/redirected") { forwarded++; res.end('{"answers":[]}'); return; }
    res.writeHead(307, { location });
    res.end();
  });
  try {
    destination.listen(0, "127.0.0.1");
    await once(destination, "listening", { signal: AbortSignal.timeout(5000) });
    source.listen(0, "127.0.0.1");
    await once(source, "listening", { signal: AbortSignal.timeout(5000) });
    const address = source.address();
    const target = destination.address();
    assert(address && typeof address !== "string" && target && typeof target !== "string");
    const cfg = { ...loadConfig(), baseUrl: `http://127.0.0.1:${address.port}`, timeoutMs: 2000 };
    for (location of [`http://127.0.0.1:${target.port}/redirected`, "/redirected"]) {
      await assert.rejects(callDecisions(cfg, { text: "fixture-private-context" }), /Decisions API 307/);
      assert.equal(forwarded, 0);
    }
  } finally {
    restoreProxy?.();
    if (previousKey === undefined) delete process.env.GUARD_OPENAI_API_KEY;
    else process.env.GUARD_OPENAI_API_KEY = previousKey;
    for (const server of [source, destination]) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }
});
