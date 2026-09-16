import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { registerMemoryTools } from "../memory-tools.js";

function fakeMcpServer() {
  const tools = new Map();
  return {
    tools,
    tool(name, description, schema, callback) {
      tools.set(name, { description, schema, callback });
    },
  };
}

function response(payload, ok = true) {
  return { ok, status: ok ? 200 : 500, async json() { return payload; } };
}

test("memory tools are not registered while the feature flag is disabled", () => {
  const server = fakeMcpServer();
  registerMemoryTools(server, { enabled: false, fetchImpl: async () => response({}) });
  assert.equal(server.tools.size, 0);
});

test("enabled memory tools register seven namespace-free operations", async () => {
  const server = fakeMcpServer();
  const requests = [];
  registerMemoryTools(server, {
    enabled: true,
    fetchImpl: async (path, options) => {
      requests.push({ path, options });
      return response(path.endsWith("/history") ? { created: true, item: { id: "history-1" } } : { active_memory: "memory", relevant_history: [] });
    },
  });
  assert.deepEqual([...server.tools.keys()], [
    "get_memory_context",
    "get_active_memory",
    "search_memory",
    "set_active_memory",
    "append_memory",
    "revise_memory",
    "forget_memory",
  ]);
  assert.ok([...server.tools.values()].every(({ schema }) => !("namespace" in schema)));

  await server.tools.get("get_memory_context").callback({ query: "today", history_limit: 3 });
  await server.tools.get("get_active_memory").callback({});
  await server.tools.get("search_memory").callback({ query: "music", limit: 2 });
  await server.tools.get("set_active_memory").callback({ content: "new", expected_revision: 1 });
  await server.tools.get("append_memory").callback({ summary: "shared", searchable_text: "shared", source: "chatgpt" });
  await server.tools.get("revise_memory").callback({ history_id: "history-1", summary: "revised" });
  await server.tools.get("forget_memory").callback({ history_id: "history-1" });

  assert.deepEqual(requests.map(({ path }) => path), [
    "/api/memory/context",
    "/api/memory/active",
    "/api/memory/search",
    "/api/memory/active",
    "/api/memory/history",
    "/api/memory/history/history-1",
    "/api/memory/history/history-1",
  ]);
  assert.deepEqual(requests.map(({ options }) => options.method), ["POST", "GET", "POST", "PUT", "POST", "PATCH", "DELETE"]);
  assert.ok(requests.every(({ options }) => !String(options.body || "").includes("namespace")));
});

test("memory audit failure never changes a successful operation", async () => {
  const server = fakeMcpServer();
  registerMemoryTools(server, {
    enabled: true,
    fetchImpl: async () => response({ active_memory: { revision: 4 } }),
    audit: async () => { throw new Error("audit unavailable"); },
  });
  const result = await server.tools.get("set_active_memory").callback({ content: "精炼事实", expected_revision: 3 });
  assert.match(result.content[0].text, /revision/);
});

test("memory audit contains only approved metadata", async () => {
  const server = fakeMcpServer();
  const events = [];
  registerMemoryTools(server, {
    enabled: true,
    fetchImpl: async () => response({ created: true, item: { id: "history-9", summary: "secret body" } }),
    audit: async (event) => events.push(event),
  });
  await server.tools.get("append_memory").callback({ summary: "private shared fact", searchable_text: "query words" });
  assert.equal(events.length, 1);
  assert.deepEqual(Object.keys(events[0]).sort(), ["duration_ms", "history_item_id", "status", "tool"]);
  assert.doesNotMatch(JSON.stringify(events), /private shared fact|query words|secret body|namespace|token/i);
});

test("writer tools reject sensitive content before any request", async () => {
  const server = fakeMcpServer();
  let requestCount = 0;
  registerMemoryTools(server, {
    enabled: true,
    fetchImpl: async () => { requestCount += 1; return response({}); },
  });
  await assert.rejects(
    server.tools.get("append_memory").callback({ summary: "password=do-not-store-this-value" }),
    /MEMORY_SENSITIVE_CONTENT_REJECTED/,
  );
  assert.equal(requestCount, 0);
  await assert.rejects(
    server.tools.get("set_active_memory").callback({ content: "令牌：this-should-never-be-stored" }),
    /MEMORY_SENSITIVE_CONTENT_REJECTED/,
  );
  assert.equal(requestCount, 0);
});

test("writer safety permits normal links and relationship preferences", async () => {
  const server = fakeMcpServer();
  let requestCount = 0;
  registerMemoryTools(server, {
    enabled: true,
    fetchImpl: async () => { requestCount += 1; return response({ created: true, item: { id: "normal" } }); },
  });
  await server.tools.get("append_memory").callback({
    summary: "以后叫我培培，回复简短一点",
    searchable_text: "项目说明在 https://example.com/docs",
  });
  assert.equal(requestCount, 1);
});

test("tool responses and errors do not expose credentials or internal namespaces", async () => {
  const server = fakeMcpServer();
  const secret = "writer-secret-test-value";
  registerMemoryTools(server, {
    enabled: true,
    fetchImpl: async () => response({ active_memory: "safe", namespace_id: "must-not-leak", token: secret }),
  });
  const result = await server.tools.get("get_active_memory").callback({});
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /must-not-leak/);
  assert.doesNotMatch(serialized, new RegExp(secret));
});

test("writer credentials are sent only to the explicitly configured server URL", () => {
  const source = readFileSync(new URL("../server.js", import.meta.url), "utf8");
  const memoryFetch = source.match(/async function memoryFetch[\s\S]*?\n}\n/);
  assert.ok(memoryFetch);
  assert.match(memoryFetch[0], /normalizeBaseUrl\(RAW_LINJIAN_URL\)/);
  assert.match(memoryFetch[0], /await fetch\(`/);
  assert.doesNotMatch(memoryFetch[0], /linjianFetch\(/);
  assert.doesNotMatch(memoryFetch[0], /candidateOrder\(/);
});

test("memory tools bypass the legacy activity wrapper", () => {
  const source = readFileSync(new URL("../server.js", import.meta.url), "utf8");
  assert.match(source, /memoryToolNames\.has\(toolName\)/);
  assert.match(source, /registerMemoryTools\(server, \{[^}]*audit: writeMemoryAudit/);
});
