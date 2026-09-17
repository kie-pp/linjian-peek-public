import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";

import { installMemoryToolListContract, registerMemoryTools } from "../memory-tools.js";

function fakeMcpServer() {
  const tools = new Map();
  return {
    tools,
    tool(name, description, schema, callback) {
      tools.set(name, { description, schema, callback });
    },
    registerTool(name, config, callback) {
      tools.set(name, { ...config, schema: config.inputSchema, callback });
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
    scopes: ["memory:read", "memory:write"],
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

test("reader scope registers only the three read tools and unauthenticated scope registers none", () => {
  const reader = fakeMcpServer();
  registerMemoryTools(reader, {
    enabled: true,
    scopes: ["memory:read"],
    fetchImpl: async () => response({}),
  });
  assert.deepEqual([...reader.tools.keys()], ["get_memory_context", "get_active_memory", "search_memory"]);

  const unauthenticated = fakeMcpServer();
  registerMemoryTools(unauthenticated, {
    enabled: true,
    scopes: [],
    fetchImpl: async () => response({}),
  });
  assert.equal(unauthenticated.tools.size, 0);
});

test("every memory tool declares exact OAuth scopes in the descriptor and compatibility metadata", () => {
  const server = fakeMcpServer();
  registerMemoryTools(server, {
    enabled: true,
    scopes: ["memory:read", "memory:write"],
    fetchImpl: async () => response({}),
  });

  for (const [name, tool] of server.tools) {
    const scopes = name.startsWith("get_") || name === "search_memory"
      ? ["memory:read"]
      : ["memory:read", "memory:write"];
    const expected = [{ type: "oauth2", scopes }];
    assert.deepEqual(tool.securitySchemes, expected, `${name} top-level securitySchemes`);
    assert.deepEqual(tool._meta?.securitySchemes, expected, `${name} compatibility securitySchemes`);
  }
});

test("real MCP tools/list exposes top-level and compatibility OAuth security schemes", async () => {
  const server = new McpServer({ name: "memory-test", version: "1.0.0" });
  registerMemoryTools(server, {
    enabled: true,
    scopes: ["memory:read", "memory:write"],
    fetchImpl: async () => response({}),
  });
  installMemoryToolListContract(server);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const pending = new Map();
  clientTransport.onmessage = (message) => pending.get(message.id)?.(message);
  await Promise.all([server.connect(serverTransport), clientTransport.start()]);
  const request = async (id, method, params = {}) => {
    const response = new Promise((resolve) => pending.set(id, resolve));
    await clientTransport.send({ jsonrpc: "2.0", id, method, params });
    return response;
  };
  try {
    await request(1, "initialize", {
      protocolVersion: LATEST_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "contract-test", version: "1.0.0" },
    });
    await clientTransport.send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
    const response = await request(2, "tools/list");
    const tools = response.result.tools;
    assert.equal(tools.length, 7);
    for (const tool of tools) {
      assert.deepEqual(tool.securitySchemes, tool._meta?.securitySchemes, tool.name);
      assert.equal(tool.securitySchemes[0].type, "oauth2");
    }
  } finally {
    await clientTransport.close();
    await server.close();
  }
});

test("memory audit failure never changes a successful operation", async () => {
  const server = fakeMcpServer();
  registerMemoryTools(server, {
    enabled: true,
    scopes: ["memory:read", "memory:write"],
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
    scopes: ["memory:read", "memory:write"],
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
    scopes: ["memory:read", "memory:write"],
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
    scopes: ["memory:read", "memory:write"],
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
    scopes: ["memory:read", "memory:write"],
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

test("the public MCP never registers memory tools and the protected endpoint authenticates first", () => {
  const source = readFileSync(new URL("../server.js", import.meta.url), "utf8");
  const routerSource = readFileSync(new URL("../memory-mcp-router.js", import.meta.url), "utf8");
  const publicFactory = source.slice(source.indexOf("function makeServer()"), source.indexOf("const app = express()"));
  assert.doesNotMatch(publicFactory, /registerMemoryTools\(/);
  assert.match(source, /app\.use\(createMemoryMcpRouter\(/);
  assert.match(routerSource, /router\.post\("\/mcp-memory"/);
  assert.match(routerSource, /await oauth\.validateProvider\(\)/);
  assert.match(routerSource, /return await oauth\.authenticate\(req\.headers\)/);
  assert.match(source, /function makeMemoryServer\(authInfo\)/);
});
