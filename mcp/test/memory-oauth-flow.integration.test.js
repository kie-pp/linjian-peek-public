import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import express from "express";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { createMemoryMcpRouter } from "../memory-mcp-router.js";
import { createMemoryOAuth } from "../memory-oauth.js";
import { installMemoryToolListContract, registerMemoryTools } from "../memory-tools.js";

async function listen(app) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve({ server, origin: `http://127.0.0.1:${address.port}` });
    });
    server.on("error", reject);
  });
}

async function close(server) {
  if (!server) return;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function base64url(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

test("local OAuth discovery, PKCE login, reader/writer MCP permissions, and public endpoint isolation", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = "local-oauth-test";
  publicJwk.alg = "RS256";
  const codes = new Map();
  const authorizationRequests = [];
  const tokenRequests = [];
  let issuer;
  let resource;

  const identityApp = express();
  identityApp.use(express.urlencoded({ extended: false }));
  identityApp.use(express.json());
  identityApp.get("/.well-known/oauth-authorization-server", (_req, res) => res.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    registration_endpoint: `${issuer}/register`,
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "profile", "offline_access"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
  }));
  identityApp.get("/jwks", (_req, res) => res.json({ keys: [publicJwk] }));
  identityApp.post("/register", (_req, res) => res.status(201).json({
    client_id: "local-chatgpt-client",
    token_endpoint_auth_method: "none",
  }));
  identityApp.get("/authorize", (req, res) => {
    authorizationRequests.push({ ...req.query });
    assert.equal(req.query.response_type, "code");
    assert.equal(req.query.code_challenge_method, "S256");
    assert.equal(req.query.resource, resource);
    const code = base64url(randomBytes(18));
    codes.set(code, {
      challenge: req.query.code_challenge,
      clientId: req.query.client_id,
      redirectUri: req.query.redirect_uri,
      scope: req.query.scope,
    });
    const redirect = new URL(req.query.redirect_uri);
    redirect.searchParams.set("code", code);
    redirect.searchParams.set("state", req.query.state);
    redirect.searchParams.set("iss", issuer);
    res.redirect(302, redirect.toString());
  });
  identityApp.post("/token", async (req, res) => {
    tokenRequests.push({ ...req.body });
    const grant = codes.get(req.body.code);
    const actualChallenge = base64url(createHash("sha256").update(req.body.code_verifier).digest());
    assert.ok(grant);
    assert.equal(actualChallenge, grant.challenge);
    assert.equal(req.body.resource, resource);
    assert.equal(req.body.client_id, grant.clientId);
    assert.equal(req.body.redirect_uri, grant.redirectUri);
    codes.delete(req.body.code);
    const accessToken = await new SignJWT({ sub: "user-1", scope: grant.scope })
      .setProtectedHeader({ alg: "RS256", kid: publicJwk.kid })
      .setIssuer(issuer)
      .setAudience(resource)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
    res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 300, scope: grant.scope });
  });

  let identityServer;
  let mcpServer;
  const clients = [];
  try {
    ({ server: identityServer, origin: issuer } = await listen(identityApp));

    const memoryApp = express();
    memoryApp.use(express.json());
    const placeholder = await listen(memoryApp);
    mcpServer = placeholder.server;
    resource = `${placeholder.origin}/mcp-memory`;

    const oauth = createMemoryOAuth({
      issuer,
      audience: resource,
      jwksUrl: `${issuer}/jwks`,
      resource,
      allowedSubjects: ["user-1"],
      allowInsecureLocalhost: true,
    });
    const backendCalls = [];
    const makeServer = (authInfo) => {
      const server = new McpServer({ name: "local-memory", version: "1.0.0" });
      registerMemoryTools(server, {
        enabled: true,
        scopes: authInfo.scopes,
        fetchImpl: async (path, options) => {
          backendCalls.push({ path, method: options.method });
          return new Response(JSON.stringify({ active_memory: { content: "fake", revision: 1 } }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        },
      });
      installMemoryToolListContract(server);
      return server;
    };
    const makeDiscoveryServer = () => {
      const server = new McpServer({ name: "local-memory", version: "1.0.0" });
      registerMemoryTools(server, {
        enabled: true,
        scopes: ["memory:read", "memory:write"],
        fetchImpl: async () => new Response(JSON.stringify({ error: "memory_oauth_required" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        }),
      });
      installMemoryToolListContract(server);
      return server;
    };
    memoryApp.use(createMemoryMcpRouter({
      enabled: true,
      toolsEnabled: true,
      writerReady: true,
      oauth,
      makeServer,
      makeDiscoveryServer,
    }));
    memoryApp.post("/mcp", (_req, res) => res.json({
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [{ name: "public_status_tool" }] },
    }));

    const challengeResponse = await fetch(resource);
    assert.equal(challengeResponse.status, 401);
    const challenge = challengeResponse.headers.get("www-authenticate");
    assert.match(challenge, /^Bearer realm="shared-memory"/);
    assert.match(challenge, /scope="memory:read memory:write"/);
    const metadataUrl = challenge.match(/resource_metadata="([^"]+)"/)[1];
    assert.equal(metadataUrl, `${placeholder.origin}/.well-known/oauth-protected-resource/mcp-memory`);
    const protectedMetadata = await fetch(metadataUrl).then((response) => response.json());
    assert.equal(protectedMetadata.resource, resource);
    assert.deepEqual(protectedMetadata.authorization_servers, [issuer]);

    const anonymousClient = new Client({ name: "local-chatgpt-scanner", version: "1.0.0" });
    const anonymousTransport = new StreamableHTTPClientTransport(new URL(resource));
    await anonymousClient.connect(anonymousTransport);
    clients.push(anonymousClient);
    const anonymousTools = await anonymousClient.listTools();
    assert.equal(anonymousTools.tools.length, 7);
    assert.ok(anonymousTools.tools.every((tool) => (
      tool.securitySchemes?.[0]?.type === "oauth2" || tool._meta?.securitySchemes?.[0]?.type === "oauth2"
    )));

    const anonymousCall = await fetch(resource, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 90,
        method: "tools/call",
        params: { name: "get_active_memory", arguments: {} },
      }),
    });
    assert.equal(anonymousCall.status, 401);
    assert.match(anonymousCall.headers.get("www-authenticate"), /error="invalid_token"/);

    const providerMetadata = await fetch(`${issuer}/.well-known/oauth-authorization-server`).then((response) => response.json());
    assert.equal(providerMetadata.issuer, issuer);
    assert.ok(providerMetadata.code_challenge_methods_supported.includes("S256"));
    const registration = await fetch(providerMetadata.registration_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://chatgpt.example.test/callback"] }),
    }).then((response) => response.json());

    const issueToken = async (scope) => {
      const verifier = base64url(randomBytes(48));
      const challengeValue = base64url(createHash("sha256").update(verifier).digest());
      const state = base64url(randomBytes(12));
      const authorize = new URL(providerMetadata.authorization_endpoint);
      authorize.search = new URLSearchParams({
        response_type: "code",
        client_id: registration.client_id,
        redirect_uri: "https://chatgpt.example.test/callback",
        scope,
        state,
        resource,
        code_challenge: challengeValue,
        code_challenge_method: "S256",
      });
      const authorization = await fetch(authorize, { redirect: "manual" });
      assert.equal(authorization.status, 302);
      const callback = new URL(authorization.headers.get("location"));
      assert.equal(callback.searchParams.get("state"), state);
      assert.equal(callback.searchParams.get("iss"), issuer);
      return fetch(providerMetadata.token_endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: callback.searchParams.get("code"),
          redirect_uri: "https://chatgpt.example.test/callback",
          client_id: registration.client_id,
          code_verifier: verifier,
          resource,
        }),
      }).then((response) => response.json());
    };

    const connect = async (scope) => {
      const token = await issueToken(scope);
      const client = new Client({ name: "local-chatgpt-simulator", version: "1.0.0" });
      const transport = new StreamableHTTPClientTransport(new URL(resource), {
        requestInit: { headers: { Authorization: `Bearer ${token.access_token}` } },
      });
      await client.connect(transport);
      clients.push(client);
      return client;
    };

    const reader = await connect("memory:read");
    const readerTools = await reader.listTools();
    assert.deepEqual(readerTools.tools.map(({ name }) => name), [
      "get_memory_context", "get_active_memory", "search_memory",
    ]);
    assert.ok(readerTools.tools.every((tool) => tool._meta?.securitySchemes?.[0]?.scopes?.join(" ") === "memory:read"));
    await reader.callTool({ name: "get_active_memory", arguments: {} });
    const denied = await reader.callTool({ name: "set_active_memory", arguments: { content: "no" } });
    assert.equal(denied.isError, true);

    const invalidTokenResponse = await fetch(resource, {
      method: "POST",
      headers: {
        Authorization: "Bearer invalid-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 91, method: "tools/list", params: {} }),
    });
    assert.equal(invalidTokenResponse.status, 401);
    assert.match(invalidTokenResponse.headers.get("www-authenticate"), /error="invalid_token"/);

    const writeOnlyToken = await issueToken("memory:write");
    const insufficientScopeResponse = await fetch(resource, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${writeOnlyToken.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 92, method: "tools/list", params: {} }),
    });
    assert.equal(insufficientScopeResponse.status, 403);
    assert.match(insufficientScopeResponse.headers.get("www-authenticate"), /error="insufficient_scope"/);

    const writer = await connect("memory:read memory:write");
    const writerTools = await writer.listTools();
    assert.equal(writerTools.tools.length, 7);
    const setActive = writerTools.tools.find(({ name }) => name === "set_active_memory");
    assert.deepEqual(setActive._meta.securitySchemes, [{ type: "oauth2", scopes: ["memory:read", "memory:write"] }]);
    await writer.callTool({ name: "set_active_memory", arguments: { content: "共享测试事实" } });

    const publicResponse = await fetch(`${placeholder.origin}/mcp`, { method: "POST" }).then((response) => response.json());
    assert.ok(publicResponse.result.tools.every(({ name }) => !name.includes("memory")));
    assert.deepEqual(backendCalls.map(({ method }) => method), ["GET", "PUT"]);
    assert.equal(authorizationRequests.length, 3);
    assert.equal(tokenRequests.length, 3);
  } finally {
    await Promise.allSettled(clients.map((client) => client.close()));
    await close(mcpServer);
    await close(identityServer);
  }
});
