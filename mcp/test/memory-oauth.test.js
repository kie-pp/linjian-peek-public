import test from "node:test";
import assert from "node:assert/strict";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";

import { MemoryOAuthError, createMemoryOAuth, verifyMemoryAccessToken } from "../memory-oauth.js";

function authWith(payload) {
  return createMemoryOAuth({
    issuer: "https://auth.example.test/",
    audience: "https://memory.example.test/mcp-memory",
    jwksUrl: "https://auth.example.test/.well-known/jwks.json",
    resource: "https://memory.example.test/mcp-memory",
    allowedSubjects: ["user-1"],
    verifyToken: async (token) => {
      assert.equal(token, "valid-test-token");
      return payload;
    },
  });
}

test("missing bearer token is rejected without exposing any tools", async () => {
  const auth = authWith({ sub: "user-1", scope: "memory:read" });
  await assert.rejects(
    auth.authenticate({}),
    (error) => error instanceof MemoryOAuthError && error.status === 401 && error.code === "memory_oauth_required",
  );
  assert.match(auth.challenge(), /resource_metadata=/);
  assert.doesNotMatch(auth.challenge(), /valid-test-token/);
});

test("reader and writer scopes are isolated", async () => {
  const reader = await authWith({ sub: "user-1", scope: "memory:read offline_access" })
    .authenticate({ authorization: "Bearer valid-test-token" });
  assert.deepEqual(reader.scopes, ["memory:read", "offline_access"]);
  assert.equal(reader.canWrite, false);

  const writer = await authWith({ sub: "user-1", scope: "memory:read memory:write" })
    .authenticate({ authorization: "Bearer valid-test-token" });
  assert.equal(writer.canWrite, true);
});

test("token without memory read scope is rejected", async () => {
  const auth = authWith({ sub: "user-1", scope: "profile" });
  await assert.rejects(
    auth.authenticate({ authorization: "Bearer valid-test-token" }),
    (error) => error instanceof MemoryOAuthError && error.status === 403 && error.code === "memory_oauth_insufficient_scope",
  );
});

test("signed token for a different subject is rejected", async () => {
  const auth = authWith({ sub: "user-2", scope: "memory:read memory:write" });
  await assert.rejects(
    auth.authenticate({ authorization: "Bearer valid-test-token" }),
    (error) => error instanceof MemoryOAuthError && error.status === 403 && error.code === "memory_oauth_subject_denied",
  );
});

test("protected resource metadata points to the external authorization server", () => {
  const auth = authWith({ sub: "user-1", scope: "memory:read" });
  assert.deepEqual(auth.metadata(), {
    resource: "https://memory.example.test/mcp-memory",
    authorization_servers: ["https://auth.example.test/"],
    scopes_supported: ["memory:read", "memory:write"],
    bearer_methods_supported: ["header"],
  });
});

test("real JWT verification enforces signature issuer audience and expiry", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = "memory-test-key";
  publicJwk.alg = "RS256";
  const jwks = createLocalJWKSet({ keys: [publicJwk] });
  const issuer = "https://auth.example.test/";
  const audience = "https://memory.example.test/mcp-memory";
  const token = await new SignJWT({ scope: "memory:read", sub: "user-1" })
    .setProtectedHeader({ alg: "RS256", kid: "memory-test-key" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);

  const payload = await verifyMemoryAccessToken(token, { issuer, audience, jwks });
  assert.equal(payload.sub, "user-1");
  await assert.rejects(
    verifyMemoryAccessToken(token, { issuer, audience: "https://wrong.example.test/mcp-memory", jwks }),
  );
});
