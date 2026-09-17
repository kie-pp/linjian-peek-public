import test from "node:test";
import assert from "node:assert/strict";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";

import {
  MemoryOAuthError,
  createMemoryOAuth,
  validateAuthorizationServerMetadata,
  verifyMemoryAccessToken,
} from "../memory-oauth.js";

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
  assert.equal(
    auth.challenge("invalid_token"),
    'Bearer realm="shared-memory", resource_metadata="https://memory.example.test/.well-known/oauth-protected-resource/mcp-memory", scope="memory:read memory:write", error="invalid_token", error_description="OAuth access token is missing or invalid"',
  );
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

test("resource, audience, and endpoint path must identify the same mcp-memory resource", () => {
  assert.throws(
    () => createMemoryOAuth({
      issuer: "https://auth.example.test",
      audience: "https://memory.example.test/other",
      jwksUrl: "https://auth.example.test/.well-known/jwks.json",
      resource: "https://memory.example.test/mcp-memory",
      allowedSubjects: ["user-1"],
      verifyToken: async () => ({}),
    }),
    (error) => error instanceof MemoryOAuthError && error.code === "memory_oauth_audience_resource_mismatch",
  );
  assert.throws(
    () => createMemoryOAuth({
      issuer: "https://auth.example.test",
      audience: "https://memory.example.test/not-memory",
      jwksUrl: "https://auth.example.test/.well-known/jwks.json",
      resource: "https://memory.example.test/not-memory",
      allowedSubjects: ["user-1"],
      verifyToken: async () => ({}),
    }),
    (error) => error instanceof MemoryOAuthError && error.code === "memory_oauth_resource_path_invalid",
  );
  assert.throws(
    () => createMemoryOAuth({
      issuer: "https://user:password@auth.example.test",
      audience: "https://memory.example.test/mcp-memory",
      jwksUrl: "https://auth.example.test/.well-known/jwks.json",
      resource: "https://memory.example.test/mcp-memory",
      allowedSubjects: ["user-1"],
      verifyToken: async () => ({}),
    }),
    (error) => error instanceof MemoryOAuthError && error.code === "memory_oauth_issuer_required",
  );
  assert.throws(
    () => createMemoryOAuth({
      issuer: "https://auth.example.test",
      audience: "https://memory.example.test/mcp-memory",
      jwksUrl: "https://keys.example.test/.well-known/jwks.json",
      resource: "https://memory.example.test/mcp-memory",
      allowedSubjects: ["user-1"],
      verifyToken: async () => ({}),
    }),
    (error) => error instanceof MemoryOAuthError && error.code === "memory_oauth_jwks_origin_invalid",
  );
});

test("authorization server metadata must match issuer, JWKS, authorization code, and PKCE S256", () => {
  const expected = {
    issuer: "https://auth.example.test",
    jwksUrl: "https://auth.example.test/.well-known/jwks.json",
  };
  const valid = {
    issuer: expected.issuer,
    authorization_endpoint: "https://auth.example.test/oauth2/authorize",
    token_endpoint: "https://auth.example.test/oauth2/token",
    jwks_uri: expected.jwksUrl,
    registration_endpoint: "https://auth.example.test/oauth2/register",
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "profile", "offline_access"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
  };
  assert.equal(validateAuthorizationServerMetadata(valid, expected).issuer, expected.issuer);
  for (const [field, value] of [
    ["issuer", { ...valid, issuer: "https://other.example.test" }],
    ["jwks", { ...valid, jwks_uri: "https://other.example.test/jwks" }],
    ["pkce", { ...valid, code_challenge_methods_supported: ["plain"] }],
    ["scopes", { ...valid, scopes_supported: ["openid", ""] }],
    ["response_type", { ...valid, response_types_supported: ["token"] }],
    ["grant_type", { ...valid, grant_types_supported: ["client_credentials"] }],
    ["endpoint_origin", { ...valid, token_endpoint: "https://other.example.test/oauth2/token" }],
  ]) {
    assert.throws(
      () => validateAuthorizationServerMetadata(value, expected),
      (error) => error instanceof MemoryOAuthError && error.code === `memory_oauth_provider_${field}_invalid`,
    );
  }
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
