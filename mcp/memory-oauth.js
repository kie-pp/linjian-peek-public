import { createRemoteJWKSet, jwtVerify } from "jose";

const REQUIRED_READ_SCOPE = "memory:read";
const WRITE_SCOPE = "memory:write";

export class MemoryOAuthError extends Error {
  constructor(code, status = 401) {
    super(code);
    this.name = "MemoryOAuthError";
    this.code = code;
    this.status = status;
  }
}

export function createMemoryOAuth({ issuer, audience, jwksUrl, resource, allowedSubjects, verifyToken } = {}) {
  const config = {
    issuer: normalizeUrl(issuer, "memory_oauth_issuer_required"),
    audience: requiredText(audience, "memory_oauth_audience_required"),
    jwksUrl: normalizeUrl(jwksUrl, "memory_oauth_jwks_url_required"),
    resource: normalizeUrl(resource, "memory_oauth_resource_required"),
    allowedSubjects: normalizeAllowedSubjects(allowedSubjects),
  };
  const jwks = verifyToken ? null : createRemoteJWKSet(new URL(config.jwksUrl));
  const verifier = verifyToken || ((token) => verifyMemoryAccessToken(token, {
    issuer: config.issuer,
    audience: config.audience,
    jwks,
  }));
  const metadataUrl = new URL("/.well-known/oauth-protected-resource/mcp-memory", config.resource).toString();

  return {
    async authenticate(headers = {}) {
      const authorization = headerValue(headers, "authorization");
      const match = /^Bearer\s+([^\s]+)$/i.exec(authorization);
      if (!match) throw new MemoryOAuthError("memory_oauth_required", 401);
      let payload;
      try {
        payload = await verifier(match[1]);
      } catch {
        throw new MemoryOAuthError("memory_oauth_invalid_token", 401);
      }
      const subject = typeof payload?.sub === "string" ? payload.sub.trim() : "";
      if (!subject || !config.allowedSubjects.has(subject)) {
        throw new MemoryOAuthError("memory_oauth_subject_denied", 403);
      }
      const scopes = normalizeScopes([payload?.scope, payload?.scp, payload?.permissions]);
      if (!scopes.includes(REQUIRED_READ_SCOPE)) {
        throw new MemoryOAuthError("memory_oauth_insufficient_scope", 403);
      }
      return {
        subject: subject.slice(0, 256),
        scopes,
        canWrite: scopes.includes(WRITE_SCOPE),
      };
    },
    metadata() {
      return {
        resource: config.resource,
        authorization_servers: [config.issuer],
        scopes_supported: [REQUIRED_READ_SCOPE, WRITE_SCOPE],
        bearer_methods_supported: ["header"],
      };
    },
    challenge(error = "") {
      const fields = [`resource_metadata="${metadataUrl}"`, `scope="${REQUIRED_READ_SCOPE}"`];
      if (error === "insufficient_scope") fields.unshift('error="insufficient_scope"');
      return `Bearer ${fields.join(", ")}`;
    },
  };
}

export async function verifyMemoryAccessToken(token, { issuer, audience, jwks }) {
  const verified = await jwtVerify(token, jwks, {
    issuer,
    audience,
    algorithms: ["RS256", "ES256", "EdDSA"],
    clockTolerance: 5,
  });
  return verified.payload;
}

export function createMemoryOAuthFromEnv(env = process.env, verifyToken) {
  return createMemoryOAuth({
    issuer: env.MEMORY_MCP_OAUTH_ISSUER,
    audience: env.MEMORY_MCP_OAUTH_AUDIENCE,
    jwksUrl: env.MEMORY_MCP_OAUTH_JWKS_URL,
    resource: env.MEMORY_MCP_OAUTH_RESOURCE,
    allowedSubjects: env.MEMORY_MCP_OAUTH_ALLOWED_SUBJECTS,
    verifyToken,
  });
}

function normalizeScopes(value) {
  const flattened = Array.isArray(value) ? value.flat(Infinity) : [value];
  const items = flattened.flatMap((item) => String(item || "").split(/\s+/));
  return [...new Set(items.map((item) => String(item || "").trim()).filter(Boolean))].sort();
}

function normalizeAllowedSubjects(value) {
  const subjects = (Array.isArray(value) ? value : String(value || "").split(","))
    .map((item) => String(item || "").trim())
    .filter(Boolean);
  if (!subjects.length) throw new MemoryOAuthError("memory_oauth_allowed_subjects_required", 503);
  return new Set(subjects);
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== "object") return "";
  const value = headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
  return Array.isArray(value) ? String(value[0] || "") : String(value || "");
}

function requiredText(value, code) {
  const text = String(value || "").trim();
  if (!text) throw new MemoryOAuthError(code, 503);
  return text;
}

function normalizeUrl(value, code) {
  const text = requiredText(value, code);
  try {
    const url = new URL(text);
    if (url.protocol !== "https:") throw new Error("https required");
    return url.toString();
  } catch {
    throw new MemoryOAuthError(code, 503);
  }
}
