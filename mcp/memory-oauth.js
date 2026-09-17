import { createRemoteJWKSet, jwtVerify } from "jose";

const REQUIRED_READ_SCOPE = "memory:read";
const WRITE_SCOPE = "memory:write";
const INITIAL_SCOPES = `${REQUIRED_READ_SCOPE} ${WRITE_SCOPE}`;

export class MemoryOAuthError extends Error {
  constructor(code, status = 401) {
    super(code);
    this.name = "MemoryOAuthError";
    this.code = code;
    this.status = status;
  }
}

export function createMemoryOAuth({
  issuer,
  audience,
  jwksUrl,
  resource,
  allowedSubjects,
  verifyToken,
  loadProviderMetadata,
  allowInsecureLocalhost = false,
} = {}) {
  const config = {
    issuer: normalizeUrl(issuer, "memory_oauth_issuer_required", allowInsecureLocalhost),
    audience: normalizeUrl(audience, "memory_oauth_audience_required", allowInsecureLocalhost),
    jwksUrl: normalizeUrl(jwksUrl, "memory_oauth_jwks_url_required", allowInsecureLocalhost),
    resource: normalizeUrl(resource, "memory_oauth_resource_required", allowInsecureLocalhost),
    allowedSubjects: normalizeAllowedSubjects(allowedSubjects),
  };
  if (config.audience !== config.resource) {
    throw new MemoryOAuthError("memory_oauth_audience_resource_mismatch", 503);
  }
  if (new URL(config.jwksUrl).origin !== new URL(config.issuer).origin) {
    throw new MemoryOAuthError("memory_oauth_jwks_origin_invalid", 503);
  }
  const resourceUrl = new URL(config.resource);
  if (resourceUrl.pathname !== "/mcp-memory" || resourceUrl.search || resourceUrl.hash) {
    throw new MemoryOAuthError("memory_oauth_resource_path_invalid", 503);
  }
  const jwks = verifyToken ? null : createRemoteJWKSet(new URL(config.jwksUrl));
  const verifier = verifyToken || ((token) => verifyMemoryAccessToken(token, {
    issuer: config.issuer,
    audience: config.audience,
    jwks,
  }));
  const metadataUrl = new URL("/.well-known/oauth-protected-resource/mcp-memory", config.resource).toString();
  const providerMetadataUrl = new URL("/.well-known/oauth-authorization-server", config.issuer).toString();
  const providerLoader = loadProviderMetadata || (() => fetchProviderMetadata(providerMetadataUrl));
  let providerMetadataPromise;

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
    async validateProvider() {
      providerMetadataPromise ||= Promise.resolve()
        .then(() => providerLoader(providerMetadataUrl))
        .then((metadata) => validateAuthorizationServerMetadata(metadata, {
          issuer: config.issuer,
          jwksUrl: config.jwksUrl,
          allowInsecureLocalhost,
        }))
        .catch((error) => {
          providerMetadataPromise = undefined;
          if (error instanceof MemoryOAuthError) throw error;
          throw new MemoryOAuthError("memory_oauth_provider_unavailable", 503);
        });
      return providerMetadataPromise;
    },
    challenge(error = "") {
      const fields = [
        'realm="shared-memory"',
        `resource_metadata="${metadataUrl}"`,
        `scope="${INITIAL_SCOPES}"`,
      ];
      if (error === "insufficient_scope") {
        fields.push('error="insufficient_scope"', 'error_description="Required OAuth scope is missing"');
      } else if (error === "invalid_token") {
        fields.push('error="invalid_token"', 'error_description="OAuth access token is missing or invalid"');
      }
      return `Bearer ${fields.join(", ")}`;
    },
    config: Object.freeze({
      issuer: config.issuer,
      audience: config.audience,
      jwksUrl: config.jwksUrl,
      resource: config.resource,
      metadataUrl,
      providerMetadataUrl,
    }),
  };
}

export function validateAuthorizationServerMetadata(metadata, {
  issuer,
  jwksUrl,
  allowInsecureLocalhost = false,
} = {}) {
  if (!metadata || typeof metadata !== "object" || metadata.issuer !== issuer) {
    throw new MemoryOAuthError("memory_oauth_provider_issuer_invalid", 503);
  }
  if (metadata.jwks_uri !== jwksUrl) {
    throw new MemoryOAuthError("memory_oauth_provider_jwks_invalid", 503);
  }
  const issuerOrigin = new URL(issuer).origin;
  const authorizationEndpoint = normalizeUrl(
    metadata.authorization_endpoint,
    "memory_oauth_provider_authorization_endpoint_invalid",
    allowInsecureLocalhost,
  );
  const tokenEndpoint = normalizeUrl(
    metadata.token_endpoint,
    "memory_oauth_provider_token_endpoint_invalid",
    allowInsecureLocalhost,
  );
  if (new URL(authorizationEndpoint).origin !== issuerOrigin || new URL(tokenEndpoint).origin !== issuerOrigin) {
    throw new MemoryOAuthError("memory_oauth_provider_endpoint_origin_invalid", 503);
  }
  if (!Array.isArray(metadata.code_challenge_methods_supported) || !metadata.code_challenge_methods_supported.includes("S256")) {
    throw new MemoryOAuthError("memory_oauth_provider_pkce_invalid", 503);
  }
  if (metadata.scopes_supported !== undefined
    && (!Array.isArray(metadata.scopes_supported)
      || metadata.scopes_supported.some((scope) => typeof scope !== "string" || !scope.trim()))) {
    throw new MemoryOAuthError("memory_oauth_provider_scopes_invalid", 503);
  }
  if (metadata.response_types_supported !== undefined
    && (!Array.isArray(metadata.response_types_supported) || !metadata.response_types_supported.includes("code"))) {
    throw new MemoryOAuthError("memory_oauth_provider_response_type_invalid", 503);
  }
  if (metadata.grant_types_supported !== undefined
    && (!Array.isArray(metadata.grant_types_supported) || !metadata.grant_types_supported.includes("authorization_code"))) {
    throw new MemoryOAuthError("memory_oauth_provider_grant_type_invalid", 503);
  }
  const authMethods = new Set(Array.isArray(metadata.token_endpoint_auth_methods_supported)
    ? metadata.token_endpoint_auth_methods_supported
    : []);
  if (!authMethods.has("none") && !authMethods.has("private_key_jwt")) {
    throw new MemoryOAuthError("memory_oauth_provider_client_auth_invalid", 503);
  }
  if (metadata.client_id_metadata_document_supported !== true && !metadata.registration_endpoint) {
    throw new MemoryOAuthError("memory_oauth_provider_client_registration_invalid", 503);
  }
  if (metadata.registration_endpoint) {
    const registrationEndpoint = normalizeUrl(
      metadata.registration_endpoint,
      "memory_oauth_provider_client_registration_invalid",
      allowInsecureLocalhost,
    );
    if (new URL(registrationEndpoint).origin !== issuerOrigin) {
      throw new MemoryOAuthError("memory_oauth_provider_endpoint_origin_invalid", 503);
    }
  }
  return metadata;
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
    allowInsecureLocalhost: env.NODE_ENV === "test",
  });
}

async function fetchProviderMetadata(url) {
  let response;
  try {
    response = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(3000),
    });
  } catch {
    throw new MemoryOAuthError("memory_oauth_provider_unavailable", 503);
  }
  if (!response.ok) throw new MemoryOAuthError("memory_oauth_provider_unavailable", 503);
  try {
    return await response.json();
  } catch {
    throw new MemoryOAuthError("memory_oauth_provider_metadata_invalid", 503);
  }
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

function normalizeUrl(value, code, allowInsecureLocalhost = false) {
  const text = requiredText(value, code);
  try {
    const url = new URL(text);
    const loopback = ["127.0.0.1", "localhost", "::1"].includes(url.hostname);
    if (url.username || url.password) throw new Error("URL credentials are forbidden");
    if (url.protocol !== "https:" && !(allowInsecureLocalhost && url.protocol === "http:" && loopback)) {
      throw new Error("https required");
    }
    return text;
  } catch {
    throw new MemoryOAuthError(code, 503);
  }
}
