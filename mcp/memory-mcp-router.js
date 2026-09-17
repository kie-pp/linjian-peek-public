import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { MemoryOAuthError } from "./memory-oauth.js";

export function createMemoryMcpRouter({
  enabled = false,
  toolsEnabled = false,
  writerReady = false,
  oauth,
  makeServer,
} = {}) {
  const router = express.Router();
  const configured = enabled && toolsEnabled;

  router.get("/.well-known/oauth-protected-resource/mcp-memory", (_req, res) => {
    if (!configured) return res.status(404).json({ ok: false, error: "memory_mcp_not_enabled" });
    if (!oauth) return res.status(503).json({ ok: false, error: "memory_mcp_not_ready" });
    return res.json(oauth.metadata());
  });

  const authenticate = async (req, res) => {
    if (!configured) {
      res.status(404).json({ ok: false, error: "memory_mcp_not_enabled" });
      return null;
    }
    if (!oauth || !writerReady || typeof makeServer !== "function") {
      res.status(503).json({ ok: false, error: "memory_mcp_not_ready" });
      return null;
    }
    if (!/^Bearer\s+\S+$/i.test(String(req.headers.authorization || ""))) {
      return sendOAuthError(res, oauth, new MemoryOAuthError("memory_oauth_required", 401));
    }
    try {
      await oauth.validateProvider();
    } catch {
      res.status(503).json({ ok: false, error: "memory_oauth_provider_not_ready" });
      return null;
    }
    try {
      return await oauth.authenticate(req.headers);
    } catch (error) {
      if (error instanceof MemoryOAuthError) return sendOAuthError(res, oauth, error);
      return sendOAuthError(res, oauth, new MemoryOAuthError("memory_oauth_invalid_token", 401));
    }
  };

  router.post("/mcp-memory", async (req, res) => {
    const authInfo = await authenticate(req, res);
    if (!authInfo) return;
    try {
      const server = makeServer(authInfo);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => transport.close());
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch {
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Memory MCP request failed" }, id: null });
      }
    }
  });

  router.get("/mcp-memory", async (req, res) => {
    const authInfo = await authenticate(req, res);
    if (!authInfo) return;
    return res.status(405).json({ ok: false, error: "Use POST /mcp-memory for authenticated Streamable HTTP MCP." });
  });

  return router;
}

function sendOAuthError(res, oauth, error) {
  const insufficient = error.code === "memory_oauth_insufficient_scope";
  const challengeError = insufficient ? "insufficient_scope" : "invalid_token";
  res.setHeader("WWW-Authenticate", oauth.challenge(challengeError));
  res.status(error.status).json({ ok: false, error: error.code });
  return null;
}
