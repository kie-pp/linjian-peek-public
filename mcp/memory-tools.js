import { z } from "zod";
import { assertSafeMemoryContent } from "./memory-safety.js";

const PRIVATE_KEYS = /(?:namespace|credential|token|authorization|digest)/i;
const POLICY = "共享记忆只保存 ChatGPT 与 Cyberboss 都需要知道的精炼事实；不替代 ChatGPT 小本本、Cyberboss 世界书或当前 thread，默认不得保存原始聊天。";

export function registerMemoryTools(server, { enabled = false, fetchImpl, audit = async () => {} } = {}) {
  if (!enabled) return [];
  if (typeof fetchImpl !== "function") throw new Error("Memory client is unavailable");

  const registered = [];
  const add = (name, description, schema, callback) => {
    server.tool(name, `${description} ${POLICY}`, schema, async (...args) => {
      const started = Date.now();
      try {
        const result = await callback(...args);
        await emitAudit(audit, auditEvent(name, "success", started, result));
        return result;
      } catch (error) {
        await emitAudit(audit, auditEvent(name, "failed", started));
        throw error;
      }
    });
    registered.push(name);
  };

  add(
    "get_memory_context",
    "读取共享 active memory 和最多三条相关历史。只读取当前鉴权凭据映射的用户空间。",
    { query: z.string().max(500).default(""), history_limit: z.number().int().min(1).max(3).default(3) },
    async ({ query = "", history_limit = 3 }) => callJson(fetchImpl, "/api/memory/context", "POST", { query, history_limit }),
  );

  add("get_active_memory", "读取当前共享 active memory。", {},
    async () => callJson(fetchImpl, "/api/memory/active", "GET"));

  add(
    "search_memory",
    "在当前共享用户空间的近期记忆中检索相关历史。",
    { query: z.string().min(1).max(500), limit: z.number().int().min(1).max(3).default(3) },
    async ({ query, limit = 3 }) => callJson(fetchImpl, "/api/memory/search", "POST", { query, limit }),
  );

  add(
    "set_active_memory",
    "更新当前共享 active memory。可提供 expected_revision 防止覆盖并发修改。",
    { content: z.string().min(1).max(600), expected_revision: z.number().int().nonnegative().optional() },
    async ({ content, expected_revision }) => {
      assertSafeMemoryContent(content);
      return callJson(fetchImpl, "/api/memory/active", "PUT", compact({ content, expected_revision }));
    },
  );

  const historySchema = {
    summary: z.string().min(1).max(600),
    searchable_text: z.string().max(2000).default(""),
    source: z.string().min(1).max(64).default("chatgpt"),
    occurred_at: z.string().max(40).optional(),
    expires_at: z.string().max(40).optional(),
  };

  add(
    "append_memory",
    "向当前共享用户空间追加一条去重历史记忆。",
    historySchema,
    async ({ summary, searchable_text = "", source = "chatgpt", occurred_at, expires_at }) => {
      assertSafeMemoryContent(summary, searchable_text, source);
      return callJson(fetchImpl, "/api/memory/history", "POST", compact({ summary, searchable_text, source, occurred_at, expires_at }));
    },
  );

  add(
    "revise_memory",
    "修订一条共享历史记忆：新增后继记录并保留修订关系，不覆盖旧正文。",
    { history_id: z.string().min(1).max(128), ...historySchema },
    async ({ history_id, summary, searchable_text = "", source = "chatgpt", occurred_at, expires_at }) => {
      assertSafeMemoryContent(summary, searchable_text, source);
      return callJson(fetchImpl, `/api/memory/history/${encodeURIComponent(history_id)}`, "PATCH", compact({ summary, searchable_text, source, occurred_at, expires_at }));
    },
  );

  add(
    "forget_memory",
    "软删除一条共享历史记忆；删除后默认不再参与检索和上下文。",
    { history_id: z.string().min(1).max(128) },
    async ({ history_id }) => callJson(fetchImpl, `/api/memory/history/${encodeURIComponent(history_id)}`, "DELETE"),
  );

  return registered;
}

async function callJson(fetchImpl, path, method, body) {
  let response;
  try {
    response = await fetchImpl(path, {
      method,
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new Error("Shared memory request failed");
  }
  if (!response?.ok || typeof response.json !== "function") throw new Error("Shared memory request failed");
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("Shared memory returned invalid JSON");
  }
  return { content: [{ type: "text", text: JSON.stringify(stripPrivateFields(payload), null, 2) }] };
}

function auditEvent(tool, status, started, result) {
  const event = { tool, status, duration_ms: Math.max(0, Date.now() - started) };
  if (!result?.content?.[0]?.text) return event;
  try {
    const payload = JSON.parse(result.content[0].text);
    const active = payload?.active_memory && typeof payload.active_memory === "object" ? payload.active_memory : payload;
    const item = payload?.item && typeof payload.item === "object" ? payload.item : {};
    if (Number.isInteger(active?.revision)) event.revision = active.revision;
    if (typeof item?.id === "string" && item.id) event.history_item_id = item.id.slice(0, 128);
  } catch {}
  return event;
}

async function emitAudit(audit, event) {
  try {
    await audit(event);
  } catch {}
}

function stripPrivateFields(value) {
  if (Array.isArray(value)) return value.map(stripPrivateFields);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !PRIVATE_KEYS.test(key))
    .map(([key, item]) => [key, stripPrivateFields(item)]));
}

function compact(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

export const MEMORY_TOOL_NAMES = Object.freeze([
  "get_memory_context",
  "get_active_memory",
  "search_memory",
  "set_active_memory",
  "append_memory",
  "revise_memory",
  "forget_memory",
]);
