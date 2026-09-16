CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS memory_namespaces (
  namespace_id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS memory_credentials (
  credential_digest CHAR(64) PRIMARY KEY,
  namespace_id TEXT NOT NULL REFERENCES memory_namespaces(namespace_id) ON DELETE CASCADE,
  scopes TEXT[] NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  rotated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS memory_credentials_namespace_idx
  ON memory_credentials(namespace_id);

CREATE TABLE IF NOT EXISTS active_memory (
  namespace_id TEXT PRIMARY KEY REFERENCES memory_namespaces(namespace_id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  revision BIGINT NOT NULL CHECK (revision > 0),
  content_hash CHAR(64) NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS memory_history (
  id TEXT PRIMARY KEY,
  namespace_id TEXT NOT NULL REFERENCES memory_namespaces(namespace_id) ON DELETE CASCADE,
  summary TEXT NOT NULL,
  searchable_text TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL,
  content_hash CHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(namespace_id, content_hash)
);

CREATE INDEX IF NOT EXISTS memory_history_namespace_time_idx
  ON memory_history(namespace_id, occurred_at DESC, created_at DESC);
