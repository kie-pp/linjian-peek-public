ALTER TABLE memory_history
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS supersedes_id TEXT,
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'memory_history_status_check'
      AND conrelid = 'memory_history'::regclass
  ) THEN
    ALTER TABLE memory_history
      ADD CONSTRAINT memory_history_status_check
      CHECK (status IN ('active', 'superseded', 'deleted', 'expired'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'memory_history_supersedes_fk'
      AND conrelid = 'memory_history'::regclass
  ) THEN
    ALTER TABLE memory_history
      ADD CONSTRAINT memory_history_supersedes_fk
      FOREIGN KEY (supersedes_id) REFERENCES memory_history(id);
  END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS memory_history_one_successor_idx
  ON memory_history(namespace_id, supersedes_id)
  WHERE supersedes_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS memory_history_active_expiry_idx
  ON memory_history(namespace_id, status, expires_at, occurred_at DESC);
