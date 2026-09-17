"""PostgreSQL-backed shared memory with credential-scoped namespace isolation."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from memory_safety import MemorySafetyError, validate_memory_content


MAX_ACTIVE_CHARS = 600
MAX_QUERY_CHARS = 500
MAX_HISTORY_ITEMS = 3
MAX_HISTORY_SUMMARY_CHARS = 600
MAX_HISTORY_SEARCHABLE_CHARS = 2000
MAX_HISTORY_SOURCE_CHARS = 64
MAX_HISTORY_TOTAL_CHARS = 600
RECENT_CANDIDATE_LIMIT = 100
POSTGRES_CONNECT_TIMEOUT_SECONDS = 3


class MemoryErrorBase(Exception):
    pass


class MemoryAuthError(MemoryErrorBase):
    pass


class MemoryValidationError(MemoryErrorBase):
    pass


class MemoryConflictError(MemoryErrorBase):
    pass


class MemoryDatabaseError(MemoryErrorBase):
    pass


def digest_credential(token: str, pepper: str) -> str:
    token = _require_secret(token, "memory_credential_required")
    pepper = _require_secret(pepper, "memory_credential_pepper_required")
    return hmac.new(pepper.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _credential_readiness(rows) -> dict:
    by_namespace: dict[str, dict[str, bool]] = {}
    any_reader = False
    any_writer = False
    for namespace_id, raw_scopes in rows:
        scopes = set(raw_scopes or [])
        is_reader = "memory:read" in scopes and "memory:write" not in scopes
        is_writer = "memory:write" in scopes
        state = by_namespace.setdefault(namespace_id, {"reader": False, "writer": False})
        state["reader"] = state["reader"] or is_reader
        state["writer"] = state["writer"] or is_writer
        any_reader = any_reader or is_reader
        any_writer = any_writer or is_writer
    if any(item["reader"] and item["writer"] for item in by_namespace.values()):
        return {"ready": True, "reason": "ready"}
    if any_reader and any_writer:
        reason = "memory_credentials_namespace_mismatch"
    elif not any_reader and not any_writer:
        reason = "memory_credentials_missing"
    elif not any_reader:
        reason = "memory_reader_credential_missing"
    else:
        reason = "memory_writer_credential_missing"
    return {"ready": False, "reason": reason}


class PostgresRepository:
    def __init__(
        self,
        database_url: str,
        schema_path: str | Path | None = None,
        connect: Callable[..., Any] | None = None,
        migrations_dir: str | Path | None = None,
        connect_timeout: int = POSTGRES_CONNECT_TIMEOUT_SECONDS,
    ):
        self.database_url = _require_secret(database_url, "database_url_required")
        self.schema_path = Path(schema_path or Path(__file__).with_name("schema.sql"))
        self.migrations_dir = Path(migrations_dir or Path(__file__).with_name("migrations"))
        self.connect_timeout = max(1, min(10, int(connect_timeout)))
        self._connect_impl = connect

    def _connect(self):
        if self._connect_impl is None:
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError("postgres_driver_unavailable") from exc
            return psycopg.connect(self.database_url, connect_timeout=self.connect_timeout)
        return self._connect_impl(self.database_url)

    def migrate(self) -> None:
        migrations = sorted(self.migrations_dir.glob("*.sql"))
        if not migrations:
            raise RuntimeError("memory_migrations_missing")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET LOCAL lock_timeout = '3s'")
                cursor.execute("SET LOCAL statement_timeout = '10s'")
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS schema_migrations (
                         version TEXT PRIMARY KEY,
                         applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                       )"""
                )
                cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("linjian-shared-memory-migrations",))
                cursor.execute("SELECT version FROM schema_migrations")
                applied = {row[0] for row in cursor.fetchall()}
                for migration in migrations:
                    version = migration.stem
                    if version in applied:
                        continue
                    cursor.execute(migration.read_text(encoding="utf-8"))
                    cursor.execute("INSERT INTO schema_migrations(version) VALUES (%s)", (version,))

    def bootstrap_credentials(self, reader_digest: str, writer_digest: str) -> str:
        digests = [value for value in (reader_digest, writer_digest) if value]
        if not digests:
            raise RuntimeError("bootstrap_credentials_required")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("linjian-shared-memory-bootstrap",))
                cursor.execute(
                    "SELECT credential_digest, namespace_id FROM memory_credentials WHERE credential_digest = ANY(%s)",
                    (digests,),
                )
                rows = cursor.fetchall()
                namespace_ids = {row[1] for row in rows}
                if len(namespace_ids) > 1:
                    raise RuntimeError("bootstrap_namespace_mismatch")
                namespace_id = next(iter(namespace_ids), None)
                if namespace_id is None:
                    cursor.execute("SELECT namespace_id FROM memory_namespaces ORDER BY created_at LIMIT 2")
                    existing_namespaces = [row[0] for row in cursor.fetchall()]
                    if len(existing_namespaces) > 1:
                        raise RuntimeError("bootstrap_namespace_ambiguous")
                    namespace_id = existing_namespaces[0] if existing_namespaces else secrets.token_urlsafe(32)
                cursor.execute(
                    "INSERT INTO memory_namespaces(namespace_id) VALUES (%s) ON CONFLICT (namespace_id) DO NOTHING",
                    (namespace_id,),
                )
                for credential_digest, scopes in (
                    (reader_digest, ["memory:read"]),
                    (writer_digest, ["memory:read", "memory:write"]),
                ):
                    if credential_digest:
                        cursor.execute(
                            """INSERT INTO memory_credentials(credential_digest, namespace_id, scopes, status)
                               VALUES (%s, %s, %s, 'active')
                               ON CONFLICT (credential_digest) DO NOTHING""",
                            (credential_digest, namespace_id, scopes),
                        )
        return namespace_id

    def credential_readiness(self) -> dict:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT namespace_id, scopes FROM memory_credentials WHERE status = 'active'")
                rows = cursor.fetchall()
        return _credential_readiness(rows)

    def resolve_credential(self, credential_digest: str) -> dict | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT namespace_id, scopes, status FROM memory_credentials WHERE credential_digest = %s",
                    (credential_digest,),
                )
                row = cursor.fetchone()
        return {"namespace_id": row[0], "scopes": list(row[1] or []), "status": row[2]} if row else None

    def add_credential(self, namespace_id: str, credential_digest: str, scopes: list[str]) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO memory_credentials(credential_digest, namespace_id, scopes, status)
                       VALUES (%s, %s, %s, 'active') ON CONFLICT (credential_digest) DO NOTHING""",
                    (credential_digest, namespace_id, scopes),
                )
                cursor.execute("SELECT namespace_id FROM memory_credentials WHERE credential_digest = %s", (credential_digest,))
                row = cursor.fetchone()
                if not row or row[0] != namespace_id:
                    raise RuntimeError("credential_namespace_mismatch")
                cursor.execute(
                    """UPDATE memory_credentials SET scopes = %s, status = 'active', rotated_at = NOW()
                       WHERE credential_digest = %s AND namespace_id = %s""",
                    (scopes, credential_digest, namespace_id),
                )

    def disable_credential(self, credential_digest: str) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE memory_credentials SET status = 'disabled', rotated_at = NOW() WHERE credential_digest = %s",
                    (credential_digest,),
                )

    def get_active(self, namespace_id: str) -> dict | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT content, revision, content_hash, updated_at FROM active_memory WHERE namespace_id = %s",
                    (namespace_id,),
                )
                row = cursor.fetchone()
        return {"content": row[0], "revision": row[1], "content_hash": row[2], "updated_at": row[3]} if row else None

    def set_active(self, namespace_id: str, content: str, content_hash: str, expected_revision: int | None = None) -> dict:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"linjian-active-memory:{namespace_id}",))
                cursor.execute("SELECT revision FROM active_memory WHERE namespace_id = %s FOR UPDATE", (namespace_id,))
                row = cursor.fetchone()
                current_revision = int(row[0]) if row else 0
                if expected_revision is not None and expected_revision != current_revision:
                    raise MemoryConflictError("revision_conflict")
                revision = current_revision + 1
                cursor.execute(
                    """INSERT INTO active_memory(namespace_id, content, revision, content_hash, updated_at)
                       VALUES (%s, %s, %s, %s, NOW())
                       ON CONFLICT (namespace_id) DO UPDATE SET content = EXCLUDED.content,
                         revision = EXCLUDED.revision, content_hash = EXCLUDED.content_hash, updated_at = NOW()
                       RETURNING content, revision, content_hash, updated_at""",
                    (namespace_id, content, revision, content_hash),
                )
                result = cursor.fetchone()
                cursor.execute("UPDATE memory_namespaces SET updated_at = NOW() WHERE namespace_id = %s", (namespace_id,))
        return {"content": result[0], "revision": result[1], "content_hash": result[2], "updated_at": result[3]}

    def append_history(self, namespace_id: str, item: dict) -> tuple[dict, bool]:
        history_id = secrets.token_urlsafe(24)
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO memory_history(id, namespace_id, summary, searchable_text, source,
                         occurred_at, content_hash, status, expires_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, 'active', %s)
                       ON CONFLICT (namespace_id, content_hash) DO NOTHING
                       RETURNING id, summary, searchable_text, source, occurred_at, created_at,
                                 status, supersedes_id, expires_at, deleted_at""",
                    (history_id, namespace_id, item["summary"], item["searchable_text"], item["source"],
                     item["occurred_at"], item["content_hash"], item.get("expires_at")),
                )
                row = cursor.fetchone()
                created = row is not None
                if not row:
                    cursor.execute(
                        """SELECT id, summary, searchable_text, source, occurred_at, created_at,
                                  status, supersedes_id, expires_at, deleted_at
                           FROM memory_history WHERE namespace_id = %s AND content_hash = %s""",
                        (namespace_id, item["content_hash"]),
                    )
                    row = cursor.fetchone()
                if created:
                    cursor.execute("UPDATE memory_namespaces SET updated_at = NOW() WHERE namespace_id = %s", (namespace_id,))
        return _history_row(row), created

    def revise_history(self, namespace_id: str, history_id: str, item: dict) -> tuple[dict, bool]:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"linjian-history:{namespace_id}:{history_id}",))
                cursor.execute(
                    "SELECT id, status, expires_at, content_hash FROM memory_history WHERE namespace_id = %s AND id = %s FOR UPDATE",
                    (namespace_id, history_id),
                )
                old = cursor.fetchone()
                if not old:
                    raise MemoryValidationError("history_not_found")
                cursor.execute(
                    """SELECT id, summary, searchable_text, source, occurred_at, created_at,
                              status, supersedes_id, expires_at, deleted_at, content_hash
                       FROM memory_history WHERE namespace_id = %s AND supersedes_id = %s""",
                    (namespace_id, history_id),
                )
                existing = cursor.fetchone()
                if existing:
                    if existing[10] == item["content_hash"]:
                        return _history_row(existing[:10]), False
                    raise MemoryConflictError("history_already_revised")
                if old[1] != "active":
                    raise MemoryConflictError("history_not_active")
                if old[2] is not None and old[2] <= datetime.now(timezone.utc):
                    cursor.execute("UPDATE memory_history SET status = 'expired' WHERE namespace_id = %s AND id = %s", (namespace_id, history_id))
                    raise MemoryConflictError("history_not_active")
                if old[3] == item["content_hash"]:
                    raise MemoryValidationError("history_revision_unchanged")
                new_id = secrets.token_urlsafe(24)
                cursor.execute(
                    """INSERT INTO memory_history(id, namespace_id, summary, searchable_text, source,
                         occurred_at, content_hash, status, supersedes_id, expires_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, 'active', %s, %s)
                       ON CONFLICT (namespace_id, content_hash) DO NOTHING
                       RETURNING id, summary, searchable_text, source, occurred_at, created_at,
                                 status, supersedes_id, expires_at, deleted_at""",
                    (new_id, namespace_id, item["summary"], item["searchable_text"], item["source"],
                     item["occurred_at"], item["content_hash"], history_id, item.get("expires_at")),
                )
                row = cursor.fetchone()
                if not row:
                    raise MemoryConflictError("history_duplicate")
                cursor.execute("UPDATE memory_history SET status = 'superseded' WHERE namespace_id = %s AND id = %s", (namespace_id, history_id))
                cursor.execute("UPDATE memory_namespaces SET updated_at = NOW() WHERE namespace_id = %s", (namespace_id,))
        return _history_row(row), True

    def forget_history(self, namespace_id: str, history_id: str) -> dict:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"linjian-history:{namespace_id}:{history_id}",))
                cursor.execute(
                    """WITH RECURSIVE chain(id, supersedes_id) AS (
                         SELECT id, supersedes_id
                           FROM memory_history
                          WHERE namespace_id = %s AND id = %s
                         UNION
                         SELECT item.id, item.supersedes_id
                           FROM memory_history item
                           JOIN chain linked
                             ON item.namespace_id = %s
                            AND (item.id = linked.supersedes_id OR item.supersedes_id = linked.id)
                       )
                       SELECT id, summary, searchable_text, status
                         FROM memory_history
                        WHERE namespace_id = %s AND id IN (SELECT id FROM chain)
                        FOR UPDATE""",
                    (namespace_id, history_id, namespace_id, namespace_id),
                )
                rows = cursor.fetchall()
                if not rows:
                    raise MemoryValidationError("history_not_found")
                changed = any(row[1] or row[2] or row[3] != "deleted" for row in rows)
                summaries = [row[1] for row in rows if row[1]]
                chain_ids = [row[0] for row in rows]
                for chain_id in chain_ids:
                    forgotten_hash = hashlib.sha256(f"forgotten:{chain_id}".encode("utf-8")).hexdigest()
                    cursor.execute(
                        """UPDATE memory_history
                              SET summary = '', searchable_text = '', source = 'forgotten',
                                  content_hash = %s, status = 'deleted',
                                  deleted_at = COALESCE(deleted_at, NOW())
                            WHERE namespace_id = %s AND id = %s""",
                        (forgotten_hash, namespace_id, chain_id),
                    )

                cursor.execute(
                    "SELECT content, revision FROM active_memory WHERE namespace_id = %s FOR UPDATE",
                    (namespace_id,),
                )
                active = cursor.fetchone()
                active_status = "not_present"
                active_revision = int(active[1]) if active else 0
                if active and active[0]:
                    purged_content, matched = _purge_active_content(active[0], summaries)
                    if matched:
                        active_revision += 1
                        cursor.execute(
                            """UPDATE active_memory
                                  SET content = %s, revision = %s, content_hash = %s, updated_at = NOW()
                                WHERE namespace_id = %s""",
                            (purged_content, active_revision,
                             hashlib.sha256(purged_content.encode("utf-8")).hexdigest(), namespace_id),
                        )
                        active_status = "purged_exact_match"
                    else:
                        active_status = "manual_revision_required"
                if changed or active_status == "purged_exact_match":
                    cursor.execute("UPDATE memory_namespaces SET updated_at = NOW() WHERE namespace_id = %s", (namespace_id,))
        return {
            "id": history_id,
            "changed": changed,
            "purged_records": len(chain_ids),
            "active_memory_status": active_status,
            "active_revision": active_revision,
        }

    def recent_history(self, namespace_id: str, limit: int) -> list[dict]:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE memory_history SET status = 'expired'
                       WHERE namespace_id = %s AND status = 'active' AND expires_at IS NOT NULL AND expires_at <= NOW()""",
                    (namespace_id,),
                )
                cursor.execute(
                    """SELECT id, summary, searchable_text, source, occurred_at, created_at,
                              status, supersedes_id, expires_at, deleted_at
                       FROM memory_history WHERE namespace_id = %s AND status = 'active'
                         AND (expires_at IS NULL OR expires_at > NOW())
                       ORDER BY occurred_at DESC, created_at DESC LIMIT %s""",
                    (namespace_id, limit),
                )
                rows = cursor.fetchall()
        return [_history_row(row) for row in rows]


class MemoryStore:
    def __init__(self, repository, pepper: str, enabled: bool = True):
        self.repository = repository
        self.pepper = _require_secret(pepper, "memory_credential_pepper_required")
        self.enabled = bool(enabled)

    @classmethod
    def postgres(cls, database_url: str, pepper: str, schema_path: str | Path | None = None):
        return cls(PostgresRepository(database_url, schema_path=schema_path), pepper=pepper, enabled=True)

    def migrate(self) -> None:
        self._database_call(self.repository.migrate)

    def bootstrap(self, reader_token: str, writer_token: str) -> str:
        reader_digest = digest_credential(reader_token, self.pepper)
        writer_digest = digest_credential(writer_token, self.pepper)
        if hmac.compare_digest(reader_digest, writer_digest):
            raise MemoryValidationError("bootstrap_credentials_must_differ")
        return self._database_call(self.repository.bootstrap_credentials, reader_digest, writer_digest)

    def readiness(self) -> dict:
        result = self._database_call(self.repository.credential_readiness)
        allowed = {"ready", "memory_credentials_missing", "memory_reader_credential_missing",
                   "memory_writer_credential_missing", "memory_credentials_namespace_mismatch"}
        reason = str(result.get("reason") or "memory_credentials_missing")
        return {"ready": bool(result.get("ready")), "reason": reason if reason in allowed else "memory_credentials_missing"}

    def authenticate(self, token: str, required_scope: str) -> str:
        try:
            credential_digest = digest_credential(token, self.pepper)
        except MemoryValidationError as exc:
            raise MemoryAuthError("invalid_memory_credential") from exc
        credential = self._database_call(self.repository.resolve_credential, credential_digest)
        if not credential or credential.get("status") != "active":
            raise MemoryAuthError("invalid_memory_credential")
        if required_scope not in set(credential.get("scopes") or []):
            raise MemoryAuthError("insufficient_memory_scope")
        namespace_id = credential.get("namespace_id")
        if not namespace_id:
            raise MemoryAuthError("invalid_memory_credential")
        return namespace_id

    def get_active(self, token: str) -> dict:
        namespace_id = self.authenticate(token, "memory:read")
        return _public_active(self._database_call(self.repository.get_active, namespace_id))

    def set_active(self, token: str, content: str, expected_revision: int | None = None) -> dict:
        namespace_id = self.authenticate(token, "memory:write")
        content = _bounded_text(content, "content", MAX_ACTIVE_CHARS, required=True)
        _validate_safe(content)
        expected_revision = _optional_revision(expected_revision)
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        item = self._database_call(self.repository.set_active, namespace_id, content, content_hash, expected_revision)
        return _public_active(item)

    def append_history(self, token: str, summary: str, searchable_text: str = "", source: str = "chatgpt",
                       occurred_at: str | datetime | None = None, expires_at: str | datetime | None = None) -> dict:
        namespace_id = self.authenticate(token, "memory:write")
        item = _build_history_item(summary, searchable_text, source, occurred_at, expires_at)
        stored, created = self._database_call(self.repository.append_history, namespace_id, item)
        return {"created": created, "item": _public_history(stored)}

    def revise_history(self, token: str, history_id: str, summary: str, searchable_text: str = "",
                       source: str = "chatgpt", occurred_at: str | datetime | None = None,
                       expires_at: str | datetime | None = None) -> dict:
        namespace_id = self.authenticate(token, "memory:write")
        item = _build_history_item(summary, searchable_text, source, occurred_at, expires_at)
        stored, created = self._database_call(self.repository.revise_history, namespace_id, _history_id(history_id), item)
        return {"created": created, "item": _public_history(stored)}

    def forget_history(self, token: str, history_id: str) -> dict:
        namespace_id = self.authenticate(token, "memory:write")
        result = self._database_call(self.repository.forget_history, namespace_id, _history_id(history_id))
        active_status = str(result.get("active_memory_status") or "manual_revision_required")
        return {
            "deleted": True,
            "changed": bool(result.get("changed")),
            "purged_records": int(result.get("purged_records") or 0),
            "active_memory_status": active_status,
            "requires_manual_active_revision": active_status == "manual_revision_required",
            "active_revision": int(result.get("active_revision") or 0),
            "item": {"id": str(result.get("id") or ""), "status": "deleted"},
        }

    def rotate_credential(self, old_token: str, new_token: str, scopes: list[str], disable_old: bool = True) -> None:
        allowed_scopes = {"memory:read", "memory:write"}
        normalized_scopes = sorted(set(scopes or []))
        if not normalized_scopes or not set(normalized_scopes).issubset(allowed_scopes):
            raise MemoryValidationError("credential_scopes_invalid")
        required_scope = "memory:write" if "memory:write" in normalized_scopes else "memory:read"
        namespace_id = self.authenticate(old_token, required_scope)
        old_digest = digest_credential(old_token, self.pepper)
        new_digest = digest_credential(new_token, self.pepper)
        self._database_call(self.repository.add_credential, namespace_id, new_digest, normalized_scopes)
        if disable_old:
            self._database_call(self.repository.disable_credential, old_digest)

    def search(self, token: str, query: str, limit: int = MAX_HISTORY_ITEMS) -> list[dict]:
        namespace_id = self.authenticate(token, "memory:read")
        query = _bounded_text(query, "query", MAX_QUERY_CHARS, required=True)
        candidates = self._database_call(self.repository.recent_history, namespace_id, RECENT_CANDIDATE_LIMIT)
        return _rank_history(query, candidates, _bounded_limit(limit), total_chars=MAX_HISTORY_TOTAL_CHARS)

    def get_context(self, token: str, query: str = "", history_limit: int = MAX_HISTORY_ITEMS) -> dict:
        namespace_id = self.authenticate(token, "memory:read")
        query = _bounded_text(query, "query", MAX_QUERY_CHARS)
        history_limit = _bounded_limit(history_limit)
        active = self._database_call(self.repository.get_active, namespace_id)
        candidates = self._database_call(self.repository.recent_history, namespace_id, RECENT_CANDIDATE_LIMIT)
        history = _rank_history(query, candidates, history_limit, total_chars=MAX_HISTORY_TOTAL_CHARS)
        public_active = _public_active(active)
        return {"active_memory": public_active["content"], "relevant_history": history,
                "revision": public_active["revision"], "generated_at": _iso(datetime.now(timezone.utc))}

    def _database_call(self, operation, *args):
        try:
            return operation(*args)
        except (MemoryAuthError, MemoryValidationError, MemoryConflictError, MemoryDatabaseError):
            raise
        except Exception as exc:
            raise MemoryDatabaseError("memory_database_unavailable") from exc


def _build_history_item(summary, searchable_text, source, occurred_at, expires_at) -> dict:
    summary = _bounded_text(summary, "summary", MAX_HISTORY_SUMMARY_CHARS, required=True)
    searchable_text = _bounded_text(searchable_text, "searchable_text", MAX_HISTORY_SEARCHABLE_CHARS)
    source = _bounded_text(source, "source", MAX_HISTORY_SOURCE_CHARS, required=True)
    occurred = _parse_datetime(occurred_at, "occurred_at")
    expiry = _parse_datetime(expires_at, "expires_at") if expires_at not in (None, "") else None
    _validate_safe(summary, searchable_text, source)
    canonical = "\0".join((summary, searchable_text, source, _iso(expiry) or ""))
    return {"summary": summary, "searchable_text": searchable_text, "source": source,
            "occurred_at": occurred, "expires_at": expiry,
            "content_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}


def _validate_safe(*values: str) -> None:
    try:
        validate_memory_content(values)
    except MemorySafetyError as exc:
        raise MemoryValidationError("memory_sensitive_content_rejected") from exc


def _public_active(item: dict | None) -> dict:
    if not item:
        return {"content": "", "revision": 0, "updated_at": None}
    return {"content": str(item.get("content") or "")[:MAX_ACTIVE_CHARS],
            "revision": int(item.get("revision") or 0), "updated_at": _iso(item.get("updated_at"))}


def _purge_active_content(content: str, forgotten_summaries: list[str]) -> tuple[str, bool]:
    """Remove only exact remembered statements; paraphrases require manual revision."""
    purged = str(content or "")
    matched = False
    summaries = sorted({str(value).strip() for value in forgotten_summaries if str(value).strip()}, key=len, reverse=True)
    for summary in summaries:
        if summary in purged:
            purged = purged.replace(summary, "")
            matched = True
    if not matched:
        return purged, False
    purged = re.sub(r"[。！？；，、]{2,}", lambda match: match.group(0)[-1], purged)
    purged = re.sub(r"(?m)^[\s。！？；，、]+$", "", purged)
    purged = re.sub(r"\n{3,}", "\n\n", purged)
    return purged.strip(" \t\r\n。；，、"), True


def _public_history(item: dict) -> dict:
    return {"id": str(item.get("id") or ""),
            "summary": str(item.get("summary") or "")[:MAX_HISTORY_SUMMARY_CHARS],
            "source": str(item.get("source") or ""), "status": str(item.get("status") or "active"),
            "supersedes_id": str(item.get("supersedes_id") or "") or None,
            "expires_at": _iso(item.get("expires_at")), "occurred_at": _iso(item.get("occurred_at")),
            "created_at": _iso(item.get("created_at"))}


def _rank_history(query: str, candidates: list[dict], limit: int, total_chars: int | None = None) -> list[dict]:
    query_terms = _search_terms(query)
    def scored(item):
        haystack = f"{item.get('summary', '')} {item.get('searchable_text', '')}"
        return len(query_terms.intersection(_search_terms(haystack))), _timestamp(item.get("occurred_at") or item.get("created_at")), item
    ranked = sorted((scored(item) for item in candidates), key=lambda item: item[:2], reverse=True)
    result, remaining = [], total_chars
    for score, _occurred_at, item in ranked:
        if len(result) >= limit:
            break
        if query_terms and score == 0:
            continue
        public = _public_history(item)
        if remaining is not None:
            if remaining <= 0:
                break
            public["summary"] = public["summary"][:remaining]
            remaining -= len(public["summary"])
        if public["summary"]:
            result.append(public)
    return result


def _search_terms(value: str) -> set[str]:
    normalized = str(value or "").lower()
    latin = set(re.findall(r"[a-z0-9_]{2,}", normalized))
    cjk = "".join(re.findall(r"[\u3400-\u9fff]", re.sub(r"\s+", "", normalized)))
    return latin | set(cjk) | {cjk[index:index + 2] for index in range(max(0, len(cjk) - 1))}


def _bounded_text(value: Any, field: str, limit: int, required: bool = False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise MemoryValidationError(f"{field}_must_be_string")
    value = value.strip().replace("\x00", "")
    if required and not value:
        raise MemoryValidationError(f"{field}_required")
    if len(value) > limit:
        raise MemoryValidationError(f"{field}_too_long")
    return value


def _history_id(value: Any) -> str:
    value = _bounded_text(value, "history_id", 128, required=True)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise MemoryValidationError("history_id_invalid")
    return value


def _bounded_limit(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MemoryValidationError("history_limit_must_be_integer")
    if value < 1 or value > MAX_HISTORY_ITEMS:
        raise MemoryValidationError("history_limit_out_of_range")
    return value


def _optional_revision(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MemoryValidationError("expected_revision_invalid")
    return value


def _parse_datetime(value: str | datetime | None, field: str = "occurred_at") -> datetime:
    if value is None or value == "":
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise MemoryValidationError(f"{field}_invalid") from exc
    else:
        raise MemoryValidationError(f"{field}_invalid")
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _history_row(row) -> dict:
    return {"id": row[0], "summary": row[1], "searchable_text": row[2], "source": row[3],
            "occurred_at": row[4], "created_at": row[5], "status": row[6],
            "supersedes_id": row[7], "expires_at": row[8], "deleted_at": row[9]}


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _timestamp(value: Any) -> float:
    try:
        return _parse_datetime(value).timestamp()
    except MemoryValidationError:
        return 0.0


def _require_secret(value: Any, error: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MemoryValidationError(error)
    return value.strip()
