"""Opt-in PostgreSQL tests. Never connect unless TEST_DATABASE_URL names localhost."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

SERVER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_DIR))

from memory_store import MemoryAuthError, MemoryConflictError, MemoryDatabaseError, MemoryStore, PostgresRepository, digest_credential


TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "").strip()


def _is_local_database(url: str) -> bool:
    try:
        return (urlparse(url).hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}
    except ValueError:
        return False


@unittest.skipUnless(
    TEST_DATABASE_URL and _is_local_database(TEST_DATABASE_URL),
    "TEST_DATABASE_URL is absent or is not a localhost PostgreSQL URL",
)
class PostgresMemoryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql

        cls.psycopg = psycopg
        cls.sql = sql
        cls.schema_name = f"memory_test_{uuid.uuid4().hex}"
        with psycopg.connect(TEST_DATABASE_URL, connect_timeout=3) as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema_name)))

        def connect(_database_url):
            return psycopg.connect(
                TEST_DATABASE_URL,
                connect_timeout=3,
                options=f"-c search_path={cls.schema_name}",
            )

        cls.repository = PostgresRepository(TEST_DATABASE_URL, connect=connect)
        cls.store = MemoryStore(cls.repository, pepper="postgres-test-pepper")
        cls.store.migrate()
        cls.reader = "postgres-reader-test"
        cls.writer = "postgres-writer-test"
        cls.namespace_id = cls.store.bootstrap(cls.reader, cls.writer)

    @classmethod
    def tearDownClass(cls):
        with cls.psycopg.connect(TEST_DATABASE_URL, connect_timeout=3) as connection:
            with connection.cursor() as cursor:
                cursor.execute(cls.sql.SQL("DROP SCHEMA {} CASCADE").format(cls.sql.Identifier(cls.schema_name)))

    def test_migrations_multistatement_bootstrap_and_readiness(self):
        # Re-running both migrations must be a no-op and must not duplicate
        # migration bookkeeping after bootstrap has already completed.
        self.store.migrate()
        with self.repository._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT version FROM schema_migrations ORDER BY version")
                self.assertEqual([row[0] for row in cursor.fetchall()], ["001_shared_memory", "002_memory_lifecycle"])
                cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_schema = %s AND table_name = 'memory_history'", (self.schema_name,))
                columns = {row[0] for row in cursor.fetchall()}
        self.assertTrue({"status", "supersedes_id", "expires_at", "deleted_at"}.issubset(columns))
        self.assertEqual(self.store.readiness(), {"ready": True, "reason": "ready"})
        self.assertEqual(self.store.authenticate(self.reader, "memory:read"), self.namespace_id)
        self.assertEqual(self.store.authenticate(self.writer, "memory:write"), self.namespace_id)

    def test_revision_lock_deduplication_and_namespace_isolation(self):
        first = self.store.set_active(self.writer, "first", expected_revision=0)
        self.assertEqual(first["revision"], 1)
        outcomes = []

        def update(content):
            try:
                outcomes.append(("ok", self.store.set_active(self.writer, content, expected_revision=1)))
            except MemoryConflictError:
                outcomes.append(("conflict", None))

        threads = [threading.Thread(target=update, args=(f"next-{index}",)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([kind for kind, _ in outcomes].count("ok"), 1)
        self.assertEqual([kind for kind, _ in outcomes].count("conflict"), 1)

        item = self.store.append_history(self.writer, "共享决定", "项目")
        duplicate = self.store.append_history(self.writer, "共享决定", "项目")
        self.assertTrue(item["created"])
        self.assertFalse(duplicate["created"])

        other_namespace = f"opaque-{uuid.uuid4().hex}"
        other_token = "postgres-other-reader"
        with self.repository._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO memory_namespaces(namespace_id) VALUES (%s)", (other_namespace,))
        self.repository.add_credential(other_namespace, digest_credential(other_token, "postgres-test-pepper"), ["memory:read"])
        self.assertEqual(self.store.search(other_token, "项目"), [])
        with self.assertRaises(MemoryAuthError):
            self.store.append_history(other_token, "denied")

    def test_revision_forget_purges_chain_active_and_expiry_filtering(self):
        first = self.store.append_history(self.writer, "旧偏好", "偏好", source="chatgpt")
        revised = self.store.revise_history(self.writer, first["item"]["id"], "新偏好", "偏好", source="chatgpt")
        repeated = self.store.revise_history(self.writer, first["item"]["id"], "新偏好", "偏好", source="chatgpt")
        self.assertTrue(revised["created"])
        self.assertFalse(repeated["created"])
        self.assertEqual([row["summary"] for row in self.store.search(self.reader, "偏好")], ["新偏好"])
        self.store.set_active(self.writer, "当前项目。新偏好。其他事实。", expected_revision=0)
        forgotten = self.store.forget_history(self.writer, revised["item"]["id"])
        self.assertTrue(forgotten["changed"])
        self.assertEqual(forgotten["purged_records"], 2)
        self.assertEqual(forgotten["active_memory_status"], "purged_exact_match")
        self.assertFalse(self.store.forget_history(self.writer, revised["item"]["id"])["changed"])
        with self.repository._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id, status, summary, searchable_text, source, content_hash, deleted_at "
                    "FROM memory_history WHERE namespace_id = %s AND id = ANY(%s) ORDER BY id",
                    (self.namespace_id, [first["item"]["id"], revised["item"]["id"]]),
                )
                forgotten_rows = cursor.fetchall()
        self.assertEqual(len(forgotten_rows), 2)
        for row in forgotten_rows:
            self.assertEqual(row[1], "deleted")
            self.assertEqual(row[2], "")
            self.assertEqual(row[3], "")
            self.assertEqual(row[4], "forgotten")
            self.assertRegex(row[5], r"^[0-9a-f]{64}$")
            self.assertIsNotNone(row[6])
        self.assertEqual(self.store.search(self.reader, "偏好"), [])
        self.assertNotIn("新偏好", repr(self.store.get_context(self.reader)))
        self.assertNotIn("新偏好", repr(self.store.get_active(self.reader)))
        self.store.append_history(
            self.writer,
            "已过期状态",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        self.assertNotIn("已过期状态", repr(self.store.get_context(self.reader)))

    def test_failed_migration_rolls_back_without_marking_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            migration_dir = Path(temp_dir)
            for source in sorted((SERVER_DIR / "migrations").glob("*.sql")):
                shutil.copy2(source, migration_dir / source.name)
            (migration_dir / "999_broken.sql").write_text(
                "CREATE TABLE rollback_probe(id INTEGER); THIS IS NOT VALID SQL;",
                encoding="utf-8",
            )
            broken = PostgresRepository(TEST_DATABASE_URL, connect=self.repository._connect_impl, migrations_dir=migration_dir)
            with self.assertRaises(Exception):
                broken.migrate()
            with self.repository._connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = '999_broken'")
                    self.assertEqual(cursor.fetchone()[0], 0)
                    cursor.execute("SELECT to_regclass('rollback_probe')")
                    self.assertIsNone(cursor.fetchone()[0])

    def test_database_failure_is_sanitized(self):
        def broken_connect(_url):
            raise RuntimeError("private database detail")
        broken = MemoryStore(PostgresRepository("postgresql://placeholder.invalid/test", connect=broken_connect), "pepper")
        with self.assertRaises(MemoryDatabaseError) as caught:
            broken.migrate()
        self.assertEqual(str(caught.exception), "memory_database_unavailable")


if __name__ == "__main__":
    unittest.main()
