import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SERVER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_DIR))

from linjian_server import State


class FakeStartupStore:
    readiness_result = {"ready": True, "reason": "ready"}

    def migrate(self):
        return None

    def bootstrap(self, _reader, _writer):
        return "opaque"

    def readiness(self):
        return dict(self.readiness_result)


class MemoryStaticTests(unittest.TestCase):
    def test_feature_disabled_constructs_legacy_state_without_database(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {
            "MEMORY_ENABLED": "false",
            "LINJIAN_DATA_DIR": temp_dir,
        }, clear=False):
            state = State()
            self.assertFalse(state.memory_enabled)
            self.assertFalse(state.memory_ready)
            self.assertIsNone(state.memory_store)

    def test_enabled_without_database_is_not_ready_but_does_not_crash(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {
            "MEMORY_ENABLED": "true",
            "DATABASE_URL": "",
            "MEMORY_CREDENTIAL_PEPPER": "",
            "LINJIAN_DATA_DIR": temp_dir,
        }, clear=False):
            state = State()
            self.assertTrue(state.memory_enabled)
            self.assertFalse(state.memory_ready)
            self.assertEqual(state.memory_error, "memory_configuration_incomplete")

    def test_startup_ready_requires_safe_credential_readiness(self):
        cases = [
            ({"ready": False, "reason": "memory_credentials_missing"}, False),
            ({"ready": False, "reason": "memory_credentials_namespace_mismatch"}, False),
            ({"ready": False, "reason": "memory_writer_credential_missing"}, False),
            ({"ready": True, "reason": "ready"}, True),
        ]
        for readiness, expected in cases:
            with self.subTest(readiness=readiness), tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {
                "MEMORY_ENABLED": "true",
                "DATABASE_URL": "postgresql://placeholder.invalid/test",
                "MEMORY_CREDENTIAL_PEPPER": "placeholder-pepper",
                "MEMORY_BOOTSTRAP_READER_TOKEN": "",
                "MEMORY_BOOTSTRAP_WRITER_TOKEN": "",
                "LINJIAN_DATA_DIR": temp_dir,
            }, clear=False), patch("linjian_server.MemoryStore.postgres", return_value=FakeStartupStore()):
                FakeStartupStore.readiness_result = readiness
                state = State()
                self.assertEqual(state.memory_ready, expected)
                expected_reason = "" if expected else readiness["reason"]
                self.assertEqual(state.memory_error, expected_reason)
                self.assertNotIn("opaque", state.memory_error)

    def test_schema_and_versioned_migrations_enforce_memory_lifecycle(self):
        schema = (SERVER_DIR / "schema.sql").read_text(encoding="utf-8")
        migration = (SERVER_DIR / "migrations" / "001_shared_memory.sql").read_text(encoding="utf-8")
        lifecycle = (SERVER_DIR / "migrations" / "002_memory_lifecycle.sql").read_text(encoding="utf-8")
        self.assertIn("CREATE TABLE IF NOT EXISTS", schema)
        self.assertIn("UNIQUE(namespace_id, content_hash)", schema)
        self.assertIn("supersedes_id", schema)
        self.assertIn("deleted_at", schema)
        self.assertIn("expires_at", schema)
        self.assertIn("schema_migrations", (SERVER_DIR / "memory_store.py").read_text(encoding="utf-8"))
        self.assertNotIn("INSERT INTO schema_migrations", migration)
        self.assertIn("ALTER TABLE memory_history", lifecycle)
        self.assertNotIn("device_id", schema)
        store_source = (SERVER_DIR / "memory_store.py").read_text(encoding="utf-8")
        self.assertNotIn("memory_namespaces SET updated_at = NOW() WHERE id =", store_source)
        self.assertIn("memory_namespaces SET updated_at = NOW() WHERE namespace_id =", store_source)
        self.assertIn("pg_advisory_xact_lock", store_source)
        self.assertNotIn("namespace_id = EXCLUDED.namespace_id", store_source)
        self.assertIn("bootstrap_namespace_ambiguous", store_source)
        self.assertIn("connect_timeout", store_source)
        self.assertIn("WHERE status = 'active'", store_source)

    def test_dockerfile_installs_only_locked_requirements_before_starting_legacy_entrypoint(self):
        dockerfile = (SERVER_DIR / "Dockerfile").read_text(encoding="utf-8")
        requirements = (SERVER_DIR / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("pip install --no-cache-dir -r requirements.txt", dockerfile)
        self.assertIn('CMD ["python", "linjian_server.py"]', dockerfile)
        self.assertIn("psycopg[binary]>=3.2,<4", requirements)


if __name__ == "__main__":
    unittest.main()
