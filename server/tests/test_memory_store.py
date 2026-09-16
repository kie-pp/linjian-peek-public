import copy
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memory_store import (
    MemoryAuthError,
    MemoryConflictError,
    MemoryDatabaseError,
    MemoryStore,
    MemoryValidationError,
    digest_credential,
)


class FakeRepository:
    def __init__(self):
        self.namespaces = set()
        self.credentials = {}
        self.active = {}
        self.history = {}
        self.fail = False

    def migrate(self):
        if self.fail:
            raise RuntimeError("database unavailable with private details")

    def bootstrap_credentials(self, reader_digest, writer_digest):
        if self.fail:
            raise RuntimeError("database unavailable")
        existing = {
            self.credentials[d]["namespace_id"]
            for d in (reader_digest, writer_digest)
            if d and d in self.credentials
        }
        if len(existing) > 1:
            raise RuntimeError("bootstrap credentials map to different namespaces")
        namespace_id = next(iter(existing), f"opaque-{len(self.namespaces) + 1}")
        self.namespaces.add(namespace_id)
        if reader_digest:
            self.credentials.setdefault(reader_digest, {"namespace_id": namespace_id, "scopes": ["memory:read"], "status": "active"})
        if writer_digest:
            self.credentials.setdefault(writer_digest, {"namespace_id": namespace_id, "scopes": ["memory:read", "memory:write"], "status": "active"})
        return namespace_id

    def resolve_credential(self, digest):
        if self.fail:
            raise RuntimeError("database unavailable")
        item = self.credentials.get(digest)
        return copy.deepcopy(item) if item else None

    def add_credential(self, namespace_id, digest, scopes):
        self.credentials[digest] = {"namespace_id": namespace_id, "scopes": list(scopes), "status": "active"}

    def disable_credential(self, digest):
        if digest in self.credentials:
            self.credentials[digest]["status"] = "disabled"

    def get_active(self, namespace_id):
        return copy.deepcopy(self.active.get(namespace_id))

    def set_active(self, namespace_id, content, content_hash, expected_revision=None):
        current = self.active.get(namespace_id)
        revision = int(current["revision"]) if current else 0
        if expected_revision is not None and expected_revision != revision:
            raise MemoryConflictError("revision_conflict")
        item = {
            "content": content,
            "revision": revision + 1,
            "content_hash": content_hash,
            "updated_at": datetime.now(timezone.utc),
        }
        self.active[namespace_id] = item
        return copy.deepcopy(item)

    def append_history(self, namespace_id, item):
        bucket = self.history.setdefault(namespace_id, [])
        duplicate = next((entry for entry in bucket if entry["content_hash"] == item["content_hash"]), None)
        if duplicate:
            return copy.deepcopy(duplicate), False
        stored = {"id": f"history-{len(bucket) + 1}", **item, "created_at": datetime.now(timezone.utc)}
        bucket.append(stored)
        return copy.deepcopy(stored), True

    def recent_history(self, namespace_id, limit):
        return copy.deepcopy(self.history.get(namespace_id, [])[-limit:])


class MemoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.repo = FakeRepository()
        self.store = MemoryStore(repository=self.repo, pepper="unit-test-pepper", enabled=True)
        self.reader = "reader-test-credential"
        self.writer = "writer-test-credential"
        self.namespace_id = self.store.bootstrap(self.reader, self.writer)

    def test_bootstrap_maps_reader_and_writer_to_one_namespace_without_plaintext(self):
        self.assertEqual(len(self.repo.namespaces), 1)
        reader_auth = self.store.authenticate(self.reader, "memory:read")
        writer_auth = self.store.authenticate(self.writer, "memory:write")
        self.assertEqual(reader_auth, writer_auth)
        serialized = repr(self.repo.credentials)
        self.assertNotIn(self.reader, serialized)
        self.assertNotIn(self.writer, serialized)
        self.assertIn(digest_credential(self.reader, "unit-test-pepper"), self.repo.credentials)

    def test_bootstrap_restart_reuses_namespace_and_rotation_does_not_change_it(self):
        self.assertEqual(self.store.bootstrap(self.reader, self.writer), self.namespace_id)
        new_reader = "rotated-reader-test-credential"
        self.store.rotate_credential(self.reader, new_reader, ["memory:read"])
        self.assertEqual(self.store.authenticate(new_reader, "memory:read"), self.namespace_id)
        with self.assertRaises(MemoryAuthError):
            self.store.authenticate(self.reader, "memory:read")
        self.assertEqual(len(self.repo.namespaces), 1)

    def test_bootstrap_rejects_reusing_one_token_for_reader_and_writer(self):
        with self.assertRaises(MemoryValidationError):
            MemoryStore(FakeRepository(), pepper="unit-test-pepper").bootstrap("same-token", "same-token")

    def test_reader_can_read_but_cannot_write_and_writer_can_do_both(self):
        self.assertEqual(self.store.get_active(self.reader)["revision"], 0)
        with self.assertRaises(MemoryAuthError):
            self.store.set_active(self.reader, "reader must not write")
        with self.assertRaises(MemoryAuthError):
            self.store.append_history(self.reader, "reader must not append")
        written = self.store.set_active(self.writer, "共享有效记忆")
        self.assertEqual(written["revision"], 1)
        self.assertEqual(self.store.get_active(self.writer)["content"], "共享有效记忆")

    def test_credentials_for_different_namespaces_are_isolated(self):
        other_reader = "other-reader"
        other_digest = digest_credential(other_reader, "unit-test-pepper")
        self.repo.credentials[other_digest] = {"namespace_id": "opaque-other", "scopes": ["memory:read"], "status": "active"}
        self.repo.namespaces.add("opaque-other")
        self.repo.active["opaque-other"] = {"content": "other", "revision": 1, "updated_at": datetime.now(timezone.utc)}
        self.store.set_active(self.writer, "mine")
        self.assertEqual(self.store.get_active(other_reader)["content"], "other")
        self.assertEqual(self.store.get_active(self.reader)["content"], "mine")

    def test_active_revision_increments_and_expected_revision_prevents_overwrite(self):
        first = self.store.set_active(self.writer, "first", expected_revision=0)
        second = self.store.set_active(self.writer, "second", expected_revision=1)
        self.assertEqual((first["revision"], second["revision"]), (1, 2))
        with self.assertRaises(MemoryConflictError):
            self.store.set_active(self.writer, "stale", expected_revision=1)

    def test_history_deduplicates_by_namespace_and_content_hash(self):
        first = self.store.append_history(self.writer, summary="一起决定做共享记忆", searchable_text="共享记忆", source="chatgpt")
        second = self.store.append_history(self.writer, summary="一起决定做共享记忆", searchable_text="共享记忆", source="chatgpt")
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["item"]["id"], second["item"]["id"])

    def test_context_scores_relevance_then_recency_and_enforces_limits(self):
        now = datetime.now(timezone.utc)
        for index in range(5):
            self.repo.append_history(self.namespace_id, {
                "summary": ("一起听歌" if index in (0, 3) else "无关事项") + "史" * 260,
                "searchable_text": "网易云 一起听歌" if index in (0, 3) else "天气",
                "source": "chatgpt",
                "occurred_at": now - timedelta(days=5 - index),
                "content_hash": f"hash-{index}",
            })
        self.repo.active[self.namespace_id] = {
            "content": "记" * 700,
            "revision": 1,
            "updated_at": datetime.now(timezone.utc),
        }
        context = self.store.get_context(self.reader, query="想继续一起听歌", history_limit=3)
        self.assertEqual(len(context["active_memory"]), 600)
        self.assertLessEqual(len(context["relevant_history"]), 3)
        self.assertLessEqual(sum(len(item["summary"]) for item in context["relevant_history"]), 600)
        self.assertIn("一起听歌", context["relevant_history"][0]["summary"])
        self.assertTrue(all("一起听歌" in item["summary"] for item in context["relevant_history"]))
        relevant_dates = [item["occurred_at"] for item in context["relevant_history"] if "一起听歌" in item["summary"]]
        self.assertEqual(relevant_dates, sorted(relevant_dates, reverse=True))
        self.assertNotIn("namespace", repr(context))
        search_results = self.store.search(self.reader, query="一起听歌", limit=3)
        self.assertLessEqual(sum(len(item["summary"]) for item in search_results), 600)

    def test_database_failures_are_sanitized(self):
        self.repo.fail = True
        with self.assertRaises(MemoryDatabaseError) as caught:
            self.store.get_active(self.reader)
        self.assertEqual(str(caught.exception), "memory_database_unavailable")
        self.assertNotIn(self.reader, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
