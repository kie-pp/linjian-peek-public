import copy
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memory_store import (
    MemoryConflictError,
    MemoryStore,
    MemoryValidationError,
    digest_credential,
    _credential_readiness,
)


class LifecycleRepository:
    def __init__(self):
        self.credentials = {}
        self.history = {}
        self._lock = threading.Lock()

    def bootstrap_credentials(self, reader_digest, writer_digest):
        namespace_id = "opaque-primary"
        self.credentials.setdefault(reader_digest, {
            "namespace_id": namespace_id,
            "scopes": ["memory:read"],
            "status": "active",
        })
        self.credentials.setdefault(writer_digest, {
            "namespace_id": namespace_id,
            "scopes": ["memory:read", "memory:write"],
            "status": "active",
        })
        return namespace_id

    def resolve_credential(self, credential_digest):
        return copy.deepcopy(self.credentials.get(credential_digest))

    def get_active(self, _namespace_id):
        return None

    def credential_readiness(self):
        active = [item for item in self.credentials.values() if item["status"] == "active"]
        by_namespace = {}
        for item in active:
            scopes = set(item["scopes"])
            roles = by_namespace.setdefault(item["namespace_id"], {"reader": False, "writer": False})
            roles["reader"] = roles["reader"] or ("memory:read" in scopes and "memory:write" not in scopes)
            roles["writer"] = roles["writer"] or "memory:write" in scopes
        if any(roles["reader"] and roles["writer"] for roles in by_namespace.values()):
            return {"ready": True, "reason": "ready"}
        has_read = any("memory:read" in item["scopes"] and "memory:write" not in item["scopes"] for item in active)
        has_write = any("memory:write" in item["scopes"] for item in active)
        if has_read and has_write:
            reason = "memory_credentials_namespace_mismatch"
        elif not has_read and not has_write:
            reason = "memory_credentials_missing"
        elif not has_read:
            reason = "memory_reader_credential_missing"
        else:
            reason = "memory_writer_credential_missing"
        return {"ready": False, "reason": reason}

    def append_history(self, namespace_id, item):
        with self._lock:
            bucket = self.history.setdefault(namespace_id, [])
            duplicate = next((row for row in bucket if row["content_hash"] == item["content_hash"]), None)
            if duplicate:
                return copy.deepcopy(duplicate), False
            row = {
                "id": f"history-{namespace_id}-{len(bucket) + 1}",
                **item,
                "status": "active",
                "supersedes_id": None,
                "deleted_at": None,
                "created_at": datetime.now(timezone.utc),
            }
            bucket.append(row)
            return copy.deepcopy(row), True

    def revise_history(self, namespace_id, history_id, item):
        with self._lock:
            bucket = self.history.setdefault(namespace_id, [])
            old = next((row for row in bucket if row["id"] == history_id), None)
            if not old:
                raise MemoryValidationError("history_not_found")
            existing = next((row for row in bucket if row.get("supersedes_id") == history_id), None)
            if existing:
                if existing["content_hash"] == item["content_hash"]:
                    return copy.deepcopy(existing), False
                raise MemoryConflictError("history_already_revised")
            if old["status"] != "active":
                raise MemoryConflictError("history_not_active")
            row = {
                "id": f"history-{namespace_id}-{len(bucket) + 1}",
                **item,
                "status": "active",
                "supersedes_id": history_id,
                "deleted_at": None,
                "created_at": datetime.now(timezone.utc),
            }
            old["status"] = "superseded"
            bucket.append(row)
            return copy.deepcopy(row), True

    def forget_history(self, namespace_id, history_id):
        with self._lock:
            bucket = self.history.setdefault(namespace_id, [])
            row = next((item for item in bucket if item["id"] == history_id), None)
            if not row:
                raise MemoryValidationError("history_not_found")
            changed = row["status"] != "deleted"
            if changed:
                row["status"] = "deleted"
                row["deleted_at"] = datetime.now(timezone.utc)
            return copy.deepcopy(row), changed

    def recent_history(self, namespace_id, limit):
        now = datetime.now(timezone.utc)
        rows = []
        for item in self.history.get(namespace_id, []):
            if item["status"] != "active":
                continue
            expires_at = item.get("expires_at")
            if expires_at and expires_at <= now:
                item["status"] = "expired"
                continue
            rows.append(copy.deepcopy(item))
        return rows[-limit:]


class MemoryHardeningTests(unittest.TestCase):
    def setUp(self):
        self.repo = LifecycleRepository()
        self.store = MemoryStore(self.repo, pepper="hardening-pepper")
        self.reader = "reader-unit-credential"
        self.writer = "writer-unit-credential"
        self.namespace_id = self.store.bootstrap(self.reader, self.writer)

    def test_readiness_requires_active_reader_and_writer_in_same_namespace(self):
        self.assertEqual(self.store.readiness(), {"ready": True, "reason": "ready"})

        writer_digest = digest_credential(self.writer, "hardening-pepper")
        self.repo.credentials[writer_digest]["status"] = "disabled"
        self.assertEqual(self.store.readiness()["reason"], "memory_writer_credential_missing")

        self.repo.credentials[writer_digest]["status"] = "active"
        reader_digest = digest_credential(self.reader, "hardening-pepper")
        self.repo.credentials[reader_digest]["status"] = "disabled"
        self.assertEqual(self.store.readiness()["reason"], "memory_reader_credential_missing")

        self.repo.credentials.clear()
        self.assertEqual(self.store.readiness()["reason"], "memory_credentials_missing")

        self.repo.credentials[digest_credential("read-two", "hardening-pepper")] = {
            "namespace_id": "ns-a", "scopes": ["memory:read"], "status": "active"
        }
        self.repo.credentials[digest_credential("write-two", "hardening-pepper")] = {
            "namespace_id": "ns-b", "scopes": ["memory:write"], "status": "active"
        }
        result = self.store.readiness()
        self.assertEqual(result, {"ready": False, "reason": "memory_credentials_namespace_mismatch"})
        self.assertNotIn("ns-a", repr(result))

    def test_production_readiness_evaluator_covers_all_credential_shapes(self):
        cases = [
            ([], {"ready": False, "reason": "memory_credentials_missing"}),
            ([("a", ["memory:read"])], {"ready": False, "reason": "memory_writer_credential_missing"}),
            ([("a", ["memory:read", "memory:write"])], {"ready": False, "reason": "memory_reader_credential_missing"}),
            ([("a", ["memory:read"]), ("b", ["memory:write"])], {"ready": False, "reason": "memory_credentials_namespace_mismatch"}),
            ([("a", ["memory:read"]), ("a", ["memory:read", "memory:write"])], {"ready": True, "reason": "ready"}),
        ]
        for rows, expected in cases:
            with self.subTest(rows=rows):
                self.assertEqual(_credential_readiness(rows), expected)

    def test_revision_inserts_new_record_and_is_idempotent(self):
        first = self.store.append_history(self.writer, "旧称呼", "称呼", "chatgpt")
        revised = self.store.revise_history(self.writer, first["item"]["id"], "新称呼", "称呼", "chatgpt")
        repeated = self.store.revise_history(self.writer, first["item"]["id"], "新称呼", "称呼", "chatgpt")
        self.assertTrue(revised["created"])
        self.assertFalse(repeated["created"])
        self.assertEqual(revised["item"]["supersedes_id"], first["item"]["id"])
        self.assertEqual(revised["item"]["id"], repeated["item"]["id"])
        original = self.repo.history[self.namespace_id][0]
        self.assertEqual(original["summary"], "旧称呼")
        self.assertEqual(original["status"], "superseded")
        visible = self.store.search(self.reader, "称呼")
        self.assertEqual([item["summary"] for item in visible], ["新称呼"])

    def test_forget_is_soft_idempotent_and_namespace_isolated(self):
        first = self.store.append_history(self.writer, "需要忘记的事实")
        history_id = first["item"]["id"]
        forgotten = self.store.forget_history(self.writer, history_id)
        repeated = self.store.forget_history(self.writer, history_id)
        self.assertTrue(forgotten["deleted"])
        self.assertFalse(repeated["changed"])
        self.assertEqual(self.repo.history[self.namespace_id][0]["summary"], "需要忘记的事实")
        self.assertEqual(self.store.get_context(self.reader)["relevant_history"], [])

        other_writer = "other-writer"
        self.repo.credentials[digest_credential(other_writer, "hardening-pepper")] = {
            "namespace_id": "opaque-other", "scopes": ["memory:read", "memory:write"], "status": "active"
        }
        with self.assertRaises(MemoryValidationError):
            self.store.forget_history(other_writer, history_id)

    def test_expired_history_is_not_returned(self):
        self.store.append_history(
            self.writer,
            "临时状态",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        self.assertEqual(self.store.get_context(self.reader)["relevant_history"], [])
        self.assertEqual(self.repo.history[self.namespace_id][0]["status"], "expired")

    def test_concurrent_revision_creates_only_one_successor(self):
        first = self.store.append_history(self.writer, "旧规则")
        history_id = first["item"]["id"]
        results = []

        def revise():
            results.append(self.store.revise_history(self.writer, history_id, "新规则"))

        threads = [threading.Thread(target=revise) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(1 for result in results if result["created"]), 1)
        self.assertEqual(len({result["item"]["id"] for result in results}), 1)

    def test_sensitive_content_is_rejected_without_echo(self):
        rejected = [
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
            "password=hunter2-secret-value",
            "Cookie: session=abc123secretvalue",
            "密码：this-should-never-be-stored",
            "postgresql://user:password@example.invalid/db",
            "C:\\Users\\person\\private\\notes.txt",
            "/home/person/private/notes.txt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturevalue",
            "用户: 第一段原始聊天内容\n助手: 第二段原始聊天内容\n用户: 第三段原始聊天内容\n助手: 第四段原始聊天内容" * 6,
        ]
        for content in rejected:
            with self.subTest(content=content[:20]):
                with self.assertRaises(MemoryValidationError) as caught:
                    self.store.append_history(self.writer, content)
                self.assertEqual(str(caught.exception), "memory_sensitive_content_rejected")
                self.assertNotIn(content, str(caught.exception))

    def test_normal_memory_content_is_not_overblocked(self):
        allowed = [
            "以后叫我培培",
            "我们约定说话简短一些",
            "项目文档在 https://example.com/docs",
            "今天完成了共享记忆接口设计",
            "我喜欢被叫昵称，不喜欢模板化问候",
        ]
        for index, content in enumerate(allowed):
            result = self.store.append_history(self.writer, content, source=f"test-{index}")
            self.assertTrue(result["created"])


if __name__ == "__main__":
    unittest.main()
