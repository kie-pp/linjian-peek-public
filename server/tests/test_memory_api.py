import json
import io
import sys
import threading
import unittest
from contextlib import redirect_stderr
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linjian_server import Handler
from memory_store import MemoryAuthError, MemoryConflictError, MemoryDatabaseError, MemoryValidationError


class FakeMemoryStore:
    def __init__(self):
        self.active = {"content": "当前记忆", "revision": 2, "updated_at": "2026-09-15T00:00:00Z"}

    def _check(self, token, write=False):
        if token not in ({"writer"} if write else {"reader", "writer"}):
            raise MemoryAuthError("invalid_memory_credential")

    def get_context(self, token, query="", history_limit=3):
        self._check(token)
        return {"active_memory": self.active["content"], "relevant_history": [{"summary": "相关历史"}], "revision": self.active["revision"], "generated_at": "2026-09-15T00:00:00Z"}

    def get_active(self, token):
        self._check(token)
        return dict(self.active)

    def search(self, token, query, limit=3):
        self._check(token)
        return [{"summary": "搜索结果"}]

    def set_active(self, token, content, expected_revision=None):
        self._check(token, write=True)
        if expected_revision not in (None, self.active["revision"]):
            raise MemoryConflictError("revision_conflict")
        if not isinstance(content, str) or not content.strip():
            raise MemoryValidationError("content_required")
        self.active = {"content": content, "revision": self.active["revision"] + 1, "updated_at": "2026-09-15T00:00:01Z"}
        return dict(self.active)

    def append_history(self, token, **item):
        self._check(token, write=True)
        return {"created": True, "item": {"id": "fake-history", "summary": item["summary"]}}

    def revise_history(self, token, history_id, **item):
        self._check(token, write=True)
        return {"created": True, "item": {"id": "fake-revision", "supersedes_id": history_id, "summary": item["summary"]}}

    def forget_history(self, token, history_id):
        self._check(token, write=True)
        return {"deleted": True, "changed": True, "item": {"id": history_id, "status": "deleted"}}


class FakeState:
    token = "legacy-token"
    port = 0
    memory_enabled = True
    memory_ready = True
    memory_store = FakeMemoryStore()
    memory_error = ""
    audit_events = []

    @classmethod
    def record_memory_audit(cls, event):
        cls.audit_events.append(event)


class MemoryApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Handler.state = FakeState()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        Handler.state.memory_enabled = True
        Handler.state.memory_ready = True
        Handler.state.memory_error = ""
        Handler.state.memory_store = FakeMemoryStore()
        Handler.state.audit_events = []

    def request(self, method, path, body=None, token=None, raw_body=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=2)
        headers = {}
        if token:
            headers["X-Auth-Token"] = token
        payload = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        decoded = json.loads(response.read().decode())
        connection.close()
        return response.status, decoded

    def test_reader_context_has_no_namespace_and_query_token_is_rejected(self):
        status, payload = self.request("POST", "/api/memory/context", {"query": "今天", "history_limit": 3}, "reader")
        self.assertEqual(status, 200)
        self.assertNotIn("namespace", repr(payload))
        captured = io.StringIO()
        with redirect_stderr(captured):
            status, _ = self.request("POST", "/api/memory/context?token=query-secret-must-not-log", {"query": "今天"})
        self.assertEqual(status, 403)
        self.assertNotIn("query-secret-must-not-log", captured.getvalue())
        self.assertIn("<redacted>", captured.getvalue())

    def test_client_cannot_submit_namespace(self):
        status, payload = self.request("POST", "/api/memory/context", {"query": "今天", "namespace": "chosen"}, "reader")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "namespace_not_allowed")
        status, payload = self.request("GET", "/api/memory/active?namespace_id=chosen", token="reader")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "namespace_not_allowed")

    def test_reader_endpoints_and_writer_endpoints_enforce_scope(self):
        self.assertEqual(self.request("GET", "/api/memory/active", token="reader")[0], 200)
        self.assertEqual(self.request("POST", "/api/memory/search", {"query": "搜索"}, "reader")[0], 200)
        self.assertEqual(self.request("PUT", "/api/memory/active", {"content": "new"}, "reader")[0], 403)
        self.assertEqual(self.request("POST", "/api/memory/history", {"summary": "denied"}, "reader")[0], 403)
        self.assertEqual(self.request("PUT", "/api/memory/active", {"content": "new", "expected_revision": 2}, "writer")[0], 200)
        self.assertEqual(self.request("POST", "/api/memory/history", {"summary": "new history", "source": "chatgpt"}, "writer")[0], 201)
        self.assertEqual(self.request("PATCH", "/api/memory/history/fake-history", {"summary": "revised"}, "reader")[0], 403)
        self.assertEqual(self.request("PATCH", "/api/memory/history/fake-history", {"summary": "revised"}, "writer")[0], 200)
        self.assertEqual(self.request("DELETE", "/api/memory/history/fake-history", token="writer")[0], 200)
        allowed_audit_keys = {"tool", "status", "duration_ms", "revision", "history_item_id"}
        self.assertTrue(all(set(event).issubset(allowed_audit_keys) for event in Handler.state.audit_events))
        self.assertNotIn("new history", repr(Handler.state.audit_events))
        self.assertNotIn("revised", repr(Handler.state.audit_events))
        self.assertTrue(all("namespace" not in repr(event) for event in Handler.state.audit_events))

    def test_device_id_is_rejected_and_audit_failure_does_not_change_success(self):
        status, payload = self.request("POST", "/api/memory/history", {"summary": "safe", "device_id": "phone"}, "writer")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "namespace_not_allowed")
        original = Handler.state.record_memory_audit
        Handler.state.record_memory_audit = lambda _event: (_ for _ in ()).throw(RuntimeError("audit failed"))
        try:
            status, payload = self.request("POST", "/api/memory/history", {"summary": "still succeeds"}, "writer")
            self.assertEqual(status, 201)
            self.assertTrue(payload["ok"])
        finally:
            Handler.state.record_memory_audit = original

    def test_bearer_auth_invalid_json_limits_and_revision_conflict(self):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request("GET", "/api/memory/active", headers={"Authorization": "Bearer reader"})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        response.read(); connection.close()
        self.assertEqual(self.request("POST", "/api/memory/context", token="reader", raw_body=b"not-json")[0], 400)
        self.assertEqual(self.request("POST", "/api/memory/search", {"query": "x" * 501}, "reader")[0], 400)
        self.assertEqual(self.request("PUT", "/api/memory/active", {"content": "conflict", "expected_revision": 1}, "writer")[0], 409)

    def test_disabled_feature_does_not_break_existing_routes(self):
        previous = Handler.state.memory_enabled
        Handler.state.memory_enabled = False
        try:
            self.assertEqual(self.request("GET", "/api/memory/active", token="reader")[0], 404)
            self.assertEqual(self.request("GET", "/api/known_apps")[0], 200)
        finally:
            Handler.state.memory_enabled = previous

    def test_database_failure_is_sanitized_and_does_not_break_existing_routes(self):
        original = Handler.state.memory_store
        class FailingStore:
            def get_active(self, _token):
                raise MemoryDatabaseError("memory_database_unavailable")
        Handler.state.memory_store = FailingStore()
        try:
            status, payload = self.request("GET", "/api/memory/active", token="reader")
            self.assertEqual(status, 503)
            self.assertEqual(payload["error"], "memory_database_unavailable")
            self.assertEqual(self.request("GET", "/api/known_apps")[0], 200)
        finally:
            Handler.state.memory_store = original


if __name__ == "__main__":
    unittest.main()
