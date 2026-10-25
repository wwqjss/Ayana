"""P6.2 Web provider contracts with isolated files and zero model calls."""
from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from aiohttp import web
from ayana.db import Database
from ayana.mimo_admin import MimoAdmin
from ayana.web import WebApp


SUCCESS = {"ok": True, "result": "success", "message": "连接成功", "http_status": 200}
FAILURE = {"ok": False, "result": "auth_failed", "message": "认证失败", "http_status": 401}


def request(body=None, *, method="POST", csrf="csrf", origin=""):
    return SimpleNamespace(
        json=AsyncMock(return_value=body), method=method,
        headers={"X-CSRF-Token": csrf, "Host": "ayana.test", "Origin": origin},
        rel_url=SimpleNamespace(query={}),
    )


def payload(response):
    return json.loads(response.text)


class ProviderAPITests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.db = Database(self.base / "web.db")
        self.addCleanup(self.db.close)
        self.admin = MimoAdmin()
        self.path = self.base / "mimocode.jsonc"
        self.admin.config_path = lambda config_dir="": self.path
        self.admin.status = AsyncMock(return_value={"exists": True, "version": "test"})
        self.admin.test_connection = Mock(return_value=dict(SUCCESS))
        self.incidents = Mock()
        self.incidents.get_incident.return_value = {"id": "inc1", "asset_id": "host"}
        self.app = WebApp(self.db, Mock(), Mock(), self.incidents, None, None, None,
                          static_dir=self.base, mimo_admin=self.admin)
        self.session = {"username": "admin", "is_admin": True, "csrf_token": "csrf"}
        self.app._require_auth = Mock(return_value=self.session)
        self.app._visible_asset_ids = Mock(return_value={"host"})
        self.credentials = {"provider_id": "selected", "api_key": "dummy-private-key",
                            "base_url": "https://example.test/v1", "model": "model-a"}

    def seed(self):
        self.admin.apply_provider(**self.credentials)
        self.admin.record_verification(self.db, self.credentials, dict(SUCCESS))
        self.assertTrue(self.admin.verification_state(self.db)["verified"])

    async def test_provider_reads_and_mutations_require_admin(self):
        self.session["is_admin"] = False
        for handler in (self.app.api_mimo_providers, self.app.api_mimo_provider_status,
                        self.app.api_mimo_provider_test, self.app.api_mimo_provider_apply,
                        self.app.api_mimo_provider_clear, self.app.api_mimo_chat):
            with self.assertRaises(web.HTTPForbidden):
                await handler(request({}))
        self.admin.test_connection.assert_not_called()
        self.assertFalse(self.path.exists())

    async def test_mutations_keep_csrf_and_origin_checks(self):
        for handler in (self.app.api_mimo_provider_test, self.app.api_mimo_provider_apply,
                        self.app.api_mimo_provider_clear, self.app.api_mimo_chat):
            for fields in ({"csrf": ""}, {"origin": "https://evil.test"}):
                with self.assertRaises(web.HTTPForbidden):
                    await handler(request({}, **fields))
        self.admin.test_connection.assert_not_called()

    async def test_invalid_json_and_field_types_fail_before_model_calls(self):
        for handler in (self.app.api_mimo_provider_test, self.app.api_mimo_provider_apply,
                        self.app.api_mimo_provider_clear):
            for body in (None, [], "text", {"api_key": {}}, {"test": "false"}, {"config_dir": "ignored"}):
                response = await handler(request(body))
                self.assertEqual(response.status, 400)
                self.assertEqual(payload(response)["error"], "bad_request")
            req = request({})
            req.json.side_effect = ValueError("invalid JSON dummy-private-key")
            response = await handler(req)
            self.assertEqual(response.status, 400)
            self.assertNotIn("dummy-private-key", response.text)
        self.admin.test_connection.assert_not_called()

    async def test_blank_key_save_reuses_selected_saved_provider_without_echo(self):
        self.seed()
        response = await self.app.api_mimo_provider_apply(request({"api_key": ""}))
        self.assertEqual(response.status, 200)
        self.assertTrue(payload(response)["verified"])
        self.assertEqual(payload(response)["provider"], "selected")
        self.admin.test_connection.assert_called_once_with(
            base_url=self.credentials["base_url"], api_key=self.credentials["api_key"], model="model-a")
        status = await self.app.api_mimo_provider_status(request(method="GET"))
        self.assertTrue(payload(status)["available"])
        audit = [dict(row) for row in self.db.query("SELECT detail_json FROM audit_log")]
        self.assertNotIn(self.credentials["api_key"], response.text + status.text + json.dumps(audit))

    async def test_blank_key_cannot_forward_saved_credentials_to_changed_endpoint(self):
        self.seed()
        before = self.path.read_bytes()
        response = await self.app.api_mimo_provider_test(request({"base_url": "https://other.example.test/v1"}))
        self.assertEqual(response.status, 400)
        self.assertEqual(payload(response)["error"], "key_required_for_endpoint_change")
        self.admin.test_connection.assert_not_called()
        self.assertEqual(self.path.read_bytes(), before)

    async def test_failed_saved_key_retest_invalidates_availability(self):
        self.seed()
        self.admin.test_connection.return_value = dict(FAILURE)
        response = await self.app.api_mimo_provider_test(request({}))
        self.assertFalse(payload(response)["ok"])
        self.assertFalse(self.admin.verification_state(self.db)["verified"])
        status = payload(await self.app.api_mimo_provider_status(request(method="GET")))
        self.assertFalse(status["available"])

    async def test_failed_draft_test_does_not_invalidate_saved_good_config(self):
        self.seed()
        before = self.path.read_bytes()
        self.admin.test_connection.return_value = dict(FAILURE)
        response = await self.app.api_mimo_provider_test(request({"api_key": "dummy-new-draft"}))
        self.assertFalse(payload(response)["ok"])
        self.assertTrue(self.admin.verification_state(self.db)["verified"])
        self.assertEqual(self.path.read_bytes(), before)

    async def test_changed_or_missing_config_is_not_available(self):
        self.seed()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data["provider"]["selected"]["options"]["apiKey"] = "dummy-external-change"
        self.path.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(payload(await self.app.api_mimo_provider_status(request(method="GET")))["available"])
        self.path.unlink()
        self.assertFalse(payload(await self.app.api_mimo_provider_status(request(method="GET")))["available"])

    async def test_failed_save_test_keeps_existing_config_intact(self):
        self.seed()
        before = self.path.read_bytes()
        self.admin.test_connection.return_value = dict(FAILURE)
        response = await self.app.api_mimo_provider_apply(request({"api_key": "dummy-failing-draft"}))
        self.assertEqual(response.status, 400)
        self.assertFalse(payload(response)["saved"])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(self.admin.verification_state(self.db)["verified"])

    async def test_save_exception_is_redacted_and_does_not_mark_draft_verified(self):
        self.seed()
        before = self.path.read_bytes()
        with patch.object(self.admin, "apply_provider", side_effect=OSError("dummy-private-key storage failure")):
            response = await self.app.api_mimo_provider_apply(request({"api_key": "dummy-new-draft"}))
        self.assertEqual(response.status, 500)
        self.assertEqual(payload(response)["error"], "provider_save_failed")
        self.assertNotIn("dummy-private-key", response.text)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(self.admin.verification_state(self.db)["verified"])

    async def test_explicit_untested_draft_never_marks_available(self):
        self.seed()
        response = await self.app.api_mimo_provider_apply(request({"api_key": "dummy-new-draft", "test": False}))
        self.assertTrue(payload(response)["saved"])
        self.assertFalse(payload(response)["verified"])
        self.admin.test_connection.assert_not_called()
        self.assertFalse(payload(await self.app.api_mimo_provider_status(request(method="GET")))["available"])

    async def test_clear_uses_active_provider_and_resets_verification(self):
        self.seed()
        response = await self.app.api_mimo_provider_clear(request({}))
        self.assertTrue(payload(response)["ok"])
        self.assertFalse(payload(response)["verified"])
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertNotIn("apiKey", data["provider"]["selected"]["options"])
        self.assertFalse(payload(await self.app.api_mimo_provider_status(request(method="GET")))["available"])

    async def test_model_test_does_not_block_event_loop(self):
        self.seed()
        released = threading.Event()
        waited = []
        def model_request(**kwargs):
            waited.append(released.wait(1))
            return dict(SUCCESS)
        self.admin.test_connection = model_request
        async def release_from_event_loop():
            await asyncio.sleep(0.01)
            released.set()
        try:
            response, _ = await asyncio.gather(self.app.api_mimo_provider_test(request({})), release_from_event_loop())
        finally:
            released.set()
        self.assertTrue(payload(response)["ok"])
        self.assertEqual(waited, [True])

    async def test_chat_propagates_prompt_failure_without_raw_errors(self):
        bridge = Mock()
        bridge.attach_remote.return_value = {"ok": True, "remote_session_id": "ses-test"}
        bridge.prompt_remote.return_value = {"ok": False, "message": "dummy-private-key runtime error"}
        self.app.session_bridge = bridge
        response = await self.app.api_mimo_chat(request({"incident_id": "inc1", "prompt": "inspect"}))
        self.assertEqual(response.status, 502)
        self.assertFalse(payload(response)["ok"])
        self.assertNotIn("dummy-private-key", response.text)

    async def test_chat_respects_incident_visibility_before_remote_call(self):
        bridge = Mock()
        self.app.session_bridge = bridge
        self.app._visible_asset_ids.return_value = set()
        response = await self.app.api_mimo_chat(request({"incident_id": "inc1", "prompt": "inspect"}))
        self.assertEqual(response.status, 403)
        self.assertEqual(bridge.mock_calls, [])

    async def test_invalid_existing_config_is_not_overwritten_or_tested(self):
        original = '{"provider": broken}'
        self.path.write_text(original, encoding="utf-8")
        response = await self.app.api_mimo_provider_apply(request(self.credentials))
        self.assertEqual(response.status, 400)
        self.assertEqual(payload(response)["error"], "invalid_provider_config")
        self.admin.test_connection.assert_not_called()
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

    async def test_state_storage_failure_reports_a_written_but_unverified_config(self):
        self.seed()
        with patch.object(self.admin, "record_verification", side_effect=ValueError("provider_state_save_failed")):
            response = await self.app.api_mimo_provider_apply(request({"api_key": "dummy-new-draft"}))
        self.assertEqual(response.status, 500)
        self.assertTrue(payload(response)["saved"])
        self.assertFalse(payload(response)["verified"])
        self.assertEqual(payload(response)["error"], "provider_state_save_failed")
        self.assertFalse(self.admin.verification_state(self.db)["verified"])
        self.assertNotIn("dummy-new-draft", response.text)


if __name__ == "__main__":
    unittest.main()
