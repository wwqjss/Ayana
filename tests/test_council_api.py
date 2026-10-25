"""Retired Council surfaces preserve visibility, historical reads and mutation gates."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from aiohttp import web

from ayana.db import Database
from ayana.fmt import fmt_council_notice
from ayana.web import WebApp


def request(body=None, *, method="GET", csrf="csrf", origin=""):
    return SimpleNamespace(
        json=AsyncMock(return_value=body), method=method,
        match_info={"inc_id": "inc1"},
        headers={"X-CSRF-Token": csrf, "Host": "ayana.test", "Origin": origin},
        rel_url=SimpleNamespace(query={}, path="/api/autonomy/providers"),
    )


def payload(response):
    return json.loads(response.body)


class CouncilAPITests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "web.db")
        self.auth = Mock()
        self.auth.totp_enabled.return_value = False
        self.incidents = Mock()
        self.incidents.get_incident.return_value = {"id": "inc1", "asset_id": "nerv", "generation": 2}
        self.providers = Mock()
        self.providers.public_config.return_value = {"enabled": False, "roles": {"planner": {"key_configured": True}}}
        self.providers.usage_summary.return_value = {"overall": {"cost_cny": 0, "complete": False}, "budget": {"budget_cny": 100}}
        self.autonomy = Mock()
        self.autonomy.snapshot.return_value = {"phase": "reviewing", "plans": [], "manual_required": False}
        self.autonomy.release_manual_barrier.return_value = {"goal_id": "goal1", "manual_required": False}
        self.app = WebApp(self.db, self.auth, Mock(), self.incidents, None, None, None,
                          static_dir=Path(self.tmp.name), providers=self.providers, autonomy=self.autonomy)
        self.history = Mock()
        self.history.snapshot.return_value = {"enabled": False, "retired": True, "read_only": True, "phase": "reviewing", "plans": [], "manual_required": False}
        self.history.public_config.return_value = {"enabled": False, "retired": True, "read_only": True, "roles": {}}
        self.history.usage_summary.return_value = {"overall": {"cost_cny": None, "complete": False}}
        self.app.legacy_history = self.history
        self.session = {"username": "operator", "is_admin": True, "csrf_token": "csrf"}
        self.app._require_auth = Mock(return_value=self.session)
        self.app._visible_asset_ids = Mock(return_value={"nerv"})

    def tearDown(self):
        self.assertEqual(self.providers.mock_calls, [], "Retired provider service must not be invoked")
        self.assertEqual(self.autonomy.mock_calls, [], "Retired autonomy service must not be invoked")
        self.db.close()
        self.tmp.cleanup()

    def assert_retired(self, response, req=None):
        self.assertEqual(response.status, 410)
        result = payload(response)
        self.assertEqual(result["error"], "legacy_autonomy_retired")
        self.assertTrue(result["retired"])
        self.assertTrue(result["read_only"])
        self.assertFalse(result["enabled"])
        if req is not None:
            req.json.assert_not_awaited()

    async def test_incident_snapshot_reuses_asset_visibility_before_reading_ai_records(self):
        self.app._visible_asset_ids.return_value = {"other"}
        response = await self.app.api_incident_council(request())
        self.assertEqual(response.status, 403)
        self.history.snapshot.assert_not_called()

    async def test_missing_incident_does_not_load_council(self):
        self.incidents.get_incident.return_value = None
        self.assertEqual((await self.app.api_incident_council(request())).status, 404)
        self.history.snapshot.assert_not_called()

    async def test_asset_reader_can_read_snapshot_but_cannot_read_provider_settings_or_global_usage(self):
        self.session["is_admin"] = False
        self.assertTrue(payload(await self.app.api_incident_council(request()))["ok"])
        for handler in (self.app.api_autonomy_providers, self.app.api_autonomy_usage):
            with self.assertRaises(web.HTTPForbidden):
                await handler(request())
        self.providers.public_config.assert_not_called()

    async def test_provider_update_requires_admin(self):
        self.session["is_admin"] = False
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_autonomy_providers_save(request({}, method="POST"))
        self.providers.update_config.assert_not_called()

    async def test_provider_update_requires_csrf_and_same_origin(self):
        for fields in ({"csrf": ""}, {"origin": "https://evil.test"}):
            with self.assertRaises(web.HTTPForbidden):
                await self.app.api_autonomy_providers_save(request({}, method="POST", **fields))
        self.providers.update_config.assert_not_called()

    async def test_provider_update_is_retired_even_with_totp_enabled(self):
        self.auth.totp_enabled.return_value = True
        req = request({}, method="POST")
        self.assert_retired(await self.app.api_autonomy_providers_save(req), req)
        self.auth.verify_totp.assert_not_called()

    async def test_invalid_totp_cannot_save_key(self):
        self.auth.totp_enabled.return_value = True
        self.auth.verify_totp.return_value = False
        req = request({"totp": "123456", "roles": {"planner": {"api_key": "secret"}}}, method="POST")
        response = await self.app.api_autonomy_providers_save(req)
        self.assert_retired(response, req)
        self.assertNotIn("123456", response.text)
        self.auth.verify_totp.assert_not_called()

    async def test_keys_and_totp_never_reach_retired_provider_config(self):
        req = request({"roles": {"planner": {"api_key": "fresh-api-secret"}}, "totp": "123456"}, method="POST")
        response = await self.app.api_autonomy_providers_save(req)
        self.assert_retired(response, req)
        self.assertNotIn("fresh-api-secret", response.text)
        self.assertNotIn("123456", response.text)
        settings = payload(await self.app.api_autonomy_providers(request()))
        self.assertEqual(settings["config"]["roles"], {})
        self.assertTrue(settings["retired"])
        self.assertFalse(settings["available"])

    async def test_configuration_errors_do_not_echo_secrets(self):
        self.providers.update_config.side_effect = ValueError("bad key fresh-api-secret")
        req = request({"roles": {"planner": {"api_key": "fresh-api-secret"}}}, method="POST")
        response = await self.app.api_autonomy_providers_save(req)
        self.assert_retired(response, req)
        self.assertNotIn("fresh-api-secret", response.text)

    async def test_config_array_rejected_without_mutation(self):
        req = request([], method="POST")
        self.assert_retired(await self.app.api_autonomy_providers_save(req), req)

    async def test_manual_review_preserves_admin_visibility_and_csrf_before_retirement(self):
        self.session["is_admin"] = False
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST"))
        self.session["is_admin"] = True
        self.app._visible_asset_ids.return_value = set()
        self.assertEqual((await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST"))).status, 403)
        self.app._visible_asset_ids.return_value = {"nerv"}
        for fields in ({"csrf": ""}, {"origin": "https://evil.test"}):
            with self.assertRaises(web.HTTPForbidden):
                await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST", **fields))
        self.auth.totp_enabled.return_value = True
        req = request({"goal_id": "goal1"}, method="POST")
        self.assert_retired(await self.app.api_council_manual_review(req), req)

    async def test_manual_review_cannot_reopen_even_an_exact_goal(self):
        req = request({"goal_id": "goal1", "totp": ""}, method="POST")
        self.assert_retired(await self.app.api_council_manual_review(req), req)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM council_grants")[0], 0)

    async def test_manual_review_rejects_missing_goal_or_execution_fields(self):
        for body in ({}, {"goal_id": ""}, {"goal_id": "goal1", "execute": True}, {"goal_id": "goal1", "approve": True}):
            req = request(body, method="POST")
            self.assert_retired(await self.app.api_council_manual_review(req), req)

    async def test_manual_conflicts_cannot_call_a_retired_service(self):
        for result in (ValueError("old generation"), {"ok": False}):
            self.autonomy.release_manual_barrier.side_effect = result if isinstance(result, Exception) else None
            self.autonomy.release_manual_barrier.return_value = result
            req = request({"goal_id": "goal1"}, method="POST")
            self.assert_retired(await self.app.api_council_manual_review(req), req)

    async def test_history_failure_does_not_break_existing_incident_detail(self):
        self.app._incident_human_summary = Mock(return_value={"title": "frps"})
        self.app._incident_disposition = Mock(return_value={})
        self.history.snapshot.side_effect = RuntimeError("offline")
        response = await self.app.api_incident_detail(request())
        self.assertEqual(response.status, 200)
        self.assertEqual(payload(response)["council"]["status"], "unavailable")
        self.assertTrue(payload(response)["council"]["retired"])
        self.assertEqual(payload(response)["incident"]["id"], "inc1")

    async def test_injected_async_legacy_snapshot_is_ignored(self):
        self.autonomy.snapshot = AsyncMock(return_value={"phase": "investigating"})
        response = payload(await self.app.api_incident_council(request()))
        self.assertEqual(response["council"]["phase"], "reviewing")
        self.assertTrue(response["council"]["retired"])
        self.history.snapshot.assert_called_once_with("inc1")
        self.autonomy.snapshot.assert_not_awaited()
        self.assertIsNone(self.app.autonomy)
        self.assertIsNone(self.app.providers)

    def test_reviewed_actions_do_not_become_manual_approval_proposals(self):
        self.app.policy.effective_decision.return_value = {"allowed": False}
        disposition = self.app._incident_disposition({"actions": [
            {"id": "a1", "mode": "reviewed", "state": "proposed", "council_grant_id": "g1"},
            {"id": "a2", "mode": "reviewed", "state": "approved", "council_grant_id": "g1"},
        ]})
        self.assertEqual(disposition["proposals"], [])

    async def test_unconfigured_ai_keeps_history_readable_and_write_routes_retired(self):
        self.app.autonomy = None
        self.app.providers = None
        self.assertFalse(payload(await self.app.api_incident_council(request()))["council"]["enabled"])
        self.assertFalse(payload(await self.app.api_autonomy_providers(request()))["available"])
        self.assertIsNone(payload(await self.app.api_autonomy_usage(request()))["usage"]["overall"]["cost_cny"])
        req = request({}, method="POST")
        self.assert_retired(await self.app.api_autonomy_providers_save(req), req)

    async def test_account_verification_preserves_admin_and_csrf_without_external_calls(self):
        self.providers.verify_account = AsyncMock(return_value={"ok": True, "role": "reviewer_kimi"})
        self.session["is_admin"] = False
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_autonomy_provider_verify(request({"role": "reviewer_kimi"}, method="POST"))
        self.session["is_admin"] = True
        for fields in ({"csrf": ""}, {"origin": "https://evil.test"}):
            with self.assertRaises(web.HTTPForbidden):
                await self.app.api_autonomy_provider_verify(request({"role": "reviewer_kimi"}, method="POST", **fields))
        for body in ({"role": "random"}, {"role": []}, {"role": {}}, {"role": "reviewer_kimi", "api_key": "forged"}):
            req = request(body, method="POST")
            self.assert_retired(await self.app.api_autonomy_provider_verify(req), req)
        self.auth.totp_enabled.return_value = True
        req = request({"role": "reviewer_kimi"}, method="POST")
        self.assert_retired(await self.app.api_autonomy_provider_verify(req), req)

    async def test_account_verification_failure_does_not_claim_support(self):
        self.providers.verify_account = AsyncMock(return_value={"ok": False, "error": "model_not_available"})
        req = request({"role": "reviewer_kimi"}, method="POST")
        response = await self.app.api_autonomy_provider_verify(req)
        self.assert_retired(response, req)
        self.assertNotIn("result", payload(response))

    async def test_saved_role_cannot_reenable_retired_account_verification(self):
        self.providers.verify_account = AsyncMock(return_value={"ok": True, "role": "reviewer_deepseek", "models": ["real-model"]})
        req = request({"role": "reviewer_deepseek", "totp": ""}, method="POST")
        self.assert_retired(await self.app.api_autonomy_provider_verify(req), req)
        self.providers.verify_account.assert_not_awaited()

    async def test_court_manual_conflict_returns_retired_without_loading_court(self):
        self.autonomy.release_manual_barrier.side_effect = RuntimeError("retired service must not run")
        req = request({"goal_id": "goal1"}, method="POST")
        self.assert_retired(await self.app.api_council_manual_review(req), req)

    def test_manual_notice_contains_three_round_vetoes_and_requires_new_reviews(self):
        rounds = [{"version": index, "plan": {"rationale": "证据"}, "reviews": [{"provider": "kimi", "approve": False, "reason": "缺少日志"}]} for index in range(1, 5)]
        notice = fmt_council_notice({"id": "inc1", "generation": 2, "asset_id": "nerv"}, "manual_required", rounds=rounds)
        self.assertNotIn("方案 v1", notice)
        self.assertIn("方案 v4", notice)
        self.assertEqual(notice.count("封驳: 缺少日志"), 3)
        self.assertIn("重新拟案仍须双委员审议", notice)

    async def test_all_retired_mutations_still_require_authentication(self):
        self.app._require_auth.side_effect = web.HTTPUnauthorized()
        for handler in (self.app.api_autonomy_providers_save, self.app.api_autonomy_provider_verify,
                        self.app.api_council_manual_review, self.app.api_agent_auto_toggle):
            with self.assertRaises(web.HTTPUnauthorized):
                await handler(request({}, method="POST"))

    async def test_auto_toggle_retires_both_enable_and_disable_without_touching_state(self):
        agent = Mock()
        self.app.agent = agent
        self.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('agent_auto_enabled','1')")
        before = self.db.query_one("SELECT total_changes()")[0]
        for enabled in (True, False):
            req = request({"enabled": enabled}, method="POST")
            self.assert_retired(await self.app.api_agent_auto_toggle(req), req)
        self.assertEqual(agent.mock_calls, [])
        self.assertEqual(self.db.query_one("SELECT total_changes()")[0], before)
        self.assertEqual(self.db.query_one("SELECT value FROM meta WHERE key='agent_auto_enabled'")[0], "1")
        status = payload(await self.app.api_agent_status(request()))
        self.assertTrue(status["retired"])
        self.assertFalse(status["auto_enabled"])
        self.assertFalse(status["enabled"])
        self.assertFalse(status["llm_enabled"])

    async def test_auto_toggle_preserves_admin_csrf_and_origin_gates(self):
        self.session["is_admin"] = False
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_agent_auto_toggle(request({}, method="POST"))
        self.session["is_admin"] = True
        for fields in ({"csrf": ""}, {"origin": "https://evil.test"}):
            with self.assertRaises(web.HTTPForbidden):
                await self.app.api_agent_auto_toggle(request({}, method="POST", **fields))

    async def test_registered_legacy_post_routes_return_http_gone(self):
        from aiohttp.test_utils import TestClient, TestServer

        client = TestClient(TestServer(self.app.build()))
        await client.start_server()
        try:
            for route in ("/api/autonomy/providers", "/api/autonomy/providers/verify",
                          "/api/incidents/inc1/council/review", "/api/agent/auto"):
                response = await client.post(route, data="not-json", headers={"X-CSRF-Token": "csrf"})
                self.assertEqual(response.status, 410, route)
                self.assertEqual((await response.json())["error"], "legacy_autonomy_retired")
        finally:
            await client.close()


if __name__ == "__main__":
    unittest.main()
