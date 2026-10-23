"""Council surfaces preserve asset visibility, administrator gates and write-only keys."""
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
        self.session = {"username": "operator", "is_admin": True, "csrf_token": "csrf"}
        self.app._require_auth = Mock(return_value=self.session)
        self.app._visible_asset_ids = Mock(return_value={"nerv"})

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    async def test_incident_snapshot_reuses_asset_visibility_before_reading_ai_records(self):
        self.app._visible_asset_ids.return_value = {"other"}
        response = await self.app.api_incident_council(request())
        self.assertEqual(response.status, 403)
        self.autonomy.snapshot.assert_not_called()

    async def test_missing_incident_does_not_load_council(self):
        self.incidents.get_incident.return_value = None
        self.assertEqual((await self.app.api_incident_council(request())).status, 404)
        self.autonomy.snapshot.assert_not_called()

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

    async def test_provider_update_requires_totp_when_enabled(self):
        self.auth.totp_enabled.return_value = True
        self.assertEqual((await self.app.api_autonomy_providers_save(request({}, method="POST"))).status, 403)
        self.providers.update_config.assert_not_called()

    async def test_invalid_totp_cannot_save_key(self):
        self.auth.totp_enabled.return_value = True
        self.auth.verify_totp.return_value = False
        response = await self.app.api_autonomy_providers_save(request({"totp": "123456", "roles": {"planner": {"api_key": "secret"}}}, method="POST"))
        self.assertEqual(response.status, 403)
        self.providers.update_config.assert_not_called()

    async def test_keys_are_write_only_and_totp_never_reaches_provider_config(self):
        patch = {"roles": {"planner": {"api_key": "fresh-api-secret"}}, "totp": "123456"}
        response = await self.app.api_autonomy_providers_save(request(patch, method="POST"))
        self.assertTrue(payload(response)["ok"])
        self.providers.update_config.assert_called_once_with({"roles": patch["roles"]}, actor="operator")
        self.assertNotIn("fresh-api-secret", response.text)
        self.assertNotIn("123456", response.text)

    async def test_configuration_errors_do_not_echo_secrets(self):
        self.providers.update_config.side_effect = ValueError("bad key fresh-api-secret")
        response = await self.app.api_autonomy_providers_save(request({"roles": {"planner": {"api_key": "fresh-api-secret"}}}, method="POST"))
        self.assertEqual(response.status, 400)
        self.assertNotIn("fresh-api-secret", response.text)

    async def test_config_array_rejected_without_mutation(self):
        self.assertEqual((await self.app.api_autonomy_providers_save(request([], method="POST"))).status, 400)
        self.providers.update_config.assert_not_called()

    async def test_manual_review_requires_admin_visibility_csrf_and_totp(self):
        self.session["is_admin"] = False
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST"))
        self.session["is_admin"] = True
        self.app._visible_asset_ids.return_value = set()
        self.assertEqual((await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST"))).status, 403)
        self.app._visible_asset_ids.return_value = {"nerv"}
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST", csrf=""))
        self.auth.totp_enabled.return_value = True
        self.assertEqual((await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST"))).status, 403)
        self.autonomy.release_manual_barrier.assert_not_called()

    async def test_manual_review_is_exact_goal_only_and_creates_no_execute_permission(self):
        response = await self.app.api_council_manual_review(request({"goal_id": "goal1", "totp": ""}, method="POST"))
        self.assertTrue(payload(response)["ok"])
        self.autonomy.release_manual_barrier.assert_called_once_with("inc1", "goal1", actor="operator")
        self.assertIn("重新审议", payload(response)["message"])
        self.assertEqual([call[0] for call in self.autonomy.method_calls], ["release_manual_barrier"])

    async def test_manual_review_rejects_missing_goal_or_execution_fields(self):
        for body in ({}, {"goal_id": ""}, {"goal_id": "goal1", "execute": True}, {"goal_id": "goal1", "approve": True}):
            self.assertEqual((await self.app.api_council_manual_review(request(body, method="POST"))).status, 400)
        self.autonomy.release_manual_barrier.assert_not_called()

    async def test_manual_conflicts_do_not_report_success(self):
        self.autonomy.release_manual_barrier.side_effect = ValueError("old generation")
        self.assertEqual((await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST"))).status, 409)
        self.autonomy.release_manual_barrier.side_effect = None
        self.autonomy.release_manual_barrier.return_value = {"ok": False}
        self.assertEqual((await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST"))).status, 409)

    async def test_optional_ai_failure_does_not_break_existing_incident_detail(self):
        self.app._incident_human_summary = Mock(return_value={"title": "frps"})
        self.app._incident_disposition = Mock(return_value={})
        self.autonomy.snapshot.side_effect = RuntimeError("offline")
        response = await self.app.api_incident_detail(request())
        self.assertEqual(response.status, 200)
        self.assertEqual(payload(response)["council"]["status"], "unavailable")
        self.assertEqual(payload(response)["incident"]["id"], "inc1")

    async def test_async_snapshot_is_supported(self):
        self.autonomy.snapshot = AsyncMock(return_value={"phase": "investigating"})
        self.assertEqual(payload(await self.app.api_incident_council(request()))["council"]["phase"], "investigating")

    def test_reviewed_actions_do_not_become_manual_approval_proposals(self):
        self.app.policy.effective_decision.return_value = {"allowed": False}
        disposition = self.app._incident_disposition({"actions": [
            {"id": "a1", "mode": "reviewed", "state": "proposed", "council_grant_id": "g1"},
            {"id": "a2", "mode": "reviewed", "state": "approved", "council_grant_id": "g1"},
        ]})
        self.assertEqual(disposition["proposals"], [])

    async def test_unconfigured_ai_is_disabled_not_a_fake_success(self):
        self.app.autonomy = None
        self.app.providers = None
        self.assertFalse(payload(await self.app.api_incident_council(request()))["council"]["enabled"])
        self.assertFalse(payload(await self.app.api_autonomy_providers(request()))["available"])
        self.assertIsNone(payload(await self.app.api_autonomy_usage(request()))["usage"]["cost_cny"])
        self.assertEqual((await self.app.api_autonomy_providers_save(request({}, method="POST"))).status, 503)

    async def test_account_verification_requires_admin_csrf_totp_and_exact_role(self):
        self.providers.verify_account = AsyncMock(return_value={"ok": True, "role": "reviewer_kimi"})
        self.session["is_admin"] = False
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_autonomy_provider_verify(request({"role": "reviewer_kimi"}, method="POST"))
        self.session["is_admin"] = True
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_autonomy_provider_verify(request({"role": "reviewer_kimi"}, method="POST", csrf=""))
        for body in ({"role": "random"}, {"role": []}, {"role": {}}, {"role": "reviewer_kimi", "api_key": "forged"}):
            self.assertEqual((await self.app.api_autonomy_provider_verify(request(body, method="POST"))).status, 400)
        self.auth.totp_enabled.return_value = True
        self.assertEqual((await self.app.api_autonomy_provider_verify(request({"role": "reviewer_kimi"}, method="POST"))).status, 403)
        self.providers.verify_account.assert_not_called()

    async def test_account_verification_failure_does_not_claim_support(self):
        self.providers.verify_account = AsyncMock(return_value={"ok": False, "error": "model_not_available", "models": ["other"]})
        response = await self.app.api_autonomy_provider_verify(request({"role": "reviewer_kimi"}, method="POST"))
        self.assertEqual(response.status, 400)
        self.assertFalse(payload(response)["ok"])
        self.assertEqual(payload(response)["error"], "model_not_available")
        self.providers.verify_account.assert_awaited_once_with("reviewer_kimi")

    async def test_account_verification_success_is_bound_to_one_saved_role(self):
        self.providers.verify_account = AsyncMock(return_value={"ok": True, "role": "reviewer_deepseek", "models": ["real-model"]})
        response = await self.app.api_autonomy_provider_verify(request({"role": "reviewer_deepseek", "totp": ""}, method="POST"))
        self.assertEqual(response.status, 200)
        self.assertTrue(payload(response)["ok"])
        self.providers.verify_account.assert_awaited_once_with("reviewer_deepseek")
        self.providers.update_config.assert_not_called()

    async def test_court_manual_conflict_preserves_deterministic_error_code(self):
        from ayana.council import CouncilError
        self.autonomy.release_manual_barrier.side_effect = CouncilError("goal_generation_stale")
        response = await self.app.api_council_manual_review(request({"goal_id": "goal1"}, method="POST"))
        self.assertEqual(response.status, 409)
        self.assertEqual(payload(response)["error"], "goal_generation_stale")

    def test_manual_notice_contains_three_round_vetoes_and_requires_new_reviews(self):
        rounds = [{"version": index, "plan": {"rationale": "证据"}, "reviews": [{"provider": "kimi", "approve": False, "reason": "缺少日志"}]} for index in range(1, 5)]
        notice = fmt_council_notice({"id": "inc1", "generation": 2, "asset_id": "nerv"}, "manual_required", rounds=rounds)
        self.assertNotIn("方案 v1", notice)
        self.assertIn("方案 v4", notice)
        self.assertEqual(notice.count("封驳: 缺少日志"), 3)
        self.assertIn("重新拟案仍须双委员审议", notice)


if __name__ == "__main__":
    unittest.main()
