"""Provider transport, encrypted settings, budget and restart fault injection."""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from aiohttp import web
from aiohttp.test_utils import TestServer

from ayana.ai_providers import ProviderError, ProviderRegistry, ROLES
from ayana.db import Database
from ayana.llm import LLMClient, PublicAPIResolver, make_llm


class ProviderTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "ai.db")
        self.requests = []
        self.response = {"choices": [{"message": {"content": '{"approve":true}'}, "finish_reason": "stop"}],
                         "usage": {"prompt_tokens": 100, "completion_tokens": 50}}
        self.status = 200
        self.delay = 0
        self.redirect = False
        self.on_request = None
        async def handler(request):
            self.requests.append({"body": await request.json(), "auth": request.headers.get("Authorization")})
            if self.on_request:
                self.on_request()
            if self.redirect:
                raise web.HTTPTemporaryRedirect(location="/stolen-key")
            if self.delay:
                await asyncio.sleep(self.delay)
            return web.json_response(self.response, status=self.status)
        app = web.Application()
        app.router.add_post("/v1/chat/completions", handler)
        async def models_handler(request):
            self.requests.append({"path": "/models", "auth": request.headers.get("Authorization")})
            return web.json_response({"data": [{"id": "kimi-k2.6"}, {"id": "mimo-v2.6-pro"}]}, status=self.status)
        app.router.add_get("/v1/models", models_handler)
        async def stolen_handler(request):
            self.requests.append({"path": "stolen-key", "auth": request.headers.get("Authorization")})
            return web.json_response(self.response)
        app.router.add_post("/stolen-key", stolen_handler)
        self.server = TestServer(app)
        await self.server.start_server()
        self.cfg = {"ai_credential_key": "unit-test-encryption-key", "llm_api_key": "OLD-TOKEN-PLAN",
                    "llm_base_url": "https://old.invalid/v1",
                    "autonomous_agent": {"enabled": True, "roles": {role: {
                        "base_url": str(self.server.make_url("/v1")), "timeout": 1,
                        "input_cny_per_million": 2, "output_cny_per_million": 8,
                    } for role in ROLES}}}
        self.registry = ProviderRegistry(self.db, self.cfg, client_factory=LLMClient)
        self.registry.update_config({"roles": {role: {"api_key": "new-" + role} for role in ROLES}})

    async def asyncTearDown(self):
        await self.server.close()
        self.db.close()
        self.tmp.cleanup()

    async def call(self, role="planner", **kwargs):
        return await self.registry.call_json(role, [{"role": "user", "content": "请返回 JSON"}], incident_id="inc-a", **kwargs)

    async def test_independent_keys_usage_cost_and_no_old_plan_reuse(self):
        results = await asyncio.gather(*(self.call(role) for role in ROLES))
        self.assertTrue(all(r["ok"] for r in results))
        self.assertEqual({r["auth"] for r in self.requests}, {"Bearer new-" + role for role in ROLES})
        self.assertTrue(all(r["usage"] == {"input_tokens": 100, "output_tokens": 50} for r in results))
        self.assertAlmostEqual(results[0]["cost_cny"], 0.0006)
        self.assertIsNone(results[0]["account_charge_cny"])
        summary = self.registry.usage_summary("inc-a")
        self.assertEqual(summary["overall"]["calls"], 3)
        self.assertAlmostEqual(summary["overall"]["cost_cny"], 0.0018)
        self.assertEqual(summary["overall"]["reserved_cny"], 0)
        self.assertEqual(set(summary["by_role"]), set(ROLES))

    async def test_encrypted_keys_not_in_config_audit_or_public(self):
        public = json.dumps(self.registry.public_config())
        audit = json.dumps([dict(r) for r in self.db.query("SELECT * FROM audit_log")])
        config = self.db.query_one("SELECT value_json FROM ai_provider_config")["value_json"]
        for role in ROLES:
            self.assertNotIn("new-" + role, public + audit + config)
            encrypted = self.db.query_one("SELECT secret_enc FROM ai_provider_keys WHERE role=?", (role,))["secret_enc"]
            self.assertNotIn(("new-" + role).encode(), encrypted)
        restarted = ProviderRegistry(self.db, self.cfg, client_factory=LLMClient)
        self.assertEqual(restarted.client("reviewer_kimi").api_key, "new-reviewer_kimi")

    async def test_clear_key_masks_environment_instead_of_falling_back(self):
        self.cfg["ai_planner_api_key"] = "ENV-SHOULD-NOT-REAPPEAR"
        self.registry.update_config({"roles": {"planner": {"clear_api_key": True}}})
        self.assertFalse(self.registry.public_config()["roles"]["planner"]["key_configured"])
        result = await self.call()
        self.assertEqual(result["error"], "provider_unconfigured")
        self.assertEqual(self.requests, [])

    async def test_unknown_prices_block_instead_of_zero_cost(self):
        self.registry.update_config({"roles": {"planner": {"input_cny_per_million": None}}})
        result = await self.call()
        self.assertEqual(result["error"], "price_unknown")
        self.assertEqual(self.requests, [])

    async def test_old_analysis_client_remains_independent(self):
        self.registry.update_config({"enabled": False})
        self.assertEqual((await self.call())["error"], "agent_disabled")
        old = make_llm(self.cfg)
        self.assertTrue(old.enabled)
        self.assertEqual(old.api_key, "OLD-TOKEN-PLAN")

    async def test_simultaneous_reservations_cannot_exceed_budget(self):
        self.delay = .04
        self.registry.update_config({"budget_cny": .025, "roles": {role: {
            "input_cny_per_million": 10, "output_cny_per_million": 10,
        } for role in ROLES}})
        results = await asyncio.gather(*(self.call(role) for role in ROLES))
        self.assertEqual(sum(r["ok"] for r in results), 1)
        self.assertEqual(sum(r["error"] == "budget_exhausted" for r in results), 2)
        self.assertEqual(len(self.requests), 1)

    async def test_timeout_retains_budget_hold_and_records_reason(self):
        self.delay = .04
        self.registry.update_config({"roles": {"planner": {"timeout": .01}}})
        result = await self.call()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "llm_timeout")
        row = self.db.query_one("SELECT * FROM ai_calls")
        self.assertEqual(row["status"], "usage_unknown")
        self.assertIsNone(row["cost_cny"])
        self.assertGreater(row["reserved_cny"], 0)
        self.assertFalse(self.registry.usage_summary()["overall"]["complete"])

    async def test_missing_usage_is_not_reported_as_zero_charges(self):
        del self.response["usage"]
        result = await self.call()
        self.assertTrue(result["ok"])
        self.assertIsNone(result["cost_cny"])
        self.assertIsNone(result["usage"])
        self.assertGreater(self.registry.usage_summary()["overall"]["reserved_cny"], 0)

    async def test_retry_gets_separate_paid_reservation(self):
        self.status = 500
        self.registry.update_config({"roles": {"planner": {"retries": 1}}})
        result = await self.call()
        self.assertFalse(result["ok"])
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.registry.usage_summary()["overall"]["calls"], 2)
        self.assertEqual(self.registry.usage_summary()["overall"]["unknown_usage_calls"], 2)

    async def test_disabling_during_failed_request_stops_retries(self):
        self.status = 500
        self.registry.update_config({"roles": {"planner": {"retries": 2}}})
        self.on_request = lambda: self.registry.update_config({"enabled": False})
        result = await self.call()
        self.assertEqual(result["error"], "agent_disabled")
        self.assertFalse(result["ok"])
        self.assertEqual(len(self.requests), 1)
        self.assertGreater(self.registry.usage_summary()["overall"]["reserved_cny"], 0)

    async def test_disabling_during_success_keeps_usage_but_discards_result(self):
        self.on_request = lambda: self.registry.update_config({"enabled": False})
        result = await self.call()
        self.assertEqual(result["error"], "agent_disabled")
        self.assertIsNone(result["data"])
        self.assertAlmostEqual(result["cost_cny"], .0006)
        self.assertEqual(self.registry.usage_summary()["overall"]["input_tokens"], 100)

    async def test_key_rotation_during_failed_request_does_not_retry_old_key(self):
        self.status = 500
        self.registry.update_config({"roles": {"planner": {"retries": 2}}})
        self.on_request = lambda: self.registry.update_config({"roles": {"planner": {"api_key": "rotated-fake-key"}}})
        result = await self.call()
        self.assertEqual(result["error"], "provider_configuration_changed")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.registry.client("planner").api_key, "rotated-fake-key")

    async def test_model_switch_during_success_discards_stale_model_result(self):
        self.on_request = lambda: self.registry.update_config({"roles": {"planner": {"model": "replacement-model"}}})
        result = await self.call()
        self.assertEqual(result["error"], "provider_configuration_changed")
        self.assertFalse(result["ok"])
        self.assertIsNone(result["data"])
        self.assertAlmostEqual(result["cost_cny"], .0006)

    async def test_loop_breaker_covers_retries_and_generation_limits(self):
        self.registry.update_config({"max_calls_per_generation": 1})
        self.assertTrue((await self.call())["ok"])
        self.assertEqual((await self.call())["error"], "call_limit_exhausted")
        self.assertTrue((await self.call(generation=2))["ok"])
        self.registry.update_config({"max_calls_per_incident": 2})
        self.assertEqual((await self.call(generation=3))["error"], "call_limit_exhausted")

    async def test_malformed_json_duplicate_keys_nan_array_and_truncation_fail_closed(self):
        for content in ('```json\n{}\n```', '{"approve":true,"approve":false}', '{"n":NaN}', '[]'):
            self.response["choices"][0]["message"]["content"] = content
            result = await self.call()
            self.assertFalse(result["ok"], content)
            self.assertEqual(result["error"], "llm_invalid_json")
            self.assertIn("category", result["format_error"])
            self.assertIsNotNone(result["cost_cny"])
        self.response["choices"][0]["message"]["content"] = '{}'
        self.response["choices"][0]["finish_reason"] = "length"
        self.assertEqual((await self.call())["error"], "llm_incomplete")

    async def test_json_contract_is_included_without_mutating_callers_messages(self):
        messages = [{"role": "system", "content": "Review this plan"}, {"role": "user", "content": "synthetic"}]
        before = json.loads(json.dumps(messages))
        self.assertTrue((await self.registry.call_json("planner", messages, incident_id="inc-a"))["ok"])
        self.assertEqual(messages, before)
        system = self.requests[0]["body"]["messages"][0]["content"]
        self.assertIn("No Markdown fences", system)
        self.assertIn("duplicate property names", system)

    async def test_restart_marks_unknown_and_never_replays(self):
        self.registry._reserve("planner", "inc-a", 1, self.registry._settings["roles"]["planner"], 100, 100, "test")
        restarted = ProviderRegistry(self.db, self.cfg, client_factory=LLMClient)
        self.assertEqual(restarted.recover_inflight(), 1)
        self.assertEqual(restarted.recover_inflight(), 0)
        summary = restarted.usage_summary()
        self.assertEqual(summary["calls"][0]["status"], "interrupted_usage_unknown")
        self.assertGreater(summary["overall"]["reserved_cny"], 0)
        self.assertEqual(self.requests, [])

    async def test_cancellation_records_uncertain_cost(self):
        self.delay = .1
        task = asyncio.create_task(self.call())
        await asyncio.sleep(.01)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.registry.usage_summary()["calls"][0]["error"], "call_cancelled")
        self.assertGreater(self.registry.usage_summary()["overall"]["reserved_cny"], 0)

    async def test_runtime_validation_is_atomic_and_forbids_secret_in_url(self):
        for patch in ({"roles": {"reviewer_kimi": {"provider": "deepseek"}}},
                      {"roles": {"planner": {"base_url": "https://key-secret@example.com/v1"}}},
                      {"roles": {"planner": {"timeout": float("nan")}}},
                      {"budget_cny": -1}, {"enabled": "true"}, {"arbitrary": True}):
            with self.assertRaises(ProviderError):
                self.registry.update_config(patch)
        self.assertEqual(self.registry.public_config()["budget_cny"], 100)

    async def test_duplicate_reviewer_endpoint_and_model_are_rejected(self):
        with self.assertRaisesRegex(ProviderError, "independent_reviewer_required"):
            self.registry.update_config({"roles": {"reviewer_deepseek": {
                "base_url": self.registry.public_config()["roles"]["reviewer_kimi"]["base_url"] + "/",
                "model": "KIMI-K2.6",
            }}})
        self.assertEqual(self.registry.public_config()["roles"]["reviewer_deepseek"]["model"], "deepseek-v4-pro")

    async def test_new_role_keys_absent_does_not_reuse_old_llm_secret(self):
        empty_db = Database(Path(self.tmp.name) / "empty.db")
        try:
            registry = ProviderRegistry(empty_db, self.cfg, client_factory=LLMClient)
            result = await registry.call_json("planner", [{"role": "user", "content": "json"}], incident_id="inc-a")
            self.assertEqual(result["error"], "provider_unconfigured")
            self.assertEqual(self.requests, [])
        finally:
            empty_db.close()

    async def test_account_model_discovery_is_read_only_and_bound_to_key_url_model(self):
        self.assertFalse(self.registry.public_config()["roles"]["reviewer_kimi"]["account_verified"])
        result = await self.registry.verify_account("reviewer_kimi")
        self.assertTrue(result["ok"])
        self.assertTrue(self.registry.public_config()["roles"]["reviewer_kimi"]["account_verified"])
        self.assertEqual(self.registry.usage_summary()["overall"]["calls"], 0)
        self.registry.update_config({"roles": {"reviewer_kimi": {"api_key": "replacement-test-key"}}})
        self.assertFalse(self.registry.public_config()["roles"]["reviewer_kimi"]["account_verified"])
        self.registry.update_config({"roles": {"reviewer_kimi": {"model": "absent-model"}}})
        self.assertEqual((await self.registry.verify_account("reviewer_kimi"))["error"], "model_not_available")

    async def test_successful_completion_supersedes_old_models_failure(self):
        self.status = 500
        self.assertFalse((await self.registry.verify_account("reviewer_kimi"))["ok"])
        self.status = 200
        self.assertTrue((await self.call("reviewer_kimi"))["ok"])
        conf = self.registry.public_config()["roles"]["reviewer_kimi"]
        self.assertTrue(conf["account_verified"])
        self.assertEqual(conf["verification_error"], "")

    async def test_revoked_key_response_invalidates_old_account_verification(self):
        self.assertTrue((await self.registry.verify_account("reviewer_kimi"))["ok"])
        self.status = 401
        self.assertEqual((await self.call("reviewer_kimi"))["error"], "llm_http_error")
        conf = self.registry.public_config()["roles"]["reviewer_kimi"]
        self.assertFalse(conf["account_verified"])
        self.assertEqual(conf["verification_error"], "llm_http_error")

    async def test_production_registry_rejects_local_http_private_metadata_and_credentials(self):
        empty_db = Database(Path(self.tmp.name) / "production.db")
        try:
            registry = ProviderRegistry(empty_db, {})
            for endpoint in ("http://127.0.0.1/v1", "https://127.0.0.1/v1", "https://10.0.0.1/v1", "https://169.254.169.254/v1", "https://metadata.google.internal/v1", "https://api.deepseek.com/?key=oops"):
                with self.assertRaises(ProviderError, msg=endpoint):
                    registry.update_config({"roles": {"planner": {"base_url": endpoint}}})
            client = registry.client("planner")
            self.assertTrue(client.secure_network)
        finally:
            empty_db.close()

    async def test_secure_provider_does_not_forward_key_on_redirect(self):
        self.redirect = True
        client = LLMClient("fake-sensitive-key", str(self.server.make_url("/v1")), "test", secure_network=True)
        # Override only endpoint/connector checks to use the local test server;
        # exercise the real redirect behavior of the secure HTTP request.
        client._endpoint_allowed = lambda: True
        client._connector = lambda: None
        result = await client.chat_raw([{"role": "user", "content": "json"}])
        self.assertEqual(result["status"], 307)
        self.assertEqual(len(self.requests), 1)
        self.assertFalse(any(row.get("path") == "stolen-key" for row in self.requests))

    async def test_dns_rebinding_to_private_ip_is_blocked_before_connection(self):
        resolver = PublicAPIResolver()
        try:
            with patch("ayana.llm.DefaultResolver.resolve", new=AsyncMock(return_value=[{"host": "10.0.0.7"}])):
                with self.assertRaises(OSError):
                    await resolver.resolve("apparently-public.example", 443)
            with patch("ayana.llm.DefaultResolver.resolve", new=AsyncMock(return_value=[{"host": "169.254.169.254"}])):
                with self.assertRaises(OSError):
                    await resolver.resolve("apparently-public.example", 443)
        finally:
            await resolver.close()


if __name__ == "__main__":
    unittest.main()
