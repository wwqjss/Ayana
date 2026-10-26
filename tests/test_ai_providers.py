"""Retired provider entry points: all former paid workflows are unreachable.

The original 27 scenarios remain covered as permanent-denial cases. Shared
HTTP/redirect/DNS protections also run directly against LLMClient in test_llm.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from ayana.ai_providers import ProviderError, ProviderRegistry, ROLES
from ayana.db import Database
from ayana.legacy_history import RetiredAutonomyError
from ayana.llm import make_llm


class ProviderTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=Database(Path(self.tmp.name)/"ai.db")
        self.addCleanup(self.db.close)
        # Existing encrypted/provider state is historical, not a source of authority.
        self.db.execute("CREATE TABLE ai_provider_keys(role TEXT PRIMARY KEY,ciphertext TEXT)")
        self.db.execute("INSERT INTO ai_provider_keys VALUES('planner','opaque-historical-value')")
        self.cfg={"ai_credential_key":"test-only","llm_api_key":"OLD-TEST","llm_base_url":"https://analysis.example.test/v1","llm_model":"analysis","autonomous_agent":{"enabled":True,"budget_cny":100,"roles":{role:{"api_key":"test-only"} for role in ROLES}}}

    async def denied(self, scenario, patch_config=None, method="call_json"):
        if patch_config:
            self.cfg["autonomous_agent"].update(patch_config)
        before="\n".join(self.db._connect().iterdump())
        changes=self.db._connect().total_changes
        model=AsyncMock(side_effect=AssertionError("retired provider reached network"))
        with patch("ayana.llm.LLMClient.chat_raw",model), patch("ayana.llm.LLMClient.models",create=True,new=AsyncMock()) as discovery:
            with self.assertRaises(RetiredAutonomyError,msg=scenario) as error:
                ProviderRegistry(self.db,self.cfg)
            self.assertEqual(error.exception.code,"legacy_autonomy_retired")
            # Bypassing construction cannot recover a paid/configuration capability.
            retired=ProviderRegistry.__new__(ProviderRegistry)
            retired.db=self.db
            retired.cfg=self.cfg
            with self.assertRaises(RetiredAutonomyError,msg=scenario):
                if method in {"call_json","verify_account"}:
                    await getattr(retired,method)("planner",incident_id="inc-a")
                else:
                    getattr(retired,method)({"enabled":True})
            model.assert_not_awaited()
            discovery.assert_not_awaited()
        self.assertEqual("\n".join(self.db._connect().iterdump()),before,scenario)
        self.assertEqual(self.db._connect().total_changes,changes)
        self.assertEqual(self.db.schema_version(), 22)
        self.assertEqual(self.db.query_one("SELECT ciphertext FROM ai_provider_keys")["ciphertext"],"opaque-historical-value")
        self.assertNotIn("test-only",str(error.exception))

    async def test_independent_keys_usage_cost_and_no_old_plan_reuse(self):
        await self.denied('test_independent_keys_usage_cost_and_no_old_plan_reuse', {}, method='call_json')

    async def test_encrypted_keys_not_in_config_audit_or_public(self):
        await self.denied('test_encrypted_keys_not_in_config_audit_or_public', {}, method='public_config')

    async def test_clear_key_masks_environment_instead_of_falling_back(self):
        await self.denied('test_clear_key_masks_environment_instead_of_falling_back', {}, method='update_config')

    async def test_unknown_prices_block_instead_of_zero_cost(self):
        await self.denied('test_unknown_prices_block_instead_of_zero_cost', {"roles":{"planner":{"input_cny_per_million":None}}}, method='call_json')

    async def test_old_analysis_client_remains_independent(self):
        await self.denied("old analysis is separate", {"enabled":False})
        client=make_llm(self.cfg)
        self.assertTrue(client.enabled)
        self.assertEqual(client.api_key,"OLD-TEST")
        self.assertEqual(client.model,"analysis")

    async def test_simultaneous_reservations_cannot_exceed_budget(self):
        await self.denied('test_simultaneous_reservations_cannot_exceed_budget', {"budget_cny":0.000001}, method='call_json')

    async def test_timeout_retains_budget_hold_and_records_reason(self):
        await self.denied('test_timeout_retains_budget_hold_and_records_reason', {}, method='call_json')

    async def test_missing_usage_is_not_reported_as_zero_charges(self):
        await self.denied('test_missing_usage_is_not_reported_as_zero_charges', {}, method='call_json')

    async def test_retry_gets_separate_paid_reservation(self):
        await self.denied('test_retry_gets_separate_paid_reservation', {}, method='call_json')

    async def test_disabling_during_failed_request_stops_retries(self):
        await self.denied('test_disabling_during_failed_request_stops_retries', {"enabled":False}, method='update_config')

    async def test_disabling_during_success_keeps_usage_but_discards_result(self):
        await self.denied('test_disabling_during_success_keeps_usage_but_discards_result', {"enabled":False}, method='update_config')

    async def test_key_rotation_during_failed_request_does_not_retry_old_key(self):
        await self.denied('test_key_rotation_during_failed_request_does_not_retry_old_key', {"roles":{"planner":{"api_key":"rotated-test"}}}, method='update_config')

    async def test_model_switch_during_success_discards_stale_model_result(self):
        await self.denied('test_model_switch_during_success_discards_stale_model_result', {"roles":{"planner":{"model":"changed-test"}}}, method='call_json')

    async def test_loop_breaker_covers_retries_and_generation_limits(self):
        await self.denied('test_loop_breaker_covers_retries_and_generation_limits', {"max_calls":0,"budget_cny":0}, method='call_json')

    async def test_malformed_json_duplicate_keys_nan_array_and_truncation_fail_closed(self):
        await self.denied('test_malformed_json_duplicate_keys_nan_array_and_truncation_fail_closed', {}, method='call_json')

    async def test_json_contract_is_included_without_mutating_callers_messages(self):
        await self.denied('test_json_contract_is_included_without_mutating_callers_messages', {}, method='call_json')

    async def test_restart_marks_unknown_and_never_replays(self):
        await self.denied('test_restart_marks_unknown_and_never_replays', {}, method='recover_inflight')

    async def test_cancellation_records_uncertain_cost(self):
        await self.denied('test_cancellation_records_uncertain_cost', {}, method='call_json')

    async def test_runtime_validation_is_atomic_and_forbids_secret_in_url(self):
        await self.denied('test_runtime_validation_is_atomic_and_forbids_secret_in_url', {"roles":{"planner":{"base_url":"https://example.test/?key=test"}}}, method='update_config')

    async def test_duplicate_reviewer_endpoint_and_model_are_rejected(self):
        await self.denied('test_duplicate_reviewer_endpoint_and_model_are_rejected', {"roles":{"reviewer_kimi":{"model":"same"},"reviewer_deepseek":{"model":"same"}}}, method='update_config')

    async def test_new_role_keys_absent_does_not_reuse_old_llm_secret(self):
        await self.denied('test_new_role_keys_absent_does_not_reuse_old_llm_secret', {"roles":{}}, method='client')

    async def test_account_model_discovery_is_read_only_and_bound_to_key_url_model(self):
        await self.denied('test_account_model_discovery_is_read_only_and_bound_to_key_url_model', {}, method='verify_account')

    async def test_successful_completion_supersedes_old_models_failure(self):
        await self.denied('test_successful_completion_supersedes_old_models_failure', {}, method='call_json')

    async def test_revoked_key_response_invalidates_old_account_verification(self):
        await self.denied('test_revoked_key_response_invalidates_old_account_verification', {}, method='verify_account')

    async def test_production_registry_rejects_local_http_private_metadata_and_credentials(self):
        await self.denied('test_production_registry_rejects_local_http_private_metadata_and_credentials', {"roles":{"planner":{"base_url":"http://127.0.0.1/v1"}}}, method='client')

    async def test_secure_provider_does_not_forward_key_on_redirect(self):
        await self.denied('test_secure_provider_does_not_forward_key_on_redirect', {"roles":{"planner":{"base_url":"https://redirect.example.test/v1"}}}, method='call_json')

    async def test_dns_rebinding_to_private_ip_is_blocked_before_connection(self):
        await self.denied('test_dns_rebinding_to_private_ip_is_blocked_before_connection', {"roles":{"planner":{"base_url":"https://169.254.169.254/v1"}}}, method='call_json')


if __name__ == "__main__":
    unittest.main()
