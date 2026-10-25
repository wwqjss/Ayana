"""P4.4 migrations of all 32 old-engine scenarios: retirement always wins.

Original scenario names remain for traceability. Old execution-positive cases
now require rejection even with forged approvals, permissive policy and mutable
legacy flags. Shared Action/transport/model safety remains asserted separately.
"""
from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, Mock

from ayana.autonomy import AutonomyEngine
from ayana.legacy_history import RetiredAutonomyError


class AutonomyEngineTests(unittest.IsolatedAsyncioTestCase):
    async def assert_retired(self, scenario):
        services = {name: Mock(name=name) for name in (
            "db", "investigation", "actions", "policy", "providers", "council", "notifier", "transport",
        )}
        services["actions"].execute = AsyncMock()
        services["transport"].exec = AsyncMock()
        services["providers"].call_json = AsyncMock()
        services["providers"].public_config.return_value = {"enabled": True}
        with self.assertRaises(RetiredAutonomyError) as cm:
            AutonomyEngine(
                services["db"], services["investigation"], services["actions"], services["policy"],
                services["providers"], services["council"], services["notifier"],
                runbook_auto_enabled=lambda: True,
            )
        self.assertEqual(cm.exception.code, "legacy_autonomy_retired")
        self.assertNotIn("sensitive-test-value", str(cm.exception))
        # An object restored/built without __init__ cannot restore execution.
        engine = object.__new__(AutonomyEngine)
        engine.__dict__.update(services)
        engine.__dict__.update(scenario=scenario, enabled=True, writes_enabled=True,
                               runbook_auto_enabled=lambda: True)
        with self.assertRaises(RetiredAutonomyError):
            await engine.tick("inc1", scenario=scenario)
        for method, args in (
            ("poll_verifications", ()), ("recover_inflight", ()),
            ("ready_incident_ids", ()), ("snapshot", ("inc1",)),
            ("release_manual_barrier", ("inc1", "goal1")),
        ):
            with self.subTest(entry=method), self.assertRaises(RetiredAutonomyError):
                getattr(engine, method)(*args)
        for name, service in services.items():
            self.assertEqual(service.mock_calls, [], name + " must not be used after retirement")

    async def test_watching_incident_two_independent_parallel_approvals_dispatch_once(self):
        await self.assert_retired({'phase': 'watching', 'reviewers': ['approve', 'approve'], 'grant': 'valid'})

    async def test_full_immutable_plan_is_not_truncated_after_hashing(self):
        await self.assert_retired({'plan': {'steps': [{'capability': 'service.restart', 'params': {'payload': 'x' * 10000}}]}})

    async def test_one_and_two_vetoes_do_not_execute(self):
        await self.assert_retired({'reviewers': ['approve', 'veto']})

    async def test_three_veto_rounds_hold_writes_but_keep_read_investigation(self):
        await self.assert_retired({'veto_rounds': 3, 'read_investigation': True})

    async def test_reviewer_exception_is_closed_as_failed_not_pending(self):
        await self.assert_retired({'reviewers': ['exception', 'approve']})

    async def test_legal_maximum_timeout_creates_both_tickets(self):
        await self.assert_retired({'timeout': 300, 'reviewers': ['approve', 'approve']})

    async def test_background_verification_poll_does_not_overwrite_running_tick_context(self):
        await self.assert_retired({'phase': 'reviewing', 'verification': 'passed', 'active_tick': True})

    async def test_completed_multi_step_strategy_is_not_sent_for_duplicate_review(self):
        await self.assert_retired({'completed_steps': [0, 1], 'reviewers': ['approve', 'approve']})

    async def test_cooldown_blocks_only_restart_and_allows_different_reviewed_repair(self):
        await self.assert_retired({'cooldown': True, 'capability': 'service.reset_failed'})

    async def test_rule_without_satisfied_preconditions_cannot_monopolize_incident(self):
        await self.assert_retired({'runbook_match': True, 'preconditions': 'unknown'})

    async def test_restart_failure_returns_evidence_then_tries_different_strategy(self):
        await self.assert_retired({'prior_failure': 'restart', 'next_strategy': 'reset_failed'})

    async def test_same_failed_strategy_is_not_replayed(self):
        await self.assert_retired({'failed_signatures': ['same-plan'], 'plan': 'same-plan'})

    async def test_verification_failure_returns_to_planner_with_new_evidence(self):
        await self.assert_retired({'verification': 'failed', 'evidence': ['fresh-failure']})

    async def test_passed_verification_is_reported_not_business_recovery_and_reads_continue(self):
        await self.assert_retired({'verification': 'passed', 'business_recovered': False})

    async def test_recovery_during_planning_never_creates_or_executes_old_plan(self):
        await self.assert_retired({'planning_transition': 'resolved'})

    async def test_recovery_during_review_never_dispatches(self):
        await self.assert_retired({'review_transition': 'resolved'})

    async def test_disable_autonomy_or_auto_during_review_prevents_execution(self):
        await self.assert_retired({'provider_enabled': False, 'auto_enabled': False})

    async def test_human_request_persists_backend_barrier_until_admin_releases(self):
        await self.assert_retired({'human_required': True, 'admin_release': True})

    async def test_explicit_rejection_allows_reads_but_no_new_votes_or_writes(self):
        await self.assert_retired({'explicit_rejection': True, 'read_allowed': True})

    async def test_unknown_write_is_not_replayed_and_reads_remain_available(self):
        await self.assert_retired({'write_state': 'unknown', 'retry_requested': True})

    async def test_agent_can_choose_further_read_but_never_write_as_read_tool(self):
        await self.assert_retired({'read_tool': {'capability': 'service.restart', 'channel': 'read'}})

    async def test_unregistered_read_target_is_rejected(self):
        await self.assert_retired({'read_tool': {'asset_id': 'unregistered'}})

    async def test_malformed_plans_are_rejected_without_unhandled_type_errors(self):
        await self.assert_retired({'plan': [None, {'steps': 'malformed'}]})

    async def test_restart_interrupts_votes_and_never_replays_claimed_write(self):
        await self.assert_retired({'restart': True, 'pending_review': True, 'write_state': 'claimed'})

    async def test_duplicate_workers_lease_incident_and_do_not_duplicate_execution(self):
        await self.assert_retired({'duplicate_workers': 2, 'same_incident': 'inc1'})

    async def test_recurrence_new_generation_gets_new_investigation_and_plan(self):
        await self.assert_retired({'generation': 2, 'previous_generation': 1})

    async def test_provider_outage_and_budget_do_not_dispatch_or_mutate_existing_auto_switch(self):
        await self.assert_retired({'provider_outage': True, 'budget_remaining': 0, 'auto_enabled': True})

    async def test_disabled_by_default_engine_does_not_affect_monitoring_or_actions(self):
        await self.assert_retired({'enabled': False, 'manual_actions_available': True})

    async def test_permission_required_uses_manual_adjudication_instead_of_retry_loop(self):
        await self.assert_retired({'permission': 'confirm', 'manual_adjudication': True})

    async def test_legacy_runbook_path_delegates_without_spurious_human_obligation(self):
        await self.assert_retired({'legacy_runbook': True, 'preconditions': 'satisfied'})

    async def test_evidence_masks_credential_flags_and_private_key_blocks(self):
        await self.assert_retired({'evidence': '--token sensitive-test-value -----BEGIN PRIVATE KEY-----'})

    async def test_strategy_signature_ignores_plan_compilation_fields_and_step_order(self):
        await self.assert_retired({'same_strategy_different_order': True, 'reviewers': ['approve', 'approve']})


if __name__ == "__main__":
    unittest.main()
