"""End-to-end orchestration with real Policy/Investigation/Action/Council.

Only the model responses and SSH/Prometheus boundary are simulated. No network
credentials, real machines, or production message channels are used here.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from ayana.autonomy import AutonomyEngine, _signature, redact
from ayana.agent import AgentLoop
from ayana.db import now
from ayana.incidents import IncidentService
from ayana.investigation import InvestigationService
from ayana.ntsafe import NTResult
from ayana.runbook import apply_runbook_rules
from tests import test_council_security as fixture


class Models:
    def __init__(self):
        self.enabled = True
        self.calls = []
        self.steps = [{"capability": "service.restart", "params": {}}]
        self.decision = "plan"
        self.opinions = {"reviewer_kimi": True, "reviewer_deepseek": True}
        self.errors = {}
        self.on_call = None
        self.next_tools = []
        self.concurrent = False
        self.timeout = 1
        self.retries = 0
        self.reviewers_started = set()
        self.both_started = asyncio.Event()

    def public_config(self):
        return {"enabled": self.enabled, "roles": {
            "reviewer_kimi": {"provider": "kimi", "model": "account-kimi", "timeout": self.timeout, "retries":self.retries},
            "reviewer_deepseek": {"provider": "deepseek", "model": "account-deepseek", "timeout": self.timeout, "retries":self.retries}}}

    def usage_summary(self, incident_id=None):
        return {"overall": {"calls": len(self.calls), "cost_cny": None}, "budget": {"total_cny": 100}}

    def recover_inflight(self):
        return 0

    async def call_json(self, role, messages, **kwargs):
        self.calls.append({"role": role, "messages": messages, **kwargs})
        if self.on_call:
            self.on_call(role)
        if role in self.errors:
            if isinstance(self.errors[role], Exception):
                raise self.errors[role]
            return {"ok": False, "error": self.errors[role]}
        if role != "planner":
            self.reviewers_started.add(role)
            if len(self.reviewers_started) == 2:
                self.both_started.set()
            if self.concurrent:
                await asyncio.wait_for(self.both_started.wait(), timeout=1)
            return {"ok": True, "data": fixture.opinion(self.opinions[role])}
        context = json.loads(messages[-1]["content"])
        data = {"decision": self.decision, "summary": "Inspect the failed registered frps service",
                "root_cause": "A failed unit is observed; further evidence may revise this",
                "evidence_refs": [e["evidence_id"] for e in context["evidence"] if e["classification"] == "observed"][:2],
                "next_tools": self.next_tools, "plan": None}
        if self.decision == "plan":
            data["plan"] = {"steps": self.steps, "rationale": "The registered service is inactive and the logs agree",
                            "scope": "Only the registered frps unit", "rollback": "Stop further writes and inspect logs on failure",
                            "verification": "Independent fresh service state and probe samples"}
        return {"ok": True, "data": data}


class AutonomyEngineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixture.CouncilSecurityTests.setUp(self)
        self.models = Models()
        self.transport.probe = AsyncMock(return_value=NTResult(ok=True, output="inactive", returncode=3))
        prom = SimpleNamespace(probe_success=AsyncMock(return_value=[]))
        self.investigation = InvestigationService(self.db, None, self.gate, prom, self.policy, transport=self.transport)
        for cap in ("service.status", "service.logs", "service.config", "service.process", "port.listen", "probe.status"):
            self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent", capability=cap,
                                         asset_id="host", object_id="obj", allow=True)
        for cap in ("service.reload", "service.reset_failed"):
            self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent", capability=cap,
                asset_id="host", object_id="obj", allow=True, require_approval=False, auto_allowed=True)
        self.notifier = SimpleNamespace(enqueue_for_event=lambda *a, **k: None)
        self.engine = AutonomyEngine(self.db, self.investigation, self.actions, self.policy,
                                     self.models, self.court, self.notifier)

    def tearDown(self):
        fixture.CouncilSecurityTests.tearDown(self)

    def due(self):
        self.db.execute("UPDATE autonomy_state SET next_retry_at=0")

    async def tick(self):
        self.due()
        return await self.engine.tick("inc")

    def runbook(self):
        apply_runbook_rules([{"id": "frps_restart", "name": "restart", "asset_id": "host", "object_name": "frps",
            "alertname": "*", "capability": "service.restart", "cooldown_sec": 1800, "max_per_day": 1}])

    async def test_watching_incident_two_independent_parallel_approvals_dispatch_once(self):
        self.models.concurrent = True
        self.assertEqual(self.engine.ready_incident_ids(), ["inc"])
        result = await self.tick()
        self.assertEqual(result["state"], "verifying")
        self.assertEqual(self.transport.exec.await_count, 1)
        requests = [c for c in self.models.calls if c["role"] != "planner"]
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0]["messages"], requests[1]["messages"])
        content = json.loads(requests[0]["messages"][-1]["content"])
        plan = self.court.get_plan(result["plan_id"])
        self.assertEqual(content, {"plan_id": plan["id"], "digest": plan["digest"], "plan": plan["plan"]})
        self.assertEqual(self.db.query_one("SELECT status FROM incidents")[0], "open")
        self.assertEqual((await self.tick())["state"], "operation_in_progress")
        self.assertEqual(self.transport.exec.await_count, 1)
        self.assertGreaterEqual(self.transport.probe.await_count, 8)

    async def test_full_immutable_plan_is_not_truncated_after_hashing(self):
        plan = fixture.CouncilSecurityTests.plan(self, rationale="x" * 6500)
        ballot = await self.engine._review(dict(self.db.query_one("SELECT * FROM incidents")), plan)
        self.assertEqual(ballot["decision"], "approved")
        for request in self.models.calls:
            self.assertEqual(len(json.loads(request["messages"][-1]["content"])["plan"]["rationale"]), 6500)

    async def test_one_and_two_vetoes_do_not_execute(self):
        for votes in ((True, False), (False, False)):
            self.models.opinions = dict(zip(("reviewer_kimi", "reviewer_deepseek"), votes))
            self.assertEqual((await self.tick())["state"], "vetoed")
        self.transport.exec.assert_not_awaited()
        feedback = self.engine.snapshot("inc")["feedback"]
        self.assertTrue(any(f["kind"] == "deliberation" for f in feedback))

    async def test_three_veto_rounds_hold_writes_but_keep_read_investigation(self):
        self.models.opinions["reviewer_kimi"] = False
        for _ in range(3):
            self.assertEqual((await self.tick())["state"], "vetoed")
        before = len(self.models.calls)
        reads = self.transport.probe.await_count
        self.assertEqual((await self.tick())["state"], "manual")
        self.assertEqual(len(self.models.calls), before)
        self.assertGreater(self.transport.probe.await_count, reads)
        self.assertTrue(self.engine.snapshot("inc")["manual_required"])
        self.assertGreater(self.db.query_one("SELECT COUNT(*) FROM events WHERE type='autonomy_notice'")[0], 0)
        goal = self.court.snapshot("inc")["goals"][0]
        self.engine.release_manual_barrier("inc", goal["id"])
        self.models.opinions["reviewer_kimi"] = True
        self.assertEqual((await self.tick())["state"], "verifying")

    async def test_reviewer_exception_is_closed_as_failed_not_pending(self):
        self.models.errors["reviewer_kimi"] = TimeoutError("fake timeout")
        result = await self.tick()
        self.assertEqual(result["state"], "failed")
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM council_reviews WHERE state='pending'")[0], 0)
        self.transport.exec.assert_not_awaited()

    async def test_legal_maximum_timeout_creates_both_tickets(self):
        self.models.timeout = 600
        self.models.retries = 2
        self.assertEqual((await self.tick())["state"], "verifying")
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM council_reviews")[0], 2)

    async def test_background_verification_poll_does_not_overwrite_running_tick_context(self):
        self.models.steps = [{"capability":"service.reload","params":{}}, {"capability":"service.reset_failed","params":{}}]
        self.assertEqual((await self.tick())["state"], "verifying")
        async def finish_during_read(*args, **kwargs):
            self.db.execute("UPDATE verifications SET status='failed',note='failed while next read awaited'")
            self.engine.poll_verifications()
            return NTResult(ok=True, output="inactive", returncode=3)
        self.transport.probe.side_effect = finish_during_read
        self.assertEqual((await self.tick())["reason"], "verification_pending")
        self.assertEqual(self.db.query_one("SELECT state FROM council_grants")[0], "verifying")
        self.transport.probe.side_effect = None
        self.models.decision = "observe"
        self.assertEqual((await self.tick())["state"], "observe")
        context = json.loads(self.db.query_one("SELECT context_json FROM autonomy_state")[0])
        self.assertTrue(any(f["kind"]=="verification_result" for f in context["feedback"]))
        self.assertIn(_signature(self.models.steps),context["failed_signatures"])

    async def test_completed_multi_step_strategy_is_not_sent_for_duplicate_review(self):
        self.db.execute("INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,alertname,status,asset_id,object_id,incident_id,first_seen,last_seen)"
                        " VALUES('ep','am','fp','start','TargetDown','firing','host','frps','inc',?,?)", (now(), now()))
        self.models.steps = [{"capability":"service.reload","params":{}}, {"capability":"service.reset_failed","params":{}}]
        self.assertEqual((await self.tick())["state"], "verifying")
        self.db.execute("UPDATE verifications SET status='passed'")
        self.engine.poll_verifications()
        self.assertEqual((await self.tick())["error"], "repeated_completed_strategy")
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM council_plans")[0], 1)
        self.assertEqual(self.transport.exec.await_count, 2)

    async def test_cooldown_blocks_only_restart_and_allows_different_reviewed_repair(self):
        self.runbook()
        self.db.execute("INSERT INTO actions(id,asset_id,object_id,capability,state,mode,created_at,dispatched_at)"
                        " VALUES('old','host','obj','service.restart','failure','auto',?,?)", (now(), now()))
        self.models.steps = [{"capability": "service.reset_failed", "params": {}}]
        result = await self.tick()
        self.assertEqual(result["state"], "verifying")
        self.assertEqual(self.transport.exec.await_args.args[1], ["systemctl", "reset-failed", "frps"])
        self.assertGreater(self.transport.probe.await_count, 0)

    async def test_rule_without_satisfied_preconditions_cannot_monopolize_incident(self):
        self.runbook()
        self.assertEqual((await self.tick())["state"], "runbook_priority")
        self.assertEqual((await self.tick())["state"], "verifying")
        self.assertEqual(self.transport.exec.await_count, 1)

    async def test_restart_failure_returns_evidence_then_tries_different_strategy(self):
        self.transport.exec.return_value = NTResult(ok=False, output="unit start limit hit", returncode=1)
        self.assertEqual((await self.tick())["state"], "failed")
        self.transport.exec.return_value = NTResult(ok=True, output="reset failed state", returncode=0)
        self.models.steps = [{"capability": "service.reset_failed", "params": {}}]
        self.assertEqual((await self.tick())["state"], "verifying")
        planner = [c for c in self.models.calls if c["role"] == "planner"][-1]
        self.assertIn("unit start limit hit", planner["messages"][-1]["content"])
        self.assertEqual(self.transport.exec.await_count, 2)

    async def test_same_failed_strategy_is_not_replayed(self):
        self.transport.exec.return_value = NTResult(ok=False, output="unit fails", returncode=1)
        self.assertEqual((await self.tick())["state"], "failed")
        self.assertEqual((await self.tick())["error"], "repeated_failed_strategy")
        self.assertEqual(self.transport.exec.await_count, 1)

    async def test_verification_failure_returns_to_planner_with_new_evidence(self):
        self.assertEqual((await self.tick())["state"], "verifying")
        self.db.execute("UPDATE verifications SET status='failed',note='fresh probe still failing'")
        self.engine.poll_verifications()
        self.models.steps = [{"capability": "service.reload", "params": {}}]
        self.assertEqual((await self.tick())["state"], "verifying")
        self.assertEqual(self.transport.exec.await_args.args[1], ["systemctl", "reload", "frps"])
        planner = [c for c in self.models.calls if c["role"] == "planner"][-1]
        self.assertIn("fresh probe still failing", planner["messages"][-1]["content"])

    async def test_passed_verification_is_reported_not_business_recovery_and_reads_continue(self):
        self.db.execute("INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,alertname,status,asset_id,object_id,incident_id,first_seen,last_seen)"
                        " VALUES('ep','am','fp','start','TargetDown','firing','host','frps','inc',?,?)", (now(), now()))
        await self.tick()
        self.db.execute("UPDATE verifications SET status='passed'")
        self.engine.poll_verifications()
        self.assertEqual(self.db.query_one("SELECT status FROM incidents")[0], "open")
        self.models.decision = "observe"
        calls = len(self.models.calls)
        self.assertEqual((await self.tick())["state"], "observe")
        self.assertGreater(len(self.models.calls), calls)
        self.assertEqual(self.transport.exec.await_count, 1)

    async def test_recovery_during_planning_never_creates_or_executes_old_plan(self):
        self.models.on_call = lambda role: self.db.execute("UPDATE incidents SET status='resolved'")
        self.assertEqual((await self.tick())["state"], "stale")
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM council_plans")[0], 0)
        self.transport.exec.assert_not_awaited()

    async def test_recovery_during_review_never_dispatches(self):
        def recover(role):
            if role == "reviewer_kimi":
                self.db.execute("UPDATE incidents SET status='resolved'")
        self.models.on_call = recover
        self.assertEqual((await self.tick())["state"], "stale")
        self.transport.exec.assert_not_awaited()
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM council_reviews WHERE state='pending'")[0],0)
        self.assertEqual(self.db.query_one("SELECT state FROM council_plans")[0],"stale")

    async def test_disable_autonomy_or_auto_during_review_prevents_execution(self):
        for switch in ("autonomy", "auto"):
            flags = {"auto": True}
            self.engine.runbook_auto_enabled = lambda: flags["auto"]
            self.models.enabled = True
            def disable(role):
                if role == "reviewer_deepseek":
                    if switch == "autonomy":
                        self.models.enabled = False
                    else:
                        flags["auto"] = False
            self.models.on_call = disable
            self.assertEqual((await self.tick())["state"], "writes_disabled")
        self.transport.exec.assert_not_awaited()

    async def test_human_request_persists_backend_barrier_until_admin_releases(self):
        self.models.decision = "human"
        self.assertEqual((await self.tick())["state"], "human")
        self.models.decision = "plan"
        calls = len(self.models.calls)
        self.assertEqual((await self.tick())["state"], "manual")
        self.assertEqual(len(self.models.calls), calls)
        self.assertTrue(self.engine.snapshot("inc")["manual_required"])
        self.transport.exec.assert_not_awaited()

    async def test_explicit_rejection_allows_reads_but_no_new_votes_or_writes(self):
        IncidentService(self.db).set_need_human("inc", "action_rejected:human-request")
        self.assertEqual((await self.tick())["reason"], "manual_write_stop")
        self.assertGreater(self.transport.probe.await_count, 0)
        self.assertEqual(self.models.calls, [])

    async def test_unknown_write_is_not_replayed_and_reads_remain_available(self):
        self.db.execute("INSERT INTO actions(id,incident_id,asset_id,object_id,capability,state,created_at)"
                        " VALUES('unknown','inc','host','obj','service.restart','unknown',?)", (now(),))
        result = await self.tick()
        self.assertEqual(result["reason"], "unknown_write")
        self.assertGreater(self.transport.probe.await_count, 0)
        self.assertEqual(self.models.calls, [])
        self.transport.exec.assert_not_awaited()

    async def test_agent_can_choose_further_read_but_never_write_as_read_tool(self):
        self.models.decision = "investigate"
        self.models.next_tools = [{"capability": "service.config", "object_id": "obj", "why": "Inspect ExecReload"}]
        self.assertEqual((await self.tick())["state"], "investigating")
        self.assertTrue(any("--property=FragmentPath,DropInPaths,Restart,User,Group,Type,LoadState,UnitFileState,CanStart,CanReload" in call.args[1]
                            for call in self.transport.probe.await_args_list))
        self.models.next_tools = [{"capability": "service.restart", "object_id": "obj"}]
        self.assertEqual((await self.tick())["error"], "read_only_tools_required")
        self.transport.exec.assert_not_awaited()

    async def test_unregistered_read_target_is_rejected(self):
        self.models.decision = "investigate"
        self.models.next_tools = [{"capability": "service.logs", "object_id": "other-host-object"}]
        self.assertEqual((await self.tick())["error"], "unregistered_read_target")

    async def test_malformed_plans_are_rejected_without_unhandled_type_errors(self):
        context = {"evidence": [{"classification": "observed", "evidence_id": "ev1"}]}
        for steps in (["shell text"], [None], [{"capability": "service.restart", "params": {"cmd": "other"}}], []):
            response = {"decision": "plan", "evidence_refs": ["ev1"], "plan": {
                "steps": steps, "rationale": "r", "scope": "s", "rollback": "r", "verification": "v"}}
            with self.assertRaises(ValueError):
                self.engine._parse(response, context)
        # identity echo is stripped, never passed through as write params
        response = {"decision": "plan", "evidence_refs": ["ev1"], "plan": {
            "steps": [{"capability": "service.restart", "params": {"unit": "other"}}],
            "rationale": "r", "scope": "s", "rollback": "r", "verification": "v"}}
        parsed = self.engine._parse(response, context)
        self.assertEqual(parsed["plan"]["steps"], [{"capability": "service.restart", "params": {}}])

    async def test_restart_interrupts_votes_and_never_replays_claimed_write(self):
        plan = fixture.CouncilSecurityTests.plan(self)
        self.court.begin_review(plan["id"], "reviewer_kimi", "kimi", "kimi-model")
        inc = dict(self.db.query_one("SELECT * FROM incidents"))
        self.engine._state(inc)
        self.db.execute("UPDATE autonomy_state SET phase='reviewing',lease_until=?", (now()+1000,))
        result = self.engine.recover_inflight()
        self.assertEqual(result["reviews_interrupted"], 1)
        self.assertEqual(self.db.query_one("SELECT state FROM council_reviews")[0], "failed")
        self.assertEqual(self.db.query_one("SELECT lease_until FROM autonomy_state")[0], 0)
        self.transport.exec.assert_not_awaited()
        self.assertEqual((await self.tick())["state"], "verifying")

    async def test_duplicate_workers_lease_incident_and_do_not_duplicate_execution(self):
        self.models.concurrent = True
        results = await asyncio.gather(self.engine.tick("inc"), self.engine.tick("inc"))
        self.assertEqual(sum(r["state"] == "verifying" for r in results), 1)
        self.assertEqual(self.transport.exec.await_count, 1)

    async def test_recurrence_new_generation_gets_new_investigation_and_plan(self):
        self.models.decision = "human"
        await self.tick()
        self.db.execute("UPDATE incidents SET generation=2,stage='watching',need_human=0,need_human_reason=''")
        self.db.event("generation_bumped", "new fault", incident_id="inc", payload={"generation": 2})
        self.models.decision = "plan"
        self.assertIn("inc", self.engine.ready_incident_ids())
        self.assertEqual((await self.tick())["state"], "verifying")
        plan = self.court.snapshot("inc")["plans"][0]
        self.assertEqual(plan["generation"], 2)
        self.assertFalse(self.engine.snapshot("inc")["manual_required"])

    async def test_provider_outage_and_budget_do_not_dispatch_or_mutate_existing_auto_switch(self):
        for error in ("api_unavailable", "budget_exhausted"):
            self.models.errors["planner"] = error
            result = await self.tick()
            self.assertIn(result["state"], ("provider_unavailable", "budget_blocked"))
        self.assertTrue(self.engine.runbook_auto_enabled)
        self.assertGreater(self.transport.probe.await_count, 0)
        self.transport.exec.assert_not_awaited()
        self.models.errors.clear()
        self.models.decision="observe"
        self.assertEqual((await self.tick())["state"],"observe")
        self.assertEqual(self.engine.snapshot("inc")["last_error"],"")
        context=json.loads(self.db.query_one("SELECT context_json FROM autonomy_state")[0])
        self.assertNotIn("budget",context["notices"])

    async def test_disabled_by_default_engine_does_not_affect_monitoring_or_actions(self):
        self.models.enabled = False
        self.assertEqual(await self.tick(), {"state": "disabled"})
        self.assertEqual(self.engine.ready_incident_ids(), [])
        self.transport.exec.assert_not_awaited()

    async def test_permission_required_uses_manual_adjudication_instead_of_retry_loop(self):
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent", capability="service.restart",
                                     asset_id="host", object_id="obj", allow=True, require_approval=True)
        self.assertEqual((await self.tick())["state"], "manual")
        self.assertTrue(self.engine.snapshot("inc")["manual_required"])
        self.assertEqual((await self.tick())["state"], "manual")
        self.assertEqual(len(self.models.calls), 1)
        self.transport.exec.assert_not_awaited()

    async def test_legacy_runbook_path_delegates_without_spurious_human_obligation(self):
        agent = AgentLoop(self.db, self.investigation, self.actions, self.policy,
                          SimpleNamespace(enabled=False), self.notifier)
        agent.autonomy_enabled = lambda: self.engine.enabled
        self.assertEqual((await agent.handle_incident("inc"))["action"], "delegated_autonomy")
        self.assertEqual(self.db.query_one("SELECT need_human FROM incidents")[0], 0)

    def test_evidence_masks_credential_flags_and_private_key_blocks(self):
        data = {"output": "--token abcsecret --api-key=secretkey\n-----BEGIN PRIVATE KEY-----\nsensitive body\n-----END PRIVATE KEY-----",
                "password": "db-password"}
        cleaned = json.dumps(redact(data))
        for secret in ("abcsecret", "secretkey", "sensitive body", "db-password"):
            self.assertNotIn(secret, cleaned)

    def test_strategy_signature_ignores_plan_compilation_fields_and_step_order(self):
        simple = [{"capability": "service.reload", "params": {}}, {"capability": "service.reset_failed", "params": {}}]
        compiled = [{**s, "ordinal": i, "tokens": ["systemctl", "reload", "frps"]} for i, s in enumerate(simple)]
        self.assertEqual(_signature(simple), _signature(list(reversed(compiled))))


if __name__ == "__main__":
    unittest.main()
