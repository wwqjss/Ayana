"""Council fault injection: fake models and fake SSH, never production writes."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ayana.actions import ActionError, ActionService
from ayana.council import CouncilError, CouncilService
from ayana.db import Database, SCHEMA_VERSION, now
from ayana.ntsafe import NTResult
from ayana.policy import Policy
from ayana.runbook import apply_runbook_rules


def opinion(approve: bool = True) -> dict:
    return {"approve": approve, "reason": "Observed service and failed probe agree" if approve else "Port owner evidence is missing",
            "missing_evidence": [] if approve else ["current port owner"],
            "suggested_revision": "" if approve else "inspect the registered port before attempting restart"}


class CouncilSecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "council.db")
        t = now()
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,expected_host_id,host_id_verified_at,created_at,updated_at)"
                        " VALUES('host','Host','read','write','HOST',?,?,?)", (t, t, t))
        self.db.execute("INSERT INTO objects(id,asset_id,kind,name,unit,auto_recover,created_at)"
                        " VALUES('obj','host','service','frps','frps',1,?)", (t,))
        self.db.execute("INSERT INTO incidents(id,title,asset_id,object_id,stage,created_at,updated_at)"
                        " VALUES('inc','frps down','host','frps','watching',?,?)", (t, t))
        self.policy = Policy(self.db)
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent", capability="service.restart",
            asset_id="host", object_id="obj", allow=True, require_approval=False, auto_allowed=True)
        binding = SimpleNamespace(asset_id="host", read_alias="read", write_alias="write", expected_host_id="HOST", host_id_verified_at=t)
        self.gate = SimpleNamespace(get=lambda _: binding, verify_account=AsyncMock(return_value={"ok": True, "mode": "exec"}))
        self.transport = SimpleNamespace(exec=AsyncMock(return_value=NTResult(ok=True, output="done", returncode=0)))
        self.actions = ActionService(self.db, None, self.gate, self.policy, SimpleNamespace(), transport=self.transport)
        # Independent verifier is deliberately pending. Command success is not recovery.
        self.actions._run_verification = AsyncMock(return_value={"status": "pending"})
        self.court = CouncilService(self.db, self.actions)
        apply_runbook_rules([])

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
        apply_runbook_rules([])

    def plan(self, **overrides):
        values = {"steps": [{"capability": "service.restart", "params": {}}],
                  "evidence": [{"id": "e1", "service": "inactive", "probe_success": 0}],
                  "rationale": "The registered frps service is inactive and its endpoint fails",
                  "scope": "registered frps service only", "rollback": "If restart fails stop further writes and inspect service logs",
                  "verification": "independent service state and continuous fresh probe samples"}
        values.update(overrides)
        return self.court.create_plan("inc", **values)

    def reviews(self, plan, a=True, b=True):
        tickets = [self.court.begin_review(plan["id"], "reviewer_kimi", "kimi", "configured-kimi-model"),
                   self.court.begin_review(plan["id"], "reviewer_deepseek", "deepseek", "configured-deepseek-model")]
        self.court.record_review(tickets[0]["id"], opinion(a))
        self.court.record_review(tickets[1]["id"], opinion(b))
        return tickets

    def grant(self):
        p = self.plan()
        self.reviews(p)
        return p, self.court.tally(p["id"])

    async def test_two_approvals_dispatch_once_and_require_independent_verification(self):
        p, ballot = self.grant()
        selector=p["plan"]["verification_contracts"][0]["profile"]["checks"][0]["selector"]
        self.assertEqual(selector,{"asset":"host","service":"frps"})
        self.assertEqual(p["plan"]["policy_at_draft"][0]["decision"],"automatic")
        self.assertIn("current_policy_and_agent_ceiling",p["plan"]["backend_preconditions"]["rechecked_before_dispatch"])
        self.assertEqual(ballot["decision"], "approved")
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["state"], "verifying")
        self.assertEqual(self.transport.exec.await_count, 1)
        self.assertEqual(self.transport.exec.await_args.args, ("host", ["systemctl", "restart", "frps"]))
        self.assertEqual(self.db.query_one("SELECT status FROM verifications")["status"], "pending")
        criteria=json.loads(self.db.query_one("SELECT criteria_json FROM verifications")[0])
        self.assertEqual(selector,{"asset":criteria["asset_id"],"service":criteria["service"]})
        self.assertEqual(self.db.query_one("SELECT status FROM incidents")["status"], "open")
        self.assertEqual(self.court.finish_verification(ballot["grant_id"], recovered=True)["state"], "verifying")
        self.assertEqual(self.db.query_one("SELECT state FROM council_steps")["state"], "success")

    async def test_one_or_two_vetoes_never_dispatch_and_count_one_round(self):
        for a, b in ((True, False), (False, False)):
            p = self.plan()
            self.reviews(p, a, b)
            ballot = self.court.tally(p["id"])
            self.assertEqual(ballot["decision"], "vetoed")
            self.assertFalse(ballot["grant_id"])
            self.assertEqual(self.court.tally(p["id"])["id"], ballot["id"])
        self.assertEqual(self.db.query_one("SELECT consecutive_vetoes FROM council_goals")[0], 2)
        self.transport.exec.assert_not_called()

    async def test_three_substantive_vetoes_hold_same_goal_despite_rename(self):
        p = None
        for i in range(3):
            p = self.plan(repair_goal=f"minor wording change {i}", rationale=f"Revised with additional evidence, round {i}")
            self.reviews(p, False, True)
            self.court.tally(p["id"])
        snapshot = self.court.snapshot("inc")
        self.assertTrue(snapshot["manual_required"])
        self.assertEqual(len(snapshot["goals"]), 1)
        with self.assertRaisesRegex(CouncilError, "manual_adjudication_required"):
            self.plan(repair_goal="another invented repair target")
        self.court.release_manual_barrier("inc", p["goal_id"], actor="admin")
        revised = self.plan()
        self.assertEqual(revised["version"], 4)
        self.assertFalse(self.court.snapshot("inc")["manual_required"])
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM council_grants")[0], 0)

    async def test_manual_release_cannot_apply_to_old_generation_or_recovered_incident(self):
        goal = self.court.request_manual_adjudication("inc", reason="evidence needs human review")
        self.db.execute("UPDATE incidents SET generation=2 WHERE id='inc'")
        with self.assertRaisesRegex(CouncilError, "stale_generation"):
            self.court.release_manual_barrier("inc",goal["id"])
        self.db.execute("UPDATE incidents SET generation=1,status='resolved' WHERE id='inc'")
        with self.assertRaisesRegex(CouncilError, "incident_not_open"):
            self.court.release_manual_barrier("inc",goal["id"])
        self.assertTrue(self.db.query_one("SELECT manual_required FROM council_goals WHERE id=?",(goal["id"],))[0])

    async def test_api_failure_timeout_and_invalid_schema_fail_closed_without_veto_count(self):
        for failure in ("error", "timeout", "invalid"):
            p = self.plan()
            tickets = [self.court.begin_review(p["id"], "reviewer_kimi", "kimi", "kimi-model"),
                       self.court.begin_review(p["id"], "reviewer_deepseek", "deepseek", "deepseek-model")]
            self.court.record_review(tickets[0]["id"], opinion())
            if failure == "error":
                self.court.record_review(tickets[1]["id"], error="official API unavailable")
            elif failure == "timeout":
                with patch("ayana.council.now", return_value=now() + 100):
                    self.court.record_review(tickets[1]["id"], opinion())
            else:
                self.court.record_review(tickets[1]["id"], {**opinion(), "approve": "true"})
            self.assertEqual(self.court.tally(p["id"])["decision"], "failed")
        self.assertEqual(self.db.query_one("SELECT consecutive_vetoes FROM council_goals")[0], 0)
        self.transport.exec.assert_not_called()

    async def test_model_cannot_self_identify_as_both_reviewers(self):
        p = self.plan()
        with self.assertRaisesRegex(CouncilError, "reviewer_identity_invalid"):
            self.court.begin_review(p["id"], "reviewer_deepseek", "kimi", "same-model")
        ticket = self.court.begin_review(p["id"], "reviewer_kimi", "kimi", "model")
        review = self.court.record_review(ticket["id"], {**opinion(), "role": "reviewer_deepseek"})
        self.assertEqual(review["state"], "invalid")
        self.assertEqual(self.court.tally(p["id"])["decision"], "pending")

    async def test_duplicate_review_callback_cannot_change_vote(self):
        p = self.plan()
        ticket = self.court.begin_review(p["id"], "reviewer_kimi", "kimi", "model")
        self.court.record_review(ticket["id"], opinion(False))
        self.assertFalse(self.court.record_review(ticket["id"], opinion(True))["approve"])
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable council review result"):
            self.db.execute("UPDATE council_reviews SET approve=1 WHERE id=?", (ticket["id"],))

    async def test_plan_revision_revokes_old_grant_and_cannot_mutate_content(self):
        p, ballot = self.grant()
        newer = self.plan(rationale="New evidence identifies a different root cause")
        self.assertEqual(newer["version"], p["version"] + 1)
        with self.assertRaisesRegex(CouncilError, "grant_already_consumed"):
            await self.court.execute_grant(ballot["grant_id"])
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable council plan"):
            self.db.execute("UPDATE council_plans SET plan_json='{}' WHERE id=?", (p["id"],))
        self.transport.exec.assert_not_called()

    async def test_reviewed_version_cannot_authorize_modified_plan(self):
        p = self.plan()
        self.reviews(p)
        self.plan(rationale="Modified after both votes but before tally")
        self.assertEqual(self.court.tally(p["id"])["decision"], "stale")
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM council_grants")[0], 0)

    async def test_generation_and_recovery_invalidate_grants(self):
        for change in ("generation", "recovery"):
            p, ballot = self.grant()
            if change == "generation":
                self.db.execute("UPDATE incidents SET generation=generation+1 WHERE id='inc'")
            else:
                self.db.execute("UPDATE incidents SET status='resolved' WHERE id='inc'")
            with self.assertRaises(CouncilError):
                await self.court.execute_grant(ballot["grant_id"])
            self.db.execute("UPDATE incidents SET status='open' WHERE id='inc'")
        self.transport.exec.assert_not_called()

    async def test_recovery_during_identity_wait_prevents_dispatch(self):
        p, ballot = self.grant()
        async def recovered(*args, **kw):
            self.db.execute("UPDATE incidents SET status='resolved' WHERE id='inc'")
            return {"ok": True, "mode": "exec"}
        self.gate.verify_account = recovered
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["state"], "failed")
        self.transport.exec.assert_not_called()

    async def test_expired_authorization_cannot_dispatch(self):
        p, ballot = self.grant()
        with patch("ayana.council.now", return_value=p["expires_at"] + 1):
            with self.assertRaisesRegex(CouncilError, "plan_expired"):
                await self.court.execute_grant(ballot["grant_id"])
        self.transport.exec.assert_not_called()

    async def test_duplicate_execution_race_has_one_dispatch(self):
        _, ballot = self.grant()
        results = await asyncio.gather(self.court.execute_grant(ballot["grant_id"]),
                                       self.court.execute_grant(ballot["grant_id"]), return_exceptions=True)
        self.assertEqual(sum(isinstance(r, CouncilError) for r in results), 1)
        self.assertEqual(self.transport.exec.await_count, 1)
        action = self.db.query_one("SELECT id FROM actions")
        with self.assertRaisesRegex(ActionError, "no_replay"):
            await self.actions.execute(action["id"], actor_type="auto_rule", actor_id="agent")

    async def test_unknown_execution_is_never_replayed_and_requires_human(self):
        _, ballot = self.grant()
        self.transport.exec.side_effect = TimeoutError("transport lost after dispatch")
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["state"], "manual")
        self.assertTrue(self.court.snapshot("inc")["manual_required"])
        with self.assertRaises(CouncilError):
            await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(self.transport.exec.await_count, 1)

    async def test_review_does_not_override_human_required_policy(self):
        _, ballot = self.grant()
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent", capability="service.restart",
            asset_id="host", object_id="obj", allow=True, require_approval=True, auto_allowed=True)
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["state"], "failed")
        self.transport.exec.assert_not_called()

    async def test_reviewed_cannot_be_requested_without_ballot_grant(self):
        with self.assertRaisesRegex(ActionError, "council_grant_required"):
            self.actions.propose(asset_id="host", object_id="obj", capability="service.restart",
                incident_id="inc", mode="reviewed", proposer_type="auto_rule", proposer_id="agent")
        with self.assertRaisesRegex(ActionError, "council_grant_invalid"):
            self.actions.propose(asset_id="host", object_id="obj", capability="service.restart",
                incident_id="inc", mode="reviewed", proposer_type="auto_rule", proposer_id="agent",
                council_grant_id="forged-grant", council_step=0)

    async def test_recovery_fails_pending_reviews_and_revokes_unclaimed_grants(self):
        p = self.plan()
        ticket = self.court.begin_review(p["id"], "reviewer_kimi", "kimi", "model")
        summary = self.court.recover_inflight()
        self.assertEqual(summary["reviews_interrupted"], 1)
        self.assertEqual(self.court.record_review(ticket["id"], opinion())["state"], "failed")
        _, ballot = self.grant()
        summary = self.court.recover_inflight()
        self.assertEqual(summary["grants_revoked"], 1)
        with self.assertRaises(CouncilError):
            await self.court.execute_grant(ballot["grant_id"])

    async def test_restart_mid_execution_preserves_unknown_and_manual_barrier(self):
        _, ballot = self.grant()
        self.db.execute("UPDATE council_grants SET state='executing',claimed_at=? WHERE id=?", (now(), ballot["grant_id"]))
        proposed = self.actions.propose(asset_id="host", object_id="obj", capability="service.restart", incident_id="inc",
            mode="reviewed", proposer_type="auto_rule", proposer_id="agent", council_grant_id=ballot["grant_id"], council_step=0)
        self.actions.authorize_reviewed(proposed["id"], grant_id=ballot["grant_id"], ordinal=0)
        self.db.execute("UPDATE actions SET state='dispatched',dispatched_at=? WHERE id=?", (now(), proposed["id"]))
        self.assertEqual(self.court.recover_inflight()["executions_held"], 1)
        self.assertEqual(self.db.query_one("SELECT state FROM actions")["state"], "unknown")
        self.assertTrue(self.court.snapshot("inc")["manual_required"])
        self.transport.exec.assert_not_called()

    async def test_cooldown_does_not_stop_plan_investigation_but_blocks_same_operation(self):
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        self.db.execute("UPDATE verifications SET status='failed'")
        self.court.finish_verification(ballot["grant_id"], recovered=False)
        p = self.plan(evidence=[{"id": "e2", "new_log": "restart failed to restore port"}])
        self.reviews(p)
        second = self.court.tally(p["id"])
        result = await self.court.execute_grant(second["grant_id"])
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["results"][-1]["error"], "cooldown")
        self.assertEqual(self.transport.exec.await_count, 1)

    async def test_manual_only_and_arbitrary_parameters_cannot_be_wrapped_as_plan(self):
        with self.assertRaisesRegex(CouncilError, "capability_not_autonomous"):
            self.plan(steps=[{"capability": "service.start"}])
        with self.assertRaisesRegex(CouncilError, "parameter overrides"):
            self.plan(steps=[{"capability": "service.restart", "params": {"unit": "another-service"}}])
        with self.assertRaisesRegex(CouncilError, "steps accept only"):
            self.plan(steps=[{"capability": "service.restart", "tokens": ["sh", "-c", "anything"]}])

    async def test_verification_result_cannot_be_asserted_by_planner(self):
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        self.db.execute("UPDATE verifications SET status='failed'")
        result = self.court.finish_verification(ballot["grant_id"], recovered=True, evidence="model says healthy")
        self.assertEqual(result["state"], "verification_failed")

    async def test_current_generation_goal_and_snapshot_after_recurrence(self):
        p = self.plan()
        self.reviews(p, False, True)
        self.court.tally(p["id"])
        self.db.execute("UPDATE incidents SET generation=2,stage='watching' WHERE id='inc'")
        fresh = self.plan()
        self.assertEqual(fresh["generation"], 2)
        self.assertNotEqual(fresh["goal_id"], p["goal_id"])
        self.assertEqual(self.court.snapshot("inc")["current_generation"], 2)

    async def test_schema_migration_records_council_version(self):
        self.assertEqual(self.db.schema_version(), SCHEMA_VERSION)
        self.assertEqual(self.db.query_one("SELECT name FROM schema_migrations WHERE version=16")["name"], "council_plans_reviews_grants")

    async def test_multi_step_plan_preserves_exact_order_and_pending_verification_locks(self):
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent", capability="service.reset_failed",
            asset_id="host", object_id="obj", allow=True, require_approval=False, auto_allowed=True)
        p = self.plan(steps=[{"capability": "service.reset_failed"}, {"capability": "service.restart"}])
        self.reviews(p)
        ballot = self.court.tally(p["id"])
        observed = []
        async def exec_step(asset, tokens, timeout=None):
            observed.append(tokens)
            if len(observed) == 2:
                self.assertTrue(self.actions._object_locked("host", "obj"))
                self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM verifications WHERE status='pending'")[0], 1)
                self.actions._run_verification.assert_not_awaited()
            return NTResult(ok=True, output="done", returncode=0)
        self.transport.exec.side_effect = exec_step
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["state"], "verifying")
        self.assertEqual(observed, [["systemctl", "reset-failed", "frps"], ["systemctl", "restart", "frps"]])
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM verifications WHERE status='pending'")[0], 2)
        self.assertEqual([r["state"] for r in self.db.query("SELECT state FROM council_steps ORDER BY ordinal")], ["success", "success"])

    async def test_runbook_restart_limit_does_not_block_distinct_reset_failed_repair(self):
        apply_runbook_rules([{"id": "rb", "name": "restart", "asset_id": "host", "object_name": "frps",
                              "capability": "service.restart", "max_per_day": 1, "cooldown_sec": 1800}])
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        self.db.execute("UPDATE verifications SET status='failed'")
        self.court.finish_verification(ballot["grant_id"], recovered=False)
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent", capability="service.reset_failed",
            asset_id="host", object_id="obj", allow=True, require_approval=False, auto_allowed=True)
        p = self.plan(steps=[{"capability": "service.reset_failed"}],
                      evidence=[{"id": "e2", "log": "Start request repeated too quickly"}],
                      rationale="The rate limit is active; inspect and clear failed state without repeating restart")
        self.reviews(p)
        reset = self.court.tally(p["id"])
        result = await self.court.execute_grant(reset["grant_id"])
        self.assertEqual(result["state"], "verifying")
        self.assertEqual(self.transport.exec.await_count, 2)
        self.assertEqual(self.transport.exec.await_args.args[1], ["systemctl", "reset-failed", "frps"])

    async def test_action_payload_tampering_after_approval_blocks_dispatch(self):
        _, ballot = self.grant()
        async def tampered(*args, **kw):
            row = self.db.query_one("SELECT id,params_json FROM actions")
            payload = json.loads(row["params_json"])
            payload["params"] = {"unit": "another-service"}
            self.db.execute("UPDATE actions SET params_json=? WHERE id=?", (json.dumps(payload), row["id"]))
            return {"ok": True, "mode": "exec"}
        self.gate.verify_account = tampered
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["results"][-1]["error"], "council_step_mismatch")
        self.transport.exec.assert_not_called()

    async def test_registration_target_change_during_identity_wait_blocks_dispatch(self):
        _, ballot = self.grant()
        async def changed(*args, **kw):
            self.db.execute("UPDATE objects SET unit='nginx' WHERE id='obj'")
            return {"ok": True, "mode": "exec"}
        self.gate.verify_account = changed
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["state"], "failed")
        self.transport.exec.assert_not_called()

    async def test_ordinary_action_approval_cannot_replace_two_reviewers(self):
        _, ballot = self.grant()
        self.db.execute("UPDATE council_grants SET state='executing',claimed_at=? WHERE id=?", (now(), ballot["grant_id"]))
        proposed = self.actions.propose(asset_id="host", object_id="obj", capability="service.restart", incident_id="inc",
            mode="reviewed", proposer_type="auto_rule", proposer_id="agent", council_grant_id=ballot["grant_id"], council_step=0)
        with self.assertRaisesRegex(ActionError, "council_approval_required"):
            self.actions.approve(proposed["id"], approver_type="auto_rule", approver_id="agent")
        self.transport.exec.assert_not_called()

    async def test_second_step_never_runs_after_first_step_failure(self):
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent", capability="service.reset_failed",
            asset_id="host", object_id="obj", allow=True, require_approval=False, auto_allowed=True)
        p = self.plan(steps=[{"capability": "service.reset_failed"}, {"capability": "service.restart"}])
        self.reviews(p)
        ballot = self.court.tally(p["id"])
        self.transport.exec.return_value = NTResult(ok=False, output="unit missing", returncode=1)
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["state"], "failed")
        self.assertEqual(self.transport.exec.await_count, 1)
        self.assertEqual([r["state"] for r in self.db.query("SELECT state FROM council_steps ORDER BY ordinal")], ["failure", "pending"])

    async def test_switch_disabled_during_identity_wait_stops_reviewed_dispatch(self):
        _, ballot = self.grant()
        async def disabled(*args, **kw):
            self.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('agent_auto_enabled','0')")
            return {"ok": True, "mode": "exec"}
        self.gate.verify_account = disabled
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["results"][-1]["error"], "agent_auto_disabled")
        self.transport.exec.assert_not_called()

    async def test_provider_switch_disabled_during_identity_wait_stops_dispatch(self):
        self.db.execute("CREATE TABLE ai_provider_config(id INTEGER PRIMARY KEY,value_json TEXT NOT NULL)")
        self.db.execute("INSERT INTO ai_provider_config VALUES(1,?)", (json.dumps({"enabled": True}),))
        _, ballot = self.grant()
        async def disabled(*args, **kw):
            self.db.execute("UPDATE ai_provider_config SET value_json=? WHERE id=1", (json.dumps({"enabled": False}),))
            return {"ok": True, "mode": "exec"}
        self.gate.verify_account = disabled
        result = await self.court.execute_grant(ballot["grant_id"])
        self.assertEqual(result["results"][-1]["error"], "autonomy_disabled")
        self.transport.exec.assert_not_called()

    def _old_verification(self, vid, status, *, generation=1, obj="obj"):
        self.db.execute("INSERT INTO actions(id,incident_id,asset_id,object_id,capability,state,created_at)"
            " VALUES(?, 'inc','host',?,'service.restart','success',?)", (f"a-{vid}", obj, now()-100))
        self.db.execute("INSERT INTO verifications(id,action_id,incident_id,status,generation,started_at,finished_at)"
            " VALUES(?,?,'inc',?,?,?,?)", (vid, f"a-{vid}", status, generation, now()-100, now()-90))
        from ayana.incidents import IncidentService
        IncidentService(self.db).set_need_human("inc", f"verify_{status}:{vid}")

    async def test_new_independent_pass_clears_only_same_generation_target_technical_obligations(self):
        self._old_verification("old-failure", "failed")
        self._old_verification("old-inconclusive", "inconclusive")
        self._old_verification("old-unknown", "unknown")
        self._old_verification("prior-generation", "failed", generation=0)
        self._old_verification("other-target", "failed", obj="other")
        from ayana.incidents import IncidentService
        service = IncidentService(self.db)
        service.set_need_human("inc", "manual_review")
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        self.db.execute("UPDATE verifications SET status='passed',finished_at=? WHERE action_id IN"
                        " (SELECT id FROM actions WHERE council_grant_id=?)", (now(), ballot["grant_id"]))
        self.court.finish_verification(ballot["grant_id"], recovered=True)
        reasons = self.db.query_one("SELECT need_human_reason FROM incidents")[0].splitlines()
        self.assertNotIn("verify_failed:old-failure", reasons)
        self.assertNotIn("verify_inconclusive:old-inconclusive", reasons)
        self.assertIn("verify_unknown:old-unknown", reasons)
        self.assertIn("verify_failed:prior-generation", reasons)
        self.assertIn("verify_failed:other-target", reasons)
        self.assertIn("manual_review", reasons)

    async def test_independent_pass_in_old_generation_cannot_clear_current_obligation(self):
        self._old_verification("old-failure", "failed")
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        self.db.execute("UPDATE incidents SET generation=2")
        self.db.execute("UPDATE verifications SET status='passed',finished_at=? WHERE action_id IN"
                        " (SELECT id FROM actions WHERE council_grant_id=?)", (now(), ballot["grant_id"]))
        self.court.finish_verification(ballot["grant_id"], recovered=True)
        self.assertIn("verify_failed:old-failure", self.db.query_one("SELECT need_human_reason FROM incidents")[0])

    async def test_planner_request_for_human_persists_without_plan_and_needs_admin_release(self):
        goal = self.court.request_manual_adjudication("inc", reason="Need an operator to inspect physical connectivity")
        self.assertTrue(goal["manual_required"])
        with self.assertRaisesRegex(CouncilError, "manual_adjudication_required"):
            self.plan()
        self.assertEqual(self.court.request_manual_adjudication("inc", reason="Still waiting")["id"], goal["id"])
        self.court.release_manual_barrier("inc", goal["id"], actor="admin")
        self.assertFalse(self.court.snapshot("inc")["manual_required"])
        self.assertEqual(self.plan()["goal_id"], goal["id"])

    async def test_actual_verification_contract_change_requires_new_reviews(self):
        from ayana.verify_profiles import PROFILES
        _, ballot = self.grant()
        with patch.dict(PROFILES, {"svc.recover": replace(PROFILES["svc.recover"], continuous_success_sec=1)}):
            with self.assertRaisesRegex(CouncilError, "verification_contract_changed"):
                await self.court.execute_grant(ballot["grant_id"])
        self.transport.exec.assert_not_called()

    async def test_successful_repair_preserves_later_human_rejection_and_council_manual_hold(self):
        self._old_verification("old-failure", "failed")
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        from ayana.incidents import IncidentService
        IncidentService(self.db).set_need_human("inc", "action_rejected:operator-stop")
        goal = self.court.request_manual_adjudication("inc", reason="Operator needs to inspect a separate risk")
        self.db.execute("UPDATE verifications SET status='passed',finished_at=? WHERE action_id IN"
                        " (SELECT id FROM actions WHERE council_grant_id=?)", (now(), ballot["grant_id"]))
        self.court.finish_verification(ballot["grant_id"], recovered=True)
        reasons = self.db.query_one("SELECT need_human_reason FROM incidents")[0].splitlines()
        self.assertNotIn("verify_failed:old-failure", reasons)
        self.assertIn("action_rejected:operator-stop", reasons)
        self.assertIn(f"council_manual:{goal['id']}", reasons)

    async def test_verified_autonomous_repair_clears_legacy_no_runbook_obligation_and_closes(self):
        from ayana.incidents import IncidentService
        IncidentService(self.db).set_need_human("inc", "no_runbook_match")
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        self.db.execute("UPDATE verifications SET status='passed',finished_at=?", (now(),))
        self.court.finish_verification(ballot["grant_id"], recovered=True)
        inc = self.db.query_one("SELECT * FROM incidents WHERE id='inc'")
        self.assertFalse(inc["need_human"])
        self.assertEqual(inc["status"], "resolved")
        self.assertEqual(inc["outcome"], "recovered")
        self.assertEqual(self.db.query_one("SELECT COUNT(*) FROM audit_log WHERE entry='council_legacy_obligation_superseded'")[0], 1)

    async def test_legacy_no_runbook_llm_suffix_cleanup_preserves_distinct_obligations(self):
        from ayana.incidents import IncidentService
        service = IncidentService(self.db)
        service.set_need_human("inc", "no_runbook_match | llm: the known runbook cannot repair this service")
        service.set_need_human("inc", "manual_review")
        service.set_need_human("inc", "policy_denied:service.reload")
        service.set_need_human("inc", "verify_unknown:unproven")
        service.set_need_human("inc", "no_runbook_match_operator_exception")
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        self.db.execute("UPDATE verifications SET status='passed',finished_at=?", (now(),))
        self.court.finish_verification(ballot["grant_id"], recovered=True)
        reasons = self.db.query_one("SELECT need_human_reason FROM incidents WHERE id='inc'")[0].splitlines()
        self.assertEqual(set(reasons), {"manual_review", "policy_denied:service.reload", "verify_unknown:unproven", "no_runbook_match_operator_exception"})
        self.assertEqual(self.db.query_one("SELECT status FROM incidents WHERE id='inc'")[0], "open")

    async def test_stale_verification_cannot_clear_legacy_runbook_obligation(self):
        from ayana.incidents import IncidentService
        IncidentService(self.db).set_need_human("inc", "no_runbook_match")
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        self.db.execute("UPDATE incidents SET generation=2")
        self.db.execute("UPDATE verifications SET status='passed',finished_at=?", (now(),))
        self.court.finish_verification(ballot["grant_id"], recovered=True)
        self.assertIn("no_runbook_match", self.db.query_one("SELECT need_human_reason FROM incidents WHERE id='inc'")[0])

    async def test_failed_verification_cannot_clear_legacy_runbook_obligation(self):
        from ayana.incidents import IncidentService
        IncidentService(self.db).set_need_human("inc", "no_runbook_match")
        _, ballot = self.grant()
        await self.court.execute_grant(ballot["grant_id"])
        self.db.execute("UPDATE verifications SET status='failed',finished_at=?", (now(),))
        self.assertEqual(self.court.finish_verification(ballot["grant_id"], recovered=True)["state"], "verification_failed")
        self.assertIn("no_runbook_match", self.db.query_one("SELECT need_human_reason FROM incidents WHERE id='inc'")[0])


if __name__ == "__main__":
    unittest.main()
