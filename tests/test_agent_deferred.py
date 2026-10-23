"""自动处置限速只等待；只有真实授权请求才创建待批准操作。"""
from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_phase_d_p1 import close_env, make_env
from ayana.actions import ActionError
from ayana.db import new_id, now
from ayana.runbook import get_runbook_rule


class AgentDeferredTests(unittest.TestCase):
    def env(self, **kwargs):
        env = make_env(auto_rule=(True, False, True), auto_enabled=True, **kwargs)
        tmp, db, _, _, _, _, _, _, _ = env
        self.addCleanup(close_env, tmp, db)
        return env

    def usage(self, db, at, object_id="frps"):
        db.execute(
            "INSERT INTO actions(id,asset_id,object_id,capability,state,mode,created_at,dispatched_at)"
            " VALUES(?,'nerv',?,'service.restart','success','auto',?,?)",
            (new_id("act"), object_id, at, at),
        )

    def source(self, db, health="ok"):
        db.execute(
            "INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,alertname,status,"
            " asset_id,object_id,incident_id,first_seen,last_seen,source_health)"
            " VALUES('source','am','fp','start','TargetDown','firing','nerv','frps','inc1',?,?,?)",
            (now(), now(), health),
        )

    def test_cooldown_waits_without_approval_and_dispatches_when_due(self):
        _, db, _, _, prom, _, _, agent, _ = self.env()
        t = now()
        self.usage(db, t - 600)
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["decision"], "automatic")
        self.assertEqual(result["action"], "waiting_precondition")
        self.assertAlmostEqual(result["retry_at"], t + 1200, places=2)
        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM actions WHERE incident_id='inc1'")["n"], 0)
        inc = dict(db.query_one("SELECT * FROM incidents WHERE id='inc1'"))
        self.assertEqual((inc["stage"], inc["need_human"]), ("watching", 0))
        self.assertIn("冷却中", agent.notifier.sent[0]["body"])
        self.assertNotIn("执行一次", agent.notifier.sent[0]["body"])
        agent.investigation.run_loop = AsyncMock(return_value={"evidence": []})
        agent._auto_dispatch = AsyncMock(return_value={"action": "success"})
        repeated = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(repeated["action"], "waiting_precondition")
        agent.investigation.run_loop.assert_not_awaited()
        due = result["retry_at"] + 1
        prom.samples[0]["sample_at"] = due
        with patch("ayana.agent.now", return_value=due):
            resumed = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(resumed["action"], "success")
        agent._auto_dispatch.assert_awaited_once()
        self.assertEqual(len(agent.notifier.sent), 1)

    def test_daily_budget_retry_is_expiry_of_oldest_retained_usage(self):
        _, db, _, _, _, _, _, agent, _ = self.env()
        t = now()
        for offset in (1200, 1000, 800, 600):
            self.usage(db, t - offset)
        ok, reason, retry_at = agent._budget_state(
            get_runbook_rule("rb_frps_down_restart"), "nerv", "frps",
        )
        self.assertFalse(ok)
        self.assertIn("24小时执行上限", reason)
        self.assertAlmostEqual(retry_at, t - 1000 + 86400, places=2)

    def test_budget_matches_both_object_name_and_reference(self):
        _, db, _, _, _, _, _, agent, _ = self.env()
        self.usage(db, now() - 60, "nerv:service:frps")
        rule = get_runbook_rule("rb_frps_down_restart")
        for oid in ("frps", "nerv:service:frps"):
            self.assertFalse(agent._budget_state(rule, "nerv", oid)[0])

    def test_missing_probe_waits_and_remains_eligible(self):
        _, db, _, nt, _, _, _, agent, _ = self.env(probe_value=None)
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "waiting_precondition")
        self.assertFalse(nt.exec_calls)
        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)
        self.assertEqual(db.query_one("SELECT need_human FROM incidents")["need_human"], 0)

    def test_pause_waits_without_approval(self):
        _, db, _, nt, _, _, _, agent, _ = self.env()
        db.execute("UPDATE global_stops SET enabled=1 WHERE key='auto_dispatch'")
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "waiting_precondition")
        self.assertFalse(nt.exec_calls)
        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)

    def test_authorization_request_contains_reply_protocol(self):
        tmp, db, _, nt, _, _, _, agent, _ = make_env(
            auto_rule=(True, True, False), auto_enabled=True,
        )
        self.addCleanup(close_env, tmp, db)
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "awaiting_approval")
        self.assertFalse(nt.exec_calls)
        body = agent.notifier.sent[-1]["body"]
        for phrase in ("需要你授权", "执行一次", "不执行", "永久允许执行"):
            self.assertIn(phrase, body)
        self.assertNotIn(result["action_id"], body)

    def test_waiting_incidents_do_not_starve_ready_incidents(self):
        _, db, _, _, _, _, _, agent, _ = self.env()
        self.usage(db, now() - 60)
        asyncio.run(agent.handle_incident("inc1"))
        for i in range(2, 6):
            db.execute(
                "INSERT INTO incidents(id,title,asset_id,object_id,status,stage,created_at,updated_at)"
                " VALUES(?, 'other', 'nerv', ?, 'open','pending',?,?)",
                (f"inc{i}", f"svc{i}", now() + i, now() + i),
            )
        self.assertEqual(agent.ready_incident_ids(3), ["inc2", "inc3", "inc4"])

    def test_wait_is_persisted_but_does_not_cross_generation(self):
        _, db, _, _, _, _, _, agent, _ = self.env()
        self.usage(db, now() - 60)
        asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(agent.ready_incident_ids(), [])
        db.execute("UPDATE incidents SET generation=generation+1,stage='pending' WHERE id='inc1'")
        self.assertEqual(agent.ready_incident_ids(), ["inc1"])

    def test_human_rejection_blocks_only_current_generation(self):
        tmp, db, _, nt, _, _, actions, agent, _ = make_env(
            auto_rule=(True, True, False), auto_enabled=True,
        )
        self.addCleanup(close_env, tmp, db)
        first = asyncio.run(agent.handle_incident("inc1"))
        actions.reject(first["action_id"], actor_type="web_user", actor_id="admin", reason="skip")
        second = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(second["action"], "skipped_rejected")
        self.assertFalse(nt.exec_calls)
        db.execute("UPDATE incidents SET generation=2,need_human=0,stage='pending' WHERE id='inc1'")
        db.event("generation_bumped", incident_id="inc1", payload={"generation": 2})
        third = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(third["action"], "awaiting_approval")
        self.assertNotEqual(first["action_id"], third["action_id"])

    def test_control_plane_cannot_enter_auto_dispatch(self):
        _, db, _, nt, _, _, _, agent, _ = self.env()
        db.execute("UPDATE incidents SET object_id='ayana',title='nerv / ayana: TargetDown' WHERE id='inc1'")
        agent._auto_dispatch = AsyncMock(return_value={"action": "unsafe"})
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "escalated")
        agent._auto_dispatch.assert_not_awaited()
        self.assertFalse(nt.exec_calls)

    def test_latest_recovered_probe_overrides_earlier_failure(self):
        _, db, _, nt, prom, _, _, agent, _ = self.env()
        prom.samples.append({
            "metric": {"asset": "nerv", "service": "frps"},
            "value": 1, "sample_at": now(),
        })
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "waiting_precondition")
        self.assertFalse(nt.exec_calls)
        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)

    def test_service_state_requirement_uses_matching_observed_evidence(self):
        _, _, _, _, _, _, _, agent, _ = self.env()
        get_runbook_rule("rb_frps_down_restart").require_service_state = "inactive"
        agent.investigation.run_loop = AsyncMock(return_value={"evidence": [{
            "classification": "observed", "object_id": "frps", "ok": True,
            "observed": {"service_state": "inactive"},
        }]})
        agent._auto_dispatch = AsyncMock(return_value={"action": "success"})
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "success")
        agent._auto_dispatch.assert_awaited_once()

    def test_unknown_write_requires_human_adjudication(self):
        _, db, _, nt, _, _, _, agent, _ = self.env()
        self.usage(db, now() - 3600, "nerv:service:frps")
        db.execute("UPDATE actions SET state='unknown'")
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "escalated_precondition")
        self.assertFalse(nt.exec_calls)
        self.assertEqual(db.query_one("SELECT need_human FROM incidents")["need_human"], 1)

    def test_other_incident_verification_holds_object_until_finished(self):
        _, db, _, nt, _, _, _, agent, _ = self.env()
        self.usage(db, now() - 3600, "nerv:service:frps")
        old = db.query_one("SELECT id FROM actions")["id"]
        db.execute(
            "INSERT INTO verifications(id,action_id,status,started_at) VALUES('ver_old',?,'pending',?)",
            (old, now()),
        )
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "waiting_precondition")
        self.assertFalse(nt.exec_calls)
        self.assertEqual(db.query_one("SELECT need_human FROM incidents")["need_human"], 0)

    def test_pause_racing_dispatch_returns_to_waiting(self):
        _, db, _, nt, _, gate, _, agent, _ = self.env()
        async def pause_at_identity(*args, **kwargs):
            db.execute("UPDATE global_stops SET enabled=1 WHERE key='auto_dispatch'")
            return {"ok": True, "mode": "exec"}
        gate.verify_account = AsyncMock(side_effect=pause_at_identity)
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "waiting_precondition")
        self.assertFalse(nt.exec_calls)
        self.assertEqual(db.query_one("SELECT state FROM actions")["state"], "cancelled")
        self.assertEqual(db.query_one("SELECT need_human FROM incidents")["need_human"], 0)

    def test_disabled_auto_keeps_explicit_manual_confirmation(self):
        _, db, _, nt, _, _, _, agent, _ = self.env()
        agent.set_auto_enabled(False)
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "awaiting_approval")
        self.assertEqual(db.query_one("SELECT mode FROM actions")["mode"], "manual")
        self.assertFalse(nt.exec_calls)

    def test_proposal_has_one_persistent_notification_obligation(self):
        tmp, db, _, _, _, _, _, agent, _ = make_env(
            auto_rule=(True, True, False), auto_enabled=True,
        )
        self.addCleanup(close_env, tmp, db)
        result = asyncio.run(agent.handle_incident("inc1"))
        rule = get_runbook_rule("rb_frps_down_restart")
        agent._notify_awaiting_approval("inc1", result["action_id"], rule, {}, {})
        events = db.query("SELECT payload_json FROM events WHERE type='proposal_waiting'")
        self.assertEqual(len(events), 1)
        payload = json.loads(events[0]["payload_json"])
        self.assertEqual(payload["generation"], 1)
        self.assertEqual(payload["action_id"], result["action_id"])
        self.assertIn("执行一次", payload["body"])

    def test_notification_exception_does_not_turn_success_into_escalation(self):
        _, db, _, _, _, _, _, agent, _ = self.env()
        class FailingNotify:
            def enqueue_for_event(self, *args, **kwargs):
                raise RuntimeError("temporary channel failure")
        agent.notifier = FailingNotify()
        with self.assertLogs("ayana.agent", level="ERROR"):
            result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "success")
        event = db.query_one("SELECT payload_json FROM events WHERE type='agent_auto_exec'")
        payload = json.loads(event["payload_json"])
        self.assertIn("自动处置", payload["body"])
        self.assertEqual(db.query_one("SELECT need_human FROM incidents")["need_human"], 0)

    def test_unavailable_source_waits_then_recovers_without_human_reset(self):
        _, db, _, nt, prom, _, _, agent, _ = self.env()
        self.source(db, "unavailable")
        agent.investigation.run_loop = AsyncMock(return_value={"evidence": []})
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "waiting_precondition")
        agent.investigation.run_loop.assert_not_awaited()
        self.assertFalse(nt.exec_calls)
        self.assertEqual(db.query_one("SELECT need_human FROM incidents")["need_human"], 0)
        db.execute("UPDATE alert_episodes SET source_health='ok'")
        due = result["retry_at"] + 1
        prom.samples[0]["sample_at"] = due
        agent._auto_dispatch = AsyncMock(return_value={"action": "success"})
        with patch("ayana.agent.now", return_value=due):
            resumed = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(resumed["action"], "success")

    def test_source_becomes_unavailable_at_dispatch_cancels_and_waits(self):
        _, db, _, nt, _, gate, _, agent, _ = self.env()
        self.source(db)
        async def source_fails(*args, **kwargs):
            db.execute("UPDATE alert_episodes SET source_health='unavailable'")
            return {"ok": True, "mode": "exec"}
        gate.verify_account = AsyncMock(side_effect=source_fails)
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "waiting_precondition")
        self.assertFalse(nt.exec_calls)
        self.assertEqual(db.query_one("SELECT state FROM actions")["state"], "cancelled")
        self.assertEqual(db.query_one("SELECT need_human FROM incidents")["need_human"], 0)
        self.assertEqual(db.query_one("SELECT stage FROM incidents")["stage"], "watching")

    def test_retryable_error_retires_unclaimed_approved_action_and_its_obligation(self):
        _, db, _, nt, _, _, actions, agent, incidents = self.env()
        async def refused(action_id, **kwargs):
            incidents.set_need_human("inc1", f"execution_blocked:{action_id}")
            raise ActionError("object_locked", "concurrent operation")
        actions.execute = AsyncMock(side_effect=refused)
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "waiting_precondition")
        self.assertEqual(db.query_one("SELECT state FROM actions")["state"], "cancelled")
        inc = db.query_one("SELECT * FROM incidents")
        self.assertEqual((inc["need_human"], inc["stage"]), (0, "watching"))
        self.assertFalse(nt.exec_calls)
        with patch("ayana.agent.now", return_value=result["retry_at"] + 1):
            self.assertIn("inc1", agent.ready_incident_ids())

    def test_equal_timestamp_previous_generation_rejection_does_not_block(self):
        tmp, db, _, _, _, _, actions, agent, _ = make_env(
            auto_rule=(True, True, False), auto_enabled=True,
        )
        self.addCleanup(close_env, tmp, db)
        first = asyncio.run(agent.handle_incident("inc1"))
        actions.reject(first["action_id"], actor_type="web_user", actor_id="admin")
        created = db.query_one("SELECT created_at FROM actions")["created_at"]
        db.execute("UPDATE incidents SET generation=2,need_human=0,stage='pending'")
        event_id = db.event("generation_bumped", incident_id="inc1", payload={"generation": 2})
        db.execute("UPDATE events SET at=? WHERE id=?", (created, event_id))
        second = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(second["action"], "awaiting_approval")
        self.assertNotEqual(first["action_id"], second["action_id"])


if __name__ == "__main__":
    unittest.main()
