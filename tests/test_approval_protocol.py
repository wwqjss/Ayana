"""One-action consent, account roles and live authority, without production IO."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from ayana.actions import ActionError, ActionService
from ayana.approval import ApprovalService, parse_approval_reply
from ayana.db import Database, now
from ayana.ntsafe import AssetBinding, NTResult
from ayana.policy import Policy
from ayana.runbook import RUNBOOK, RunbookRule


class Transport:
    def __init__(self):
        self.calls = []

    async def exec(self, asset, tokens, timeout=None):
        self.calls.append((asset, list(tokens)))
        return NTResult(ok=True, output="restarted", returncode=0)


class Gate:
    def get(self, asset):
        return AssetBinding(
            asset_id=asset, read_alias="host-read", write_alias="host-write",
            expected_host_id="HOST", host_id_verified_at=1.0,
        )

    async def verify_account(self, asset, *, write=False):
        return {"ok": True, "mode": "exec", "account": "host-write"}


class ApprovalProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.db.close)
        t = now()
        self.db.execute(
            "INSERT INTO assets(id,display_name,read_alias,write_alias,expected_host_id,"
            " host_id_verified_at,created_at,updated_at) VALUES('host','Host','host-read',"
            " 'host-write','HOST',?,?,?)", (t, t, t),
        )
        for name in ("service-a", "service-b", "ayana"):
            self.db.execute(
                "INSERT INTO objects(id,asset_id,kind,name,unit,created_at)"
                " VALUES(?,'host','service',?,?,?)", (f"host:service:{name}", name, name, t),
            )
        self.db.execute(
            "INSERT INTO incidents(id,title,asset_id,object_id,stage,created_at,updated_at)"
            " VALUES('inc','service down','host','service-a','awaiting_approval',?,?)", (t, t),
        )
        self.policy = Policy(self.db, admin_qq="123", admin_wecom_users=["operator"])
        for username, admin in (("admin", 1), ("viewer", 0)):
            self.db.execute("INSERT INTO users(username,password_hash,is_admin,created_at,updated_at) VALUES(?,'unused',?,?,?)",
                            (username, admin, t, t))
        self.transport = Transport()
        self.actions = ActionService(
            self.db, nt=self.transport, gate=Gate(), policy=self.policy,
            prom=object(), transport=self.transport,
        )
        self.actions._run_verification = AsyncMock()
        self.approval = ApprovalService(self.actions)

    def propose(self, *, object_name="service-a", incident_id="inc", **kwargs):
        return self.actions.propose(
            asset_id="host", object_id=f"host:service:{object_name}",
            capability="service.restart", proposer_type="qq_user", proposer_id="123",
            incident_id=incident_id, **kwargs,
        )["id"]

    def decide(self, choice="execute_once", **kwargs):
        return asyncio.run(self.approval.decide(
            choice, actor_type=kwargs.pop("actor_type", "web_user"),
            actor_id=kwargs.pop("actor_id", "admin"), is_admin=kwargs.pop("is_admin", True),
            **kwargs,
        ))

    def audit(self, entry):
        return [dict(r) for r in self.db.query("SELECT * FROM audit_log WHERE entry=?", (entry,))]

    def auto_proposal(self):
        # P4.4：自动授权永久退役，propose(mode=auto) 必须拒绝
        self.assert_error(
            "legacy_autonomy_retired",
            lambda: self.propose(mode="auto", runbook_id="rb_restart"),
        )
        return None

    def seed_episode(self, health="ok", state="firing"):
        t = now()
        self.db.execute(
            "INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,alertname,status,"
            " asset_id,object_id,incident_id,first_seen,last_seen,source_health,source_state)"
            " VALUES('ep','source','fp','start','TargetDown','firing','host','service-a','inc',?,?,?,?)",
            (t, t, health, state),
        )

    def assert_error(self, code, callback):
        with self.assertRaises(ActionError) as ctx:
            callback()
        self.assertEqual(ctx.exception.code, code)

    def test_reply_parser_requires_entire_unambiguous_reply(self):
        for text in ("执行一次", "  执行这次！ ", "同意执行一次。"):
            self.assertEqual(parse_approval_reply(text), "execute_once")
        for text in ("不执行", "拒绝执行", "跳过这次"):
            self.assertEqual(parse_approval_reply(text), "reject")
        for text in ("永久允许执行", "始终允许执行", "以后自动执行"):
            self.assertEqual(parse_approval_reply(text), "allow_always")
        for text in ("不要永久允许执行", "不执行一次", "执行一次或者不执行", "他说执行一次", "执行一次\n不执行"):
            self.assertIsNone(parse_approval_reply(text))

    def test_execute_once_preserves_permissions_and_human_identity(self):
        aid = self.propose()
        permissions = [dict(r) for r in self.db.query("SELECT * FROM permissions ORDER BY id")]
        result = self.decide(actor_type="wecom_user", actor_id="operator", channel="wecom_aibot")
        self.assertTrue(result["executed"])
        self.assertFalse(result["permanent_granted"])
        self.assertEqual(self.transport.calls, [("host", ["systemctl", "restart", "service-a"])])
        row = self.actions._get(aid)
        self.assertEqual((row["approver_type"], row["approver_id"]), ("wecom_user", "operator"))
        self.assertEqual(row["mode"], "manual")
        self.assertEqual(permissions, [dict(r) for r in self.db.query("SELECT * FROM permissions ORDER BY id")])
        self.assertEqual(self.audit("action_approved")[0]["channel"], "wecom_aibot")
        self.assertEqual(self.audit("action_success")[0]["actor_id"], "operator")

    def test_reject_audits_and_records_generation_suppression(self):
        aid = self.propose()
        self.db.execute(
            "UPDATE incidents SET need_human=1,need_human_reason=? WHERE id='inc'",
            (f"awaiting_approval:{aid} permission_required",),
        )
        result = self.decide("不执行", actor_type="qq_user", actor_id="123", channel="qq")
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.audit("action_rejected")[0]["actor_id"], "123")
        inc = self.db.query_one("SELECT * FROM incidents WHERE id='inc'")
        self.assertEqual(inc["need_human"], 1)
        self.assertIn(f"action_rejected:{aid}", inc["need_human_reason"])
        self.assertNotIn("awaiting_approval:", inc["need_human_reason"])
        self.assert_error("approval_not_found", lambda: self.decide("执行一次"))

    def test_permanent_requests_are_retired_without_mutating_rules_or_settings(self):
        aid = self.propose()
        before_settings = [tuple(r) for r in self.db.query("SELECT * FROM agent_settings ORDER BY key")]
        before_rules = [tuple(r) for r in self.db.query("SELECT * FROM permissions ORDER BY id")]
        for text in ("永久允许执行", "以后自动执行", "allow_always"):
            self.assert_error("permanent_permission_retired", lambda: self.decide(text, action_id=aid))
        self.assertEqual(self.actions._get(aid)["state"], "proposed")
        self.assertEqual(before_settings, [tuple(r) for r in self.db.query("SELECT * FROM agent_settings ORDER BY key")])
        self.assertEqual(before_rules, [tuple(r) for r in self.db.query("SELECT * FROM permissions ORDER BY id")])
        self.assertFalse(self.transport.calls)
        self.assertFalse(self.audit("action_approved"))

    def test_once_ignores_legacy_operation_denies_and_agent_ceiling(self):
        t = now()
        for subject_type, subject_id in (("qq_user", "123"), ("web_user", "admin")):
            self.db.execute("INSERT INTO permissions(subject_type,subject_id,asset_id,capability,object_id,allow,created_at,updated_at) VALUES(?,?,'host','service.restart','*',0,?,?)",
                            (subject_type, subject_id, t, t))
        self.db.execute("INSERT OR REPLACE INTO agent_ceiling(capability,allowed,allow_auto,updated_at,updated_by) VALUES('service.restart',0,0,?,'old')", (t,))
        aid = self.propose()
        result = self.decide(action_id=aid)
        self.assertTrue(result["executed"])
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM permissions WHERE allow=0")["n"], 2)

    def test_revoked_account_cannot_approve(self):
        aid = self.propose()
        self.db.execute("UPDATE users SET is_admin=0 WHERE username='admin'")
        self.assert_error("approve_denied", lambda: self.decide(action_id=aid))
        self.assertEqual(self.actions._get(aid)["state"], "proposed")
        self.assertFalse(self.transport.calls)

    def test_unknown_account_cannot_approve_even_with_admin_flag(self):
        aid = self.propose()
        self.assert_error("approve_denied", lambda: self.decide(actor_id="stranger", is_admin=True))
        self.assertEqual(self.actions._get(aid)["state"], "proposed")

    def test_account_revoked_during_identity_wait_prevents_dispatch(self):
        self.propose()
        async def verify(asset, *, write=False):
            self.db.execute("UPDATE users SET is_admin=0 WHERE username='admin'")
            return {"ok": True, "mode": "exec"}
        self.actions.gate.verify_account = verify
        result = self.decide()
        self.assertEqual(result["error"], "actor_access_revoked")
        self.assertFalse(result["executed"])
        self.assertFalse(self.transport.calls)

    def test_machine_cannot_use_manual_mode_to_avoid_session_authority(self):
        self.assert_error("authority_session_required", lambda: self.actions.propose(
            asset_id="host", object_id="service-a", capability="service.restart",
            proposer_type="auto_rule", proposer_id="agent", mode="manual"))

    def test_autonomous_requires_session_even_when_global_mode_is_automatic(self):
        from ayana.duty_session import DutySessionManager
        DutySessionManager(self.db).set_settings({"auto_access_mode":"readwrite", "auto_approval_mode":"automatic"})
        self.assert_error("authority_session_required", lambda: asyncio.run(self.actions.autonomous_execute(
            asset_id="host", object_id="service-a", capability="service.restart")))

    def test_ambiguous_replies_never_choose_latest_action(self):
        first = self.propose()
        second = self.propose(object_name="service-b", incident_id="")
        self.assert_error("approval_ambiguous", lambda: self.decide())
        self.assertEqual(self.transport.calls, [])
        self.assertTrue(all(self.actions._get(aid)["state"] == "proposed" for aid in (first, second)))
        result = self.decide(action_id=first)
        self.assertTrue(result["executed"])

    def test_old_generation_is_not_approved_even_by_explicit_id(self):
        old = self.propose()
        self.db.event("generation_bumped", incident_id="inc", payload={"generation": 2})
        self.assert_error("approval_not_found", lambda: self.decide(action_id=old))
        self.assertEqual(self.transport.calls, [])

    def test_expired_and_recovered_proposals_cannot_be_selected(self):
        aid = self.propose()
        self.db.execute("UPDATE actions SET approval_deadline=? WHERE id=?", (now() - 1, aid))
        self.assert_error("approval_not_found", lambda: self.decide())
        self.db.execute("UPDATE actions SET approval_deadline=? WHERE id=?", (now() + 100, aid))
        self.db.execute("UPDATE incidents SET status='resolved' WHERE id='inc'")
        self.assert_error("approval_not_found", lambda: self.decide(action_id=aid))
        self.assertEqual(self.transport.calls, [])

    def test_stale_proposal_does_not_make_current_reply_ambiguous(self):
        old = self.propose()
        self.db.event("generation_bumped", incident_id="inc", payload={"generation": 2})
        current = self.propose(object_name="service-b", incident_id="")
        result = self.decide()
        self.assertEqual(result["id"], current)
        self.assertEqual(self.actions._get(old)["state"], "proposed")

    def test_repeated_explicit_decision_does_not_replay(self):
        aid = self.propose()
        self.decide(action_id=aid)
        self.assert_error("approval_not_found", lambda: self.decide("execute_once", action_id=aid))
        self.assertEqual(len(self.transport.calls), 1)
        self.assertFalse(self.audit("permission_auto_allowed_granted"))

    def test_permanent_request_is_retired_for_human_proposals_too(self):
        aid = self.actions.propose(
            asset_id="host", object_id="host:service:service-a", capability="service.restart",
            proposer_type="qq_user", proposer_id="123", incident_id="inc",
        )["id"]
        self.assert_error("permanent_permission_retired", lambda: self.decide("allow_always", action_id=aid))
        self.assertFalse(self.audit("permission_auto_allowed_granted"))

    def test_nonhuman_cannot_use_human_decision_api(self):
        self.propose()
        self.assert_error("human_required", lambda: self.decide(actor_type="auto_rule", actor_id="agent"))
        self.assertEqual(self.transport.calls, [])

    def test_legacy_approval_also_rejects_closed_and_old_generation(self):
        aid = self.propose()
        self.db.execute("UPDATE incidents SET status='resolved' WHERE id='inc'")
        self.assert_error("incident_not_open", lambda: self.actions.approve(aid, approver_id="admin"))
        self.db.execute("UPDATE incidents SET status='open' WHERE id='inc'")
        self.db.event("generation_bumped", incident_id="inc", payload={"generation": 2})
        self.assert_error("stale_generation", lambda: self.actions.approve(aid, approver_id="admin"))
        self.assertEqual(self.actions._get(aid)["state"], "proposed")

    def test_target_recovers_during_identity_wait_prevents_dispatch(self):
        aid = self.propose()

        async def verify(asset, *, write=False):
            await asyncio.sleep(0)
            self.db.execute("UPDATE incidents SET status='resolved' WHERE id='inc'")
            return {"ok": True, "mode": "exec"}

        self.actions.gate.verify_account = verify
        result = self.decide()
        self.assertEqual(result["error"], "incident_not_open")
        self.assertFalse(result["executed"])
        self.assertEqual(self.actions._get(aid)["state"], "cancelled")
        self.assertEqual(self.transport.calls, [])

    def test_generation_changes_during_identity_wait_prevents_dispatch(self):
        aid = self.propose()

        async def verify(asset, *, write=False):
            await asyncio.sleep(0)
            self.db.event("generation_bumped", incident_id="inc", payload={"generation": 2})
            return {"ok": True, "mode": "exec"}

        self.actions.gate.verify_account = verify
        result = self.decide()
        self.assertEqual(result["error"], "stale_generation")
        self.assertEqual(self.actions._get(aid)["state"], "cancelled")
        self.assertEqual(self.transport.calls, [])

    def test_incident_object_changes_during_identity_wait_prevents_dispatch(self):
        self.propose()

        async def verify(asset, *, write=False):
            await asyncio.sleep(0)
            self.db.execute("UPDATE incidents SET object_id='service-b' WHERE id='inc'")
            return {"ok": True, "mode": "exec"}

        self.actions.gate.verify_account = verify
        self.assertEqual(self.decide()["error"], "incident_mismatch")
        self.assertEqual(self.transport.calls, [])

    def test_cancel_obsolete_includes_approved_but_never_dispatched(self):
        aid = self.propose()
        self.actions.approve(aid, approver_id="admin")
        self.assertEqual(self.actions.cancel_pending_for_incident("inc"), 1)
        self.assertEqual(self.actions._get(aid)["state"], "cancelled")
        self.db.execute("UPDATE actions SET state='dispatched' WHERE id=?", (aid,))
        self.assertEqual(self.actions.cancel_pending_for_incident("inc"), 0)
        self.assertEqual(self.actions._get(aid)["state"], "dispatched")

    def test_final_dispatch_gate_blocks_control_plane_even_with_auto_permission(self):
        original = RUNBOOK[:]
        self.addCleanup(lambda: RUNBOOK.__setitem__(slice(None), original))
        rule = RunbookRule(id="rb_control", name="Control", asset_id="host", object_name="ayana",
                           capability="service.restart")
        RUNBOOK[:] = [rule]
        # P4.4：即便 Policy/Runbook 允许，自动授权也永久拒绝
        self.assert_error(
            "legacy_autonomy_retired",
            lambda: self.actions.propose(
                asset_id="host", object_id="host:service:ayana", capability="service.restart",
                proposer_type="auto_rule", proposer_id="agent", mode="auto", runbook_id=rule.id,
                runbook_rev=rule.rev,
            ),
        )
        return
        self.actions.approve(aid, approver_type="auto_rule", approver_id="agent")
        self.assert_error("control_plane_forbidden", lambda: asyncio.run(
            self.actions.execute(aid, actor_type="auto_rule", actor_id="agent"),
        ))
        self.assertEqual(self.transport.calls, [])

    def test_pre_dispatch_failure_requires_human_and_can_resume_without_reapproval(self):
        aid = self.propose()
        self.actions.gate.verify_account = AsyncMock(return_value={"ok": False, "error": "temporary"})
        result = self.decide()
        self.assertFalse(result["executed"])
        self.assertTrue(result["execution_pending"])
        self.assertEqual(self.actions._get(aid)["state"], "approved")
        inc = self.db.query_one("SELECT * FROM incidents WHERE id='inc'")
        self.assertEqual(inc["need_human"], 1)
        self.assertIn(f"execution_blocked:{aid}", inc["need_human_reason"])
        self.assertEqual(self.audit("action_execution_blocked")[0]["actor_id"], "admin")
        self.db.execute(
            "UPDATE incidents SET need_human_reason=need_human_reason || ? WHERE id='inc'",
            ("\nunrelated_manual_review",),
        )
        self.actions.gate.verify_account = AsyncMock(return_value={"ok": True, "mode": "exec"})
        resumed = asyncio.run(self.actions.execute(aid, actor_type="web_user", actor_id="admin"))
        self.assertEqual(resumed["state"], "success")
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(len(self.audit("action_approved")), 1)
        inc = self.db.query_one("SELECT * FROM incidents WHERE id='inc'")
        self.assertNotIn("execution_blocked:", inc["need_human_reason"])
        self.assertIn("unrelated_manual_review", inc["need_human_reason"])

    def test_temporary_source_loss_at_final_gate_never_demands_human(self):
        self.seed_episode()
        self.auto_proposal()
        return  # P4.4: auto 已退役，后续自动路径不再适用
        self.actions.approve(aid, approver_type="auto_rule", approver_id="agent")

        async def verify(asset, *, write=False):
            await asyncio.sleep(0)
            self.db.execute("UPDATE alert_episodes SET source_health='unavailable' WHERE id='ep'")
            return {"ok": True, "mode": "exec"}

        self.actions.gate.verify_account = verify
        self.assert_error("source_unavailable", lambda: asyncio.run(
            self.actions.execute(aid, actor_type="auto_rule", actor_id="agent"),
        ))
        self.assertEqual(self.actions._get(aid)["state"], "cancelled")
        self.assertTrue(self.actions.safe_cancel_pending_auto(aid, reason="source_unavailable"))
        self.assertFalse(self.db.query_one("SELECT need_human FROM incidents WHERE id='inc'")["need_human"])
        self.assertEqual(self.transport.calls, [])

    def test_source_unavailable_at_proposal_is_retryable_but_quarantine_is_hard(self):
        self.auto_proposal()
        return  # P4.4: auto 已退役，后续自动路径不再适用
        self.assertTrue(self.actions.safe_cancel_pending_auto(aid, reason="test_setup"))
        self.seed_episode(health="unavailable")
        self.assert_error("source_unavailable", lambda: self.propose(mode="auto", runbook_id="rb_restart"))
        self.db.execute("UPDATE alert_episodes SET source_state='quarantine' WHERE id='ep'")
        self.assert_error("source_quarantined", lambda: self.propose(mode="auto", runbook_id="rb_restart"))
        self.assertEqual(self.transport.calls, [])

    def test_auto_transient_exception_keeps_human_flag_clear_then_safe_cancels(self):
        self.auto_proposal()
        return  # P4.4: auto 已退役，后续自动路径不再适用
        self.actions.approve(aid, approver_type="auto_rule", approver_id="agent")
        with patch.object(self.actions, "_execute_locked", new=AsyncMock(side_effect=ActionError("object_locked"))):
            self.assert_error("object_locked", lambda: asyncio.run(
                self.actions.execute(aid, actor_type="auto_rule", actor_id="agent"),
            ))
        self.assertEqual(self.actions._get(aid)["state"], "approved")
        self.assertFalse(self.db.query_one("SELECT need_human FROM incidents WHERE id='inc'")["need_human"])
        self.assertTrue(self.actions.safe_cancel_pending_auto(aid, reason="object_locked"))
        self.assertEqual(self.actions._get(aid)["state"], "cancelled")

    def test_safe_auto_cancel_clears_only_its_execution_obligation(self):
        self.auto_proposal()
        return  # P4.4: auto 已退役，后续自动路径不再适用
        self.actions.approve(aid, approver_type="auto_rule", approver_id="agent")
        self.db.execute(
            "UPDATE incidents SET need_human=1,need_human_reason=? WHERE id='inc'",
            (f"execution_blocked:{aid}\nexecution_blocked:other\nmanual_review",),
        )
        self.assertTrue(self.actions.safe_cancel_pending_auto(aid, reason="global_pause"))
        self.assertTrue(self.actions.safe_cancel_pending_auto(aid, reason="global_pause"))
        self.assertEqual(len(self.audit("action_cancelled_for_retry")), 1)
        inc = self.db.query_one("SELECT * FROM incidents WHERE id='inc'")
        self.assertEqual(inc["need_human_reason"], "execution_blocked:other\nmanual_review")
        self.assertTrue(inc["need_human"])

    def test_safe_auto_cancel_never_retires_claimed_unknown_or_manual_actions(self):
        self.auto_proposal()
        return  # P4.4: auto 已退役，后续自动路径不再适用
        for state in ("unknown", "dispatched", "success", "failure"):
            self.db.execute("UPDATE actions SET state=? WHERE id=?", (state, aid))
            self.assertFalse(self.actions.safe_cancel_pending_auto(aid, reason="cooldown"))
            self.assertEqual(self.actions._get(aid)["state"], state)
        self.db.execute("UPDATE actions SET state='approved',dispatched_at=? WHERE id=?", (now(), aid))
        self.assertFalse(self.actions.safe_cancel_pending_auto(aid, reason="cooldown"))
        self.db.execute("UPDATE actions SET state='proposed',dispatched_at=NULL,mode='manual' WHERE id=?", (aid,))
        self.assertFalse(self.actions.safe_cancel_pending_auto(aid, reason="cooldown"))


if __name__ == "__main__":
    unittest.main()
