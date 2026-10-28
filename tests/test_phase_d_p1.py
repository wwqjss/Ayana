"""Phase D: P1-01 人工闭环 + P1-03 对账/关联/时间线。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import aiohttp.web  # noqa: F401
except Exception:
    _a = types.ModuleType("aiohttp")

    class _CT:
        def __init__(self, **k):
            pass

    class _CS:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def post(self, *a, **k):
            raise RuntimeError("no net")

    _a.ClientTimeout = _CT
    _a.ClientSession = _CS
    _a.web = types.SimpleNamespace(
        Application=type("Application", (), {"__init__": lambda self, **k: None}),
        Response=type("Response", (), {"__init__": lambda self, *a, **k: None}),
        json_response=lambda *a, **k: None,
    )
    sys.modules["aiohttp"] = _a
    sys.modules["aiohttp.web"] = _a.web

from ayana.actions import ActionError, ActionService
from ayana.agent import AgentLoop
from ayana.notification_obligations import NotificationObligations
from ayana.legacy_history import RetiredAutonomyError
from ayana.alertmanager import (
    AlertIngest,
    normalize_starts_at,
    problem_family_of,
)
from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.investigation import InvestigationService
from ayana.knowledge import KnowledgeBase
from ayana.ntsafe import AssetBinding, IdentityGate, NTResult
from ayana.policy import Policy
from ayana.runbook import RunbookRule, apply_runbook_rules, match_runbook


class FakeNT:
    def __init__(self, describe_json: str | None = None):
        self.exec_calls = []
        self.describe_json = describe_json or (
            '{"user":"nt-exec","mode":"exec","uid":1,"host_id":"NERV","protocol_version":2}'
        )

    async def describe(self, alias):
        return NTResult(ok=True, output=self.describe_json)

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"nt-exec","mode":"exec","uid":1}')

    async def probe(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="ok", returncode=0)

    async def exec(self, alias, tokens, timeout=None):
        self.exec_calls.append((alias, list(tokens)))
        return NTResult(ok=True, output="ok", returncode=0)


class FakeProm:
    def __init__(self, probe_value: int | None = 0):
        self.since_calls = []
        self.probe_value = probe_value
        self.samples = []
        if probe_value is not None:
            self.samples = [
                {
                    "metric": {"asset": "nerv", "service": "frps"},
                    "value": probe_value,
                    "sample_at": now() - 10,
                }
            ]

    async def probe_success_since(self, asset, service="", *, start, end=None, step=15.0,
                                  window_sec=None, max_window_sec=600.0):
        self.since_calls.append({"asset": asset, "service": service, "start": start})
        out = []
        for s in self.samples:
            ts = s.get("sample_at")
            if ts is None or float(ts) <= float(start):
                continue
            labels = s.get("metric") or {}
            if labels.get("asset") != asset:
                continue
            if service and labels.get("service") != service:
                continue
            out.append(s)
        return out

    async def probe_success(self, asset, service=""):
        return {"result": list(self.samples), "evaluated_at": now()}


class Gate:
    def __init__(self, nt, verified=True, host_id="NERV"):
        self.nt = nt
        self.binding = AssetBinding(
            asset_id="nerv", read_alias="nerv", write_alias="nerv-exec",
            expected_host_id=host_id if verified else "",
            host_id_verified_at=1.0 if verified else None,
        )
        self.gate = IdentityGate(nt, [self.binding])

    def get(self, asset_id):
        return self.gate.get(asset_id)

    async def verify_account(self, asset_id, *, write=False):
        return await self.gate.verify_account(asset_id, write=write)


class NoLLM:
    enabled = False

    async def analyze_incident(self, **kw):
        return None


class NQ:
    def __init__(self):
        self.sent = []

    def enqueue(self, **kw):
        self.sent.append(kw)


def make_env(
    *,
    auto_rule: tuple[bool, bool, bool] = (True, True, False),
    probe_value: int | None = 0,
    auto_enabled: bool = False,
    with_incident: bool = True,
):
    """auto_rule = (allow, require_approval, auto_allowed)"""
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "t.db")
    t = now()
    db.execute(
        "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
        " host_id_verified_at, prom_asset, enabled, notes, created_at, updated_at)"
        " VALUES(?,?,?,?,?,?,?,1,'',?,?)",
        ("nerv", "NERV", "nerv", "nerv-exec", "NERV", t, "nerv", t, t),
    )
    db.execute(
        "INSERT INTO objects(id, asset_id, kind, name, unit, container, port, protocol,"
        " external_probe, auto_recover, created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("nerv:service:frps", "nerv", "service", "frps", "frps", "", None, "", "", 1, t),
    )
    db.execute(
        "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
        " VALUES('admin','x',0,1,?,?)",
        (now(), now()),
    )

    # Unified model: account roles only (admin web / configured QQ operator).
    # The retired auto_rule tuple no longer grants anything.
    policy = Policy(db, admin_qq="10001")
    nt = FakeNT()
    prom = FakeProm(probe_value=probe_value)
    gate = Gate(nt)
    actions = ActionService(db, nt, gate, policy, prom, verify_timeout=1, verify_window=5)
    if with_incident:
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
            " need_human, summary, generation, outcome, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("inc1", "nerv / frps: TargetDown", "nerv", "frps", "warning", "open", "pending",
             0, "", 1, "", t, t),
        )
    inv = InvestigationService(db, nt, gate, prom, policy)
    agent = NotificationObligations(db, NQ())
    incidents = IncidentService(db)
    # 注入测试本地 runbook 规则（发行版 RUNBOOK 为空）
    rule = seed_runbook_rule()
    apply_runbook_rules([{
        "id": rule.id, "name": rule.name, "asset_id": rule.asset_id,
        "object_name": rule.object_name, "alertname": rule.alertname,
        "capability": rule.capability, "reason": rule.reason,
        "require_probe_fail": rule.require_probe_fail,
    }])
    return tmp, db, policy, nt, prom, gate, actions, agent, incidents


def close_env(tmp, db):
    apply_runbook_rules([])
    try:
        db.close()
    except Exception:
        pass
    try:
        tmp.cleanup()
    except Exception:
        pass


def seed_runbook_rule():
    return RunbookRule(
        id="rb_frps_down_restart",
        name="frps down restart",
        asset_id="nerv",
        object_name="frps",
        alertname="TargetDown",
        capability="service.restart",
        reason="restart frps",
        require_probe_fail=True,
    )


# ---------------------------------------------------------------------------
# P1-01 人工闭环
# ---------------------------------------------------------------------------

class TestP101HumanLoop(unittest.TestCase):
    def test_forbidden_no_proposal(self):
        tmp, db, policy, nt, prom, gate, actions, obligations, incidents = make_env(auto_rule=(False, True, False), probe_value=0)
        self.addCleanup(close_env, tmp, db)
        with self.assertRaises(ActionError):
            actions.propose(asset_id="nerv",object_id="frps",capability="service.restart",reason="explicit request",incident_id="inc1",proposer_type="auto_rule",proposer_id="agent",mode="manual",template_id="tmpl_service_restart")
        self.assertFalse(nt.exec_calls)
        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM actions")["n"],0)

    def test_approval_required_proposal_zero_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions, obligations, incidents = make_env(auto_rule=(True, True, False), probe_value=0, auto_enabled=False)
        self.addCleanup(close_env,tmp,db)
        prop=actions.propose(asset_id="nerv",object_id="frps",capability="service.restart",reason="human request",incident_id="inc1",proposer_type="web_user",proposer_id="admin",mode="manual",template_id="tmpl_service_restart")
        obligations._notify_awaiting_approval("inc1",prop["id"],seed_runbook_rule(),{"decision":"approval_required"},{"status":"satisfied"})
        self.assertFalse(nt.exec_calls)
        row=db.query_one("SELECT * FROM actions")
        self.assertEqual((row["state"],row["mode"]),("proposed","manual"))
        self.assertTrue(db.query_one("SELECT need_human FROM incidents")["need_human"])

    def test_approve_exactly_one_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions, agent, incidents = make_env(
            auto_rule=(True, True, False), probe_value=0
        )
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="t", incident_id="inc1", proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        res = asyncio.run(actions.approve_and_execute(
            prop["id"], actor_type="web_user", actor_id="admin", channel="web",
        ))
        self.assertTrue(res.get("executed") or res.get("state") in ("success", "unknown"),
                        res)
        self.assertEqual(len(nt.exec_calls), 1)
        row = db.query_one("SELECT * FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["state"], "success")

    def test_reject_zero_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions, agent, incidents = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="t", incident_id="inc1", proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        res = actions.reject(
            prop["id"], actor_type="web_user", actor_id="admin", channel="web",
            reason="not now",
        )
        self.assertEqual(res["state"], "cancelled")
        self.assertFalse(nt.exec_calls)
        row = db.query_one("SELECT * FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["state"], "cancelled")
        self.assertIn("rejected", row["result_detail"])
        # 审批记录
        aud = db.query_one(
            "SELECT * FROM audit_log WHERE action_id=? AND entry='action_rejected'",
            (prop["id"],),
        )
        self.assertIsNotNone(aud)

    def test_duplicate_approve_no_duplicate_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions, agent, incidents = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="t", incident_id="inc1", proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        r1 = asyncio.run(actions.approve_and_execute(
            prop["id"], actor_type="web_user", actor_id="admin", channel="web",
        ))
        r2 = asyncio.run(actions.approve_and_execute(
            prop["id"], actor_type="qq_user", actor_id="10001", channel="qq",
        ))
        self.assertEqual(len(nt.exec_calls), 1, (r1, r2))
        self.assertTrue(r2.get("already") or r2.get("idempotent"))

    def test_natural_recovery_cancels_proposal(self):
        tmp, db, policy, nt, prom, gate, actions, agent, incidents = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="t", incident_id="inc1", proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        # 自然恢复
        n = incidents._cancel_pending_proposals("inc1", "incident_recovered")
        self.assertGreaterEqual(n, 1)
        row = db.query_one("SELECT * FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["state"], "cancelled")
        self.assertIn("stale", row["result_detail"])
        # 过时 proposal 不执行
        with self.assertRaises(ActionError):
            asyncio.run(actions.approve_and_execute(
                prop["id"], actor_type="web_user", actor_id="admin",
            ))
        self.assertFalse(nt.exec_calls)

    def test_expired_proposal_no_execute(self):
        tmp, db, policy, nt, prom, gate, actions, agent, incidents = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="t", incident_id="inc1", proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        db.execute(
            "UPDATE actions SET approval_deadline=? WHERE id=?",
            (now() - 10, prop["id"]),
        )
        n = actions.expire_stale_proposals()
        self.assertGreaterEqual(n, 1)
        row = db.query_one("SELECT state FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["state"], "expired")
        self.assertFalse(nt.exec_calls)

    def test_policy_tightened_after_approval_blocks_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions, agent, incidents = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="t", incident_id="inc1", proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        actions.approve(prop["id"], approver_type="web_user", approver_id="admin",
                        channel="web")
        # 批准后撤权（管理员降为 viewer）——派发门复查账号角色
        db.execute("UPDATE users SET is_admin=0 WHERE username='admin'")
        with self.assertRaises(ActionError) as ctx:
            asyncio.run(actions.execute(prop["id"], actor_type="web_user",
                                        actor_id="admin", is_admin=True))
        self.assertEqual(ctx.exception.code, "actor_access_revoked")
        self.assertFalse(nt.exec_calls)

    def test_web_qq_same_service_semantics(self):
        tmp, db, policy, nt, prom, gate, actions, agent, incidents = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="t", incident_id="inc1", proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        # QQ 批准 → 同一 approve_and_execute
        res_qq = asyncio.run(actions.approve_and_execute(
            prop["id"], actor_type="qq_user", actor_id="10001", channel="qq",
        ))
        self.assertEqual(len(nt.exec_calls), 1)
        self.assertEqual(res_qq.get("channel"), "qq")
        # 再来一次 Web 批准 → 幂等
        res_web = asyncio.run(actions.approve_and_execute(
            prop["id"], actor_type="web_user", actor_id="admin", channel="web",
        ))
        self.assertEqual(len(nt.exec_calls), 1)
        self.assertTrue(res_web.get("already") or res_web.get("idempotent"))
        # 审批记录含 channel
        aud = db.query_one(
            "SELECT detail_json FROM audit_log WHERE action_id=? AND entry='action_approved'"
            " ORDER BY at DESC LIMIT 1",
            (prop["id"],),
        )
        self.assertIn("qq", aud["detail_json"])

    def test_auto_off_still_investigates_and_proposes(self):
        """Retired automatic entry leaves explicit read investigation/manual actions intact."""
        tmp, db, policy, nt, prom, gate, actions, obligations, incidents = make_env(auto_rule=(True, True, False),probe_value=0,auto_enabled=False)
        self.addCleanup(close_env,tmp,db)
        with self.assertRaises(RetiredAutonomyError):
            AgentLoop(db,None,actions,policy,None,None,auto_enabled=False)
        inv=InvestigationService(db,nt,gate,prom,policy)
        asyncio.run(inv.run(incident_id="inc1",asset_id="nerv",object_id="frps",actor_type="web_user",actor_id="admin",capability="asset.summary"))
        prop=actions.propose(asset_id="nerv",object_id="frps",capability="service.restart",reason="human request",incident_id="inc1",proposer_type="web_user",proposer_id="admin",mode="manual",template_id="tmpl_service_restart")
        self.assertGreaterEqual(db.query_one("SELECT COUNT(*) n FROM investigations")["n"],1)
        self.assertEqual(actions.get_action(prop["id"])["state"],"proposed")
        self.assertFalse(nt.exec_calls)

    def test_policy_three_state_values(self):
        """Unified tiers: read=automatic, write=approval, automation=session-only."""
        tmp, db, policy, nt, prom, gate, actions, agent, incidents = make_env()
        self.addCleanup(close_env, tmp, db)
        d1 = policy.effective_decision(
            subject_type="web_user", subject_id="admin", capability="service.logs",
            asset_id="nerv", object_id="nerv:service:frps",
        )
        self.assertEqual(d1["decision"], "automatic")
        self.assertFalse(d1["require_approval"])
        d2 = policy.effective_decision(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps",
        )
        self.assertEqual(d2["decision"], "approval_required")
        self.assertTrue(d2["require_approval"])
        d3 = policy.effective_decision(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", auto=True,
        )
        self.assertFalse(d3["allowed"])
        self.assertEqual(d3["reason"], "trusted_session_context_required")
        db.execute(
            "INSERT INTO users(username,password_hash,is_admin,created_at,updated_at)"
            " VALUES('viewer','x',0,?,?)",
            (now(), now()),
        )
        d4 = policy.effective_decision(
            subject_type="web_user", subject_id="viewer", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps",
        )
        self.assertFalse(d4["allowed"])
        self.assertEqual(d4["reason"], "admin_required")
        d5 = policy.effective_decision(
            subject_type="auto_rule", subject_id="agent", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps",
        )
        self.assertFalse(d5["allowed"])
        self.assertEqual(d5["reason"], "trusted_session_context_required")

    def test_approval_records_actor_channel_timestamp(self):
        tmp, db, policy, nt, prom, gate, actions, agent, incidents = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="t", incident_id="inc1", proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        actions.approve(
            prop["id"], approver_type="qq_user", approver_id="10001",
            channel="qq", reason="ok",
        )
        row = db.query_one("SELECT * FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["approver_type"], "qq_user")
        self.assertEqual(row["approver_id"], "10001")
        self.assertEqual(row["decision_channel"], "qq")
        self.assertEqual(row["decision_reason"], "ok")
        self.assertIsNotNone(row["decided_at"])
        self.assertTrue(row["decision_snapshot_json"])


# ---------------------------------------------------------------------------
# P1-03 reconciliation / correlation / timeline
# ---------------------------------------------------------------------------

def am_alert(labels=None, status="firing", starts="2026-10-07T10:00:00Z"):
    return {
        "labels": labels or {
            "alertname": "TargetDown",
            "asset": "nerv",
            "service": "frps",
        },
        "annotations": {},
        "status": status,
        "startsAt": starts,
    }


class TestP103Reconcile(unittest.TestCase):
    def _env(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        t = now()
        db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
            " host_id_verified_at, prom_asset, enabled, notes, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,1,'',?,?)",
            ("nerv", "NERV", "nerv", "nerv-exec", "NERV", t, "nerv", t, t),
        )
        db.execute(
            "INSERT INTO objects(id, asset_id, kind, name, unit, container, port, protocol,"
            " external_probe, auto_recover, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("nerv:service:frps", "nerv", "service", "frps", "frps", "", None, "", "", 1, t),
        )
        incidents = IncidentService(db)
        ingest = AlertIngest(db)
        ingest.set_incidents(incidents)
        return tmp, db, ingest, incidents

    def test_am_firing_enters_and_updates_episode(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        r1 = ingest.ingest_webhook({"alerts": [am_alert()]})
        self.assertEqual(r1["created"], 1)
        ep = db.query_one("SELECT * FROM alert_episodes")
        self.assertEqual(ep["status"], "firing")
        self.assertEqual(ep["source_state"], "firing")
        self.assertIsNotNone(ep["last_reconciled_at"])
        # 再次接收 → 更新不新建
        r2 = ingest.ingest_webhook({"alerts": [am_alert()]})
        self.assertEqual(r2["created"], 0)
        self.assertEqual(r2["updated"], 1)
        ep2 = db.query_one("SELECT * FROM alert_episodes")
        self.assertEqual(ep2["id"], ep["id"])
        self.assertGreaterEqual(ep2["receive_count"], 2)

    def test_am_absence_not_auto_recovered(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        ingest.ingest_webhook({"alerts": [am_alert()]})
        # AM 对账为空
        res = ingest.reconcile([], source_ok=True)
        self.assertGreaterEqual(res["not_seen"], 1)
        ep = db.query_one("SELECT * FROM alert_episodes")
        self.assertEqual(ep["status"], "firing")
        self.assertEqual(ep["source_state"], "not_seen")
        inc = db.query_one("SELECT * FROM incidents")
        self.assertIsNotNone(inc)
        self.assertEqual(inc["status"], "open")
        self.assertNotEqual(inc["outcome"], "recovered")

    def test_source_unavailable_not_resolved(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        ingest.ingest_webhook({"alerts": [am_alert()]})
        res = ingest.reconcile([], source_ok=False)
        self.assertFalse(res["source_ok"])
        ep = db.query_one("SELECT * FROM alert_episodes")
        self.assertEqual(ep["status"], "firing")
        self.assertEqual(ep["source_health"], "unavailable")

    def test_fresh_recovery_evidence_allows_recovered(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        ingest.ingest_webhook({"alerts": [am_alert()]})
        inc = db.query_one("SELECT * FROM incidents")
        inc_id = inc["id"]
        # AM 明确报告目标恢复即闭环；不同于 source unavailable/not_seen。
        ingest.ingest_webhook({"alerts": [am_alert(status="resolved")]})
        mid = incidents.reconcile(inc_id, resolution_basis="alert_only")
        self.assertEqual(mid.get("outcome"), "recovered")
        self.assertEqual(mid.get("resolution_basis"), "target_recovered")
        # 后到的 passed verification 不改写目标恢复事实。
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, state, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("act1", inc_id, "nerv", "nerv:service:frps", "service.restart",
             "{}", "success", now(), now()),
        )
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, generation,"
            " started_at) VALUES(?,?,?,?,?,?)",
            ("ver1", "act1", inc_id, "passed", 1, now()),
        )
        res = incidents.reconcile(inc_id, resolution_basis="fresh_recovery")
        self.assertEqual(res["status"], "resolved")
        self.assertEqual(res["outcome"], "recovered")
        self.assertEqual(res["resolution_basis"], "target_recovered")

    def test_event_bound_to_episode_and_incident(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        ingest.ingest_webhook({"alerts": [am_alert()]})
        ep = db.query_one("SELECT * FROM alert_episodes")
        self.assertTrue(ep["incident_id"])
        ev = db.query_one(
            "SELECT * FROM events WHERE episode_id=? AND type='alert_fired'", (ep["id"],)
        )
        self.assertIsNotNone(ev)
        # _sync 后应回填 incident_id
        self.assertEqual(ev["incident_id"], ep["incident_id"])

    def test_recurrence_generation_correct(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        ingest.ingest_webhook({"alerts": [am_alert()]})
        inc1 = db.query_one("SELECT * FROM incidents WHERE object_id='frps'")
        self.assertEqual(inc1["generation"], 1)
        inc_id = inc1["id"]
        # 验证恢复 + episode resolved
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, state, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("act1", inc_id, "nerv", "nerv:service:frps", "service.restart",
             "{}", "success", now(), now()),
        )
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, generation,"
            " started_at) VALUES(?,?,?,?,?,?)",
            ("ver1", "act1", inc_id, "passed", 1, now()),
        )
        ingest.ingest_webhook({"alerts": [am_alert(status="resolved")]})
        row = db.query_one("SELECT status, outcome FROM incidents WHERE id=?", (inc_id,))
        self.assertEqual(row["status"], "resolved")
        # 中间插入 nginx 事件
        ingest.ingest_webhook({
            "alerts": [am_alert(labels={
                "alertname": "TargetDown", "asset": "nerv", "service": "nginx",
            })]
        })
        # frps 复发：新周期
        ingest.ingest_webhook({
            "alerts": [am_alert(starts="2026-10-07T11:00:00Z")]
        })
        frps_rows = db.query(
            "SELECT * FROM incidents WHERE asset_id='nerv' AND object_id='frps'"
        )
        self.assertEqual(len(frps_rows), 1)
        self.assertEqual(frps_rows[0]["generation"], 2)
        self.assertEqual(frps_rows[0]["status"], "open")

    def test_timeline_latest_visible_over_200(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        inc_id = "inc_timeline"
        t0 = now()
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
            " need_human, summary, generation, outcome, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (inc_id, "x", "nerv", "frps", "warning", "open", "pending",
             0, "", 1, "", t0, t0),
        )
        for i in range(250):
            db.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json)"
                " VALUES(?,?,?,?,?)",
                (inc_id, t0 + i, "note", f"e{i}", "{}"),
            )
        data = incidents.get_incident(inc_id)
        events = data["events"]
        self.assertLessEqual(len(events), 200)
        # 最新事件必须可见
        titles = [e["title"] for e in events]
        self.assertIn("e249", titles)
        self.assertNotIn("e0", titles)
        self.assertTrue(data["events_has_more"])
        # cursor 加载历史
        oldest = data["events_oldest_id"]
        more = incidents.get_incident(inc_id, event_limit=50, event_cursor=oldest)
        more_titles = [e["title"] for e in more["events"]]
        self.assertTrue(any(t.startswith("e") for t in more_titles))

    def test_duplicate_reconcile_no_duplicate_key_events(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        ingest.ingest_webhook({"alerts": [am_alert()]})
        n1 = db.query_one("SELECT COUNT(*) AS n FROM events WHERE type='alert_fired'")
        ingest.ingest_webhook({"alerts": [am_alert()]})
        n2 = db.query_one("SELECT COUNT(*) AS n FROM events WHERE type='alert_fired'")
        self.assertEqual(int(n1["n"]), int(n2["n"]))

    def test_malformed_timestamp_quarantine(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        r = ingest.ingest_webhook({"alerts": [am_alert(starts="not-a-time")]})
        self.assertGreaterEqual(r["quarantined"], 1)
        ep = db.query_one("SELECT * FROM alert_episodes")
        self.assertEqual(ep["source_state"], "quarantine")
        self.assertEqual(ep["source_health"], "quarantine")
        # quarantine 不自动进入 incident
        inc = db.query_one("SELECT COUNT(*) AS n FROM incidents")
        self.assertEqual(int(inc["n"]), 0)

    def test_normalize_utc_equivalent(self):
        a, sa = normalize_starts_at("2026-10-07T12:00:00+02:00")
        b, sb = normalize_starts_at("2026-10-07T10:00:00Z")
        self.assertEqual(sa, "ok")
        self.assertEqual(sb, "ok")
        self.assertEqual(a, b)

    def test_problem_family(self):
        self.assertEqual(problem_family_of("TargetDown"), "availability")
        self.assertEqual(problem_family_of("DiskUsageHigh"), "capacity")
        self.assertEqual(problem_family_of("SomethingElse"), "other")

    def test_not_seen_event_idempotent(self):
        tmp, db, ingest, incidents = self._env()
        self.addCleanup(close_env, tmp, db)
        ingest.ingest_webhook({"alerts": [am_alert()]})
        ingest.reconcile([], source_ok=True)
        ingest.reconcile([], source_ok=True)
        n = db.query_one(
            "SELECT COUNT(*) AS n FROM events WHERE type='reconcile_not_seen'"
        )
        self.assertEqual(int(n["n"]), 1)
