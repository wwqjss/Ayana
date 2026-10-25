"""Phase B: P0-01/02/03 positive and negative dispatch-gate tests."""

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
from ayana.legacy_history import RetiredAutonomyError
from ayana.db import Database, now
from ayana.investigation import InvestigationService
from ayana.knowledge import KnowledgeBase
from ayana.instance import acquire_single_instance_lock
from ayana.ntsafe import AssetBinding, IdentityGate, NTResult
from ayana.policy import Policy
from ayana.runbook import RunbookRule, apply_runbook_rules, get_runbook_rule, match_runbook
from ayana.prom import match_series


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
    def __init__(self):
        self.samples = []
        self.since_calls = []

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


def make_env(describe_json=None, verified=True):
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

    policy = Policy(db)
    policy.upsert_permission(
        subject_type="web_user", subject_id="admin", capability="service.restart",
        asset_id="nerv", object_id="*", allow=True, require_approval=False, actor="t",
    )
    policy.upsert_permission(
        subject_type="auto_rule", subject_id="agent", capability="service.restart",
        asset_id="nerv", object_id="*", allow=True, require_approval=False,
        auto_allowed=True, actor="t",
    )
    nt = FakeNT(describe_json=describe_json)
    prom = FakeProm()
    gate = Gate(nt, verified=verified)
    actions = ActionService(
        db, nt, gate, policy, prom, action_ttl=1800, approval_ttl=900,
        verify_window=5, verify_timeout=1,
    )
    # 注入测试本地 runbook 规则（发行版 RUNBOOK 为空）
    apply_runbook_rules([{
        "id": "rb_frps_down_restart", "name": "frps down restart",
        "asset_id": "nerv", "object_name": "frps", "alertname": "TargetDown",
        "capability": "service.restart", "reason": "restart frps",
        "require_probe_fail": True,
    }])
    return tmp, db, policy, nt, prom, gate, actions


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


class TestP001SingleInstance(unittest.TestCase):
    def test_second_lock_rejected(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        lock = Path(tmp.name) / "ayana.lock"
        a = acquire_single_instance_lock(lock)
        self.addCleanup(lambda: getattr(a, 'close', lambda: None)())
        with self.assertRaises((SystemExit, OSError, PermissionError)):
            acquire_single_instance_lock(lock)

    def test_runbook_excludes_ayana_control_plane(self):
        self.assertIsNone(
            match_runbook(
                asset_id="kanata", object_name="ayana", alertname="TargetDown"
            )
        )
        rule = RunbookRule(id="r", name="n", asset_id="kanata", object_name="ayana",
                           capability="service.restart")
        pre = rule.check_preconditions(
            {"control_plane": True, "probe_failed_recent": True, "exec_channel_ok": True}
        )
        self.assertEqual(pre["status"], "unsatisfied")


class TestP002DispatchGate(unittest.TestCase):
    def test_wrong_host_id_zero_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions = make_env(
            describe_json='{"user":"nt-exec","mode":"exec","uid":1,"host_id":"WRONG"}'
        )
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        actions.approve(prop["id"], approver_type="web_user", approver_id="admin")

        async def run():
            return await actions.execute(prop["id"], actor_type="web_user", actor_id="admin")

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "identity_gate")
        self.assertFalse(nt.exec_calls)

    def test_missing_remote_host_id_zero_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions = make_env(
            describe_json='{"user":"nt-exec","mode":"exec","uid":1}'
        )
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        actions.approve(prop["id"], approver_type="web_user", approver_id="admin")

        async def run():
            return await actions.execute(prop["id"], actor_type="web_user", actor_id="admin")

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "identity_gate")
        self.assertFalse(nt.exec_calls)

    def test_manual_positive_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        self.assertEqual(prop.get("template_id"), "tmpl_service_restart")
        actions.approve(prop["id"], approver_type="web_user", approver_id="admin")

        async def run():
            return await actions.execute(prop["id"], actor_type="web_user", actor_id="admin")

        res = asyncio.run(run())
        self.assertEqual(res.get("state"), "success")
        self.assertTrue(nt.exec_calls)

    def test_approval_expired_zero_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions = make_env()
        self.addCleanup(close_env, tmp, db)
        actions.approval_ttl = 0
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        actions.approve(prop["id"], approver_type="web_user", approver_id="admin")

        async def run():
            return await actions.execute(prop["id"], actor_type="web_user", actor_id="admin")

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "approval_expired")
        self.assertFalse(nt.exec_calls)

    def test_runbook_changed_zero_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions = make_env()
        self.addCleanup(close_env, tmp, db)
        rule = get_runbook_rule("rb_frps_down_restart")
        # P4.4：自动授权退役，propose(mode=auto) 直接拒绝，零派发
        with self.assertRaises(ActionError) as ctx:
            actions.propose(
                asset_id="nerv", object_id="frps", capability="service.restart",
                proposer_type="auto_rule", proposer_id="agent",
                mode="auto", runbook_id="rb_frps_down_restart", runbook_rev="OLDREV",
            )
        self.assertEqual(ctx.exception.code, "legacy_autonomy_retired")
        self.assertFalse(nt.exec_calls)
        return
        actions.approve(prop["id"], approver_type="auto_rule", approver_id="agent")

        async def run():
            return await actions.execute(prop["id"], actor_type="web_user", actor_id="admin")

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "runbook_changed")
        self.assertFalse(nt.exec_calls)

    def test_policy_tightened_zero_dispatch(self):
        tmp, db, policy, nt, prom, gate, actions = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        actions.approve(prop["id"], approver_type="web_user", approver_id="admin")
        policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="*", allow=False, actor="t",
        )

        async def run():
            return await actions.execute(prop["id"], actor_type="web_user", actor_id="admin")

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "policy_revoked")
        self.assertFalse(nt.exec_calls)


class TestP003Preconditions(unittest.TestCase):
    def _agent_env(self, probe_value=0):
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
            "INSERT INTO objects(id, asset_id, kind, name, unit, created_at)"
            " VALUES(?,?,?,?,?,?)",
            ("nerv:service:frps", "nerv", "service", "frps", "frps", t),
        )
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES(?,?,?,?,?,?,?,?)",
            ("inc1", "nerv/frps: TargetDown", "nerv", "frps", "open", "pending", t, t),
        )
        db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm, alertname,"
            " status, asset_id, object_id, incident_id, first_seen, last_seen, receive_count,"
            " labels_json, annotations_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("ep1", "am", "fp", "x", "TargetDown", "firing", "nerv", "frps", "inc1", t, t, 1, "{}", "{}"),
        )
        policy = Policy(db)
        for cap, auto in (("asset.summary", False), ("service.restart", True)):
            policy.upsert_permission(
                subject_type="auto_rule", subject_id="agent", capability=cap,
                asset_id="*", object_id="*", allow=True, require_approval=False,
                auto_allowed=auto, actor="t",
            )
        nt = FakeNT()
        prom = FakeProm()
        if probe_value is not None:
            prom.samples = [
                {"metric": {"asset": "nerv", "service": "frps"}, "value": probe_value, "sample_at": now() - 10},
            ]
        gate = Gate(nt)
        inv = InvestigationService(db, nt, gate, prom, policy)
        actions = ActionService(db, nt, gate, policy, prom, verify_timeout=1)

        class NoLLM:
            enabled = False

            async def analyze_incident(self, **kw):
                return None

        class NQ:
            def enqueue(self, **kw):
                pass

        agent = AgentLoop.__new__(AgentLoop)
        # 注入测试本地 runbook 规则（发行版 RUNBOOK 为空）
        apply_runbook_rules([{
            "id": "rb_frps_down_restart", "name": "frps down restart",
            "asset_id": "nerv", "object_name": "frps", "alertname": "TargetDown",
            "capability": "service.restart", "reason": "restart frps",
            "require_probe_fail": True,
        }])
        return tmp, db, nt, actions, agent

    def test_global_pause_zero_auto_dispatch(self):
        tmp,db,nt,actions,agent=self._agent_env(probe_value=0)
        self.addCleanup(close_env,tmp,db)
        db.execute("UPDATE global_stops SET enabled=1 WHERE key='auto_dispatch'")
        before=list(db.query("SELECT id,state FROM actions ORDER BY id"))
        with self.assertRaises(RetiredAutonomyError):
            asyncio.run(agent.handle_incident("inc1"))
        self.assertFalse(nt.exec_calls)
        self.assertEqual([tuple(r) for r in before],[tuple(r) for r in db.query("SELECT id,state FROM actions ORDER BY id")])
        self.assertEqual(db.query_one("SELECT need_human FROM incidents WHERE id='inc1'")["need_human"],0)

    def test_budget_exhausted_zero_auto_dispatch(self):
        tmp,db,nt,actions,agent=self._agent_env(probe_value=0)
        self.addCleanup(close_env,tmp,db)
        for i in range(3):
           db.execute("INSERT INTO actions(id,asset_id,object_id,capability,state,mode,created_at,dispatched_at) VALUES(?,'nerv','frps','service.restart','success','auto',?,?)",(f"old{i}",now()-3600,now()-3600))
        before=list(db.query("SELECT id,state FROM actions ORDER BY id"))
        with self.assertRaises(RetiredAutonomyError):
            asyncio.run(agent.handle_incident("inc1"))
        self.assertFalse(nt.exec_calls)
        self.assertEqual([tuple(r) for r in before],[tuple(r) for r in db.query("SELECT id,state FROM actions ORDER BY id")])
        self.assertEqual(db.query_one("SELECT need_human FROM incidents WHERE id='inc1'")["need_human"],0)

    def test_fresh_fail_probe_auto_positive(self):
        tmp,db,nt,actions,agent=self._agent_env(probe_value=0)
        self.addCleanup(close_env,tmp,db)

        before=list(db.query("SELECT id,state FROM actions ORDER BY id"))
        with self.assertRaises(RetiredAutonomyError):
            asyncio.run(agent.handle_incident("inc1"))
        self.assertFalse(nt.exec_calls)
        self.assertEqual([tuple(r) for r in before],[tuple(r) for r in db.query("SELECT id,state FROM actions ORDER BY id")])
        self.assertEqual(db.query_one("SELECT need_human FROM incidents WHERE id='inc1'")["need_human"],0)

    def test_recovered_probe_zero_auto_dispatch(self):
        tmp,db,nt,actions,agent=self._agent_env(probe_value=1)
        self.addCleanup(close_env,tmp,db)

        before=list(db.query("SELECT id,state FROM actions ORDER BY id"))
        with self.assertRaises(RetiredAutonomyError):
            asyncio.run(agent.handle_incident("inc1"))
        self.assertFalse(nt.exec_calls)
        self.assertEqual([tuple(r) for r in before],[tuple(r) for r in db.query("SELECT id,state FROM actions ORDER BY id")])
        self.assertEqual(db.query_one("SELECT need_human FROM incidents WHERE id='inc1'")["need_human"],0)

    def test_empty_probe_zero_auto_dispatch(self):
        tmp,db,nt,actions,agent=self._agent_env(probe_value=None)
        self.addCleanup(close_env,tmp,db)

        before=list(db.query("SELECT id,state FROM actions ORDER BY id"))
        with self.assertRaises(RetiredAutonomyError):
            asyncio.run(agent.handle_incident("inc1"))
        self.assertFalse(nt.exec_calls)
        self.assertEqual([tuple(r) for r in before],[tuple(r) for r in db.query("SELECT id,state FROM actions ORDER BY id")])
        self.assertEqual(db.query_one("SELECT need_human FROM incidents WHERE id='inc1'")["need_human"],0)

    def test_require_probe_fail_consumed(self):
        apply_runbook_rules([{
            "id": "rb_frps_down_restart", "name": "frps down restart",
            "asset_id": "nerv", "object_name": "frps", "alertname": "TargetDown",
            "capability": "service.restart", "reason": "restart frps",
            "require_probe_fail": True,
        }])
        self.addCleanup(lambda: apply_runbook_rules([]))
        rule = get_runbook_rule("rb_frps_down_restart")
        self.assertIsNotNone(rule)
        self.assertTrue(rule.require_probe_fail)
        pre = rule.check_preconditions(
            {
                "asset_id": "nerv",
                "object_name": "frps",
                "probe_failed_recent": False,
                "exec_channel_ok": True,
                "verification_ready": True,
                "global_pause": False,
                "policy_allowed": True,
                "budget_ok": True,
                "object_locked": False,
            }
        )
        self.assertEqual(pre["status"], "unsatisfied")
        self.assertTrue(any("fresh_failed_probe" in r for r in pre["reasons"]))


if __name__ == "__main__":
    unittest.main()

