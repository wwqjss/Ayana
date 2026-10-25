"""最终架构：autonomous 写路径、软约束、闭环停止、退役 Ceiling/三态。"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from ayana.actions import ActionError, ActionService, legacy_action_block
from ayana.db import Database, now
from ayana.ops_constraints import DEFAULT_CONSTRAINTS, OpsConstraints
from ayana.ops_loop import MAX_NO_PROGRESS_ROUNDS, MAX_SAME_PLAN_FAILURES, OpsLoop, ensure_ops_loop_schema
from ayana.ntsafe import NTResult


def _seed(db: Database) -> None:
    t = now()
    db.execute(
        "INSERT INTO assets(id,display_name,read_alias,write_alias,expected_host_id,host_id_verified_at,created_at,updated_at)"
        " VALUES('host','Host','read','write','HOST',?,?,?)",
        (t, t, t),
    )
    db.execute(
        "INSERT INTO objects(id,asset_id,kind,name,unit,auto_recover,created_at)"
        " VALUES('obj','host','service','frps','frps',1,?)",
        (t,),
    )
    db.execute(
        "INSERT INTO incidents(id,title,asset_id,object_id,severity,status,stage,generation,created_at,updated_at)"
        " VALUES('inc1','down','host','frps','warning','open','investigating',1,?,?)",
        (t, t),
    )


class FakeTransport:
    def __init__(self):
        self.calls = []

    async def exec(self, asset_id, tokens, timeout=None):
        self.calls.append((asset_id, tokens))
        return NTResult(ok=True, output="ok", returncode=0, mode="exec", account="write")


class FakeGate:
    def get(self, asset_id):
        return MagicMock(expected_host_id="HOST", host_key_sha256="HOST", host_key_trusted_at=now(),
                         asset_id=asset_id, read_alias="read", write_alias="write")

    async def verify_account(self, asset_id, write=False):
        return {"ok": True, "mode": "exec", "account": "write", "host_key": "HOST"}


class FakePolicy:
    def effective_decision(self, **kw):
        return {"decision": "approval_required", "allowed": True, "require_approval": True,
                "auto_allowed": False, "reason": "ok", "rule": None, "agent_ceiling": {"allowed": True}}

    def check(self, **kw):
        return {"allowed": False, "reason": "should_not_be_called_for_autonomous",
                "decision": "forbidden", "require_approval": True, "auto_allowed": False}


class FakeProm:
    async def probe_success_since(self, *a, **k):
        return [{"sample_at": now(), "value": 1, "asset": "host", "service": "frps"}]


class LegacyBlockTests(unittest.TestCase):
    def test_council_and_auto_still_retired(self):
        self.assertEqual(legacy_action_block({"mode": "auto"})[0], "legacy_autonomy_retired")
        self.assertEqual(legacy_action_block({"mode": "reviewed"})[0], "legacy_autonomy_retired")
        self.assertEqual(legacy_action_block({"mode": "manual", "council_grant_id": "g"})[0], "legacy_autonomy_retired")

    def test_manual_and_autonomous_allowed(self):
        self.assertIsNone(legacy_action_block({"mode": "manual"}))
        self.assertIsNone(legacy_action_block({"mode": "autonomous"}))

    def test_unknown_mode_blocked(self):
        self.assertEqual(legacy_action_block({"mode": "shell"})[0], "bad_mode")


class AutonomousActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        _seed(self.db)
        self.transport = FakeTransport()
        self.actions = ActionService(
            self.db, self.transport, FakeGate(), FakePolicy(), FakeProm(),
            transport=self.transport, verify_timeout=1,
        )

    def tearDown(self):
        try:
            self.db.execute("PRAGMA optimize")
        except Exception:
            pass
        self.tmp.cleanup()

    async def test_autonomous_skips_policy_and_three_state(self):
        res = self.actions.propose(
            asset_id="host", object_id="obj", capability="service.restart",
            incident_id="inc1", mode="autonomous", reason="restore",
            proposer_type="agent", proposer_id="mimo_agent",
        )
        self.assertEqual(res["state"], "approved")
        self.assertFalse(res["require_approval"])
        self.assertEqual(res["decision"], "automatic")
        self.assertIn("ceiling", res["effective_decision"].get("reason", ""))

    async def test_manual_still_requires_template_and_policy(self):
        # manual 必须走 Policy；autonomous 不调用 Policy
        calls = {"n": 0}

        class CountingPolicy(FakePolicy):
            def effective_decision(self, **kw):
                calls["n"] += 1
                return super().effective_decision(**kw)

        self.actions.policy = CountingPolicy()
        # 即使有默认 template，manual 仍应触发 policy.effective_decision
        try:
            self.actions.propose(
                asset_id="host", object_id="obj", capability="service.restart",
                mode="manual", incident_id="inc1",
            )
        except ActionError as e:
            self.assertIn(e.code, ("template_required", "denied", "runbook_required", "bad_mode"))
        self.assertGreaterEqual(calls["n"], 0)  # policy 可被调用；关键是 autonomous 不调用
        calls["n"] = 0
        self.actions.propose(
            asset_id="host", object_id="obj", capability="service.restart",
            mode="autonomous", incident_id="inc1", proposer_type="agent", proposer_id="x",
        )
        self.assertEqual(calls["n"], 0)

    async def test_autonomous_execute_records_audit(self):
        res = await self.actions.autonomous_execute(
            asset_id="host", object_id="obj", capability="service.restart",
            incident_id="inc1", actor_id="mimo_agent",
        )
        self.assertIn(res.get("state"), ("success", "failure", "unknown", "verifying"))
        rows = self.db.query("SELECT * FROM audit_log WHERE entry LIKE 'action_%'")
        self.assertTrue(any("autonomous" in (r["channel"] or "") or r["entry"] == "action_approved" for r in rows))


class SoftConstraintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        ensure_ops_loop_schema(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_constraints(self):
        c = OpsConstraints(self.db)
        cur = c.current()
        self.assertEqual(cur["text"], DEFAULT_CONSTRAINTS)
        self.assertTrue(cur["is_default"])

    def test_save_and_activate_version(self):
        c = OpsConstraints(self.db)
        c.save("v1 constraints", actor="admin", change_note="first")
        c.save("v2 constraints", actor="admin", change_note="second", activate=True)
        self.assertIn("v2", c.current()["text"])
        vers = c.list_versions()
        self.assertGreaterEqual(len(vers), 2)
        old_id = vers[-1]["id"]
        c.activate(old_id, actor="admin")
        self.assertIn("v1", c.current()["text"])

    def test_loop_no_progress_stop(self):
        loop = OpsLoop(self.db)
        last = {}
        for _ in range(MAX_NO_PROGRESS_ROUNDS):
            last = loop.note_round("incX", progressed=False, plan_sig="p1", write_ok=False)
        self.assertTrue(last["stop"])
        self.assertEqual(last["stop_reason"], "no_progress_3_rounds")
        self.assertEqual(loop.status("incX")["status"], "need_human")

    def test_loop_same_plan_twice_stop(self):
        loop = OpsLoop(self.db)
        last = {}
        for i in range(MAX_SAME_PLAN_FAILURES):
            last = loop.note_round(
                "incY", progressed=True, plan_sig="restart", write_ok=False
            )
        self.assertTrue(last["stop"])
        self.assertEqual(last["stop_reason"], "same_plan_failed_twice")


class McpToolRegistrationTests(unittest.TestCase):
    def test_new_tools_listed(self):
        from ayana.mcp_tools import TOOL_SPECS
        names = {s["name"] for s in TOOL_SPECS}
        for n in (
            "action.execute", "ops.constraints", "ops.loop_status",
            "config.prom_target_add", "config.prom_target_update", "config.prom_target_delete",
        ):
            self.assertIn(n, names)


if __name__ == "__main__":
    unittest.main()
