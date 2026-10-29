"""最终架构：autonomous 写路径、软约束、闭环停止、退役 Ceiling/三态。"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from ayana.exec_facts import ActionError, legacy_action_block
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
        for index in range(MAX_NO_PROGRESS_ROUNDS):
            # 不同方案连续无进展；同一方案应先触发两次执行失败门槛。
            last = loop.note_round("incX", progressed=False, plan_sig=f"p{index}", write_ok=False)
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
        self.assertNotIn("action.execute", names)
        for n in (
            "host.exec", "ops.constraints", "ops.loop_status",
            "config.prom_target_add", "config.prom_target_update", "config.prom_target_delete",
        ):
            self.assertIn(n, names)


if __name__ == "__main__":
    unittest.main()
