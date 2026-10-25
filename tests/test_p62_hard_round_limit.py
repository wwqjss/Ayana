"""P6.2 执行前硬轮次上限。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ayana.actions import ActionService
from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.ntsafe import NTResult
from ayana.ops_loop import MAX_EXECUTE_ROUNDS, OpsLoop, ensure_ops_loop_schema


class FakeTransport:
    async def exec(self, asset_id, tokens, timeout=None):
        return NTResult(ok=True, output="ok", returncode=0, mode="exec", account="write")


class FakeGate:
    def get(self, asset_id):
        return SimpleNamespace(
            expected_host_id="H", host_key_sha256="H", host_key_trusted_at=now(),
            asset_id=asset_id, read_alias="r", write_alias="w",
        )

    async def verify_account(self, asset_id, write=False):
        return {"ok": True, "mode": "exec", "account": "w", "host_key": "H"}


class FakePolicy:
    def effective_decision(self, **kw):
        return {"decision": "automatic", "allowed": True, "require_approval": False,
                "auto_allowed": True, "reason": "ok", "rule": None, "agent_ceiling": None}

    def check(self, **kw):
        return {"allowed": True, "decision": "automatic", "require_approval": False, "auto_allowed": True}


class FakeProm:
    async def probe_success_since(self, *a, **k):
        t = now()
        return [{"sample_at": t, "value": 1, "asset": "h", "service": "s"}]


class HardRoundLimitTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        ensure_ops_loop_schema(self.db)
        t = now()
        self.db.execute(
            "INSERT INTO assets(id,display_name,read_alias,write_alias,expected_host_id,host_id_verified_at,created_at,updated_at)"
            " VALUES('h','H','r','w','H',?,?,?)", (t, t, t),
        )
        self.db.execute(
            "INSERT INTO objects(id,asset_id,kind,name,unit,auto_recover,created_at)"
            " VALUES('o','h','service','svc','svc',1,?)", (t,),
        )
        self.db.execute(
            "INSERT INTO incidents(id,title,asset_id,object_id,severity,status,stage,generation,created_at,updated_at)"
            " VALUES('inc1','t','h','o','warning','open','investigating',1,?,?)", (t, t),
        )
        self.actions = ActionService(
            self.db, FakeTransport(), FakeGate(), FakePolicy(), FakeProm(),
            transport=FakeTransport(), verify_timeout=1,
        )
        self.loop = OpsLoop(self.db, actions=self.actions, incidents=IncidentService(self.db))

    def tearDown(self):
        self.tmp.cleanup()

    async def test_hard_limit_blocks_execute_and_escalates(self):
        self.loop._state("inc1")
        self.loop._save("inc1", rounds=MAX_EXECUTE_ROUNDS, status="running")
        res = await self.loop.run_action_and_verify(
            incident_id="inc1", asset_id="h", object_id="o",
            capability="service.restart", plan_sig="p",
        )
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "max_execute_rounds")
        self.assertEqual(self.loop.status("inc1")["status"], "need_human")
        self.assertEqual(self.db.query_one("SELECT COUNT(*) c FROM actions")["c"], 0)

    async def test_stopped_loop_does_not_execute(self):
        self.loop.escalate("inc1", reason="test")
        res = await self.loop.run_action_and_verify(
            incident_id="inc1", asset_id="h", object_id="o",
            capability="service.restart", plan_sig="p",
        )
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "loop_stopped")
        self.assertEqual(self.db.query_one("SELECT COUNT(*) c FROM actions")["c"], 0)


if __name__ == "__main__":
    unittest.main()
