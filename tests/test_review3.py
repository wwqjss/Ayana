"""三审 P1 回归：range vector 真采样、派发权限、资产绑定复查、通知补偿、补建接线。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionError, ActionService
from ayana.db import Database, now
from ayana.ntsafe import NTError, NTResult
from ayana.policy import Policy
from ayana.notify import Notifier


class FakeNT:
    def __init__(self):
        self.calls = []
        self.next = NTResult(ok=True, output="ok", returncode=0)

    async def probe(self, alias, tokens, timeout=None):
        self.calls.append(("probe", alias, tokens))
        return self.next

    async def exec(self, alias, tokens, timeout=None):
        self.calls.append(("exec", alias, tokens))
        return self.next

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"nt-exec","mode":"exec","uid":1}')


class FakeGate:
    class B:
        asset_id = "nerv"
        read_alias = "nerv"
        write_alias = "nerv-exec"
        expected_host_id = "NERV"
        host_id_verified_at = 1.0

    def __init__(self):
        self.binding = self.B()

    def get(self, asset_id):
        return self.binding

    async def verify_account(self, asset_id, *, write=False):
        return {"ok": True, "mode": "exec" if write else "probe", "error": ""}


class FakeProm:
    def __init__(self):
        self.samples = []

    async def probe_success_since(self, asset, service="", *, start, end, step=15.0, window_sec=None):
        out = []
        for s in self.samples:
            ts = s.get("sample_at")
            if ts is None or ts <= start or ts > end:
                continue
            labels = s.get("metric") or {}
            if labels.get("asset") != asset:
                continue
            if service and labels.get("service") != service:
                continue
            out.append(s)
        return out


def make_env():
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "t.db")
    t = now()
    db.execute(
        "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
        " host_id_verified_at, created_at, updated_at)"
        " VALUES('nerv','N','nerv','nerv-exec','NERV',?,?,?)",
        (t, t, t),
    )
    db.execute(
        "INSERT INTO objects(id, asset_id, kind, name, unit, created_at)"
        " VALUES('nerv:service:frps','nerv','service','frps','frps',?)",
        (t,),
    )
    policy = Policy(db)
    return tmp, db, policy


class TestDispatcherPermission(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.policy = make_env()
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=True,
        )
        self.nt = FakeNT()
        self.gate = FakeGate()
        self.prom = FakeProm()
        self.actions = ActionService(
            self.db, self.nt, self.gate, self.policy, self.prom,
            action_ttl=1800, approval_ttl=900, verify_window=5, verify_timeout=1,
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_unauthorized_dispatcher_denied(self):
        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )
        self.actions.approve(prop["id"], approver_type="web_user", approver_id="admin")

        async def run():
            return await self.actions.execute(
                prop["id"], actor_type="web_user", actor_id="stranger"
            )

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "dispatcher_denied")
        row = self.db.query_one("SELECT state, result_detail FROM actions WHERE id=?", (prop["id"],))
        # 无权派发者不得取消原 Action
        self.assertEqual(row["state"], "approved")
        self.assertEqual(self.nt.calls, [])

    def test_rejection_status_committed(self):
        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )
        self.actions.approve(prop["id"], approver_type="web_user", approver_id="admin")
        # 撤权提案人
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=False,
        )

        async def run():
            return await self.actions.execute(
                prop["id"], actor_type="web_user", actor_id="admin", is_admin=True
            )

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "policy_revoked")
        row = self.db.query_one("SELECT state FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["state"], "cancelled")


class TestAssetBindingDuringWait(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.policy = make_env()
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=True,
        )
        self.nt = FakeNT()
        self.gate = FakeGate()
        self.prom = FakeProm()
        self.actions = ActionService(
            self.db, self.nt, self.gate, self.policy, self.prom,
            action_ttl=1800, approval_ttl=900, verify_window=5, verify_timeout=1,
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_disable_asset_during_identity_wait(self):
        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )
        self.actions.approve(prop["id"], approver_type="web_user", approver_id="admin")

        # 身份核验等待期禁用资产
        class SabotageGate(FakeGate):
            async def verify_account(self, asset_id, *, write=False):
                self.db_ref.execute("UPDATE assets SET enabled=0 WHERE id=?", (asset_id,))
                return {"ok": True, "mode": "exec", "error": ""}

        g = SabotageGate()
        g.db_ref = self.db
        self.actions.gate = g

        async def run():
            return await self.actions.execute(
                prop["id"], actor_type="web_user", actor_id="admin", is_admin=True
            )

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "asset_disabled")
        self.assertEqual(self.nt.calls, [])

    def test_clear_host_id_during_wait(self):
        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )
        self.actions.approve(prop["id"], approver_type="web_user", approver_id="admin")

        class ClearGate(FakeGate):
            async def verify_account(self, asset_id, *, write=False):
                self.db_ref.execute(
                    "UPDATE assets SET host_id_verified_at=NULL, expected_host_id='' WHERE id=?",
                    (asset_id,),
                )
                return {"ok": True, "mode": "exec", "error": ""}

        g = ClearGate()
        g.db_ref = self.db
        self.actions.gate = g

        async def run():
            return await self.actions.execute(
                prop["id"], actor_type="web_user", actor_id="admin", is_admin=True
            )

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertIn(ctx.exception.code, ("identity_gate", "binding_changed"))
        self.assertEqual(self.nt.calls, [])


class TestNotificationKeys(unittest.TestCase):
    def test_transition_keys_unique(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        n = Notifier(db, default_target="user:1")
        a = n.incident_key("i1", "opened", 1)
        b = n.incident_key("i1", "opened", 2)
        self.assertNotEqual(a, b)
        self.assertTrue(n.enqueue_transition(incident_id="i1", typ="opened", target="user:1", body="x"))
        self.assertTrue(n.enqueue_transition(incident_id="i1", typ="opened", target="user:1", body="y"))
        row = db.query_one("SELECT COUNT(*) AS n FROM notification_outbox")
        self.assertEqual(row["n"], 2)
        db.close()
        tmp.cleanup()


class TestBackfillWired(unittest.TestCase):
    def test_backfill_before_resume(self):
        src = (Path(__file__).resolve().parents[1] / "ayana" / "main.py").read_text(encoding="utf-8")
        self.assertIn("backfill_missing_verifications", src)
        self.assertLess(
            src.index("backfill_missing_verifications"),
            src.index("resume_pending_verifications"),
        )


if __name__ == "__main__":
    unittest.main()
