"""策略、告警入库、Action 状态机单测（不触网）。"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionError, ActionService
from ayana.alertmanager import AlertIngest, fingerprint_of
from ayana.db import Database, now
from ayana.ntsafe import NTError, NTResult
from ayana.policy import Policy


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
        return NTResult(ok=True, output='{"user":"nt-probe","mode":"probe","uid":1}')


class FakeGate:
    class B:
        asset_id = "nerv"
        read_alias = "nerv"
        write_alias = "nerv-exec"
        expected_host_id = "NERV"
        host_id_verified_at = 1.0

    def get(self, asset_id):
        if asset_id != "nerv":
            raise NTError("unknown-asset", asset_id)
        return self.B()

    async def verify_account(self, asset_id, *, write=False):
        return {
            "ok": True,
            "mode": "exec" if write else "probe",
            "account": "nt-exec" if write else "nt-probe",
            "error": "",
        }


class FakeProm:
    def __init__(self):
        self.samples = []

    async def probe_success(self, asset, service=""):
        return {"result": list(self.samples)}


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.policy = Policy(self.db)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_default_deny(self):
        d = self.policy.check(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="o1",
        )
        self.assertFalse(d["allowed"])

    def test_allow_and_auto(self):
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="o1", allow=True, require_approval=True, auto_allowed=True,
            actor="t",
        )
        d = self.policy.check(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="o1",
        )
        self.assertTrue(d["allowed"])
        self.assertTrue(d["require_approval"])
        # S08: require_approval=True 时即使 auto_allowed=True，也不允许自动派发
        d2 = self.policy.check(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="o1", auto=True,
        )
        self.assertFalse(d2["allowed"])
        self.assertEqual(d2.get("reason"), "approval_required")

    def test_auto_allowed_without_approval(self):
        """auto_allowed=True 且 require_approval=False → 可自动派发。"""
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="o1", allow=True, require_approval=False, auto_allowed=True,
            actor="t",
        )
        d = self.policy.check(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="o1", auto=True,
        )
        self.assertTrue(d["allowed"])
        self.assertEqual(d.get("decision"), "automatic")

    def test_auto_denied_when_not_allowed(self):
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="o1", allow=True, auto_allowed=False,
        )
        d = self.policy.check(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="o1", auto=True,
        )
        self.assertFalse(d["allowed"])


class TestAlertIngest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.ingest = AlertIngest(self.db)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _payload(self):
        return {
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "TargetDown", "asset": "nerv", "service": "frps"},
                    "annotations": {"summary": "x"},
                    "startsAt": "2026-10-05T10:00:00Z",
                }
            ]
        }

    def test_create_and_dedupe(self):
        r1 = self.ingest.ingest_webhook(self._payload())
        self.assertEqual(r1["created"], 1)
        r2 = self.ingest.ingest_webhook(self._payload())
        self.assertEqual(r2["created"], 0)
        self.assertEqual(r2["updated"], 1)
        row = self.db.query_one("SELECT receive_count FROM alert_episodes LIMIT 1")
        self.assertEqual(row["receive_count"], 2)

    def test_fingerprint_stable(self):
        a = {"alertname": "X", "asset": "n"}
        self.assertEqual(fingerprint_of(a), fingerprint_of(dict(a)))


class TestActions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        t = now()
        self.db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
            " host_id_verified_at, created_at, updated_at)"
            " VALUES('nerv','N','nerv','nerv-exec','NERV',?,?,?)",
            (t, t, t),
        )
        self.db.execute(
            "INSERT INTO objects(id, asset_id, kind, name, unit, created_at)"
            " VALUES('nerv:service:frps','nerv','service','frps','frps',?)",
            (t,),
        )
        self.db.execute(
            "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
            " VALUES('admin','x',0,1,?,?)",
            (t, t),
        )
        self.policy = Policy(self.db)
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=True,
        )
        self.nt = FakeNT()
        self.prom = FakeProm()
        self.actions = ActionService(
            self.db, self.nt, FakeGate(), self.policy, self.prom,
            action_ttl=1800, verify_window=5, verify_timeout=1,
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_propose_approve_exec(self):
        import asyncio

        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="test", proposer_type="web_user", proposer_id="admin",
        )
        self.assertEqual(prop["state"], "proposed")
        self.assertEqual(prop["tokens"], ["systemctl", "restart", "frps"])
        self.actions.approve(prop["id"], approver_type="web_user", approver_id="admin")

        async def run():
            return await self.actions.execute(
                prop["id"], actor_type="web_user", actor_id="admin", is_admin=True
            )

        res = asyncio.run(run())
        self.assertEqual(res["state"], "success")
        self.assertEqual(self.nt.calls[0][0], "exec")
        # NT 别名已移除：transport 以 asset_id 调用
        self.assertEqual(self.nt.calls[0][1], "nerv")

    def test_deny_without_permission(self):
        with self.assertRaises(ActionError):
            self.actions.propose(
                asset_id="nerv", object_id="frps", capability="service.stop",
                reason="", proposer_type="web_user", proposer_id="admin",
            )

    def test_unknown_on_dispatched_restart(self):
        self.db.execute(
            "INSERT INTO actions(id, asset_id, object_id, capability, params_json, state,"
            " created_at) VALUES('a1','nerv','frps','service.restart','{}','dispatched',?)",
            (now(),),
        )
        n = self.actions.mark_unknown_unfinished()
        self.assertEqual(n, 1)
        row = self.db.query_one("SELECT state FROM actions WHERE id='a1'")
        self.assertEqual(row["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
