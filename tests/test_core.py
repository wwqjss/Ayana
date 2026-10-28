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
from ayana.policy import Policy, PolicyDeny


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
    """Compatibility imports enforce account roles, never stored grants."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.policy = Policy(self.db)
        for username, admin in (("admin", 1), ("viewer", 0)):
            self.db.execute(
                "INSERT INTO users(username,password_hash,is_admin,created_at,updated_at) VALUES(?,?,?,?,?)",
                (username, "test-hash", admin, now(), now()),
            )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_unknown_user_denied(self):
        decision = self.policy.check(subject_type="web_user", subject_id="absent",
            capability="service.restart", asset_id="nerv", object_id="o1")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "authenticated_account_required")

    def test_admin_can_propose_but_cannot_automate_without_session(self):
        args = dict(subject_type="web_user", subject_id="admin", capability="service.restart",
                    asset_id="nerv", object_id="o1")
        decision = self.policy.check(**args)
        self.assertTrue(decision["allowed"])
        self.assertTrue(decision["require_approval"])
        automatic = self.policy.check(**args, auto=True)
        self.assertFalse(automatic["allowed"])
        self.assertEqual(automatic["reason"], "trusted_session_context_required")

    def test_viewer_can_read_but_not_write(self):
        args = dict(subject_type="web_user", subject_id="viewer", asset_id="nerv")
        self.assertTrue(self.policy.check(**args, capability="service.logs")["allowed"])
        decision = self.policy.check(**args, capability="service.restart")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "admin_required")

    def test_old_rule_writes_are_retired(self):
        for call in (
            lambda: self.policy.upsert_permission(
                subject_type="web_user", subject_id="admin", capability="service.restart",
                asset_id="nerv", object_id="o1", allow=True, actor="t",
            ),
            lambda: self.policy.delete_permission(1),
            lambda: self.policy.list_permissions(),
            lambda: self.policy.preview(subject_type="web_user", subject_id="admin",
                                        capability="service.restart"),
            lambda: self.policy.default_policy(),
        ):
            with self.assertRaises(PolicyDeny):
                call()


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

    def test_ingest_canonicalizes_asset_label_case(self):
        t = now()
        self.db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, created_at, updated_at)"
            " VALUES('romi','R','romi','romi-exec',?,?)",
            (t, t),
        )
        payload = {"alerts": [{
            "status": "firing",
            "labels": {"alertname": "TargetDown", "asset": "ROMI", "service": "nginx"},
            "annotations": {"summary": "x"},
            "startsAt": "2026-10-05T10:00:00Z",
        }]}
        self.ingest.ingest_webhook(payload)
        row = self.db.query_one("SELECT asset_id FROM alert_episodes LIMIT 1")
        self.assertEqual(row["asset_id"], "romi")

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
        self.assertEqual(self.nt.calls[0][1], "nerv")

    def test_viewer_cannot_propose_a_write(self):
        self.db.execute("UPDATE users SET is_admin=0 WHERE username='admin'")
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
