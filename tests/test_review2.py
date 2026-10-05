"""二审 P1 回归：跨等待撤权、验证义务原子性、对象占用、跨 Incident、采样错配。"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionError, ActionService, classify_exec_result
from ayana.db import Database, now
from ayana.ntsafe import NTError, NTResult
from ayana.policy import Policy
from ayana.prom import group_by_series, match_series, series_key


class FakeNT:
    def __init__(self, result: NTResult | None = None):
        self.calls = []
        self.next = result or NTResult(ok=True, output="ok", returncode=0)

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

    def get(self, asset_id):
        return self.B()

    async def verify_account(self, asset_id, *, write=False):
        return {"ok": True, "mode": "exec" if write else "probe", "error": ""}


class FakeProm:
    def __init__(self):
        self.samples = []

    async def probe_success_since(self, asset, service="", *, start, end, step=15.0):
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

    async def probe_success(self, asset, service=""):
        return {"result": self.samples, "evaluated_at": now()}


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
    db.execute(
        "INSERT INTO objects(id, asset_id, kind, name, unit, created_at)"
        " VALUES('nerv:service:nginx','nerv','service','nginx','nginx',?)",
        (t,),
    )
    policy = Policy(db)
    return tmp, db, policy


def make_actions(db, policy, prom, nt=None, gate=None):
    return ActionService(
        db,
        nt or FakeNT(),
        gate or FakeGate(),
        policy,
        prom,
        action_ttl=1800,
        approval_ttl=900,
        verify_window=5,
        verify_timeout=1,
    )


class TestClassifyNegative(unittest.TestCase):
    def test_signal_kill_is_unknown(self):
        r = NTResult(ok=False, output="", returncode=-15)
        state, _ = classify_exec_result(r)
        self.assertEqual(state, "unknown")


class TestMultiSeries(unittest.TestCase):
    def test_same_time_different_series_not_overwritten(self):
        samples = [
            {"metric": {"asset": "n", "service": "s", "instance": "a"}, "sample_at": 100, "value": 0},
            {"metric": {"asset": "n", "service": "s", "instance": "b"}, "sample_at": 100, "value": 1},
        ]
        groups = group_by_series(samples)
        self.assertEqual(len(groups), 2)
        keys = {series_key(s["metric"]) for s in samples}
        self.assertEqual(set(groups.keys()), keys)


class TestIncidentBinding(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.policy = make_env()
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=True,
        )
        self.prom = FakeProm()
        self.actions = make_actions(self.db, self.policy, self.prom)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_cross_incident_rejected(self):
        self.db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES('inc-nginx','t','nerv','nginx','open','pending',?,?)",
            (now(), now()),
        )
        with self.assertRaises(ActionError) as ctx:
            self.actions.propose(
                asset_id="nerv", object_id="frps", capability="service.restart",
                incident_id="inc-nginx", proposer_type="web_user", proposer_id="admin",
            )
        self.assertEqual(ctx.exception.code, "incident_mismatch")

    def test_verify_does_not_close_other_incident(self):
        # frps action 误绑 nginx incident 时，最终关闭也被拦住
        self.db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES('inc-nginx','t','nerv','nginx','open','pending',?,?)",
            (now(), now()),
        )
        aid = "act-x"
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                aid,
                "inc-nginx",
                "nerv",
                "nerv:service:frps",
                "service.restart",
                '{"tokens":["systemctl","restart","frps"],"object_name":"frps"}',
                "success",
                "web_user",
                "admin",
                now(),
                now(),
            ),
        )
        base = now()
        self.prom.samples = [
            {"metric": {"asset": "nerv", "service": "frps"}, "sample_at": base + 10, "value": 1},
            {"metric": {"asset": "nerv", "service": "frps"}, "sample_at": base + 25, "value": 1},
        ]

        async def run():
            return await self.actions.verify(aid)

        res = asyncio.run(run())
        # 样本是 frps，incident 是 nginx：不得关闭
        inc = self.db.query_one("SELECT status FROM incidents WHERE id='inc-nginx'")
        self.assertEqual(inc["status"], "open")


class TestVerificationObligation(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.policy = make_env()
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=True,
        )
        self.prom = FakeProm()
        self.actions = make_actions(self.db, self.policy, self.prom)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_backfill_creates_missing_verification(self):
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, created_at, finished_at) VALUES('a1','','nerv','nerv:service:frps',"
            " 'service.restart','{}','success',?,?)",
            (now(), now()),
        )
        n = self.actions.backfill_missing_verifications()
        self.assertEqual(n, 1)
        row = self.db.query_one("SELECT COUNT(*) AS n FROM verifications")
        self.assertEqual(row["n"], 1)

    def test_object_locked_while_verifying(self):
        self.db.execute(
            "INSERT INTO actions(id, asset_id, object_id, capability, params_json, state,"
            " created_at, finished_at) VALUES('a1','nerv','nerv:service:frps','service.restart',"
            " '{}','success',?,?)",
            (now(), now()),
        )
        self.db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, criteria_json,"
            " started_at) VALUES('v1','a1','','pending','{}',?)",
            (now(),),
        )
        with self.assertRaises(ActionError) as ctx:
            self.actions.propose(
                asset_id="nerv", object_id="frps", capability="service.restart",
                proposer_type="web_user", proposer_id="admin",
            )
        self.assertEqual(ctx.exception.code, "object_locked")


class TestAlertRowAccess(unittest.TestCase):
    def test_row_dict_no_get_on_sqlite3_row(self):
        # 确保 _sync_incident 路径用 dict() 而不是 Row.get
        import inspect
        from ayana.alertmanager import AlertIngest

        src = inspect.getsource(AlertIngest._sync_incident)
        self.assertNotIn(".get(", src.replace("ep.get(", "SKIP(").replace("before.get(", "SKIP(").replace("after.get(", "SKIP("))
        # 更直接：不允许 sqlite3.Row 调 .get
        src_all = inspect.getsource(AlertIngest)
        self.assertIn("dict(", src_all)


if __name__ == "__main__":
    unittest.main()
