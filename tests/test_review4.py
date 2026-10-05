"""四审回归：样本新鲜度、派发不取消、pending 验证保护、恢复 hold 幂等。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionError, ActionService
from ayana.db import Database, now
from ayana.ntsafe import NTResult
from ayana.policy import Policy
from ayana.incidents import IncidentService
from ayana.notify import Notifier


class FakeNT:
    def __init__(self):
        self.calls = []

    async def probe(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="ok", returncode=0)

    async def exec(self, alias, tokens, timeout=None):
        self.calls.append(("exec", alias, tokens))
        return NTResult(ok=True, output="ok", returncode=0)

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

    async def probe_success_since(
        self, asset, service="", *, start, end, step=15.0, window_sec=None, max_window_sec=600.0
    ):
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


class TestStaleSamples(unittest.TestCase):
    def test_old_samples_after_action_do_not_pass(self):
        tmp, db, policy = make_env()
        policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=True,
        )
        prom = FakeProm()
        actions = ActionService(
            db, FakeNT(), FakeGate(), policy, prom,
            action_ttl=1800, approval_ttl=900, verify_window=5, verify_timeout=1,
        )
        aid = "act-stale"
        finished = time.time() - 3600
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, created_at, finished_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                aid, "inc1", "nerv", "nerv:service:frps", "service.restart",
                '{"tokens":["systemctl","restart","frps"],"object_name":"frps"}',
                "success", finished, finished,
            ),
        )
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES('inc1','t','nerv','frps','open','pending',?,?)",
            (now(), now()),
        )
        # 操作后 10s、25s 的样本，但距 now 已 1 小时
        prom.samples = [
            {"metric": {"asset": "nerv", "service": "frps"}, "sample_at": finished + 10, "value": 1},
            {"metric": {"asset": "nerv", "service": "frps"}, "sample_at": finished + 25, "value": 1},
        ]

        async def run():
            return await actions.verify(aid)

        res = asyncio.run(run())
        self.assertNotEqual(res["status"], "passed")
        self.assertIn("stale", (res.get("note") or ""))
        inc = db.query_one("SELECT status, need_human FROM incidents WHERE id='inc1'")
        self.assertEqual(inc["need_human"], 1)
        db.close()
        tmp.cleanup()


class TestPendingVerificationProtectsIncident(unittest.TestCase):
    def test_am_resolved_hold_while_verifying(self):
        tmp, db, policy = make_env()
        inc = IncidentService(db)
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES('inc1','t','nerv','frps','open','pending',?,?)",
            (now(), now()),
        )
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, created_at, finished_at) VALUES('a1','inc1','nerv','nerv:service:frps',"
            " 'service.restart','{}','success',?,?)",
            (now(), now()),
        )
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, criteria_json,"
            " started_at) VALUES('v1','a1','inc1','pending','{}',?)",
            (now(),),
        )
        db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm, alertname,"
            " status, asset_id, object_id, incident_id, first_seen, last_seen, receive_count)"
            " VALUES('ep1','am','fp','s1','TargetDown','resolved','nerv','frps','inc1',?,?,1)",
            (now(), now()),
        )
        inc.on_episode_resolved("ep1")
        row = db.query_one("SELECT status, stage, need_human FROM incidents WHERE id='inc1'")
        # pending verification → 不得直接 resolved
        self.assertEqual(row["status"], "open")
        self.assertEqual(row["stage"], "watching")
        db.close()
        tmp.cleanup()


class TestVerifyFailureReopens(unittest.TestCase):
    def test_failure_reopens_resolved_incident(self):
        tmp, db, policy = make_env()
        policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=True,
        )
        prom = FakeProm()
        actions = ActionService(
            db, FakeNT(), FakeGate(), policy, prom,
            action_ttl=1800, approval_ttl=900, verify_window=5, verify_timeout=1,
        )
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, created_at, finished_at) VALUES('a1','inc1','nerv','nerv:service:frps',"
            " 'service.restart','{}','success',?,?)",
            (now(), now()),
        )
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES('inc1','t','nerv','frps','resolved','done',?,?)",
            (now(), now()),
        )
        prom.samples = []  # 无样本 → failed

        async def run():
            return await actions.verify("a1")

        res = asyncio.run(run())
        self.assertIn(res["status"], ("failed", "inconclusive"))
        inc = db.query_one("SELECT status, need_human FROM incidents WHERE id='inc1'")
        self.assertEqual(inc["status"], "open")
        self.assertEqual(inc["need_human"], 1)
        db.close()
        tmp.cleanup()


class TestOutboxDueFilter(unittest.TestCase):
    def test_due_filtered_before_limit(self):
        src = (Path(__file__).resolve().parents[1] / "ayana" / "notify.py").read_text(encoding="utf-8")
        # 分页寻找到期项，不允许先截取再过滤
        self.assertIn("OFFSET", src)
        self.assertIn("if not self._due(d)", src)
        self.assertLess(src.index("if not self._due(d)"), src.index("if sent >= limit"))


class TestHoldIdempotent(unittest.TestCase):
    def test_hold_not_duplicated(self):
        tmp, db, policy = make_env()
        inc = IncidentService(db)
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, need_human,"
            " created_at, updated_at) VALUES('inc1','t','nerv','frps','open','pending',1,?,?)",
            (now(), now()),
        )
        db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm, alertname,"
            " status, asset_id, object_id, incident_id, first_seen, last_seen, receive_count)"
            " VALUES('ep1','am','fp','s1','TargetDown','resolved','nerv','frps','inc1',?,?,1)",
            (now(), now()),
        )
        for _ in range(3):
            inc.on_episode_resolved("ep1")
        n = db.query_one(
            "SELECT COUNT(*) AS n FROM events WHERE incident_id='inc1' AND type='alert_resolved_hold'"
        )
        self.assertEqual(n["n"], 1)
        db.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
