"""五审回归：通知补偿、分页到期、51 续验、hold 收敛、重复 resolved。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionService
from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.notify import Notifier
from ayana.ntsafe import NTResult
from ayana.policy import Policy


class FakeNT:
    async def probe(self, *a, **k):
        return NTResult(ok=True, output="ok", returncode=0)

    async def exec(self, *a, **k):
        return NTResult(ok=True, output="ok", returncode=0)

    async def identity(self, *a, **k):
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
    async def probe_success_since(self, *a, **k):
        return []


class TestNotificationCompensation(unittest.TestCase):
    def test_event_without_outbox_gets_compensated(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        n = Notifier(db, default_target="user:1")
        # 模拟：生命周期 Event 已写但 outbox 入队失败
        db.execute(
            "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
            ("inc1", now(), "incident_opened", "x", '{"body":"hello"}'),
        )
        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM notification_outbox")["n"], 0)
        fixed = n.compensate_missing()
        self.assertEqual(fixed, 1)
        row = db.query_one("SELECT dedup_key, body FROM notification_outbox")
        self.assertTrue(row["dedup_key"].startswith("ev:"))
        self.assertIn("hello", row["body"])
        db.close()
        tmp.cleanup()


class TestOutboxPagination(unittest.TestCase):
    def test_201_not_blocked_by_old(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        n = Notifier(db, default_target="user:1")
        t0 = now()
        # 201 条旧通知（未到期，next_try_at 在未来）
        for i in range(201):
            db.execute(
                "INSERT INTO notification_outbox(id, dedup_key, channel, target, body, state,"
                " tries, created_at, last_try_at, next_try_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (f"old{i}", f"k{i}", "qq", "user:1", "old", "pending", 1, t0, now(), t0 + 600),
            )
        # 1 条紧急（立即到期）
        db.execute(
            "INSERT INTO notification_outbox(id, dedup_key, channel, target, body, state,"
            " tries, created_at, last_try_at, next_try_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("urgent", "k-urgent", "qq", "user:1", "urgent", "pending", 0, now(), 0, 0),
        )

        sent_boxes = []

        async def sender(target, body):
            sent_boxes.append(body)
            return True

        n.set_sender(sender)

        async def run():
            return await n.flush(limit=5)

        asyncio.run(run())
        self.assertIn("urgent", sent_boxes)
        db.close()
        tmp.cleanup()


class TestResume51(unittest.TestCase):
    def test_fifty_one_verifications_all_scheduled(self):
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
        actions = ActionService(
            db, FakeNT(), FakeGate(), policy, FakeProm(),
            action_ttl=1800, approval_ttl=900, verify_window=1, verify_timeout=1,
        )
        for i in range(51):
            aid = f"a{i:03d}"
            db.execute(
                "INSERT INTO actions(id, asset_id, object_id, capability, params_json, state,"
                " created_at, finished_at) VALUES(?,?,?,?,?,?,?,?)",
                (aid, "nerv", "nerv:service:frps", "service.restart", "{}", "success", t, t),
            )
        n = actions.backfill_missing_verifications()
        self.assertEqual(n, 51)
        # 同步创建任务计数应覆盖全部 51（游标遍历）
        scheduled = actions.resume_pending_verifications()
        self.assertEqual(scheduled, 51)
        db.close()
        tmp.cleanup()


class TestHoldConvergence(unittest.TestCase):
    def test_hold_released_when_obligations_clear(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        inc = IncidentService(db)
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, need_human,"
            " created_at, updated_at) VALUES('inc1','t','nerv','frps','open','watching',0,?,?)",
            (now(), now()),
        )
        db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm, alertname,"
            " status, asset_id, object_id, incident_id, first_seen, last_seen, receive_count)"
            " VALUES('ep1','am','fp','s1','T','resolved','nerv','frps','inc1',?,?,1)",
            (now(), now()),
        )
        # 无 firing、无 blocked、无 need_human → 收敛
        inc.reevaluate_after_action("inc1")
        row = db.query_one("SELECT status FROM incidents WHERE id='inc1'")
        self.assertEqual(row["status"], "resolved")
        db.close()
        tmp.cleanup()


class TestDuplicateResolved(unittest.TestCase):
    def test_resolved_event_once(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        inc = IncidentService(db)
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES('inc1','t','nerv','frps','open','pending',?,?)",
            (now(), now()),
        )
        db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm, alertname,"
            " status, asset_id, object_id, incident_id, first_seen, last_seen, receive_count)"
            " VALUES('ep1','am','fp','s1','T','resolved','nerv','frps','inc1',?,?,1)",
            (now(), now()),
        )
        for _ in range(3):
            inc.on_episode_resolved("ep1")
        n = db.query_one(
            "SELECT COUNT(*) AS n FROM events WHERE incident_id='inc1' AND type='incident_resolved'"
        )
        self.assertEqual(n["n"], 1)
        db.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
