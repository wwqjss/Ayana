"""六审回归：summary_text、生命周期通知、SQL 到期、空目标重试。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.notify import Notifier


class TestSummaryText(unittest.TestCase):
    def test_summary_text_exists_and_works(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        inc = IncidentService(db)
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES('inc1','nerv/frps 异常','nerv','frps','open','pending',?,?)",
            (now(), now()),
        )
        text = inc.summary_text("inc1")
        self.assertIn("inc1", text)
        self.assertIn("nerv/frps", text)
        self.assertIn("处理中", text)
        self.assertEqual(inc.summary_text("nope"), "未找到事件")
        db.close()
        tmp.cleanup()


class TestLifecycleNotification(unittest.TestCase):
    def test_lifecycle_event_gets_notified(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        n = Notifier(db, default_target="user:1")
        n.set_channel_store(SimpleNamespace(list_enabled=lambda: [
            {"id": "c1", "kind": "qq", "targets": ["user:1"]},
        ]))
        db.execute(
            "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
            ("inc1", now(), "incident_resolved", "resolved", "{}"),
        )
        db.execute(
            "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
            ("inc1", now(), "verified_recovered", "verified", "{}"),
        )
        self.assertEqual(n.compensate_missing(), 2)
        keys = {r["dedup_key"] for r in db.query("SELECT dedup_key FROM notification_outbox")}
        self.assertEqual(len(keys), 2)
        self.assertTrue(all(k.startswith("ev:") for k in keys))
        db.close()
        tmp.cleanup()

    def test_lifecycle_event_without_channels_stays_in_ayana(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        n = Notifier(db, default_target="user:1")
        db.execute(
            "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
            ("inc1", now(), "incident_opened", "opened", '{"body":"x"}'),
        )
        self.assertEqual(n.compensate_missing(), 0)
        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM notification_outbox")["n"], 0)
        db.close()
        tmp.cleanup()


class TestSqlDueFilter(unittest.TestCase):
    def test_flush_uses_next_try_at_sql(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        n = Notifier(db, default_target="user:1")
        # 3 条未到期 + 1 条到期
        for i in range(3):
            db.execute(
                "INSERT INTO notification_outbox(id, dedup_key, channel, target, body, state,"
                " tries, created_at, last_try_at, next_try_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (f"old{i}", f"k{i}", "qq", "user:1", "old", "pending", 1, now(), now(), now() + 600),
            )
        db.execute(
            "INSERT INTO notification_outbox(id, dedup_key, channel, target, body, state,"
            " tries, created_at, last_try_at, next_try_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("now1", "kn", "qq", "user:1", "NOW", "pending", 0, now(), 0, 0),
        )
        sent = []

        async def sender(t, b):
            sent.append(b)
            return True

        n.set_sender(sender)

        async def run():
            return await n.flush(limit=10)

        asyncio.run(run())
        self.assertEqual(sent, ["NOW"])
        db.close()
        tmp.cleanup()


class TestEmptyTargetRetry(unittest.TestCase):
    def test_retry_fills_default_target(self):
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        n = Notifier(db, default_target="")
        # 无默认目标 → failed / missing_target（显式渠道行，测重试补目标）
        ok = n.enqueue(
            dedup_key="k1", target="", body="hello", channel="qq", channel_id="c-qq"
        )
        self.assertFalse(ok)
        row = db.query_one("SELECT state, last_error, target FROM notification_outbox")
        self.assertEqual(row["state"], "failed")
        self.assertEqual(row["target"], "")
        # 配置默认目标后重试
        n.set_default_target("user:1")
        rid = db.query_one("SELECT id FROM notification_outbox")["id"]
        retried = n.retry_failed(rid)
        self.assertEqual(retried, 1)
        row = db.query_one("SELECT state, target FROM notification_outbox")
        self.assertEqual(row["state"], "pending")
        self.assertEqual(row["target"], "user:1")
        db.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
