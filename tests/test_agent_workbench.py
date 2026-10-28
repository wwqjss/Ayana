"""Agent 工作台：值班会话 / 手动会话 / 归档倒计时 / 审批开关。"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionService  # noqa: E402
from ayana.db import Database, now  # noqa: E402
from ayana.duty_session import DutySessionManager  # noqa: E402
from ayana.session_bridge import SessionBridge  # noqa: E402


class FakeTransport:
    async def exec(self, *a, **k):
        class R:
            stdout = "ok"
            stderr = ""
            returncode = 0
            truncated = False

        return R()

    async def probe(self, *a, **k):
        return await self.exec()


class FakeGate:
    pass


class FakePolicy:
    def effective_decision(self, **kw):
        return {
            "decision": "approval_required",
            "allowed": True,
            "require_approval": True,
            "auto_allowed": False,
            "reason": "ok",
            "rule": None,
            "agent_ceiling": {"allowed": True},
        }

    def check(self, **kw):
        return {"allowed": True, "decision": "approval_required", "require_approval": True, "auto_allowed": False}


class FakeProm:
    async def probe_success_since(self, *a, **k):
        return []


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
        " VALUES('inc1','t1','host','frps','warning','open','pending',1,?,?)",
        (t, t),
    )
    db.execute(
        "INSERT INTO incidents(id,title,asset_id,object_id,severity,status,stage,generation,created_at,updated_at)"
        " VALUES('inc2','t2','host','frps','warning','open','pending',1,?,?)",
        (t, t),
    )


class DutySessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        _seed(self.db)
        self.duty = DutySessionManager(self.db, archive_delay_sec=300)
        self.bridge = SessionBridge(self.db, duty=self.duty)

    def tearDown(self):
        self.tmp.cleanup()

    def test_auto_session_shared_across_incidents(self):
        r1 = self.bridge.ensure_session("inc1")
        self.assertTrue(r1["ok"])
        r2 = self.bridge.ensure_session("inc2")
        self.assertTrue(r2["ok"])
        self.assertEqual(r1["session_id"], r2["session_id"])
        incs = self.duty.incidents(r1["session_id"])
        self.assertEqual({i["incident_id"] for i in incs}, {"inc1", "inc2"})

    def test_manual_session_independent(self):
        manual = self.duty.create(origin="manual", title="查磁盘", created_by="alice")
        self.assertTrue(manual["ok"])
        self.assertEqual(manual["origin"], "manual")
        auto = self.bridge.ensure_session("inc1")
        self.assertNotEqual(manual["session_id"], auto["session_id"])

    def test_archive_countdown_and_cancel(self):
        sid = self.bridge.ensure_session("inc1")["session_id"]
        # 未全部关闭：不启动倒计时
        self.db.execute("UPDATE incidents SET status='open' WHERE id='inc1'")
        res = self.duty.maybe_start_archive_countdown(sid)
        self.assertEqual(res["action"], "keep_open")
        # 全部关闭：启动倒计时
        self.db.execute("UPDATE incidents SET status='closed' WHERE id='inc1'")
        res = self.duty.maybe_start_archive_countdown(sid)
        self.assertEqual(res["action"], "countdown")
        self.assertGreater(res["archive_due_at"], 0)
        # 新告警取消倒计时
        self.duty.cancel_archive(sid)
        s = self.duty.get(sid)
        self.assertEqual(float(s["archive_due_at"] or 0), 0)
        # 重新启动后 tick 归档
        self.duty.maybe_start_archive_countdown(sid)
        self.db.execute("UPDATE duty_sessions SET archive_due_at=? WHERE id=?", (now() - 1, sid))
        out = self.duty.tick_archives()
        self.assertIn(sid, out["archived"])
        self.assertEqual(self.duty.get(sid)["status"], "archived")

    def test_manual_session_not_auto_archived(self):
        manual = self.duty.create(origin="manual", title="x", created_by="a")
        sid = manual["session_id"]
        res = self.duty.maybe_start_archive_countdown(sid)
        self.assertEqual(res["action"], "noop")

    def test_auto_title(self):
        sid = self.bridge.ensure_session("inc1")["session_id"]
        self.bridge.ensure_session("inc2")
        title = self.duty.auto_title_from_incidents(sid)
        self.assertTrue(title)

    def test_recover_restores_countdown(self):
        sid = self.bridge.ensure_session("inc1")["session_id"]
        self.db.execute("UPDATE incidents SET status='closed' WHERE id='inc1'")
        self.db.execute("UPDATE duty_sessions SET archive_due_at=0 WHERE id=?", (sid,))
        out = self.duty.recover()
        self.assertIn(sid, out["countdown_restored"])

    def test_settings_default_automatic_approval(self):
        # 旧全局审批开关已退役：默认自主执行，审批档位由 auto_approval_mode 表达
        s = self.duty.settings()
        self.assertEqual(s["auto_approval_mode"], "automatic")
        self.duty.set_setting("auto_approval_mode", "manual", actor="t")
        self.assertEqual(self.duty.settings()["auto_approval_mode"], "manual")


class PendingWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        _seed(self.db)
        self.duty = DutySessionManager(self.db)
        self.bridge = SessionBridge(self.db, duty=self.duty)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pending_write_approve_reject(self):
        self.bridge.ensure_session("inc1")
        key = self.bridge.make_action_key("host", "exec_shell", {"command": "uptime"})
        p = self.bridge.pending_write("inc1", key, target="host", params={"command": "uptime", "channel": "read"})
        self.assertTrue(p["ok"])
        # 重复 pending 幂等
        p2 = self.bridge.pending_write("inc1", key, target="host", params={"command": "uptime"})
        self.assertTrue(p2["ok"])
        self.assertEqual(p2.get("action"), "already_pending")
        pend = self.bridge.list_pending_writes()
        self.assertTrue(any(w["action_key"] == key for w in pend))
        approved = self.bridge.approve_pending_write("inc1", key, approved_by="alice")
        self.assertTrue(approved["ok"])
        self.assertTrue(approved["claimed"])
        self.bridge.complete_write("inc1", key, ok=True, result="ok")
        self.assertTrue(self.bridge.is_write_done("inc1", key))

    def test_reject_pending(self):
        self.bridge.ensure_session("inc1")
        key = self.bridge.make_action_key("host", "exec_shell", {"command": "reboot"})
        self.bridge.pending_write("inc1", key, target="host", params={"command": "reboot"})
        self.bridge.reject_pending_write("inc1", key, reason="too_risky")
        row = self.db.query_one(
            "SELECT status FROM session_write_ops WHERE incident_id=? AND action_key=?",
            ("inc1", key),
        )
        self.assertEqual(row["status"], "failed")



if __name__ == "__main__":
    unittest.main()
