"""P2：Incident→Session 薄桥。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database, new_id, now  # noqa: E402
from ayana.incidents import IncidentService  # noqa: E402
from ayana.knowledge import KnowledgeBase  # noqa: E402
from ayana.session_bridge import SessionBridge  # noqa: E402
from ayana.mcp_tools import OpsContext, OpsTools  # noqa: E402


def make_db():
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db = Database(Path(tmp.name) / "t.db")
    return tmp, db


def insert_incident(db, inc_id="inc_1", asset="nerv", obj="frps", status="open", gen=1):
    t = now()
    db.execute(
        "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
        " generation, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (inc_id, f"{asset}/{obj}", asset, obj, "warning", status, "pending", gen, t, t),
    )
    return inc_id


class TestSessionBridge(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.kb = KnowledgeBase(self.db, root=self.tmp.name + "/kb")
        Path(self.tmp.name, "kb").mkdir(exist_ok=True)
        self.kb.reload()
        self.bridge = SessionBridge(self.db, knowledge=self.kb)
        self.incidents = IncidentService(self.db)
        self.incidents.session_bridge = self.bridge

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_new_incident_creates_session(self):
        insert_incident(self.db)
        r = self.bridge.ensure_session("inc_1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["action"], "created")
        self.assertTrue(r["session_id"].startswith("sess_"))
        # 时间线留下痕迹
        ev = self.db.query_one(
            "SELECT * FROM events WHERE incident_id='inc_1' AND type='session_opened'"
        )
        self.assertIsNotNone(ev)

    def test_repeat_alert_reuses_session(self):
        insert_incident(self.db)
        a = self.bridge.ensure_session("inc_1")
        b = self.bridge.ensure_session("inc_1")
        c = self.bridge.ensure_session("inc_1")
        self.assertEqual(a["session_id"], b["session_id"])
        self.assertEqual(b["session_id"], c["session_id"])
        self.assertEqual(b["action"], "reused")
        n = self.db.query_one(
            "SELECT COUNT(*) AS n FROM events WHERE incident_id='inc_1' AND type='session_opened'"
        )
        self.assertEqual(n["n"], 1, "重复告警不得重复开会话")

    def test_concurrent_ensure_single_session(self):
        insert_incident(self.db)
        results = []
        errors = []

        def worker():
            try:
                results.append(self.bridge.ensure_session("inc_1"))
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        sids = {r["session_id"] for r in results if r.get("ok")}
        self.assertEqual(len(sids), 1, f"concurrent must converge, got {sids}")
        row = self.db.query_one("SELECT COUNT(*) AS n FROM incident_session")
        self.assertEqual(row["n"], 1)

    def test_restart_recovers_mapping(self):
        insert_incident(self.db)
        before = self.bridge.ensure_session("inc_1")
        sid = before["session_id"]
        # 模拟进程重启：新 Database + 新 Bridge 同库文件
        self.db.close()
        db2 = Database(self.tmp.name + "/t.db")
        self.addCleanup(db2.close)
        br2 = SessionBridge(db2)
        m = br2.get_mapping("inc_1")
        self.assertIsNotNone(m, "映射必须落库可恢复")
        self.assertEqual(m["session_id"], sid)
        again = br2.ensure_session("inc_1")
        self.assertEqual(again["action"], "reused")
        self.assertEqual(again["session_id"], sid)

    def test_episode_hook_opens_session(self):
        """Incident 创建路径自动挂 session（模拟 episode）。"""
        insert_incident(self.db)
        # 直接走 hook 语义：upsert 场景中 _touch_session 被调用
        self.incidents._touch_session("inc_1")
        m = self.bridge.get_mapping("inc_1")
        self.assertIsNotNone(m)

    def test_generation_bump_keeps_same_session(self):
        insert_incident(self.db, gen=1)
        self.bridge.ensure_session("inc_1", generation=1)
        sid = self.bridge.get_mapping("inc_1")["session_id"]
        # 复发升 generation：同一 session 可重复调查
        self.incidents.bump_generation("inc_1")
        m = self.bridge.get_mapping("inc_1")
        self.assertEqual(m["session_id"], sid)
        self.assertEqual(int(m["generation"]), 2)

    def test_write_idempotent_no_double_exec(self):
        insert_incident(self.db)
        self.bridge.ensure_session("inc_1")
        c1 = self.bridge.claim_write("inc_1", "restart:frps")
        self.assertTrue(c1["claimed"])
        self.bridge.complete_write("inc_1", "restart:frps", ok=True, result="active")
        # 重复执行必须被拒
        c2 = self.bridge.claim_write("inc_1", "restart:frps")
        self.assertFalse(c2["claimed"])
        self.assertTrue(c2["already_done"])
        self.assertTrue(self.bridge.is_write_done("inc_1", "restart:frps"))

    def test_write_in_flight_blocks_second_claim(self):
        insert_incident(self.db)
        self.bridge.ensure_session("inc_1")
        self.bridge.claim_write("inc_1", "restart:frps")
        c2 = self.bridge.claim_write("inc_1", "restart:frps")
        self.assertFalse(c2["claimed"])
        self.assertTrue(c2.get("in_flight"))
        self.assertFalse(c2.get("already_done"))

    def test_failed_write_can_retry(self):
        insert_incident(self.db)
        self.bridge.ensure_session("inc_1")
        self.bridge.claim_write("inc_1", "restart:frps")
        self.bridge.complete_write("inc_1", "restart:frps", ok=False, result="timeout")
        self.assertFalse(self.bridge.is_write_done("inc_1", "restart:frps"))
        # 失败可重试：释放后再次 claim
        self.bridge.release_write("inc_1", "restart:frps")
        c = self.bridge.claim_write("inc_1", "restart:frps")
        self.assertTrue(c["claimed"])
        self.bridge.complete_write("inc_1", "restart:frps", ok=True, result="ok")
        self.assertTrue(self.bridge.is_write_done("inc_1", "restart:frps"))

    def test_done_write_survives_restart(self):
        insert_incident(self.db)
        self.bridge.ensure_session("inc_1")
        self.bridge.claim_write("inc_1", "restart:frps")
        self.bridge.complete_write("inc_1", "restart:frps", ok=True, result="ok")
        self.db.close()
        db2 = Database(self.tmp.name + "/t.db")
        self.addCleanup(db2.close)
        br2 = SessionBridge(db2)
        self.assertTrue(br2.is_write_done("inc_1", "restart:frps"))
        c = br2.claim_write("inc_1", "restart:frps")
        self.assertTrue(c["already_done"])

    def test_prompt_includes_knowledge(self):
        md = Path(self.tmp.name, "kb", "frps.md")
        md.write_text(
            "---\nid: frps\ntitle: frps\nstatus: active\ntype: issue\n"
            "objects: [nerv:frps]\ntags: [frps]\nverified: result\nroot_cause: unknown\n---\n"
            "## 有效命令\nsystemctl restart frps\n",
            encoding="utf-8",
        )
        self.kb.reload()
        insert_incident(self.db)
        r = self.bridge.ensure_session("inc_1")
        self.assertIn("Knowledge", r["prompt"])
        self.assertIn("systemctl restart frps", r["prompt"])

    def test_close_incident_closes_session(self):
        insert_incident(self.db)
        self.bridge.ensure_session("inc_1")
        self.incidents.close_manual("inc_1", "done")
        m = self.bridge.get_mapping("inc_1")
        self.assertEqual(m["status"], "closed")


class TestMcpSessionTools(unittest.IsolatedAsyncioTestCase):
    async def test_session_get_and_write_ops(self):
        tmp, db = make_db()
        self.addCleanup(db.close)
        self.addCleanup(tmp.cleanup)
        kb = KnowledgeBase(db, root=tmp.name + "/kb")
        Path(tmp.name, "kb").mkdir(exist_ok=True)
        kb.reload()
        br = SessionBridge(db, knowledge=kb)
        inc = IncidentService(db)
        inc.session_bridge = br
        insert_incident(db)
        tools = OpsTools(
            OpsContext(
                transport=None,
                prom=None,
                incidents=inc,
                knowledge=kb,
                db=db,
                session_bridge=br,
            )
        )
        out = await tools.call("session.get", {"incident_id": "inc_1"})
        self.assertTrue(out["ok"])
        self.assertTrue(out["session_id"].startswith("sess_"))
        br.claim_write("inc_1", "restart:frps")
        br.complete_write("inc_1", "restart:frps", ok=True, result="ok")
        ops = await tools.call("session.write_ops", {"incident_id": "inc_1"})
        self.assertEqual(len(ops["write_ops"]), 1)
        self.assertEqual(ops["write_ops"][0]["status"], "done")


if __name__ == "__main__":
    unittest.main()
