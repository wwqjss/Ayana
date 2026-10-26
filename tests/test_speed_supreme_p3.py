"""P3：MiMo 远端 Session 映射与生命周期。"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database, now  # noqa: E402
from ayana.incidents import IncidentService  # noqa: E402
from ayana.knowledge import KnowledgeBase  # noqa: E402
from ayana.mimo_session import MimoSessionClient, MimoSessionError, RemoteSession  # noqa: E402
from ayana.session_bridge import SessionBridge  # noqa: E402


def make_db():
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db = Database(Path(tmp.name) / "t.db")
    return tmp, db


def insert_incident(db, inc_id="inc_1", asset="nerv", obj="frps"):
    t = now()
    db.execute(
        "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
        " generation, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (inc_id, f"{asset}/{obj}", asset, obj, "warning", "open", "pending", 1, t, t),
    )


class FakeMimo:
    """模拟实测行为：创建/续接/存活/失效。"""

    def __init__(self):
        self.model = "xiaomi-token-plan-cn/mimo-v2.6-pro"
        self.live: set[str] = set()
        self.created: list[str] = []
        self.resumed: list[tuple[str, str]] = []
        self.fail_create = False
        self.fail_resume_code = ""
        self.n = 0

    def create(self, *, title: str, prompt: str, timeout=None):
        if self.fail_create:
            raise MimoSessionError("timeout", "mimo run exceeded 120s")
        self.n += 1
        sid = f"ses_fake{self.n:04d}"
        self.live.add(sid)
        self.created.append(sid)
        return RemoteSession(remote_session_id=sid, status="active", model=self.model, text="PONG")

    def resume(self, remote_session_id: str, prompt: str, *, timeout=None, expect_existing=True):
        if self.fail_resume_code == "session_missing":
            raise MimoSessionError("session_missing", remote_session_id)
        if self.fail_resume_code == "timeout":
            raise MimoSessionError("timeout", "timeout")
        if remote_session_id not in self.live:
            raise MimoSessionError("session_missing", remote_session_id)
        self.resumed.append((remote_session_id, prompt))
        return RemoteSession(remote_session_id=remote_session_id, status="active", text="OK")

    def exists(self, remote_session_id: str, *, timeout: float = 20.0) -> bool:
        return remote_session_id in self.live


class TestRemoteSessionMapping(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.kb = KnowledgeBase(self.db, root=self.tmp.name + "/kb")
        Path(self.tmp.name, "kb").mkdir(exist_ok=True)
        self.kb.reload()
        self.mimo = FakeMimo()
        self.bridge = SessionBridge(self.db, knowledge=self.kb, mimo=self.mimo)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_new_incident_creates_local_and_remote(self):
        insert_incident(self.db)
        r = self.bridge.attach_remote("inc_1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["action"], "created")
        self.assertTrue(r["local_session_id"].startswith("sess_"))
        self.assertTrue(r["remote_session_id"].startswith("ses_fake"))
        m = self.bridge.get_mapping("inc_1")
        self.assertEqual(m["remote_status"], "active")
        self.assertEqual(len(self.mimo.created), 1)

    def test_repeat_alert_reuses_both_sessions(self):
        insert_incident(self.db)
        a = self.bridge.attach_remote("inc_1")
        b = self.bridge.attach_remote("inc_1")
        c = self.bridge.attach_remote("inc_1")
        self.assertEqual(a["local_session_id"], b["local_session_id"])
        self.assertEqual(a["remote_session_id"], b["remote_session_id"])
        self.assertEqual(b["remote_session_id"], c["remote_session_id"])
        self.assertEqual(b["action"], "reused")
        self.assertEqual(len(self.mimo.created), 1, "重复告警不得重复建远端会话")

    def test_restart_recovers_and_resumes_remote(self):
        insert_incident(self.db)
        a = self.bridge.attach_remote("inc_1")
        rid = a["remote_session_id"]
        self.db.close()
        db2 = Database(self.tmp.name + "/t.db")
        self.addCleanup(db2.close)
        br2 = SessionBridge(db2, knowledge=self.kb, mimo=self.mimo)
        r = br2.attach_remote("inc_1")
        self.assertEqual(r["remote_session_id"], rid)
        self.assertEqual(r["action"], "reused", "重启后应续接原远端，不无故新建")
        self.assertEqual(len(self.mimo.created), 1)

    def test_remote_missing_creates_new_but_keeps_history(self):
        insert_incident(self.db)
        a = self.bridge.attach_remote("inc_1")
        old = a["remote_session_id"]
        self.mimo.live.discard(old)  # 远端失效
        r = self.bridge.attach_remote("inc_1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["action"], "created")
        self.assertNotEqual(r["remote_session_id"], old)
        m = self.bridge.get_mapping("inc_1")
        hist = self.bridge._remote_fields(m)["remote_history"]
        self.assertTrue(any(h.get("id") == old for h in hist), "旧远端必须留在历史")
        # 本地 session 不变
        self.assertEqual(m["session_id"], a["local_session_id"])

    def test_two_incidents_isolated(self):
        insert_incident(self.db, "inc_1")
        insert_incident(self.db, "inc_2", asset="kanata", obj="mysql")
        a = self.bridge.attach_remote("inc_1")
        b = self.bridge.attach_remote("inc_2")
        # 工作台模型：同一值班会话承载多 Incident（同一 MiMo 远端）
        self.assertEqual(a["local_session_id"], b["local_session_id"])
        self.assertEqual(a["remote_session_id"], b["remote_session_id"])
        # 但 Incident 事实与写台账彼此独立
        self.bridge.claim_write("inc_1", "k1")
        self.bridge.complete_write("inc_1", "k1", ok=True, result="ok")
        self.assertTrue(self.bridge.is_write_done("inc_1", "k1"))
        self.assertFalse(self.bridge.is_write_done("inc_2", "k1"))
        self.assertEqual(len(self.bridge.write_ops("inc_1")), 1)
        self.assertEqual(len(self.bridge.write_ops("inc_2")), 0)
        # 调查 prompt 覆盖两个故障，由 Agent 判断关联
        self.bridge.prompt_remote("inc_1", "investigate frps")
        self.bridge.prompt_remote("inc_2", "investigate mysql")
        self.assertGreaterEqual(len(self.mimo.resumed), 1)

    def test_prompt_uses_resume_not_recreate(self):
        insert_incident(self.db)
        a = self.bridge.attach_remote("inc_1")
        self.bridge.prompt_remote("inc_1", "next step")
        self.assertEqual(len(self.mimo.created), 1)
        self.assertEqual(self.mimo.resumed[0][0], a["remote_session_id"])

    def test_remote_missing_on_prompt_reports_clearly(self):
        insert_incident(self.db)
        a = self.bridge.attach_remote("inc_1")
        self.mimo.live.discard(a["remote_session_id"])
        r = self.bridge.prompt_remote("inc_1", "hello")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "session_missing")
        m = self.bridge.get_mapping("inc_1")
        self.assertEqual(m["remote_status"], "missing")

    def test_timeout_status_recorded_no_retry_loop(self):
        insert_incident(self.db)
        self.mimo.fail_create = True
        r = self.bridge.attach_remote("inc_1")
        self.assertFalse(r["ok"])
        self.assertEqual(r["code"], "timeout")
        m = self.bridge.get_mapping("inc_1")
        self.assertEqual(m["remote_status"], "timeout")
        # 不无限重试：只调用一次 create
        self.assertEqual(self.mimo.n, 0)

    def test_reconnect_does_not_replay_writes(self):
        insert_incident(self.db)
        a = self.bridge.attach_remote("inc_1")
        self.bridge.claim_write("inc_1", "restart:frps")
        self.bridge.complete_write("inc_1", "restart:frps", ok=True, result="ok")
        self.mimo.live.discard(a["remote_session_id"])
        self.bridge.attach_remote("inc_1")  # 受控新建远端
        # 写台账不被重放
        self.assertTrue(self.bridge.is_write_done("inc_1", "restart:frps"))
        c = self.bridge.claim_write("inc_1", "restart:frps")
        self.assertTrue(c["already_done"])

    def test_no_mimo_client_is_safe(self):
        insert_incident(self.db)
        br = SessionBridge(self.db, knowledge=self.kb, mimo=None)
        r = br.attach_remote("inc_1")
        self.assertTrue(r["ok"])
        self.assertEqual(r["action"], "no_mimo")
        self.assertEqual(r["remote_session_id"], "")

    def test_force_new_appends_history(self):
        insert_incident(self.db)
        a = self.bridge.attach_remote("inc_1")
        r = self.bridge.attach_remote("inc_1", force_new=True)
        self.assertEqual(r["action"], "created")
        self.assertNotEqual(r["remote_session_id"], a["remote_session_id"])
        hist = self.bridge._remote_fields(self.bridge.get_mapping("inc_1"))["remote_history"]
        self.assertGreaterEqual(len(hist), 1)


class TestMimoClientParsing(unittest.TestCase):
    def test_extract_session_id(self):
        out = '{"type":"step_start","sessionID":"ses_abc123","part":{}}'
        self.assertEqual(MimoSessionClient._extract_session_id(out), "ses_abc123")

    def test_extract_text(self):
        out = "\n".join(
            [
                '{"type":"text","sessionID":"ses_1","part":{"type":"text","text":"PONG1"}}',
                '{"type":"step_finish","sessionID":"ses_1"}',
            ]
        )
        self.assertEqual(MimoSessionClient._extract_text(out), "PONG1")

    def test_error_types(self):
        self.assertEqual(MimoSessionError("timeout", "t").code, "timeout")
        self.assertEqual(MimoSessionError("session_missing", "x").code, "session_missing")


if __name__ == "__main__":
    unittest.main()
