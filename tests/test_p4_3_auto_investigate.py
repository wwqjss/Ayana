"""P4.3：无人值守只读调查闭环。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.auto_investigate import (  # noqa: E402
    AutoInvestigator,
    InvestConfig,
    _extract_json,
)
from ayana.db import Database, now  # noqa: E402
from ayana.incidents import IncidentService  # noqa: E402
from ayana.knowledge import KnowledgeBase  # noqa: E402
from ayana.mcp_tools import OpsContext, OpsTools  # noqa: E402
from ayana.ntsafe import NTResult  # noqa: E402
from ayana.session_bridge import SessionBridge  # noqa: E402


def make_db():
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db = Database(Path(tmp.name) / "t.db")
    return tmp, db


def insert_incident(db, inc_id="inc_1", status="open", gen=1):
    t = now()
    db.execute(
        "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
        " generation, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (inc_id, f"{inc_id}-title", "nerv", "frps", "warning", status, "pending", gen, t, t),
    )


async def _drain(ai):
    for t in list(ai._running.values()):
        await asyncio.gather(t, return_exceptions=True)
    ai._running.clear()


def _run_tick(ai):
    """tick 与收尾必须同一事件循环。"""

    async def _both():
        await ai.tick_once()
        await _drain(ai)

    asyncio.run(_both())


class FakeMimo:
    def __init__(self):
        self.calls = []
        self.responses = []
        self.fail = False
        self.model = "test-model"

    def create(self, *, title, prompt, timeout=None):
        self.calls.append(("create", title, prompt[:50]))
        if self.fail:
            raise RuntimeError("api_quota_exhausted")
        text = self.responses.pop(0) if self.responses else '{"status":"completed","root_cause":"unknown","facts":[],"hypotheses":[],"unconfirmed":[],"next_steps":[],"symptoms":"x"}'
        return type("R", (), {"remote_session_id": "ses_test1", "status": "active", "text": text, "model": "m"})()

    def resume(self, remote_session_id, prompt, *, timeout=None, expect_existing=True):
        self.calls.append(("resume", remote_session_id, prompt[:50]))
        if self.fail:
            raise RuntimeError("api_quota_exhausted")
        text = self.responses.pop(0) if self.responses else '{"status":"completed","root_cause":"unknown"}'
        return type("R", (), {"remote_session_id": remote_session_id, "status": "active", "text": text, "model": "m"})()

    def exists(self, remote_session_id, *, timeout=20.0):
        return True


class TestExtractJson(unittest.TestCase):
    def test_fenced(self):
        d = _extract_json('xx\n```json\n{"status":"completed","root_cause":"unknown"}\n```\n')
        self.assertEqual(d["status"], "completed")

    def test_bare(self):
        d = _extract_json('result: {"status":"partial","root_cause":"unknown"} done')
        self.assertEqual(d["status"], "partial")

    def test_bad(self):
        self.assertIsNone(_extract_json("no json here"))
        self.assertIsNone(_extract_json(""))


class TestOfferAndDedup(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.kb = KnowledgeBase(self.db, root=self.tmp.name + "/kb")
        Path(self.tmp.name, "kb").mkdir(exist_ok=True)
        self.kb.reload()
        self.mimo = FakeMimo()
        self.bridge = SessionBridge(self.db, knowledge=self.kb, mimo=self.mimo)
        self.cfg = InvestConfig(enabled=True, max_concurrent=2, cooldown_sec=0.0)
        self.ai = AutoInvestigator(
            self.db, knowledge=self.kb, mimo=self.mimo, bridge=self.bridge, config=self.cfg
        )
        insert_incident(self.db)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_offer_disabled_by_default(self):
        ai = AutoInvestigator(self.db, config=InvestConfig(enabled=False))
        r = ai.offer("inc_1")
        self.assertEqual(r.get("skipped"), "disabled")

    def test_offer_new_incident(self):
        r = self.ai.offer("inc_1")
        self.assertEqual(r["action"], "queued")
        row = self.db.query_one("SELECT * FROM investigation_jobs WHERE incident_id='inc_1'")
        self.assertEqual(row["status"], "queued")

    def test_repeat_firing_no_duplicate(self):
        self.ai.offer("inc_1")
        r2 = self.ai.offer("inc_1")
        self.assertEqual(r2["action"], "noop")
        n = self.db.query_one("SELECT COUNT(*) n FROM investigation_jobs")
        self.assertEqual(n["n"], 1)

    def test_running_blocks_second(self):
        self.ai.offer("inc_1")
        self.db.execute("UPDATE investigation_jobs SET status='running' WHERE incident_id='inc_1'")
        r = self.ai.offer("inc_1")
        self.assertEqual(r["action"], "noop")
        self.assertEqual(r["status"], "running")

    def test_generation_bump_requeues(self):
        self.ai.offer("inc_1", generation=1)
        self.db.execute("UPDATE investigation_jobs SET status='done' WHERE incident_id='inc_1'")
        r = self.ai.offer("inc_1", generation=2)
        self.assertEqual(r["action"], "requeued")
        row = self.db.query_one("SELECT status, generation FROM investigation_jobs")
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["generation"], 2)

    def test_closed_incident_skipped(self):
        insert_incident(self.db, "inc_closed", status="closed")
        r = self.ai.offer("inc_closed")
        self.assertEqual(r.get("skipped"), "not_open")


class TestExecutionLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.kb = KnowledgeBase(self.db, root=self.tmp.name + "/kb")
        Path(self.tmp.name, "kb").mkdir(exist_ok=True)
        self.kb.reload()
        self.mimo = FakeMimo()
        self.bridge = SessionBridge(self.db, knowledge=self.kb, mimo=self.mimo)
        self.cfg = InvestConfig(enabled=True, max_concurrent=2, timeout_sec=5.0, max_rounds=2, cooldown_sec=0.0)
        self.ai = AutoInvestigator(
            self.db, knowledge=self.kb, mimo=self.mimo, bridge=self.bridge, config=self.cfg
        )
        insert_incident(self.db)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_successful_investigation_writes_timeline(self):
        self.mimo.responses.append(
            '{"status":"completed","root_cause":"unknown","facts":[{"claim":"service down","evidence":"systemctl"}],'
            '"hypotheses":[{"claim":"crash","confidence":"low"}],"unconfirmed":[],"next_steps":["check logs"],"symptoms":"TargetDown"}'
        )
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT * FROM investigation_jobs WHERE incident_id='inc_1'")
        self.assertIn(row["status"], ("done", "partial", "running"))
        ev = self.db.query_one(
            "SELECT * FROM events WHERE incident_id='inc_1' AND type='auto_investigation'"
        )
        self.assertIsNotNone(ev, "结论必须进 Incident 时间线")

    def test_timeout_marks_timeout(self):
        self.ai.config.timeout_sec = 0.01

        async def slow(*a, **k):
            await asyncio.sleep(1)
            return {}
        self.ai._investigate = slow  # type: ignore
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT status FROM investigation_jobs")
        self.assertEqual(row["status"], "timeout")

    def test_api_failure_not_infinite_retry(self):
        self.mimo.fail = True
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT status, rounds FROM investigation_jobs")
        self.assertEqual(row["status"], "failed")
        # 冷却内不再排队
        self.cfg.cooldown_sec = 3600
        self.ai.config = self.cfg
        r = self.ai.offer("inc_1")
        self.assertEqual(r.get("action"), "cooldown")

    def test_max_rounds_blocks(self):
        self.ai.offer("inc_1")
        self.db.execute("UPDATE investigation_jobs SET rounds=5, status='queued' WHERE incident_id='inc_1'")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT status, last_error FROM investigation_jobs")
        self.assertEqual(row["status"], "failed")
        self.assertIn("max_rounds", row["last_error"])

    def test_restart_recover_expires_running(self):
        self.ai.offer("inc_1")
        self.db.execute(
            "UPDATE investigation_jobs SET status='running', lease_expires_at=1 WHERE incident_id='inc_1'"
        )
        r = self.ai.recover()
        self.assertEqual(r["expired"], 1)
        row = self.db.query_one("SELECT status FROM investigation_jobs")
        self.assertEqual(row["status"], "failed")
        self.assertFalse(self.ai._running)

    def test_no_auto_close_incident(self):
        self.mimo.responses.append('{"status":"completed","root_cause":"unknown"}')
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        inc = self.db.query_one("SELECT status FROM incidents WHERE id='inc_1'")
        self.assertEqual(inc["status"], "open", "调查完成不得自动关闭事件")

    def test_concurrency_limit(self):
        for i in range(4):
            insert_incident(self.db, f"inc_q{i}")
        for i in range(4):
            self.ai.offer(f"inc_q{i}")
        asyncio.run(self.ai.tick_once())
        running = [r for r in self.ai._running]
        self.assertLessEqual(len(running), 2, "全局并发不得超过 max_concurrent")

    def test_parallel_incidents_isolated(self):
        insert_incident(self.db, "inc_a")
        insert_incident(self.db, "inc_b")
        self.mimo.responses.append('{"status":"completed","root_cause":"unknown","symptoms":"A"}')
        self.mimo.responses.append('{"status":"completed","root_cause":"unknown","symptoms":"B"}')
        self.ai.offer("inc_a")
        self.ai.offer("inc_b")
        _run_tick(self.ai)
        n = self.db.query_one(
            "SELECT COUNT(*) n FROM events WHERE type='auto_investigation'"
        )
        self.assertGreaterEqual(n["n"], 1)

    def test_malformed_output_not_fake_success(self):
        self.mimo.responses.append("完全不是 JSON 的胡言乱语")
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT status, last_conclusion_json FROM investigation_jobs")
        self.assertIn(row["status"], ("partial", "failed"))
        self.assertIn("raw_excerpt", row["last_conclusion_json"])


class TestReadonlyBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.transport = MagicMock()

        async def exec_shell(asset_id, command, timeout=None, *, channel="write"):
            return NTResult(ok=True, output="ok", returncode=0)
        self.transport.exec_shell = exec_shell
        self.tools = OpsTools(
            OpsContext(
                transport=self.transport,
                prom=MagicMock(),
                incidents=MagicMock(),
                knowledge=MagicMock(),
                db=self.db,
                readonly=True,
            )
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_readonly_rejects_write_command(self):
        with self.assertRaises(Exception) as cm:
            asyncio.run(
                self.tools.call(
                    "host.exec",
                    {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "write"},
                )
            )
        self.assertEqual(getattr(cm.exception, "code", ""), "readonly_mode_rejects_write")

    def test_readonly_rejects_shell_wrappers(self):
        for cmd in (
            "cat /etc/passwd | tee /tmp/x",
            "echo hi > /tmp/x",
            "sed -i s/a/b/ /etc/hosts",
            "rm -rf /tmp/x",
            "sudo systemctl stop frps",
        ):
            with self.assertRaises(Exception):
                asyncio.run(
                    self.tools.call(
                        "host.exec",
                        {"asset_id": "nerv", "command": cmd, "channel": "read"},
                    )
                )

    def test_readonly_allows_read(self):
        out = asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "uptime", "channel": "read"},
            )
        )
        self.assertTrue(out["ok"])
        self.assertTrue(out.get("readonly"))

    def test_readonly_rejects_knowledge_upsert_and_close(self):
        with self.assertRaises(Exception) as cm:
            asyncio.run(self.tools.call("knowledge.upsert", {"title": "x", "objects": ["a:b"]}))
        self.assertEqual(getattr(cm.exception, "code", ""), "readonly_mode_rejects_write")
        with self.assertRaises(Exception) as cm:
            asyncio.run(self.tools.call("incident.close", {"incident_id": "i", "reason": "r"}))
        self.assertEqual(getattr(cm.exception, "code", ""), "readonly_mode_rejects_write")

    def test_rejection_audited(self):
        try:
            asyncio.run(
                self.tools.call(
                    "host.exec",
                    {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "write"},
                )
            )
        except Exception:
            pass
        row = self.db.query_one("SELECT * FROM audit_log WHERE entry='mcp_host_exec_write'")
        self.assertIsNotNone(row)


class TestKnowledgeDiscipline(unittest.TestCase):
    def test_auto_investigation_cannot_claim_verified(self):
        tmp, db = make_db()
        self.addCleanup(db.close)
        self.addCleanup(tmp.cleanup)
        kb = KnowledgeBase(db, root=Path(tmp.name) / "kb")
        Path(tmp.name, "kb").mkdir(exist_ok=True)
        kb.reload()
        insert_incident(db)
        ai = AutoInvestigator(db, knowledge=kb, mimo=FakeMimo(), bridge=None, config=InvestConfig(enabled=True))
        ai._maybe_write_knowledge(
            "inc_1",
            {
                "status": "completed",
                "root_cause": "unknown",
                "symptoms": "down",
                "knowledge_write": {
                    "enabled": True,
                    "verified": "result",
                    "title": "auto inv",
                    "body": "body",
                },
            },
        )
        docs = kb.list_docs()
        self.assertTrue(docs)
        self.assertNotEqual(docs[0].verified, "result", "自动调查不得写 verified=result")


if __name__ == "__main__":
    unittest.main()
