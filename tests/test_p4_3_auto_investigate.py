"""P4.3：无人值守只读调查闭环。"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

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


    def test_bare_nested_conclusion(self):
        expected = {
            "status": "completed",
            "facts": [{"claim": "read", "evidence": {"ok": True}}],
            "root_cause": "unknown",
        }
        self.assertEqual(_extract_json(json.dumps(expected)), expected)

    def test_final_conclusion_wins_over_prelude(self):
        text = '{"status":"partial"}\nFinal:\n{"status":"completed","facts":[{"claim":"read"}]}'
        self.assertEqual(_extract_json(text)["status"], "completed")

    def test_last_fenced_conclusion_wins(self):
        text = '```json\n{"status":"partial"}\n```\n```JSON\n{"status":"completed","facts":[{"claim":"read"}]}\n```'
        self.assertEqual(_extract_json(text)["status"], "completed")

    def test_braces_and_escaped_quotes_in_evidence(self):
        expected = {"status": "partial", "facts": [{"evidence": 'literal } { and "quoted" \\ path'}]}
        self.assertEqual(_extract_json('Conclusion: ' + json.dumps(expected)), expected)

    def test_truncated_nested_output_is_not_an_inner_conclusion(self):
        self.assertIsNone(_extract_json('{"status":"completed","facts":[{"claim":"read"}]'))


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
        self.db.execute(
            "UPDATE investigation_jobs SET status='failed', rounds=3, last_error='old failure',"
            " last_result_status='failed', last_conclusion_json='old conclusion' WHERE incident_id='inc_1'"
        )
        r = self.ai.offer("inc_1", generation=2)
        self.assertEqual(r["action"], "requeued")
        row = self.db.query_one("SELECT * FROM investigation_jobs")
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["generation"], 2)
        self.assertEqual(row["rounds"], 0)
        self.assertEqual(row["last_error"], "")
        self.assertEqual(row["last_result_status"], "")
        self.assertEqual(row["last_conclusion_json"], "")

    def test_same_generation_retry_keeps_round_budget(self):
        self.ai.offer("inc_1")
        self.db.execute("UPDATE investigation_jobs SET status='failed', rounds=1, updated_at=0")
        self.assertEqual(self.ai.offer("inc_1")["action"], "requeued")
        self.assertEqual(self.db.query_one("SELECT rounds FROM investigation_jobs")["rounds"], 1)

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
        self.assertEqual(row["status"], "done")
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
        # Parallel calls are not ordered. Bind each scripted reply to its
        # Incident, as real independent MiMo sessions are, rather than popping
        # a shared FIFO that accidentally assigns A/B by thread scheduling.
        entered = threading.Barrier(2)
        def create(*, title, prompt, timeout=None):
            incident_id = title.removeprefix("inv:")
            symptoms = {"inc_a": "A", "inc_b": "B"}[incident_id]
            self.assertIn(f"## Incident {incident_id} (", prompt)
            entered.wait(timeout=2)
            self.mimo.calls.append(("create", title, prompt))
            return type("R", (), {"remote_session_id": f"ses_{incident_id}", "status": "active",
                                  "text": json.dumps({"status":"completed", "root_cause":"unknown", "symptoms":symptoms}),
                                  "model":"test-model"})()
        self.mimo.create = create
        self.ai.offer("inc_a")
        self.ai.offer("inc_b")
        _run_tick(self.ai)
        n = self.db.query_one(
            "SELECT COUNT(*) n FROM events WHERE type='auto_investigation'"
        )
        self.assertEqual(n["n"], 2)
        for incident_id, symptoms in (("inc_a", "A"), ("inc_b", "B")):
            row = self.db.query_one("SELECT * FROM investigation_jobs WHERE incident_id=?", (incident_id,))
            self.assertEqual(row["status"], "done")
            self.assertEqual(json.loads(row["last_conclusion_json"])["symptoms"], symptoms)
            mapping = self.bridge.get_mapping(incident_id)
            self.assertEqual(mapping["remote_session_id"], f"ses_{incident_id}")

    def test_new_generation_runs_after_previous_round_budget_exhausted(self):
        self.ai.offer("inc_1")
        self.db.execute("UPDATE investigation_jobs SET status='failed', rounds=2")
        self.db.execute("UPDATE incidents SET generation=2 WHERE id='inc_1'")
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT * FROM investigation_jobs")
        self.assertEqual(row["generation"], 2)
        self.assertEqual(row["status"], "done")
        self.assertEqual(row["rounds"], 1)
        self.assertEqual(len(self.mimo.calls), 1)

    def test_obsolete_generation_does_not_start_remote_work(self):
        self.ai.offer("inc_1")
        stale_job = self.ai._row("inc_1")
        self.ai.offer("inc_1", generation=2)
        asyncio.run(self.ai._run_job("inc_1", stale_job))
        self.assertEqual(self.mimo.calls, [])
        row = self.db.query_one("SELECT generation, status FROM investigation_jobs")
        self.assertEqual((row["generation"], row["status"]), (2, "queued"))

    def test_old_generation_result_cannot_overwrite_recurrence_or_write_knowledge(self):
        async def race():
            entered = asyncio.Event()
            release = asyncio.Event()
            original_investigate = self.ai._investigate

            async def old_investigation(*args, **kwargs):
                entered.set()
                await release.wait()
                return {
                    "status": "completed",
                    "root_cause": "unknown",
                    "knowledge_write": {"enabled": True, "title": "stale knowledge", "body": "old generation"},
                }

            self.ai._investigate = old_investigation
            self.ai.offer("inc_1")
            await self.ai.tick_once()
            await asyncio.wait_for(entered.wait(), timeout=1)
            self.db.execute("UPDATE incidents SET generation=2 WHERE id='inc_1'")
            self.ai.offer("inc_1")
            release.set()
            await _drain(self.ai)
            row = self.ai._row("inc_1")
            self.assertEqual((row["generation"], row["status"], row["rounds"]), (2, "queued", 0))
            self.assertEqual(row["last_conclusion_json"], "")
            self.assertEqual(self.kb.list_docs(), [])
            self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM events WHERE type='auto_investigation'")["n"], 0)
            self.ai._investigate = original_investigate
            await self.ai.tick_once()
            await _drain(self.ai)
            row = self.ai._row("inc_1")
            self.assertEqual((row["generation"], row["status"], row["rounds"]), (2, "done", 1))

        asyncio.run(race())

    def test_malformed_output_not_fake_success(self):
        self.mimo.responses.append("完全不是 JSON 的胡言乱语")
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT status, last_conclusion_json FROM investigation_jobs")
        self.assertIn(row["status"], ("partial", "failed"))
        self.assertIn("raw_excerpt", row["last_conclusion_json"])


    def test_tool_result_json_is_not_a_completed_conclusion(self):
        self.mimo.responses.append('{"ok":true,"assets":[]}')
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT status, last_conclusion_json FROM investigation_jobs")
        self.assertEqual(row["status"], "partial")
        self.assertEqual(json.loads(row["last_conclusion_json"])["root_cause"], "unknown")

    def test_malformed_conclusion_collections_are_partial(self):
        self.mimo.responses.append('{"status":"completed","facts":{"evidence":"tool"}}')
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT status FROM investigation_jobs")
        self.assertEqual(row["status"], "partial")

    def test_root_cause_without_evidence_is_unknown(self):
        self.mimo.responses.append('{"status":"completed","root_cause":"claimed crash","facts":[{"claim":"crash"}]}')
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT last_conclusion_json FROM investigation_jobs")
        self.assertEqual(json.loads(row["last_conclusion_json"])["root_cause"], "unknown")

    def test_root_cause_with_evidence_is_preserved(self):
        self.mimo.responses.append('{"status":"completed","root_cause":"service exited","facts":[{"claim":"service exited","evidence":"service status: exited"}]}')
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT last_conclusion_json FROM investigation_jobs")
        self.assertEqual(json.loads(row["last_conclusion_json"])["root_cause"], "service exited")

    def test_long_created_response_reaches_valid_persisted_conclusion(self):
        self._assert_long_conclusion(reused=False)

    def test_long_resumed_response_reaches_valid_persisted_conclusion(self):
        self._assert_long_conclusion(reused=True)

    def _assert_long_conclusion(self, *, reused):
        if reused:
            attached = self.bridge.attach_remote("inc_1")
            self.assertEqual(attached["action"], "created")
        evidence = "read-only MCP evidence " * 800
        payload = {
            "status": "completed",
            "symptoms": "long response",
            "facts": [{"claim": "read succeeded", "evidence": evidence}],
            "hypotheses": [],
            "unconfirmed": [],
            "next_steps": [],
            "root_cause": "unknown",
        }
        text = "Investigating...\n" + json.dumps(payload)
        self.assertGreater(len(text), 8000)
        self.mimo.responses.append(text)
        self.ai.offer("inc_1")
        _run_tick(self.ai)
        row = self.db.query_one("SELECT * FROM investigation_jobs WHERE incident_id='inc_1'")
        self.assertEqual(row["status"], "done")
        saved = json.loads(row["last_conclusion_json"])
        self.assertEqual(saved["facts"], payload["facts"])
        self.assertEqual(saved["remote_session_id"], "ses_test1")
        self.assertGreater(len(row["last_conclusion_json"]), 8000)
        self.assertEqual(self.mimo.calls[-1][0], "resume" if reused else "create")
        event = self.db.query_one("SELECT * FROM events WHERE type='auto_investigation'")
        self.assertEqual(json.loads(event["payload_json"])["fact_count"], 1)


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


    def test_readonly_rejects_command_and_argument_bypasses_before_transport(self):
        self.transport.exec_shell = AsyncMock(return_value=NTResult(ok=True, output="ok", returncode=0))
        for command in (
            "uptime; touch /tmp/x",
            "uptime$(touch /tmp/x)",
            "date -s 2026-01-01",
            "curl -q -X POST http://localhost",
            "wget -O /tmp/x http://localhost",
            "ip link set lo down",
            "env PATH=/tmp uptime",
        ):
            with self.subTest(command=command), self.assertRaises(Exception) as cm:
                asyncio.run(self.tools.call("host.exec", {"asset_id": "nerv", "command": command, "channel": "read"}))
            self.assertEqual(getattr(cm.exception, "code", ""), "readonly_mode_rejects_write")
        self.transport.exec_shell.assert_not_awaited()

    def test_readonly_normal_reads_use_read_transport_even_with_default_channel(self):
        self.transport.exec_shell = AsyncMock(return_value=NTResult(ok=True, output="ok", returncode=0))
        for command in ("uptime", "systemctl status --no-pager frps"):
            with self.subTest(command=command):
                out = asyncio.run(self.tools.call("host.exec", {"asset_id": "nerv", "command": command}))
                self.assertTrue(out["ok"])
                self.assertTrue(out["readonly"])
                self.assertEqual(self.transport.exec_shell.await_args.kwargs["channel"], "read")

    def test_readonly_rejects_note_and_remote_session_before_side_effects(self):
        bridge = MagicMock()
        self.tools.ctx.session_bridge = bridge
        for name, args in (
            ("incident.note", {"incident_id": "inc_1", "text": "mutation"}),
            ("session.remote", {"incident_id": "inc_1", "prompt": "start another session"}),
        ):
            with self.subTest(name=name), self.assertRaises(Exception) as cm:
                asyncio.run(self.tools.call(name, args))
            self.assertEqual(getattr(cm.exception, "code", ""), "readonly_mode_rejects_write")
        self.assertFalse(bridge.mock_calls)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM events")["n"], 0)


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


    def test_auto_knowledge_always_speculative_for_all_supplied_labels(self):
        tmp, db = make_db()
        try:
            kb = KnowledgeBase(db, root=Path(tmp.name) / "kb")
            Path(tmp.name, "kb").mkdir(exist_ok=True)
            kb.reload()
            insert_incident(db)
            ai = AutoInvestigator(db, knowledge=kb, config=InvestConfig(enabled=True))
            for verified in ("none", "invalid", "result", "speculation"):
                with self.subTest(verified=verified):
                    ai._maybe_write_knowledge("inc_1", {
                        "status": "completed", "symptoms": "auto draft", "root_cause": "unknown",
                        "knowledge_write": {"enabled": True, "title": "auto draft", "body": "unverified", "verified": verified},
                    })
                    docs = kb.list_docs()
                    self.assertEqual(len(docs), 1)
                    self.assertEqual(docs[0].verified, "speculation")
                    self.assertEqual(docs[0].status, "draft")
                    self.assertEqual(kb.docs_for_object("nerv", "frps"), [])
        finally:
            db.close()
            tmp.cleanup()

    def test_same_named_verified_document_is_preserved(self):
        tmp, db = make_db()
        try:
            kb = KnowledgeBase(db, root=Path(tmp.name) / "kb")
            Path(tmp.name, "kb").mkdir(exist_ok=True)
            kb.reload()
            insert_incident(db)
            original = kb.upsert(title="same title", objects=["nerv:frps"], tags=["auto-investigation"], body="verified evidence", verified="result")
            ai = AutoInvestigator(db, knowledge=kb, config=InvestConfig(enabled=True))
            ai._maybe_write_knowledge("inc_1", {
                "status": "completed", "root_cause": "unknown",
                "knowledge_write": {"enabled": True, "title": "same title", "body": "unverified guess", "verified": "none"},
            })
            fact = kb.get(original["doc_id"])
            self.assertEqual((fact.verified, fact.status, fact.body), ("result", "active", "verified evidence"))
            docs = kb.list_docs()
            self.assertEqual(len(docs), 2)
            self.assertEqual([doc.id for doc in kb.docs_for_object("nerv", "frps")], [fact.id])
            self.assertNotIn("unverified guess", kb.investigation_context("nerv", "frps")["context_text"])
        finally:
            db.close()
            tmp.cleanup()

    def test_auto_draft_id_cannot_overwrite_a_promoted_verified_fact(self):
        tmp, db = make_db()
        try:
            kb = KnowledgeBase(db, root=Path(tmp.name) / "kb")
            Path(tmp.name, "kb").mkdir(exist_ok=True)
            kb.reload()
            insert_incident(db)
            ai = AutoInvestigator(db, knowledge=kb, config=InvestConfig(enabled=True))
            payload = {"status": "completed", "knowledge_write": {"enabled": True, "title": "draft", "body": "guess"}}
            ai._maybe_write_knowledge("inc_1", payload)
            draft = kb.list_docs()[0]
            kb.upsert(doc_id=draft.id, title="verified", objects=["nerv:frps"], body="verified evidence", verified="result")
            ai._maybe_write_knowledge("inc_1", payload)
            fact = kb.get(draft.id)
            self.assertEqual((fact.verified, fact.status, fact.body), ("result", "active", "verified evidence"))
        finally:
            db.close()
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
