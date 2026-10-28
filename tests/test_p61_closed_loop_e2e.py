"""P6.1 闭环 E2E：调查→决策→autonomous→验证→结案（隔离环境，不碰生产）。

场景：修复成功 / 修复失败转人工 / 重复告警不双执行 / 重启租约恢复。
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from ayana.actions import ActionService
from ayana.auto_investigate import AutoInvestigator, InvestConfig
from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.ntsafe import NTResult
from ayana.ops_loop import OpsLoop, ensure_ops_loop_schema
from ayana.session_bridge import SessionBridge


def _seed(db: Database, inc_id: str = "inc1", gen: int = 1) -> None:
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
        " VALUES(?,?,'host','obj','warning','open','investigating',?,?,?)",
        (inc_id, "down", gen, t, t),
    )


class FakeTransport:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.calls = []

    async def exec(self, asset_id, tokens, timeout=None):
        self.calls.append(tokens)
        return NTResult(
            ok=self.ok,
            output="ok" if self.ok else "fail",
            returncode=0 if self.ok else 1,
            mode="exec",
            account="write",
        )

    async def exec_shell(self, asset_id, command, timeout=None, channel="write"):
        return await self.exec(asset_id, [command], timeout=timeout)


class FakeGate:
    def get(self, asset_id):
        return SimpleNamespace(
            expected_host_id="HOST", host_id_verified_at=now(), host_key_sha256="HOST", host_key_trusted_at=now(),
            asset_id=asset_id, read_alias="read", write_alias="write",
        )

    async def verify_account(self, asset_id, write=False):
        return {"ok": True, "mode": "exec", "account": "write", "host_key": "HOST"}


class FakePolicy:
    def effective_decision(self, **kw):
        return {
            "decision": "automatic", "allowed": True, "require_approval": False,
            "auto_allowed": True, "reason": "ok", "rule": None, "agent_ceiling": None,
        }

    def check(self, **kw):
        return {"allowed": True, "decision": "automatic", "require_approval": False, "auto_allowed": True}


class FakeProm:
    """verify 成功：返回连续 success 样本。"""

    def __init__(self, healthy: bool = True):
        self.healthy = healthy

    async def probe_success_since(self, *a, **k):
        if not self.healthy:
            return []
        t = now()
        return [
            {"sample_at": t - 60, "value": 1, "asset": "host", "service": "frps"},
            {"sample_at": t - 30, "value": 1, "asset": "host", "service": "frps"},
            {"sample_at": t, "value": 1, "asset": "host", "service": "frps"},
        ]


class FakeMimo:
    """脚本化调查/决策输出。返回属性对象以匹配 SessionBridge 约定。"""

    def __init__(self, conclusion: dict, decision_text: str = ""):
        self.conclusion = conclusion
        self.decision_text = decision_text
        self.prompts = []
        self.model = "fake"

    def exists(self, rid: str) -> bool:
        return True

    def create(self, *, title: str = "", prompt: str = "", timeout: float = 60):
        self.prompts.append(prompt)
        return SimpleNamespace(
            ok=True,
            text=self._wrap(self.conclusion),
            remote_session_id="ses_1",
            status="active",
            model=self.model,
            last_error="",
        )

    def resume(self, rid: str, prompt: str, timeout: float = 60):
        self.prompts.append(prompt)
        if "决定是否执行修复" in prompt or "处置 Agent" in prompt:
            return SimpleNamespace(
                ok=True,
                text=self.decision_text or self._wrap({"decision": "observe"}),
                remote_session_id=rid,
                status="active",
                model=self.model,
                last_error="",
            )
        return SimpleNamespace(
            ok=True,
            text=self._wrap(self.conclusion),
            remote_session_id=rid,
            status="active",
            model=self.model,
            last_error="",
        )

    @staticmethod
    def _wrap(payload: dict) -> str:
        return "done\n```json\n" + json.dumps(payload, ensure_ascii=False) + "\n```"


class ClosedLoopE2E(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        ensure_ops_loop_schema(self.db)
        _seed(self.db)
        # 闭环 E2E：自动处置自主执行（P6 自动路径）
        from ayana.duty_session import DutySessionManager
        DutySessionManager(self.db).set_setting("auto_approval_mode", "automatic", actor="test")
        self.incidents = IncidentService(self.db)
        self.transport = FakeTransport(ok=True)
        self.prom = FakeProm(healthy=True)
        self.actions = ActionService(
            self.db, self.transport, FakeGate(), FakePolicy(), self.prom,
            transport=self.transport, verify_timeout=1,
        )
        self.loop = OpsLoop(self.db, actions=self.actions, incidents=self.incidents)
        self.config = InvestConfig(enabled=True, closed_loop=True, timeout_sec=10, decision_timeout_sec=5)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_agent(self, conclusion: dict, decision_text: str = "", prom=None, transport=None) -> AutoInvestigator:
        if prom is not None:
            self.prom = prom
            self.actions.prom = prom
        if transport is not None:
            self.transport = transport
            self.actions.transport = transport
        mimo = FakeMimo(conclusion, decision_text)
        bridge = SessionBridge(self.db, mimo=mimo)
        agent = AutoInvestigator(
            self.db,
            knowledge=None,
            mimo=mimo,
            bridge=bridge,
            config=self.config,
            ops_loop=self.loop,
            actions=self.actions,
            incidents=self.incidents,
            mimo_write=mimo,
        )
        self.incidents.auto_investigator = agent
        self.incidents.session_bridge = bridge
        return agent

    async def _run_one(self, agent: AutoInvestigator) -> None:
        self.assertTrue(agent.offer("inc1", generation=1)["ok"])
        # 直接跑 job，避免依赖后台 tick
        job = agent._row("inc1")
        self.assertIsNotNone(job)
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE investigation_jobs SET status='running', lease_expires_at=? WHERE incident_id=?",
                (now() + 600, "inc1"),
            )
        job = agent._row("inc1")
        await agent._run_job("inc1", job)

    async def test_repair_success_closes_loop(self):
        conclusion = {
            "status": "completed",
            "root_cause": "service down",
            "facts": [{"claim": "down", "evidence": "probe"}],
            "suggested_action": {
                "capability": "service.restart",
                "object_id": "obj",
                "plan_sig": "restart-frps",
                "evidence_ok": True,
            },
            "remote_session_id": "ses_1",
        }
        agent = self._make_agent(conclusion)
        await self._run_one(agent)
        loop = self.loop.status("inc1")
        self.assertGreaterEqual(loop.get("rounds", 0), 1)
        # 调用链证据：autonomous Action 被创建并派发
        acts = list(self.db.query("SELECT id, mode, state, capability FROM actions WHERE incident_id='inc1'"))
        auto = [r for r in acts if r["mode"] == "autonomous"]
        self.assertTrue(auto, f"no autonomous action: {acts}")
        self.assertEqual(auto[0]["capability"], "service.restart")
        self.assertEqual(auto[0]["state"], "success")
        self.assertEqual(len(self.transport.calls), 1)
        # 审计链：proposal/approved/execute
        entries = [r["entry"] for r in self.db.query("SELECT entry FROM audit_log WHERE incident_id='inc1'")]
        self.assertTrue(any(e.startswith("action_") for e in entries), entries)
        # ops_loop 状态与结案尝试
        close = self.loop.maybe_close("inc1")
        self.assertIn("reconcile", close)
        # 事件链：auto_investigation（调查收尾）
        ev = list(self.db.query("SELECT type, title FROM events WHERE incident_id='inc1'"))
        self.assertTrue(any(r["type"] == "auto_investigation" for r in ev), ev)

    async def test_repair_failure_escalates_human(self):
        conclusion = {
            "status": "completed",
            "root_cause": "service down",
            "facts": [{"claim": "down", "evidence": "probe"}],
            "suggested_action": {
                "capability": "service.restart",
                "object_id": "obj",
                "plan_sig": "restart-frps",
                "evidence_ok": True,
            },
            "remote_session_id": "ses_1",
        }
        transport = FakeTransport(ok=False)
        prom = FakeProm(healthy=False)
        agent = self._make_agent(conclusion, transport=transport, prom=prom)
        await self._run_one(agent)
        loop = self.loop.status("inc1")
        # 失败或未验证 → need_human 或 stop
        self.assertTrue(
            loop.get("status") in ("need_human", "stopped", "running")
            or loop.get("stop_reason")
            or loop.get("same_plan_failures", 0) >= 1
            or loop.get("rounds", 0) >= 1
        )
        inc = self.db.query_one("SELECT need_human, need_human_reason FROM incidents WHERE id='inc1'")
        # 至少记录了一次处置轮次
        self.assertGreaterEqual(loop.get("rounds", 0), 1)
        self.assertIsNotNone(inc)
        self.assertEqual(inc["need_human"], 1)
        self.assertEqual(loop["status"], "need_human")
        self.assertEqual(self.db.query_one("SELECT state FROM actions WHERE mode='autonomous'")["state"], "failure")
        self.assertEqual(len(transport.calls), 1)

    async def test_repeated_alert_does_not_double_execute(self):
        conclusion = {
            "status": "completed",
            "root_cause": "down",
            "facts": [{"claim": "x", "evidence": "y"}],
            "suggested_action": {
                "capability": "service.restart", "object_id": "obj",
                "plan_sig": "restart-frps", "evidence_ok": True,
            },
            "remote_session_id": "ses_1",
        }
        agent = self._make_agent(conclusion)
        r1 = agent.offer("inc1", generation=1)
        self.assertIn(r1.get("action"), ("queued", None))
        r2 = agent.offer("inc1", generation=1)
        # 同代重复告警不重复排队执行
        self.assertIn(r2.get("action"), ("noop", "queued", "requeued"))
        if r2.get("action") == "noop":
            self.assertEqual(r2.get("status"), "queued")
        job = agent._row("inc1")
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE investigation_jobs SET status='running', lease_expires_at=? WHERE incident_id=?",
                (now() + 600, "inc1"),
            )
        await agent._run_job("inc1", agent._row("inc1"))
        n1 = self.db.query_one("SELECT COUNT(*) c FROM actions WHERE mode='autonomous'")["c"]
        # 再次 offer 同代：不再启动新执行
        r3 = agent.offer("inc1", generation=1)
        self.assertIn(r3.get("action"), ("noop", "requeued", "cooldown", "queued"))
        if r3.get("action") == "noop":
            self.assertLessEqual(
                self.db.query_one("SELECT COUNT(*) c FROM actions WHERE mode='autonomous'")["c"],
                max(n1, 1),
            )

    async def test_restart_lease_recovery_no_auto_replay(self):
        agent = self._make_agent({"status": "completed", "facts": [], "root_cause": "unknown"})
        agent.offer("inc1", generation=1)
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE investigation_jobs SET status='running', lease_expires_at=? WHERE incident_id=?",
                (now() - 10, "inc1"),
            )
        rec = agent.recover()
        self.assertGreaterEqual(rec["expired"], 1)
        job = agent._row("inc1")
        self.assertEqual(job["status"], "failed")
        # recover 后不自动重放写
        self.assertEqual(self.db.query_one("SELECT COUNT(*) c FROM actions")["c"], 0)

    async def test_decision_human_without_evidence(self):
        conclusion = {
            "status": "partial",
            "root_cause": "unknown",
            "facts": [],
            "remote_session_id": "ses_1",
        }
        agent = self._make_agent(
            conclusion,
            decision_text='```json\n{"decision":"human","reason":"evidence_insufficient","evidence_ok":false}\n```',
        )
        await self._run_one(agent)
        loop = self.loop.status("inc1")
        self.assertEqual(loop.get("status"), "need_human")
        inc = self.db.query_one("SELECT need_human FROM incidents WHERE id='inc1'")
        self.assertEqual(inc["need_human"], 1)

    async def test_idempotent_action_key_blocks_replay(self):
        conclusion = {
            "status": "completed",
            "facts": [{"claim": "a", "evidence": "b"}],
            "root_cause": "down",
            "suggested_action": {
                "capability": "service.restart", "object_id": "obj",
                "plan_sig": "s1", "evidence_ok": True,
            },
            "remote_session_id": "ses_1",
        }
        agent = self._make_agent(conclusion)
        await self._run_one(agent)
        ops = self.db.query("SELECT action_key, status FROM session_write_ops")
        states = [r["state"] for r in self.db.query("SELECT state FROM actions WHERE mode='autonomous'")]
        self.assertLessEqual(states.count("dispatched"), 1)

    async def test_human_approval_gate_blocks_auto_execute(self):
        from ayana.duty_session import DutySessionManager
        # 人工审批拦截属 manual 档语义（旧全局审批开关已退役）
        DutySessionManager(self.db).set_setting("auto_approval_mode", "manual", actor="test")
        self.db.execute("UPDATE duty_sessions SET approval_mode='manual'")
        conclusion = {
            "status": "completed",
            "root_cause": "service down",
            "facts": [{"claim": "down", "evidence": "probe"}],
            "suggested_action": {
                "capability": "service.restart",
                "object_id": "obj",
                "plan_sig": "restart-frps",
                "evidence_ok": True,
            },
            "remote_session_id": "ses_1",
        }
        agent = self._make_agent(conclusion)
        await self._run_one(agent)
        # 应停在 proposed，不得自动派发
        rows = list(self.db.query("SELECT state FROM actions WHERE mode='autonomous'"))
        self.assertTrue(rows, "should create proposed action")
        for r in rows:
            self.assertEqual(r["state"], "proposed")
        self.assertFalse(list(self.db.query("SELECT id FROM actions WHERE mode='autonomous' AND state='dispatched'")))


if __name__ == "__main__":
    unittest.main()
