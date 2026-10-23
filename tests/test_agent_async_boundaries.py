"""迟到的 Agent 调查不能污染已恢复事件或新故障代次。"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_phase_d_p1 import close_env, make_env
from ayana.actions import ActionError


class AgentAsyncBoundaryTests(unittest.TestCase):
    def environment(self):
        env = make_env(auto_rule=(True, False, True), auto_enabled=True)
        tmp, db, _, _, _, _, _, agent, incidents = env
        self.addCleanup(close_env, tmp, db)
        agent.investigation.run_loop = AsyncMock(return_value={"evidence": []})
        return env

    def advance(self, db, incidents, transition):
        if transition == "resolved":
            incidents._force_recovered("inc1")
        else:
            db.execute("UPDATE incidents SET generation=generation+1,stage='pending' WHERE id='inc1'")
            db.event("generation_bumped", incident_id="inc1", payload={"generation": 2})

    def test_context_is_rechecked_after_each_read_only_await_even_on_failure(self):
        for phase in ("investigation", "llm", "probe"):
            for transition in ("resolved", "next_generation"):
                for fails in (False, True):
                    with self.subTest(phase=phase, transition=transition, fails=fails):
                        tmp, db, _, nt, prom, _, _, agent, incidents = self.environment()
                        async def late_result(*args, **kwargs):
                            self.advance(db, incidents, transition)
                            if fails:
                                raise RuntimeError("late network failure")
                            if phase == "investigation":
                                return {"evidence": [], "stop_reason": "transport_unavailable"}
                            if phase == "llm":
                                return None
                            return []
                        if phase == "investigation":
                            agent.investigation.run_loop = AsyncMock(side_effect=late_result)
                        elif phase == "llm":
                            agent.llm.enabled = True
                            agent.llm.analyze_incident = AsyncMock(side_effect=late_result)
                        else:
                            prom.probe_success_since = AsyncMock(side_effect=late_result)
                        result = asyncio.run(agent.handle_incident("inc1"))
                        self.assertEqual(result["action"], "skipped_incident_changed")
                        inc = db.query_one("SELECT * FROM incidents WHERE id='inc1'")
                        self.assertEqual(inc["stage"], "done" if transition == "resolved" else "pending")
                        self.assertEqual(inc["generation"], 1 if transition == "resolved" else 2)
                        self.assertEqual(inc["need_human"], 0)
                        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)
                        self.assertEqual(db.query_one(
                            "SELECT COUNT(*) n FROM events WHERE type IN ('agent_waiting','agent_escalated','proposal_waiting')"
                        )["n"], 0)
                        self.assertFalse(nt.exec_calls)
                        self.assertFalse(agent.notifier.sent)
                        # 每个参数组合独立数据库，不在同一测试尾部积累资源。
                        close_env(tmp, db)

    def test_wait_and_escalate_reject_a_stale_snapshot(self):
        for transition in ("resolved", "next_generation"):
            with self.subTest(transition=transition):
                _, db, _, _, _, _, _, agent, incidents = self.environment()
                snapshot = dict(db.query_one("SELECT * FROM incidents WHERE id='inc1'"))
                self.advance(db, incidents, transition)
                result = agent._wait_for_preconditions(snapshot, None, {"steps": []}, {"blockers": ["budget"]})
                agent._escalate(snapshot, "no_runbook_match")
                self.assertEqual(result["action"], "skipped_incident_changed")
                inc = db.query_one("SELECT * FROM incidents WHERE id='inc1'")
                self.assertEqual(inc["stage"], "done" if transition == "resolved" else "pending")
                self.assertEqual(inc["need_human"], 0)
                self.assertFalse(agent.notifier.sent)

    def test_late_execution_error_does_not_add_an_obligation_to_the_next_generation(self):
        for error in (ActionError("object_locked"), RuntimeError("transport unavailable")):
            with self.subTest(error=type(error).__name__):
                _, db, _, _, _, _, actions, agent, incidents = self.environment()
                async def rejected_late(*args, **kwargs):
                    self.advance(db, incidents, "next_generation")
                    raise error
                actions.execute = AsyncMock(side_effect=rejected_late)
                result = asyncio.run(agent.handle_incident("inc1"))
                self.assertEqual(result["action"], "skipped_incident_changed")
                inc = db.query_one("SELECT * FROM incidents WHERE id='inc1'")
                self.assertEqual((inc["generation"], inc["stage"], inc["need_human"]), (2, "pending", 0))
                self.assertEqual(db.query_one(
                    "SELECT COUNT(*) n FROM events WHERE type IN ('agent_waiting','agent_escalated')"
                )["n"], 0)

    def test_late_execution_failure_keeps_history_without_escalating_a_new_generation(self):
        _, db, _, _, _, _, actions, agent, incidents = self.environment()
        async def failed_late(action_id, **kwargs):
            self.advance(db, incidents, "next_generation")
            return {"id": action_id, "state": "failure"}
        actions.execute = AsyncMock(side_effect=failed_late)
        result = asyncio.run(agent.handle_incident("inc1"))
        self.assertEqual(result["action"], "failure")
        inc = db.query_one("SELECT * FROM incidents WHERE id='inc1'")
        self.assertEqual((inc["generation"], inc["stage"], inc["need_human"]), (2, "pending", 0))
        self.assertFalse(agent.notifier.sent)


if __name__ == "__main__":
    unittest.main()
