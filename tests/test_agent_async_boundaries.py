"""Late manual evidence/notifications cannot mutate a recovered/new incident.

The scheduler previously tested here is retired. The shared obligation checks
remain live, while actual automatic investigation generation guards are covered
by test_p4_3_auto_investigate and test_p4_4_retirement.
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_phase_d_p1 import close_env,make_env
from ayana.actions import ActionError
from ayana.ntsafe import NTResult


class AgentAsyncBoundaryTests(unittest.TestCase):
    def environment(self):
        env=make_env(auto_rule=(True,False,True),auto_enabled=True)
        self.addCleanup(close_env,env[0],env[1])
        return env

    def advance(self,db,incidents,transition):
        if transition=="resolved":incidents._force_recovered("inc1")
        else:
            db.execute("UPDATE incidents SET generation=generation+1,stage='pending' WHERE id='inc1'")
            db.event("generation_bumped",incident_id="inc1",payload={"generation":2})

    def test_context_is_rechecked_after_each_read_only_await_even_on_failure(self):
        for phase in ("investigation","llm","probe"):
            for transition in ("resolved","next_generation"):
                for fails in (False,True):
                    with self.subTest(phase=phase,transition=transition,fails=fails):
                        tmp,db,_,nt,_,_,_,obligations,incidents=self.environment()
                        snapshot=dict(db.query_one("SELECT * FROM incidents WHERE id='inc1'"))
                        async def late_result():
                            self.advance(db,incidents,transition)
                            if fails:raise RuntimeError("late read failure")
                            return {"evidence":[]}
                        async def manual_reader():
                            try:await late_result()
                            except RuntimeError:pass
                            obligations._escalate(snapshot,"manual_read_unavailable")
                        asyncio.run(manual_reader())
                        inc=db.query_one("SELECT * FROM incidents WHERE id='inc1'")
                        self.assertEqual(inc["stage"],"done" if transition=="resolved" else "pending")
                        self.assertEqual(inc["generation"],1 if transition=="resolved" else 2)
                        self.assertEqual(inc["need_human"],0)
                        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM actions")["n"],0)
                        self.assertEqual(db.query_one("SELECT COUNT(*) n FROM events WHERE type IN ('agent_waiting','agent_escalated','proposal_waiting')")["n"],0)
                        self.assertFalse(nt.exec_calls);self.assertFalse(obligations.notifier.sent)
                        close_env(tmp,db)

    def test_wait_and_escalate_reject_a_stale_snapshot(self):
        for transition in ("resolved","next_generation"):
            with self.subTest(transition=transition):
                _,db,_,_,_,_,_,obligations,incidents=self.environment()
                snapshot=dict(db.query_one("SELECT * FROM incidents WHERE id='inc1'"))
                self.advance(db,incidents,transition)
                result=obligations._wait_for_preconditions(snapshot,None,{"steps":[]},{"blockers":["budget"]})
                obligations._escalate(snapshot,"no_runbook_match")
                self.assertEqual(result["action"],"skipped_incident_changed")
                inc=db.query_one("SELECT * FROM incidents WHERE id='inc1'")
                self.assertEqual(inc["stage"],"done" if transition=="resolved" else "pending")
                self.assertEqual(inc["need_human"],0);self.assertFalse(obligations.notifier.sent)

    def test_late_execution_error_does_not_add_an_obligation_to_the_next_generation(self):
        for error in (ActionError("object_locked"),RuntimeError("transport unavailable")):
            with self.subTest(error=type(error).__name__):
                _,db,_,_,_,_,actions,obligations,incidents=self.environment()
                snapshot=dict(db.query_one("SELECT * FROM incidents WHERE id='inc1'"))
                async def rejected_late(*args,**kwargs):
                    self.advance(db,incidents,"next_generation");raise error
                actions.execute=AsyncMock(side_effect=rejected_late)
                async def human_controller():
                    try:await actions.execute("explicit-human-action")
                    except (ActionError,RuntimeError):obligations._escalate(snapshot,"exec_error")
                asyncio.run(human_controller())
                self.assertEqual(tuple(db.query_one("SELECT generation,stage,need_human FROM incidents WHERE id='inc1'")),(2,"pending",0))
                self.assertEqual(db.query_one("SELECT COUNT(*) n FROM events WHERE type IN ('agent_waiting','agent_escalated')")["n"],0)

    def test_late_execution_failure_keeps_history_without_escalating_a_new_generation(self):
        _,db,_,nt,_,_,actions,obligations,incidents=self.environment()
        prop=actions.propose(asset_id="nerv",object_id="frps",capability="service.restart",reason="human request",incident_id="inc1",proposer_type="web_user",proposer_id="admin",mode="manual",template_id="tmpl_service_restart")
        actions.approve(prop["id"],approver_id="admin")
        async def failed_late(alias,tokens,timeout=None):
            nt.exec_calls.append((alias,tokens));self.advance(db,incidents,"next_generation")
            return NTResult(ok=False,output="operation failed",returncode=1)
        nt.exec=failed_late
        result=asyncio.run(actions.execute(prop["id"],actor_type="web_user",actor_id="admin"))
        self.assertEqual(result["state"],"failure")
        self.assertEqual(actions.get_action(prop["id"])["state"],"failure")
        # 执行已产生确定 failure → reconcile 进入 watching（非再次 pending/escalate）
        self.assertEqual(tuple(db.query_one("SELECT generation,stage,need_human FROM incidents WHERE id='inc1'")),(2,"watching",0))
        self.assertEqual(len(nt.exec_calls),1);self.assertFalse(obligations.notifier.sent)


if __name__=="__main__":unittest.main()
