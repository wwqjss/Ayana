"""Shared deferred obligations survive; retired scheduling never resumes.

Former automatic positives now require permanent refusal. Common budget,
manual authorization, object locks and exact notification obligations remain
real service assertions, not old AgentLoop implementations.
"""
from __future__ import annotations
import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_phase_d_p1 import close_env,make_env
from ayana.agent import AgentLoop
from ayana.actions import ActionError
from ayana.auto_investigate import AutoInvestigator,InvestConfig
from ayana.db import new_id,now
from ayana.legacy_history import RetiredAutonomyError
from ayana.runbook import auto_budget_state,get_runbook_rule


class AgentDeferredTests(unittest.TestCase):
    def env(self,**kwargs):
        env=make_env(auto_rule=(True,False,True),auto_enabled=True,**kwargs)
        self.addCleanup(close_env,env[0],env[1])
        return env

    def usage(self,db,at,object_id="frps"):
        action_id=new_id("act")
        db.execute("INSERT INTO actions(id,asset_id,object_id,capability,state,mode,created_at,dispatched_at) VALUES(?,'nerv',?,'service.restart','success','auto',?,?)",(action_id,object_id,at,at))
        return action_id

    def source(self,db,health="ok"):
        db.execute("INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,alertname,status,asset_id,object_id,incident_id,first_seen,last_seen,source_health) VALUES('source','am','fp','start','TargetDown','firing','nerv','frps','inc1',?,?,?)",(now(),now(),health))

    def proposal(self,env):
        return env[6].propose(asset_id="nerv",object_id="frps",capability="service.restart",reason="human request",incident_id="inc1",proposer_type="web_user",proposer_id="admin",mode="manual",template_id="tmpl_service_restart")

    def notify(self,env,prop):
        env[7]._notify_awaiting_approval("inc1",prop["id"],get_runbook_rule("rb_frps_down_restart"),{"decision":"approval_required"},{"status":"satisfied"})

    def retired(self,env):
        db,nt=env[1],env[3]
        before="\n".join(db._connect().iterdump())
        with self.assertRaises(RetiredAutonomyError):
            AgentLoop(db,None,env[6],env[2],None,None,auto_enabled=True)
        old=AgentLoop.__new__(AgentLoop)
        old.legacy_locked=False
        old.auto_enabled=True
        with self.assertRaises(RetiredAutonomyError):
            asyncio.run(old.handle_incident("inc1"))
        with self.assertRaises(RetiredAutonomyError):
            asyncio.run(old._auto_dispatch({},None,{}))
        self.assertFalse(nt.exec_calls)
        self.assertEqual("\n".join(db._connect().iterdump()),before)

    def test_cooldown_waits_without_approval_and_dispatches_when_due(self):
        env=self.env();db=env[1];t=now();self.usage(db,t-600)
        budget=auto_budget_state(db,get_runbook_rule("rb_frps_down_restart"),"nerv","frps",at=t)
        self.assertFalse(budget["ok"]);self.assertAlmostEqual(budget["retry_at"],t+1200,places=2)
        self.retired(env)
        # Even a due cooldown confers no authority after retirement.
        db.execute("UPDATE actions SET dispatched_at=?",(t-90000,));self.retired(env)

    def test_daily_budget_retry_is_expiry_of_oldest_retained_usage(self):
        env=self.env();db=env[1];t=now()
        for offset in (1200,1000,800,600):self.usage(db,t-offset)
        b=auto_budget_state(db,get_runbook_rule("rb_frps_down_restart"),"nerv","frps",at=t)
        self.assertFalse(b["ok"]);self.assertIn("24小时执行上限",b["reason"])
        self.assertAlmostEqual(b["retry_at"],t-1000+86400,places=2)
        self.retired(env)

    def test_budget_matches_both_object_name_and_reference(self):
        env=self.env();db=env[1];self.usage(db,now()-60,"nerv:service:frps")
        for oid in ("frps","nerv:service:frps"):
            self.assertFalse(auto_budget_state(db,get_runbook_rule("rb_frps_down_restart"),"nerv",oid,at=now())["ok"])
        self.retired(env)

    def test_missing_probe_waits_and_remains_eligible(self):
        env=self.env(probe_value=None);self.retired(env)
        self.assertEqual(env[1].query_one("SELECT COUNT(*) n FROM actions")["n"],0)

    def test_pause_waits_without_approval(self):
        env=self.env();env[1].execute("UPDATE global_stops SET enabled=1 WHERE key='auto_dispatch'")
        self.retired(env)
        self.assertEqual(env[1].query_one("SELECT COUNT(*) n FROM actions")["n"],0)

    def test_authorization_request_contains_reply_protocol(self):
        env=self.env();prop=self.proposal(env);self.notify(env,prop)
        body=env[7].notifier.sent[-1]["body"]
        for phrase in ("需要你授权","执行一次","不执行","永久允许执行"):self.assertIn(phrase,body)
        self.assertNotIn(prop["id"],body);self.assertFalse(env[3].exec_calls)

    def test_waiting_incidents_do_not_starve_ready_incidents(self):
        env=self.env();db=env[1]
        env[7]._wait_for_preconditions(dict(db.query_one("SELECT * FROM incidents WHERE id='inc1'")),None,{}, {"blockers":["budget"],"retry_at":now()+3600})
        ai=AutoInvestigator(db,config=InvestConfig(enabled=True))
        for i in range(2,6):
            db.execute("INSERT INTO incidents(id,title,asset_id,object_id,status,stage,created_at,updated_at) VALUES(?,'other','nerv',?,'open','pending',?,?)",(f"inc{i}",f"svc{i}",now()+i,now()+i))
            ai.offer(f"inc{i}")
        self.assertEqual([j["incident_id"] for j in ai.ready_jobs(3)],["inc2","inc3","inc4"])
        self.retired(env)

    def test_wait_is_persisted_but_does_not_cross_generation(self):
        env=self.env();db=env[1];h=env[7];inc=dict(db.query_one("SELECT * FROM incidents WHERE id='inc1'"))
        h._wait_for_preconditions(inc,None,{}, {"blockers":["budget"]})
        self.assertIsNotNone(h._waiting_state(inc))
        db.execute("UPDATE incidents SET generation=2,stage='pending'")
        self.assertIsNone(h._waiting_state(dict(db.query_one("SELECT * FROM incidents WHERE id='inc1'"))))
        self.retired(env)

    def test_human_rejection_blocks_only_current_generation(self):
        env=self.env();db=env[1];prop=self.proposal(env)
        env[6].reject(prop["id"],actor_type="web_user",actor_id="admin",reason="skip")
        self.assertIsNotNone(env[7]._current_rejection("inc1"))
        db.execute("UPDATE incidents SET generation=2,need_human=0,stage='pending'")
        db.event("generation_bumped",incident_id="inc1",payload={"generation":2})
        self.assertIsNone(env[7]._current_rejection("inc1"))
        self.retired(env)

    def test_control_plane_cannot_enter_auto_dispatch(self):
        env=self.env();env[1].execute("UPDATE incidents SET object_id='ayana',title='control plane'")
        self.retired(env)

    def test_latest_recovered_probe_overrides_earlier_failure(self):
        env=self.env();env[4].samples.append({"metric":{"asset":"nerv","service":"frps"},"value":1,"sample_at":now()})
        self.retired(env)

    def test_service_state_requirement_uses_matching_observed_evidence(self):
        env=self.env();rule=get_runbook_rule("rb_frps_down_restart")
        for state in ("active","failed","unknown"):
            env[1].execute("INSERT OR REPLACE INTO meta(key,value) VALUES('test_observed_state',?)",(state,))
            self.retired(env)
        self.assertIsNotNone(rule)

    def test_unknown_write_requires_human_adjudication(self):
        env=self.env();db=env[1];aid=self.usage(db,now()-60)
        db.execute("UPDATE actions SET state='unknown' WHERE id=?",(aid,))
        with self.assertRaises(ActionError) as denied:
            asyncio.run(env[6].execute(aid,actor_type="web_user",actor_id="admin",is_admin=True))
        self.assertEqual(denied.exception.code,"no_replay_unknown")
        self.assertEqual(env[6].get_action(aid)["state"],"unknown")
        self.retired(env)

    def test_other_incident_verification_holds_object_until_finished(self):
        env=self.env();db=env[1];aid=self.usage(db,now()-3600,"nerv:service:frps")
        db.execute("INSERT INTO verifications(id,action_id,status,started_at) VALUES('ver_old',?,'pending',?)",(aid,now()))
        self.assertTrue(env[6]._object_locked("nerv","nerv:service:frps"))
        with self.assertRaises(ActionError) as denied:self.proposal(env)
        self.assertEqual(denied.exception.code,"object_locked")
        self.retired(env)

    def test_pause_racing_dispatch_returns_to_waiting(self):
        env=self.env();env[5].verify_account=AsyncMock(side_effect=AssertionError("no identity or dispatch should start"))
        self.retired(env);env[5].verify_account.assert_not_awaited()

    def test_disabled_auto_keeps_explicit_manual_confirmation(self):
        env=self.env();self.retired(env);prop=self.proposal(env)
        self.assertEqual(env[6].get_action(prop["id"])["mode"],"manual")
        self.assertEqual(env[6].get_action(prop["id"])["state"],"proposed")
        self.assertFalse(env[3].exec_calls)

    def test_proposal_has_one_persistent_notification_obligation(self):
        env=self.env();prop=self.proposal(env);self.notify(env,prop);self.notify(env,prop)
        events=env[1].query("SELECT payload_json FROM events WHERE type='proposal_waiting'")
        self.assertEqual(len(events),1);payload=json.loads(events[0]["payload_json"])
        self.assertEqual(payload["generation"],1);self.assertEqual(payload["action_id"],prop["id"])
        self.assertIn("执行一次",payload["body"])

    def test_notification_exception_does_not_turn_success_into_escalation(self):
        env=self.env();db=env[1];prop=self.proposal(env)
        db.execute("UPDATE actions SET state='success' WHERE id=?",(prop["id"],))
        class FailingNotify:
            def enqueue_for_event(self,*args,**kwargs):raise RuntimeError("temporary channel failure")
        env[7].notifier=FailingNotify()
        eid=db.event("action_success",incident_id="inc1",payload={"action_id":prop["id"]})
        with self.assertLogs("ayana.notification_obligations",level="ERROR"):
            env[7]._notify_event(eid,"action_success","operation finished")
        self.assertEqual(env[6].get_action(prop["id"])["state"],"success")
        self.assertEqual(db.query_one("SELECT need_human FROM incidents")["need_human"],0)

    def test_unavailable_source_waits_then_recovers_without_human_reset(self):
        env=self.env();self.source(env[1],"unavailable");self.retired(env)
        env[1].execute("UPDATE alert_episodes SET source_health='ok'");self.retired(env)

    def test_source_becomes_unavailable_at_dispatch_cancels_and_waits(self):
        env=self.env();self.source(env[1]);env[1].execute("UPDATE alert_episodes SET source_health='unavailable'")
        env[5].verify_account=AsyncMock();self.retired(env);env[5].verify_account.assert_not_awaited()

    def test_retryable_error_retires_unclaimed_approved_action_and_its_obligation(self):
        env=self.env();prop=self.proposal(env);env[6].approve(prop["id"],approver_id="admin")
        self.retired(env)
        self.assertEqual(env[6].get_action(prop["id"])["state"],"approved")
        self.assertEqual(env[1].query_one("SELECT COUNT(*) n FROM actions")["n"],1)

    def test_equal_timestamp_previous_generation_rejection_does_not_block(self):
        env=self.env();db=env[1];prop=self.proposal(env)
        env[6].reject(prop["id"],actor_type="web_user",actor_id="admin",reason="skip")
        stamp=db.query_one("SELECT created_at FROM actions WHERE id=?",(prop["id"],))["created_at"]
        db.execute("UPDATE incidents SET generation=2,need_human=0,stage='pending'")
        eid=db.event("generation_bumped",incident_id="inc1",payload={"generation":2});db.execute("UPDATE events SET at=? WHERE id=?",(stamp,eid))
        self.assertIsNone(env[7]._current_rejection("inc1"));self.retired(env)


if __name__=="__main__":unittest.main()
