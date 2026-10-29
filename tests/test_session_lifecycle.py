"""Lifecycle, native admission, work ownership and copy API: isolated DBs only."""
import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.agent_tui import AgentTuiManager
from ayana.native_turns import NativeTurns, NativeAdmissionError
from ayana.agent_work_scope import claim_incident, claim_target, find_work_conflict, WorkScopeError
from ayana.agent_authority import resolve_authority
from ayana.transport import session_ssh_scope, SSHAssetStore, SSHTransport, TransportError
from ayana.mimo_serve import MimoServeError


class Fixture:
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db=Database(Path(self.tmp.name)/"test.db");self.duty=DutySessionManager(self.db)
        self.auto=self.duty.create(origin="auto")["session_id"]
        self.manual=self.duty.create(origin="manual")["session_id"]
        self.duty.set_runtime_state(self.auto,"idle");self.duty.set_runtime_state(self.manual,"idle")
        for iid in ("inc1","inc2"):
            self.db.execute("INSERT INTO incidents(id,title,asset_id,object_id,status,created_at,updated_at) VALUES(?,?,?,?,'open',?,?)",(iid,iid,"host","service",time.time(),time.time()))
        self.duty.join_incident(self.auto,"inc1")

    def tearDown(self):self.db.close();self.tmp.cleanup()


class LifecycleTests(Fixture,unittest.TestCase):
    def test_delete_hides_chat_but_preserves_messages_and_incident(self):
        self.duty.add_message(self.manual,role="user",body="history")
        claim_incident(self.db,self.manual,"inc2")
        result=self.duty.request_delete(self.manual,actor="admin")
        self.assertTrue(result["deleted"])
        self.assertNotIn(self.manual,{s["id"] for s in self.duty.list_sessions()})
        self.assertTrue(self.duty.get(self.manual)["deleted_at"])
        self.assertEqual(self.db.query_one("SELECT status FROM incidents WHERE id='inc2'")[0],"open")
        self.assertTrue(self.duty.messages(self.manual))
        self.assertFalse(self.duty.reopen_session(self.manual)["ok"])

    def test_stop_delete_waits_for_real_completion(self):
        self.duty.record_receipt(self.manual,"ses_manual","receipt1")
        self.duty.set_runtime_state(self.manual,"running",receipt_id="receipt1",receipt_status="accepted")
        self.assertFalse(self.duty.request_delete(self.manual,actor="admin")["ok"])
        result=self.duty.request_delete(self.manual,actor="admin",stop=True)
        self.assertTrue(result["pending"])
        self.assertFalse(self.duty.get(self.manual)["deleted_at"])
        self.db.execute("UPDATE agent_runtime_receipts SET status='cancelled' WHERE receipt_id='receipt1'")
        self.duty.set_runtime_state(self.manual,"idle",receipt_id="receipt1",receipt_status="cancelled")
        self.assertEqual(self.duty.tick_deletions(),[self.manual])

    def test_unknown_write_blocks_deletion_without_releasing_ledger(self):
        from ayana.session_bridge import SessionBridge
        bridge=SessionBridge(self.db,duty=self.duty)
        self.duty.set_setting("auto_approval_mode","automatic")
        bridge.claim_write("inc1","key",authority_session_id=self.auto)
        bridge.mark_unknown("inc1","key")
        result=self.duty.request_delete(self.auto,actor="admin",stop=True)
        self.assertTrue(result["pending"])
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops WHERE action_key='key'")[0],"unknown")

    def test_manual_participation_does_not_steal_primary_or_cancel_auto_job(self):
        claim_incident(self.db,self.manual,"inc1")
        self.db.execute("UPDATE duty_sessions SET updated_at=? WHERE id=?",(time.time()+50,self.manual))
        self.assertEqual(self.duty.session_for_incident("inc1")["id"],self.auto)
        self.db.execute("INSERT INTO investigation_jobs(incident_id,status,updated_at,created_at) VALUES('inc1','running',?,?)",(time.time(),time.time()))
        self.assertTrue(self.duty.request_delete(self.manual,actor="admin")["deleted"])
        self.assertEqual(self.db.query_one("SELECT status FROM investigation_jobs WHERE incident_id='inc1'")[0],"running")

    def test_pause_independent_permissions_and_user_stop_not_reoffered(self):
        self.db.execute("INSERT INTO investigation_jobs(incident_id,status,updated_at,created_at) VALUES('inc1','running',?,?)",(time.time(),time.time()))
        self.duty.pause_session(self.auto,actor="admin")
        self.assertEqual(resolve_authority(self.db,self.auto)["access_mode"],"readwrite")
        self.assertEqual(resolve_authority(self.db,self.auto)["lifecycle_block"],"session_paused")
        self.assertEqual(resolve_authority(self.db,self.manual)["lifecycle_block"],"")
        self.duty.interrupt_business_work(self.auto,actor="admin")
        from ayana.auto_investigate import AutoInvestigator,InvestConfig
        agent=AutoInvestigator(self.db,config=InvestConfig(enabled=True))
        self.assertEqual(agent.offer("inc1").get("skipped"),"operator_stopped")
        self.duty.resume_session(self.auto,actor="admin")
        self.assertFalse(self.duty.get(self.auto)["paused_at"])
        self.assertEqual(self.db.query_one("SELECT status FROM investigation_jobs WHERE incident_id='inc1'")[0],"cancelled")

    def test_recovery_submission_and_human_control_block_archive(self):
        self.db.execute("UPDATE incidents SET status='closed' WHERE id='inc1'")
        self.db.execute("INSERT INTO agent_native_submissions(session_id,submission_id,kind,state,created_at,updated_at) VALUES(?,?,'recovery','recovering',?,?)",(self.auto,"sub1",time.time(),time.time()))
        self.assertIn("submission_pending",self.duty.archive_blockers(self.auto))
        self.assertIn("native_submission_pending",self.duty.native_admission_blockers(self.auto))
        self.assertFalse(self.duty.archive_session(self.auto)["ok"])

    def test_active_other_owner_stops_claim_and_raw_target(self):
        self.duty.record_receipt(self.auto,"ses_auto","receipt_active")
        with self.assertRaises(WorkScopeError) as caught:claim_incident(self.db,self.manual,"inc1")
        self.assertEqual(caught.exception.detail["owner_session_id"],self.auto)
        self.assertTrue(caught.exception.detail["stop_processing"])
        with self.assertRaises(WorkScopeError):claim_target(self.db,self.manual,asset_id="host")
        self.assertIsNone(find_work_conflict(self.db,self.manual,asset_id="different"))

    def test_unknown_owner_cannot_be_reclaimed_even_if_archived(self):
        claim_target(self.db,self.auto,asset_id="host")
        self.db.execute("UPDATE agent_runtime_bindings SET state='unknown' WHERE session_id=?",(self.auto,))
        self.db.execute("UPDATE duty_sessions SET status='archived' WHERE id=?",(self.auto,))
        with self.assertRaises(WorkScopeError):claim_target(self.db,self.manual,asset_id="host")


class FakeNative:
    base_url="http://127.0.0.1:9"
    def __init__(self):
        self.busy=False;self.calls=[];self.fail=False;self.ids=0
        self.history=[{"info":{"id":"msg_user","role":"user","time":{"created":1}},"parts":[]}, {"info":{"id":"msg_old","role":"assistant","parentID":"msg_user","time":{"created":2}},"parts":[]}]
    def _admit(self):pass
    async def session_status(self,rid):return {"type":"busy" if self.busy else "idle"}
    async def require_session_idle(self,rid):
        if self.busy:raise MimoServeError("session_busy")
    async def messages(self,rid,**kw):return self.history
    async def _request(self,method,path,**kwargs):
        self.calls.append((method,path,kwargs))
        if self.fail:raise MimoServeError("timeout")
        if method=="GET":return {"candidates":[{"kind":"assistant","assistantMessageID":"msg_old","parentMessageID":"msg_user","created":2}]}
        self.ids+=1
        return {"status":202,"data":None if path.endswith('/resume') else {"receiptId":"receipt_"+str(self.ids)}}


class NativeLifecycleTests(Fixture,unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp();self.native=FakeNative();self.rid="ses_manual"
        self.db.execute("UPDATE duty_sessions SET remote_session_id=? WHERE id=?",(self.rid,self.manual))
        self.manager=AgentTuiManager(self.db,lambda:self.native,runtime_resolver=lambda:{"model":"test/model"},state_dir=self.tmp.name)
        self.manager._connections['conn']={"username":"admin","session_id":self.manual}
        self.manager.acquire_control(self.manual,"admin","conn")
        self.turns=NativeTurns(self.db)
    async def test_deleted_viewport_reaped_even_when_pane_identity_drifted(self):
        from unittest.mock import AsyncMock,Mock
        self.duty.request_delete(self.manual,actor="admin")
        self.db.execute("UPDATE agent_runtime_bindings SET tmux_name='ayana-own',pane_id='%2',pane_pid=123,pane_started_at='start' WHERE session_id=?",(self.manual,))
        self.manager._pane=AsyncMock(return_value={"pane_id":"%2","pane_pid":999,"pane_started_at":"different"})
        self.manager._tmux=Mock(return_value=SimpleNamespace(returncode=0))
        await self.manager.reap_deleted_viewports()
        self.manager._tmux.assert_any_call("kill-session","-t","ayana-own")
        self.assertIsNone(self.db.query_one("SELECT tmux_name FROM agent_runtime_bindings WHERE session_id=?",(self.manual,))[0])
    async def test_reap_clears_every_deleted_viewport_without_empty_name_conflict(self):
        from unittest.mock import AsyncMock,Mock
        self.manager._pane=AsyncMock(return_value=None)
        self.manager._tmux=Mock(return_value=SimpleNamespace(returncode=0))
        for i in range(3):
            row=self.duty.create(origin="manual")["session_id"]
            self.duty.set_runtime_state(row,"idle")
            self.assertTrue(self.duty.request_delete(row,actor="admin")["deleted"])
            self.db.execute("UPDATE agent_runtime_bindings SET tmux_name=? WHERE session_id=?",(f"ayana-own{i}",row))
        await self.manager.reap_deleted_viewports()
        left=self.db.query("SELECT session_id FROM agent_runtime_bindings WHERE tmux_name IS NOT NULL AND tmux_name<>''")
        self.assertEqual([r[0] for r in left],[])
    async def test_ensure_refuses_deleted_session(self):
        self.duty.request_delete(self.manual,actor="admin")
        with self.assertRaises(Exception) as caught:
            await self.manager.ensure(self.manual,self.rid)
        self.assertEqual(getattr(caught.exception,"code",""),"session_deleted")
    async def test_idle_viewport_release_keeps_remote_session_and_last_capture(self):
        from unittest.mock import AsyncMock,Mock
        self.manager.release_control(self.manual,"admin","conn")
        self.manager._connections.clear();self.manager._activity.clear()
        self.db.execute("UPDATE duty_sessions SET last_activity_at=? WHERE id=?",(time.time()-600,self.manual))
        self.db.execute("UPDATE agent_runtime_bindings SET remote_session_id=?,tmux_name='ayana-idle',pane_id='%3',pane_pid=123,pane_started_at='start',updated_at=? WHERE session_id=?",(self.rid,time.time()-600,self.manual))
        self.manager._pane=AsyncMock(return_value={"pane_id":"%3","pane_pid":123,"pane_started_at":"start"})
        self.manager._tmux=Mock(return_value=SimpleNamespace(returncode=0,stdout="last frame"))
        released=await self.manager.release_idle_viewports(idle_seconds=120)
        self.assertIn(self.manual,released)
        row=self.db.query_one("SELECT tmux_name,remote_session_id,last_capture,released_at FROM agent_runtime_bindings WHERE session_id=?",(self.manual,))
        self.assertIsNone(row[0]);self.assertEqual(row[1],self.rid)
        self.assertEqual(row[2],"last frame");self.assertGreater(row[3],0)
    async def test_idle_release_holds_on_control_client_or_running_task(self):
        from unittest.mock import AsyncMock,Mock
        self.manager._pane=AsyncMock(return_value=None)
        self.manager._tmux=Mock(return_value=SimpleNamespace(returncode=0))
        self.db.execute("UPDATE duty_sessions SET last_activity_at=? WHERE id=?",(time.time()-600,self.manual))
        self.db.execute("UPDATE agent_runtime_bindings SET tmux_name='ayana-hold',updated_at=? WHERE session_id=?",(time.time()-600,self.manual))
        self.manager._activity.clear()
        self.assertEqual(await self.manager.release_idle_viewports(idle_seconds=120),[])
        self.manager.release_control(self.manual,"admin","conn")
        self.assertEqual(await self.manager.release_idle_viewports(idle_seconds=120),[])
        self.manager._connections.clear()
        self.duty.set_runtime_state(self.manual,"running",receipt_id="r1",receipt_status="running")
        self.assertEqual(await self.manager.release_idle_viewports(idle_seconds=120),[])
        self.assertEqual(self.db.query_one("SELECT tmux_name FROM agent_runtime_bindings WHERE session_id=?",(self.manual,))[0],"ayana-hold")
    async def test_guidance_admitted_while_business_turn_held(self):
        self.native.busy=True
        with self.duty.turn(self.manual,require_idle=False):
            status,_=await self.manager._submit_prompt(self.manual,self.rid,"/session/"+self.rid+"/prompt_async",{"messageID":"msg_new","parts":[{"type":"text","text":"guidance"}]})
        self.assertEqual(status,202)
        self.assertEqual(self.db.query_one("SELECT status FROM agent_runtime_receipts WHERE session_id=?",(self.manual,))[0],"queued")
        self.assertEqual(self.duty.get(self.manual)["human_message_revision"],1)
    async def test_repeated_message_id_does_not_repost(self):
        body={"messageID":"msg_new","parts":[{"type":"text","text":"guidance"}]}
        await self.turns.prompt(self.manager,self.manual,self.rid,"/prompt_async",body)
        await self.turns.prompt(self.manager,self.manual,self.rid,"/prompt_async",body)
        self.assertEqual(sum(c[0]=='POST' for c in self.native.calls),1)
    async def test_unknown_admission_never_replays(self):
        self.native.fail=True
        with self.assertRaises(MimoServeError):await self.turns.prompt(self.manager,self.manual,self.rid,"/prompt_async",{"messageID":"msg_new"})
        self.native.fail=False
        with self.assertRaises(NativeAdmissionError):await self.turns.prompt(self.manager,self.manual,self.rid,"/prompt_async",{"messageID":"msg_new"})
        self.assertEqual(sum(c[0]=='POST' for c in self.native.calls),1)
    async def test_native_resume_empty202_no_fabricated_receipt(self):
        self.duty.pause_session(self.manual,actor="admin")
        response=await self.manager.recover_session(self.manual,{})
        self.assertTrue(response["accepted"])
        sent=next(c for c in self.native.calls if c[0]=='POST')
        self.assertEqual(sent[2]["body"],{"assistantMessageID":"msg_old"})
        self.assertFalse(self.duty.get(self.manual)["paused_at"])
        self.assertEqual(self.db.query_one("SELECT count(*) FROM agent_runtime_receipts")[0],0)
        self.native.history.append({"info":{"id":"msg_new_assistant","role":"assistant","parentID":"msg_user","time":{"created":3,"completed":4},"finish":"stop"},"parts":[]})
        await self.turns.reconcile(self.manager)
        self.assertEqual(self.db.query_one("SELECT state FROM agent_native_submissions WHERE kind='recovery'")[0],"completed")
        self.assertEqual(len([m for m in self.native.history if m['info']['role']=='user']),1)
    async def test_recovery_rejects_foreign_candidate_and_engine_change_stays_unknown(self):
        with self.assertRaises(Exception):await self.manager.recover_session(self.manual,{"assistantMessageID":"foreign"})
        self.assertFalse(any(c[0]=='POST' for c in self.native.calls))
        await self.manager.recover_session(self.manual,{})
        self.manager.engine_signature=lambda:{"different_engine":True}
        await self.turns.reconcile(self.manager)
        self.assertEqual(self.db.query_one("SELECT state FROM agent_native_submissions")[0],"unknown")
    async def test_recovery_record_survives_queued_guidance(self):
        await self.manager.recover_session(self.manual,{})
        self.native.busy=True
        await self.turns.prompt(self.manager,self.manual,self.rid,"/prompt_async",{"messageID":"msg_guide"})
        self.assertEqual(self.db.query_one("SELECT count(*) FROM agent_native_submissions")[0],2)
        self.assertEqual(self.db.query_one("SELECT state FROM agent_native_submissions WHERE kind='recovery'")[0],"recovering")
    async def test_recovery_of_parent_user_uses_one_target_and_same_parent(self):
        original_request=self.native._request
        async def request(method,path,**kwargs):
            if method=='GET':return {"candidates":[{"kind":"parent-user","userMessageID":"msg_user","created":1}]}
            return await original_request(method,path,**kwargs)
        self.native._request=request
        await self.manager.recover_session(self.manual,{"userMessageID":"msg_user"})
        self.assertEqual(self.native.calls[-1][2]["body"],{"userMessageID":"msg_user"})
        self.native.history.append({"info":{"id":"msg_recovered","role":"assistant","parentID":"msg_user","time":{"created":3,"completed":4},"finish":"stop"}})
        await self.turns.reconcile(self.manager)
        self.assertEqual(self.db.query_one("SELECT state FROM agent_native_submissions")[0],"completed")
    async def test_completed_tool_step_is_not_completed_recovery(self):
        await self.manager.recover_session(self.manual,{})
        self.native.history.append({"info":{"id":"msg_tool_step","role":"assistant","parentID":"msg_user","time":{"created":3,"completed":4},"finish":"tool-calls"}})
        await self.turns.reconcile(self.manager)
        self.assertEqual(self.db.query_one("SELECT state FROM agent_native_submissions")[0],"recovering")
        self.assertFalse(any(e["title"]=="原生恢复已完成。" for e in self.duty.events(self.manual)))
    async def test_control_transfer_during_recovery_preflight_prevents_dispatch(self):
        original_messages=self.native.messages
        async def messages(*args,**kwargs):
            result=await original_messages(*args,**kwargs)
            self.db.execute("UPDATE agent_runtime_bindings SET controller_connection_id='different-window' WHERE session_id=?",(self.manual,))
            return result
        self.native.messages=messages
        with self.assertRaises(Exception) as caught:await self.manager.recover_session(self.manual,{})
        self.assertEqual(caught.exception.code,"control_changed")
        self.assertFalse(any(c[0]=='POST' for c in self.native.calls))
    async def test_old_cancelled_receipt_cannot_complete_active_recovery(self):
        from ayana.main import App
        self.duty.record_receipt(self.manual,self.rid,"receipt_old",status="cancelled")
        self.duty.set_runtime_state(self.manual,"idle",receipt_id="receipt_old",receipt_status="cancelled")
        await self.manager.recover_session(self.manual,{})
        owner=App.__new__(App);owner.db=self.db;owner.duty=self.duty
        owner.agent_tui=self.manager
        owner.mimo_serve=SimpleNamespace(client=lambda:SimpleNamespace(session_status=lambda:asyncio.sleep(0,result={})))
        await owner._reconcile_native_receipts_once()
        self.assertEqual(self.db.query_one("SELECT receipt_status FROM agent_runtime_bindings WHERE session_id=?",(self.manual,))[0],"recovering")
    async def test_copy_api_returns_body_without_reasoning_or_tools(self):
        from ayana.web import WebApp
        self.native.history=[{"info":{"role":"assistant","time":{"created":3}},"parts":[{"type":"reasoning","text":"private reason"},{"type":"tool","text":"debug"},{"type":"text","text":"实际回复"}]}]
        handler=WebApp.__new__(WebApp);handler.mimo_serve=SimpleNamespace(client=lambda:self.native)
        handler._require_auth=lambda request:{"username":"admin"}
        handler._agent_session_require=lambda *args,**kwargs:self.duty.get(self.manual)
        response=await handler.api_agent_session_copy_text(SimpleNamespace(match_info={"sid":self.manual}))
        self.assertEqual(json.loads(response.text)["text"],"实际回复")


class WorkerInterventionTests(Fixture,unittest.IsolatedAsyncioTestCase):
    async def test_pause_cancels_old_business_owner_even_when_abort_unconfirmed(self):
        from ayana.web import WebApp
        self.db.execute("INSERT INTO investigation_jobs(incident_id,generation,status,updated_at,created_at) VALUES('inc1',1,'running',?,?)",(time.time(),time.time()))
        self.db.execute("UPDATE duty_sessions SET remote_session_id='ses_auto' WHERE id=?",(self.auto,))
        async def abort(rid):raise RuntimeError("network unavailable")
        handler=WebApp.__new__(WebApp);handler.db=self.db;handler.duty=self.duty
        handler._require_admin=lambda request:{"username":"admin"}
        handler._check_csrf=lambda *args:None
        handler._agent_session_require=lambda *args,**kwargs:self.duty.get(self.auto)
        handler.mimo_serve=SimpleNamespace(client=lambda:SimpleNamespace(abort=abort))
        result=json.loads((await handler.api_agent_session_pause(SimpleNamespace(match_info={"sid":self.auto}))).text)
        self.assertFalse(result["stop_requested"])
        self.assertEqual(self.db.query_one("SELECT status FROM investigation_jobs")[0],"cancelled")
        self.assertGreater(self.duty.get(self.auto)["paused_at"],0)

    async def test_guidance_invalidates_success_timeout_and_error_without_reoffer(self):
        from ayana.auto_investigate import AutoInvestigator,InvestConfig
        for outcome in ("success","timeout","error"):
            with self.subTest(outcome=outcome):
                self.db.execute("DELETE FROM investigation_jobs")
                self.db.execute("INSERT INTO investigation_jobs(incident_id,generation,status,updated_at,created_at) VALUES('inc1',1,'running',?,?)",(time.time(),time.time()))
                bridge=SimpleNamespace(duty=self.duty,get_mapping=lambda iid:{"session_id":self.auto})
                worker=AutoInvestigator(self.db,bridge=bridge,config=InvestConfig(enabled=True,closed_loop=True))
                async def investigate(*args,**kwargs):
                    self.db.execute("UPDATE duty_sessions SET human_message_revision=human_message_revision+1 WHERE id=?",(self.auto,))
                    if outcome=="timeout":raise asyncio.TimeoutError()
                    if outcome=="error":raise RuntimeError("interrupted old turn")
                    return {"status":"completed","root_cause":"stale"}
                worker._investigate=investigate
                async def forbidden(*args,**kwargs):self.fail("stale automatic decision executed after human guidance")
                worker._close_loop=forbidden
                await worker._run_job_locked("inc1",worker._row("inc1"))
                job=worker._row("inc1")
                self.assertEqual((job["status"],job["last_error"]),("partial","human_guidance"))
                self.assertEqual(worker.offer("inc1")["action"],"noop")


if __name__=='__main__':unittest.main()
