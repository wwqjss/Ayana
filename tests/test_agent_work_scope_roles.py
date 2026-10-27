"""Trusted session participation, active-work conflicts and real role selection.

Isolated SQLite and SSH transport selection only; no production/model requests.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from ayana.agent_authority import resolve_authority
from ayana.agent_work_scope import (WorkScopeError, claim_incident, claim_target,
                                   find_work_conflict, session_has_work)
from ayana.db import Database, now
from ayana.duty_session import DutySessionManager
from ayana.incidents import IncidentService
from ayana.mcp_server import McpStdioServer, TURN_LIFECYCLE_CAPABILITY
from ayana.mcp_tools import McpToolError, OpsContext, OpsTools
from ayana.ntsafe import NTResult
from ayana.session_bridge import SessionBridge
from ayana.transport import (SSHAssetStore, SSHTransport, TransportError,
                            session_dispatch_guard, session_ssh_scope)


class ScopeFixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name)/"scope.db")
        t=now()
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES('host','Host','read','write',?,?)",(t,t))
        for oid,name in (("obj1","mysql"),("obj2","nginx")):
            self.db.execute("INSERT INTO objects(id,asset_id,kind,name,unit,created_at) VALUES(?,'host','service',?,?,?)",(oid,name,name,t))
        for iid,obj in (("inc1","mysql"),("inc2","nginx")):
            self.db.execute("INSERT INTO incidents(id,title,asset_id,object_id,status,generation,created_at,updated_at) VALUES(?,?,'host',?,'open',1,?,?)",(iid,iid,obj,t,t))
        self.duty = DutySessionManager(self.db)
        self.auto = self.duty.create(origin="auto")["session_id"]
        self.manual = self.duty.create(origin="manual")["session_id"]
        self.other = self.duty.create(origin="manual")["session_id"]
        self.duty.join_incident(self.auto,"inc1")
        for sid,rid in ((self.auto,"ses_auto"),(self.manual,"ses_manual"),(self.other,"ses_other")):
            self.db.execute("UPDATE duty_sessions SET remote_session_id=? WHERE id=?",(rid,sid))
            self.duty.set_runtime_state(sid,"idle")
        self.bridge = SessionBridge(self.db,duty=self.duty)
        self.ctx = OpsContext(transport=None,prom=None,incidents=IncidentService(self.db),knowledge=None,
                              db=self.db,session_bridge=self.bridge,managed_context=True)
        self.tools = OpsTools(self.ctx)
        self.meta = {"sessionId":"ses_manual","turnId":"turn1","actorId":"main"}

    def tearDown(self):
        self.db.close();self.tmp.cleanup()


class WorkConflictTests(ScopeFixture,unittest.TestCase):
    def test_manual_participation_does_not_replace_auto_primary(self):
        result=claim_incident(self.db,self.manual,"inc1")
        self.assertTrue(result["joined"])
        self.db.execute("UPDATE duty_sessions SET updated_at=? WHERE id=?",(now()+100,self.manual))
        self.assertEqual(self.bridge.get_mapping("inc1")["session_id"],self.auto)
        self.assertIsNotNone(self.db.query_one("SELECT 1 FROM session_incidents WHERE session_id=? AND incident_id='inc1'",(self.manual,)))

    def test_busy_auto_rejects_claim_and_identifies_existing_session(self):
        self.duty.set_runtime_state(self.auto,"running")
        with self.assertRaises(WorkScopeError) as caught:claim_incident(self.db,self.manual,"inc1")
        self.assertEqual(caught.exception.code,"work_already_running")
        self.assertEqual(caught.exception.detail["owner_session_id"],self.auto)
        self.assertTrue(caught.exception.detail["stop_processing"])
        self.assertIsNone(self.db.query_one("SELECT 1 FROM session_incidents WHERE session_id=?",(self.manual,)))

    def test_shared_auto_context_is_valid_and_not_a_mapping_collision(self):
        self.duty.join_incident(self.auto,"inc2")
        self.duty.set_runtime_state(self.auto,"running")
        self.assertEqual(self.bridge.get_mapping("inc1")["session_id"],self.bridge.get_mapping("inc2")["session_id"])
        self.assertIsNone(find_work_conflict(self.db,self.auto,incident_id="inc1"))

    def test_distinct_service_on_same_asset_can_progress(self):
        self.duty.set_runtime_state(self.auto,"running")
        self.duty.set_runtime_state(self.manual,"running")
        result=claim_incident(self.db,self.manual,"inc2")
        self.assertTrue(result["ok"])
        self.assertIsNone(find_work_conflict(self.db,self.manual,asset_id="host",object_id="obj2"))

    def test_object_name_and_registered_id_coordinate_same_target(self):
        self.duty.set_runtime_state(self.auto,"running")
        conflict=find_work_conflict(self.db,self.manual,asset_id="host",object_id="obj1")
        self.assertEqual(conflict["owner_session_id"],self.auto)
        self.assertEqual(conflict["object_id"],"obj1")

    def test_raw_command_reservation_coordinates_without_incident(self):
        self.duty.set_runtime_state(self.manual,"running")
        claim_target(self.db,self.manual,asset_id="host")
        with self.assertRaises(WorkScopeError):claim_target(self.db,self.other,asset_id="host",object_id="obj2")
        self.duty.set_runtime_state(self.manual,"idle")
        claim_target(self.db,self.other,asset_id="host",object_id="obj2")
        self.assertEqual(self.db.query_one("SELECT session_id FROM agent_work_targets WHERE object_id='obj2'")[0],self.other)

    def test_unknown_write_never_expires_into_a_new_owner(self):
        self.bridge.claim_write("_session:"+self.manual,"probe",target="host",authority_session_id=self.manual)
        self.bridge.mark_unknown("_session:"+self.manual,"probe")
        self.db.execute("UPDATE session_write_ops SET lease_expires_at=1 WHERE action_key='probe'")
        self.db.execute("UPDATE duty_sessions SET status='archived' WHERE id=?",(self.manual,))
        conflict=find_work_conflict(self.db,self.other,asset_id="host")
        self.assertEqual(conflict["owner_session_id"],self.manual)
        self.assertTrue(session_has_work(self.db,self.manual))

    def test_recovery_submission_blocks_new_target_owner(self):
        claim_target(self.db,self.manual,asset_id="host")
        self.db.execute("INSERT INTO agent_native_submissions(session_id,submission_id,kind,state,created_at,updated_at) VALUES(?,'sub_probe','recovery','recovering',?,?)",(self.manual,now(),now()))
        conflict=find_work_conflict(self.db,self.other,asset_id="host")
        self.assertEqual(conflict["owner_session_id"],self.manual)
        self.db.execute("UPDATE agent_native_submissions SET state='completed'")
        self.assertIsNone(find_work_conflict(self.db,self.other,asset_id="host"))

    def test_manual_participant_does_not_own_the_auto_queue(self):
        claim_incident(self.db,self.manual,"inc1")
        self.db.execute("INSERT INTO investigation_jobs(incident_id,generation,status,phase,created_at,updated_at) VALUES('inc1',1,'queued','queued',?,?)",(now(),now()))
        self.assertFalse(session_has_work(self.db,self.manual))
        self.assertTrue(session_has_work(self.db,self.auto))

    def test_parallel_claims_have_one_winner(self):
        self.duty.set_runtime_state(self.manual,"running")
        self.duty.set_runtime_state(self.other,"running")
        barrier=threading.Barrier(2)
        def acquire(sid):
            barrier.wait()
            try:
                claim_target(self.db,sid,asset_id="host")
                return "claimed"
            except WorkScopeError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(acquire,(self.manual,self.other)))
        self.assertEqual(sorted(results),["claimed","work_already_running"])


class ManagedScopeTests(ScopeFixture,unittest.IsolatedAsyncioTestCase):
    async def test_claim_uses_native_rid_and_ignores_model_session_argument(self):
        result=await self.tools.call("session.claim",{"incident_id":"inc1","session_id":self.auto},invocation_context=self.meta)
        self.assertEqual(result["session_id"],self.manual)
        self.assertEqual(self.bridge.get_mapping("inc1")["session_id"],self.auto)

    async def test_busy_peer_is_structured_in_real_mcp_protocol_response(self):
        self.duty.set_runtime_state(self.auto,"running")
        server=McpStdioServer(self.tools)
        result=await server.handle({"id":1,"method":"tools/call","params":{"name":"session.claim","arguments":{"incident_id":"inc1"},"_meta":{TURN_LIFECYCLE_CAPABILITY:self.meta}}})
        body=json.loads(result["result"]["content"][0]["text"])
        self.assertEqual(body["error"],"work_already_running")
        self.assertEqual(body["owner_session_id"],self.auto)
        self.assertTrue(body["stop_processing"])
        audit=self.db.query_one("SELECT detail_json FROM audit_log WHERE entry='agent_work_conflict' ORDER BY id DESC LIMIT 1")
        self.assertIsNotNone(audit)
        self.assertEqual(json.loads(audit[0])["owner_session_id"],self.auto)

    async def test_unlinked_incident_has_actionable_claim_hint(self):
        with self.assertRaises(McpToolError) as caught:
            await self.tools.call("incident.note",{"incident_id":"inc1","text":"note"},invocation_context=self.meta)
        self.assertEqual(caught.exception.code,"incident_session_mismatch")
        self.assertEqual(caught.exception.detail["current_session_id"],self.manual)
        self.assertEqual(caught.exception.detail["owner_session_id"],self.auto)
        self.assertEqual(caught.exception.detail["next_tool"],"ayana_session_claim")

    async def test_remote_links_same_rid_without_nested_prompt(self):
        result=await self.tools.call("session.remote",{"incident_id":"inc1"},invocation_context=self.meta)
        self.assertEqual(result["remote_session_id"],"ses_manual")
        self.assertEqual(result["action"],"associated_current_native")
        for extra in ({"force_new":True},{"prompt":"start another task"}):
            with self.assertRaises(McpToolError) as caught:
                await self.tools.call("session.remote",{"incident_id":"inc1",**extra},invocation_context=self.meta)
            self.assertEqual(caught.exception.code,"use_current_session_input")
        self.assertEqual(self.db.query_one("SELECT remote_session_id FROM duty_sessions WHERE id=?",(self.manual,))[0],"ses_manual")

    async def test_general_shell_cannot_bypass_busy_incident_scope(self):
        self.duty.set_runtime_state(self.auto,"running")
        calls=[]
        class Transport:
            async def exec_shell(inner,*args,**kwargs):
                calls.append(args)
                return NTResult(ok=True,output="ok",returncode=0,mode="exec",account="write")
        self.ctx.transport=Transport()
        with self.assertRaises(McpToolError) as caught:
            await self.tools.call("host.exec",{"asset_id":"host","command":"touch /tmp/probe"},invocation_context=self.meta)
        self.assertEqual(caught.exception.code,"work_already_running")
        self.assertFalse(calls)

    async def test_readonly_error_names_actual_manual_authority(self):
        self.db.execute("UPDATE duty_sessions SET access_mode='readonly' WHERE id=?",(self.manual,))
        with self.assertRaises(McpToolError) as caught:
            await self.tools.call("host.exec",{"asset_id":"host","command":"echo probe"},invocation_context=self.meta)
        self.assertEqual(caught.exception.code,"readonly_mode_rejects_write")
        self.assertNotIn("auto-investigation",caught.exception.message)
        authority=caught.exception.detail["effective_permissions"]
        self.assertEqual(authority["session_id"],self.manual)
        self.assertEqual(authority["source"],"manual_session")

    async def test_pause_deletion_block_write_without_fake_access_downgrade(self):
        for column,code in (("paused_at","session_paused"),("delete_requested_at","session_deleting"),("deleted_at","session_deleted")):
            self.db.execute("UPDATE duty_sessions SET paused_at=0,delete_requested_at=0,deleted_at=0 WHERE id=?",(self.manual,))
            self.db.execute(f"UPDATE duty_sessions SET {column}=1 WHERE id=?",(self.manual,))
            authority=resolve_authority(self.db,self.manual)
            self.assertEqual(authority["access_mode"],"readwrite")
            self.assertFalse(authority["write_allowed"])
            with self.assertRaises(McpToolError) as caught:
                await self.tools.call("session.claim",{"incident_id":"inc1"},invocation_context=self.meta)
            self.assertEqual(caught.exception.code,code)
            with self.assertRaises(TransportError) as caught:
                with session_dispatch_guard(self.db,self.manual):pass
            self.assertEqual(caught.exception.code,code)


class RoleConsumptionTests(ScopeFixture,unittest.IsolatedAsyncioTestCase):
    def prepare_roles(self):
        self.store=SSHAssetStore(self.db)
        for name,kind,user in (("investigator","read","observer"),("operator","write","operator")):
            self.store.add_role(name=name,kind=kind)
            self.store.upsert_endpoint(asset_id="host",role=name,host="host.example",username=user)
        self.store.upsert_endpoint(asset_id="host",role="write",host="host.example",username="root")
        self.duty.set_settings({"ssh_investigate_role":"investigator","ssh_execute_role":"operator"})
        return SSHTransport(self.store,None)

    async def test_managed_mcp_read_uses_actual_configured_investigation_account(self):
        transport=self.prepare_roles()
        calls=[]
        async def command(asset,kind,text,timeout):
            endpoint=transport._endpoint_for_channel(asset,kind)
            calls.append(endpoint.username)
            return NTResult(ok=True,output="ok",returncode=0,mode="probe",account=endpoint.username)
        transport._run_command=command
        self.ctx.transport=transport
        result=await self.tools.call("host.exec",{"asset_id":"host","command":"uname -a","channel":"read"},invocation_context=self.meta)
        self.assertEqual(result["account"],"observer")
        self.assertEqual(calls,["observer"])

    async def test_managed_write_uses_actual_execution_account(self):
        transport=self.prepare_roles()
        self.ctx.transport=transport
        self.duty.set_setting("auto_approval_mode","automatic")
        self.db.execute("UPDATE duty_sessions SET approval_mode='automatic' WHERE id=?",(self.manual,))
        async def command(asset,kind,text,timeout):
            endpoint=transport._endpoint_for_channel(asset,kind)
            return NTResult(ok=True,output="ok",returncode=0,mode="exec",account=endpoint.username)
        transport._run_command=command
        result=await self.tools.call("host.exec",{"asset_id":"host","command":"touch /tmp/probe"},invocation_context=self.meta)
        self.assertEqual(result["account"],"operator")
        self.assertEqual(result["exec_state"],"success")

    async def test_explicit_role_missing_for_target_never_falls_back_to_root(self):
        transport=self.prepare_roles()
        self.store.add_role(name="missing",kind="read")
        self.duty.set_setting("ssh_investigate_role","missing")
        with session_ssh_scope(self.db,self.manual):
            with self.assertRaises(TransportError) as caught:transport._endpoint_for_channel("host","read")
        self.assertEqual(caught.exception.code,"configured_ssh_endpoint_missing")
        self.assertEqual(transport._endpoint_for_channel("host","read").username,"observer")

    async def test_missing_role_returns_real_mcp_error_without_detail_type_crash(self):
        transport=self.prepare_roles()
        self.store.add_role(name="missing",kind="read")
        self.duty.set_setting("ssh_investigate_role","missing")
        self.ctx.transport=transport
        server=McpStdioServer(self.tools)
        reply=await server.handle({"id":1,"method":"tools/call","params":{
            "name":"host.exec","arguments":{"asset_id":"host","command":"uname -a","channel":"read"},
            "_meta":{TURN_LIFECYCLE_CAPABILITY:self.meta}}})
        result=json.loads(reply["result"]["content"][0]["text"])
        self.assertTrue(reply["result"]["isError"])
        self.assertEqual(result["error"],"configured_ssh_endpoint_missing")
        self.assertIn("missing",result["message"])

    async def test_legacy_and_default_read_fallback_are_preserved(self):
        transport=self.prepare_roles()
        self.assertEqual(transport._endpoint_for_channel("host","write").username,"root")
        self.db.execute("UPDATE ssh_endpoints SET enabled=0 WHERE role='investigator'")
        self.duty.set_setting("ssh_investigate_role","read")
        with session_ssh_scope(self.db,self.manual):
            self.assertEqual(transport._endpoint_for_channel("host","read").username,"root")

    async def test_explicit_read_role_can_be_execution_credential_without_kind_whitelist(self):
        transport=self.prepare_roles()
        self.duty.set_setting("ssh_execute_role","investigator")
        with session_dispatch_guard(self.db,self.manual):
            self.assertEqual(transport._endpoint_for_channel("host","write").username,"observer")

    async def test_role_scope_is_task_local(self):
        transport=self.prepare_roles()
        async def managed():
            with session_ssh_scope(self.db,self.manual):
                await asyncio.sleep(0)
                return transport._endpoint_for_channel("host","write").username
        async def legacy():
            await asyncio.sleep(0)
            return transport._endpoint_for_channel("host","write").username
        self.assertEqual(await asyncio.gather(managed(),legacy()),["operator","root"])


class TemporaryActionBlockTests(ScopeFixture,unittest.IsolatedAsyncioTestCase):
    def prepare_action(self):
        from ayana.actions import ActionService
        from tests.test_p61_closed_loop_e2e import FakeTransport,FakeGate,FakePolicy,FakeProm
        self.db.execute("UPDATE assets SET expected_host_id='HOST',host_id_verified_at=?",(now(),))
        claim_incident(self.db,self.manual,"inc1")
        self.transport=FakeTransport()
        self.actions=ActionService(self.db,self.transport,FakeGate(),FakePolicy(),FakeProm(),transport=self.transport)
        self.actions.write_ops=self.bridge
        proposal=self.actions.propose(asset_id="host",object_id="obj1",capability="service.restart",incident_id="inc1",
                                      mode="autonomous",proposer_type="agent",proposer_id="mimo",authority_session_id=self.manual)
        aid=proposal["id"]
        self.db.execute("UPDATE actions SET state='approved',approver_type='web_user',approver_id='admin',approved_at=? WHERE id=?",(now(),aid))
        return aid

    async def test_pause_after_identity_preserves_human_approval_and_resumes_once(self):
        from ayana.actions import ActionError
        aid=self.prepare_action();original=self.actions.gate.verify_account
        async def verify(*args,**kwargs):
            result=await original(*args,**kwargs)
            self.db.execute("UPDATE duty_sessions SET paused_at=? WHERE id=?",(now(),self.manual))
            return result
        self.actions.gate.verify_account=verify
        with self.assertRaises(ActionError) as caught:await self.actions.execute(aid,actor_type="web_user",actor_id="admin",is_admin=True)
        self.assertEqual(caught.exception.code,"session_paused")
        row=self.db.query_one("SELECT state,approver_type,approver_id FROM actions WHERE id=?",(aid,))
        self.assertEqual(tuple(row),("approved","web_user","admin"))
        self.assertFalse(self.db.query_one("SELECT need_human FROM incidents WHERE id='inc1'")[0])
        self.assertFalse(self.transport.calls)
        self.db.execute("UPDATE duty_sessions SET paused_at=0 WHERE id=?",(self.manual,));self.actions.gate.verify_account=original
        result=await self.actions.execute(aid,actor_type="web_user",actor_id="admin",is_admin=True)
        self.assertEqual(result["state"],"success")
        self.assertEqual(len(self.transport.calls),1)
        ledger=self.db.query_one("SELECT session_id,status FROM session_write_ops WHERE incident_id='inc1'")
        self.assertEqual(tuple(ledger),(self.manual,"done"))
        with self.assertRaises(ActionError):await self.actions.execute(aid,actor_type="web_user",actor_id="admin",is_admin=True)
        self.assertEqual(len(self.transport.calls),1)

    async def test_peer_work_after_identity_preserves_approval_and_owner_context(self):
        from ayana.actions import ActionError
        aid=self.prepare_action();original=self.actions.gate.verify_account
        async def verify(*args,**kwargs):
            result=await original(*args,**kwargs);self.duty.set_runtime_state(self.auto,"running");return result
        self.actions.gate.verify_account=verify
        with self.assertRaises(ActionError) as caught:await self.actions.execute(aid,actor_type="web_user",actor_id="admin",is_admin=True)
        self.assertEqual(caught.exception.code,"work_already_running")
        self.assertEqual(caught.exception.context["owner_session_id"],self.auto)
        self.assertEqual(self.db.query_one("SELECT state FROM actions WHERE id=?",(aid,))[0],"approved")
        self.assertFalse(self.db.query_one("SELECT need_human FROM incidents WHERE id='inc1'")[0])
        self.assertFalse(self.transport.calls)

    async def test_delete_after_identity_cancels_not_yet_dispatched_action(self):
        from ayana.actions import ActionError
        aid=self.prepare_action();original=self.actions.gate.verify_account
        async def verify(*args,**kwargs):
            result=await original(*args,**kwargs)
            self.db.execute("UPDATE duty_sessions SET delete_requested_at=? WHERE id=?",(now(),self.manual));return result
        self.actions.gate.verify_account=verify
        with self.assertRaises(ActionError) as caught:await self.actions.execute(aid,actor_type="web_user",actor_id="admin",is_admin=True)
        self.assertEqual(caught.exception.code,"session_deleting")
        self.assertEqual(self.db.query_one("SELECT state FROM actions WHERE id=?",(aid,))[0],"cancelled")
        self.assertFalse(self.transport.calls)

    async def test_delete_at_final_transport_guard_is_cancelled_not_unknown(self):
        from ayana.actions import ActionError
        from ayana.transport import check_dispatch_authority
        aid=self.prepare_action()
        async def exec_late(asset,tokens,timeout=None):
            self.db.execute("UPDATE duty_sessions SET delete_requested_at=? WHERE id=?",(now(),self.manual))
            check_dispatch_authority()
            raise AssertionError("must not dispatch")
        self.transport.exec=exec_late
        with self.assertRaises(ActionError) as caught:await self.actions.execute(aid,actor_type="web_user",actor_id="admin",is_admin=True)
        self.assertEqual(caught.exception.code,"session_deleting")
        self.assertEqual(self.db.query_one("SELECT state FROM actions WHERE id=?",(aid,))[0],"cancelled")
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops WHERE incident_id='inc1'")[0],"released")
        self.assertFalse(self.transport.calls)


if __name__=="__main__":unittest.main()
