"""Live authority contracts; isolated SQLite and no external model/SSH calls."""
import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from ayana.agent_authority import AuthorityError, resolve_authority, resolve_remote_authority
from ayana.agent_tui import AgentTuiManager, AgentTuiError
from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.incidents import IncidentService
from ayana.mcp_tools import OpsContext, OpsTools, McpToolError
from ayana.mcp_server import McpStdioServer, TURN_LIFECYCLE_CAPABILITY
from ayana.session_bridge import SessionBridge
from ayana.transport import session_dispatch_guard, check_dispatch_authority, TransportError


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name)/"test.db")
        self.duty = DutySessionManager(self.db)
        self.auto = self.duty.create(origin="auto")["session_id"]
        self.manual = self.duty.create(origin="manual")["session_id"]
        self.manager = AgentTuiManager(self.db, lambda: None, state_dir=self.tmp.name)
        for sid in (self.auto,self.manual):
            self.duty.set_runtime_state(sid, "idle")
            self.manager._connections[sid] = {"session_id":sid,"username":"admin"}
        self.bridge = SessionBridge(self.db, duty=self.duty)
        self.incidents = IncidentService(self.db)
        self.ctx = OpsContext(transport=None,prom=None,incidents=self.incidents,knowledge=None,db=self.db,session_bridge=self.bridge,managed_context=True)
        self.tools = OpsTools(self.ctx)
        self.db.execute("UPDATE duty_sessions SET remote_session_id='ses_trusted' WHERE id=?", (self.auto,))
        self.meta = {"sessionId":"ses_trusted","turnId":"turn1","actorId":"main"}

    def tearDown(self):
        self.db.close(); self.tmp.cleanup()

    def switch(self, sid, **kw):
        return self.manager.change_permissions(sid,"admin",sid,expected_revision=resolve_authority(self.db,sid)["revision"],**kw)

    def test_all_auto_modes_independent(self):
        for access in ("readonly","readwrite"):
            for approval in ("manual","automatic"):
                self.duty.set_settings({"auto_access_mode":access,"auto_approval_mode":approval})
                a=resolve_authority(self.db,self.auto)
                self.assertEqual((a["access_mode"],a["approval_mode"]),(access,approval))

    def test_manual_owns_state(self):
        before=resolve_authority(self.db,self.manual)
        self.duty.set_settings({"auto_access_mode":"readonly","auto_approval_mode":"automatic"})
        after=resolve_authority(self.db,self.manual)
        self.assertEqual((after["access_mode"],after["approval_mode"]),(before["access_mode"],before["approval_mode"]))
        self.assertEqual(after["access_mode"],"readwrite")

    def test_takeover_inherits_all_four_combinations(self):
        for access in ("readonly","readwrite"):
            for approval in ("manual","automatic"):
                self.duty.set_settings({"auto_access_mode":access,"auto_approval_mode":approval})
                a=self.manager.acquire_control(self.auto,"admin",self.auto)["effective_permissions"]
                self.assertEqual((a["access_mode"],a["approval_mode"]),(access,approval))
                self.manager.release_control(self.auto,"admin",self.auto)

    def test_switch_does_not_mutate_global_and_release_restores_latest(self):
        self.duty.set_settings({"auto_access_mode":"readonly","auto_approval_mode":"manual"})
        self.manager.acquire_control(self.auto,"admin",self.auto)
        self.switch(self.auto,access_mode="readwrite",approval_mode="automatic")
        self.assertEqual(self.duty.settings()["auto_access_mode"],"readonly")
        self.duty.set_settings({"auto_access_mode":"readwrite","auto_approval_mode":"manual"})
        self.assertEqual(resolve_authority(self.db,self.auto)["approval_mode"],"automatic")
        a=self.manager.release_control(self.auto,"admin",self.auto)["effective_permissions"]
        self.assertEqual((a["access_mode"],a["approval_mode"],a["source"]),("readwrite","manual","auto_global"))

    def test_manual_release_restores_own_base(self):
        self.manager.acquire_control(self.manual,"admin",self.manual)
        self.switch(self.manual,access_mode="readonly",approval_mode="automatic")
        a=self.manager.release_control(self.manual,"admin",self.manual)["effective_permissions"]
        self.assertEqual((a["access_mode"],a["approval_mode"]),("readwrite","manual"))

    def test_observer_cannot_switch(self):
        with self.assertRaises(AgentTuiError): self.switch(self.auto,access_mode="readonly")

    def test_connection_competition_and_stale_revision(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        old=resolve_authority(self.db,self.auto)["revision"]
        self.switch(self.auto,access_mode="readonly")
        with self.assertRaises(AgentTuiError):
            self.manager.change_permissions(self.auto,"admin",self.auto,access_mode="readwrite",expected_revision=old)
        self.manager._connections["other"]={"session_id":self.auto,"username":"admin"}
        with self.assertRaises(AgentTuiError): self.manager.acquire_control(self.auto,"admin","other")
        self.assertFalse(self.manager.release_control(self.auto,"admin","other")["released"])

    def test_expiry_ignored_before_cleanup_and_audited(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        self.switch(self.auto,access_mode="readonly")
        self.db.execute("UPDATE agent_runtime_bindings SET control_expires_at=1 WHERE session_id=?", (self.auto,))
        self.assertEqual(resolve_authority(self.db,self.auto)["access_mode"],"readwrite")
        self.assertFalse(self.manager._has_control(self.auto,"admin",self.auto,renew=True))
        self.assertEqual(self.manager._binding(self.auto)["override_access_mode"],"")

    def test_restart_revokes_override(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        self.switch(self.auto,access_mode="readonly")
        self.duty.recover()
        self.assertFalse(resolve_authority(self.db,self.auto)["controller_active"])
        self.assertEqual(resolve_authority(self.db,self.auto)["access_mode"],"readwrite")

    def test_multiple_manager_instances_do_not_revoke_control(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        AgentTuiManager(self.db, lambda: None, state_dir=self.tmp.name)
        self.assertTrue(resolve_authority(self.db,self.auto)["controller_active"])

    def test_remote_binding_requires_unique_actual_rid(self):
        self.assertEqual(resolve_remote_authority(self.db,"ses_trusted")["session_id"],self.auto)
        with self.assertRaises(AuthorityError): resolve_remote_authority(self.db,"ses_fake")
        self.db.execute("UPDATE duty_sessions SET remote_session_id='ses_trusted' WHERE id=?",(self.manual,))
        with self.assertRaises(AuthorityError): resolve_remote_authority(self.db,"ses_trusted")

    def test_managed_missing_context_cannot_forge_model_arguments(self):
        with self.assertRaises(McpToolError) as caught:
            asyncio.run(self.tools.call("asset.list", {"session_id":self.auto,"approved":True}))
        self.assertEqual(caught.exception.code,"trusted_session_context_required")

    def test_mcp_negotiates_and_reads_real_metadata(self):
        server=McpStdioServer(self.tools)
        init=asyncio.run(server.handle({"id":1,"method":"initialize"}))
        self.assertEqual(init["result"]["capabilities"]["experimental"][TURN_LIFECYCLE_CAPABILITY],{"version":1})
        result=asyncio.run(server.handle({"id":2,"method":"tools/call","params":{"name":"asset.list","arguments":{},"_meta":{TURN_LIFECYCLE_CAPABILITY:self.meta}}}))
        self.assertFalse(result["result"]["isError"])

    def test_live_ro_write_rejects_and_rw_manual_waits(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        self.switch(self.auto,access_mode="readonly")
        with self.assertRaises(McpToolError) as caught:
            asyncio.run(self.tools.call("knowledge.upsert", {"title":"probe","objects":["host"]}, invocation_context=self.meta))
        self.assertEqual(caught.exception.code,"readonly_mode_rejects_write")
        self.switch(self.auto,access_mode="readwrite",approval_mode="manual")
        out=asyncio.run(self.tools.call("knowledge.upsert", {"title":"probe","objects":["host"],"approved":True}, invocation_context=self.meta))
        self.assertEqual(out["error"],"approval_required")
        row=self.db.query_one("SELECT * FROM session_write_ops WHERE action_key=?",(out["action_key"],))
        self.assertEqual(row["session_id"],self.auto)
        self.switch(self.auto,access_mode="readonly")
        approved=self.bridge.approve_pending_write(out["incident_id"],out["action_key"],approved_by="admin")
        self.assertEqual(approved["error"],"readonly_mode_rejects_write")

    def test_explicit_hard_readonly_survives_rw(self):
        self.ctx.readonly=True
        self.duty.set_setting("auto_approval_mode","automatic")
        with self.assertRaises(McpToolError):
            asyncio.run(self.tools.call("knowledge.upsert", {}, invocation_context=self.meta))

    def test_final_dispatch_rechecks_downgrade_and_approval(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        self.switch(self.auto,approval_mode="automatic")
        with session_dispatch_guard(self.db,self.auto,require_automatic=True):
            self.switch(self.auto,access_mode="readonly")
            with self.assertRaises(TransportError) as caught: check_dispatch_authority()
            self.assertTrue(caught.exception.dispatch_not_started)
        self.switch(self.auto,access_mode="readwrite",approval_mode="automatic")
        with session_dispatch_guard(self.db,self.auto,require_automatic=True):
            self.switch(self.auto,approval_mode="manual")
            with self.assertRaises(TransportError) as caught: check_dispatch_authority()
            self.assertEqual(caught.exception.code,"approval_required")

    def test_no_cross_task_context_leak(self):
        async def run():
            self.duty.set_setting("auto_access_mode","readonly")
            async def rejected():
                with self.assertRaises(TransportError):
                    with session_dispatch_guard(self.db,self.auto): pass
            async def unrelated():
                await asyncio.sleep(0)
                check_dispatch_authority()
            await asyncio.gather(rejected(),unrelated())
        asyncio.run(run())


class ExecutionAuthorityTests(unittest.IsolatedAsyncioTestCase):
    setUp=AuthorityTests.setUp
    tearDown=AuthorityTests.tearDown
    switch=AuthorityTests.switch

    def action_service(self):
        from tests.test_p61_closed_loop_e2e import _seed, FakeTransport, FakeGate, FakePolicy, FakeProm
        from ayana.actions import ActionService
        _seed(self.db)
        self.transport=FakeTransport()
        self.actions=ActionService(self.db,self.transport,FakeGate(),FakePolicy(),FakeProm(),transport=self.transport)
        self.duty.join_incident(self.auto,"inc1")
        return self.actions

    def propose(self):
        return self.actions.propose(asset_id="host",object_id="obj",capability="service.restart",incident_id="inc1",mode="autonomous",proposer_type="agent",proposer_id="mimo",authority_session_id=self.auto)

    async def test_action_all_permission_approval_combinations(self):
        from ayana.actions import ActionError
        self.action_service()
        for access in ("readonly","readwrite"):
            for approval in ("manual","automatic"):
                self.duty.set_settings({"auto_access_mode":access,"auto_approval_mode":approval})
                if access=="readonly":
                    with self.assertRaises(ActionError) as caught:self.propose()
                    self.assertEqual(caught.exception.code,"readonly_mode_rejects_write")
                else:
                    result=self.propose()
                    self.assertEqual(result["state"],"proposed" if approval=="manual" else "approved")

    async def test_action_system_approval_revoked_when_now_manual(self):
        from ayana.actions import ActionError
        self.action_service()
        self.duty.set_setting("auto_approval_mode","automatic")
        action=self.propose()
        self.duty.set_setting("auto_approval_mode","manual")
        with self.assertRaises(ActionError) as caught:
            await self.actions.execute(action["id"],actor_type="agent",actor_id="mimo")
        self.assertEqual(caught.exception.code,"approval_required")
        row=self.db.query_one("SELECT state,approver_type FROM actions WHERE id=?",(action["id"],))
        self.assertEqual(row["state"],"proposed")
        self.assertFalse(row["approver_type"])
        self.assertFalse(self.transport.calls)

    async def test_action_final_gate_rechecks_after_identity_await(self):
        from ayana.actions import ActionError
        self.action_service()
        self.duty.set_setting("auto_approval_mode","automatic")
        action=self.propose()
        original=self.actions.gate.verify_account
        async def verify(*args,**kwargs):
            result=await original(*args,**kwargs)
            self.duty.set_setting("auto_access_mode","readonly")
            return result
        self.actions.gate.verify_account=verify
        with self.assertRaises(ActionError) as caught:
            await self.actions.execute(action["id"],actor_type="agent",actor_id="mimo")
        self.assertEqual(caught.exception.code,"readonly_mode_rejects_write")
        self.assertFalse(self.transport.calls)

    async def test_pending_command_preserves_long_command_and_unknown_blocks(self):
        from tests.test_p61_closed_loop_e2e import FakeTransport
        self.ctx.transport=FakeTransport()
        self.duty.set_setting("auto_approval_mode","manual")
        command="printf '%s' '"+"a"*2500+"'"
        result=await self.tools.call("host.exec",{"asset_id":"host","command":command},invocation_context=self.meta)
        self.assertEqual(result["error"],"approval_required")
        params=self.bridge.approve_pending_write(result["incident_id"],result["action_key"],approved_by="admin")["params"]
        self.assertEqual(params["command"],command)
        self.bridge.mark_unknown(result["incident_id"],result["action_key"])
        repeated=await self.tools.call("host.exec",{"asset_id":"host","command":command},invocation_context=self.meta)
        self.assertNotEqual(repeated.get("error"),"approval_required")
        self.assertFalse(self.ctx.transport.calls)

    async def test_same_rid_running_call_sees_switch_before_dispatch(self):
        from ayana.ntsafe import NTResult
        started,proceed=asyncio.Event(),asyncio.Event()
        calls=[]
        class PausedTransport:
            async def exec_shell(inner,*args,**kwargs):
                started.set();await proceed.wait()
                check_dispatch_authority()
                calls.append(args)
                return NTResult(ok=True,output="ok",returncode=0,mode="exec",account="write")
        self.ctx.transport=PausedTransport()
        self.duty.set_setting("auto_approval_mode","automatic")
        self.manager.acquire_control(self.auto,"admin",self.auto)
        task=asyncio.create_task(self.tools.call("host.exec",{"asset_id":"host","command":"touch /tmp/probe"},invocation_context=self.meta))
        await started.wait()
        self.switch(self.auto,access_mode="readonly")
        proceed.set();result=await task
        self.assertEqual(result["error"],"readonly_mode_rejects_write")
        self.assertFalse(calls)
        self.assertEqual(resolve_remote_authority(self.db,"ses_trusted")["session_id"],self.auto)

    async def test_generic_pending_executes_once_via_actual_web_handler(self):
        from ayana.web import WebApp
        t=time.time()
        self.db.execute("INSERT INTO incidents(id,title,status,created_at,updated_at) VALUES('probe','Probe','open',?,?)",(t,t))
        self.duty.join_incident(self.auto,"probe")
        result=await self.tools.call("incident.note",{"incident_id":"probe","text":"approved probe"},invocation_context=self.meta)
        self.assertEqual(result["error"],"approval_required")
        handler=WebApp.__new__(WebApp)
        handler.db=self.db;handler.session_bridge=self.bridge;handler.transport=None;handler.prom=None
        handler.incidents=self.incidents;handler.actions=None
        handler._require_admin=lambda request:{"username":"admin","is_admin":True}
        handler._check_csrf=lambda *args:None
        class Request:
            async def json(inner):return {"incident_id":result["incident_id"],"action_key":result["action_key"]}
        reply=await handler.api_agent_pending_approve(Request())
        out=json.loads(reply.text)
        self.assertEqual(out.get("exec_state"),"success",out)
        row=self.db.query_one("SELECT status FROM session_write_ops WHERE action_key=?",(result["action_key"],))
        self.assertEqual(row["status"],"done")
        reply=await handler.api_agent_pending_approve(Request())
        self.assertFalse(json.loads(reply.text)["ok"])

    async def test_permission_web_api_reports_confirmed_failure_and_conflict(self):
        from ayana.web import WebApp
        handler=WebApp.__new__(WebApp)
        handler.db=self.db;handler.duty=self.duty;handler.agent_tui=self.manager
        handler._require_admin=lambda request:{"username":"admin","is_admin":True}
        handler._check_csrf=lambda *args:None
        handler._agent_session_require=lambda user,sid,**kw:self.duty.get(sid)
        payload={"connection_id":self.auto,"revision":resolve_authority(self.db,self.auto)["revision"],"access_mode":"readonly"}
        class Request:
            match_info={"sid":self.auto}
            async def json(inner):return payload
        reply=await handler.api_agent_session_permissions(Request())
        self.assertEqual(reply.status,409)
        self.assertEqual(json.loads(reply.text)["effective_permissions"]["access_mode"],"readwrite")
        self.manager.acquire_control(self.auto,"admin",self.auto)
        payload["revision"]=resolve_authority(self.db,self.auto)["revision"]
        reply=await handler.api_agent_session_permissions(Request())
        self.assertEqual(reply.status,200)
        self.assertEqual(json.loads(reply.text)["effective_permissions"]["access_mode"],"readonly")


class RuntimeAndMigrationTests(unittest.TestCase):
    def test_managed_profile_keeps_all_existing_tools_and_denies_native_shell(self):
        from ayana.mcp_tools import TOOL_SPECS
        from ayana.mimo_serve import MimoServeManager
        manager=MimoServeManager(password="test")
        env=manager._env({"managed_context":True,"config":{"mcp":{"ayana":{"environment":{}}}}})
        config=json.loads(env["MIMOCODE_CONFIG_CONTENT"])
        self.assertEqual(config["default_agent"],"ayana")
        self.assertEqual(set(config["agent"]["ayana"]["tool_allowlist"]),{"ayana_"+s["name"].replace(".","_") for s in TOOL_SPECS})
        self.assertEqual(config["permission"]["*"],"deny")
        self.assertNotIn("bash",config["agent"]["ayana"]["tool_allowlist"])
        self.assertEqual(config["mcp"]["ayana"]["environment"]["AYANA_MCP_MANAGED_CONTEXT"],"1")

    def test_v23_upgrade_preserves_history_and_modes_and_is_idempotent(self):
        from unittest.mock import patch
        from ayana.db import _migrate_v24_agent_authority
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            path=Path(directory)/"old.db"
            with patch("ayana.db.SCHEMA_VERSION",23):
                old=Database(path)
                old.execute("INSERT INTO duty_sessions(id,origin,status,created_at,updated_at) VALUES('sess_old','manual','open',1,1)")
                old.execute("UPDATE agent_settings SET value='0' WHERE key='require_human_approval'")
                old.close()
            db=Database(path)
            from ayana.db import SCHEMA_VERSION
            self.assertEqual(db.schema_version(),SCHEMA_VERSION)
            before=resolve_authority(db,"sess_old")
            self.assertEqual((before["access_mode"],before["approval_mode"]),("readonly","automatic"))
            duty=DutySessionManager(db)
            sid=duty.create(origin="manual")["session_id"]
            self.assertEqual(resolve_authority(db,sid)["access_mode"],"readwrite")
            duty.set_setting("auto_approval_mode","manual")
            self.assertEqual(resolve_authority(db,sid)["approval_mode"],"automatic")
            with db.tx() as conn:_migrate_v24_agent_authority(conn)
            self.assertEqual(resolve_authority(db,sid)["approval_mode"],"automatic")
            self.assertIsNotNone(db.query_one("SELECT id FROM duty_sessions WHERE id='sess_old'"))
            db.close()


if __name__ == "__main__": unittest.main()
