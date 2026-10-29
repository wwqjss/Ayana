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

    def test_write_allowed_unless_lifecycle_block(self):
        # PERM-03：三档只读/审批已删除；未阻塞会话可写，由 SSH 账号组决定能力
        a=resolve_authority(self.db,self.auto)
        self.assertTrue(a["write_allowed"])
        self.duty.pause_session(self.auto, actor="admin")
        a=resolve_authority(self.db,self.auto)
        self.assertFalse(a["write_allowed"])
        self.assertEqual(a["lifecycle_block"],"session_paused")

    def test_manual_and_auto_share_authority_shape(self):
        for sid in (self.auto, self.manual):
            a=resolve_authority(self.db,sid)
            self.assertTrue(a["write_allowed"])
            self.assertEqual(a["access_mode"],"readwrite")

    def test_takeover_sets_source_and_survives_release(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        a=resolve_authority(self.db,self.auto)
        self.assertTrue(a["controller_active"])
        self.assertEqual(a["source"],"takeover")
        self.manager.release_control(self.auto,"admin",self.auto)
        a=resolve_authority(self.db,self.auto)
        self.assertFalse(a["controller_active"])
        self.assertEqual(a["source"],"auto_global")

    def test_observer_cannot_switch(self):
        with self.assertRaises(AgentTuiError): self.switch(self.auto,access_mode="readonly")

    def test_connection_competition_and_stale_revision(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        old=resolve_authority(self.db,self.auto)["revision"]
        self.switch(self.auto,access_mode="readwrite",approval_mode="automatic")
        with self.assertRaises(AgentTuiError):
            self.manager.change_permissions(self.auto,"admin",self.auto,access_mode="readwrite",expected_revision=old)
        self.manager._connections["other"]={"session_id":self.auto,"username":"admin"}
        with self.assertRaises(AgentTuiError): self.manager.acquire_control(self.auto,"admin","other")
        self.assertFalse(self.manager.release_control(self.auto,"admin","other")["released"])

    def test_expiry_ignored_before_cleanup_and_audited(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        self.db.execute("UPDATE agent_runtime_bindings SET control_expires_at=1 WHERE session_id=?", (self.auto,))
        self.assertFalse(self.manager._has_control(self.auto,"admin",self.auto,renew=True))
        self.assertEqual(self.manager._binding(self.auto)["override_access_mode"],"")

    def test_restart_revokes_override(self):
        self.manager.acquire_control(self.auto,"admin",self.auto)
        self.duty.recover()
        self.assertFalse(resolve_authority(self.db,self.auto)["controller_active"])

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

    def test_explicit_hard_readonly_survives_rw(self):
        self.ctx.readonly=True
        with self.assertRaises(McpToolError):
            asyncio.run(self.tools.call("knowledge.upsert", {}, invocation_context=self.meta))


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
            # PERM-03：历史会话保留；权威不再按旧三档读写
            before=resolve_authority(db,"sess_old")
            self.assertTrue(before["write_allowed"])
            duty=DutySessionManager(db)
            sid=duty.create(origin="manual")["session_id"]
            self.assertTrue(resolve_authority(db,sid)["write_allowed"])
            with db.tx() as conn:_migrate_v24_agent_authority(conn)
            self.assertTrue(resolve_authority(db,sid)["write_allowed"])
            self.assertIsNotNone(db.query_one("SELECT id FROM duty_sessions WHERE id='sess_old'"))
            db.close()


if __name__ == "__main__": unittest.main()
