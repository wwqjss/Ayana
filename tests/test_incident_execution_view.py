"""Current incident evidence and native execution must not inherit retired loop state."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.incidents import IncidentService
from ayana.ops_loop import OpsLoop
from ayana.web import WebApp


class IncidentExecutionViewTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "state.db")
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES('romi','Romi','','',1,1)")
        self.db.execute("INSERT INTO incidents(id,title,asset_id,status,stage,generation,created_at,updated_at)"
                        " VALUES('inc','Nginx','romi','open','pending',2,1,2)")
        self.incidents = IncidentService(self.db)
        self.duty = DutySessionManager(self.db)
        self.loop = OpsLoop(self.db, incidents=self.incidents)
        self.app = WebApp(self.db, None, None, self.incidents, None, None, None,
                          static_dir=Path(self.tmp.name), duty=self.duty, ops_loop=self.loop)
        self.app._require_auth = lambda request: {"username": "reader"}
        self.app._visible_asset_ids = lambda user: {"romi"}

    def request(self):
        return SimpleNamespace(match_info={"inc_id": "inc"}, rel_url=SimpleNamespace(query={}))

    def record_exec(self, key, generation, *, status="done", state="success"):
        self.db.execute("INSERT INTO session_write_ops(id,incident_id,session_id,action_key,status,target,created_at,updated_at)"
                        " VALUES(?, 'inc','sess',?,?, 'romi',1,2)", (key, key, status))
        self.db.audit("agent", "mcp_agent", "mcp_host_exec_write", incident_id="inc", action_id=key,
                      detail={"generation": generation, "session_id": "sess", "command": "systemctl start nginx",
                              "state": state, "ssh_account_group": "ops", "ssh_account": "operator", "returncode": 0})

    def record_recovery(self, generation):
        self.db.event("incident_resolved", "Target recovered", incident_id="inc",
                      payload={"generation": generation, "resolution_basis": "target_recovered",
                               "evidence": {"generation": generation, "verdict": "green", "checks": [
                                   {"contract": "check.service", "check_id": "nginx", "verdict": "green", "sample_at": 10}]}})

    async def test_listing_uses_current_generation_host_exec_and_keeps_legacy_state_historical(self):
        self.record_exec("old", 1)
        self.record_exec("current", 2)
        self.record_exec("unscoped", 0)
        self.db.execute("INSERT INTO ops_loop_state(incident_id,generation,status,stop_reason,updated_at)"
                        " VALUES('inc',1,'need_human','unsupported_verification_profile',1)")
        before = self.db.query_one("SELECT total_changes()")[0]
        data = json.loads((await self.app.api_loops(self.request())).body)["loops"][0]
        self.assertEqual([op["id"] for op in data["host_exec"]["operations"]], ["current"])
        self.assertEqual(data["host_exec"]["operations"][0]["account_group"], "ops")
        self.assertTrue(data["legacy_loop"]["retired"])
        self.assertFalse(data["legacy_loop"]["active"])
        self.assertFalse(data["legacy_loop"]["same_generation"])
        self.assertEqual(data["legacy_loop"]["snapshot"]["status"], "need_human")
        self.assertEqual(self.db.query_one("SELECT total_changes()")[0], before)

    async def test_resolved_without_current_recovery_proof_is_not_confirmed(self):
        self.db.execute("UPDATE incidents SET status='resolved',outcome='recovered' WHERE id='inc'")
        self.record_recovery(1)
        data = json.loads((await self.app.api_incident_detail(self.request())).body)["incident"]
        self.assertFalse(data["recovery"]["confirmed"])
        self.record_recovery(2)
        data = json.loads((await self.app.api_incident_detail(self.request())).body)["incident"]
        self.assertTrue(data["recovery"]["confirmed"])
        self.assertEqual(data["recovery"]["evidence"]["checks"][0]["check_id"], "nginx")

    async def test_native_task_state_is_separate_from_incident_recovery(self):
        sid = self.duty.create(origin="manual")["session_id"]
        self.duty.join_incident(sid, "inc", generation=2)
        self.db.execute("INSERT INTO agent_runtime_bindings(session_id,state,receipt_status) VALUES(?,'idle','cancelled')", (sid,))
        self.db.execute("UPDATE incidents SET status='resolved',stage='done',outcome='recovered' WHERE id='inc'")
        self.record_recovery(2)
        data = json.loads((await self.app.api_loops(self.request())).body)["loops"][0]
        self.assertTrue(data["recovery"]["confirmed"])
        self.assertEqual(data["native_task"]["task_state"], "interrupted")
        self.assertEqual(data["native_task"]["session_id"], sid)

    async def test_loop_api_returns_retired_history_without_creating_a_loop_row(self):
        data = json.loads((await self.app.api_ops_loop_status(self.request())).body)
        self.assertEqual(data["loop"]["status"], "retired")
        self.assertEqual(data["loop"]["execution_mode"], "session_host_exec")
        self.assertIsNone(data["loop"]["legacy_loop"]["snapshot"])
        self.assertIsNone(self.db.query_one("SELECT * FROM ops_loop_state WHERE incident_id='inc'"))

    async def test_latest_audit_for_an_operation_replaces_claim_without_duplicate_execution_rows(self):
        self.record_exec("write", 2, status="claimed", state="claimed")
        self.db.audit("agent", "mcp_agent", "mcp_host_exec_write", incident_id="inc", action_id="write",
                      detail={"generation": 2, "session_id": "sess", "state": "success", "returncode": 0,
                              "ssh_account_group": "ops", "ssh_account": "operator"})
        self.db.execute("UPDATE session_write_ops SET status='done' WHERE id='write'")
        data = json.loads((await self.app.api_loops(self.request())).body)["loops"][0]
        self.assertEqual(len(data["host_exec"]["operations"]), 1)
        self.assertEqual(data["host_exec"]["operations"][0]["exec_state"], "success")
        self.assertEqual(data["host_exec"]["operations"][0]["returncode"], 0)

    async def test_loop_history_endpoint_obeys_incident_asset_visibility(self):
        self.app._visible_asset_ids = lambda user: set()
        response = await self.app.api_ops_loop_status(self.request())
        self.assertEqual(response.status, 403)
        self.assertNotIn("loop", json.loads(response.body))
