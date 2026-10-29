"""Incident write attribution, generation isolation and uncertainty; no network."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from ayana.db import Database, now
from ayana.duty_session import DutySessionManager
from ayana.exec_facts import NTResult
from ayana.mcp_tools import McpToolError, OpsContext, OpsTools
from ayana.session_bridge import SessionBridge
from ayana.transport import check_dispatch_authority


class FakeSSH:
    def __init__(self):
        self.calls = []
        self.before_dispatch = None
        self.result = NTResult(ok=True, output="active", returncode=0, account="operator", account_group="ops")

    async def exec_shell(self, asset_id, command, timeout=None, *, channel="write"):
        if self.before_dispatch:
            self.before_dispatch()
        check_dispatch_authority()
        self.calls.append((asset_id, command, channel))
        return self.result


class IncidentWriteBindingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "bindings.db")
        self.addCleanup(self.db.close)
        for asset in ("romi", "other"):
            self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                            (asset, asset, asset + '-read', asset + '-write', now(), now()))
        for iid, asset in (("inc-nginx", "romi"), ("inc-mysql", "romi"), ("inc-other", "other")):
            self.db.execute("INSERT INTO incidents(id,title,asset_id,object_id,status,generation,created_at,updated_at)"
                            " VALUES(?,?,?,'nginx','open',1,?,?)", (iid, iid, asset, now(), now()))
        self.duty = DutySessionManager(self.db)
        self.first = self.duty.create()["session_id"]
        self.second = self.duty.create()["session_id"]
        for sid in (self.first, self.second):
            self.db.execute("UPDATE duty_sessions SET remote_session_id=? WHERE id=?", ("rid-" + sid, sid))
            self.duty.set_runtime_state(sid, "idle")
        self.bridge = SessionBridge(self.db, duty=self.duty)
        self.ssh = FakeSSH()
        self.tools = OpsTools(OpsContext(transport=self.ssh, prom=None, incidents=None, knowledge=None,
                                        db=self.db, session_bridge=self.bridge, managed_context=True))

    async def execute(self, sid=None, **extra):
        sid = sid or self.first
        return await self.tools.call("host.exec", {"asset_id": "romi", "command": "systemctl start nginx", **extra},
                                     invocation_context={"sessionId": "rid-" + sid, "turnId": "turn", "actorId": "main"})

    def join(self, sid=None, iid="inc-nginx"):
        self.duty.join_incident(sid or self.first, iid)

    def advance_generation(self, iid="inc-nginx", *, refresh=True):
        self.db.execute("UPDATE incidents SET generation=generation+1 WHERE id=?", (iid,))
        if refresh:
            self.db.execute("UPDATE session_incidents SET generation=(SELECT generation FROM incidents WHERE id=?)"
                            " WHERE incident_id=?", (iid, iid))

    async def test_unique_participation_binds_real_incident_and_complete_audit_facts(self):
        self.join()
        result = await self.execute()
        self.assertEqual((result["incident_id"], result["generation"], result["scope"]), ("inc-nginx", 1, "incident"))
        row = self.db.query_one("SELECT * FROM session_write_ops")
        self.assertEqual((row["incident_id"], row["session_id"], row["status"]), ("inc-nginx", self.first, "done"))
        audit = self.db.query_one("SELECT * FROM audit_log WHERE entry='mcp_host_exec_write' ORDER BY id DESC LIMIT 1")
        facts = json.loads(audit["detail_json"])
        self.assertEqual((audit["incident_id"], audit["action_id"]), ("inc-nginx", row["action_key"]))
        self.assertEqual((facts["generation"], facts["session_id"], facts["ssh_account_group"]), (1, self.first, "ops"))
        self.assertEqual((facts["state"], facts["returncode"], facts["timed_out"], facts["ok"]), ("success", 0, False, True))
        self.assertEqual(self.db.query_one("SELECT status FROM incidents WHERE id='inc-nginx'")["status"], "open")
        self.assertTrue(self.db.query_one("SELECT 1 FROM audit_log WHERE entry='mcp_host_exec_write'"
                                         " AND json_extract(detail_json,'$.state')='claimed'"))

    async def test_same_incident_generation_and_command_share_key_across_sessions(self):
        self.join(); self.join(self.second)
        first = await self.execute()
        second = await self.execute(self.second)
        self.assertEqual(second["error"], "idempotent_block")
        self.assertTrue(second["detail"]["already_done"])
        self.assertEqual(first["action_key"], second["action_key"])
        self.assertEqual(len(self.ssh.calls), 1)

    async def test_new_generation_is_not_suppressed_by_old_done(self):
        self.join()
        first = await self.execute()
        self.advance_generation()
        second = await self.execute()
        self.assertEqual(second["exec_state"], "success")
        self.assertNotEqual(first["action_key"], second["action_key"])
        self.assertEqual(len(self.ssh.calls), 2)

    async def test_unknown_remains_guarded_in_same_session_after_generation_changes(self):
        self.join()
        self.ssh.result = NTResult(ok=False, output="connection lost", returncode=255)
        first = await self.execute()
        self.assertEqual(first["exec_state"], "unknown")
        self.advance_generation()
        result = await self.execute()
        self.assertEqual(result["error"], "idempotent_block")
        self.assertTrue(result["detail"]["unknown"])
        self.assertEqual(result["detail"]["action_key"], first["action_key"])
        self.assertEqual(len(self.ssh.calls), 1)

    async def test_unknown_remains_guarded_in_other_session_even_if_original_archived(self):
        self.join(); self.join(self.second)
        self.ssh.result = NTResult(ok=False, output="connection lost", returncode=255)
        await self.execute()
        self.advance_generation()
        self.db.execute("UPDATE duty_sessions SET status='archived' WHERE id=?", (self.first,))
        with self.assertRaises(McpToolError) as error:
            await self.execute(self.second)
        self.assertEqual(error.exception.code, "work_already_running")
        self.assertEqual(len(self.ssh.calls), 1)

    async def test_historical_session_scope_unknown_cannot_be_bypassed_by_binding_incident(self):
        self.bridge.claim_write("_session:" + self.first, "legacy-key", target="romi", authority_session_id=self.first)
        self.bridge.mark_unknown("_session:" + self.first, "legacy-key")
        self.join()
        result = await self.execute()
        self.assertTrue(result["detail"]["unknown"])
        self.assertEqual(result["detail"]["incident_id"], "_session:" + self.first)
        self.assertFalse(self.ssh.calls)
        read = await self.execute(channel="read", command="systemctl is-active nginx")
        self.assertTrue(read["ok"])
        self.assertEqual(len(self.ssh.calls), 1)

    async def test_legacy_unknown_without_session_owner_still_blocks_target(self):
        self.bridge.claim_write("_mcp_", "unbound-legacy", target="romi")
        self.bridge.mark_unknown("_mcp_", "unbound-legacy")
        self.join()
        result = await self.execute()
        self.assertTrue(result["detail"]["unknown"])
        self.assertEqual(result["detail"]["action_key"], "unbound-legacy")
        self.assertFalse(self.ssh.calls)

    async def test_expired_claim_remains_unknown_instead_of_replaying(self):
        self.bridge.claim_write("_session:" + self.first, "expired", target="romi", authority_session_id=self.first)
        self.db.execute("UPDATE session_write_ops SET lease_expires_at=1 WHERE action_key='expired'")
        self.join()
        result = await self.execute()
        self.assertTrue(result["detail"]["unknown"])
        self.assertFalse(result["detail"]["in_flight"])
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops WHERE action_key='expired'")["status"], "unknown")
        self.assertFalse(self.ssh.calls)

    async def test_multi_incident_scope_requires_explicit_choice(self):
        self.join(); self.join(iid="inc-mysql")
        with self.assertRaises(McpToolError) as error:
            await self.execute()
        self.assertEqual(error.exception.code, "incident_scope_required")
        self.assertEqual(error.exception.detail["candidate_incident_ids"], ["inc-mysql", "inc-nginx"])
        self.assertFalse(self.ssh.calls)
        result = await self.execute(incident_id="inc-nginx")
        self.assertEqual(result["incident_id"], "inc-nginx")

    async def test_unlinked_or_wrong_asset_incident_is_never_accepted(self):
        self.join(iid="inc-other")
        for iid, code in (("inc-nginx", "incident_session_mismatch"), ("inc-other", "incident_asset_mismatch")):
            with self.subTest(iid=iid), self.assertRaises(McpToolError) as error:
                await self.execute(incident_id=iid)
            self.assertEqual(error.exception.code, code)
        self.assertFalse(self.ssh.calls)

    async def test_stale_membership_never_degrades_to_unscoped_write(self):
        self.join()
        self.advance_generation(refresh=False)
        with self.assertRaises(McpToolError) as error:
            await self.execute()
        self.assertEqual(error.exception.code, "incident_generation_stale")
        self.assertFalse(self.ssh.calls)

    async def test_generation_changes_during_preparation_reject_before_actual_command(self):
        self.join()
        self.ssh.before_dispatch = self.advance_generation
        result = await self.execute()
        self.assertEqual(result["error"], "incident_generation_changed")
        self.assertFalse(self.ssh.calls)
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")["status"], "released")

    async def test_unassociated_manual_operation_keeps_session_scope(self):
        result = await self.execute()
        self.assertEqual((result["incident_id"], result["generation"], result["scope"]), ("", 0, "session"))
        self.assertEqual(self.db.query_one("SELECT incident_id FROM session_write_ops")["incident_id"], "_session:" + self.first)

    def close_historical_incident(self, status="resolved"):
        self.db.execute("UPDATE incidents SET status=?,generation=4 WHERE id='inc-nginx'", (status,))

    async def test_terminal_history_allows_independent_manual_commands_without_erasing_association(self):
        self.join()
        for status in ("resolved", "closed"):
            with self.subTest(status=status):
                self.close_historical_incident(status)
                result = await self.execute(command="systemctl restart task-" + status)
                self.assertEqual((result["scope"], result["incident_id"], result["generation"]), ("session", "", 0))
                self.assertEqual(result["exec_state"], "success")
                self.assertEqual(self.db.query_one("SELECT generation FROM session_incidents WHERE session_id=?",
                                                   (self.first,))["generation"], 1)
        self.assertEqual(len(self.ssh.calls), 2)
        self.assertEqual(self.db.query_one("SELECT count(*) AS n FROM session_write_ops WHERE incident_id=?",
                                           ("_session:" + self.first,))["n"], 2)
        last = self.db.query_one("SELECT incident_id,detail_json FROM audit_log WHERE entry='mcp_host_exec_write' ORDER BY id DESC LIMIT 1")
        self.assertEqual(last["incident_id"], "")
        self.assertEqual(json.loads(last["detail_json"])["generation"], 0)

    async def test_explicit_closed_incident_has_an_actionable_independent_manual_path(self):
        self.join(); self.close_historical_incident()
        with self.assertRaises(McpToolError) as error:
            await self.execute(incident_id="inc-nginx")
        self.assertEqual(error.exception.code, "incident_not_open")
        self.assertTrue(error.exception.detail["can_run_standalone"])
        self.assertEqual(error.exception.detail["next_action"], "omit_incident_id")
        self.assertFalse(self.ssh.calls)
        self.assertEqual(self.db.query_one("SELECT count(*) AS n FROM session_write_ops")["n"], 0)
        result = await self.execute()
        self.assertEqual(result["exec_state"], "success")
        self.assertEqual(result["scope"], "session")

    async def test_open_incident_is_bound_even_with_stale_terminal_history(self):
        self.join(); self.close_historical_incident(); self.join(iid="inc-mysql")
        result = await self.execute()
        self.assertEqual((result["incident_id"], result["generation"]), ("inc-mysql", 1))
        with self.assertRaises(McpToolError) as error:
            await self.execute(incident_id="inc-nginx", command="systemctl reload nginx")
        self.assertFalse(error.exception.detail["can_run_standalone"])
        self.assertEqual(error.exception.detail["next_action"], "select_open_incident")

    async def test_auto_session_with_terminal_incident_cannot_degrade_to_independent_write(self):
        self.db.execute("UPDATE duty_sessions SET origin='auto' WHERE id=?", (self.first,))
        self.join(); self.close_historical_incident()
        for args in ({}, {"incident_id": "inc-nginx"}):
            with self.subTest(args=args), self.assertRaises(McpToolError) as error:
                await self.execute(**args)
            self.assertEqual(error.exception.code, "incident_not_open")
            self.assertFalse(error.exception.detail["can_run_standalone"])
        self.assertFalse(self.ssh.calls)

    async def test_terminal_history_does_not_release_an_unknown_session_write(self):
        self.join(); self.close_historical_incident()
        scope = "_session:" + self.first
        self.bridge.claim_write(scope, "old-unknown", target="romi", authority_session_id=self.first)
        self.bridge.mark_unknown(scope, "old-unknown")
        result = await self.execute(command="systemctl reload nginx")
        self.assertEqual(result["error"], "idempotent_block")
        self.assertTrue(result["detail"]["unknown"])
        self.assertFalse(self.ssh.calls)

    async def test_terminal_history_does_not_bypass_unknown_in_archived_other_session(self):
        self.join(self.first); self.join(self.second); self.close_historical_incident()
        scope = "_session:" + self.first
        self.bridge.claim_write(scope, "old-unknown", target="romi", authority_session_id=self.first)
        self.bridge.mark_unknown(scope, "old-unknown")
        self.db.execute("UPDATE duty_sessions SET status='archived' WHERE id=?", (self.first,))
        with self.assertRaises(McpToolError) as error:
            await self.execute(self.second)
        self.assertEqual(error.exception.code, "work_already_running")
        self.assertFalse(self.ssh.calls)

    async def test_already_done_independent_command_remains_deduplicated_after_incident_closes(self):
        first = await self.execute()
        self.join(); self.close_historical_incident()
        repeated = await self.execute()
        self.assertEqual(repeated["error"], "idempotent_block")
        self.assertTrue(repeated["detail"]["already_done"])
        self.assertEqual(first["action_key"], repeated["action_key"])
        self.assertEqual(len(self.ssh.calls), 1)
        distinct = await self.execute(command="systemctl reload nginx")
        self.assertEqual(distinct["exec_state"], "success")
        self.assertEqual(len(self.ssh.calls), 2)

    async def test_incident_closing_during_ssh_preparation_refuses_the_old_incident_write(self):
        self.join()
        self.ssh.before_dispatch = self.close_historical_incident
        result = await self.execute()
        self.assertEqual(result["error"], "incident_not_open")
        self.assertFalse(self.ssh.calls)
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")["status"], "released")

    async def test_terminal_incident_reopening_during_preparation_refuses_independent_write(self):
        self.join(); self.close_historical_incident()
        self.ssh.before_dispatch = lambda: self.db.execute("UPDATE incidents SET status='open',generation=5 WHERE id='inc-nginx'")
        result = await self.execute()
        self.assertEqual(result["error"], "incident_generation_stale")
        self.assertFalse(self.ssh.calls)
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")["status"], "released")

    async def test_new_open_association_during_preparation_refuses_independent_write(self):
        self.join(); self.close_historical_incident()
        self.ssh.before_dispatch = lambda: self.join(iid="inc-mysql")
        result = await self.execute()
        self.assertEqual(result["error"], "incident_generation_changed")
        self.assertFalse(self.ssh.calls)
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")["status"], "released")

    async def test_released_retry_transfers_ledger_ownership_to_actual_session(self):
        self.join(); self.join(self.second)
        first = await self.execute()
        self.db.execute("UPDATE session_write_ops SET status='released'")
        second = await self.execute(self.second)
        self.assertEqual(second["exec_state"], "success")
        self.assertEqual(first["action_key"], second["action_key"])
        self.assertEqual(self.db.query_one("SELECT session_id FROM session_write_ops")["session_id"], self.second)

    async def test_loop_tool_uses_readonly_observation_not_retired_state_dispatch(self):
        loop = SimpleNamespace(observed_status=Mock(return_value={"status": "retired", "retired": True}), status=Mock())
        self.tools.ctx.ops_loop = loop
        result = await self.tools.ops_loop_status({"incident_id": "inc-nginx"})
        self.assertTrue(result["loop"]["retired"])
        loop.observed_status.assert_called_once_with("inc-nginx")
        loop.status.assert_not_called()


if __name__ == "__main__":
    unittest.main()
