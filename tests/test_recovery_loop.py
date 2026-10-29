"""Recovery callbacks must preserve loop terminal state and execution budgets."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ayana.actions import ActionError
from ayana.db import Database, MigrationError, SCHEMA_VERSION, now
from ayana.incidents import IncidentService
from ayana.ops_loop import (
    MAX_EXECUTE_ROUNDS, MAX_PREFLIGHT_BLOCKS, OpsLoop, close_recovered, ensure_ops_loop_schema,
)


class PreflightMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = Path(self.tmp.name) / "legacy.db"
        self.db = Database(self.path)
        self.db.execute(
            "INSERT INTO ops_loop_state(incident_id,generation,rounds,no_progress_rounds,"
            " same_plan_failures,last_plan_sig,status,stop_reason,last_result,updated_at)"
            " VALUES('legacy',4,6,1,1,'restart','need_human','verify_unknown','unknown',123)")
        self.db.execute("ALTER TABLE ops_loop_state DROP COLUMN preflight_blocks")
        self.db.execute("ALTER TABLE ops_loop_state DROP COLUMN preflight_at")
        self.db.execute("UPDATE meta SET value='27' WHERE key='schema_version'")
        self.db.execute("DELETE FROM schema_migrations WHERE version=28")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_v27_upgrade_preserves_loop_budget_and_is_idempotent(self):
        before = dict(self.db.query_one("SELECT * FROM ops_loop_state WHERE incident_id='legacy'"))
        self.db.close()
        self.db = Database(self.path)
        self.assertEqual(self.db.schema_version(), SCHEMA_VERSION)
        upgraded = dict(self.db.query_one("SELECT * FROM ops_loop_state WHERE incident_id='legacy'"))
        self.assertEqual({key: upgraded[key] for key in before}, before)
        self.assertEqual((upgraded["preflight_blocks"], upgraded["preflight_at"]), (0, 0))
        self.db.execute("UPDATE ops_loop_state SET preflight_blocks=2,preflight_at=456 WHERE incident_id='legacy'")
        ensure_ops_loop_schema(self.db)
        ensure_ops_loop_schema(self.db)
        self.db.close()
        self.db = Database(self.path)
        current = self.db.query_one("SELECT * FROM ops_loop_state WHERE incident_id='legacy'")
        self.assertEqual((current["preflight_blocks"], current["preflight_at"]), (2, 456))
        self.assertEqual((current["status"], current["stop_reason"], current["rounds"]),
                         ("need_human", "verify_unknown", 6))

    def test_failed_upgrade_does_not_advance_schema_version(self):
        conn = self.db._connect()
        conn.set_authorizer(lambda operation, *args:
                            sqlite3.SQLITE_DENY if operation == sqlite3.SQLITE_ALTER_TABLE
                            else sqlite3.SQLITE_OK)
        try:
            with self.assertRaises(MigrationError):
                self.db._run_migrations(conn)
            self.assertEqual(self.db.schema_version(), 27)
            self.assertIsNone(self.db.query_one("SELECT 1 FROM schema_migrations WHERE version=28"))
            with self.assertRaises(sqlite3.DatabaseError):
                ensure_ops_loop_schema(self.db)
        finally:
            conn.set_authorizer(None)


class RecoveryLoopTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "loop.db")
        self.db.execute(
            "INSERT INTO incidents(id,title,status,stage,generation,created_at,updated_at)"
            " VALUES('inc1','down','open','investigating',1,?,?)", (now(), now()))
        self.loop = OpsLoop(self.db, incidents=IncidentService(self.db))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    async def test_run_action_and_verify_is_retired(self):
        # 旧结构化动作执行已退役：MiMoCode 通过 host.exec 自行处置
        res = await self.loop.run_action_and_verify(
            incident_id="inc1", asset_id="host", object_id="nginx",
            capability="service.start", plan_sig="start-nginx")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "action_service_retired")

    def test_late_progress_does_not_reset_new_generation_state(self):
        self.loop.note_round("inc1", progressed=False, plan_sig="p", write_ok=False)
        self.db.execute("UPDATE incidents SET generation=2 WHERE id='inc1'")
        self.loop.record_action_progress("inc1", plan_sig="p", generation=1)
        state = self.db.query_one("SELECT * FROM ops_loop_state WHERE incident_id='inc1'")
        self.assertEqual(state["generation"], 1)
        self.assertEqual(state["same_plan_failures"], 1)
        self.assertEqual(state["rounds"], 1)

    def test_action_success_preserves_manual_stop(self):
        self.loop.escalate("inc1", reason="verify_unknown")
        self.loop.record_action_progress("inc1", plan_sig="p", generation=1)
        self.loop.note_round("inc1", progressed=True, plan_sig="p", write_ok=True)
        state = self.loop.status("inc1")
        self.assertEqual((state["status"], state["stop_reason"]),
                         ("need_human", "verify_unknown"))
        self.assertEqual(state["rounds"], 0)

    def test_preflight_dispatch_failure_uses_only_its_own_budget(self):
        for count in range(1, MAX_PREFLIGHT_BLOCKS + 1):
            self.db.execute("UPDATE ops_loop_state SET preflight_at=0 WHERE incident_id='inc1'")
            self.loop.note_preflight_block("inc1", plan_sig="p", code="target_not_found")
            state = self.loop.status("inc1")
            self.assertEqual(state["preflight_blocks"], count)
            self.assertEqual(state["rounds"], 0)
            self.assertEqual(state["same_plan_failures"], 0)
            self.assertEqual(state["no_progress_rounds"], 0)
        self.assertEqual(state["status"], "need_human")
        self.assertEqual(state["stop_reason"], "preflight_blocked:target_not_found")

    def test_maybe_close_does_not_claim_stale_loop_was_closed(self):
        self.db.execute("INSERT INTO ops_loop_state(incident_id,generation,status,updated_at) VALUES('inc1',1,'idle',1)")
        self.db.execute("UPDATE incidents SET generation=2 WHERE id='inc1'")
        self.loop.incidents = SimpleNamespace(
            reconcile=lambda incident_id: {"outcome": "recovered", "generation": 1})
        self.assertFalse(self.loop.maybe_close("inc1")["closed"])
        state = self.db.query_one("SELECT status FROM ops_loop_state WHERE incident_id='inc1'")
        self.assertEqual(state["status"], "idle")
