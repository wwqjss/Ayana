"""Native duty/runtime safety contracts; isolated files and zero model calls."""
from __future__ import annotations
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

from ayana.auto_investigate import AutoInvestigator, InvestConfig
from ayana.db import Database, SCHEMA_VERSION, now
from ayana.duty_session import DutySessionManager
from ayana.ops_loop import OpsLoop
from ayana.session_bridge import SessionBridge


def incident(db, ident="i", status="open", generation=1):
    db.execute("INSERT INTO incidents(id,title,status,generation,created_at,updated_at) VALUES(?,?,?,?,?,?)",(ident,ident,status,generation,now(),now()))


class DutySafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"test.db"
        self.db=Database(self.path);self.addCleanup(self.db.close)
        incident(self.db)
        self.duty=DutySessionManager(self.db)
        self.bridge=SessionBridge(self.db,duty=self.duty)

    def auto(self):return self.bridge.ensure_session("i")["session_id"]

    def closed(self):
        sid=self.auto();self.db.execute("UPDATE incidents SET status='closed'");return sid

    def test_migration_preserves_duplicate_auto_history_without_archiving_running_context(self):
        self.db.execute("DROP INDEX idx_one_open_auto_session")
        older=self.duty.create(origin="auto",title="older")["session_id"]
        newer=self.duty.create(origin="auto",title="newer")["session_id"]
        self.db.execute("UPDATE duty_sessions SET created_at=100 WHERE id=?",(older,))
        self.db.execute("UPDATE duty_sessions SET created_at=200 WHERE id=?",(newer,))
        self.duty.join_incident(older,"i")
        self.duty.add_message(older,body="retained")
        self.db.execute("UPDATE duty_sessions SET remote_session_id='ses_older' WHERE id=?",(older,))
        self.db.execute("UPDATE meta SET value='22' WHERE key='schema_version'")
        self.db.close();upgraded=Database(self.path)
        try:
            self.assertEqual(upgraded.schema_version(),SCHEMA_VERSION)
            rows=[dict(row) for row in upgraded.query("SELECT * FROM duty_sessions")]
            self.assertEqual(len(rows),2)
            self.assertEqual(sum(row["origin"]=="auto" and row["status"]=="open" for row in rows),1)
            old=upgraded.query_one("SELECT * FROM duty_sessions WHERE id=?",(older,))
            self.assertEqual((old["origin"],old["status"],old["remote_session_id"]),("legacy_auto","open","ses_older"))
            self.assertEqual(upgraded.query_one("SELECT COUNT(*) n FROM session_messages WHERE session_id=?",(older,))["n"],1)
            self.assertEqual(upgraded.query_one("SELECT COUNT(*) n FROM session_incidents WHERE session_id=?",(older,))["n"],1)
        finally:upgraded.close()

    def test_auto_creation_converges_across_database_instances(self):
        barrier=threading.Barrier(2)
        def create(_):
            db=Database(self.path)
            try:
                barrier.wait(2)
                result=DutySessionManager(db).ensure_auto_session()
                return result.get("session_id") or result["id"]
            finally:db.close()
        with ThreadPoolExecutor(2) as pool:ids=list(pool.map(create,range(2)))
        self.assertEqual(ids[0],ids[1])
        self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM duty_sessions WHERE origin='auto' AND status='open'")["n"],1)

    def test_generation_link_updates_without_duplicate_or_lost_join_time(self):
        sid=self.auto();joined=self.duty.incidents(sid)[0]["joined_at"]
        self.duty.join_incident(sid,"i",generation=2)
        links=self.duty.incidents(sid)
        self.assertEqual(len(links),1);self.assertEqual(links[0]["generation"],2);self.assertEqual(links[0]["joined_at"],joined)

    def test_countdown_is_idempotent_and_new_incident_cancels_it(self):
        sid=self.closed()
        with patch("ayana.duty_session.now",return_value=1000):first=self.duty.maybe_start_archive_countdown(sid)
        with patch("ayana.duty_session.now",return_value=1100):second=self.duty.maybe_start_archive_countdown(sid)
        self.assertEqual(first["archive_due_at"],1300);self.assertEqual(second["archive_due_at"],1300)
        incident(self.db,"new")
        self.duty.join_incident(sid,"new")
        self.assertEqual(self.duty.get(sid)["archive_due_at"],0)

    def test_archive_rechecks_current_incident_state_at_deadline(self):
        sid=self.closed();self.duty.maybe_start_archive_countdown(sid)
        self.db.execute("UPDATE duty_sessions SET archive_due_at=? WHERE id=?",(now()-1,sid))
        self.db.execute("UPDATE incidents SET status='open'")
        self.assertEqual(self.duty.tick_archives()["archived"],[])
        self.assertEqual(self.duty.get(sid)["status"],"open")
        self.assertEqual(self.duty.get(sid)["archive_due_at"],0)

    def test_unknown_or_approval_obligations_block_automatic_and_manual_archive(self):
        sid=self.closed()
        self.db.execute("INSERT INTO actions(id,incident_id,asset_id,capability,state,created_at) VALUES('a','i','host','service.restart','unknown',?)",(now(),))
        self.assertIn("actions",self.duty.archive_blockers(sid))
        self.assertEqual(self.duty.maybe_start_archive_countdown(sid)["action"],"keep_open")
        self.assertEqual(self.duty.archive_session(sid)["error"],"session_busy")
        self.db.execute("UPDATE actions SET state='proposed'")
        self.assertEqual(self.duty.archive_session(sid)["error"],"session_busy")

    def test_queued_job_and_running_receipt_block_archive(self):
        sid=self.closed()
        self.db.execute("INSERT INTO investigation_jobs(incident_id,status) VALUES('i','queued')")
        self.assertIn("pending_jobs",self.duty.archive_blockers(sid))
        self.db.execute("UPDATE investigation_jobs SET status='done'")
        self.duty.set_runtime_state(sid,"busy",receipt_id="receipt1",receipt_status="running")
        self.assertIn("runtime_busy",self.duty.archive_blockers(sid))
        self.duty.set_runtime_state(sid,"idle",receipt_id="receipt1",receipt_status="completed")
        self.assertEqual(self.duty.archive_blockers(sid),[])

    def test_manual_reopen_keeps_native_history_and_does_not_take_auto_slot(self):
        sid=self.closed();self.db.execute("UPDATE duty_sessions SET remote_session_id='ses_history' WHERE id=?",(sid,))
        self.assertTrue(self.duty.archive_session(sid)["ok"])
        auto=self.duty.ensure_auto_session()["session_id"]
        self.assertTrue(self.duty.reopen_session(sid,actor="admin")["ok"])
        row=self.duty.get(sid)
        self.assertEqual((row["origin"],row["status"],row["remote_session_id"]),("manual","open","ses_history"))
        self.assertEqual(self.duty.open_auto_session()["id"],auto)
        self.assertEqual(self.duty.maybe_start_archive_countdown(sid)["action"],"noop")

    def test_pending_approval_has_exactly_one_claim_across_database_connections(self):
        self.auto();key=self.bridge.make_action_key("host","exec_shell",{"command":"service restart"})
        self.bridge.pending_write("i",key,target="host",params={"command":"service restart"})
        barrier=threading.Barrier(2)
        def claim(_):
            db=Database(self.path)
            try:
                bridge=SessionBridge(db);barrier.wait(2)
                return bridge.approve_pending_write("i",key,approved_by="admin")
            finally:db.close()
        with ThreadPoolExecutor(2) as pool:results=list(pool.map(claim,range(2)))
        self.assertEqual(sum(result.get("claimed") is True for result in results),1)
        self.assertEqual(sum(result.get("ok") is True for result in results),1)

    def test_same_session_turns_serialize_but_manual_sessions_can_run_concurrently(self):
        a=self.duty.create(origin="manual")["session_id"];b=self.duty.create(origin="manual")["session_id"]
        guard=threading.Lock();active=0;maximum=0
        def turn(sid):
            nonlocal active,maximum
            db=Database(self.path)
            try:
                with DutySessionManager(db).turn(sid,timeout=2):
                    with guard:active+=1;maximum=max(active,maximum)
                    time.sleep(0.04)
                    with guard:active-=1
            finally:db.close()
        with ThreadPoolExecutor(2) as pool:list(pool.map(turn,[a,a]))
        self.assertEqual(maximum,1)
        active=maximum=0;entered=threading.Barrier(2)
        def parallel(sid):
            db=Database(self.path)
            try:
                with DutySessionManager(db).turn(sid,timeout=2):entered.wait(2)
            finally:db.close()
        with ThreadPoolExecutor(2) as pool:list(pool.map(parallel,[a,b]))

    def test_allocate_persists_remote_id_before_waiting_for_model(self):
        sid=self.auto();observed=[]
        class Client:
            model="test"
            def allocate(inner,**kwargs):return type("R",(),{"remote_session_id":"ses_allocated","model":"test"})()
            def resume(inner,rid,prompt,**kwargs):
                observed.append(self.duty.get(sid)["remote_session_id"])
                return type("R",(),{"remote_session_id":rid,"status":"active","text":"done","model":"test"})()
        self.bridge.mimo=Client()
        result=self.bridge.attach_remote(session_id=sid,prompt="inspect")
        self.assertTrue(result["ok"]);self.assertEqual(observed,["ses_allocated"])

    def test_ops_loop_recurrence_query_preserves_retired_history(self):
        loop=OpsLoop(self.db)
        self.db.execute("INSERT INTO ops_loop_state(incident_id,generation,status,rounds,updated_at) VALUES('i',1,'done',8,1)")
        self.db.execute("UPDATE incidents SET generation=2")
        state=loop.status("i")
        self.assertEqual((state["generation"],state["rounds"],state["status"]),(1,8,"done"))
        observed=loop.observed_status("i")
        self.assertEqual(observed["incident"]["generation"],2)
        self.assertFalse(observed["legacy_loop"]["same_generation"])
        self.assertFalse(observed["legacy_loop"]["active"])
        self.assertIsNone(self.db.query_one("SELECT 1 FROM events WHERE type='ops_loop_generation_reset'"))


class PhaseSafetyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(ignore_cleanup_errors=True);self.addCleanup(self.tmp.cleanup)
        self.db=Database(Path(self.tmp.name)/"phase.db");self.addCleanup(self.db.close)
        incident(self.db)
        self.ai=AutoInvestigator(self.db,config=InvestConfig(enabled=True,closed_loop=True),ops_loop=Mock())
        self.ai.offer("i")
        self.db.execute("UPDATE investigation_jobs SET status='running',lease_expires_at=0 WHERE incident_id='i'")

    async def test_conclusion_finishes_job_without_second_phase(self):
        # core-008：单会话调查完成后直接收尾，不再进入决策阶段
        self.ai._investigate=AsyncMock(return_value={"status":"completed","facts":[]})
        await self.ai._run_job("i",self.ai._row("i"))
        self.assertEqual((self.ai._row("i")["status"],self.ai._row("i")["phase"]),("done","complete"))

    async def test_interrupted_execution_never_replays_and_escalates(self):
        self.db.execute("UPDATE investigation_jobs SET phase='execution'")
        self.ai.recover()
        row=self.ai._row("i")
        self.assertEqual((row["status"],row["phase"]),("failed","interrupted"))
        self.ai.ops_loop.escalate.assert_called_once()

    async def test_periodic_recovery_handles_lease_expiring_after_startup(self):
        self.db.execute("UPDATE investigation_jobs SET lease_expires_at=?",(now()+60,))
        self.ai.recover();self.assertEqual(self.ai._row("i")["status"],"running")
        self.db.execute("UPDATE investigation_jobs SET lease_expires_at=0")
        self.ai.readiness_callback=lambda:False
        await self.ai.tick_once()
        self.assertEqual(self.ai._row("i")["status"],"failed")


if __name__=="__main__":unittest.main()
