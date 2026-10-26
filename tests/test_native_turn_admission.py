"""Native TUI/worker admission contracts; isolated DBs, no live model calls."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock

from ayana.auto_investigate import AutoInvestigator, InvestConfig
from ayana.db import Database, now
from ayana.duty_session import DutySessionManager, NativeTurnBusyError
from ayana.main import App
from ayana.session_bridge import SessionBridge
from ayana.web import WebApp


class NativeTurnAdmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "native.db")
        self.addCleanup(self.db.close)
        self.duty = DutySessionManager(self.db)
        self.sid = self.duty.create(origin="manual", created_by="admin")["session_id"]
        self.rid = "ses_native"
        self.db.execute("UPDATE duty_sessions SET remote_session_id=? WHERE id=?", (self.rid, self.sid))
        self.client = SimpleNamespace(
            session_status=AsyncMock(return_value={}),
            prompt_async=AsyncMock(return_value={"accepted": True, "receipt_id": "rcpt_one", "status": 202}),
            receipt=AsyncMock(return_value={"status": "completed"}),
        )
        self.serve = SimpleNamespace(ensure_running=AsyncMock(), client=lambda: self.client)
        self.bridge = SessionBridge(self.db, duty=self.duty, mimo=Mock())
        self.app = WebApp(self.db, Mock(), Mock(), Mock(), None, None, None,
                          static_dir=Path(self.tmp.name), duty=self.duty,
                          session_bridge=self.bridge, mimo_serve=self.serve)
        self.user = {"username": "admin", "is_admin": True, "csrf_token": "csrf"}
        self.app._require_auth = Mock(return_value=self.user)
        self.app._visible_asset_ids = Mock(return_value={"host"})
        self.owner = App.__new__(App)
        self.owner.db, self.owner.duty, self.owner.mimo_serve = self.db, self.duty, self.serve

    def request(self, body=None):
        return SimpleNamespace(
            match_info={"sid": self.sid}, method="POST",
            headers={"Host": "ayana.test", "Origin": "http://ayana.test", "X-CSRF-Token": "csrf"},
            json=AsyncMock(return_value=body if body is not None else {"prompt": "inspect"}),
            rel_url=SimpleNamespace(query={}),
        )

    def receipt(self, status="accepted"):
        self.duty.record_receipt(self.sid, self.rid, "rcpt_one", status=status, origin="test")
        self.duty.set_runtime_state(self.sid, "unknown" if status == "unknown" else "running",
                                    receipt_id="rcpt_one", receipt_status=status)

    async def test_unknown_receipt_blocks_new_owner_even_without_a_lease(self):
        self.receipt("unknown")
        with self.assertRaises(NativeTurnBusyError):
            with self.duty.turn(self.sid, timeout=0):
                self.fail("unknown native owner admitted another turn")
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 409)
        self.client.prompt_async.assert_not_awaited()

    async def test_unknown_without_receipt_cannot_be_cleared_by_idle_status(self):
        self.duty.set_runtime_state(self.sid, "unknown", receipt_status="unknown")
        await self.owner._reconcile_native_receipts_once()
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))
        self.client.receipt.assert_not_awaited()

    async def test_pending_receipt_rejects_manual_input_without_calling_model(self):
        self.receipt()
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 409)
        self.client.prompt_async.assert_not_awaited()

    async def test_untracked_native_busy_is_rejected(self):
        self.client.session_status.return_value = {self.rid: {"type": "busy"}}
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 409)
        self.client.prompt_async.assert_not_awaited()

    async def test_unavailable_native_status_never_admits_prompt(self):
        self.client.session_status.side_effect = RuntimeError("offline")
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 503)
        self.client.prompt_async.assert_not_awaited()

    async def test_accepted_manual_turn_persists_receipt_and_blocks_second_input(self):
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 202)
        receipt = self.db.query_one("SELECT * FROM agent_runtime_receipts WHERE receipt_id='rcpt_one'")
        self.assertEqual((receipt["session_id"], receipt["remote_session_id"], receipt["origin"]),
                         (self.sid, self.rid, "manual_api"))
        self.assertTrue(self.client.prompt_async.call_args.kwargs["message_id"].startswith("msg_"))
        self.assertEqual((await self.app.api_agent_session_prompt(self.request())).status, 409)
        self.client.prompt_async.assert_awaited_once()

    async def test_204_is_not_reported_as_an_accepted_task(self):
        self.client.prompt_async.return_value = {"accepted": False, "status": 204, "receipt_id": ""}
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 409)
        self.assertFalse(json.loads(response.body)["ok"])
        self.assertIsNone(self.db.query_one("SELECT 1 FROM agent_runtime_receipts"))

    async def test_ambiguous_submission_blocks_automatic_replay(self):
        self.client.prompt_async.side_effect = RuntimeError("connection reset after send")
        self.assertEqual((await self.app.api_agent_session_prompt(self.request())).status, 503)
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))
        self.assertEqual((await self.app.api_agent_session_prompt(self.request())).status, 409)
        self.client.prompt_async.assert_awaited_once()

    async def test_cancelled_http_request_records_uncertainty_before_releasing_lease(self):
        entered = asyncio.Event()
        async def pending(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()
        self.client.prompt_async.side_effect = pending
        task = asyncio.create_task(self.app.api_agent_session_prompt(self.request()))
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))
        self.assertIsNone(self.db.query_one("SELECT 1 FROM agent_session_turns WHERE session_id=?", (self.sid,)))

    async def test_parallel_http_submissions_have_one_native_owner(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def status():
            entered.set()
            await release.wait()
            return {}
        self.client.session_status.side_effect = status
        first = asyncio.create_task(self.app.api_agent_session_prompt(self.request()))
        await asyncio.wait_for(entered.wait(), 2)
        second = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(second.status, 409)
        release.set()
        self.assertEqual((await first).status, 202)
        self.client.prompt_async.assert_awaited_once()

    async def test_observer_attaches_without_waiting_for_running_worker_lease(self):
        self.receipt()
        self.db.execute("INSERT INTO agent_session_turns(session_id,owner,expires_at,updated_at) VALUES(?,?,?,?)",
                        (self.sid, "worker", now() + 300, now()))
        result = await asyncio.wait_for(self.app._agent_remote_ready(self.sid), 0.5)
        self.assertEqual(result["remote_session_id"], self.rid)
        self.client.prompt_async.assert_not_awaited()

    async def test_same_owner_nested_worker_continuation_keeps_context(self):
        async with self.duty.async_turn(self.sid):
            self.receipt()
            def nested():
                with self.duty.turn(self.sid, timeout=0):
                    return True
            self.assertTrue(await asyncio.to_thread(nested))
        self.assertIn("native_turn_pending", self.duty.native_admission_blockers(self.sid))

    async def test_long_turn_renews_lease_instead_of_allowing_another_owner(self):
        async with self.duty.async_turn(self.sid, lease_sec=1):
            await asyncio.sleep(1.15)
            row = self.db.query_one("SELECT expires_at FROM agent_session_turns WHERE session_id=?", (self.sid,))
            self.assertGreater(row["expires_at"], now())
            foreign = Database(self.db.path)
            try:
                with self.assertRaises(TimeoutError):
                    DutySessionManager(foreign)._acquire_turn(self.sid, "other", 0, 1)
            finally:
                foreign.close()

    async def test_unknown_known_receipt_is_reconciled_without_resubmitting(self):
        self.receipt("unknown")
        await self.owner._reconcile_native_receipts_once()
        self.assertEqual(self.duty.native_admission_blockers(self.sid), [])
        self.assertEqual(self.db.query_one("SELECT state FROM agent_runtime_bindings WHERE session_id=?", (self.sid,))["state"], "idle")
        self.client.receipt.assert_awaited_once_with(self.rid, "rcpt_one")
        self.client.prompt_async.assert_not_awaited()

    async def test_terminal_receipt_cannot_clear_busy_native_owner(self):
        self.receipt("unknown")
        self.client.session_status.return_value = {self.rid: {"type": "busy"}}
        await self.owner._reconcile_native_receipts_once()
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))
        self.client.session_status.return_value = {}
        await self.owner._reconcile_native_receipts_once()
        self.assertEqual(self.duty.native_admission_blockers(self.sid), [])

    async def test_missing_receipt_remains_unknown_instead_of_replaying(self):
        self.receipt()
        self.client.receipt.side_effect = RuntimeError("receipt not found")
        await self.owner._reconcile_native_receipts_once()
        self.assertEqual(self.db.query_one("SELECT status FROM agent_runtime_receipts")["status"], "unknown")
        self.assertIn("native_turn_pending", self.duty.native_admission_blockers(self.sid))
        self.client.prompt_async.assert_not_awaited()

    def add_running_business_job(self):
        self.db.execute("INSERT INTO incidents(id,title,status,generation,created_at,updated_at) VALUES('i','i','open',1,?,?)", (now(), now()))
        self.duty.join_incident(self.sid, "i")
        self.db.execute("INSERT INTO investigation_jobs(incident_id,generation,status,phase,lease_expires_at,created_at,updated_at) VALUES('i',1,'running','decision',0,?,?)", (now(), now()))

    async def test_action_or_verification_phase_blocks_manual_input_after_lease_expiry(self):
        self.add_running_business_job()
        self.assertEqual((await self.app.api_agent_session_prompt(self.request())).status, 409)
        self.client.prompt_async.assert_not_awaited()

    async def test_recovery_does_not_replay_readonly_decision_with_unresolved_native_owner(self):
        self.add_running_business_job()
        self.receipt("unknown")
        worker = AutoInvestigator(self.db, config=InvestConfig(enabled=True, closed_loop=True), bridge=self.bridge, ops_loop=Mock())
        result = worker.recover()
        self.assertEqual(result["resumed_readonly_decisions"], 0)
        self.assertEqual(self.db.query_one("SELECT phase FROM investigation_jobs")["phase"], "interrupted")

    async def test_approval_setting_rejects_ambiguous_values_without_mutating_other_fields(self):
        response = await self.app.api_agent_settings_post(self.request({"archive_delay_sec": 60, "require_human_approval": None}))
        self.assertEqual(response.status, 400)
        self.assertTrue(self.duty.require_human_approval())
        self.assertEqual(self.duty.archive_delay_sec(), 300)

    async def test_detail_exposes_native_permissions_without_starting_a_task(self):
        payload = json.loads((await self.app.api_agent_session_detail(self.request())).body)
        self.assertTrue(payload["can_control"])
        self.assertTrue(payload["can_prepare"])
        self.client.prompt_async.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
