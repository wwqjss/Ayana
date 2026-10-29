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
from ayana.agent_tui import AgentTuiManager
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
        self.native_statuses = {}
        self.receipt_serial = 0
        async def native_status(session_id=None):
            return (self.native_statuses.get(session_id, {"type": "idle"})
                    if session_id else dict(self.native_statuses))
        async def native_request(method, path, **kwargs):
            self.assertEqual(method, "POST")
            self.assertEqual(path, "/session/" + self.rid + "/prompt_async")
            self.assertTrue(kwargs["include_status"])
            self.receipt_serial += 1
            return {"status": 202, "data": {"receiptId": "rcpt_one" if self.receipt_serial == 1 else "rcpt_" + str(self.receipt_serial)}}
        self.client = SimpleNamespace(
            base_url="http://127.0.0.1:9", _admit=Mock(),
            session_status=AsyncMock(side_effect=native_status),
            _request=AsyncMock(side_effect=native_request), messages=AsyncMock(return_value=[]),
            prompt_async=AsyncMock(return_value={"accepted": True, "receipt_id": "rcpt_one", "status": 202}),
            receipt=AsyncMock(return_value={"status": "completed"}),
        )
        self.serve = SimpleNamespace(ensure_running=AsyncMock(), client=lambda: self.client)
        self.bridge = SessionBridge(self.db, duty=self.duty, mimo=Mock())
        self.duty.set_runtime_state(self.sid, "idle")
        self.manager = AgentTuiManager(self.db, lambda: self.client,
            runtime_resolver=lambda: {"managed_context": True, "model": "verified/model"}, state_dir=self.tmp.name)
        # Model/PTY processes are outside this isolated admission fixture.
        # Keep the actual manager, DB state, connection and lease implementation.
        self.manager._pane = AsyncMock(return_value=None)
        self.manager._connections["test_connection"] = {"session_id": self.sid, "username": "admin"}
        self.manager.acquire_control(self.sid, "admin", "test_connection")
        self.app = WebApp(self.db, Mock(), Mock(), Mock(), None, None, None,
                          static_dir=Path(self.tmp.name), duty=self.duty,
                          session_bridge=self.bridge, mimo_serve=self.serve, agent_tui=self.manager)
        self.user = {"username": "admin", "is_admin": True, "csrf_token": "csrf"}
        self.app._require_auth = Mock(return_value=self.user)
        self.app._visible_asset_ids = Mock(return_value={"host"})
        self.owner = App.__new__(App)
        self.owner.db, self.owner.duty, self.owner.mimo_serve = self.db, self.duty, self.serve
        self.owner.agent_tui = self.manager

    def request(self, body=None):
        return SimpleNamespace(
            match_info={"sid": self.sid}, method="POST",
            headers={"Host": "ayana.test", "Origin": "http://ayana.test", "X-CSRF-Token": "csrf"},
            json=AsyncMock(return_value=body if body is not None else {"prompt": "inspect", "connection_id": "test_connection"}),
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
        self.client._request.assert_not_awaited()

    async def test_observer_without_live_control_cannot_submit_guidance(self):
        self.manager.release_control(self.sid, "admin", "test_connection")
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 409)
        self.assertEqual(json.loads(response.body)["error"], "control_required")
        self.client._request.assert_not_awaited()

    async def test_another_window_connection_cannot_submit(self):
        response = await self.app.api_agent_session_prompt(self.request({"prompt": "inspect", "connection_id": "other_window"}))
        self.assertEqual(response.status, 409)
        self.client._request.assert_not_awaited()

    async def test_control_revoked_during_status_await_is_rechecked_before_dispatch(self):
        async def status(session_id=None):
            self.manager.release_control(self.sid, "admin", "test_connection")
            return {"type": "idle"} if session_id else {}
        self.client.session_status.side_effect = status
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 409)
        self.client._request.assert_not_awaited()

    async def test_unknown_without_receipt_cannot_be_cleared_by_idle_status(self):
        self.duty.set_runtime_state(self.sid, "unknown", receipt_status="unknown")
        await self.owner._reconcile_native_receipts_once()
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))
        self.client.receipt.assert_not_awaited()

    async def test_known_running_receipt_accepts_controlled_guidance_in_same_native_queue(self):
        self.receipt()
        self.native_statuses[self.rid] = {"type": "busy"}
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 202)
        self.client._request.assert_awaited_once()
        call = self.client._request.await_args
        self.assertEqual(call.args, ("POST", "/session/" + self.rid + "/prompt_async"))
        self.assertEqual(call.kwargs["body"]["parts"], [{"type": "text", "text": "inspect"}])
        ack = json.loads(self.db.query_one("SELECT payload_json FROM session_events WHERE type='input_ack' ORDER BY id DESC LIMIT 1")[0])
        self.assertEqual((ack["state"], ack["queued"]), ("queued", True))
        self.client.prompt_async.assert_not_awaited()

    async def test_same_bound_native_busy_can_queue_without_replaying_or_aborting_it(self):
        self.native_statuses[self.rid] = {"type": "busy"}
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 202)
        self.client._request.assert_awaited_once()
        self.assertEqual(self.db.query_one("SELECT status FROM agent_runtime_receipts WHERE receipt_id='rcpt_one'")[0], "queued")
        self.assertEqual(self.client._request.await_args.args[1], "/session/" + self.rid + "/prompt_async")

    async def test_unavailable_native_status_never_admits_prompt(self):
        self.client.session_status.side_effect = RuntimeError("offline")
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 503)
        self.client.prompt_async.assert_not_awaited()
        self.client._request.assert_not_awaited()

    async def test_each_accepted_manual_input_has_own_receipt_and_same_native_context(self):
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 202)
        receipt = self.db.query_one("SELECT * FROM agent_runtime_receipts WHERE receipt_id='rcpt_one'")
        self.assertEqual((receipt["session_id"], receipt["remote_session_id"], receipt["origin"]),
                         (self.sid, self.rid, "manual_api"))
        first_body = self.client._request.await_args.kwargs["body"]
        self.assertTrue(first_body["messageID"].startswith("msg_"))
        self.assertEqual(first_body["agent"], "ayana")
        self.native_statuses[self.rid] = {"type": "busy"}
        self.assertEqual((await self.app.api_agent_session_prompt(self.request())).status, 202)
        self.assertEqual(self.client._request.await_count, 2)
        rows = self.db.query("SELECT receipt_id,remote_session_id,status FROM agent_runtime_receipts ORDER BY created_at")
        self.assertEqual([(r["receipt_id"],r["remote_session_id"],r["status"]) for r in rows], [("rcpt_one",self.rid,"accepted"),("rcpt_2",self.rid,"queued")])
        second_body = self.client._request.await_args.kwargs["body"]
        self.assertNotEqual(first_body["messageID"], second_body["messageID"])
        self.client.prompt_async.assert_not_awaited()

    async def test_204_is_not_reported_as_an_accepted_task(self):
        self.client._request.side_effect = None
        self.client._request.return_value = {"status": 204, "data": None}
        response = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(response.status, 409)
        self.assertFalse(json.loads(response.body)["ok"])
        self.assertIsNone(self.db.query_one("SELECT 1 FROM agent_runtime_receipts"))
        self.assertEqual(self.db.query_one("SELECT state FROM agent_native_submissions")[0], "failed")

    async def test_ambiguous_submission_blocks_automatic_replay(self):
        self.client._request.side_effect = RuntimeError("connection reset after send")
        self.assertEqual((await self.app.api_agent_session_prompt(self.request())).status, 503)
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))
        self.assertEqual((await self.app.api_agent_session_prompt(self.request())).status, 409)
        self.client._request.assert_awaited_once()
        self.assertEqual(self.db.query_one("SELECT state FROM agent_native_submissions")[0], "unknown")

    async def test_cancelled_http_request_records_uncertainty_before_releasing_lease(self):
        entered = asyncio.Event()
        async def pending(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()
        self.client._request.side_effect = pending
        task = asyncio.create_task(self.app.api_agent_session_prompt(self.request()))
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))
        self.assertIsNone(self.db.query_one("SELECT 1 FROM agent_session_turns WHERE session_id=?", (self.sid,)))
        self.client._request.assert_awaited_once()
        self.assertEqual(self.db.query_one("SELECT state FROM agent_native_submissions")[0], "unknown")

    async def test_parallel_http_submissions_have_one_native_owner(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def submit(*args, **kwargs):
            entered.set()
            await release.wait()
            return {"status": 202, "data": {"receiptId": "rcpt_one"}}
        self.client._request.side_effect = submit
        first = asyncio.create_task(self.app.api_agent_session_prompt(self.request()))
        await asyncio.wait_for(entered.wait(), 2)
        second = await self.app.api_agent_session_prompt(self.request())
        self.assertEqual(second.status, 409)
        release.set()
        self.assertEqual((await first).status, 202)
        self.client._request.assert_awaited_once()
        self.assertEqual(self.client._request.await_args.args, ("POST", "/session/" + self.rid + "/prompt_async"))
        self.assertEqual(self.db.query_one("SELECT count(*) FROM agent_native_submissions")[0], 1)

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
        self.native_statuses[self.rid] = {"type": "busy"}
        await self.owner._reconcile_native_receipts_once()
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))
        self.native_statuses.clear()
        await self.owner._reconcile_native_receipts_once()
        self.assertEqual(self.duty.native_admission_blockers(self.sid), [])

    async def test_missing_receipt_remains_unknown_instead_of_replaying(self):
        self.receipt()
        self.client.receipt.side_effect = RuntimeError("receipt not found")
        await self.owner._reconcile_native_receipts_once()
        self.assertEqual(self.db.query_one("SELECT status FROM agent_runtime_receipts")["status"], "unknown")
        self.assertIn("native_turn_unknown", self.duty.native_admission_blockers(self.sid))
        self.client.prompt_async.assert_not_awaited()

    def add_running_business_job(self):
        self.db.execute("UPDATE duty_sessions SET origin='auto' WHERE id=?", (self.sid,))
        self.db.execute("INSERT INTO incidents(id,title,status,generation,created_at,updated_at) VALUES('i','i','open',1,?,?)", (now(), now()))
        self.duty.join_incident(self.sid, "i")
        self.db.execute("INSERT INTO investigation_jobs(incident_id,generation,status,phase,lease_expires_at,created_at,updated_at) VALUES('i',1,'running','execution',0,?,?)", (now(), now()))

    async def test_action_or_verification_phase_blocks_manual_input_after_lease_expiry(self):
        self.add_running_business_job()
        self.assertEqual((await self.app.api_agent_session_prompt(self.request())).status, 409)
        self.client.prompt_async.assert_not_awaited()
        self.client._request.assert_not_awaited()

    async def test_recovery_does_not_replay_readonly_decision_with_unresolved_native_owner(self):
        self.add_running_business_job()
        self.receipt("unknown")
        worker = AutoInvestigator(self.db, config=InvestConfig(enabled=True, closed_loop=True), bridge=self.bridge, ops_loop=Mock())
        result = worker.recover()
        self.assertEqual(result["resumed_readonly_decisions"], 0)
        self.assertEqual(self.db.query_one("SELECT phase FROM investigation_jobs")["phase"], "interrupted")

    async def test_ssh_group_setting_rejects_ambiguous_values_without_mutating_other_fields(self):
        # Preserve atomic settings validation using the current SSH-group field.
        response = await self.app.api_agent_settings_post(self.request({"archive_delay_sec": 60, "ssh_default_group": None}))
        self.assertEqual(response.status, 400)
        self.assertEqual(self.duty.settings()["ssh_default_group"], "default")
        self.assertEqual(self.duty.archive_delay_sec(), 300)

    async def test_detail_exposes_native_permissions_without_starting_a_task(self):
        payload = json.loads((await self.app.api_agent_session_detail(self.request())).body)
        self.assertTrue(payload["can_control"])
        self.assertTrue(payload["can_prepare"])
        self.client.prompt_async.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
