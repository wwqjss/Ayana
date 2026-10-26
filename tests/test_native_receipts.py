"""Actual MiMo receipt contracts, task ownership and independent owner safety."""
from __future__ import annotations

import asyncio
from pathlib import Path
import subprocess
import unittest
from unittest.mock import AsyncMock, Mock, patch

from ayana.agent_runtime import _check_tmux_owner, runtime_is_quiescent
from ayana.mimo_serve import MimoServeClient, MimoServeError, normalize_receipt_status
from ayana.mimo_session import MimoServeSessionClient, MimoSessionError


class NativeReceiptTests(unittest.TestCase):
    def test_real_settled_receipt_requires_successful_consumption(self):
        receipt = {"id": "rcp_1", "lane": {"sessionID": "ses_one", "agentID": "main"},
                   "state": "settled", "type": "prompt", "epoch": 0, "consumed": True,
                   "outcome": "success", "inputMessageID": "msg_one", "deliveryMessageID": "msg_two"}
        self.assertEqual(normalize_receipt_status(receipt), "completed")
        for change in ({"consumed": False}, {"consumed": None}, {"outcome": None}, {"outcome": "unexpected"}):
            with self.subTest(change=change):
                self.assertEqual(normalize_receipt_status({**receipt, **change}), "unknown")

    def test_actual_receipt_state_and_outcome_enums(self):
        for receipt, expected in (({"state": "accepted"}, "pending"),
                ({"state": "claimed"}, "running"),
                ({"state": "settled", "outcome": "assistant_error"}, "failed"),
                ({"state": "settled", "outcome": "interrupted"}, "cancelled"),
                ({"state": "cancelled", "outcome": "never_ran"}, "cancelled"),
                ({"state": "rejected"}, "failed")):
            with self.subTest(receipt=receipt):
                self.assertEqual(normalize_receipt_status(receipt), expected)

    def test_ambiguous_receipt_does_not_become_success(self):
        for receipt in ({}, {"state": "settled"}, {"state": "maybe"}, [], None):
            self.assertEqual(normalize_receipt_status(receipt), "unknown")


class NativeClientOwnershipTests(unittest.IsolatedAsyncioTestCase):
    def client(self, result):
        client = MimoServeClient(base_url="http://127.0.0.1:6290")
        client._request = AsyncMock(return_value=result)
        return client

    async def test_other_session_busy_does_not_block_idle_session(self):
        await self.client({"ses_other": {"type": "busy"}}).require_session_idle("ses_one")

    async def test_native_idle_map_omits_idle_session(self):
        await self.client({}).require_session_idle("ses_one")

    async def test_busy_or_retry_session_cannot_accept_second_turn(self):
        for state in ("busy", "retry"):
            with self.subTest(state=state):
                with self.assertRaises(MimoServeError) as caught:
                    await self.client({"ses_one": {"type": state}}).require_session_idle("ses_one")
                self.assertEqual(caught.exception.code, "session_busy")

    async def test_unknown_or_malformed_status_fails_closed(self):
        for result in ({"ses_one": None}, {"ses_one": {}}, {"ses_one": {"type": "unknown"}}, []):
            with self.subTest(result=result):
                with self.assertRaises(MimoServeError):
                    await self.client(result).require_session_idle("ses_one")

    async def test_receipt_identity_cannot_cross_session(self):
        for result in ({"id": "rcp_other"}, {"id": "rcp_1", "lane": {"sessionID": "ses_other"}},
                       {"id": "rcp_1", "lane": []}):
            with self.subTest(result=result):
                with self.assertRaises(MimoServeError) as caught:
                    await self.client(result).receipt("ses_one", "rcp_1")
                self.assertEqual(caught.exception.code, "receipt_binding_mismatch")


class FakeNativeClient:
    def __init__(self, *, receipts=None, idle_error=None, submit_error=None):
        self.receipts = list(receipts or [{"state": "settled", "outcome": "success", "consumed": True}])
        self.idle_error, self.submit_error = idle_error, submit_error
        self.prompt_calls = self.receipt_calls = self.message_calls = 0
        self.message_id = ""

    def _admit(self):
        pass

    async def require_session_idle(self, sid):
        if self.idle_error:
            raise self.idle_error

    async def prompt_async(self, sid, prompt, **kwargs):
        self.prompt_calls += 1
        self.message_id = kwargs["message_id"]
        if self.submit_error:
            raise self.submit_error
        return {"accepted": True, "receipt_id": "rcp_1"}

    async def receipt(self, sid, receipt_id):
        self.receipt_calls += 1
        result = self.receipts[min(self.receipt_calls - 1, len(self.receipts) - 1)]
        if isinstance(result, Exception):
            raise result
        return result

    async def messages(self, sid, **kwargs):
        self.message_calls += 1
        def assistant(parent, text, identity):
            return {"info": {"id": identity, "role": "assistant", "parentID": parent,
                             "time": {"created": 1, "completed": 2}, "finish": "stop"},
                    "parts": [{"type": "text", "text": text}]}
        return [assistant(self.message_id, "owned conclusion", "msg_answer"),
                assistant("msg_someone_else", "unrelated latest answer", "msg_later")]


class NativeAdapterTests(unittest.TestCase):
    def adapter(self, fake, *, on_receipt=None):
        states = []
        client = MimoServeSessionClient(default_timeout=.05, poll_interval=.01,
            on_state=lambda rid, state, detail: states.append((state, detail)), on_receipt=on_receipt)
        client._client = lambda runtime, timeout: fake
        return client, states

    def test_result_is_owned_and_waits_for_settled_receipt(self):
        fake = FakeNativeClient(receipts=[{"state": "claimed"},
            {"state": "settled", "outcome": "success", "consumed": True}])
        client, states = self.adapter(fake)
        result = client.resume("ses_one", "investigate")
        self.assertEqual(result.text, "owned conclusion")
        self.assertEqual(fake.prompt_calls, 1)
        self.assertEqual(fake.receipt_calls, 2)
        self.assertEqual([state for state, _ in states], ["running", "completed"])

    def test_preexisting_native_task_keeps_its_state_and_input(self):
        fake = FakeNativeClient(idle_error=MimoServeError("session_busy"))
        client, states = self.adapter(fake)
        with self.assertRaises(MimoSessionError) as caught:
            client.resume("ses_one", "second task")
        self.assertEqual(caught.exception.code, "session_busy")
        self.assertEqual(fake.prompt_calls, 0)
        self.assertEqual(states, [])

    def test_pending_receipt_never_uses_finished_text_as_success(self):
        fake = FakeNativeClient(receipts=[{"state": "claimed"}])
        client, states = self.adapter(fake)
        with self.assertRaises(MimoSessionError):
            client.resume("ses_one", "investigate", timeout=.025)
        self.assertEqual(fake.prompt_calls, 1)
        self.assertEqual(states[-1][0], "unknown")
        self.assertNotIn("completed", [state for state, _ in states])

    def test_uncertain_submission_is_not_replayed(self):
        fake = FakeNativeClient(submit_error=MimoServeError("timeout"))
        client, states = self.adapter(fake)
        with self.assertRaises(MimoSessionError):
            client.resume("ses_one", "investigate")
        self.assertEqual(fake.prompt_calls, 1)
        self.assertEqual(states[-1][0], "unknown")

    def test_missing_receipt_after_admission_stays_unknown(self):
        fake = FakeNativeClient(receipts=[MimoServeError("http_404")])
        client, states = self.adapter(fake)
        with self.assertRaises(MimoSessionError):
            client.resume("ses_one", "investigate")
        self.assertEqual(fake.prompt_calls, 1)
        self.assertEqual(states[-1][0], "unknown")

    def test_explicit_submission_rejection_is_failed(self):
        fake = FakeNativeClient(submit_error=MimoServeError("http_400"))
        client, states = self.adapter(fake)
        with self.assertRaises(MimoSessionError):
            client.resume("ses_one", "investigate")
        self.assertEqual(states[-1][0], "failed")
        self.assertEqual(fake.prompt_calls, 1)

    def test_failed_settlement_does_not_use_assistant_success_text(self):
        fake = FakeNativeClient(receipts=[{"state": "settled", "outcome": "assistant_error", "consumed": True}])
        client, states = self.adapter(fake)
        with self.assertRaises(MimoSessionError):
            client.resume("ses_one", "investigate")
        self.assertEqual(fake.message_calls, 0)
        self.assertEqual(states[-1][0], "failed")

    def test_receipt_persistence_failure_keeps_unknown_blocker(self):
        def fail(*args):
            raise RuntimeError("database unavailable")
        fake = FakeNativeClient()
        client, states = self.adapter(fake, on_receipt=fail)
        with self.assertRaises(MimoSessionError):
            client.resume("ses_one", "investigate")
        self.assertEqual(fake.prompt_calls, 1)
        self.assertEqual(states[-1][0], "unknown")
        self.assertEqual(states[-1][1]["receipt_id"], "rcp_1")


class IndependentRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_refuses_tmux_in_web_or_admin_cgroup(self):
        tui = Mock()
        tui._tmux.return_value = subprocess.CompletedProcess([], 0, "123\n", "")
        with patch.object(Path, "read_text", side_effect=["0::/system.slice/ayana.service", "0::/system.slice/ayana-agent-runtime.service"]):
            with self.assertRaisesRegex(RuntimeError, "tmux_runtime_owner_mismatch"):
                await _check_tmux_owner(tui)

    async def test_accepts_own_tmux_cgroup(self):
        tui = Mock()
        tui._tmux.return_value = subprocess.CompletedProcess([], 0, "123\n", "")
        with patch.object(Path, "read_text", return_value="0::/system.slice/ayana-agent-runtime.service"):
            await _check_tmux_owner(tui)

    def test_config_rotation_waits_for_all_owners_and_known_idle(self):
        self.assertTrue(runtime_is_quiescent({}, pending_receipts=False, running_jobs=False))
        for statuses, receipts, jobs in (({}, True, False), ({}, False, True),
                ({"ses_1": {"type": "busy"}}, False, False),
                ({"ses_1": {"type": "retry"}}, False, False),
                ({"ses_1": {"type": "unexpected"}}, False, False), ([], False, False),
                ({"ses_1": None}, False, False)):
            with self.subTest(statuses=statuses, receipts=receipts, jobs=jobs):
                self.assertFalse(runtime_is_quiescent(statuses, pending_receipts=receipts, running_jobs=jobs))


if __name__ == "__main__":
    unittest.main()
