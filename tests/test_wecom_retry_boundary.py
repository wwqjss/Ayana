"""Only definite pre-send failures may be automatically retried."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ayana.db import Database
from ayana.notify import Notifier
from ayana.notify_channels import ChannelStore
from ayana.wecom_aibot import WeComAibotClient, WeComAibotError, WeComAibotManager


class WeComRetryBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary_root = Path(__file__).resolve().parents[1] / ".test-tmp"
        temporary_root.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="wecom-retry-", dir=temporary_root)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.db.close)
        self.store = ChannelStore(self.db, master_key="test-key" * 4)
        self.channel = self.store.create(name="企微", kind="wecom_aibot", config={"targets": ["chat1"]}, secret={"bot_id": "test-bot", "secret": "test-secret"})
        self.client = WeComAibotClient(bot_id="test-bot", secret="test-secret")
        self.client._ws = SimpleNamespace(closed=False)
        self.client._send_frame = AsyncMock()
        self.manager = WeComAibotManager()
        self.manager._clients[self.channel["id"]] = self.client
        self.manager.ensure = AsyncMock()
        self.store.set_aibot_manager(self.manager)
        self.notifier = Notifier(self.db)
        self.notifier.set_channel_store(self.store)

    def enqueue(self):
        self.assertTrue(self.notifier.enqueue(dedup_key="retry-boundary", target="chat1", body="真实事件通知"))

    def row(self):
        return dict(self.db.query_one("SELECT * FROM notification_outbox"))

    async def acknowledge(self, frame):
        await self.client._handle_frame({"cmd": "ack", "headers": frame["headers"], "errcode": 0})

    async def test_before_authentication_failure_is_pending_and_sends_once_after_auth(self):
        self.enqueue()
        self.assertEqual(await self.notifier.flush(), 0)
        self.assertEqual(self.row()["state"], "pending")
        self.assertEqual(self.row()["last_error"], "not_authenticated")
        self.client._send_frame.assert_not_awaited()
        self.assertEqual(self.client._pending, {})
        self.client._authenticated = True
        self.client._send_frame.side_effect = self.acknowledge
        self.db.execute("UPDATE notification_outbox SET next_try_at=0")
        self.assertEqual(await self.notifier.flush(), 1)
        self.client._send_frame.assert_awaited_once()
        self.assertEqual(self.row()["state"], "sent")
        self.assertEqual(await self.notifier.flush(), 0)

    async def test_missing_client_is_pending_without_any_message_attempt(self):
        self.manager._clients.clear()
        self.enqueue()
        self.assertEqual(await self.notifier.flush(), 0)
        self.assertEqual(self.row()["state"], "pending")
        self.assertEqual(self.row()["last_error"], "client_not_running")
        self.client._send_frame.assert_not_awaited()

    async def test_connection_setup_failure_is_pending_and_never_invokes_send(self):
        self.manager.ensure.side_effect = RuntimeError("setup unavailable")
        self.enqueue()
        self.assertEqual(await self.notifier.flush(), 0)
        self.assertEqual(self.row()["state"], "pending")
        self.assertTrue(self.row()["last_error"].startswith("ensure_failed:"))
        self.client._send_frame.assert_not_awaited()

    async def test_ack_timeout_after_frame_is_unknown_and_never_auto_replayed(self):
        self.client._authenticated = True
        self.enqueue()
        with patch("ayana.wecom_aibot.ACK_TIMEOUT_SEC", 0.001):
            self.assertEqual(await self.notifier.flush(), 0)
        self.assertEqual(self.row()["state"], "failed")
        self.assertEqual(self.row()["last_error"], "unknown:ack_timeout")
        self.db.execute("UPDATE notification_outbox SET next_try_at=0")
        self.assertEqual(await self.notifier.flush(), 0)
        self.client._send_frame.assert_awaited_once()

    async def test_connection_loss_after_frame_stays_unknown(self):
        for code in ("disconnected", "closed"):
            with self.subTest(code=code):
                self.db.execute("DELETE FROM notification_outbox")
                self.client._send_frame.reset_mock()
                self.client._authenticated = True
                async def lose_connection(frame):
                    self.client._fail_pending(WeComAibotError(code, "connection lost"))
                self.client._send_frame.side_effect = lose_connection
                self.enqueue()
                self.assertEqual(await self.notifier.flush(), 0)
                self.assertEqual(self.row()["state"], "failed")
                self.assertTrue(self.row()["last_error"].startswith("unknown:"))
                self.assertEqual(await self.notifier.flush(), 0)
                self.client._send_frame.assert_awaited_once()

    async def test_send_error_after_entering_frame_writer_stays_unknown(self):
        self.client._authenticated = True
        self.client._send_frame.side_effect = RuntimeError("connection reset during send")
        self.enqueue()
        self.assertEqual(await self.notifier.flush(), 0)
        self.assertEqual(self.row()["state"], "failed")
        self.assertTrue(self.row()["last_error"].startswith("unknown:send_error:"))
        self.assertEqual(await self.notifier.flush(), 0)
        self.client._send_frame.assert_awaited_once()

    async def test_explicit_negative_ack_remains_a_known_retryable_failure(self):
        self.client._authenticated = True
        async def reject(frame):
            await self.client._handle_frame({"cmd": "ack", "headers": frame["headers"], "errcode": 45002, "errmsg": "rate limit"})
        self.client._send_frame.side_effect = reject
        self.enqueue()
        self.assertEqual(await self.notifier.flush(), 0)
        self.assertEqual(self.row()["state"], "pending")
        self.assertTrue(self.row()["last_error"].startswith("send_45002"))


if __name__ == "__main__":
    unittest.main()
