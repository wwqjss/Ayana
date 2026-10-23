"""消息记录：出入站统一列表、筛选、关联回复（outbox 不重复写入）。"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database
from ayana.messagelog import MessageLog, platform_of_kind
from ayana.notify_channels import ChannelStore
from ayana.notify import Notifier
import asyncio


class TestMessageLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        self.mlog = MessageLog(self.db)
        self.store = ChannelStore(self.db, master_key="k" * 16)
        self.store.set_mlog(self.mlog)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_platform_of_kind(self):
        self.assertEqual(platform_of_kind("qq"), "qq")
        self.assertEqual(platform_of_kind("wecom_aibot"), "wecom")
        self.assertEqual(platform_of_kind("webhook"), "webhook")

    def test_inbound_lifecycle(self):
        mid = self.mlog.record(
            direction="in",
            platform="wecom",
            channel_kind="wecom_aibot",
            channel_id="ch1",
            channel_name="机器人",
            sender="u1",
            target="CHAT1",
            body="/status",
            state="received",
        )
        self.mlog.update_state(mid, state="processed", replied=True)
        item = self.mlog.get(mid)
        self.assertEqual(item["state"], "processed")
        self.assertEqual(item["replied"], 1)

    def test_outbox_not_duplicated(self):
        self.store.create(
            name="qq",
            kind="qq",
            config={"target": "user:1"},
            enabled=True,
        )
        n = Notifier(self.db, default_target="user:1")
        n.set_channel_store(self.store)
        n.enqueue_for_event(1, body="hello notify")
        rows = self.mlog.list_messages(direction="out")
        self.assertEqual(rows["total"], 1)
        self.assertEqual(rows["items"][0]["body"], "hello notify")
        self.assertEqual(rows["items"][0]["sender"], "ayana")
        # 不是 message_log 表里的
        self.db.execute("SELECT COUNT(*) FROM message_log")
        ml = self.db.query_one("SELECT COUNT(*) AS n FROM message_log")
        self.assertEqual(int(ml["n"]), 0)

    def test_filter_and_search(self):
        self.mlog.record(direction="in", platform="qq", sender="a", body="hello /ping", state="received")
        self.mlog.record(direction="out", platform="wecom", target="c1", body="pong", state="sent")
        self.assertEqual(self.mlog.list_messages(direction="in")["total"], 1)
        self.assertEqual(self.mlog.list_messages(platform="wecom")["total"], 1)
        self.assertEqual(self.mlog.list_messages(q="ping")["total"], 1)
        self.assertEqual(self.mlog.list_messages(state="sent")["total"], 1)

    def test_reply_link(self):
        mid = self.mlog.record(direction="in", body="/status", state="processed")
        rid = self.mlog.record(direction="out", body="status ok", state="sent", reply_to=mid)
        self.mlog.update_state(mid, replied=True, reply_log_id=rid)
        item = self.mlog.get(mid)
        self.assertEqual(item["reply_log_id"], rid)
        out = self.mlog.get(rid)
        self.assertEqual(out["reply_to"], mid)

    def test_test_send_logged(self):
        async def run():
            self.store.create(
                name="hook", kind="webhook",
                config={"url": "https://e.com/x"},
            )
            # 不真发网，打桩
            async def fake_send(cid, body, target=""):
                return True, ""
            self.store.send = fake_send  # type: ignore
            await self.store.test("x")  # wrong id
            ch = self.store.list_meta()[0]
            await self.store.test(ch["id"], actor="admin")
            rows = self.mlog.list_messages(direction="out", q="通道测试")
            self.assertGreaterEqual(rows["total"], 1)

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
