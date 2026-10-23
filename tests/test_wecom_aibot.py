"""企微智能机器人薄客户端：帧格式、回执关联、结果未知、多目标扇出。"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database
from ayana.notify import Notifier
from ayana.notify_channels import (
    CHANNEL_GUIDES,
    CHANNEL_KINDS,
    PLATFORMS,
    ChannelError,
    ChannelStore,
    list_channel_kinds,
    list_platforms,
)
from ayana.wecom_aibot import WeComAibotClient, WeComAibotManager


class FakeWS:
    def __init__(self):
        self.sent = []
        self.closed = False
        self._q: asyncio.Queue = asyncio.Queue()
        self.type = type("T", (), {"name": "TEXT"})()

    async def send_str(self, s):
        self.sent.append(json.loads(s))

    async def close(self):
        self.closed = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.closed and self._q.empty():
            raise StopAsyncIteration
        msg = await self._q.get()
        if msg is None:
            raise StopAsyncIteration
        return msg

    def push(self, frame: dict):
        m = type("M", (), {})()
        m.data = json.dumps(frame, ensure_ascii=False)
        m.type = type("T", (), {"name": "TEXT"})()
        self._q.put_nowait(m)

    def push_close(self):
        self._q.put_nowait(None)


class TestProtocolFrames(unittest.TestCase):
    def test_subscribe_and_send_frame_format(self):
        async def run():
            client = WeComAibotClient(bot_id="BOT1", secret="SEC1")
            ws = FakeWS()
            client._ws = ws
            client._authenticated = True
            # 直接测 send_text 组帧
            fut = asyncio.get_running_loop().create_future()
            # 拦截 _send_frame 后模拟回执
            orig = client._send_frame

            async def fake_send(frame):
                ws.sent.append(frame)
                rid = frame["headers"]["req_id"]
                if frame["cmd"] == "aibot_send_msg":
                    ws.push({"cmd": "ack", "headers": {"req_id": rid}, "errcode": 0, "errmsg": "ok"})
                    # 交给 handle
                    await client._handle_frame(
                        {"cmd": "ack", "headers": {"req_id": rid}, "errcode": 0}
                    )

            client._send_frame = fake_send
            ok, err = await client.send_text("CHAT1", "hello")
            self.assertTrue(ok, err)
            frames = [f for f in ws.sent if f.get("cmd") == "aibot_send_msg"]
            self.assertTrue(frames)
            f = frames[0]
            self.assertEqual(f["body"]["chatid"], "CHAT1")
            self.assertEqual(f["body"]["msgtype"], "markdown")
            self.assertEqual(f["body"]["markdown"]["content"], "hello")
            self.assertTrue(f["headers"]["req_id"].startswith("aibot_send_msg"))

        asyncio.run(run())

    def test_ack_error_is_retryable(self):
        async def run():
            client = WeComAibotClient(bot_id="B", secret="S")
            ws = FakeWS()
            client._ws = ws
            client._authenticated = True

            async def fake_send(frame):
                rid = frame["headers"]["req_id"]
                await client._handle_frame(
                    {
                        "cmd": "ack",
                        "headers": {"req_id": rid},
                        "errcode": 45002,
                        "errmsg": "out of limit",
                    }
                )

            client._send_frame = fake_send
            ok, err = await client.send_text("C", "x")
            self.assertFalse(ok)
            self.assertFalse(err.startswith("unknown:"), err)

        asyncio.run(run())

    def test_ack_timeout_is_unknown(self):
        async def run():
            client = WeComAibotClient(bot_id="B", secret="S")
            ws = FakeWS()
            client._ws = ws
            client._authenticated = True

            async def fake_send(frame):
                pass  # 不回执

            client._send_frame = fake_send
            ok, err = await client.send_text("C", "x")
            self.assertFalse(ok)
            self.assertTrue(err.startswith("unknown:"), err)

        asyncio.run(run())

    def test_not_connected_before_send_is_retryable(self):
        async def run():
            client = WeComAibotClient(bot_id="B", secret="S")
            ok, err = await client.send_text("C", "x")
            self.assertFalse(ok)
            self.assertEqual(err, "not_authenticated")

        asyncio.run(run())

    def test_manager_one_client_per_channel(self):
        async def run():
            mgr = WeComAibotManager()
            # 不真正连网：ensure 会 start 任务，立即 stop
            task = asyncio.create_task(
                mgr.ensure("ch1", bot_id="B", secret="S")
            )
            await asyncio.sleep(0.05)
            await mgr.stop_all()
            try:
                await asyncio.wait_for(task, timeout=1)
            except Exception:
                pass
            self.assertEqual(mgr.status("ch1").get("state"), "stopped")

        asyncio.run(run())


class TestChannelsAibot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        self.store = ChannelStore(self.db, master_key="test-master-key")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_platforms_and_guides(self):
        self.assertIn("wecom_aibot", CHANNEL_KINDS)
        self.assertIn("wecom_aibot", CHANNEL_GUIDES)
        kinds = {k["kind"] for k in list_channel_kinds()}
        self.assertIn("wecom_aibot", kinds)
        plats = list_platforms()
        wecom = next(p for p in plats if p["id"] == "wecom")
        method_kinds = {m["kind"] for m in wecom["methods"]}
        self.assertEqual(method_kinds, {"wecom", "wecom_aibot"})
        # URL 回调不提供
        self.assertNotIn("wecom_callback", method_kinds)
        guide = CHANNEL_GUIDES["wecom_aibot"]
        self.assertTrue(any("Bot ID" in s or "BotID" in s for s in guide["steps"]))
        self.assertTrue(any("Secret" in s for s in guide["steps"]))
        self.assertTrue(any("目标" in s for s in guide["steps"]))

    def test_create_aibot_encrypts_and_multi_targets(self):
        ch = self.store.create(
            name="企微机器人",
            kind="wecom_aibot",
            config={"bot_id": "BOTABC123", "targets": ["user1", "CHAT9", "user1"]},
            secret={"bot_id": "BOTABC123", "secret": "SUPERSECRET"},
            actor="admin",
        )
        self.assertEqual(ch["kind"], "wecom_aibot")
        self.assertTrue(ch["has_secret"])
        dumped = json.dumps(ch, ensure_ascii=False, default=str)
        self.assertNotIn("SUPERSECRET", dumped)
        self.assertNotIn("BOTABC123", dumped)  # bot_id 也脱敏
        self.assertEqual(ch["config"]["targets"], ["user1", "CHAT9"])  # 去重
        raw = self.store.reveal_for_send(ch["id"])
        self.assertEqual(raw["secret"]["secret"], "SUPERSECRET")
        self.assertEqual(raw["secret"]["bot_id"], "BOTABC123")

    def test_aibot_requires_creds(self):
        with self.assertRaises(ChannelError):
            self.store.create(
                name="x", kind="wecom_aibot", config={"targets": ["a"]}
            )
        # 推送目标可为空
        ch = self.store.create(
            name="x",
            kind="wecom_aibot",
            config={},
            secret={"bot_id": "b", "secret": "s"},
        )
        self.assertEqual(ch["config"].get("targets") or [], [])

    def test_discovered_targets(self):
        ch = self.store.create(
            name="a", kind="wecom_aibot",
            config={"bot_id": "B"}, secret={"bot_id": "B", "secret": "S"},
        )
        cid = ch["id"]
        self.store.record_seen_target(
            cid, target_id="CHAT_G1", chattype="group", userid="u1", msgtype="text"
        )
        self.store.record_seen_target(
            cid, target_id="user1", chattype="single", userid="user1", msgtype="text"
        )
        self.store.record_seen_target(
            cid, target_id="CHAT_G1", chattype="group", userid="u2", msgtype="text"
        )
        found = self.store.list_seen_targets(cid)
        self.assertEqual(len(found), 2)
        by_id = {t["target_id"]: t for t in found}
        self.assertEqual(by_id["CHAT_G1"]["chattype"], "group")
        self.assertEqual(by_id["CHAT_G1"]["userid"], "u2")  # 更新最近发言人
        self.assertEqual(by_id["user1"]["chattype"], "single")
        # 保存勾选
        updated = self.store.set_targets(cid, ["CHAT_G1"], actor="admin")
        self.assertEqual(updated["config"]["targets"], ["CHAT_G1"])
        # 审计
        rows = self.db.query(
            "SELECT entry FROM audit_log WHERE entry='notify_channel_targets_updated'"
        )
        self.assertTrue(rows)

    def test_fanout_one_row_per_target(self):
        self.store.create(
            name="aibot",
            kind="wecom_aibot",
            config={"bot_id": "B", "targets": ["t1", "t2"]},
            secret={"bot_id": "B", "secret": "S"},
        )
        n = Notifier(self.db, default_target="")
        n.set_channel_store(self.store)
        n.enqueue_for_event(1, body="evt")
        rows = n.outbox_summary()
        self.assertEqual(len(rows), 2)
        targets = sorted(r["target"] for r in rows)
        self.assertEqual(targets, ["t1", "t2"])
        # 幂等
        n.enqueue_for_event(1, body="evt")
        self.assertEqual(len(n.outbox_summary()), 2)

    def test_unknown_error_not_auto_retried(self):
        async def run():
            self.store.create(
                name="aibot",
                kind="wecom_aibot",
                config={"bot_id": "B", "targets": ["t1"]},
                secret={"bot_id": "B", "secret": "S"},
            )
            n = Notifier(self.db)
            n.set_channel_store(self.store)

            async def fake_send(cid, body, target=""):
                return False, "unknown:ack_timeout"

            self.store.send = fake_send  # type: ignore
            n.enqueue_for_event(2, body="evt")
            await n.flush()
            rows = n.outbox_summary()
            self.assertEqual(rows[0]["state"], "failed")
            self.assertIn("unknown", rows[0]["last_error"])
            # 不应处于 pending 可再自动重试
            self.assertEqual(rows[0]["state"], "failed")

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
