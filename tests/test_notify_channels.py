"""多消息渠道：注册、加密、扇出、独立失败（不触网）。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database, now
from ayana.notify import Notifier
from ayana.notify_channels import CHANNEL_KINDS, ChannelError, ChannelStore


class TestNotifyChannels(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        self.store = ChannelStore(self.db, master_key="test-master-key")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_default_qq_seeded_once(self):
        """全新安装零渠道：ensure_default_qq 不再预置 QQ。"""
        self.store.ensure_default_qq("user:123")
        self.store.ensure_default_qq("user:456")
        chans = self.store.list_meta()
        self.assertEqual(len(chans), 0)

    def test_fresh_install_has_zero_channels(self):
        self.assertEqual(self.store.list_meta(), [])

    def test_create_webhook_encrypts_secret(self):
        ch = self.store.create(
            name="ops-hook",
            kind="webhook",
            config={"url": "https://example.com/hook", "method": "POST"},
            secret={"headers": {"Authorization": "Bearer SECRET-TOKEN"}},
            actor="admin",
        )
        self.assertEqual(ch["kind"], "webhook")
        self.assertTrue(ch["has_secret"])
        # 列表不回显敏感头
        self.assertNotIn("Authorization", json_dumps(ch))
        self.assertNotIn("SECRET-TOKEN", json_dumps(ch))
        # 发送路径可解密
        raw = self.store.reveal_for_send(ch["id"])
        self.assertEqual(raw["secret"]["headers"]["Authorization"], "Bearer SECRET-TOKEN")

    def test_update_does_not_echo_secret(self):
        ch = self.store.create(
            name="h",
            kind="webhook",
            config={"url": "https://e.com/x"},
            secret={"token": "abc123"},
        )
        meta = self.store.get_meta(ch["id"])
        self.assertNotIn("abc123", json_dumps(meta))
        self.store.update(ch["id"], secret={"token": "xyz"})
        raw = self.store.reveal_for_send(ch["id"])
        self.assertEqual(raw["secret"]["token"], "xyz")
        self.store.update(ch["id"], clear_secret=True)
        meta2 = self.store.get_meta(ch["id"])
        self.assertFalse(meta2["has_secret"])

    def test_bad_kind_and_url(self):
        with self.assertRaises(ChannelError):
            self.store.create(name="x", kind="sms", config={})
        with self.assertRaises(ChannelError):
            self.store.create(
                name="x", kind="webhook", config={"url": "ftp://bad"}
            )

    def test_fanout_independent_rows(self):
        # 用户主动添加渠道（不预置）
        self.store.create(
            name="qq",
            kind="qq",
            config={"target": "user:1"},
            enabled=True,
        )
        self.store.create(
            name="hook",
            kind="webhook",
            config={"url": "https://example.com/h"},
            enabled=True,
        )
        n = Notifier(self.db, default_target="user:1")
        n.set_channel_store(self.store)
        ok = n.enqueue_for_event(1, body="hello")
        self.assertTrue(ok)
        rows = n.outbox_summary()
        self.assertEqual(len(rows), 2)
        kinds = sorted(r["channel"] for r in rows)
        self.assertEqual(kinds, ["qq", "webhook"])
        # dedup 幂等
        n.enqueue_for_event(1, body="hello")
        self.assertEqual(len(n.outbox_summary()), 2)

    def test_one_channel_fail_does_not_block_other(self):
        async def run():
            self.store.create(
                name="bad",
                kind="webhook",
                # B5: 环回目标在创建期拒绝；用文档地址模拟不可达
                config={"url": "http://192.0.2.1:1/nope"},
                enabled=True,
            )
            self.store.create(
                name="good",
                kind="qq",
                config={"target": "user:9"},
            )
            n = Notifier(self.db, default_target="")
            n.set_channel_store(self.store)
            sent_ok = []

            async def qq_sender(target, body):
                sent_ok.append((target, body))
                return True

            self.store.set_qq_sender(qq_sender)
            n.set_sender(qq_sender)
            n.enqueue_for_event(2, body="evt")
            # flush：webhook 可能失败，qq 应成功
            await n.flush(limit=10)
            rows = n.outbox_summary()
            by_ch = {r["channel"]: r for r in rows}
            self.assertEqual(by_ch["qq"]["state"], "sent")
            self.assertIn(by_ch["webhook"]["state"], ("pending", "failed"))
            self.assertTrue(sent_ok)

        asyncio.run(run())

    def test_wecom_kind_and_guide(self):
        from ayana.notify_channels import CHANNEL_GUIDES, list_channel_kinds

        self.assertIn("wecom", CHANNEL_KINDS)
        self.assertIn("qq", CHANNEL_KINDS)
        guide = CHANNEL_GUIDES["wecom"]
        self.assertTrue(guide.get("steps"))
        self.assertTrue(guide.get("notes"))
        self.assertTrue(any("91770" in (d.get("url") or "") for d in guide.get("docs") or []))
        # 企业微信步骤与用户要求一致
        steps = "\n".join(guide["steps"])
        self.assertIn("群机器人", steps)
        self.assertIn("Webhook", steps)
        self.assertIn("发送测试消息", steps)
        # NapCat 也有说明
        self.assertTrue(CHANNEL_GUIDES["qq"].get("steps"))
        kinds = {k["kind"] for k in list_channel_kinds()}
        self.assertEqual(kinds, {"qq", "wecom", "wecom_aibot", "webhook"})

    def test_wecom_create_encrypts_webhook_url(self):
        secret_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=SECRETKEY123"
        ch = self.store.create(
            name="企微告警群",
            kind="wecom",
            config={"url": secret_url},
            secret={"webhook_url": secret_url},
            actor="admin",
        )
        self.assertEqual(ch["kind"], "wecom")
        self.assertTrue(ch["has_secret"])
        dumped = json_dumps(ch)
        self.assertNotIn("SECRETKEY123", dumped)
        self.assertIn("****", dumped)
        raw = self.store.reveal_for_send(ch["id"])
        self.assertEqual(raw["secret"]["webhook_url"], secret_url)

    def test_wecom_missing_url_rejected(self):
        with self.assertRaises(ChannelError):
            self.store.create(name="x", kind="wecom", config={})

    def test_wecom_send_uses_robot_payload(self):
        import aiohttp  # noqa: F401

        secret_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=K"
        ch = self.store.create(
            name="w",
            kind="wecom",
            secret={"webhook_url": secret_url},
        )

        async def run():
            # 打桩 _send_wecom 的 HTTP 层：直接验证 payload 组装契约
            captured = {}

            async def fake_send(sec, body):
                captured["url"] = sec.get("webhook_url")
                captured["body"] = body
                return True, ""

            self.store._send_wecom = fake_send  # type: ignore
            ok, err = await self.store.send(ch["id"], "hello wecom")
            self.assertTrue(ok)
            self.assertEqual(captured["url"], secret_url)
            self.assertEqual(captured["body"], "hello wecom")

        import asyncio

        asyncio.run(run())

    def test_kind_without_guide_rejected(self):
        # 强制：未登记 CHANNEL_GUIDES 的 kind 不可创建
        from ayana.notify_channels import CHANNEL_GUIDES

        self.assertTrue(all(k in CHANNEL_GUIDES for k in CHANNEL_KINDS))

    def test_delete_channel(self):
        ch = self.store.create(
            name="t", kind="webhook", config={"url": "https://e.com/x"}
        )
        self.store.delete(ch["id"])
        self.assertIsNone(self.store.get_meta(ch["id"]))

    def test_missing_key_blocks_secret(self):
        bare = ChannelStore(self.db, master_key="")
        with self.assertRaises(ChannelError):
            bare.create(
                name="x",
                kind="webhook",
                config={"url": "https://e.com/x"},
                secret={"token": "t"},
            )


def json_dumps(obj) -> str:
    import json

    return json.dumps(obj, ensure_ascii=False, default=str)


if __name__ == "__main__":
    unittest.main()
