"""Retiring approval must leave normal channel message routing operational."""

from __future__ import annotations

import unittest

from ayana.msgentry import parse_entry
from ayana.qqbot import HELP, QQBot


class RetiredApprovalEntryTests(unittest.TestCase):
    def test_help_is_still_a_slash_command(self):
        entry = parse_entry("@Ayana /help")
        self.assertEqual((entry.kind, entry.slash_cmd), ("slash", "/help"))

    def test_channel_query_is_still_plain_text(self):
        entry = parse_entry("@Ayana 查询 control 状态")
        self.assertEqual((entry.kind, entry.nl_text), ("nl", "查询 control 状态"))

    def test_controlled_syntax_reaches_retired_entry_handler(self):
        entry = parse_entry("@Ayana -c control systemctl status nginx")
        self.assertEqual((entry.kind, entry.host), ("controlled", "control"))
        self.assertEqual(entry.cmd_tokens, ["systemctl", "status", "nginx"])

    def test_old_approval_wording_cannot_create_an_authorization(self):
        for text in ("同意", "批准", "确认执行", "拒绝", "@Ayana 同意"):
            with self.subTest(text=text):
                entry = parse_entry(text)
                self.assertEqual(entry.kind, "nl")

    def test_help_advertises_current_entry_points(self):
        self.assertIn("/investigate", HELP)
        self.assertIn("MiMoCode", HELP)
        for command in ("-c", "/actions", "/approve", "/reject", "/cancel"):
            self.assertNotIn(command, HELP)


class RetiredChannelCommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_old_approval_and_action_commands_only_report_retirement(self):
        bot = QQBot.__new__(QQBot)
        for command in ("/approve act_old", "/reject act_old", "/cancel act_old", "/actions"):
            with self.subTest(command=command):
                reply = await bot._dispatch_authorized(command, user_id="test")
                self.assertTrue("删除" in reply or "退役" in reply)


if __name__ == "__main__":
    unittest.main()
