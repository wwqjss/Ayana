"""Human approval wording, exact replies and channel authentication boundaries."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from aiohttp import web

from ayana.actions import ActionError
from ayana.fmt import fmt_approve_request, fmt_auto_wait, fmt_escalate
from ayana.msgentry import parse_entry
from ayana.qqbot import QQBot
from ayana.web import WebApp
from ayana.wecom_bot import WeComBot


class ApprovalWordingTests(unittest.TestCase):
    def test_request_displays_service_command_and_three_replies_without_internal_ids(self):
        incident = {"id": "inc_hidden", "title": "nerv / frps: TargetDown", "object_id": "frps"}
        action = {
            "id": "act_hidden", "capability": "service.restart", "object_id": "nerv:service:frps",
            "params_json": json.dumps({"object_name": "frps", "tokens": ["systemctl", "restart", "frps"]}),
        }
        body = fmt_approve_request(incident, action, rule_name="rb_frps_down_restart")
        for expected in ("需要你授权", "服务不可达", "重启服务 systemctl restart frps", "规则: frps 探测失败自动重启", "执行一次", "不执行", "永久允许执行"):
            self.assertIn(expected, body)
        for internal in ("inc_hidden", "act_hidden", "rb_frps_down_restart", "service.restart", "nerv:service:frps", "TargetDown"):
            self.assertNotIn(internal, body)

    def test_cooldown_reports_retry_time_without_requesting_approval(self):
        body = fmt_auto_wait({"title": "nerv / frps: TargetDown"}, reason="冷却中", retry_at=1)
        self.assertIn("冷却中", body)
        self.assertIn("01-01 08:00", body)
        self.assertIn("北京时间", body)
        self.assertNotIn("需要你授权", body)
        self.assertNotIn("执行一次", body)
        self.assertIn("冷却中", fmt_escalate({}, "preconditions: cooldown"))

    def test_unknown_block_reason_does_not_expose_internal_enum(self):
        body = fmt_escalate({}, "new_unknown_enum:act_secret")
        self.assertNotIn("new_unknown_enum", body)
        self.assertNotIn("act_secret", body)

    def test_reply_parser_requires_complete_unambiguous_sentence(self):
        for phrase, expected in (("执行一次", "execute_once"), ("@Ayana 仅执行一次。", "execute_once"), ("不执行", "reject"), ("不要执行！", "reject"), ("永久允许执行", "allow_always"), ("以后自动执行", "allow_always")):
            with self.subTest(phrase=phrase):
                entry = parse_entry(phrase)
                self.assertEqual((entry.kind, entry.approval_decision), ("approval", expected))
        for phrase in ("不要永久允许执行", "他说执行一次", "执行一次还是不执行", "执行一次\n永久允许执行", "‘执行一次’", "执行一次？"):
            self.assertNotEqual(parse_entry(phrase).kind, "approval", phrase)


class ApprovalChannelTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ob = SimpleNamespace(set_message_handler=Mock(), send_private=AsyncMock(return_value=True), send_group=AsyncMock(return_value=True))
        self.bot = QQBot(Mock(), self.ob, Mock(), Mock(), Mock(), Mock(), Mock(), admin_qq="qq-admin", admin_wecom_users=["wc-admin"])
        self.decide = AsyncMock(return_value={"decision": "execute_once", "executed": True, "state": "success"})
        self.service = patch("ayana.qqbot.ApprovalService", return_value=SimpleNamespace(decide=self.decide))
        self.service.start()
        self.addCleanup(self.service.stop)

    async def test_qq_plain_reply_reaches_approval_with_authenticated_sender(self):
        await self.bot.on_event({"message_type": "private", "user_id": "qq-admin", "raw_message": "执行一次"})
        self.assertEqual(self.decide.await_args.args, ("execute_once",))
        self.assertEqual(self.decide.await_args.kwargs["actor_id"], "qq-admin")
        self.assertEqual(self.decide.await_args.kwargs["actor_type"], "qq_user")
        self.assertTrue(self.decide.await_args.kwargs["is_admin"])
        self.ob.send_private.assert_awaited_once_with("qq-admin", "已批准本次处置，执行结果：成功。")

    async def test_qq_nonadmin_is_never_elevated_by_text_or_group(self):
        await self.bot.on_event({"message_type": "group", "group_id": "qq-admin", "user_id": "other", "raw_message": "永久允许执行"})
        self.assertFalse(self.decide.await_args.kwargs["is_admin"])

    async def test_wecom_plain_reply_uses_wecom_identity_and_explicit_admin_list(self):
        aibot = SimpleNamespace(send_text=AsyncMock(return_value=(True, "")))
        bot = WeComBot(self.bot, aibot)
        frame = {"cmd": "aibot_msg_callback", "body": {"msgtype": "text", "text": {"content": "永久允许执行"}, "from": {"userid": "wc-admin"}, "chattype": "single"}}
        await bot.on_channel_frame("channel-1", frame)
        self.assertEqual(self.decide.await_args.kwargs["actor_type"], "wecom_user")
        self.assertEqual(self.decide.await_args.kwargs["actor_id"], "wc-admin")
        self.assertTrue(self.decide.await_args.kwargs["is_admin"])
        frame["body"]["from"]["userid"] = "qq-admin"
        await bot.on_channel_frame("channel-1", frame)
        self.assertFalse(self.decide.await_args.kwargs["is_admin"])

    async def test_malformed_admin_config_fails_closed(self):
        self.bot = QQBot(Mock(), self.ob, Mock(), Mock(), Mock(), Mock(), Mock(), admin_wecom_users="wc-admin")
        await self.bot._handle_approval(parse_entry("永久允许执行"), user_id="w", actor_type="wecom_user")
        self.assertFalse(self.decide.await_args.kwargs["is_admin"])

    async def test_ambiguous_reply_has_no_fallback_to_latest_or_natural_language(self):
        self.decide.side_effect = ActionError("approval_ambiguous")
        self.bot.agent_query = SimpleNamespace(handle=AsyncMock())
        await self.bot.on_event({"message_type": "private", "user_id": "qq-admin", "raw_message": "执行一次"})
        self.bot.agent_query.handle.assert_not_awaited()
        reply = self.ob.send_private.await_args.args[1]
        self.assertIn("多条", reply)
        self.assertNotIn("approval_ambiguous", reply)


class ApprovalWebTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.app = WebApp(Mock(), Mock(), Mock(), Mock(), Mock(), Mock(), Mock(), static_dir=Path("."))
        self.session = {"username": "admin", "is_admin": True}
        self.app._require_auth = Mock(return_value=self.session)
        self.app._check_csrf = Mock()
        self.app._sensitive_totp = Mock(return_value=None)
        self.decide = AsyncMock(return_value={"decision": "execute_once", "executed": True, "state": "success"})
        service = patch("ayana.web.ApprovalService", return_value=SimpleNamespace(decide=self.decide))
        service.start()
        self.addCleanup(service.stop)

    def request(self, decision):
        return SimpleNamespace(json=AsyncMock(return_value={"decision": decision, "totp": "123456"}), match_info={"aid": "act-explicit"})

    async def test_execution_choices_require_totp_and_target_explicit_action(self):
        for choice in ("execute_once", "allow_always"):
            request = self.request(choice)
            response = await self.app.api_action_decision(request)
            self.assertEqual(response.status, 200)
            self.app._check_csrf.assert_called_with(request, self.session)
            self.app._sensitive_totp.assert_called_with(self.session, {"decision": choice, "totp": "123456"})
            self.assertEqual(self.decide.await_args.kwargs["action_id"], "act-explicit")
            self.assertEqual(self.decide.await_args.kwargs["actor_id"], "admin")

    async def test_totp_failure_and_csrf_failure_never_reach_decision(self):
        self.app._sensitive_totp.return_value = {"ok": False, "error": "totp_invalid"}
        self.assertEqual((await self.app.api_action_decision(self.request("execute_once"))).status, 401)
        self.decide.assert_not_awaited()
        self.app._check_csrf.side_effect = web.HTTPForbidden()
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_action_decision(self.request("reject"))
        self.decide.assert_not_awaited()

    async def test_nonadmin_session_cannot_claim_admin_in_body(self):
        self.session["is_admin"] = False
        request = self.request("allow_always")
        request.json.return_value["is_admin"] = True
        await self.app.api_action_decision(request)
        self.assertFalse(self.decide.await_args.kwargs["is_admin"])

    async def test_rejection_does_not_require_execution_totp(self):
        await self.app.api_action_decision(self.request("reject"))
        self.app._sensitive_totp.assert_not_called()

    async def test_bad_or_failed_decisions_are_readable(self):
        self.assertEqual((await self.app.api_action_decision(self.request("unknown"))).status, 400)
        self.decide.assert_not_awaited()
        self.decide.side_effect = ActionError("admin_required")
        response = await self.app.api_action_decision(self.request("allow_always"))
        self.assertIn("管理员", json.loads(response.body)["message"])

    async def test_legacy_execute_and_reject_share_decision_service(self):
        request = self.request("execute_once")
        await self.app.api_action_approve(request)
        self.assertEqual(self.decide.await_args.args, ("execute_once",))
        self.assertEqual(self.decide.await_args.kwargs["action_id"], "act-explicit")
        await self.app.api_action_reject(request)
        self.assertEqual(self.decide.await_args.args, ("reject",))

    async def test_console_human_reason_and_cooldown_share_readable_source(self):
        waiting = {"generation": 2, "reason": "冷却中", "retry_at": 123}
        incident = {
            "status": "open", "stage": "watching", "generation": 2,
            "events": [{"type": "agent_waiting", "at": 100, "payload_json": json.dumps(waiting)}],
        }
        summary = self.app._incident_human_summary(incident, None)
        self.assertEqual(summary["automation_wait"], {"reason": "冷却中", "retry_at": 123})
        incident["generation"] = 3
        self.assertIsNone(self.app._incident_human_summary(incident, None)["automation_wait"])
        incident.update({"need_human": True, "need_human_reason": "awaiting_approval:act_hidden decision=automatic rule=rb_hidden"})
        summary = self.app._incident_human_summary(incident, None)
        self.assertIn("等待授权", summary["why_human"])
        self.assertNotIn("act_hidden", summary["why_human"])


if __name__ == "__main__":
    unittest.main()
