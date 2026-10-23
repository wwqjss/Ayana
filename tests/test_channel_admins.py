"""Optional channel administrators never become cross-channel execution rights."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from aiohttp import web

from ayana.actions import ActionService
from ayana.db import Database, now
from ayana.messagelog import MessageLog
from ayana.msgentry import parse_entry
from ayana.notify_channels import ChannelStore
from ayana.policy import Policy
from ayana.qqbot import QQBot
from ayana.web import WebApp
from ayana.wecom_bot import WeComBot


class ChannelAdminTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / ".test-tmp"
        root.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="channel-admins-", dir=root)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.db.close)
        self.store = ChannelStore(self.db, master_key="test-key" * 4)
        self.first = self.store.create(name="一号", kind="wecom_aibot", config={"targets": ["group1"]}, secret={"bot_id": "bot1", "secret": "test"})
        self.second = self.store.create(name="二号", kind="wecom_aibot", secret={"bot_id": "bot2", "secret": "test"})
        self.bot = QQBot(self.db, Mock(), Mock(), Mock(), Mock(), Mock(), Mock(), channel_store=self.store)

    async def test_default_empty_and_explicit_ids_persist_without_granting_execution_permissions(self):
        self.assertEqual(self.first["config"]["admin_user_ids"], [])
        result = self.store.set_admin_user_ids(self.first["id"], ["user1", " user1 ", "user2"], actor="admin")
        self.assertEqual(result["config"]["admin_user_ids"], ["user1", "user2"])
        self.assertEqual(self.db.query_one("SELECT COUNT(*) AS n FROM permissions")["n"], 0)
        self.assertEqual(self.db.query_one("SELECT actor_id FROM audit_log WHERE entry='notify_channel_admins_updated'")["actor_id"], "admin")
        self.store.update(self.first["id"], config={"targets": ["group2"]})
        self.assertEqual(self.store.get_meta(self.first["id"])["config"]["admin_user_ids"], ["user1", "user2"])
        self.store.set_targets(self.first["id"], ["group3"])
        self.assertTrue(self.store.is_aibot_admin(self.first["id"], "user1"))
        self.store.set_admin_user_ids(self.first["id"], [])
        self.assertFalse(self.store.is_aibot_admin(self.first["id"], "user1"))

    async def test_generic_channel_configuration_normalizes_admin_user_ids(self):
        self.store.update(self.first["id"], config={"targets": [], "admin_user_ids": "alice,bob；alice"})
        self.assertEqual(self.store.get_meta(self.first["id"])["config"]["admin_user_ids"], ["alice", "bob"])

    async def test_candidates_are_observed_senders_from_this_channel_not_group_ids(self):
        self.store.record_seen_target(self.first["id"], target_id="group1", userid="alice", chattype="group")
        self.store.record_seen_target(self.second["id"], target_id="group2", userid="other", chattype="group")
        MessageLog(self.db).record(direction="in", platform="wecom", channel_id=self.first["id"], sender="bob", target="group1", body="查询状态")
        self.assertEqual(self.store.list_seen_users(self.first["id"]), ["alice", "bob"])

    async def test_admin_status_uses_exact_channel_and_immediate_revocation(self):
        self.store.set_admin_user_ids(self.first["id"], ["alice"])
        self.assertTrue(self.bot._is_channel_admin("wecom_user", "alice", self.first["id"]))
        self.assertFalse(self.bot._is_channel_admin("wecom_user", "alice", self.second["id"]))
        self.assertFalse(self.bot._is_channel_admin("wecom_user", "alice"))
        self.assertFalse(self.bot._is_channel_admin("qq_user", "alice", self.first["id"]))
        self.store.set_enabled(self.first["id"], False)
        self.assertFalse(self.bot._is_channel_admin("wecom_user", "alice", self.first["id"]))

    async def test_authenticated_inbound_passes_actual_channel_not_message_text(self):
        self.store.set_admin_user_ids(self.first["id"], ["alice"])
        decide = AsyncMock(return_value={"decision": "allow_always", "permanent_granted": True})
        inbound = WeComBot(self.bot, SimpleNamespace(send_text=AsyncMock(return_value=(True, ""))))
        frame = {"cmd": "aibot_msg_callback", "body": {"msgtype": "text", "text": {"content": "永久允许执行"}, "from": {"userid": "alice"}, "channel_id": self.first["id"]}}
        with patch("ayana.qqbot.ApprovalService", return_value=SimpleNamespace(decide=decide)):
            await inbound.on_channel_frame(self.first["id"], frame)
            self.assertTrue(decide.await_args.kwargs["is_admin"])
            await inbound.on_channel_frame(self.second["id"], frame)
            self.assertFalse(decide.await_args.kwargs["is_admin"])

    async def test_optional_admin_role_does_not_override_actor_execution_denial(self):
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES('nerv','nerv','nerv','nerv',?,?)", (now(), now()))
        self.db.execute("INSERT INTO objects(id,asset_id,kind,name,unit,created_at) VALUES('obj1','nerv','service','frps','frps',?)", (now(),))
        policy = Policy(self.db)
        policy.upsert_permission(subject_type="auto_rule", subject_id="agent", asset_id="nerv", object_id="obj1", capability="service.restart", allow=True, auto_allowed=False)
        actions = ActionService(self.db, None, Mock(), policy, Mock())
        action = actions.propose(asset_id="nerv", object_id="obj1", capability="service.restart", proposer_type="auto_rule", proposer_id="agent", runbook_id="rb-test")
        self.bot.actions = actions
        self.store.set_admin_user_ids(self.first["id"], ["alice"])
        reply = await self.bot._handle_approval(parse_entry("永久允许执行"), user_id="alice", actor_type="wecom_user", channel_id=self.first["id"])
        self.assertIn("权限", reply)
        self.assertEqual(actions.get_action(action["id"])["state"], "proposed")
        self.assertEqual(self.db.query_one("SELECT auto_allowed FROM permissions WHERE subject_type='auto_rule'")["auto_allowed"], 0)

    async def test_web_admin_save_requires_admin_session_and_csrf(self):
        app = WebApp(self.db, Mock(), Mock(), Mock(), Mock(), Mock(), Mock(), static_dir=Path("."), channel_store=self.store)
        session = {"username": "admin", "is_admin": True}
        app._require_auth = Mock(return_value=session)
        app._check_csrf = Mock()
        request = SimpleNamespace(json=AsyncMock(return_value={"id": self.first["id"], "admin_user_ids": ["alice"]}), rel_url=SimpleNamespace(query={"channel_id": self.first["id"]}))
        self.assertEqual((await app.api_notify_aibot_admins_save(request)).status, 200)
        app._check_csrf.assert_called_once_with(request, session)
        self.assertEqual(json.loads((await app.api_notify_aibot_admins(request)).body)["selected"], ["alice"])
        app._check_csrf.side_effect = web.HTTPForbidden()
        request.json.return_value["admin_user_ids"] = ["bob"]
        with self.assertRaises(web.HTTPForbidden):
            await app.api_notify_aibot_admins_save(request)
        self.assertTrue(self.store.is_aibot_admin(self.first["id"], "alice"))
        session["is_admin"] = False
        with self.assertRaises(web.HTTPForbidden):
            await app.api_notify_aibot_admins_save(request)
        with self.assertRaises(web.HTTPForbidden):
            await app.api_notify_aibot_admins(request)


if __name__ == "__main__":
    unittest.main()
