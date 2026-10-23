"""Regression coverage for cross-entry permissions, revocation and notification recovery."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ayana.config import load_config, write_secrets_template
from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.notify import Notifier
from ayana.policy import Policy
from ayana.qqbot import QQBot
from ayana.transport import SSHAssetStore
from ayana.web import WebApp, web


class ReviewWebNotifyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.close)
        self.policy = Policy(self.db)
        self.incidents = IncidentService(self.db)
        self.ssh = SSHAssetStore(self.db)
        for aid in ("a", "b"):
            self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                            (aid, aid, aid, aid + "-exec", now(), now()))
            self.db.execute("INSERT INTO incidents(id,title,asset_id,status,stage,created_at,updated_at)"
                            " VALUES(?,?,?,'open','pending',?,?)", ("inc-" + aid, "secret-" + aid, aid, now(), now()))
            self.ssh.upsert_endpoint(asset_id=aid, role="read", host="host-" + aid, username="root")
        self.sess = {"username": "reader", "is_admin": False}
        self.policy.upsert_permission(subject_type="web_user", subject_id="reader", capability="asset.summary",
                                      asset_id="a", allow=True)
        actions = SimpleNamespace(get_action=lambda aid: {"id": aid, "asset_id": "b"}, list_actions=lambda **kw: [])
        prom = SimpleNamespace(targets=self.empty_targets)
        self.app = WebApp(self.db, None, self.policy, self.incidents, None, actions, prom,
                          static_dir=Path(self.tmp.name), ssh_store=self.ssh)
        self.app._require_auth = lambda req: self.sess
        self.app._check_csrf = lambda *args: None
        self.app._prom_business_items = self.empty_business

    async def empty_targets(self):
        return []

    async def empty_business(self, asset):
        return [], ""

    def request(self, **match):
        return SimpleNamespace(match_info=match, rel_url=SimpleNamespace(query={}), headers={},
                               json=self.empty_body)

    async def empty_body(self):
        return {}

    async def test_hidden_details_and_endpoints_denied(self):
        for handler, match in ((self.app.api_incident_detail, {"inc_id": "inc-b"}),
                               (self.app.api_action_detail, {"aid": "act-b"}),
                               (self.app.api_asset_detail, {"asset_id": "b"})):
            response = await handler(self.request(**match))
            self.assertEqual(response.status, 403)
        req = self.request()
        req.rel_url.query = {"asset_id": "b"}
        self.assertEqual((await self.app.api_ssh_endpoints(req)).status, 403)
        response = await self.app.api_ssh_endpoints(self.request())
        self.assertEqual([ep["asset_id"] for ep in json.loads(response.body)["endpoints"]], ["a"])

    async def test_reader_cannot_close_incident(self):
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_incident_close(self.request(inc_id="inc-a"))
        self.assertEqual(self.incidents.get_incident("inc-a")["status"], "open")

    async def test_loops_and_overview_hide_unavailable_assets(self):
        response = await self.app.api_loops(self.request())
        self.assertEqual([inc["asset_id"] for inc in json.loads(response.body)["loops"]], ["a"])
        response = await self.app.api_overview(self.request())
        data = json.loads(response.body)
        self.assertEqual([inc["asset_id"] for inc in data["open_incidents"]], ["a"])
        self.assertIsNone(data["health_ratio"]["ratio"])
        self.assertEqual(data["health_ratio"]["color"], "dim")

    def test_message_incidents_are_filtered_for_qq_and_wecom(self):
        bot = QQBot.__new__(QQBot)
        bot.db, bot.policy, bot.incidents = self.db, self.policy, self.incidents
        for actor_type in ("qq_user", "wecom_user"):
            self.policy.upsert_permission(subject_type=actor_type, subject_id="reader", capability="asset.summary",
                                          asset_id="a", allow=True)
            self.assertNotIn("secret-b", bot._incident_text("", actor_type, "reader"))
            self.assertNotIn("secret-b", bot._incident_text("inc-b", actor_type, "reader"))
            self.assertNotIn("secret-b", bot._status_text(actor_type, "reader"))
            self.assertIn("secret-a", bot._incident_text("inc-a", actor_type, "reader"))

    async def test_terminal_rechecks_policy_before_input(self):
        self.sess = {"username": "admin", "is_admin": True}
        self.policy.upsert_permission(subject_type="web_user", subject_id="admin", capability="shell.interactive",
                                      asset_id="a", allow=True, require_approval=False)
        writes, closed, sent = [], [], []
        app = self.app
        class Socket:
            def __init__(self, **kwargs):
                self.closed = False
            async def prepare(self, req):
                pass
            async def send_json(self, data):
                sent.append(data)
            async def close(self, **kwargs):
                self.closed = True
            def __aiter__(self):
                return self
            async def __anext__(self):
                if self.closed:
                    raise StopAsyncIteration
                app.policy.upsert_permission(subject_type="web_user", subject_id="admin", capability="shell.interactive",
                                             asset_id="a", allow=False)
                return SimpleNamespace(type=web.WSMsgType.BINARY, data=b"id\n")
        tsess = SimpleNamespace(session_id="terminal-1", write=writes.append, alive=lambda: True,
                                read=lambda: b"", close_reason="", resize=lambda *args: None)
        async def create(**kwargs):
            return tsess, {}
        app.terminal = SimpleNamespace(create=create, close=lambda *args, **kwargs: closed.append(kwargs))
        app._session = lambda req: self.sess
        req = self.request()
        req.rel_url.query = {"asset_id": "a"}
        with patch.object(web, "WebSocketResponse", Socket):
            await app.ws_terminal(req)
        self.assertEqual(writes, [])
        self.assertTrue(closed)
        self.assertTrue(any(item.get("error") == "permission_revoked" for item in sent))

    def routes(self):
        return SimpleNamespace(list_enabled=lambda: [
            {"id": "c1", "kind": "qq", "targets": ["user:1"]},
            {"id": "c2", "kind": "wecom_aibot", "targets": ["group:1", "group:2"]},
        ])

    async def test_idle_terminal_closes_when_permission_is_revoked(self):
        self.sess = {"username": "admin", "is_admin": True}
        self.policy.upsert_permission(subject_type="web_user", subject_id="admin", capability="shell.interactive",
                                      asset_id="a", allow=True, require_approval=False)
        closed_event = asyncio.Event()
        sent, closed = [], []
        app = self.app
        class Socket:
            def __init__(self, **kwargs):
                self.closed = False
            async def prepare(self, req):
                pass
            async def send_json(self, data):
                sent.append(data)
                if data.get("type") == "ready":
                    app.policy.upsert_permission(subject_type="web_user", subject_id="admin", capability="shell.interactive",
                                                 asset_id="a", allow=False)
            async def close(self, **kwargs):
                self.closed = True
                closed_event.set()
            def __aiter__(self):
                return self
            async def __anext__(self):
                await closed_event.wait()
                raise StopAsyncIteration
        tsess = SimpleNamespace(session_id="idle-terminal", alive=lambda: True, read=lambda: b"", close_reason="")
        async def create(**kwargs):
            return tsess, {}
        app.terminal = SimpleNamespace(create=create, close=lambda *args, **kwargs: closed.append(kwargs))
        app._session = lambda req: self.sess
        req = self.request()
        req.rel_url.query = {"asset_id": "a"}
        with patch.object(web, "WebSocketResponse", Socket):
            await asyncio.wait_for(app.ws_terminal(req), timeout=2)
        self.assertTrue(any(item.get("error") == "permission_revoked" for item in sent))
        self.assertTrue(any(item.get("reason") == "permission_revoked" for item in closed))

    def event(self):
        self.db.event("incident_opened", incident_id="inc-a", payload={"body": "alert"})
        return self.db.query_one("SELECT MAX(id) AS id FROM events")["id"]

    def test_notification_compensation_repairs_partial_channels_and_targets(self):
        notifier = Notifier(self.db)
        notifier.set_channel_store(self.routes())
        event_id = self.event()
        notifier.enqueue(dedup_key=f"ev:{event_id}:c1", target="user:1", body="alert", channel_id="c1")
        notifier.enqueue(dedup_key=f"ev:{event_id}:c2:group:1", target="group:1", body="alert", channel_id="c2")
        self.assertEqual(notifier.compensate_missing(), 1)
        self.assertEqual(len(notifier.outbox_summary()), 3)
        self.assertEqual(notifier.compensate_missing(), 0)

    def test_notification_fanout_is_atomic_on_insert_failure(self):
        notifier = Notifier(self.db)
        notifier.set_channel_store(self.routes())
        event_id = self.event()
        execute = self.db.execute
        def fail_second(sql, params=()):
            if "notification_outbox" in sql and "INSERT" in sql and params[-1] == "c2":
                raise RuntimeError("transient insertion failure")
            return execute(sql, params)
        with patch.object(self.db, "execute", fail_second):
            self.assertFalse(notifier.enqueue_for_event(event_id, body="alert"))
        self.assertEqual(notifier.outbox_summary(), [])
        self.assertEqual(notifier.compensate_missing(), 1)
        self.assertEqual(len(notifier.outbox_summary()), 3)

    def test_notify_key_file_environment_and_template(self):
        base = Path(self.tmp.name)
        (base / "secrets.json").write_text(json.dumps({"onewbot_token": "test", "webhook_token": "test",
                                                      "notify_channel_key": "file-key"}), encoding="utf-8")
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(load_config(base)["notify_channel_key"], "file-key")
        with patch.dict(os.environ, {"AYANA_NOTIFY_CHANNEL_KEY": "env-key"}):
            self.assertEqual(load_config(base)["notify_channel_key"], "env-key")
        write_secrets_template(base / "template.json")
        self.assertIn("notify_channel_key", json.loads((base / "template.json").read_text()))

    def test_channel_lookup_failure_retries_real_channels(self):
        notifier = Notifier(self.db)
        channels = self.routes()
        notifier.set_channel_store(channels)
        event_id = self.event()
        with patch.object(channels, "list_enabled", side_effect=RuntimeError("temporary lookup failure")):
            self.assertFalse(notifier.enqueue_for_event(event_id, body="alert"))
            self.assertEqual(notifier.compensate_missing(), 0)
        self.assertEqual(notifier.outbox_summary(), [])
        self.assertEqual(notifier.compensate_missing(), 1)
        self.assertEqual(len(notifier.outbox_summary()), 3)

    def test_original_notification_plan_survives_target_and_channel_changes(self):
        notifier = Notifier(self.db)
        routes = [{"id": "c1", "kind": "qq", "targets": ["user:1"]}]
        notifier.set_channel_store(SimpleNamespace(list_enabled=lambda: routes))
        event_id = self.event()
        self.assertTrue(notifier.enqueue_for_event(event_id, body="alert"))
        routes[0]["targets"] = ["user:1", "user:2"]
        routes.append({"id": "c2", "kind": "qq", "targets": ["user:3"]})
        self.assertEqual(notifier.compensate_missing(), 0)
        self.assertEqual([row["target"] for row in notifier.outbox_summary()], ["user:1"])

    def test_legacy_short_key_does_not_duplicate_an_existing_target(self):
        notifier = Notifier(self.db)
        event_id = self.event()
        notifier.enqueue(dedup_key=f"ev:{event_id}:c1", target="user:1", body="alert", channel_id="c1")
        notifier.set_channel_store(SimpleNamespace(list_enabled=lambda: [
            {"id": "c1", "kind": "qq", "targets": ["user:1", "user:2"], "updated_at": now() + 1},
        ]))
        self.assertEqual(notifier.compensate_missing(), 0)
        self.assertEqual(len(notifier.outbox_summary()), 1)

    def test_failed_fanout_keeps_original_recipients_for_compensation(self):
        notifier = Notifier(self.db)
        routes = [{"id": "c1", "kind": "qq", "targets": ["user:1"]}]
        notifier.set_channel_store(SimpleNamespace(list_enabled=lambda: routes))
        event_id = self.event()
        with patch.object(notifier, "_insert_outbox", side_effect=RuntimeError("temporary insertion failure")):
            self.assertFalse(notifier.enqueue_for_event(event_id, body="alert"))
        routes[0]["targets"] = ["user:2"]
        self.assertEqual(notifier.compensate_missing(), 1)
        self.assertEqual([row["target"] for row in notifier.outbox_summary()], ["user:1"])

    def test_legacy_partial_multitarget_recovers_after_a_channel_rename(self):
        notifier = Notifier(self.db)
        event_id = self.event()
        notifier.enqueue(dedup_key=f"ev:{event_id}:c1:group:1", target="group:1", body="alert",
                         channel="wecom_aibot", channel_id="c1")
        notifier.set_channel_store(SimpleNamespace(list_enabled=lambda: [
            {"id": "c1", "kind": "wecom_aibot", "targets": ["group:1", "group:2"],
             "name": "renamed", "updated_at": now() + 1},
        ]))
        self.assertEqual(notifier.compensate_missing(), 1)
        self.assertEqual(sorted(row["target"] for row in notifier.outbox_summary()), ["group:1", "group:2"])

    def test_old_fallback_row_does_not_hide_missing_configured_channels(self):
        notifier = Notifier(self.db)
        event_id = self.event()
        # 历史遗留行：无 channel_id 的 QQ 兜底（手动插入，模拟升级前数据）
        self.db.execute(
            "INSERT INTO notification_outbox(id, dedup_key, channel, target, body, state,"
            " created_at, last_try_at, next_try_at, channel_id)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("ntf-legacy", f"ev:{event_id}", "qq", "user:1", "alert", "sent",
             now(), 0, 0, ""),
        )
        notifier.set_channel_store(self.routes())
        self.assertEqual(notifier.compensate_missing(), 1)
        self.assertEqual(len(notifier.outbox_summary()), 3)
        self.assertEqual(sum(row["target"] == "user:1" for row in notifier.outbox_summary()), 1)


if __name__ == "__main__":
    unittest.main()
