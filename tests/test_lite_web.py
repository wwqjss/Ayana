"""Lightweight mode remains headless even when MiMo objects are available."""
from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from aiohttp import web
from ayana.access import AccessControl
from ayana.auth import AuthService
from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.llm import LLMClient
from ayana.session_bridge import SessionBridge
from ayana.web import SESSION_COOKIE, WebApp


class Request:
    def __init__(self, sid, csrf, body=None, session_id=""):
        self.cookies = {SESSION_COOKIE: sid}
        self.headers = {"X-CSRF-Token": csrf, "User-Agent": "test"}
        self.remote = "127.0.0.1"
        self.rel_url = SimpleNamespace(path="/api/agent/sessions", query={})
        self.match_info = {"sid": session_id}
        self.method = "POST"
        self.body = body if body is not None else {}

    async def json(self):
        return self.body


class LiteWebTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.db = Database(Path(tmp.name) / "test.db")
        self.addCleanup(self.db.close)
        self.auth = AuthService(self.db, pepper="test", session_ttl=3600, max_failed=5, lockout=60)
        self.auth.ensure_bootstrap_admin("admin")
        self.auth.change_password(1, "", "test-new-password")
        login = self.auth.login("admin", "test-new-password")
        self.sid = login["session_id"]
        self.csrf = self.auth.get_session(self.sid)["csrf_token"]
        self.duty = DutySessionManager(self.db)
        self.session_id = self.duty.create(origin="manual", created_by="admin")["session_id"]
        self.llm = LLMClient("test-secret-key", "https://models.example.test/v1", "test-model")
        self.mimo = Mock()
        self.mimo.status = AsyncMock(side_effect=AssertionError("MiMo must not be inspected"))
        self.serve = Mock()
        self.tui = Mock()
        self.app = WebApp(self.db, self.auth, AccessControl(self.db), None, None, None, None,
                          static_dir=Path(tmp.name), llm=self.llm, agent_mode="lite",
                          duty=self.duty, session_bridge=SessionBridge(self.db, duty=self.duty),
                          mimo_admin=self.mimo, mimo_serve=self.serve, agent_tui=self.tui)

    def req(self, body=None):
        return Request(self.sid, self.csrf, body, self.session_id)

    async def test_health_and_authenticated_state_report_lite_capabilities(self):
        health = json.loads((await self.app.health(self.req())).text)
        self.assertEqual(health["agent_mode"], "lite")
        me = json.loads((await self.app.api_me(self.req())).text)
        self.assertFalse(me["capabilities"]["interactive_agent"])
        self.assertTrue(me["capabilities"]["automatic_duty"])

    async def test_native_entrypoints_are_rejected_without_creating_or_dispatching(self):
        routes = ["api_agent_session_create", "api_agent_session_prompt", "api_agent_session_abort",
                  "api_agent_session_recover", "api_agent_session_reopen", "api_agent_terminal_prepare",
                  "api_agent_terminal_status", "api_agent_terminal_control", "ws_agent_terminal",
                  "api_mimo_chat", "api_mimo_start", "api_mimo_stop", "api_mimo_restart"]
        before = len(self.duty.list_sessions())
        for name in routes:
            with self.subTest(route=name), self.assertRaises(web.HTTPConflict) as caught:
                await getattr(self.app, name)(self.req({"prompt": "do not execute"}))
            self.assertEqual(json.loads(caught.exception.text)["error"], "interactive_agent_disabled")
        self.assertEqual(len(self.duty.list_sessions()), before)
        self.assertEqual(self.serve.mock_calls, [])
        self.assertEqual(self.tui.mock_calls, [])
        self.assertEqual(self.mimo.mock_calls, [])

    async def test_history_is_readable_without_contacting_mimo(self):
        self.db.execute("UPDATE duty_sessions SET remote_session_id='old-native-id' WHERE id=?", (self.session_id,))
        sessions = json.loads((await self.app.api_agent_sessions(self.req())).text)
        self.assertEqual(sessions["agent_mode"], "lite")
        detail = json.loads((await self.app.api_agent_session_detail(self.req())).text)
        for key in ("can_prepare", "can_control", "can_recover"):
            self.assertFalse(detail[key])
        self.assertIsNone(detail["runtime"])
        self.assertEqual(self.serve.mock_calls, [])
        self.assertEqual(self.tui.mock_calls, [])

    async def test_optional_mimo_and_about_never_report_required_install(self):
        status = json.loads((await self.app.api_mimo_status(self.req())).text)
        self.assertFalse(status["required"])
        self.assertIn("不需要", status["message"])
        about = json.loads((await self.app.api_settings_about(self.req())).text)
        self.assertEqual(about["mimocode_version"], "轻量模式无需安装")
        skills = json.loads((await self.app.api_settings_skills(self.req())).text)
        self.assertEqual(skills["items"], [])
        self.assertEqual(self.mimo.mock_calls, [])

    async def test_model_probe_uses_saved_key_only_for_same_endpoint_and_never_saves(self):
        body = {"llm_base_url": self.llm.base_url, "llm_model": "new-model", "llm_api_key": ""}
        with patch.object(LLMClient, "chat_raw", new=AsyncMock(return_value={"content": "OK"})) as chat:
            response = await self.app.api_settings_model_test(self.req(body))
        self.assertTrue(json.loads(response.text)["ok"])
        chat.assert_awaited_once()
        self.assertIsNone(self.db.query_one("SELECT value FROM meta WHERE key='llm_model'"))
        self.assertEqual(self.llm.model, "test-model")
        body["llm_base_url"] = "https://different.example.test/v1"
        with patch.object(LLMClient, "chat_raw", new=AsyncMock()) as chat:
            response = await self.app.api_settings_model_test(self.req(body))
        self.assertEqual(response.status, 400)
        chat.assert_not_awaited()

    async def test_model_probe_blocks_private_endpoints_and_redacts_failures(self):
        for base in ("http://127.0.0.1:6200", "https://169.254.169.254/v1"):
            with self.subTest(base=base), patch.object(LLMClient, "chat_raw", new=AsyncMock()) as chat:
                response = await self.app.api_settings_model_test(self.req({"llm_base_url": base, "llm_model": "m", "llm_api_key": "test-secret-key"}))
                self.assertEqual(response.status, 400)
                chat.assert_not_awaited()
        with patch.object(LLMClient, "chat_raw", new=AsyncMock(return_value={"error": "private test-secret-key"})):
            response = await self.app.api_settings_model_test(self.req({"llm_base_url": self.llm.base_url, "llm_model": "m"}))
        self.assertEqual(response.status, 502)
        self.assertNotIn("test-secret-key", response.text)

    async def test_lite_save_retains_key_but_refuses_sending_it_to_new_endpoint(self):
        response = await self.app.api_settings_global_post(self.req({"llm_base_url": "https://different.example.test/v1", "llm_model": "m", "llm_api_key": ""}))
        self.assertEqual(response.status, 400)
        self.assertEqual(self.llm.base_url, "https://models.example.test/v1")
        response = await self.app.api_settings_global_post(self.req({"llm_base_url": self.llm.base_url, "llm_model": "new", "llm_api_key": ""}))
        self.assertTrue(json.loads(response.text)["ok"])
        self.assertEqual(self.llm.api_key, "test-secret-key")
        self.assertNotIn("test-secret-key", response.text)

    async def test_default_mimo_mode_retains_manual_sessions(self):
        self.app.agent_mode = "mimo"
        response = await self.app.api_agent_session_create(self.req({"title": "manual"}))
        self.assertTrue(json.loads(response.text)["ok"])
        self.assertTrue(self.app._agent_capabilities()["capabilities"]["manual_sessions"])

    async def test_model_settings_are_one_atomic_provider_snapshot(self):
        old = {"llm_base_url": self.llm.base_url, "llm_model": self.llm.model, "llm_api_key": self.llm.api_key}
        new = {"llm_base_url": "https://new.example.test/v1", "llm_model": "new-model", "llm_api_key": "new-test-key"}
        for key, value in old.items():
            self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        observed = []
        original_tx = self.db.tx
        def snapshot():
            with sqlite3.connect(Path(self.db.path).resolve().as_uri() + "?mode=ro", uri=True) as reader:
                return dict(reader.execute("SELECT key,value FROM meta WHERE key IN ('llm_base_url','llm_model','llm_api_key')").fetchall())
        @contextmanager
        def observing_tx():
            with original_tx() as conn:
                class Connection:
                    def __getattr__(self, name):
                        return getattr(conn, name)
                    def execute(self, sql, params=()):
                        cursor = conn.execute(sql, params)
                        if sql.startswith("INSERT INTO meta") and params[0] in old:
                            observed.append(snapshot())
                        return cursor
                yield Connection()
        with patch.object(self.db, "tx", observing_tx):
            response = await self.app.api_settings_global_post(self.req(new))
        self.assertTrue(json.loads(response.text)["ok"])
        self.assertEqual(observed, [old, old, old])
        self.assertEqual(snapshot(), new)

    async def test_failed_model_save_rolls_back_every_provider_field(self):
        old = {"llm_base_url": self.llm.base_url, "llm_model": self.llm.model, "llm_api_key": self.llm.api_key}
        for key, value in old.items():
            self.db.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        original_tx = self.db.tx
        @contextmanager
        def failing_tx():
            with original_tx() as conn:
                class Connection:
                    def __getattr__(self, name):
                        return getattr(conn, name)
                    def execute(self, sql, params=()):
                        if sql.startswith("INSERT INTO meta") and params[0] == "llm_model":
                            raise RuntimeError("simulated storage failure")
                        return conn.execute(sql, params)
                yield Connection()
        with patch.object(self.db, "tx", failing_tx), self.assertRaises(RuntimeError):
            await self.app.api_settings_global_post(self.req({"llm_base_url": "https://new.example.test/v1", "llm_model": "new", "llm_api_key": "new-test-key"}))
        actual = {row["key"]: row["value"] for row in self.db.query("SELECT key,value FROM meta WHERE key IN ('llm_base_url','llm_model','llm_api_key')")}
        self.assertEqual(actual, old)
        self.assertEqual(self.llm.base_url, old["llm_base_url"])


if __name__ == "__main__":
    unittest.main()
