"""一次性 Token 注册管理员：不得仅凭用户数为 0 开放注册。"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.auth import AuthError, AuthService
from ayana.db import Database
from ayana.policy import Policy
from ayana.web import SESSION_COOKIE, WebApp


def make_auth(db: Database) -> AuthService:
    return AuthService(db, pepper="pepper", session_ttl=3600, max_failed=5, lockout=60)


class SetupStateGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.db.close)
        self.addCleanup(self.tmp.cleanup)
        self.auth = make_auth(self.db)

    def test_fresh_install_opens_pending_with_token(self):
        info = self.auth.ensure_setup_initialized()
        self.assertEqual(info["state"], "pending")
        self.assertTrue(info["token"])
        self.assertEqual(self.auth.setup_state(), "pending")
        self.assertTrue(self.auth.verify_setup_token(info["token"]))

    def test_users_exist_forces_completed_even_without_meta(self):
        self.auth.create_user("boss", "password-boss-1", is_admin=True)
        # 模拟 meta 丢失/迁移异常
        self.db.execute("DELETE FROM meta WHERE key='setup_state'")
        info = self.auth.ensure_setup_initialized()
        self.assertEqual(info["state"], "completed")
        self.assertFalse(info["token"])
        self.assertEqual(self.auth.setup_state(), "completed")

    def test_completed_state_never_reopens_on_empty_db(self):
        self.auth._set_setup_state("completed")
        # 用户被清空也不得仅凭 count=0 重开
        info = self.auth.ensure_setup_initialized()
        self.assertEqual(info["state"], "completed")
        self.assertFalse(info["token"])

    def test_pending_with_users_auto_closes(self):
        self.auth.ensure_setup_initialized()
        self.auth.create_user("x", "password-xxxxxx", is_admin=True)
        info = self.auth.ensure_setup_initialized()
        self.assertEqual(info["state"], "completed")

    def test_register_requires_token_not_empty_users_alone(self):
        self.auth.ensure_setup_initialized()
        with self.assertRaises(AuthError) as ctx:
            self.auth.register_admin("", "admin", "brand-new-password")
        self.assertEqual(ctx.exception.code, "bad_token")

    def test_register_wrong_token(self):
        info = self.auth.ensure_setup_initialized()
        with self.assertRaises(AuthError) as ctx:
            self.auth.register_admin("not-the-token", "admin", "brand-new-password")
        self.assertEqual(ctx.exception.code, "bad_token")
        self.assertTrue(self.auth.verify_setup_token(info["token"]))

    def test_register_success_closes_and_consumes_token(self):
        info = self.auth.ensure_setup_initialized()
        sess = self.auth.register_admin(info["token"], "opsroot", "brand-new-password")
        self.assertIn("session_id", sess)
        self.assertEqual(self.auth.setup_state(), "completed")
        self.assertEqual(self.auth.user_count(), 1)
        row = self.db.query_one("SELECT username, is_admin, must_change_password FROM users")
        self.assertEqual(row["username"], "opsroot")
        self.assertEqual(row["is_admin"], 1)
        self.assertEqual(row["must_change_password"], 0)
        # token 一次性
        with self.assertRaises(AuthError):
            self.auth.register_admin(info["token"], "hacker", "brand-new-password")

    def test_register_rejects_bad_username_and_short_password(self):
        info = self.auth.ensure_setup_initialized()
        with self.assertRaises(AuthError) as ctx:
            self.auth.register_admin(info["token"], "a", "brand-new-password")
        self.assertEqual(ctx.exception.code, "bad_username")
        with self.assertRaises(AuthError) as ctx:
            self.auth.register_admin(info["token"], "goodname", "short")
        self.assertEqual(ctx.exception.code, "weak_password")

    def test_register_when_state_not_pending(self):
        self.auth._set_setup_state("completed")
        with self.assertRaises(AuthError) as ctx:
            self.auth.register_admin("any", "admin", "brand-new-password")
        self.assertEqual(ctx.exception.code, "setup_closed")


class _FakeRequest:
    def __init__(self, body=None, *, cookies=None, headers=None, remote="127.0.0.1", method="POST", path="/api/setup/register"):
        self._body = body if body is not None else {}
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.remote = remote
        self.method = method
        self.rel_url = SimpleNamespace(path=path, query={})

    async def json(self):
        return self._body


class SetupRegisterApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.db.close)
        self.addCleanup(self.tmp.cleanup)
        self.auth = make_auth(self.db)
        static = Path(self.tmp.name) / "static"
        static.mkdir(exist_ok=True)
        (static / "index.html").write_text("<html></html>", encoding="utf-8")
        self.webapp = WebApp(
            self.db,
            self.auth,
            Policy(self.db),
            None,
            None,
            None,
            None,
            static_dir=static,
            version="test",
        )

    async def test_status_closed_when_no_setup_state(self):
        resp = await self.webapp.api_setup_status(_FakeRequest(path="/api/setup/status"))
        data = json.loads(resp.text)
        self.assertFalse(data["register_open"])

    async def test_status_open_only_pending(self):
        info = self.auth.ensure_setup_initialized()
        resp = await self.webapp.api_setup_status(_FakeRequest(path="/api/setup/status"))
        data = json.loads(resp.text)
        self.assertTrue(data["register_open"])
        self.assertTrue(data["token_hint"])
        self.assertNotIn("token", data)

    async def test_register_api_success_and_session(self):
        info = self.auth.ensure_setup_initialized()
        resp = await self.webapp.api_setup_register(
            _FakeRequest(
                {
                    "token": info["token"],
                    "username": "opsroot",
                    "password": "brand-new-password",
                    "confirm_password": "brand-new-password",
                }
            )
        )
        data = json.loads(resp.text)
        self.assertTrue(data["ok"], data)
        self.assertTrue(data["user"]["is_admin"])
        self.assertFalse(data["user"]["must_change_password"])

    async def test_register_api_mismatch_confirm(self):
        info = self.auth.ensure_setup_initialized()
        resp = await self.webapp.api_setup_register(
            _FakeRequest(
                {
                    "token": info["token"],
                    "username": "opsroot",
                    "password": "brand-new-password",
                    "confirm_password": "different-password",
                }
            )
        )
        data = json.loads(resp.text)
        self.assertEqual(data["error"], "mismatch")

    async def test_register_api_seeds_admin_perms(self):
        info = self.auth.ensure_setup_initialized()
        await self.webapp.api_setup_register(
            _FakeRequest(
                {
                    "token": info["token"],
                    "username": "opsroot",
                    "password": "brand-new-password",
                }
            )
        )
        row = self.db.query_one(
            "SELECT allow FROM permissions WHERE subject_type='web_user'"
            " AND subject_id='opsroot' AND capability='asset.summary'"
        )
        self.assertIsNotNone(row)
        self.assertTrue(row["allow"])


if __name__ == "__main__":
    unittest.main()
