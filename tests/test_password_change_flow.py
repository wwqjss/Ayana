"""首次登录强制改密 / 普通改密 / 恢复码 / 本地管理员恢复 全链路回归。"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.auth import (
    AuthError,
    AuthService,
    generate_totp_secret,
    generate_recovery_codes,
    hash_password,
    hash_recovery_code,
    totp_now,
)
from ayana.db import Database, now
from ayana.web import SESSION_COOKIE, WebApp


def make_auth(db: Database) -> AuthService:
    return AuthService(db, pepper="pepper", session_ttl=3600, max_failed=5, lockout=60)


class PasswordChangeAuthTests(unittest.TestCase):
    """auth.change_password 语义与错误映射。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.close)
        self.auth = make_auth(self.db)
        self.bootstrap = self.auth.ensure_bootstrap_admin("admin")
        self.assertIsNotNone(self.bootstrap)
        self.uid = int(self.db.query_one("SELECT id FROM users WHERE username='admin'")["id"])

    def _err(self, *args, **kwargs) -> AuthError:
        with self.assertRaises(AuthError) as ctx:
            self.auth.change_password(*args, **kwargs)
        return ctx.exception

    def test_first_login_skips_old_password(self):
        """首登（must_change_password=1）只需新密码，不要求旧密。"""
        self.auth.change_password(self.uid, "", "brand-new-password")
        self.assertFalse(self.auth.must_change_password(self.uid))
        self.auth.login("admin", "brand-new-password")

    def test_first_login_ten_digit_password_accepted(self):
        self.auth.change_password(self.uid, "", "1234567890")
        self.auth.login("admin", "1234567890")

    def test_first_login_long_numeric_accepted(self):
        self.auth.change_password(self.uid, "", "12345678901234")
        self.auth.login("admin", "12345678901234")

    def test_first_login_complex_accepted(self):
        pw = "C0mplex!Passw0rd"
        self.auth.change_password(self.uid, "", pw)
        self.auth.login("admin", pw)

    def test_short_password_reports_length_not_old_password(self):
        e = self._err(self.uid, "", "short")
        self.assertEqual(e.code, "weak_password")
        self.assertIn("10", str(e))
        self.assertNotIn("当前密码", str(e))

    def test_empty_new_password_message(self):
        e = self._err(self.uid, "", "")
        self.assertEqual(e.code, "weak_password")
        self.assertEqual(str(e), "请输入新密码")

    def test_wrong_old_reports_current_password_error(self):
        # 先完成首登改密，进入普通改密语义
        self.auth.change_password(self.uid, "", "brand-new-password")
        e = self._err(self.uid, "not-the-password", "another-password")
        self.assertEqual(e.code, "invalid")
        self.assertIn("当前密码错误", str(e))

    def test_empty_old_on_voluntary_change(self):
        self.auth.change_password(self.uid, "", "brand-new-password")
        e = self._err(self.uid, "", "another-password")
        self.assertEqual(e.code, "invalid")
        self.assertIn("请输入当前密码", str(e))

    def test_wrong_old_does_not_change_password(self):
        self.auth.change_password(self.uid, "", "brand-new-password")
        self._err(self.uid, "wrong-old-password", "another-password")
        self.auth.login("admin", "brand-new-password")

    def test_voluntary_change_requires_old(self):
        self.auth.change_password(self.uid, "", "brand-new-password")
        self.auth.change_password(self.uid, "brand-new-password", "third-password-ok")
        self.auth.login("admin", "third-password-ok")

    def test_new_equals_old_rejected_when_old_provided(self):
        self.auth.change_password(self.uid, "", "brand-new-password")
        e = self._err(self.uid, "brand-new-password", "brand-new-password")
        self.assertEqual(e.code, "weak_password")

    def test_unknown_user(self):
        e = self._err(99999, "x", "brand-new-password")
        self.assertEqual(e.code, "no_user")

    def test_forced_change_keeps_session(self):
        sess = self.auth.login("admin", self.bootstrap)
        sid = sess["session_id"]
        self.auth.change_password(
            self.uid, "", "brand-new-password", keep_session_id=sid
        )
        got = self.auth.get_session(sid)
        self.assertIsNotNone(got)
        self.assertFalse(bool(got["must_change_password"]))

    def test_voluntary_change_revokes_sessions(self):
        self.auth.change_password(self.uid, "", "brand-new-password")
        sess = self.auth.login("admin", "brand-new-password")
        sid = sess["session_id"]
        self.auth.change_password(self.uid, "brand-new-password", "third-password-ok")
        self.assertIsNone(self.auth.get_session(sid))

    def test_require_old_override_forces_old_check(self):
        e = self._err(self.uid, "", "brand-new-password", require_old=True)
        self.assertEqual(e.code, "invalid")
        self.assertIn("请输入当前密码", str(e))


class RecoveryAndResetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.close)
        self.auth = make_auth(self.db)
        self.bootstrap = self.auth.ensure_bootstrap_admin("admin")
        self.uid = int(self.db.query_one("SELECT id FROM users WHERE username='admin'")["id"])
        self.auth.change_password(self.uid, "", "brand-new-password")

    def _enable_totp(self):
        setup = self.auth.setup_totp(self.uid, password="brand-new-password")
        code = totp_now(setup["secret"])
        return self.auth.confirm_totp(self.uid, code), setup["secret"]

    def test_recovery_code_replaces_totp(self):
        codes, secret = self._enable_totp()
        self.assertEqual(len(codes), 8)
        res = self.auth.begin_login("admin", "brand-new-password")
        self.assertFalse(res["complete"])
        sess = self.auth.complete_login(res["pending_id"], recovery_code=codes[0])
        self.assertIn("session_id", sess)

    def test_recovery_code_single_use(self):
        codes, _ = self._enable_totp()
        res = self.auth.begin_login("admin", "brand-new-password")
        self.auth.complete_login(res["pending_id"], recovery_code=codes[0])
        res2 = self.auth.begin_login("admin", "brand-new-password")
        with self.assertRaises(AuthError):
            self.auth.complete_login(res2["pending_id"], recovery_code=codes[0])

    def test_recovery_code_format(self):
        codes = generate_recovery_codes(3)
        self.assertEqual(len(codes), 3)
        for c in codes:
            self.assertRegex(c, r"^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$")

    def test_admin_reset_forces_change_and_revokes(self):
        sess = self.auth.login("admin", "brand-new-password")
        new_pw = self.auth.reset_user_password("admin")
        self.assertTrue(new_pw)
        self.assertTrue(self.auth.must_change_password(self.uid))
        self.assertIsNone(self.auth.get_session(sess["session_id"]))
        with self.assertRaises(AuthError):
            self.auth.login("admin", "brand-new-password")
        res = self.auth.begin_login("admin", new_pw)
        self.assertTrue(res["complete"])
        got = self.auth.get_session(res["session"]["session_id"])
        self.assertTrue(bool(got["must_change_password"]))

    def test_admin_reset_unknown_user(self):
        with self.assertRaises(AuthError):
            self.auth.reset_user_password("nobody")


class _FakeRequest:
    def __init__(self, body=None, *, cookies=None, headers=None, remote="127.0.0.1", method="POST", path="/api/password"):
        self._body = body if body is not None else {}
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.remote = remote
        self.method = method
        self.rel_url = SimpleNamespace(path=path, query={})

    async def json(self):
        return self._body


class PasswordChangeWebTests(unittest.IsolatedAsyncioTestCase):
    """Web API：首登阻断、改密、错误提示与直接访问。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.close)
        self.auth = make_auth(self.db)
        self.bootstrap = self.auth.ensure_bootstrap_admin("admin")
        self.uid = int(self.db.query_one("SELECT id FROM users WHERE username='admin'")["id"])
        static = Path(self.tmp.name) / "static"
        static.mkdir()
        (static / "index.html").write_text("<html></html>", encoding="utf-8")
        self.webapp = WebApp(
            self.db,
            self.auth,
            None,
            None,
            None,
            None,
            None,
            static_dir=static,
            version="test",
        )

    def _login(self, password: str) -> tuple[dict, str]:
        res = self.auth.begin_login("admin", password, ip="127.0.0.1", ua="test")
        self.assertTrue(res["complete"])
        sess = res["session"]
        return sess, sess["session_id"]

    def _req(self, sess: dict, sid: str, body: dict | None = None, path: str = "/api/password") -> _FakeRequest:
        return _FakeRequest(
            body if body is not None else {},
            cookies={SESSION_COOKIE: sid},
            headers={"X-CSRF-Token": sess["csrf_token"], "User-Agent": "test"},
            path=path,
        )

    async def test_api_me_reports_must_change(self):
        sess, sid = self._login(self.bootstrap)
        resp = await self.webapp.api_me(self._req(sess, sid, path="/api/me"))
        data = json.loads(resp.text)
        self.assertTrue(data["ok"])
        self.assertTrue(data["user"]["must_change_password"])

    async def test_protected_api_blocked_before_change(self):
        sess, sid = self._login(self.bootstrap)
        req = self._req(sess, sid, path="/api/overview")
        with self.assertRaises(Exception) as ctx:
            await self.webapp.api_overview(req)
        # aiohttp HTTPForbidden carries the JSON body
        exc = ctx.exception
        text = getattr(exc, "text", "") or ""
        self.assertIn("password_change_required", text)

    async def test_first_change_via_api_without_old(self):
        sess, sid = self._login(self.bootstrap)
        resp = await self.webapp.api_change_password(
            self._req(
                sess,
                sid,
                {"new_password": "1234567890", "confirm_password": "1234567890"},
            )
        )
        data = json.loads(resp.text)
        self.assertTrue(data["ok"], data)
        self.assertFalse(data["must_change_password"])
        # 会话保留
        got = self.auth.get_session(sid)
        self.assertIsNotNone(got)
        self.assertFalse(bool(got["must_change_password"]))
        self.auth.login("admin", "1234567890")

    async def test_first_change_accepts_ten_digit_and_complex(self):
        for pw in ("1234567890", "12345678901", "C0mplex!Passw0rd"):
            # 重置回 must_change 以便每轮都是首登语义
            self.db.execute(
                "UPDATE users SET must_change_password=1, password_hash=? WHERE id=?",
                (hash_password(self.bootstrap, "pepper"), self.uid),
            )
            sess, sid = self._login(self.bootstrap)
            resp = await self.webapp.api_change_password(
                self._req(sess, sid, {"new_password": pw, "confirm_password": pw})
            )
            data = json.loads(resp.text)
            self.assertTrue(data["ok"], f"{pw} -> {data}")

    async def test_error_messages_match_failure_reason(self):
        sess, sid = self._login(self.bootstrap)
        # 短密码
        resp = await self.webapp.api_change_password(
            self._req(sess, sid, {"new_password": "short", "confirm_password": "short"})
        )
        data = json.loads(resp.text)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "weak_password")
        self.assertIn("10", data["message"])

        # 确认不一致
        resp = await self.webapp.api_change_password(
            self._req(
                sess,
                sid,
                {"new_password": "1234567890", "confirm_password": "0987654321"},
            )
        )
        data = json.loads(resp.text)
        self.assertEqual(data["error"], "mismatch")

        # 空新密码
        resp = await self.webapp.api_change_password(
            self._req(sess, sid, {"new_password": "", "confirm_password": ""})
        )
        data = json.loads(resp.text)
        self.assertEqual(data["message"], "请输入新密码")

    async def test_wrong_old_on_voluntary(self):
        sess, sid = self._login(self.bootstrap)
        await self.webapp.api_change_password(
            self._req(sess, sid, {"new_password": "brand-new-password", "confirm_password": "brand-new-password"})
        )
        sess2, sid2 = self._login("brand-new-password")
        resp = await self.webapp.api_change_password(
            self._req(
                sess2,
                sid2,
                {
                    "old_password": "wrong-old-value",
                    "new_password": "third-password-ok",
                    "confirm_password": "third-password-ok",
                },
            )
        )
        data = json.loads(resp.text)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "invalid")
        self.assertIn("当前密码错误", data["message"])

    async def test_direct_api_without_session(self):
        req = _FakeRequest({"new_password": "1234567890"}, path="/api/password")
        with self.assertRaises(Exception) as ctx:
            await self.webapp.api_change_password(req)
        self.assertIn("401", str(ctx.exception.status))

    async def test_csrf_required(self):
        sess, sid = self._login(self.bootstrap)
        req = _FakeRequest(
            {"new_password": "1234567890"},
            cookies={SESSION_COOKIE: sid},
            headers={"User-Agent": "test"},
            path="/api/password",
        )
        with self.assertRaises(Exception):
            await self.webapp.api_change_password(req)

    async def test_logout_allowed_before_change(self):
        sess, sid = self._login(self.bootstrap)
        resp = await self.webapp.api_logout(self._req(sess, sid, {}, path="/api/logout"))
        data = json.loads(resp.text)
        self.assertTrue(data["ok"])
        self.assertIsNone(self.auth.get_session(sid))

    async def test_forced_change_blocks_assets_api(self):
        sess, sid = self._login(self.bootstrap)
        with self.assertRaises(Exception) as ctx:
            await self.webapp.api_assets(self._req(sess, sid, path="/api/assets"))
        self.assertIn("password_change_required", getattr(ctx.exception, "text", ""))


if __name__ == "__main__":
    unittest.main()
