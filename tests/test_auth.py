"""认证与 TOTP 单测。"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.auth import (
    AuthService,
    generate_totp_secret,
    hash_password,
    totp_now,
    totp_verify,
    verify_password,
)
from ayana.db import Database


class TestPassword(unittest.TestCase):
    def test_hash_verify(self):
        h = hash_password("hunter2", "pepper", iterations=1000)
        self.assertTrue(verify_password("hunter2", h, "pepper"))
        self.assertFalse(verify_password("hunter3", h, "pepper"))
        self.assertFalse(verify_password("hunter2", h, "other"))

    def test_bad_stored(self):
        self.assertFalse(verify_password("x", "garbage", "p"))


class TestTotp(unittest.TestCase):
    def test_roundtrip(self):
        secret = generate_totp_secret()
        code = totp_now(secret)
        self.assertTrue(totp_verify(secret, code))
        self.assertFalse(totp_verify(secret, "000000"))

    def test_window(self):
        secret = generate_totp_secret()
        code = totp_now(secret, at=1_700_000_000)
        self.assertTrue(totp_verify(secret, code, at=1_700_000_000 + 20))
        self.assertFalse(totp_verify(secret, code, at=1_700_000_000 + 120))


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.auth = AuthService(self.db, pepper="p", session_ttl=3600, max_failed=3, lockout=60)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_bootstrap_and_login(self):
        pw = self.auth.ensure_bootstrap_admin("admin")
        self.assertIsNotNone(pw)
        sess = self.auth.login("admin", pw)
        self.assertIn("session_id", sess)
        self.assertIsNone(self.auth.ensure_bootstrap_admin("admin"))

    def test_totp_flow(self):
        pw = self.auth.ensure_bootstrap_admin("admin")
        self.auth.login("admin", pw)
        row = self.db.query_one("SELECT id FROM users LIMIT 1")
        setup = self.auth.setup_totp(row["id"])
        code = totp_now(setup["secret"])
        codes = self.auth.confirm_totp(row["id"], code)
        self.assertEqual(len(codes), 8)
        with self.assertRaises(Exception):
            self.auth.login("admin", pw)  # 需要 totp
        sess = self.auth.login("admin", pw, totp_now(setup["secret"]))
        self.assertIn("session_id", sess)

    def test_lockout(self):
        self.auth.create_user("u", "pw", is_admin=True)
        for _ in range(3):
            with self.assertRaises(Exception):
                self.auth.login("u", "wrong")
        with self.assertRaises(Exception) as ctx:
            self.auth.login("u", "pw")
        self.assertEqual(getattr(ctx.exception, "code", ""), "locked")


if __name__ == "__main__":
    unittest.main()
