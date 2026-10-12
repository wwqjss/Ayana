"""pepper 迁移与首登强制改密回归。"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.auth import AuthError, AuthService, hash_password, verify_password
from ayana.db import Database


class TestPepperAndMustChange(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.close)

    def test_legacy_pepper_login_rehashes(self):
        legacy = AuthService(self.db, pepper="old-pepper", session_ttl=3600, max_failed=5, lockout=60)
        uid = legacy.create_user("admin", "legacy-password-1", is_admin=True)
        stored_old = self.db.query_one("SELECT password_hash FROM users WHERE id=?", (uid,))["password_hash"]
        self.assertTrue(verify_password("legacy-password-1", stored_old, "old-pepper"))

        new = AuthService(
            self.db,
            pepper="new-pepper",
            session_ttl=3600,
            max_failed=5,
            lockout=60,
            legacy_peppers=["old-pepper"],
        )
        session = new.login("admin", "legacy-password-1")
        self.assertTrue(session["session_id"].startswith("sess_"))
        stored_new = self.db.query_one("SELECT password_hash FROM users WHERE id=?", (uid,))["password_hash"]
        self.assertTrue(verify_password("legacy-password-1", stored_new, "new-pepper"))
        self.assertFalse(verify_password("legacy-password-1", stored_new, "old-pepper"))

    def test_bootstrap_requires_password_change(self):
        auth = AuthService(self.db, pepper="p", session_ttl=3600, max_failed=5, lockout=60)
        pw = auth.ensure_bootstrap_admin("admin")
        self.assertTrue(pw)
        uid = self.db.query_one("SELECT id FROM users WHERE username='admin'")["id"]
        self.assertTrue(auth.must_change_password(uid))
        session = auth.login("admin", pw)
        self.assertTrue(session["session_id"])
        # 改密后清除标记
        auth.change_password(uid, pw, "brand-new-password")
        self.assertFalse(auth.must_change_password(uid))
        with self.assertRaises(AuthError):
            auth.login("admin", pw)
        auth.login("admin", "brand-new-password")


if __name__ == "__main__":
    unittest.main()
