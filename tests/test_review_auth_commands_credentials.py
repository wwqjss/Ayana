"""2026-10-12 审查 F01/F09/F10/F17/F18 的实际边界回归，不接生产。"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from ayana.auth import AuthError, AuthService, hash_password, hash_recovery_code, totp_now
from ayana.controlled import ControlledExecutor
from ayana.credentials import CredentialError, CredentialStore, public_key_from_private
from ayana.db import Database, now
from ayana.msgentry import classify_command
from ayana.ntsafe import NTResult
from ayana.permission_change import PermissionChangeError, PermissionChangeService
from ayana.policy import Policy


class DatabaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.close)

    def count(self, table, where="1", params=()):
        return self.db.query_one(f"SELECT COUNT(*) AS n FROM {table} WHERE {where}", params)["n"]


class TestControlledReadBoundary(DatabaseCase):
    def setUp(self):
        super().setUp()
        t = now()
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES('host','Host','host-read','host-write',?,?)", (t, t))
        self.db.execute("INSERT INTO objects(id,asset_id,kind,name,unit,created_at) VALUES('host:svc','host','service','nginx','nginx',?)", (t,))
        self.policy = Policy(self.db)
        self.policy.upsert_permission(subject_type="qq_user", subject_id="reader", capability="asset.summary", asset_id="host", object_id="*", allow=True)
        # P1-02: 读命令映射到具体能力，测试需显式授权
        for cap in ("service.status", "service.logs", "probe.status"):
            self.policy.upsert_permission(subject_type="qq_user", subject_id="reader", capability=cap, asset_id="host", object_id="*", allow=True)
        self.calls = []

        async def probe(asset, tokens):
            self.calls.append((asset, tokens))
            return NTResult(ok=True, output="ok", returncode=0)

        self.actions = Mock()
        self.executor = ControlledExecutor(self.db, Mock(probe=probe), self.policy, self.actions)

    def execute(self, tokens):
        return asyncio.run(self.executor.execute(host="host", cmd_tokens=tokens, actor_type="qq_user", actor_id="reader"))

    def test_mutating_and_unknown_options_never_reach_transport(self):
        commands = [
            ["date", "-s", "2027-01-01"], ["date", "--set=2027-01-01"],
            ["hostname", "new-host"], ["hostname", "-F", "/tmp/name"],
            ["journalctl", "--rotate"], ["journalctl", "--vacuum-time=1s"],
            ["journalctl", "--rot"], ["ss", "-tK"], ["ss", "--kill"], ["ss", "-D", "/tmp/diag"],
            ["curl", "-q", "-X", "POST", "http://127.0.0.1/"],
            ["curl", "-q", "-XPOST", "http://127.0.0.1/"],
            ["curl", "-q", "-fsSd", "secret", "http://127.0.0.1/"],
            ["curl", "-q", "--config", "/tmp/curlrc"],
            ["curl", "-q", "-o", "/tmp/write", "http://127.0.0.1/"],
            ["curl", "-q", "--output=/tmp/write", "http://127.0.0.1/"],
            ["curl", "-q", "--variable", "name=/etc/passwd", "http://127.0.0.1/"],
            ["curl", "http://127.0.0.1/"], ["curl", "-q", "file:///etc/passwd"],
            ["docker", "ps", "--unknown"], ["systemctl", "status", "--root=/tmp", "nginx"],
            ["cat", "/etc/passwd;id"], ["/tmp/date"],
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command), "unknown")
                self.assertFalse(self.execute(command)["ok"])
        self.assertEqual(self.calls, [])
        self.actions.propose.assert_not_called()

    def test_declared_read_grammar_still_executes(self):
        commands = [
            ["date", "-u", "+%Y-%m-%d"], ["date", "--iso-8601=seconds"],
            ["systemctl", "status", "nginx", "--no-pager"],
            ["journalctl", "-u", "nginx", "-n", "20", "--no-pager"],
            ["curl", "-q", "-fsS", "--max-time", "3", "http://127.0.0.1/health"],
            ["curl", "-q", "-XHEAD", "http://127.0.0.1/health"],
            ["docker", "ps", "-a"], ["df", "-h"], ["ls", "-la", "/opt/ayana"],
            ["ss", "-lnt"],
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(classify_command(command), "read")
                self.assertTrue(self.execute(command)["ok"])
        # P1-02: tail/cat 任意文件读取已移除
        self.assertEqual(classify_command(["tail", "-n20", "/var/log/messages"]), "unknown")
        self.assertEqual([tokens for _, tokens in self.calls], commands)

    def test_write_with_extra_args_does_not_silently_create_different_action(self):
        self.policy.upsert_permission(subject_type="qq_user", subject_id="reader", capability="service.restart", asset_id="host", object_id="*", allow=True)
        self.assertFalse(self.execute(["systemctl", "restart", "nginx", "--force"])["ok"])
        self.actions.propose.assert_not_called()
        self.assertEqual(self.calls, [])


class TestLoginChallenges(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.auth = AuthService(self.db, "pepper", 3600, 2, 60)
        self.user = self.auth.create_user("user", "original-password")
        setup = self.auth.setup_totp(self.user)
        self.secret = setup["secret"]
        self.codes = self.auth.confirm_totp(self.user, totp_now(self.secret))

    def pending(self, username="user", password="original-password"):
        return self.auth.begin_login(username, password)["pending_id"]

    def test_totp_failure_limit_revokes_every_challenge_for_account(self):
        a, b = self.pending(), self.pending()
        for pending, expected in [(a, "totp_invalid"), (b, "locked")]:
            with self.assertRaises(AuthError) as ctx:
                self.auth.complete_login(pending, totp_code="invalid")
            self.assertEqual(ctx.exception.code, expected)
        for pending in [a, b]:
            with self.assertRaises(AuthError):
                self.auth.complete_login(pending, totp_code=totp_now(self.secret))
        self.assertEqual(self.count("login_attempts", "ok=0"), 2)
        self.assertEqual(self.count("web_sessions"), 0)

    def test_recovery_attempts_share_limit_and_locked_request_cannot_consume_code(self):
        pending = self.pending()
        for _ in range(2):
            with self.assertRaises(AuthError):
                self.auth.complete_login(pending, recovery_code="wrong-code")
        with self.assertRaises(AuthError):
            self.auth.complete_login(pending, recovery_code=self.codes[0])
        code = self.db.query_one("SELECT used_at FROM recovery_codes WHERE user_id=? AND code_hash=?", (self.user, hash_recovery_code(self.codes[0], "pepper")))
        self.assertIsNone(code["used_at"])
        self.assertEqual(self.count("web_sessions"), 0)

    def test_account_failures_are_checked_before_existing_challenge(self):
        pending = self.pending()
        for _ in range(2):
            with self.assertRaises(AuthError):
                self.auth.begin_login("user", "wrong")
        with self.assertRaises(AuthError) as ctx:
            self.auth.complete_login(pending, recovery_code=self.codes[0])
        self.assertEqual(ctx.exception.code, "locked")
        self.assertEqual(self.count("recovery_codes", "used_at IS NOT NULL"), 0)

    def test_password_change_revokes_all_old_challenges_and_sessions(self):
        a, b = self.pending(), self.pending()
        self.auth.complete_login(self.pending(), totp_code=totp_now(self.secret))
        self.auth.change_password(self.user, "original-password", "replacement-password")
        for pending in [a, b]:
            with self.assertRaises(AuthError) as ctx:
                self.auth.complete_login(pending, totp_code=totp_now(self.secret))
            self.assertEqual(ctx.exception.code, "pending_expired")
        self.assertEqual(self.count("web_sessions"), 0)
        fresh = self.pending(password="replacement-password")
        self.assertIn("session_id", self.auth.complete_login(fresh, totp_code=totp_now(self.secret)))

    def test_external_password_change_cannot_reuse_old_password_challenge(self):
        pending = self.pending()
        self.db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password("reset-password", "pepper"), self.user))
        with self.assertRaises(AuthError) as ctx:
            self.auth.complete_login(pending, totp_code=totp_now(self.secret))
        self.assertEqual(ctx.exception.code, "invalid")
        self.assertEqual(self.count("web_sessions"), 0)


class TestPermissionAtomicity(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.policy = Policy(self.db)
        self.service = PermissionChangeService(self.db, self.policy, totp_verifier=lambda *_: True)

    def propose(self, subject="agent"):
        return self.service.propose(subject_type="auto_rule", subject_id=subject, capability="service.restart")

    def authorize(self, change):
        return self.service.authorize(change["id"], actor_id="admin", totp_code="123456", is_admin=True)

    def test_empty_subject_is_rejected_before_proposal(self):
        for subject in ["", "   "]:
            with self.assertRaises(PermissionChangeError):
                self.propose(subject)
        self.assertEqual(self.count("permission_changes"), 0)

    def test_policy_failure_rolls_back_grant_state_events_and_success_audit(self):
        change = self.propose()
        original = self.policy.upsert_permission

        def write_then_fail(**kwargs):
            original(**kwargs)
            self.db.event("injected_policy_event")
            raise RuntimeError("injected failure after permission write")

        with patch.object(self.policy, "upsert_permission", side_effect=write_then_fail):
            with self.assertRaises(RuntimeError):
                self.authorize(change)
        row = self.db.query_one("SELECT state,applied_at,totp_verified_at FROM permission_changes WHERE id=?", (change["id"],))
        self.assertEqual(row["state"], "proposed")
        self.assertIsNone(row["applied_at"])
        self.assertIsNone(row["totp_verified_at"])
        self.assertEqual(self.count("permissions"), 0)
        self.assertEqual(self.count("config_versions"), 0)
        self.assertEqual(self.count("audit_log", "entry IN ('permission_upsert','permission_change_applied')"), 0)
        self.assertEqual(self.count("events", "type IN ('permission_change_applied','injected_policy_event')"), 0)
        self.assertEqual(self.authorize(change)["state"], "applied")
        self.assertEqual(self.count("permissions"), 1)

    def test_nested_execute_and_audit_obey_outer_rollback(self):
        with self.assertRaises(RuntimeError):
            with self.db.tx():
                self.db.execute("INSERT INTO meta(key,value) VALUES('outer','value')")
                with self.db.tx():
                    self.db.audit("system", "test", "nested_audit")
                raise RuntimeError("outer failed")
        self.assertEqual(self.count("meta", "key='outer'"), 0)
        self.assertEqual(self.count("audit_log", "entry='nested_audit'"), 0)


def keypair(key=None, private_format=serialization.PrivateFormat.OpenSSH):
    key = key or ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, private_format, serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return private, public


class TestPrivateKeyRotation(DatabaseCase):
    def setUp(self):
        super().setUp()
        self.store = CredentialStore(self.db, "master-key")

    def test_rotation_derives_new_public_key_without_old_metadata(self):
        private_a, public_a = keypair()
        private_b, public_b = keypair()
        meta = self.store.create(name="key", kind="private_key", secret=private_a)
        self.assertEqual(meta["public_key"], public_a)
        result = self.store.rotate(meta["id"], secret=private_b)
        self.assertEqual(result["public_key"], public_b)
        self.assertEqual(self.store.reveal_secret(meta["id"]), private_b)
        self.assertEqual(self.store.get_meta(meta["id"])["public_key"], public_b)

    def test_mismatched_or_invalid_rotation_preserves_old_key_and_metadata(self):
        private_a, public_a = keypair()
        private_b, _ = keypair()
        meta = self.store.create(name="key", kind="private_key", secret=private_a, public_key=public_a)
        for secret, supplied in [(private_b, public_a), ("-----BEGIN PRIVATE KEY-----\ninvalid", "")]:
            with self.assertRaises(CredentialError):
                self.store.rotate(meta["id"], secret=secret, public_key=supplied)
        self.assertEqual(self.store.reveal_secret(meta["id"]), private_a)
        self.assertEqual(self.store.get_meta(meta["id"])["public_key"], public_a)
        self.assertEqual(self.count("audit_log", "entry='ssh_credential_rotated'"), 0)

    def test_pem_rsa_key_and_matching_public_comment_are_supported(self):
        private, public = keypair(rsa.generate_private_key(public_exponent=65537, key_size=2048), serialization.PrivateFormat.PKCS8)
        self.assertEqual(public_key_from_private(private), public)
        self.assertEqual(public_key_from_private(private, public + " rotation"), public + " rotation")


if __name__ == "__main__":
    unittest.main()
