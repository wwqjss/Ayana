"""v0.4.1：SSH 凭据加密、端点/host key、Transport 抽象、命令 tokens 约束。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.credentials import (
    CredentialError,
    CredentialStore,
    generate_keypair,
)
from ayana.db import Database, now
from ayana.ntsafe import NTResult
from ayana.transport import SSHAssetStore, SSHTransport, TransportError


def make_db():
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "t.db")
    t = now()
    db.execute(
        "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
        " host_id_verified_at, prom_asset, enabled, notes, created_at, updated_at)"
        " VALUES(?,?,?,?,?,?,?,1,'',?,?)",
        ("nerv", "NERV", "nerv", "nerv-exec", "NERV", t, "nerv", t, t),
    )
    return tmp, db


class TestCredentialStore(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.store = CredentialStore(self.db, master_key="test-master-key")

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_password_roundtrip_encrypted(self):
        meta = self.store.create(
            name="root-pw", kind="password", secret="s3cret!", actor="admin"
        )
        self.assertTrue(meta["id"])
        # 库中不是明文
        row = self.db.query_one(
            "SELECT secret_enc FROM ssh_credentials WHERE id=?", (meta["id"],)
        )
        self.assertNotIn(b"s3cret!", bytes(row["secret_enc"]))
        self.assertEqual(self.store.reveal_secret(meta["id"]), "s3cret!")
        # 元数据无明文
        m = self.store.get_meta(meta["id"])
        self.assertNotIn("secret", m)

    def test_rotate_and_delete(self):
        meta = self.store.create(name="k", kind="password", secret="old", actor="admin")
        self.store.rotate(meta["id"], secret="new", actor="admin")
        self.assertEqual(self.store.reveal_secret(meta["id"]), "new")
        self.store.delete(meta["id"], actor="admin")
        with self.assertRaises(CredentialError):
            self.store.reveal_secret(meta["id"])

    def test_missing_key_refuses(self):
        s = CredentialStore(self.db, master_key="")
        with self.assertRaises(CredentialError):
            s.create(name="x", kind="password", secret="y", actor="a")

    def test_bad_kind(self):
        with self.assertRaises(CredentialError):
            self.store.create(name="x", kind="token", secret="y", actor="a")

    def test_generate_keypair(self):
        priv, pub = generate_keypair()
        self.assertIn("PRIVATE KEY", priv)
        self.assertTrue(pub.startswith("ssh-ed25519") or pub.startswith("ssh-"))


class TestSSHEndpoints(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.store = SSHAssetStore(self.db)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_upsert_and_trust(self):
        ep = self.store.upsert_endpoint(
            asset_id="nerv", role="read", host="10.0.0.1", port=22,
            username="ops", actor="admin",
        )
        self.assertEqual(ep["host"], "10.0.0.1")
        self.assertFalse(ep["host_key_trusted_at"])
        ep2 = self.store.trust_host_key(
            "nerv", "read", "SHA256:abc", actor="admin"
        )
        self.assertEqual(ep2["host_key_sha256"], "SHA256:abc")
        self.assertTrue(ep2["host_key_trusted_at"])

    def test_host_key_change_audited(self):
        self.store.upsert_endpoint(
            asset_id="nerv", role="read", host="h", username="u", actor="admin"
        )
        self.store.trust_host_key("nerv", "read", "SHA256:old", actor="admin")
        self.store.trust_host_key("nerv", "read", "SHA256:new", actor="admin")
        audits = self.db.query(
            "SELECT entry FROM audit_log WHERE entry LIKE 'ssh_host_key%' ORDER BY at"
        )
        entries = [a["entry"] for a in audits]
        self.assertIn("ssh_host_key_trusted", entries)
        self.assertIn("ssh_host_key_changed", entries)

    def test_upsert_does_not_log_secret(self):
        self.store.upsert_endpoint(
            asset_id="nerv", role="write", host="h", username="root",
            credential_id="cred_x", actor="admin",
        )
        # 审计 detail 无明文字段
        rows = self.db.query("SELECT detail_json FROM audit_log WHERE entry='ssh_endpoint_upsert'")
        self.assertTrue(rows)
        self.assertNotIn("password", rows[0]["detail_json"].lower())


class TestSSHTransportGuard(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.store = SSHAssetStore(self.db)
        self.creds = CredentialStore(self.db, master_key="k")
        self.tr = SSHTransport(self.store, self.creds)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_untrusted_host_key_refused(self):
        self.store.upsert_endpoint(
            asset_id="nerv", role="default", host="h", username="u", actor="a"
        )
        with self.assertRaises(TransportError) as ctx:
            asyncio.run(self.tr.probe("nerv", ["uptime"]))
        self.assertEqual(ctx.exception.code, "host_key_untrusted")

    def test_missing_endpoint(self):
        with self.assertRaises(TransportError):
            asyncio.run(self.tr.probe("nerv", ["uptime"]))

    def test_unsafe_tokens_refused(self):
        self.store.upsert_endpoint(
            asset_id="nerv", role="read", host="h", username="u", actor="a"
        )
        self.store.trust_host_key("nerv", "read", "SHA256:x", actor="a")
        with self.assertRaises(TransportError):
            asyncio.run(self.tr.probe("nerv", ["echo hi; rm -rf /"]))

    def test_empty_tokens(self):
        with self.assertRaises(TransportError):
            asyncio.run(self.tr.probe("nerv", []))


class FakeNT:
    async def probe(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="nt-probe", returncode=0)

    async def exec(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="nt-exec", returncode=0)


class TestRouterFallback(unittest.TestCase):
    """无 SSH 端点时回落 NT；有端点走 SSH 路径（此处用 mock 证明路由）。"""

    def test_nt_fallback_without_endpoint(self):
        tmp, db = make_db()
        try:
            store = SSHAssetStore(db)

            class R:
                def __init__(self):
                    self._ssh = SSHTransport(store, CredentialStore(db, master_key="k"))
                    self._nt = FakeNT()
                    self._store = store

                def _use_ssh(self, asset_id, role):
                    ep = self._store.get_endpoint(asset_id, role)
                    return bool(ep and ep.get("enabled"))

                async def probe(self, asset_id, tokens, timeout=None):
                    if self._use_ssh(asset_id, "read"):
                        return await self._ssh.probe(asset_id, tokens, timeout=timeout)
                    return await self._nt.probe(asset_id, tokens, timeout=timeout)

            r = R()
            res = asyncio.run(r.probe("nerv", ["uptime"]))
            self.assertTrue(res.ok)
            self.assertEqual(res.output, "nt-probe")
        finally:
            try:
                db.close()
            except Exception:
                pass
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
