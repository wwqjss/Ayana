"""Web 终端 MVP：权限隔离、host key、会话限制。"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database, now
from ayana.policy import Policy
from ayana.terminal import TerminalError, TerminalService
from ayana.transport import SSHAssetStore


def make_env():
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "t.db")
    t = now()
    db.execute(
        "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
        " host_id_verified_at, prom_asset, enabled, notes, created_at, updated_at)"
        " VALUES(?,?,?,?,?,?,?,1,'',?,?)",
        ("romi", "ROMI", "romi", "romi-exec", "ROMI", t, "romi", t, t),
    )
    return tmp, db


class TestTerminalPolicy(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_env()
        self.policy = Policy(self.db)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_agent_cannot_shell_interactive(self):
        d = self.policy.check(
            subject_type="auto_rule",
            subject_id="agent",
            capability="shell.interactive",
            asset_id="romi",
            object_id="*",
        )
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], "denied_by_agent_ceiling")

    def test_llm_cannot_shell_interactive(self):
        d = self.policy.check(
            subject_type="llm",
            subject_id="x",
            capability="shell.interactive",
        )
        self.assertFalse(d["allowed"])

    def test_web_user_can_when_permitted(self):
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin",
            capability="shell.interactive", allow=True,
            require_approval=False, actor="admin",
        )
        d = self.policy.check(
            subject_type="web_user",
            subject_id="admin",
            capability="shell.interactive",
        )
        self.assertTrue(d["allowed"])

    def test_capability_in_catalog(self):
        from ayana.capabilities import assert_within_ceiling
        cap = assert_within_ceiling("shell.interactive")
        self.assertEqual(cap.kind, "write")
        self.assertFalse(cap.auto_allowed)


class TestTerminalSessionGuard(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_env()
        self.store = SSHAssetStore(self.db)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_no_endpoint(self):
        svc = TerminalService(self.db, self.store, None)
        import asyncio

        async def run():
            with self.assertRaises(TerminalError) as ctx:
                await svc.create(asset_id="romi", username="admin")
            self.assertEqual(ctx.exception.code, "no_ssh_endpoint")

        asyncio.run(run())

    def test_untrusted_host_key_blocks(self):
        self.store.upsert_endpoint(
            asset_id="romi", role="write", host="127.0.0.1", port=22,
            username="root", credential_id="c1", actor="admin",
        )
        svc = TerminalService(self.db, self.store, None)
        import asyncio

        async def run():
            with self.assertRaises(TerminalError) as ctx:
                await svc.create(asset_id="romi", username="admin")
            self.assertIn(ctx.exception.code, ("host_key_untrusted", "no_credential", "ssh_connect_failed"))

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
