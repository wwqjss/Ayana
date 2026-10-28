"""不可逆操作提前通知：只通知不审批、不阻断、不作安全保证。"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from ayana.actions import ActionService, looks_irreversible, announce_irreversible
from ayana.db import Database, now
from ayana.ntsafe import NTError, NTResult


class FakeNT:
    def __init__(self):
        self.exec_calls = []

    async def probe(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="loaded", returncode=0)

    async def exec(self, alias, tokens, timeout=None):
        self.exec_calls.append(tokens)
        return NTResult(ok=True, output="ok", returncode=0)

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"nt-probe","mode":"probe","uid":1}')


class FakeGate:
    class B:
        asset_id = "nerv"
        read_alias = "nerv"
        write_alias = "nerv-exec"
        expected_host_id = "NERV"
        host_id_verified_at = 1.0

    def get(self, asset_id):
        return self.B()

    async def verify_account(self, asset_id, *, write=False):
        return {"ok": True, "mode": "exec", "account": "nt-exec", "error": ""}


class FakeProm:
    async def probe_success(self, asset, service=""):
        return {"result": [{"metric": {}, "value": [0, "1"]}]}


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        t = now()
        self.db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
            " host_id_verified_at, created_at, updated_at)"
            " VALUES('nerv','N','nerv','nerv-exec','NERV',?,?,?)",
            (t, t, t),
        )
        self.db.execute(
            "INSERT INTO objects(id, asset_id, kind, name, unit, created_at)"
            " VALUES('nerv:service:frps','nerv','service','frps','frps',?)",
            (t,),
        )
        self.db.execute(
            "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
            " VALUES('admin','x',0,1,?,?)",
            (t, t),
        )
        from ayana.policy import Policy

        self.nt = FakeNT()
        self.actions = ActionService(
            self.db, self.nt, FakeGate(), Policy(self.db), FakeProm(),
            action_ttl=1800, verify_window=5, verify_timeout=1,
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _events(self):
        return [dict(r) for r in self.db.query(
            "SELECT * FROM events WHERE type='irreversible_write_notice'")]

    def test_looks_irreversible_classifies_tokens(self):
        self.assertTrue(looks_irreversible("rm -rf /data"))
        self.assertTrue(looks_irreversible(["systemctl", "stop", "x"]) is False)
        self.assertTrue(looks_irreversible(["shred", "-u", "/tmp/f"]))
        self.assertFalse(looks_irreversible("systemctl restart frps"))
        self.assertFalse(looks_irreversible("confirm the state"))

    def test_announce_records_event_without_notifier(self):
        announce_irreversible(self.db, None, asset_id="nerv", command="rm -rf /tmp/x")
        self.assertEqual(len(self._events()), 1)
        self.assertIn("提前通知非审批", self._events()[0]["payload_json"])

    def test_announce_pushes_when_notifier_available(self):
        notifier = MagicMock()
        announce_irreversible(self.db, notifier, asset_id="nerv", command="reboot")
        notifier.on_event.assert_called_once()

    def test_irreversible_write_still_executes(self):
        # host_exec 写通道：通知已落时间线，但绝不阻断执行（通知非审批）
        from ayana.mcp_tools import OpsContext, OpsTools
        from ayana.session_bridge import SessionBridge

        class FakeTransport:
            def __init__(self):
                self.calls = []

            async def exec_shell(self, asset_id, command, timeout=None, *, channel="write"):
                self.calls.append((asset_id, command, channel))
                return NTResult(ok=True, output="ok", returncode=0, mode="exec")

        transport = FakeTransport()
        bridge = SessionBridge(self.db)
        tools = OpsTools(
            OpsContext(
                transport=transport, prom=MagicMock(), incidents=MagicMock(),
                knowledge=MagicMock(), db=self.db, session_bridge=bridge,
            )
        )
        out = asyncio.run(
            tools.call("host.exec", {"asset_id": "nerv", "command": "rm -rf /tmp/x", "channel": "write"})
        )
        self.assertTrue(out["ok"], out)
        self.assertTrue(transport.calls)
        self.assertGreaterEqual(len(self._events()), 1)


if __name__ == "__main__":
    unittest.main()
