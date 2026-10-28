"""P4.2：统一写路径、分类防绕过、未知结果。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database, now  # noqa: E402
from ayana.mcp_tools import OpsContext, OpsTools  # noqa: E402
from ayana.msgentry import classify_shell_command  # noqa: E402
from ayana.ntsafe import NTResult  # noqa: E402
from ayana.session_bridge import SessionBridge  # noqa: E402


def make_db():
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db = Database(Path(tmp.name) / "t.db")
    return tmp, db


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.result = NTResult(ok=True, output="ok", returncode=0, mode="exec")

    async def exec_shell(self, asset_id, command, timeout=None, *, channel="write"):
        self.calls.append((asset_id, command, channel))
        return self.result


class TestClassifyShell(unittest.TestCase):
    def test_nginx_diagnostics_and_harmless_output_redirection(self):
        for cmd in (
            "nginx -v",
            "nginx -V 2>&1",
            "systemctl is-active nginx 2>&1",
            "ss -lntp 2>/dev/null | head -30",
            "ss -lntp 2>/dev/null | head -n 30",
            "which nginx; nginx -v 2>&1; systemctl is-active nginx 2>&1; ss -lntp 2>/dev/null | head -30",
        ):
            with self.subTest(command=cmd):
                self.assertEqual(classify_shell_command(cmd), "read")

    def test_diagnostic_chain_validates_every_command_and_redirection(self):
        for cmd in (
            "which nginx; touch /tmp/x",
            "which nginx; some_custom_tool --do",
            "which nginx; nginx -s reload 2>&1",
            "which nginx; systemctl restart nginx 2>&1",
            "which nginx; ss -K 2>/dev/null",
            "ss -lntp 2>/dev/null | tee /tmp/x",
            "ss -lntp 2>/dev/null | head -30 /etc/passwd",
            "systemctl is-active nginx 2>/tmp/output",
            "systemctl is-active nginx 2>>/tmp/output",
            "systemctl is-active nginx 2>&3",
            "systemctl is-active nginx 3>&1",
            "systemctl is-active nginx </etc/passwd",
            "nginx -v $(touch /tmp/x) 2>&1",
            "nginx -v `touch /tmp/x` 2>&1",
            "which nginx & touch /tmp/x",
            "which nginx\ntouch /tmp/x",
            "ss -lntp 2>/dev/null | head -30;",
            "ss -lntp 2>/dev/null | head -30; date -s 2026-01-01",
        ):
            with self.subTest(command=cmd):
                self.assertNotEqual(classify_shell_command(cmd), "read")

    def test_reads(self):
        for cmd in (
            "uptime",
            "df -h",
            "systemctl status frps",
            "systemctl is-active frps",
            "journalctl -u frps -n 20",
            "ss -lnt",
            "cat /etc/os-release",
        ):
            self.assertEqual(classify_shell_command(cmd), "read", cmd)

    def test_writes(self):
        for cmd in (
            "systemctl restart frps",
            "systemctl stop frps",
            "rm -rf /tmp/x",
            "chmod 644 /etc/hosts",
            "echo hi > /tmp/x",
            "cat f >> /tmp/x",
            "sed -i s/a/b/ /etc/conf",
            "docker restart nginx",
            "kill 123",
            "sudo systemctl reload nginx",
        ):
            self.assertEqual(classify_shell_command(cmd), "write", cmd)

    def test_unknown_defaults_not_read(self):
        self.assertEqual(classify_shell_command("some_custom_tool --do"), "unknown")
        self.assertEqual(classify_shell_command(""), "unknown")

    def test_pipe_cannot_smuggle_write_as_read(self):
        # 管道/重定向结构 → write/unknown，不得当 read
        cls = classify_shell_command("cat /etc/passwd | tee /tmp/x")
        self.assertIn(cls, ("write", "unknown"))
        cls2 = classify_shell_command("ls; rm -rf /")
        self.assertIn(cls2, ("write", "unknown"))


class TestMcpControlledWrite(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        # 本组用例验证写路径机制（claim/审计/幂等）；默认自主执行，审批由会话档位决定
        self.transport = FakeTransport()
        self.bridge = SessionBridge(self.db)
        self.tools = OpsTools(
            OpsContext(
                transport=self.transport,
                prom=MagicMock(),
                incidents=MagicMock(),
                knowledge=MagicMock(),
                db=self.db,
                session_bridge=self.bridge,
            )
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_read_channel_rejects_write_command(self):
        with self.assertRaises(Exception) as cm:
            asyncio.run(
                self.tools.call(
                    "host.exec",
                    {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "read"},
                )
            )
        self.assertIn("classified=write", str(cm.exception))
        self.assertEqual(getattr(cm.exception, "code", ""), "write_not_allowed_on_read_channel")
        self.assertEqual(self.transport.calls, [])

    def test_read_channel_allows_read_command(self):
        out = asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "uptime", "channel": "read"},
            )
        )
        self.assertTrue(out["ok"])
        self.assertEqual(out.get("classified"), "read")

    def test_read_channel_accepts_nginx_diagnostic_chain(self):
        command = "which nginx; nginx -v 2>&1; systemctl is-active nginx 2>&1; ss -lntp 2>/dev/null | head -30"
        out = asyncio.run(self.tools.call("host.exec", {"asset_id": "romi", "command": command, "channel": "read"}))
        self.assertTrue(out["ok"])
        self.assertEqual(out["classified"], "read")
        self.assertEqual(self.transport.calls, [("romi", command, "read")])

    def test_automatic_readonly_still_rejects_compound_diagnostics(self):
        self.tools.ctx.readonly = True
        command = "which nginx; nginx -v 2>&1; systemctl is-active nginx 2>&1; ss -lntp 2>/dev/null | head -30"
        with self.assertRaises(Exception) as cm:
            asyncio.run(self.tools.call("host.exec", {"asset_id": "romi", "command": command, "channel": "read"}))
        self.assertEqual(getattr(cm.exception, "code", ""), "readonly_mode_rejects_write")
        self.assertEqual(self.transport.calls, [])

    def test_write_goes_through_claim_and_audit(self):
        out = asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "write"},
            )
        )
        self.assertTrue(out["ok"])
        self.assertEqual(out.get("exec_state"), "success")
        self.assertTrue(out.get("action_key"))
        self.assertTrue(self.bridge.is_write_done("_mcp_", out["action_key"]))
        # 二次相同写被幂等拦住
        out2 = asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "write"},
            )
        )
        self.assertFalse(out2["ok"])
        self.assertEqual(out2.get("error"), "idempotent_block")

    def test_unknown_result_not_done(self):
        self.transport.result = NTResult(
            ok=False, output="timeout", returncode=-1, timed_out=True
        )
        out = asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "write"},
            )
        )
        self.assertEqual(out.get("exec_state"), "unknown")
        key = out.get("action_key")
        self.assertFalse(self.bridge.is_write_done("_mcp_", key))
        # unknown 不可自动重放
        again = asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "write"},
            )
        )
        self.assertFalse(again["ok"])
        self.assertEqual(again.get("error"), "idempotent_block")

    def test_audit_written_for_writes(self):
        asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "write"},
            )
        )
        row = self.db.query_one(
            "SELECT * FROM audit_log WHERE entry='mcp_host_exec_write'"
        )
        self.assertIsNotNone(row)

    def test_different_command_different_key(self):
        a = asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "write"},
            )
        )
        b = asyncio.run(
            self.tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "systemctl reload frps", "channel": "write"},
            )
        )
        self.assertTrue(a["ok"] and b["ok"])
        self.assertNotEqual(a["action_key"], b["action_key"])

    def test_human_approval_blocks_write_until_approved(self):
        # 人工审批拦截属于会话 manual 档语义（不再依赖全局审批开关）
        from ayana.duty_session import DutySessionManager

        duty = DutySessionManager(self.db)
        sid = duty.create(origin="manual")["session_id"]
        duty.set_runtime_state(sid, "idle")
        self.db.execute(
            "UPDATE duty_sessions SET access_mode='readwrite', approval_mode='manual' WHERE id=?",
            (sid,),
        )
        tools = self.tools._with_authority(sid)
        out = asyncio.run(
            tools.call(
                "host.exec",
                {"asset_id": "nerv", "command": "systemctl restart frps", "channel": "write"},
            )
        )
        self.assertFalse(out["ok"])
        self.assertEqual(out.get("error"), "approval_required")
        self.assertTrue(out.get("pending"))
        self.assertEqual(self.transport.calls, [])
        key = out.get("action_key")
        self.assertTrue(key)
        scope = f"_session:{sid}"
        approved = self.bridge.approve_pending_write(scope, key, approved_by="alice")
        self.assertTrue(approved["ok"])
        # 批准后执行
        self.bridge.complete_write(scope, key, ok=True, result="ok")
        self.assertTrue(self.bridge.is_write_done(scope, key))


class TestActionServiceWriteOps(unittest.TestCase):
    def test_write_ops_hook_present(self):
        from ayana.actions import ActionService

        self.assertTrue(hasattr(ActionService, "execute"))
        src = Path("ayana/actions.py").read_text(encoding="utf-8")
        self.assertIn("self.write_ops", src)
        self.assertIn("mark_unknown", src)


if __name__ == "__main__":
    unittest.main()
