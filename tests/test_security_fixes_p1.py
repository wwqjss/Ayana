"""P1 发布阻塞项回归：B1 命令、消息权限、自批、SSRF、Unicode、expect 契约。"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionError, ActionService
from ayana.auth import totp_verify, verify_password
from ayana.checks import CheckError, evaluate, validate_argv
from ayana.db import Database, now
from ayana.policy import Policy
from ayana.transport import is_blocked_ssrf_host
from ayana.notify_channels import ChannelError, _assert_safe_webhook_url, _assert_safe_ws_url
from ayana.msgentry import classify_command
from ayana.readonly_commands import readonly_command


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
        return {"ok": True, "mode": "exec" if write else "probe"}


class FakeNT:
    async def probe(self, *a, **k):
        from ayana.ntsafe import NTResult

        return NTResult(ok=True, output="ok", returncode=0)

    async def exec(self, *a, **k):
        from ayana.ntsafe import NTResult

        return NTResult(ok=True, output="ok", returncode=0)


class FakeProm:
    async def probe_success_since(self, *a, **k):
        return []

    async def probe_success(self, *a, **k):
        return {"result": []}


class TestB1CommandGrammar(unittest.TestCase):
    def test_file_and_dig_like_rejected(self):
        for argv in (
            ["cat", "/etc/passwd"],
            ["dig", "-f", "/etc/hosts"],
            ["dig", "example.com", "@203.0.113.11"],
            ["grep", "x", "/etc/shadow"],
            ["curl", "file:///etc/passwd"],
            ["curl", "http://x/"],  # 缺 -q
            ["ss", "-F", "file"],
            ["true", "extra"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(CheckError):
                    validate_argv(argv)

    def test_safe_probes_allowed(self):
        for argv in (
            ["curl", "-q", "--disable", "https://example.com/h"],
            ["wget", "--spider", "https://example.com/h"],
            ["ping", "-c", "1", "example.com"],
            ["nc", "-z", "10.0.0.5", "22"],
            ["ss", "-lnt"],
            ["true"],
        ):
            with self.subTest(argv=argv):
                validate_argv(argv)


class TestPortEvaluate(unittest.TestCase):
    def test_header_or_error_not_ok(self):
        header_only = [{"ok": True, "returncode": 0, "output": "Netid State Recv-Q Send-Q Local Address:Port"}]
        ok, state, _ = evaluate("port", header_only, {})
        self.assertFalse(ok)
        err = [{"ok": False, "returncode": 1, "output": "permission denied"}]
        ok, state, _ = evaluate("port", err, {})
        self.assertFalse(ok)
        listen = [{"ok": True, "returncode": 0, "output": "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*"}]
        ok, state, _ = evaluate("port", listen, {})
        self.assertTrue(ok)


class TestExpectContract(unittest.TestCase):
    def test_output_match_rejected_not_stripped(self):
        from ayana.formspec import validate_fields

        fields = {
            "asset_id": "romi",
            "kind": "command",
            "name": "t",
            "params.cmd": "curl -q --disable https://example.com/h",
            "expect.mode": "contains",
            "expect.value": "healthy",
        }
        # 仅 enum 校验就会拒绝 contains（form values 只有 exit0）
        res = validate_fields(
            "checks",
            fields,
            assets=[{"id": "romi", "display_name": "R", "enabled": True}],
            partial=False,
        )
        self.assertFalse(res["valid"])


class TestMessageNoFileRead(unittest.TestCase):
    def test_cat_not_readonly(self):
        self.assertFalse(readonly_command(["cat", "/etc/passwd"]))
        self.assertNotEqual(classify_command(["cat", "/etc/passwd"]), "read")
        self.assertFalse(readonly_command(["docker", "inspect", "x"]))


class TestSelfApprove(unittest.TestCase):
    def test_qq_and_web_self_approve_denied(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        t = now()
        db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
            " host_id_verified_at, created_at, updated_at)"
            " VALUES('nerv','N','nerv','nerv-exec','NERV',?,?,?)",
            (t, t, t),
        )
        db.execute(
            "INSERT INTO objects(id, asset_id, kind, name, unit, created_at)"
            " VALUES('nerv:service:frps','nerv','service','frps','frps',?)",
            (t,),
        )
        db.execute(
            "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
            " VALUES('op','x',0,0,?,?)",
            (t, t),
        )
        policy = Policy(db)
        policy.upsert_permission(
            subject_type="qq_user", subject_id="op", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=True,
        )
        actions = ActionService(db, FakeNT(), FakeGate(), policy, FakeProm())
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="qq_user", proposer_id="op",
        )
        with self.assertRaises(ActionError) as ctx:
            actions.approve(prop["id"], approver_type="qq_user", approver_id="op")
        self.assertEqual(ctx.exception.code, "self_approve_denied")


class TestSSRF(unittest.TestCase):
    def test_ipv6_mapped_and_metadata(self):
        for host in (
            "::1",
            "127.0.0.1",
            "::ffff:7f00:1",
            "::ffff:a9fe:a9fe",
            "169.254.169.254",
            "fe80::1",
            "localhost",
        ):
            self.assertTrue(is_blocked_ssrf_host(host, allow_loopback=False), host)
        # SSH 可允许环回
        self.assertFalse(is_blocked_ssrf_host("127.0.0.1", allow_loopback=True, purpose="ssh"))
        # .local 在 webhook 拒绝，SSH 可允许（已信任资产）
        self.assertTrue(is_blocked_ssrf_host("nas.local", purpose="webhook"))
        self.assertFalse(is_blocked_ssrf_host("nas.local", purpose="ssh"))

    def test_webhook_ws_urls(self):
        with self.assertRaises(ChannelError):
            _assert_safe_webhook_url("http://[::0001]/")
        with self.assertRaises(ChannelError):
            _assert_safe_webhook_url("https://[::ffff:7f00:1]/")
        with self.assertRaises(ChannelError):
            _assert_safe_ws_url("ws://169.254.169.254/")
        self.assertTrue(_assert_safe_webhook_url("https://qyapi.weixin.qq.com/x").startswith("https://"))


class TestUnicodeAuth(unittest.TestCase):
    def test_lone_surrogate_no_500(self):
        self.assertFalse(verify_password("\ud800", "pbkdf2_sha256$1$aa$bb", "p"))
        self.assertFalse(totp_verify("MFRGGZDF", "１２３４５６"))  # 全角数字
        self.assertFalse(totp_verify("MFRGGZDF", "\ud800"))


if __name__ == "__main__":
    unittest.main()
