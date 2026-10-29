"""业务检查引擎单测（轻量，不依赖 Prometheus）。"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.checks import (
    CheckError,
    CheckService,
    build_tokens,
    evaluate,
    validate_argv,
)
from ayana.db import Database
from ayana.ntsafe import NTResult


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.result = NTResult(ok=True, output="active", returncode=0)

    async def probe(self, asset_id, tokens, timeout=None):
        self.calls.append((asset_id, list(tokens)))
        return self.result


class TestTokens(unittest.TestCase):
    def test_port(self):
        plans = build_tokens("port", {"port": 8080, "protocol": "tcp"})
        self.assertEqual(plans[0], ["ss", "-lnt", "sport", "=", ":8080"])

    def test_service(self):
        plans = build_tokens("service", {"unit": "nginx"})
        self.assertEqual(plans[0], ["systemctl", "is-active", "nginx"])

    def test_command_rejects_metachar(self):
        with self.assertRaises(CheckError):
            validate_argv(["rm", "-rf", "/"])
        with self.assertRaises(CheckError):
            validate_argv(["sh", "-c", "id"])
        with self.assertRaises(CheckError):
            validate_argv(["curl", "http://x;id"])
        with self.assertRaises(CheckError):
            validate_argv(["shutdown", "now"])
        validate_argv(["curl", "-q", "--disable", "http://127.0.0.1/health"])

    def test_command_rejects_mutating_probe_options_and_custom_executables(self):
        bad = [
            ["curl", "-X", "POST", "http://127.0.0.1/health"],
            ["curl", "-XPOST", "http://127.0.0.1/health"],
            ["curl", "-fsSd", "value", "http://127.0.0.1/health"],
            ["curl", "--data", "value", "http://127.0.0.1/health"],
            ["curl", "-T", "/etc/passwd", "http://127.0.0.1/upload"],
            ["curl", "--config", "/tmp/options"],
            ["curl", "-o", "/tmp/download", "http://127.0.0.1/health"],
            ["wget", "http://127.0.0.1/health"],
            ["wget", "--spider", "--post-data", "value", "http://127.0.0.1/health"],
            ["wget", "--spider", "-O", "/tmp/download", "http://127.0.0.1/health"],
            ["wget", "--spider", "--config", "/tmp/options"],
            ["wget", "--spider", "-r", "http://127.0.0.1/health"],
            ["nc", "-e", "/bin/sh", "127.0.0.1", "8080"],
            ["nc", "-vl", "8080"],
            ["nc", "-c", "id", "127.0.0.1", "8080"],
            ["ss", "-tK"], ["ss", "--kill"], ["ss", "--ki"], ["ss", "--di"], ["ss", "-D", "/tmp/diag"],
            ["ss", "-F", "/tmp/file"],
            ["dig", "-f", "/etc/hosts"],
            ["/tmp/curl", "http://127.0.0.1/health"],
            ["./curl", "http://127.0.0.1/health"],
            ["/bin/../tmp/curl", "http://127.0.0.1/health"],
            ["/usr/local/bin/curl", "http://127.0.0.1/health"],
        ]
        for argv in bad:
            with self.subTest(argv=argv), self.assertRaises(CheckError):
                validate_argv(argv)

    def test_readonly_probe_options_supported(self):
        good = [
            ["curl", "-q", "--disable", "-fsS", "--max-time", "3", "http://127.0.0.1/health"],
            ["/usr/bin/curl", "-q", "--disable", "-I", "http://127.0.0.1/health"],
            ["curl", "-q", "--disable", "--request", "HEAD", "http://127.0.0.1/health"],
            ["curl", "-q", "--disable", "-XGET", "http://127.0.0.1/health"],
            ["wget", "--spider", "-q", "http://127.0.0.1/health"],
            ["wget", "-O", "-", "http://127.0.0.1/health"],
            ["wget", "-O-", "http://127.0.0.1/health"],
            ["nc", "-z", "-w", "3", "127.0.0.1", "8080"],
            ["ss", "-lnt"],
        ]
        for argv in good:
            with self.subTest(argv=argv):
                self.assertEqual(validate_argv(argv), argv)

    def test_evaluate(self):
        ok, state, _ = evaluate("service", [{"output": "active", "returncode": 0, "ok": True}], {})
        self.assertTrue(ok)
        ok, state, _ = evaluate("service", [{"output": "inactive", "returncode": 0, "ok": True}], {})
        self.assertFalse(ok)
        ok, _, _ = evaluate("port", [{"output": "LISTEN 0 128 *:8080", "returncode": 0, "ok": True}], {})
        self.assertTrue(ok)
        ok, _, _ = evaluate("port", [{"output": "", "returncode": 0, "ok": True}], {})
        self.assertFalse(ok)
        # P1-07: output_contains 不再作为 oracle
        ok, _, detail = evaluate(
            "command", [{"output": "hello", "returncode": 0}], {"output_contains": "hel"}
        )
        self.assertTrue(ok)  # 仅看 exit=0
        self.assertTrue(detail.startswith("exit="))
        ok, _, _ = evaluate(
            "command", [{"output": "hello", "returncode": 1}], {"exit_code": 0}
        )
        self.assertFalse(ok)


class TestCheckService(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        t = 1000.0
        self.db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, created_at, updated_at)"
            " VALUES('nerv','NERV','nerv','nerv-exec',?,?)",
            (t, t),
        )
        self.transport = FakeTransport()
        self.svc = CheckService(self.db, self.transport)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_create_list_delete(self):
        c = self.svc.create_check(
            asset_id="nerv", kind="port", name="ssh", params={"port": 22}, actor="t"
        )
        self.assertTrue(c["id"])
        self.assertEqual(self.svc.list_checks()[0]["name"], "ssh")
        self.svc.delete_check(c["id"], actor="t")
        self.assertEqual(self.svc.list_checks(), [])

    def test_run_one_ok(self):
        self.transport.result = NTResult(ok=True, output="LISTEN x", returncode=0)
        c = self.svc.create_check(
            asset_id="nerv", kind="port", name="web", params={"port": 8080}, actor="t"
        )
        res = asyncio.run(self.svc.run_one(c))
        self.assertTrue(res["ok"])
        self.assertEqual(self.transport.calls[-1][1][0], "ss")

    def test_run_one_fail_streak(self):
        self.transport.result = NTResult(ok=True, output="", returncode=0)
        c = self.svc.create_check(
            asset_id="nerv",
            kind="port",
            name="web",
            params={"port": 8080},
            fail_threshold=2,
            actor="t",
        )
        asyncio.run(self.svc.run_one(c))
        asyncio.run(self.svc.run_one(c))
        got = self.svc.get_check(c["id"])
        self.assertEqual(got["fail_streak"], 2)
        self.assertEqual(got["last_state"], "fail")

    def test_command_tokens_safe(self):
        c = self.svc.create_check(
            asset_id="nerv",
            kind="command",
            name="health",
            params={"argv": ["curl", "-q", "--disable", "-f", "http://127.0.0.1:8080/health"]},
            expect={"exit_code": 0},
            actor="t",
        )
        self.transport.result = NTResult(ok=True, output="", returncode=0)
        res = asyncio.run(self.svc.run_one(c))
        self.assertTrue(res["ok"])
        self.assertEqual(self.transport.calls[-1][1], ["curl", "-q", "--disable", "-f", "http://127.0.0.1:8080/health"])

    def test_audit(self):
        self.svc.create_check(
            asset_id="nerv", kind="service", name="nginx", params={"unit": "nginx"}, actor="tester"
        )
        rows = self.db.query("SELECT entry FROM audit_log WHERE entry='check_create'")
        self.assertTrue(rows)

    def test_natural_language_name_saved_and_updated_without_slug_restriction(self):
        c = self.svc.create_check(asset_id="nerv", kind="service", name="监控 NERV 的 nginx 服务",
                                  params={"unit": "nginx.service"})
        self.assertEqual(c["name"], "监控 NERV 的 nginx 服务")
        self.assertTrue(c["id"].startswith("chk"))
        updated = self.svc.update_check(c["id"], name="NERV 网站服务运行情况")
        self.assertEqual(updated["name"], "NERV 网站服务运行情况")
        self.assertEqual(updated["id"], c["id"])

    def test_create_rejects_invalid_numbers_without_writing_or_clamping(self):
        for field, bad_values in {"interval_sec": [True, 60.5, 14, 3601],
                                  "fail_threshold": [False, 2.5, 0, 11]}.items():
            for value in bad_values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(CheckError):
                        self.svc.create_check(asset_id="nerv", kind="port", name="网页端口",
                                              params={"port": 8080}, **{field: value})
                    self.assertEqual(self.svc.list_checks(), [])

    def test_update_matches_create_validation_and_preserves_existing_on_error(self):
        c = self.svc.create_check(asset_id="nerv", kind="port", name="网页端口", params={"port": 8080})
        for fields in ({"interval_sec": 5}, {"fail_threshold": 99}, {"severity": "severe"},
                       {"params": {"port": 80.5}}, {"name": "x" * 65}, {"enabled": "false"}):
            with self.subTest(fields=fields):
                with self.assertRaises(CheckError):
                    self.svc.update_check(c["id"], **fields)
                self.assertEqual(self.svc.get_check(c["id"]), c)

    def test_create_rejects_unknown_params_and_conflicting_expectation(self):
        for kind, params, expect in (
            ("port", {"port": 53, "proto": "udp"}, {}),
            ("service", {"unit": "nginx", "container": "nginx"}, {}),
            ("command", {"argv": ["true"]}, {"exit_code": 0, "output_contains": "ok"}),
        ):
            with self.subTest(kind=kind):
                with self.assertRaises(CheckError) as raised:
                    self.svc.create_check(asset_id="nerv", kind=kind, name="检查", params=params, expect=expect)
                self.assertTrue(raised.exception.issues)
                self.assertEqual(self.svc.list_checks(), [])

    def test_disabled_or_unknown_assets_rejected_before_persistence(self):
        self.db.execute("UPDATE assets SET enabled=0 WHERE id='nerv'")
        for asset_id in ("nerv", "missing"):
            with self.assertRaises(CheckError):
                self.svc.create_check(asset_id=asset_id, kind="service", name="服务", params={"unit": "nginx"})
        self.assertEqual(self.svc.list_checks(), [])

    def test_existing_disabled_asset_check_can_be_disabled(self):
        c = self.svc.create_check(asset_id="nerv", kind="service", name="服务", params={"unit": "nginx"})
        self.db.execute("UPDATE assets SET enabled=0 WHERE id='nerv'")
        updated = self.svc.update_check(c["id"], enabled=False)
        self.assertFalse(updated["enabled"])
        with self.assertRaises(CheckError):
            self.svc.update_check(c["id"], enabled=True)

    def test_legacy_unsafe_check_records_failure_and_can_be_disabled(self):
        c = self.svc.create_check(asset_id="nerv", kind="command", name="旧检查", params={"argv": ["true"]})
        unsafe = {"argv": ["curl", "-X", "POST", "http://127.0.0.1/health"]}
        self.db.execute("UPDATE checks SET params_json=? WHERE id=?", (json.dumps(unsafe), c["id"]))
        legacy = self.svc.get_check(c["id"])
        result = asyncio.run(self.svc.run_one(legacy))
        self.assertFalse(result["ok"])
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(result["state"], "unknown")
        # 旧危险命令在运行期 fail-closed，detail 为校验错误文案
        self.assertTrue(result["detail"])
        disabled = self.svc.update_check(c["id"], enabled=False)
        self.assertFalse(disabled["enabled"])
        self.assertEqual(disabled["params"], unsafe)
        with self.assertRaises(CheckError):
            self.svc.update_check(c["id"], enabled=True)

    def test_port_validation_does_not_accept_fraction_or_boolean(self):
        for port in (True, False, 80.5, "80.0"):
            with self.assertRaises(CheckError):
                build_tokens("port", {"port": port})


if __name__ == "__main__":
    unittest.main()
