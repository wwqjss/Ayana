"""业务检查引擎单测（轻量，不依赖 Prometheus）。"""

from __future__ import annotations

import asyncio
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
        validate_argv(["curl", "-f", "http://127.0.0.1/health"])

    def test_evaluate(self):
        ok, state, _ = evaluate("service", [{"output": "active", "returncode": 0}], {})
        self.assertTrue(ok)
        ok, state, _ = evaluate("service", [{"output": "inactive", "returncode": 0}], {})
        self.assertFalse(ok)
        ok, _, _ = evaluate("port", [{"output": "LISTEN 0 128 *:8080", "returncode": 0}], {})
        self.assertTrue(ok)
        ok, _, _ = evaluate("port", [{"output": "", "returncode": 0}], {})
        self.assertFalse(ok)
        ok, _, _ = evaluate(
            "command", [{"output": "hello", "returncode": 0}], {"output_contains": "hel"}
        )
        self.assertTrue(ok)
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
            params={"argv": ["curl", "-f", "http://127.0.0.1:8080/health"]},
            expect={"exit_code": 0},
            actor="t",
        )
        self.transport.result = NTResult(ok=True, output="", returncode=0)
        res = asyncio.run(self.svc.run_one(c))
        self.assertTrue(res["ok"])
        self.assertEqual(self.transport.calls[-1][1], ["curl", "-f", "http://127.0.0.1:8080/health"])

    def test_audit(self):
        self.svc.create_check(
            asset_id="nerv", kind="service", name="nginx", params={"unit": "nginx"}, actor="tester"
        )
        rows = self.db.query("SELECT entry FROM audit_log WHERE entry='check_create'")
        self.assertTrue(rows)


if __name__ == "__main__":
    unittest.main()
