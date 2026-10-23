"""New bounded tools through the real SSH builder and semantic budget gates."""
from __future__ import annotations

import shlex
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ayana.capabilities import ObjectBindingError, build_probe_plans, build_write_tokens, get_capability, resolve_object_name
from ayana.db import Database, now
from ayana.policy import Policy
from ayana.runbook import RunbookRule, auto_budget_state
from ayana.transport import SSHTransport, TransportError
from ayana.verify_profiles import profile_for_action


class BoundedCatalogTests(unittest.TestCase):
    def test_registered_single_unit_and_instance_names_are_supported(self):
        for name in ("frps", "nginx.service", "foo@instance.service", "queue-worker_v2.service"):
            obj = {"kind": "service", "unit": name, "name": "display label"}
            for cap, verb in (("service.restart", "restart"), ("service.reload", "reload"), ("service.reset_failed", "reset-failed")):
                self.assertEqual(build_write_tokens(cap, obj), ["systemctl", verb, name])
            self.assertEqual(build_probe_plans("service.config", obj)[0][2], name)

    def test_option_glob_path_and_control_targets_cannot_expand_scope(self):
        bad = ("--all", "-a", "*", "frps*", "frps?", "svc[ab]", "/etc/systemd/system/frps.service",
               "a\\b.service", "frps\r.service", "frps\x00.service", "a\u2003b.service")
        for name in bad:
            obj = {"kind": "service", "unit": name, "name": "ignored"}
            for cap in ("service.restart", "service.reload", "service.reset_failed"):
                with self.subTest(name=name, cap=cap), self.assertRaises(ObjectBindingError):
                    build_write_tokens(cap, obj)
            for cap in ("service.config", "service.process"):
                with self.subTest(name=name, cap=cap), self.assertRaises(ObjectBindingError):
                    build_probe_plans(cap, obj)

    def test_configuration_observation_excludes_command_and_environment_secrets(self):
        obj = {"kind": "service", "name": "frps"}
        tokens = build_probe_plans("service.config", obj)[0]
        properties = tokens[3].split("=", 1)[1].split(",")
        for secret_property in ("Environment", "EnvironmentFiles", "ExecStart", "ExecReload", "ExecStop"):
            self.assertNotIn(secret_property, properties)
        self.assertIn("FragmentPath", properties)
        self.assertIn("CanReload", properties)

    def test_new_writes_need_separate_policy_and_existing_start_stays_manual(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "catalog.db")
        self.addCleanup(db.close)
        policy = Policy(db)
        for capability in ("service.reload", "service.reset_failed"):
            self.assertFalse(policy.check(subject_type="auto_rule", subject_id="agent", capability=capability,
                                          asset_id="host", object_id="obj", auto=True)["allowed"])
            self.assertIsNotNone(profile_for_action(capability=capability))
        self.assertFalse(get_capability("service.start").auto_allowed)
        self.assertFalse(get_capability("shell.interactive").auto_allowed)
        with self.assertRaises(ObjectBindingError):
            build_write_tokens("service.reload", {"kind": "container", "name": "frps"})


class RealSSHBuilderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.endpoints = {}
        for kind in ("read", "write"):
            self.endpoints[kind] = {"id": kind, "asset_id": "host", "role": kind, "host": "ops.example.test",
                "port": 22, "username": "ops_read" if kind == "read" else "ops_write", "credential_id": "",
                "host_key_sha256": "SHA256:trusted-test-key", "host_key_trusted_at": 1,
                "host_key_line": "ops.example.test ssh-ed25519 dGVzdA==", "enabled": True}
        self.transport = SSHTransport(SimpleNamespace(get_endpoint=lambda asset, role: self.endpoints.get(role),
            list_roles=lambda: []), None)

    async def test_new_tools_reach_native_ssh_exactly_and_keep_host_trust_and_role(self):
        calls = []
        async def subprocess(*argv, **kw):
            calls.append(argv)
            return SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(b"ok", b"")))
        obj = {"kind": "service", "unit": "foo@instance.service"}
        with patch("ayana.transport.fetch_host_key", new=AsyncMock(return_value={"ok": True, "fingerprint": "SHA256:trusted-test-key"})), \
             patch("ayana.transport.asyncio.create_subprocess_exec", side_effect=subprocess):
            for cap in ("service.config", "service.process"):
                for tokens in build_probe_plans(cap, obj):
                    result = await self.transport.probe("host", tokens)
                    self.assertTrue(result.ok)
                    self.assertEqual(calls[-1][-4:], ("ops_read", "--", "ops.example.test", shlex.join(tokens)))
            for cap in ("service.reset_failed", "service.reload"):
                tokens = build_write_tokens(cap, obj)
                result = await self.transport.exec("host", tokens)
                self.assertTrue(result.ok)
                self.assertEqual(calls[-1][-4:], ("ops_write", "--", "ops.example.test", shlex.join(tokens)))
        for argv in calls:
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertTrue(any(arg.startswith("UserKnownHostsFile=") for arg in argv))

    async def test_new_write_capability_cannot_bypass_changed_host_key(self):
        with patch("ayana.transport.fetch_host_key", new=AsyncMock(return_value={"ok": True, "fingerprint": "SHA256:changed"})), \
             patch("ayana.transport.asyncio.create_subprocess_exec", new=AsyncMock()) as subprocess:
            with self.assertRaisesRegex(TransportError, "host_key_changed"):
                await self.transport.exec("host", build_write_tokens("service.reset_failed", {"kind": "service", "name": "frps"}))
            subprocess.assert_not_called()


class SharedCapabilityBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "budget.db")
        t = now()
        self.at = t
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES('host','Host','read','write',?,?)", (t, t))
        self.db.execute("INSERT INTO objects(id,asset_id,kind,name,created_at) VALUES('obj','host','service','frps',?)", (t,))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def seed(self, aid, mode, cap, state="success", *, object_id="obj", ago=120):
        self.db.execute("INSERT INTO actions(id,asset_id,object_id,capability,state,mode,created_at,dispatched_at) VALUES(?,'host',?,?,?,?,?,?)",
                        (aid, object_id, cap, state, mode, self.at-ago, self.at-ago))

    def test_auto_and_reviewed_share_same_capability_budget_by_canonical_object(self):
        self.seed("runbook-restart", "auto", "service.restart", object_id="frps")
        self.seed("council-restart", "reviewed", "service.restart", "unknown")
        self.seed("council-reset", "reviewed", "service.reset_failed")
        self.seed("manual-restart", "manual", "service.restart")
        self.seed("unclaimed-cancelled", "reviewed", "service.restart", "cancelled")
        restart = auto_budget_state(self.db, RunbookRule(id="r", name="restart", capability="service.restart", max_per_day=2, cooldown_sec=60), "host", "obj", at=self.at)
        self.assertFalse(restart["ok"])
        self.assertEqual(restart["count"], 2)
        self.assertEqual(restart["code"], "budget_exhausted")
        for capability, count in (("service.reset_failed", 1), ("service.reload", 0)):
            budget = auto_budget_state(self.db, RunbookRule(id="other", name="distinct operation", capability=capability, max_per_day=2, cooldown_sec=60), "host", "frps", at=self.at)
            self.assertTrue(budget["ok"])
            self.assertEqual(budget["count"], count)

    def test_shared_cooldown_blocks_same_operation_across_execution_modes(self):
        self.seed("recent-reviewed", "reviewed", "service.restart", ago=10)
        rule = RunbookRule(id="restart", name="restart", capability="service.restart", cooldown_sec=60)
        self.assertEqual(auto_budget_state(self.db, rule, "host", "frps", at=self.at)["code"], "cooldown")
        reset = RunbookRule(id="reset", name="reset", capability="service.reset_failed", cooldown_sec=60)
        self.assertTrue(auto_budget_state(self.db, reset, "host", "obj", at=self.at)["ok"])


if __name__ == "__main__":
    unittest.main()
