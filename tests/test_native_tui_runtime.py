"""Native TUI gateway, serve client and runtime contracts.

Isolated files and zero model/tmux/process side effects on the developer machine.
POSIX-only paths are asserted as rejected rather than executed.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.agent_tui import (  # noqa: E402
    AgentTuiError,
    AgentTuiManager,
    _local_id,
    _remote_id,
)
from ayana.mimo_runtime_config import runtime_paths, verified_runtime  # noqa: E402
from ayana.mimo_serve import (  # noqa: E402
    MimoServeClient,
    MimoServeError,
    MimoServeManager,
    local_serve_url,
    native_id,
    normalize_receipt_status,
)


def make_db(path: Path):
    from ayana.db import Database, now

    db = Database(path)
    db.execute(
        "INSERT INTO duty_sessions(id,title,status,origin,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        ("sess_aaaaaaaaaaaa", "t", "open", "auto", now(), now()),
    )
    return db


class IdValidationTests(unittest.TestCase):
    def test_local_id_accepts_sess(self):
        self.assertEqual(_local_id("sess_abc123"), "sess_abc123")

    def test_local_id_rejects_remote_prefix(self):
        with self.assertRaises(AgentTuiError):
            _local_id("ses_ffe5e87bec385ffeyfYUbqQfND")

    def test_remote_id_accepts_native(self):
        self.assertEqual(_remote_id("ses_x-1"), "ses_x-1")

    def test_remote_id_rejects_path(self):
        with self.assertRaises(AgentTuiError):
            _remote_id("../etc/passwd")

    def test_native_id_rejects_slash(self):
        with self.assertRaises(MimoServeError):
            native_id("a/b")

    def test_native_id_accepts_colon(self):
        self.assertEqual(native_id("msg_1:2"), "msg_1%3A2")


class ServeUrlTests(unittest.TestCase):
    def test_loopback_ok(self):
        self.assertEqual(local_serve_url("http://127.0.0.1:6290/"), "http://127.0.0.1:6290")

    def test_rejects_remote_host(self):
        with self.assertRaises(MimoServeError):
            local_serve_url("http://evil.example:6290")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(MimoServeError):
            local_serve_url("http://user:pass@127.0.0.1:6290")

    def test_rejects_query(self):
        with self.assertRaises(MimoServeError):
            local_serve_url("http://127.0.0.1:6290/?x=1")

    def test_rejects_https(self):
        with self.assertRaises(MimoServeError):
            local_serve_url("https://127.0.0.1:6290")


class ReceiptStatusTests(unittest.TestCase):
    def test_maps_queue_states(self):
        for raw, expect in (
            ({"status": "accepted"}, "pending"),
            ({"status": "queued"}, "pending"),
            ({"state": "running"}, "running"),
            ({"status": "completed"}, "completed"),
            ({"status": "succeeded"}, "completed"),
            ({"status": "failed"}, "failed"),
            ({"status": "cancelled"}, "cancelled"),
            ({"status": "weird"}, "unknown"),
            ({"status": {"type": "done"}}, "completed"),
            ("not-a-dict", "unknown"),
        ):
            self.assertEqual(normalize_receipt_status(raw), expect, raw)

    def test_unknown_is_not_success(self):
        self.assertNotEqual(normalize_receipt_status({"status": "maybe"}), "completed")


class ClientAdmissionTests(unittest.TestCase):
    def test_admit_blocks_unverified_runtime(self):
        def boom():
            raise RuntimeError("nope")

        client = MimoServeClient(base_url="http://127.0.0.1:1", runtime_resolver=boom)
        with self.assertRaises(MimoServeError) as ctx:
            client._admit()
        self.assertEqual(ctx.exception.code, "provider_not_verified")

    def test_admit_passes_when_resolver_ok(self):
        client = MimoServeClient(base_url="http://127.0.0.1:1", runtime_resolver=lambda: {"ok": True})
        client._admit()

    def test_client_rejects_remote_base_url(self):
        with self.assertRaises(MimoServeError):
            MimoServeClient(base_url="http://example.com:6290")

    def test_prompt_rejects_empty(self):
        client = MimoServeClient(base_url="http://127.0.0.1:1")

        async def run():
            with self.assertRaises(MimoServeError) as ctx:
                await client.prompt_async("ses_1", "   ")
            self.assertEqual(ctx.exception.code, "invalid_prompt")

        asyncio.run(run())

    def test_prompt_requires_durable_receipt(self):
        client = MimoServeClient(base_url="http://127.0.0.1:1")

        async def fake_request(method, path, **kwargs):
            self.assertEqual(method, "POST")
            self.assertIn("prompt_async", path)
            return {"status": 202, "data": {"oops": True}}

        client._request = fake_request  # type: ignore
        with self.assertRaises(MimoServeError) as ctx:
            asyncio.run(client.prompt_async("ses_1", "hello"))
        self.assertEqual(ctx.exception.code, "invalid_receipt")

    def test_prompt_202_receipt_accepted(self):
        client = MimoServeClient(base_url="http://127.0.0.1:1")

        async def fake_request(method, path, **kwargs):
            return {"status": 202, "data": {"receiptId": "rcp_1"}}

        client._request = fake_request  # type: ignore
        out = asyncio.run(client.prompt_async("ses_1", "hello", message_id="msg_1"))
        self.assertTrue(out["accepted"])
        self.assertEqual(out["receipt_id"], "rcp_1")

    def test_prompt_204_is_not_durable_receipt(self):
        client = MimoServeClient(base_url="http://127.0.0.1:1")

        async def fake_request(method, path, **kwargs):
            return {"status": 204, "data": None}

        client._request = fake_request  # type: ignore
        out = asyncio.run(client.prompt_async("ses_1", "hello"))
        self.assertTrue(out["ok"])
        self.assertFalse(out["accepted"])
        self.assertEqual(out["receipt_id"], "")


class ManagerEnvTests(unittest.TestCase):
    def test_env_sets_home_xdg_and_drops_mimocode_home(self):
        manager = MimoServeManager(
            mimo_bin="/opt/mimo",
            workdir="/var/lib/ayana/agent-workspace",
            home="/var/lib/ayana",
            password="pw",
            runtime_resolver=lambda: {
                "mimo_bin": "/opt/mimo",
                "config": {},
                "environment": {"K": "V"},
            },
        )
        env = manager._env()
        self.assertEqual(env["HOME"], "/var/lib/ayana")
        self.assertNotIn("MIMOCODE_HOME", env)
        self.assertTrue(env["XDG_CONFIG_HOME"].endswith(".config"))
        self.assertEqual(env["AYANA_MCP_READONLY"], "1")
        self.assertEqual(env["K"], "V")
        self.assertIn("MIMOCODE_CONFIG_CONTENT", env)

    def test_validate_runtime_requires_applied_digest(self):
        manager = MimoServeManager(
            mimo_bin="mimo",
            password="pw",
            runtime_resolver=lambda: {"config": {}, "mimo_bin": "mimo"},
        )
        with self.assertRaises(MimoServeError) as ctx:
            manager.validate_runtime()
        self.assertEqual(ctx.exception.code, "runtime_changed")

    def test_ensure_running_rejects_stale_digest(self):
        manager = MimoServeManager(
            mimo_bin="mimo",
            password="pw",
            runtime_resolver=lambda: {"config": {}, "mimo_bin": "mimo"},
        )
        manager._applied_digest = "stale"

        class _Client:
            async def health(self):
                return {"ok": True}

        manager.client = lambda: _Client()  # type: ignore
        with self.assertRaises(MimoServeError) as ctx:
            asyncio.run(manager.ensure_running())
        self.assertEqual(ctx.exception.code, "runtime_changed")

    def test_external_start_refused(self):
        manager = MimoServeManager(mimo_bin="mimo", managed_externally=True, password="pw",
                                   runtime_resolver=lambda: {"config": {}})
        with self.assertRaises(MimoServeError) as ctx:
            asyncio.run(manager.start())
        self.assertEqual(ctx.exception.code, "external_runtime")


class AgentTuiManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = make_db(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.db.close)
        self.manager = AgentTuiManager(
            self.db,
            serve_client_factory=lambda: None,
            workdir=str(Path(self.tmp.name) / "work"),
            home=str(Path(self.tmp.name) / "home"),
            state_dir=str(Path(self.tmp.name) / "tui"),
            proxy_port=0,
            runtime_resolver=lambda: {"config": {}, "model": "m/x"},
        )
        self.manager.ensure_schema()

    def test_public_binding_strips_secrets(self):
        public = AgentTuiManager.public_binding({
            "session_id": "sess_x",
            "remote_session_id": "ses_y",
            "control_token_hash": "secret",
            "controller": "admin",
            "tmux_name": "ayana-z",
        })
        self.assertNotIn("control_token_hash", public)
        self.assertNotIn("controller_connection_id", public)
        self.assertEqual(public["controller"], "admin")
        self.assertEqual(public["tmux_name"], "ayana-z")

    def test_token_file_is_private_and_stable(self):
        token = self.manager._token("sess_aaaaaaaaaaaa", "ses_remote")
        self.assertGreaterEqual(len(token), 32)
        again = self.manager._token("sess_aaaaaaaaaaaa", "ses_remote")
        self.assertEqual(token, again)
        path = self.manager._file("sess_aaaaaaaaaaaa")
        self.assertTrue(path.exists())
        if os.name == "posix":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_token_rejects_remote_rebind(self):
        self.manager._token("sess_aaaaaaaaaaaa", "ses_remote")
        with self.assertRaises(AgentTuiError):
            self.manager._token("sess_aaaaaaaaaaaa", "ses_other")

    def _bind(self, remote_id: str = "ses_remote") -> None:
        self.db.execute(
            "UPDATE duty_sessions SET remote_session_id=? WHERE id=?",
            (remote_id, "sess_aaaaaaaaaaaa"),
        )
        self.db.execute(
            "INSERT INTO agent_runtime_bindings(session_id,remote_session_id,created_at,updated_at)"
            " VALUES(?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET remote_session_id=excluded.remote_session_id",
            ("sess_aaaaaaaaaaaa", remote_id, 1.0, 1.0),
        )

    def test_control_requires_binding(self):
        self.manager._connections["c1"] = {"session_id": "sess_aaaaaaaaaaaa", "username": "alice"}
        with self.assertRaises(AgentTuiError) as ctx:
            self.manager.acquire_control("sess_aaaaaaaaaaaa", "alice", "c1")
        self.assertEqual(ctx.exception.code, "binding_missing")

    def test_control_is_exclusive_across_connections(self):
        self._bind()
        self.manager._connections["c1"] = {"session_id": "sess_aaaaaaaaaaaa", "username": "alice"}
        self.manager._connections["c2"] = {"session_id": "sess_aaaaaaaaaaaa", "username": "bob"}
        first = self.manager.acquire_control("sess_aaaaaaaaaaaa", "alice", "c1")
        self.assertTrue(first["ok"])
        with self.assertRaises(AgentTuiError) as ctx:
            self.manager.acquire_control("sess_aaaaaaaaaaaa", "bob", "c2")
        self.assertEqual(ctx.exception.code, "control_in_use")
        self.manager.release_control("sess_aaaaaaaaaaaa", "alice", "c1")
        second = self.manager.acquire_control("sess_aaaaaaaaaaaa", "bob", "c2")
        self.assertTrue(second["ok"])

    def test_control_requires_live_connection(self):
        with self.assertRaises(AgentTuiError):
            self.manager.acquire_control("sess_aaaaaaaaaaaa", "alice", "missing")

    def test_status_without_binding(self):
        out = asyncio.run(self.manager.status("sess_aaaaaaaaaaaa"))
        self.assertTrue(out["ok"])
        self.assertFalse(out["attached"])
        self.assertIsNone(out["binding"])

    def test_ensure_rejects_posix_requirement_on_windows(self):
        if os.name == "posix":
            self.skipTest("windows-only rejection")
        with self.assertRaises(AgentTuiError) as ctx:
            asyncio.run(self.manager.ensure("sess_aaaaaaaaaaaa", "ses_remote"))
        self.assertEqual(ctx.exception.code, "posix_required")

    def test_ensure_rejects_mismatched_remote(self):
        self.db.execute(
            "UPDATE duty_sessions SET remote_session_id=? WHERE id=?",
            ("ses_bound", "sess_aaaaaaaaaaaa"),
        )
        if os.name == "posix":
            # posix path would need tmux; the mismatch is checked first
            pass
        with self.assertRaises(AgentTuiError) as ctx:
            asyncio.run(self.manager.ensure("sess_aaaaaaaaaaaa", "ses_other"))
        self.assertIn(ctx.exception.code, ("posix_required", "runtime_binding_changed", "tmux_runtime_not_started", "tmux_not_installed", "tmux_unavailable"))

    def test_proxy_scope_rejects_bad_token(self):
        request = Mock()
        request.headers = {"Authorization": "Basic " + base64.b64encode(b"x:wrong").decode()}
        with self.assertRaises(AgentTuiError) as ctx:
            self.manager._proxy_scope(request)
        self.assertEqual(ctx.exception.code, "unauthorized")

    def test_proxy_scope_accepts_issued_token(self):
        self._bind("ses_remote")
        token = self.manager._token("sess_aaaaaaaaaaaa", "ses_remote")
        request = Mock()
        request.headers = {"Authorization": "Basic " + base64.b64encode(("u:" + token).encode()).decode()}
        sid, binding = self.manager._proxy_scope(request)
        self.assertEqual(sid, "sess_aaaaaaaaaaaa")
        self.assertEqual(binding.get("remote_session_id"), "ses_remote")

    def test_websocket_requires_authorization(self):
        request = Mock()
        with self.assertRaises(Exception):
            asyncio.run(self.manager.websocket(request, "sess_aaaaaaaaaaaa", username="u", authorize=lambda: False))


class RuntimePathsTests(unittest.TestCase):
    def test_default_posix_home(self):
        if os.name != "posix":
            self.skipTest("posix default")
        paths = runtime_paths({})
        self.assertEqual(paths["home"], "/var/lib/ayana")
        self.assertEqual(paths["workdir"], "/var/lib/ayana/agent-workspace")
        self.assertTrue(paths["attestation"].endswith("attestation.json"))

    def test_overrides(self):
        paths = runtime_paths({"agent_runtime_home": "/tmp/h", "mimo_workdir": "/tmp/w", "agent_runtime_state_dir": "/tmp/s"})
        self.assertEqual(paths["home"], "/tmp/h")
        self.assertEqual(paths["workdir"], "/tmp/w")
        self.assertEqual(paths["state_dir"], "/tmp/s")

    def test_verified_runtime_requires_password(self):
        admin = Mock()
        admin.runtime_configuration.return_value = {"config": {}}
        db = Mock()
        db.path = "/tmp/x.db"
        with self.assertRaises(ValueError):
            verified_runtime({"base_dir": "/tmp"}, db, admin)

    def test_verified_runtime_requires_trusted_dynamic_mcp_context(self):
        admin = Mock()
        admin.runtime_configuration.return_value = {"config": {"mcp": {"other": {"type": "local"}}}}
        db = Mock()
        db.path = "/tmp/x.db"
        out = verified_runtime({"base_dir": "/tmp", "mimo_serve_password": "pw", "agent_runtime_home": "/tmp/h"}, db, admin)
        mcp = out["config"]["mcp"]
        self.assertIn("other", mcp)
        self.assertEqual(mcp["ayana"]["environment"]["AYANA_MCP_READONLY"], "0")
        self.assertEqual(mcp["ayana"]["environment"]["AYANA_MCP_MANAGED_CONTEXT"], "1")
        self.assertTrue(out["managed_context"])
        self.assertEqual(out["serve_password"], "pw")
        self.assertTrue(out["serve_url"].startswith("http://127.0.0.1:"))


class ReceiptLifecycleSafetyTests(unittest.TestCase):
    """Duty side: a receipt is bound once and never re-executed from scratch."""

    def test_record_receipt_conflict_rejected(self):
        from ayana.duty_session import DutySessionManager

        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        db = make_db(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        duty = DutySessionManager(db)
        duty.record_receipt("sess_aaaaaaaaaaaa", "ses_r", "rcp_1")
        with self.assertRaises(ValueError):
            duty.record_receipt("sess_aaaaaaaaaaaa", "ses_other", "rcp_1")
        with self.assertRaises(ValueError):
            duty.record_receipt("sess_other", "ses_r", "rcp_1")

    def test_finish_receipt_requires_terminal(self):
        from ayana.duty_session import DutySessionManager

        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        db = make_db(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        duty = DutySessionManager(db)
        duty.record_receipt("sess_aaaaaaaaaaaa", "ses_r", "rcp_1")
        with self.assertRaises(ValueError):
            duty.finish_receipt("rcp_1", "running")
        duty.finish_receipt("rcp_1", "completed")
        row = db.query_one("SELECT status FROM agent_runtime_receipts WHERE receipt_id=?", ("rcp_1",))
        self.assertEqual(row["status"], "completed")


if __name__ == "__main__":
    unittest.main()
