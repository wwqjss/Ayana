"""Definitive diagnostic results and real stdio MCP check-service wiring."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ayana.db import Database
from ayana.exec_facts import NTResult, UNKNOWN_HINTS, classify_exec_result
from ayana.mcp_server import build_ops_context
from ayana.mcp_tools import OpsContext, OpsTools
from ayana.session_bridge import SessionBridge


class ExecResultObservationTests(unittest.TestCase):
    def test_successful_diagnostic_output_is_not_transport_uncertainty(self):
        for hint in UNKNOWN_HINTS:
            with self.subTest(hint=hint):
                result = NTResult(ok=True, output=f"historical journal message: {hint}", returncode=0)
                state, detail = classify_exec_result(result)
                self.assertEqual(state, "success")
                self.assertEqual(detail, result.output)

    def test_transport_timeout_signal_or_ssh_failure_remains_unknown(self):
        for result in (NTResult(ok=True, output="healthy", returncode=0, timed_out=True),
                       NTResult(ok=False, output="terminated", returncode=-15),
                       NTResult(ok=False, output="connection lost", returncode=255)):
            with self.subTest(result=result):
                self.assertEqual(classify_exec_result(result)[0], "unknown")


class DiagnosticLedgerTests(unittest.IsolatedAsyncioTestCase):
    async def test_write_channel_diagnostic_completes_without_releasing_real_unknowns(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as folder:
            db = Database(Path(folder) / "state.db")
            self.addCleanup(db.close)
            bridge = SessionBridge(db)
            calls = []
            async def execute(asset_id, command, timeout=None, *, channel="write"):
                calls.append(channel)
                return NTResult(ok=True, returncode=0, output="journal: startup timeout; worker killed\nnow healthy")
            tools = OpsTools(OpsContext(transport=SimpleNamespace(exec_shell=execute), prom=None,
                                       incidents=None, knowledge=None, db=db, session_bridge=bridge))
            bridge.claim_write("_mcp_", "genuine-uncertainty")
            bridge.mark_unknown("_mcp_", "genuine-uncertainty", reason="SSH connection lost")
            result = await tools.call("host.exec", {"asset_id": "romi", "channel": "write",
                                                      "command": "journalctl -u nginx --no-pager -n 30; date -u"})
            self.assertEqual(result["exec_state"], "success")
            self.assertEqual(result["classified"], "read")
            self.assertEqual(calls, ["write"])
            ledger = db.query_one("SELECT status FROM session_write_ops WHERE action_key=?", (result["action_key"],))
            self.assertEqual(ledger["status"], "done")
            genuine = db.query_one("SELECT status FROM session_write_ops WHERE action_key='genuine-uncertainty'")
            self.assertEqual(genuine["status"], "unknown")


class StdioCheckServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_context_lists_configured_checks_without_network(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as folder:
            cfg = {"db_path": str(Path(folder) / "state.db"), "base_dir": folder,
                   "knowledge_dir": str(Path(folder) / "knowledge")}
            with patch.dict(os.environ, {"AYANA_MCP_DB_PATH": cfg["db_path"],
                                         "AYANA_MCP_KNOWLEDGE_DIR": cfg["knowledge_dir"],
                                         "AYANA_MCP_MANAGED_CONTEXT": "0", "AYANA_MCP_READONLY": "0",
                                         "AYANA_MIMO_BIN": "", "AYANA_MIMO_MODEL": ""}):
                context = build_ops_context(cfg)
            self.addCleanup(context.db.close)
            self.assertIs(context.checks.transport, context.transport)
            context.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,expected_host_id,created_at,updated_at)"
                               " VALUES('romi','Romi','','','',1,1)")
            item = context.checks.create_check(asset_id="romi", kind="service", name="Nginx",
                                                params={"unit": "nginx"})
            with patch.object(context.transport, "probe", side_effect=AssertionError("list must not probe")):
                for use_fallback in (False, True):
                    with self.subTest(fallback=use_fallback):
                        if use_fallback:
                            context.checks = None
                        result = await OpsTools(context).call("config.check_list", {"asset_id": "romi"})
                        self.assertTrue(result["ok"])
                        self.assertEqual([check["id"] for check in result["checks"]], [item["id"]])


if __name__ == "__main__":
    unittest.main()
