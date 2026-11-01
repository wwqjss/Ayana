"""Objective automatic verification, with no model turns or write replay."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.mcp_tools import McpToolError, OpsContext, OpsTools
from ayana.native_turns import NativeAdmissionError, NativeTurns
from ayana.ntsafe import NTResult
from ayana.promconfig import LocalConfigFS, PromConfigError, PromConfigService
from ayana.prom import PromClient
from ayana.session_bridge import SessionBridge
from ayana.write_observer import observe_prom_target, reconcile_write_results, recover_native_operation


BASE = "scrape_configs:\n  - job_name: prometheus\n    static_configs:\n      - targets: ['localhost:9090']\n"
ARGS = {"address": "https://172.16.0.12", "probe": {"exporter": "blackbox:9115", "module": "http_2xx", "job_name": "kanata-nginx"}, "labels": {"asset": "kanata"}}


def active_probe(args=ARGS):
    probe = args["probe"]
    module = probe.get("module", "http_2xx")
    job = probe.get("job_name")
    if job is None:
        fingerprint = json.dumps([args["address"], probe["exporter"], module], separators=(",", ":")).encode()
        job = "ayana-probe-" + hashlib.sha256(fingerprint).hexdigest()[:16]
    return {"scrapePool": job, "labels": {"instance": args["address"], **args.get("labels", {})},
            "scrapeUrl": "http://" + probe["exporter"] + "/probe?" + urlencode({"module": module, "target": args["address"]}),
            "health": "down"}


class WriteObserverTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.folder.cleanup)
        self.db = Database(Path(self.folder.name) / "test.db")
        self.addCleanup(self.db.close)
        self.duty = DutySessionManager(self.db)
        self.sid = self.duty.create(origin="manual")["session_id"]
        self.db.execute("UPDATE duty_sessions SET remote_session_id='ses_test' WHERE id=?", (self.sid,))
        self.bridge = SessionBridge(self.db, duty=self.duty)
        self.incident = "_session:" + self.sid
        self.fs = LocalConfigFS(Path(self.folder.name) / "prom")
        self.pc = PromConfigService(self.db, self.fs, require_promtool=False)
        self.pc._try_reload = AsyncMock(return_value={"ok": True})

    def uncertain(self, operation=None, args=None):
        args = args or ARGS
        key = self.bridge.make_action_key(self.sid, "config.prom_target_add", args, context="mcp-tool-write")
        params = {"_ayana_session_id": self.sid, "_ayana_tool": "config.prom_target_add", "_ayana_arguments": args}
        self.bridge.claim_write(self.incident, key, params=params, authority_session_id=self.sid, operation=operation)
        self.bridge.mark_unknown(self.incident, key, reason="promtool_failed: permission denied")
        return key

    async def installed_probe(self):
        await self.fs.write_text("prometheus.yml", BASE)
        await self.pc.add_target(**ARGS)
        return await self.fs.read_text("prometheus.yml")

    async def test_rollback_removes_new_discovery_file_and_restores_both_files(self):
        await self.fs.write_text("prometheus.yml", BASE)
        self.pc.require_promtool = True
        self.pc._run_promtool_check = AsyncMock(return_value={"ok": False, "output": "permission denied"})
        with self.assertRaises(PromConfigError) as caught:
            await self.pc.add_target(address="10.0.0.1:9100")
        self.assertTrue(caught.exception.execution_facts["transaction_rolled_back"])
        self.assertFalse(caught.exception.execution_facts["reload_attempted"])
        self.assertEqual(await self.fs.read_text("prometheus.yml"), BASE)
        self.assertFalse(await self.fs.exists("file_sd/ayana-nodes.json"))
        self.pc._try_reload.assert_not_awaited()

    async def test_failed_restoration_remains_unknown(self):
        await self.fs.write_text("prometheus.yml", BASE)
        self.pc.require_promtool = True
        self.pc._run_promtool_check = AsyncMock(return_value={"ok": False})
        with patch.object(self.fs, "remove", side_effect=PermissionError("rollback denied")):
            with self.assertRaises(PromConfigError) as caught:
                await self.pc.add_target(address="10.0.0.1:9100")
        self.assertFalse(caught.exception.execution_facts["transaction_rolled_back"])
        self.assertTrue(await self.fs.exists("file_sd/ayana-nodes.json"))

    async def test_failed_reload_needs_successful_rollback_reload(self):
        await self.fs.write_text("prometheus.yml", BASE)
        for second_ok in (True, False):
            self.pc._try_reload = AsyncMock(side_effect=[{"ok": False}, {"ok": second_ok}])
            with self.assertRaises(PromConfigError) as caught:
                await self.pc.add_target(**ARGS)
            self.assertEqual(caught.exception.execution_facts["transaction_rolled_back"], second_ok)
            self.assertEqual(await self.fs.read_text("prometheus.yml"), BASE)

    async def test_managed_rollback_is_definitive_failure_without_unknown(self):
        await self.fs.write_text("prometheus.yml", BASE)
        self.pc.require_promtool = True
        self.pc._run_promtool_check = AsyncMock(return_value={"ok": False})
        context = OpsContext(None, None, None, None, db=self.db, session_bridge=self.bridge, promconfig=self.pc)
        context.authority_session_id = self.sid
        context.mcp_incident_scope = self.incident
        tools = OpsTools(context)
        with self.assertRaises(McpToolError):
            await tools._managed_mutation("config.prom_target_add", ARGS, tools.config_prom_target_add)
        row = self.db.query_one("SELECT * FROM session_write_ops")
        self.assertEqual(row["status"], "failed")
        self.assertIn("transaction_rolled_back", row["result"])

    async def test_string_exception_detail_does_not_mask_uncertainty(self):
        class RemoteFailure(Exception):
            code = "transport_failed"
            detail = "connection dropped after dispatch"
        context = OpsContext(None, None, None, None, db=self.db, session_bridge=self.bridge)
        context.authority_session_id = self.sid
        context.mcp_incident_scope = self.incident
        tools = OpsTools(context)
        with self.assertRaises(RemoteFailure):
            await tools._managed_mutation("config.prom_target_add", ARGS, AsyncMock(side_effect=RemoteFailure("lost")))
        row = self.db.query_one("SELECT * FROM session_write_ops")
        self.assertEqual(row["status"], "unknown")
        self.assertIn("transport_failed", row["result"])

    async def test_native_recovery_uses_both_fingerprints_and_never_prose(self):
        key = self.uncertain()
        row = dict(self.db.query_one("SELECT * FROM session_write_ops WHERE action_key=?", (key,)))
        messages = [{"info": {"id": "msg_one", "role": "assistant", "sessionID": "ses_test"}, "parts": [
            {"type": "text", "text": "已经添加成功"},
            {"type": "tool", "id": "part_one", "tool": "mcp_tool_use", "state": {"input": {
                "name": "ayana_config_prom_target_add", "arguments": ARGS}}}]}]
        recovered = recover_native_operation(row, messages, self.bridge, "ses_test")
        self.assertEqual(recovered["arguments"], ARGS)
        self.assertEqual(recovered["source"], "native_tool_input")
        row["params_hash"] = "wrong"
        self.assertEqual(recover_native_operation(row, messages, self.bridge, "ses_test"), {})
        row["params_hash"] = ""
        messages[0]["parts"].pop()
        self.assertEqual(recover_native_operation(row, messages, self.bridge, "ses_test"), {})

    async def test_matching_disk_and_active_probe_resolves_legacy_error(self):
        await self.installed_probe()
        self.pc.prom = SimpleNamespace(targets=AsyncMock(return_value=[active_probe()]))
        key = self.uncertain()
        messages = [{"info": {"id": "msg_one", "role": "assistant", "sessionID": "ses_test"}, "parts": [
            {"type": "tool", "id": "part_one", "tool": "mcp_tool_use", "state": {"input": {
                "name": "ayana_config_prom_target_add", "arguments": ARGS}}}]}]
        client = SimpleNamespace(messages=AsyncMock(return_value=messages))
        count = await reconcile_write_results(self.db, self.bridge, promconfig=self.pc, native_client=client)
        self.assertEqual(count, 1)
        row = self.db.query_one("SELECT * FROM session_write_ops WHERE action_key=?", (key,))
        self.assertEqual(row["status"], "done")
        self.assertEqual(row["adjudication"], "auto_verified")
        self.assertIn("unknown:promtool_failed", row["result"])
        self.assertEqual(self.db.query_one("SELECT count(*) FROM audit_log WHERE entry='write_result_auto_verified'")[0], 1)

    async def test_disk_only_or_wrong_active_exporter_does_not_resolve(self):
        await self.installed_probe()
        operation = {"tool": "config.prom_target_add", "arguments": ARGS}
        self.assertEqual((await observe_prom_target(self.pc, operation))["status"], "pending")
        target = active_probe()
        target["scrapeUrl"] = target["scrapeUrl"].replace("blackbox:9115", "wrong:9115")
        self.pc.prom = SimpleNamespace(targets=AsyncMock(return_value=[target]))
        self.assertEqual((await observe_prom_target(self.pc, operation))["status"], "pending")

    async def test_probe_job_name_and_mutation_kind_are_part_of_verification(self):
        await self.installed_probe()
        target = {**active_probe(), "scrapePool": "other-job"}
        self.pc.prom = SimpleNamespace(targets=AsyncMock(return_value=[target]))
        operation = {"tool": "config.prom_target_add", "arguments": ARGS}
        self.assertEqual((await observe_prom_target(self.pc, operation))["status"], "pending")
        for tool in ("config.prom_target_update", "config.prom_target_delete"):
            self.assertEqual((await observe_prom_target(self.pc, {"tool": tool, "arguments": ARGS}))["status"], "unsupported")

    async def test_normalised_runtime_yaml_is_not_needed_for_active_json_evidence(self):
        await self.installed_probe()
        # Prometheus emits valid YAML using indentless sequences. This observer
        # reads active JSON facts and never feeds that YAML to the tiny parser.
        normalised = "global:\n  scrape_interval: 15s\nscrape_configs:\n- job_name: kanata-nginx\n  static_configs:\n  - targets:\n    - https://172.16.0.12\n"
        self.pc.prom = SimpleNamespace(targets=AsyncMock(return_value=[active_probe()]),
            _get=AsyncMock(return_value={"status": "success", "data": {"yaml": normalised}}))
        result = await observe_prom_target(self.pc, {"tool": "config.prom_target_add", "arguments": ARGS})
        self.assertEqual(result["outcome"], "executed")
        self.pc.prom._get.assert_not_awaited()

    async def test_probe_runtime_url_and_labels_must_all_match_the_exact_request(self):
        await self.installed_probe()
        valid = active_probe()
        invalid = [
            {**valid, "labels": {"instance": "https://other", "asset": "kanata"}},
            {**valid, "labels": {"instance": ARGS["address"], "asset": "other"}},
            {**valid, "scrapePool": "other-job"},
        ]
        for url in ("https://blackbox:9115/probe?", "http://blackbox:9116/probe?", "http://user@blackbox:9115/probe?",
                    "http://blackbox:9115/probe/other?", "http://fake-blackbox:9115/probe?"):
            invalid.append({**valid, "scrapeUrl": url + urlencode({"module": "http_2xx", "target": ARGS["address"]})})
        for query in ({"module": "wrong", "target": ARGS["address"]}, {"module": "http_2xx", "target": "https://other"},
                      {"module": "http_2xx", "target": ARGS["address"], "extra": "x"}):
            invalid.append({**valid, "scrapeUrl": "http://blackbox:9115/probe?" + urlencode(query)})
        invalid.extend([{**valid, "scrapeUrl": valid["scrapeUrl"] + "&module=http_2xx"},
                        {**valid, "scrapeUrl": valid["scrapeUrl"] + "#forged"}])
        for target in invalid:
            with self.subTest(target=target):
                self.pc.prom = SimpleNamespace(targets=AsyncMock(return_value=[target]))
                result = await observe_prom_target(self.pc, {"tool": "config.prom_target_add", "arguments": ARGS})
                self.assertEqual(result["status"], "pending")

    async def test_only_active_targets_qualify_not_dropped_discovery(self):
        await self.installed_probe()
        client = PromClient("http://fixture.invalid")
        client._get = AsyncMock(return_value={"status": "success", "data": {"activeTargets": [], "droppedTargets": [active_probe()]}})
        self.pc.prom = client
        result = await observe_prom_target(self.pc, {"tool": "config.prom_target_add", "arguments": ARGS})
        self.assertEqual(result["status"], "pending")
        client._get.assert_awaited_once_with("/api/v1/targets")

    async def test_default_generated_probe_pool_is_verified(self):
        args = {**ARGS, "probe": {"exporter": "blackbox:9115"}}
        await self.fs.write_text("prometheus.yml", BASE)
        await self.pc.add_target(**args)
        self.pc.prom = SimpleNamespace(targets=AsyncMock(return_value=[active_probe(args)]))
        result = await observe_prom_target(self.pc, {"tool": "config.prom_target_add", "arguments": args})
        self.assertEqual(result["outcome"], "executed")

    async def test_delete_ignores_extraneous_label_filter_and_new_address(self):
        await self.fs.write_text("file_sd/ayana-nodes.json", json.dumps([{"targets": ["host:9100"], "labels": {"asset": "actual"}}]))
        self.pc.prom = SimpleNamespace(targets=AsyncMock(return_value=[]))
        result = await observe_prom_target(self.pc, {"tool": "config.prom_target_delete", "arguments": {
            "address": "host:9100", "labels": {"asset": "wrong"}, "new_address": "unrelated:9100"}})
        self.assertEqual(result["status"], "pending")

    async def test_file_sd_verification_uses_managed_pool_and_checks_removed_old_target(self):
        await self.fs.write_text("file_sd/ayana-nodes.json", json.dumps([{"targets": ["new:9100"], "labels": {"asset": "kanata"}}]))
        args = {"address": "old:9100", "new_address": "new:9100", "labels": {"asset": "kanata"}}
        live = [{"scrapePool": "unrelated", "labels": {"instance": "new:9100", "asset": "kanata"}}]
        self.pc.prom = SimpleNamespace(targets=AsyncMock(return_value=live))
        operation = {"tool": "config.prom_target_update", "arguments": args}
        self.assertEqual((await observe_prom_target(self.pc, operation))["status"], "pending")
        live[0]["scrapePool"] = "ayana-nodes"
        self.assertEqual((await observe_prom_target(self.pc, operation))["outcome"], "executed")
        live.append({"scrapePool": "ayana-nodes", "labels": {"instance": "old:9100"}})
        self.assertEqual((await observe_prom_target(self.pc, operation))["status"], "pending")

    async def test_network_failure_records_retry_and_retains_lock(self):
        await self.installed_probe()
        key = self.uncertain({"tool": "config.prom_target_add", "arguments": ARGS})
        self.pc.prom = SimpleNamespace(targets=AsyncMock(side_effect=TimeoutError))
        self.assertEqual(await reconcile_write_results(self.db, self.bridge, promconfig=self.pc), 0)
        row = self.db.query_one("SELECT * FROM session_write_ops WHERE action_key=?", (key,))
        self.assertEqual(row["status"], "unknown")
        observation = self.bridge.list_pending_write_results(self.sid)[0]
        self.assertEqual(observation["tool"], "config.prom_target_add")
        self.assertEqual(observation["reconciliation"]["status"], "pending")
        self.assertGreater(observation["reconciliation"]["next_check_at"], observation["reconciliation"]["checked_at"])
        await reconcile_write_results(self.db, self.bridge, promconfig=self.pc)
        self.pc.prom.targets.assert_awaited_once()

    async def test_generic_unknown_is_explicitly_unsupported_and_never_replayed(self):
        self.bridge.claim_write(self.incident, "kanata:exec_shell:unknown", authority_session_id=self.sid)
        self.bridge.mark_unknown(self.incident, "kanata:exec_shell:unknown", reason="timeout")
        self.assertEqual(await reconcile_write_results(self.db, self.bridge), 0)
        observation = self.bridge.list_pending_write_results(self.sid)[0]
        self.assertEqual(observation["reconciliation"]["status"], "unsupported")
        self.assertEqual(observation["status"], "unknown")

    async def test_retry_safe_does_not_rewrite_unknown_result_as_execution_fact(self):
        key = self.uncertain()
        original = self.db.query_one("SELECT result FROM session_write_ops")[0]
        result = self.bridge.resolve_write_result(self.incident, key, outcome="retry_safe",
            evidence={"kind": "docker_pull_idle", "summary": "镜像拉取可安全重试，原结果仍未知"})
        self.assertEqual(result["status"], "released")
        row = self.db.query_one("SELECT * FROM session_write_ops")
        self.assertEqual(row["adjudication"], "auto_retry_safe")
        self.assertEqual(row["result"], original)

    async def test_late_executor_completion_supplies_definitive_result(self):
        key = self.uncertain()
        self.bridge.complete_write(self.incident, key, ok=True, result='{"ok":true}', observed_result=True)
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")[0], "done")

    async def test_plain_completion_cannot_clear_an_unknown_without_execution_evidence(self):
        key = self.uncertain()
        original = dict(self.db.query_one("SELECT * FROM session_write_ops"))
        result = self.bridge.complete_write(self.incident, key, ok=True, result="unverified assertion")
        current = dict(self.db.query_one("SELECT * FROM session_write_ops"))
        self.assertFalse(result["ok"])
        self.assertEqual(current["status"], "unknown")
        self.assertEqual(current["result"], original["result"])

    async def test_real_executor_result_can_finish_a_claim_that_expired_during_execution(self):
        async def execute(*args, **kwargs):
            row = self.db.query_one("SELECT incident_id,action_key FROM session_write_ops")
            self.bridge.mark_unknown(row["incident_id"], row["action_key"], reason="lease_expired")
            return NTResult(ok=True, output="execution finished", returncode=0)
        tools = OpsTools(OpsContext(SimpleNamespace(exec_shell=execute), None, None, None,
            db=self.db, session_bridge=self.bridge))
        result = await tools.call("host.exec", {"asset_id": "kanata", "command": "systemctl restart worker"})
        self.assertEqual(result["exec_state"], "success")
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")[0], "done")

    async def test_unknown_admission_reports_uncertainty_instead_of_active_execution(self):
        self.uncertain()
        with self.assertRaises(NativeAdmissionError) as caught:
            NativeTurns(self.db).begin(self.sid, "ses_test", "prompt", {})
        self.assertEqual(caught.exception.code, "external_result_unknown")
        self.assertNotIn("仍在执行", str(caught.exception))

    async def test_verification_audit_failure_keeps_the_unknown_lock(self):
        key = self.uncertain()
        with patch.object(self.db, "audit", side_effect=RuntimeError("sink failed")):
            with self.assertRaises(RuntimeError):
                self.bridge.resolve_write_result(self.incident, key, outcome="executed", evidence={"kind": "test_receipt"})
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")[0], "unknown")

    async def test_observed_old_unknowns_do_not_starve_a_new_supported_operation(self):
        for index in range(45):
            key = f"old:{index}"
            self.bridge.claim_write(self.incident, key, authority_session_id=self.sid)
            self.bridge.mark_unknown(self.incident, key, reason="historical timeout")
            self.bridge.set_write_observation(self.incident, key, reconciliation={"status": "unsupported", "checked_at": time.time() - 3600})
        await self.installed_probe()
        self.pc.prom = SimpleNamespace(targets=AsyncMock(return_value=[active_probe()]))
        key = self.uncertain({"tool": "config.prom_target_add", "arguments": ARGS})
        self.assertEqual(await reconcile_write_results(self.db, self.bridge, promconfig=self.pc), 1)
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops WHERE action_key=?", (key,))[0], "done")
        self.assertEqual(self.db.query_one("SELECT count(*) FROM session_write_ops WHERE status='unknown'")[0], 45)


if __name__ == "__main__":
    unittest.main()
