"""Lite duty integration: real queue, authority, ledger and check recovery.

Only the model and SSH boundary are fakes. No live provider or host is used.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from ayana.agent_authority import resolve_authority
from ayana.checks import CheckService
from ayana.db import Database, now
from ayana.exec_facts import NTResult
from ayana.incidents import IncidentService
from ayana.lite_worker import LiteInvestigator, model_client, write_attestation
from ayana.mcp_tools import OpsContext, OpsTools
from ayana.session_bridge import SessionBridge
from ayana.transport import _session_ssh_scope, check_dispatch_authority


def tool(name, args=None, ident="call_1"):
    return {"message": {"content": None, "tool_calls": [{"id": ident, "type": "function", "function": {
        "name": "ayana_" + name.replace(".", "_"), "arguments": json.dumps(args or {})}}]}, "finish_reason": "tool_calls"}


def conclusion(**fields):
    return {"message": {"content": json.dumps({"status": "completed", "facts": [], "root_cause": "unknown", **fields})}, "finish_reason": "stop"}


class FakeModel:
    enabled = True
    model = "fixture"
    api_key = "fixture-secret"

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []
        self.before_response = None

    def _endpoint_allowed(self):
        return True

    async def chat_tools(self, messages, **kwargs):
        self.requests.append(messages)
        if self.before_response:
            self.before_response()
        return self.responses.pop(0)


class FakeSSH:
    def __init__(self):
        self.healthy = False
        self.calls = []
        self.groups = []
        self.unknown = False
        self.after_probe = None
        self.dispatch_started = None
        self.hold_dispatch = None

    def scope(self):
        check_dispatch_authority()
        binding = _session_ssh_scope.get()
        if binding:
            self.groups.append(resolve_authority(*binding)["ssh_account_group"])

    async def probe(self, asset_id, tokens, timeout=None):
        self.scope()
        result = NTResult(ok=self.healthy, output="active" if self.healthy else "inactive", returncode=0 if self.healthy else 3)
        if self.after_probe:
            self.after_probe()
        return result

    async def exec_shell(self, asset_id, command, timeout=None, *, channel="write"):
        self.scope()
        self.calls.append((asset_id, command, channel))
        if self.dispatch_started:
            self.dispatch_started.set()
        if self.hold_dispatch:
            await self.hold_dispatch.wait()
        if self.unknown:
            return NTResult(ok=False, output="timeout", returncode=-1, timed_out=True)
        if channel == "write":
            self.healthy = True
        return NTResult(ok=True, output="ok", returncode=0)


class LiteWorkerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "worker.db")
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES('host','Host','host','host',?,?)", (now(), now()))
        self.ssh = FakeSSH()
        self.incidents = IncidentService(self.db)
        self.bridge = SessionBridge(self.db)
        self.incidents.session_bridge = self.bridge
        self.checks = CheckService(self.db, self.ssh, incidents=self.incidents)
        self.check = self.checks.create_check(asset_id="host", kind="service", name="worker", params={"unit": "worker"}, fail_threshold=1)
        self.ctx = OpsContext(transport=self.ssh, prom=None, incidents=self.incidents, knowledge=None,
                              db=self.db, checks=self.checks, session_bridge=self.bridge, managed_context=True)

    async def worker(self, model, **config):
        await self.checks.run_one(self.check)
        episode = self.db.query_one("SELECT incident_id FROM alert_episodes LIMIT 1")
        self.iid = episode["incident_id"]
        self.sid = self.bridge.get_mapping(self.iid)["session_id"]
        cfg = {"agent_mode": "lite", "auto_investigate": {"timeout_sec": 5, **config}}
        worker = LiteInvestigator(cfg, OpsTools(self.ctx), client_factory=lambda: model)
        worker.offer(self.iid)
        return worker

    async def run_job(self, worker):
        await worker.tick_once()
        await asyncio.gather(*list(worker._running.values()))
        return worker._row(self.iid)

    async def test_real_queue_write_ledger_and_native_evidence_complete_once(self):
        model = FakeModel(tool("host.exec", {"asset_id": "host", "command": "systemctl is-active worker", "channel": "read"}),
                          tool("host.exec", {"asset_id": "host", "command": "systemctl restart worker", "channel": "write"}, "call_2"),
                          tool("incident.verify", ident="call_3"))
        worker = await self.worker(model)
        job = await self.run_job(worker)
        self.assertEqual(job["status"], "done")
        self.assertTrue(json.loads(job["last_conclusion_json"])["verified_recovered"])
        self.assertEqual(self.db.query_one("SELECT outcome FROM incidents WHERE id=?", (self.iid,))[0], "recovered")
        self.assertEqual([row["status"] for row in self.db.query("SELECT status FROM session_write_ops")], ["done"])
        self.assertEqual(len(self.ssh.calls), 2)
        worker.offer(self.iid)
        await worker.tick_once()
        self.assertEqual(len(self.ssh.calls), 2)
        event = self.db.query_one("SELECT payload_json FROM session_events WHERE type='lite_tool_finished' LIMIT 1")
        self.assertEqual(json.loads(event[0])["state"], "completed")

    async def test_model_claim_of_recovery_never_closes_a_firing_incident(self):
        model = FakeModel(conclusion(verified_recovered=True, root_cause="invented"))
        worker = await self.worker(model)
        job = await self.run_job(worker)
        result = json.loads(job["last_conclusion_json"])
        self.assertEqual(job["status"], "partial")
        self.assertFalse(result["verified_recovered"])
        self.assertEqual(result["root_cause"], "unknown")
        self.assertEqual(self.db.query_one("SELECT status FROM incidents WHERE id=?", (self.iid,))[0], "open")

    async def test_unknown_write_stops_before_another_model_turn_or_dispatch(self):
        model = FakeModel(tool("host.exec", {"asset_id": "host", "command": "systemctl restart worker"}), conclusion())
        worker = await self.worker(model)
        self.ssh.unknown = True
        job = await self.run_job(worker)
        self.assertEqual(job["status"], "partial")
        self.assertEqual(len(model.requests), 1)
        self.assertEqual(len(self.ssh.calls), 1)
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")[0], "unknown")

    async def test_pause_while_model_responds_prevents_dispatch(self):
        model = FakeModel(tool("host.exec", {"asset_id": "host", "command": "systemctl restart worker"}))
        worker = await self.worker(model)
        model.before_response = lambda: self.bridge.duty.pause_session(self.sid, actor="operator")
        await self.run_job(worker)
        self.assertEqual(self.ssh.calls, [])

    async def test_unconfigured_model_keeps_work_queued_without_spending_a_round(self):
        model = FakeModel()
        model.enabled = False
        worker = await self.worker(model)
        self.assertEqual(await worker.tick_once(), 0)
        self.assertEqual((worker._row(self.iid)["status"], worker._row(self.iid)["rounds"]), ("queued", 0))
        self.assertEqual(model.requests, [])

    async def test_existing_unknown_blocks_even_a_different_model_command(self):
        model = FakeModel(tool("host.exec", {"asset_id": "host", "command": "systemctl start worker"}))
        worker = await self.worker(model)
        self.db.execute("INSERT INTO session_write_ops(id,incident_id,session_id,action_key,status,created_at,updated_at) "
                        "VALUES('previous',?,?, 'old-command','unknown',?,?)", (self.iid, self.sid, now(), now()))
        await self.run_job(worker)
        self.assertEqual(model.requests, [])
        self.assertEqual(self.ssh.calls, [])

    async def test_pause_during_verification_cannot_publish_probe_results(self):
        model = FakeModel(tool("incident.verify"))
        worker = await self.worker(model)
        self.ssh.healthy = True
        before = len(self.checks.recent_results(self.check["id"]))
        self.ssh.after_probe = lambda: self.bridge.duty.pause_session(self.sid, actor="operator")
        await self.run_job(worker)
        self.assertEqual(len(self.checks.recent_results(self.check["id"])), before)
        self.assertEqual(self.db.query_one("SELECT status FROM incidents WHERE id=?", (self.iid,))[0], "open")

    async def test_model_cannot_redirect_to_another_asset_or_session(self):
        model = FakeModel(tool("host.exec", {"asset_id": "other-host", "command": "systemctl restart worker", "session_id": "forged"}), conclusion())
        worker = await self.worker(model)
        await self.run_job(worker)
        self.assertEqual(self.ssh.calls, [])
        self.assertEqual(self.db.query("SELECT id FROM session_write_ops"), [])

    async def test_live_default_account_group_is_used_by_execution_and_verification(self):
        model = FakeModel(tool("host.exec", {"asset_id": "host", "command": "systemctl restart worker"}), tool("incident.verify", ident="call_2"))
        worker = await self.worker(model)
        self.db.execute("INSERT INTO ssh_account_groups(name,label,created_at,updated_at) VALUES('ops','Ops',?,?)", (now(), now()))
        self.bridge.duty.set_setting("ssh_default_group", "ops")
        await self.run_job(worker)
        self.assertEqual(self.ssh.groups, ["ops", "ops"])

    async def test_old_probe_cannot_record_recovery_for_a_new_generation(self):
        model = FakeModel(tool("incident.verify"))
        worker = await self.worker(model)
        self.ssh.healthy = True
        before = len(self.checks.recent_results(self.check["id"]))
        self.ssh.after_probe = lambda: self.db.execute("UPDATE incidents SET generation=generation+1 WHERE id=?", (self.iid,))
        await self.run_job(worker)
        self.assertEqual(len(self.checks.recent_results(self.check["id"])), before)
        self.assertEqual(self.db.query_one("SELECT status FROM incidents WHERE id=?", (self.iid,))[0], "open")
        self.assertEqual(self.db.query("SELECT id FROM events WHERE type='auto_investigation'"), [])

    async def test_cancelled_ssh_is_unknown_and_restart_does_not_replay(self):
        model = FakeModel(tool("host.exec", {"asset_id": "host", "command": "systemctl restart worker"}))
        worker = await self.worker(model)
        self.ssh.dispatch_started = asyncio.Event()
        self.ssh.hold_dispatch = asyncio.Event()
        await worker.tick_once()
        await asyncio.wait_for(self.ssh.dispatch_started.wait(), 2)
        task = worker._running[self.iid]
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")[0], "unknown")
        replacement = LiteInvestigator(worker.cfg, OpsTools(self.ctx), client_factory=lambda: model)
        self.assertEqual(replacement.recover_interrupted(), 1)
        await replacement.tick_once()
        self.assertEqual(len(self.ssh.calls), 1)
        self.assertEqual(replacement._row(self.iid)["status"], "failed")

    async def test_readonly_configuration_does_not_execute_model_repair(self):
        model = FakeModel(tool("host.exec", {"asset_id": "host", "command": "systemctl restart worker"}), conclusion())
        worker = await self.worker(model, closed_loop=False)
        await self.run_job(worker)
        self.assertEqual(self.ssh.calls, [])

    async def test_result_notice_is_durable_and_compensated_without_duplicates(self):
        from ayana.notify import Notifier
        model = FakeModel(conclusion())
        worker = await self.worker(model)
        notifier = Notifier(self.db)
        notifier.set_channel_store(SimpleNamespace(list_enabled=lambda: [
            {"id": "channel", "kind": "qq", "targets": ["user:123"], "created_at": 0, "updated_at": 0}]))
        self.ctx.notifier = notifier
        with patch.object(notifier, "enqueue_for_event", return_value=False):
            await self.run_job(worker)
        notifier.compensate_missing()
        rows = self.db.query("SELECT body FROM notification_outbox WHERE body LIKE '轻量值班%'")
        self.assertEqual(len(rows), 1)
        self.assertIn("host", rows[0]["body"])
        notifier.compensate_missing()
        self.assertEqual(len(self.db.query("SELECT id FROM notification_outbox WHERE body LIKE '轻量值班%'")), 1)

    async def test_an_old_generation_result_notice_is_not_sent_for_a_recurrence(self):
        from ayana.notify import Notifier
        model = FakeModel(conclusion())
        worker = await self.worker(model)
        await self.run_job(worker)
        self.db.execute("UPDATE incidents SET generation=generation+1 WHERE id=?", (self.iid,))
        notifier = Notifier(self.db)
        notifier.set_channel_store(SimpleNamespace(list_enabled=lambda: [
            {"id": "channel", "kind": "qq", "targets": ["user:123"], "created_at": 0, "updated_at": 0}]))
        notifier.compensate_missing()
        self.assertEqual(self.db.query("SELECT id FROM notification_outbox WHERE body LIKE '轻量值班%'"), [])


class LiteCompositionTests(unittest.TestCase):
    def test_private_runtime_lock_rejects_symlinks_without_touching_target(self):
        from ayana.instance import acquire_single_instance_lock
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "preserve.txt"
            target.write_text("keep")
            link = Path(tmp) / "lite-runtime.lock"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("creating file symlinks is unavailable")
            with self.assertRaises((RuntimeError, OSError)):
                acquire_single_instance_lock(link, nofollow=True)
            self.assertEqual(target.read_text(), "keep")

    def test_runtime_selects_lite_before_native_runtime_initialization(self):
        from ayana.agent_runtime import run
        with patch("ayana.config.load_config", return_value={"agent_mode": "lite"}), \
             patch("ayana.lite_worker.run", new_callable=AsyncMock) as lite, \
             patch("ayana.mimo_admin.MimoAdmin") as native:
            asyncio.run(run("fixture.json"))
        lite.assert_awaited_once()
        native.assert_not_called()

    def test_attestation_has_private_atomic_complete_identity(self):
        with tempfile.TemporaryDirectory() as tmp, patch("ayana.lite_worker.process_start", return_value="start-id"):
            path = Path(tmp) / "lite-attestation.json"
            write_attestation(path, "waiting_configuration")
            value = json.loads(path.read_text())
            self.assertEqual(value["owner_start"], "start-id")
            self.assertEqual(value["mode"], "lite")
            self.assertEqual(value["status"], "waiting_configuration")
            self.assertEqual(len(list(Path(tmp).iterdir())), 1)

    def test_model_uses_one_saved_provider_snapshot_and_secure_network(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db = Database(Path(tmp) / "config.db")
            try:
                for key, value in {"llm_base_url": "https://provider.example/v1", "llm_model": "saved", "llm_api_key": "saved-key"}.items():
                    db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, value))
                with patch.object(db, "query", wraps=db.query) as query:
                    client = model_client({"llm_api_key": "old-key", "llm_model": "old"}, db)
                self.assertEqual(query.call_count, 1)
                self.assertEqual((client.base_url, client.model, client.api_key), ("https://provider.example/v1", "saved", "saved-key"))
                self.assertTrue(client.secure_network)
            finally:
                db.close()
