"""P6.2 runtime provider/CLI/MCP and current autonomous-loop regressions.

Uses isolated databases and scripted subprocess responses; makes no model or
production request. Real model acceptance remains a separate user-key step.
"""
from __future__ import annotations

import asyncio
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from ayana.auto_investigate import AutoInvestigator, InvestConfig
from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.main import App
from ayana.mcp_server import build_ops_context
from ayana.mcp_tools import McpToolError, OpsContext, OpsTools, TOOL_SPECS
from ayana.mimo_session import DECISION_AGENT, DECISION_TOOLS, MimoSessionClient, MimoSessionError, RemoteSession
from ayana.ops_loop import MAX_EXECUTE_ROUNDS, OpsLoop
import test_p61_closed_loop_e2e as p61


class RuntimeClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ayana runtime config ")
        self.addCleanup(self.tmp.cleanup)
        self.runtime = {
            "mimo_bin": "configured-mimo", "model": "xiaomi/model-a", "cwd": self.tmp.name,
            "config_path": str(Path(self.tmp.name) / "mimocode.jsonc"),
            "config": {"provider": {"xiaomi": {"options": {"apiKey": "dummy-test-key"}}},
                       "model": "xiaomi/model-a",
                       "mcp": {"ayana": {"type": "local", "command": ["python", "-m", "ayana.mcp_server"],
                                          "environment": {"AYANA_MCP_READONLY": "0"}}}},
            "environment": {"AYANA_MCP_DB_PATH": str(Path(self.tmp.name) / "current.db")},
        }

    def output(self, text="done"):
        return json.dumps({"type": "text", "sessionID": "ses_runtime", "part": {"text": text}}) + "\n"

    def test_current_saved_model_bin_and_directory_override_old_nested_values(self):
        client = MimoSessionClient(mimo_bin="stale-bin", model="old/stale-model", cwd="stale-dir",
                                   readonly_env=True, runtime_resolver=lambda: self.runtime)
        with patch("ayana.mimo_session.subprocess.run", return_value=subprocess.CompletedProcess([], 0, self.output(), "")) as run:
            result = client.create(title="test", prompt="read", timeout=3)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "configured-mimo")
        self.assertEqual(argv[argv.index("-m") + 1], "xiaomi/model-a")
        self.assertEqual(argv[argv.index("--dir") + 1], self.tmp.name)
        self.assertEqual(run.call_args.kwargs["cwd"], self.tmp.name)
        self.assertEqual(run.call_args.kwargs["env"]["MIMOCODE_CONFIG"], self.runtime["config_path"])
        self.assertEqual(result.model, "xiaomi/model-a")

    def test_key_and_model_changes_are_resolved_for_each_call_without_restart(self):
        client = MimoSessionClient(readonly_env=True, runtime_resolver=lambda: self.runtime)
        with patch("ayana.mimo_session.subprocess.run", return_value=subprocess.CompletedProcess([], 0, self.output(), "")) as run:
            client.create(title="first", prompt="read")
            self.runtime["model"] = "xiaomi/model-b"
            self.runtime["config"]["model"] = "xiaomi/model-b"
            self.runtime["config"]["provider"]["xiaomi"]["options"]["apiKey"] = "rotated-test-key"
            client.resume("ses_runtime", "read again")
        self.assertEqual(run.call_count, 2)
        first, second = run.call_args_list
        self.assertEqual(first.args[0][first.args[0].index("-m") + 1], "xiaomi/model-a")
        self.assertEqual(second.args[0][second.args[0].index("-m") + 1], "xiaomi/model-b")
        overlay = json.loads(second.kwargs["env"]["MIMOCODE_CONFIG_CONTENT"])
        self.assertEqual(overlay["provider"]["xiaomi"]["options"]["apiKey"], "rotated-test-key")

    def test_unverified_provider_blocks_run_and_session_probe_before_subprocess(self):
        resolver = Mock(side_effect=ValueError("provider_not_verified dummy-test-key"))
        client = MimoSessionClient(runtime_resolver=resolver)
        with patch("ayana.mimo_session.subprocess.run") as run:
            for operation in (lambda: client.create(title="t", prompt="p"), lambda: client.exists("ses_old")):
                with self.assertRaises(MimoSessionError) as denied:
                    operation()
                self.assertEqual(denied.exception.code, "provider_not_verified")
                self.assertNotIn("dummy-test-key", str(denied.exception))
            run.assert_not_called()

    def test_decision_agent_can_plan_but_cannot_write_before_ops_loop(self):
        original = copy.deepcopy(self.runtime)
        client = MimoSessionClient(decision_only=True, runtime_resolver=lambda: self.runtime)
        env = client._environment(client._runtime())
        config = json.loads(env["MIMOCODE_CONFIG_CONTENT"])
        agent = config["agent"][DECISION_AGENT]
        self.assertEqual(agent["tool_allowlist"], list(DECISION_TOOLS))
        self.assertEqual(agent["permission"]["*"], "deny")
        for tool in ("bash", "write", "edit", "task", "ayana_action_execute", "ayana_knowledge_upsert"):
            self.assertNotIn(tool, agent["tool_allowlist"])
        self.assertEqual(config["mcp"]["ayana"]["environment"]["AYANA_MCP_READONLY"], "1")
        self.assertEqual(env["AYANA_MCP_READONLY"], "1")
        self.assertEqual(self.runtime, original)
        self.assertEqual(client._argv(["plan"])[client._argv(["plan"]).index("--agent") + 1], DECISION_AGENT)

    def test_runtime_key_is_redacted_from_cli_output_and_errors(self):
        client = MimoSessionClient(runtime_resolver=lambda: self.runtime)
        with patch("ayana.mimo_session.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "config rejected dummy-test-key")):
            _, _, error = client._run(["test"], 1)
            self.assertNotIn("dummy-test-key", error)
            self.assertIn("[redacted]", error)
            with self.assertRaises(MimoSessionError) as denied:
                client.create(title="t", prompt="p")
        self.assertNotIn("dummy-test-key", str(denied.exception))
        self.assertEqual(denied.exception.code, "run_failed")


    def test_nonzero_exit_with_valid_conclusion_is_not_success(self):
        client = MimoSessionClient(runtime_resolver=lambda: self.runtime)
        with patch("ayana.mimo_session.subprocess.run", return_value=subprocess.CompletedProcess([], 1, self.output('{"status":"completed"}'), "failed")):
            with self.assertRaises(MimoSessionError) as denied:
                client.resume("ses_runtime", "plan")
        self.assertEqual(denied.exception.code, "run_failed")

    def test_error_event_even_with_zero_exit_does_not_accept_stale_text(self):
        client = MimoSessionClient(runtime_resolver=lambda: self.runtime)
        output = self.output("stale conclusion") + json.dumps({"type":"error", "error":{"message":"dummy-test-key quota exhausted"}})
        with patch("ayana.mimo_session.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")):
            with self.assertRaises(MimoSessionError) as denied:
                client.create(title="t", prompt="p")
        self.assertEqual(denied.exception.code, "run_failed")
        self.assertNotIn("dummy-test-key", str(denied.exception))


class AppWiringTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ayana app binding ")
        self.addCleanup(self.tmp.cleanup)
        self.cfg = {"db_path": str(Path(self.tmp.name) / "actual.db"), "base_dir": self.tmp.name,
                    "onewbot_token": "test", "webhook_token": "test", "ssh_credential_key": "test",
                    "web_auth_pepper": "test", "mimo_bin": "web-configured-bin",
                    "mimo_config_dir": str(Path(self.tmp.name) / "production-model"),
                    "auto_investigate": {"enabled": True, "closed_loop": True, "mimo_bin": "old-bin", "mimo_model": "old/model"},
                    "prometheus_config": {"local_dir": str(Path(self.tmp.name) / "prom")}}
        self.app = App(self.cfg)
        self.addCleanup(self.app.db.close)
        self.app.db.execute("INSERT INTO incidents(id,title,asset_id,object_id,created_at,updated_at) VALUES('i','test','host','obj',?,?)", (now(), now()))

    async def test_unverified_jobs_stay_queued_without_round_or_model_call(self):
        ai = self.app.auto_investigator
        ai.offer("i")
        ai._investigate = AsyncMock(side_effect=AssertionError("unverified model called"))
        with patch.object(self.app.mimo_admin, "runtime_configuration", side_effect=ValueError("provider_not_verified")):
            before = self.app.db._connect().total_changes
            self.assertEqual(await ai.tick_once(), 0)
            self.assertEqual(self.app.db._connect().total_changes, before)
        job = ai._row("i")
        self.assertEqual((job["status"], job["rounds"], job["lease_expires_at"]), ("queued", 0, 0))
        ai._investigate.assert_not_awaited()

    async def test_read_decision_and_manual_chat_share_current_config_and_same_db(self):
        app = self.app
        self.assertEqual(app.mimo_admin.config_path().parent, Path(self.cfg["mimo_config_dir"]))
        runtime = {"mimo_bin": "web-configured-bin", "model": "xiaomi/saved-model", "cwd": self.tmp.name,
                   "config_path": str(Path(self.tmp.name) / "mimocode.jsonc"),
                   "config": {"provider": {"xiaomi": {"options": {"apiKey": "dummy-test-key"}}}, "model": "xiaomi/saved-model",
                              "mcp": {"ayana": {"command": ["wrong-project-mcp"]}}}}
        self.assertIs(app.session_bridge.mimo, app.mimo_read_client)
        self.assertIs(app.auto_investigator.mimo, app.mimo_read_client)
        self.assertIs(app.auto_investigator.mimo_write, app.mimo_decision_client)
        with patch.object(app.mimo_admin, "runtime_configuration", return_value=runtime):
            for client in (app.mimo_read_client, app.mimo_decision_client):
                bound = client._runtime()
                env = client._environment(bound)
                server = json.loads(env["MIMOCODE_CONFIG_CONTENT"])["mcp"]["ayana"]
                self.assertEqual(server["command"], [sys.executable, "-m", "ayana.mcp_server", self.tmp.name])
                self.assertEqual(server["environment"]["AYANA_MCP_DB_PATH"], str(Path(app.db.path).resolve()))
                self.assertEqual(server["environment"]["AYANA_MCP_READONLY"], "0")
                self.assertEqual(server["environment"]["AYANA_MCP_MANAGED_CONTEXT"], "1")
                self.assertIn(str(Path(__file__).resolve().parents[1]), server["environment"]["PYTHONPATH"])
                self.assertEqual(client._argv(["test"], bound)[0], "web-configured-bin")
                self.assertEqual(client._argv(["test"], bound)[client._argv(["test"], bound).index("-m") + 1], "xiaomi/saved-model")

    async def test_child_mcp_uses_explicit_db_instead_of_cwd_default(self):
        selected = Path(self.tmp.name) / "child-bound.db"
        ignored = Path(self.tmp.name) / "wrong-cwd.db"
        with patch.dict(os.environ, {"AYANA_MCP_DB_PATH": str(selected), "AYANA_MCP_READONLY": "1"}):
            context = build_ops_context({"db_path": str(ignored), "ssh_credential_key": "test", "prometheus_config": {"local_dir": str(Path(self.tmp.name) / "child-prom")}})
        try:
            self.assertEqual(Path(context.db.path), selected)
            self.assertTrue(context.readonly)
            self.assertTrue(selected.exists())
            self.assertFalse(ignored.exists())
        finally:
            context.db.close()


class CurrentClosedLoopTests(unittest.IsolatedAsyncioTestCase):
    setUp = p61.ClosedLoopE2E.setUp
    tearDown = p61.ClosedLoopE2E.tearDown
    _make_agent = p61.ClosedLoopE2E._make_agent
    _run_one = p61.ClosedLoopE2E._run_one

    async def _assert_loop_remains_responsive(self, operation, blocking_client):
        released = threading.Event()
        waited = []
        def slow_call(*args, **kwargs):
            waited.append(released.wait(1))
            return blocking_client(*args, **kwargs)
        async def release_from_main_loop():
            await asyncio.sleep(0.02)
            released.set()
        try:
            result, _ = await asyncio.gather(operation(slow_call), release_from_main_loop())
        finally:
            released.set()
        self.assertEqual(waited, [True], "model blocked the Web/event loop")
        return result

    async def test_investigation_attach_and_resume_keep_web_responsive(self):
        for reused in (False, True):
            with self.subTest(reused=reused):
                agent = self._make_agent({"status":"completed", "facts":[]})
                attach = Mock(return_value={"ok":True, "action":"reused" if reused else "created",
                                            "remote_session_id":"ses_1", "text":'{"status":"completed"}'})
                prompt = Mock(return_value={"ok":True, "text":'{"status":"completed"}'})
                async def operation(slow_call):
                    agent.bridge = SimpleNamespace(attach_remote=attach if reused else slow_call,
                                                   prompt_remote=slow_call if reused else prompt)
                    return await agent._investigate("inc1", round_no=1)
                result = await self._assert_loop_remains_responsive(operation, prompt if reused else attach)
                self.assertEqual(result["status"], "completed")

    async def test_decision_create_and_resume_keep_web_responsive(self):
        for remote_id in ("", "ses_1"):
            with self.subTest(remote_id=remote_id):
                agent = self._make_agent({"status":"completed", "facts":[]})
                def response(*args, **kwargs):
                    return RemoteSession(status="active", text='{"decision":"observe"}')
                async def operation(slow_call):
                    agent.mimo_write = SimpleNamespace(create=slow_call, resume=slow_call)
                    return await agent._decide_remediation("inc1", {"remote_session_id":remote_id}, generation=1)
                result = await self._assert_loop_remains_responsive(operation, response)
                self.assertEqual(result["decision"], "observe")

    async def test_timeout_does_not_accept_late_model_result_or_start_execution(self):
        agent = self._make_agent({"status":"completed", "facts":[]})
        started = threading.Event()
        released = threading.Event()
        completed = threading.Event()
        def slow_attach(*args, **kwargs):
            started.set()
            try:
                released.wait(1)
                return {"ok":True, "action":"created", "text":'{"status":"completed"}'}
            finally:
                completed.set()
        agent.bridge = SimpleNamespace(attach_remote=slow_attach)
        agent.config.timeout_sec = 0.05
        agent._close_loop = AsyncMock()
        try:
            await self._run_one(agent)
            self.assertTrue(started.is_set())
            self.assertEqual(agent._row("inc1")["status"], "timeout")
            agent._close_loop.assert_not_awaited()
        finally:
            released.set()
            await asyncio.to_thread(completed.wait, 1)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)
        agent._close_loop.assert_not_awaited()

    async def test_real_remote_session_object_decision_reaches_autonomous_action(self):
        agent = self._make_agent({"status": "completed", "root_cause": "down", "facts": [{"claim": "down", "evidence": "probe"}]},
                                 decision_text=json.dumps({"decision": "execute", "capability": "service.restart", "object_id": "obj", "evidence_ok": True}))
        # Exercise the actual production return type, not a permissive dict fake.
        agent.mimo_write.resume = lambda *a, **kw: RemoteSession(remote_session_id="ses_1", status="active", text=json.dumps({"decision": "execute", "capability": "service.restart", "object_id": "obj", "evidence_ok": True}))
        await self._run_one(agent)
        rows = self.db.query("SELECT mode,state FROM actions WHERE incident_id='inc1'")
        self.assertEqual([tuple(r) for r in rows], [("autonomous", "success")])
        self.assertEqual(len(self.transport.calls), 1)

    async def test_suggested_action_without_explicit_true_evidence_never_dispatches(self):
        for evidence in (False, None, "true", 1):
            with self.subTest(evidence=evidence):
                agent = self._make_agent({"status": "partial", "root_cause": "unknown", "facts": [],
                                         "suggested_action": {"capability": "service.restart", "object_id": "obj", "evidence_ok": evidence}})
                decision = await agent._decide_remediation("inc1", agent.mimo.conclusion, generation=1)
                self.assertEqual(decision["decision"], "human")
                await agent._close_loop("inc1", agent.mimo.conclusion, generation=1)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)
        self.assertEqual(self.transport.calls, [])

    async def test_generation_changed_while_deciding_cannot_dispatch_or_escalate_new_incident(self):
        agent = self._make_agent({"status": "completed", "facts": []})
        async def changed(*args, **kwargs):
            self.db.execute("UPDATE incidents SET generation=2,stage='pending'")
            return {"decision": "execute", "capability": "service.restart", "object_id": "obj", "evidence_ok": True}
        agent._decide_remediation = AsyncMock(side_effect=changed)
        self.loop.run_action_and_verify = AsyncMock()
        self.loop.escalate = Mock()
        result = await agent._close_loop("inc1", {}, generation=1)
        self.assertEqual(result["skipped"], "incident_changed")
        self.loop.run_action_and_verify.assert_not_awaited()
        self.loop.escalate.assert_not_called()
        self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)

    async def test_provider_cleared_while_deciding_blocks_dispatch(self):
        agent = self._make_agent({"status": "completed", "facts": []})
        agent.readiness_callback = Mock(side_effect=[True, False])
        agent._decide_remediation = AsyncMock(return_value={"decision": "execute", "capability": "service.restart", "object_id": "obj", "evidence_ok": True})
        self.loop.run_action_and_verify = AsyncMock()
        result = await agent._close_loop("inc1", {}, generation=1)
        self.assertEqual(result["skipped"], "provider_not_verified")
        self.loop.run_action_and_verify.assert_not_awaited()

    async def test_stale_finish_cannot_continue_into_closed_loop(self):
        agent = self._make_agent({"status": "completed", "facts": []})
        agent.offer("inc1")
        self.db.execute("UPDATE investigation_jobs SET status='running' WHERE incident_id='inc1'")
        old = agent._row("inc1")
        async def changed(*args, **kwargs):
            self.db.execute("UPDATE incidents SET generation=2,stage='pending'")
            agent.offer("inc1", generation=2)
            return {"status": "completed", "facts": []}
        agent._investigate = AsyncMock(side_effect=changed)
        agent._close_loop = AsyncMock()
        await agent._run_job("inc1", old)
        agent._close_loop.assert_not_awaited()
        current = agent._row("inc1")
        self.assertEqual((current["generation"], current["status"], current["rounds"]), (2, "queued", 0))

    async def test_mcp_execute_cannot_bypass_ops_loop_hard_round_limit(self):
        actions = SimpleNamespace(autonomous_execute=AsyncMock(), verify=AsyncMock())
        loop = OpsLoop(self.db, actions=actions, incidents=self.incidents)
        loop._state("inc1")
        loop._save("inc1", rounds=MAX_EXECUTE_ROUNDS, status="running")
        tools = OpsTools(OpsContext(None, None, self.incidents, None, db=self.db, actions=actions, ops_loop=loop))
        result = await tools.call("action.execute", {"incident_id": "inc1", "asset_id": "host", "object_id": "obj", "capability": "service.restart"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "max_execute_rounds")
        actions.autonomous_execute.assert_not_awaited()
        self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)

    async def test_mcp_execute_requires_incident_binding_and_wired_loop(self):
        actions = SimpleNamespace(autonomous_execute=AsyncMock())
        tools = OpsTools(OpsContext(None, None, self.incidents, None, db=self.db, actions=actions))
        with self.assertRaises(McpToolError) as denied:
            await tools.call("action.execute", {"asset_id": "host", "object_id": "obj", "capability": "service.restart"})
        self.assertEqual(denied.exception.code, "unavailable")
        actions.autonomous_execute.assert_not_awaited()
        spec = next(spec for spec in TOOL_SPECS if spec["name"] == "action.execute")
        self.assertIn("incident_id", spec["inputSchema"]["required"])


if __name__ == "__main__":
    unittest.main()
