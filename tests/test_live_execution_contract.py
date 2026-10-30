"""Current native-agent instructions must agree with the live MCP entry points."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ayana.db import Database
from ayana.mcp_tools import TOOL_SPECS
from ayana.mimo_serve import MimoServeManager
from ayana.ops_constraints import DEFAULT_CONSTRAINTS, MANAGED_EXECUTION_PROMPT, OpsConstraints


class LiveExecutionContractTests(unittest.TestCase):
    def managed_runtime(self):
        return {"managed_context": True, "config": {"mcp": {"ayana": {"environment": {}}}}}

    def test_managed_native_agent_has_current_contract_and_host_execution(self):
        runtime = self.managed_runtime()
        manager = MimoServeManager(password="test")
        env = manager._env(runtime)
        config = json.loads(env["MIMOCODE_CONFIG_CONTENT"])
        agent = config["agent"]["ayana"]
        self.assertEqual(agent["prompt"], MANAGED_EXECUTION_PROMPT)
        self.assertEqual(set(agent["tool_allowlist"]), {
            "ayana_" + spec["name"].replace(".", "_") for spec in TOOL_SPECS
        })
        self.assertIn("ayana_host_exec", agent["tool_allowlist"])
        self.assertIn("ayana_ops_constraints", agent["tool_allowlist"])
        self.assertNotIn("ayana_action_execute", agent["tool_allowlist"])
        self.assertEqual(agent["permission"]["ayana_host_exec"], "allow")
        self.assertEqual(agent["permission"]["*"], "deny")
        self.assertEqual(env["AYANA_MCP_READONLY"], "0")
        self.assertEqual(config["mcp"]["ayana"]["environment"]["AYANA_MCP_READONLY"], "0")
        self.assertEqual(runtime, self.managed_runtime())

    def test_current_contract_covers_continuations_work_scope_and_uncertainty(self):
        prompt = MANAGED_EXECUTION_PROMPT
        for requirement in ("开始、继续或恢复", "ayana_ops_constraints", "当前工具目录", "历史消息",
                            "ayana_host_exec", "incident_id", "当前故障代次", "ayana_session_claim",
                            "unknown", "盲目重试", "命令成功不等于故障恢复", "没有充分证据不得宣称 recovered"):
            self.assertIn(requirement, prompt)

    def test_default_constraints_describe_soft_budgets_and_current_account_group(self):
        self.assertNotIn("由平台独立限次", DEFAULT_CONSTRAINTS)
        self.assertNotIn("ActionService", DEFAULT_CONSTRAINTS)
        self.assertIn("由你根据执行证据记录并遵守", DEFAULT_CONSTRAINTS)
        self.assertIn("当前会话账号组", DEFAULT_CONSTRAINTS)
        self.assertIn("真实 incident_id", DEFAULT_CONSTRAINTS)
        self.assertIn("该工单当前代次", DEFAULT_CONSTRAINTS)

    def test_progress_guidance_requests_public_facts_without_repeated_logs_or_reasoning(self):
        for requirement in ("简短中文", "关键阶段", "失败原因", "下一步", "内部思考", "验证依据", "无需逐次复述工具日志"):
            self.assertIn(requirement, MANAGED_EXECUTION_PROMPT)
        self.assertIn("工具调用错误不等于目标业务故障", DEFAULT_CONSTRAINTS)

    def test_custom_active_constraints_remain_the_current_version(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "test.db")
            try:
                constraints = OpsConstraints(db)
                self.assertTrue(constraints.current()["is_default"])
                current = constraints.save("custom operation constraint", actor="test")
                MimoServeManager(password="test")._env(self.managed_runtime())
                self.assertEqual(constraints.current()["text"], "custom operation constraint")
                self.assertEqual(constraints.current()["version"], current["version"])
            finally:
                db.close()

    def test_contract_changes_invalidate_runtime_attestation(self):
        manager = MimoServeManager(password="test")
        before = manager._digest(self.managed_runtime())
        with patch("ayana.ops_constraints.MANAGED_EXECUTION_PROMPT", MANAGED_EXECUTION_PROMPT + "\nupdated"):
            self.assertNotEqual(before, manager._digest(self.managed_runtime()))

    def test_unmanaged_readonly_profile_is_not_promoted(self):
        env = MimoServeManager(password="test")._env({"config": {"mcp": {"ayana": {"environment": {}}}}})
        config = json.loads(env["MIMOCODE_CONFIG_CONTENT"])
        self.assertEqual(config["default_agent"], "ayana-readonly")
        self.assertNotIn("ayana", config["agent"])
        self.assertEqual(env["AYANA_MCP_READONLY"], "1")


if __name__ == "__main__":
    unittest.main()
