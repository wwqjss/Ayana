"""Portable stdio launch and MiMo CLI configuration regressions (no model calls)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.mimo_session import MimoSessionClient, MimoSessionError, READONLY_AGENT, READONLY_TOOLS  # noqa: E402


class TestMcpLauncher(unittest.TestCase):
    def test_stdio_from_unrelated_directory_with_spaces(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="ayana launch test ") as temp:
            base = Path(temp)
            cwd = base / "unrelated working directory"
            config_dir = base / "isolated config directory"
            cwd.mkdir()
            config_dir.mkdir()
            db_path = config_dir / "isolated test.db"
            (config_dir / "config.json").write_text(
                json.dumps({"db_path": str(db_path)}), encoding="utf-8"
            )
            env = {k: v for k, v in os.environ.items() if not k.startswith("AYANA_")}
            env.update({
                "AYANA_ONEWBOT_TOKEN": "unit-test-only",
                "AYANA_WEBHOOK_TOKEN": "unit-test-only",
                "AYANA_MCP_READONLY": "1",
                # Protocol output must override a legacy/non-Unicode parent setting.
                "PYTHONIOENCODING": "ascii",
            })
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            ]
            for i, name, args in [
                (3, "incident.note", {"incident_id": "absent", "text": "blocked"}),
                (4, "session.remote", {"incident_id": "absent"}),
                (5, "host.exec", {"asset_id": "absent", "command": "uptime; touch /tmp/x"}),
            ]:
                requests.append({
                    "jsonrpc": "2.0", "id": i, "method": "tools/call",
                    "params": {"name": name, "arguments": args},
                })
            proc = subprocess.run(
                [sys.executable, str(root / "scripts" / "mcp_stdio_launcher.py"), str(config_dir)],
                input="".join(json.dumps(msg) + "\n" for msg in requests),
                cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8",
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            responses = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
            self.assertEqual(len(responses), len(requests), proc.stdout)
            self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "ayana-mcp")
            names = {spec["name"] for spec in responses[1]["result"]["tools"]}
            self.assertTrue({"knowledge.query", "asset.list", "host.exec"} <= names)
            for reply in responses[2:]:
                self.assertTrue(reply["result"]["isError"])
                payload = json.loads(reply["result"]["content"][0]["text"])
                self.assertEqual(payload["error"], "readonly_mode_rejects_write")
            self.assertTrue(db_path.is_file())
            self.assertFalse((cwd / "ayana.db").exists())


class TestMimoCliConfiguration(unittest.TestCase):
    def test_create_and_resume_keep_dir_and_readonly_environment(self):
        with tempfile.TemporaryDirectory(prefix="ayana mimo cli test ") as cwd:
            client = MimoSessionClient(
                mimo_bin="mimo-test", model="unit-test-model", cwd=cwd, readonly_env=True,
            )
            output = json.dumps({
                "type": "text", "sessionID": "ses_test123", "part": {"text": "ok"},
            }) + "\n"
            with patch.dict(os.environ, {"AYANA_MCP_READONLY": "0"}):
                with patch("ayana.mimo_session.subprocess.run") as run:
                    run.return_value = subprocess.CompletedProcess([], 0, output, "")
                    client.create(title="isolated", prompt="inspect", timeout=7)
                    client.resume("ses_test123", "continue", timeout=8)
                self.assertEqual(os.environ["AYANA_MCP_READONLY"], "0")
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                argv = call.args[0]
                self.assertEqual(argv[argv.index("--dir") + 1], cwd)
                self.assertEqual(argv[argv.index("-m") + 1], "unit-test-model")
                self.assertEqual(argv[argv.index("--agent") + 1], READONLY_AGENT)
                self.assertEqual(call.kwargs["cwd"], cwd)
                self.assertEqual(call.kwargs["env"]["AYANA_MCP_READONLY"], "1")
                self.assertNotIn("shell", call.kwargs)
            self.assertEqual(run.call_args_list[0].kwargs["timeout"], 7)
            self.assertEqual(run.call_args_list[1].kwargs["timeout"], 8)
            self.assertIn("--session", run.call_args_list[1].args[0])

    def test_readonly_overlay_preserves_provider_mcp_and_other_agents(self):
        content = {
            "provider": {"unit-test-provider": {"options": {"apiKey": "unit-test-only"}}},
            "mcp": {"ayana": {"type": "local", "command": ["python", "launcher.py"]}},
            "agent": {
                "other-agent": {"permission": "allow"},
                READONLY_AGENT: {
                    "description": "preserved", "disable": True,
                    "tool_allowlist": ["bash", "write"], "permission": {"*": "allow"},
                },
            },
        }
        original = json.dumps(content)
        with patch.dict(os.environ, {
            "MIMOCODE_CONFIG_CONTENT": original, "MIMOCODE_PERMISSION": '{"*":"allow"}',
        }):
            env = MimoSessionClient(readonly_env=True)._environment()
            self.assertEqual(os.environ["MIMOCODE_CONFIG_CONTENT"], original)
            self.assertEqual(os.environ["MIMOCODE_PERMISSION"], '{"*":"allow"}')
        parsed = json.loads(env["MIMOCODE_CONFIG_CONTENT"])
        self.assertEqual(parsed["provider"], content["provider"])
        self.assertEqual(parsed["mcp"], content["mcp"])
        self.assertEqual(parsed["agent"]["other-agent"], content["agent"]["other-agent"])
        agent = parsed["agent"][READONLY_AGENT]
        self.assertEqual(agent["description"], "preserved")
        self.assertFalse(agent["disable"])
        self.assertEqual(agent["tool_allowlist"], list(READONLY_TOOLS))
        policy = agent["permission"]
        self.assertEqual(policy["*"], "deny")
        self.assertEqual(policy["mcp_tool_search"], "allow")
        self.assertTrue(all(policy[name] == "allow" for name in READONLY_TOOLS))
        self.assertEqual(json.loads(env["MIMOCODE_PERMISSION"]), policy)
        for tool in ("bash", "write", "edit", "exec", "task", "actor", "skill",
                     "ayana_session_remote", "ayana_knowledge_upsert", "ayana_incident_close"):
            self.assertNotIn(tool, agent["tool_allowlist"])
            self.assertEqual(policy.get(tool, policy["*"]), "deny")

    def test_readonly_invalid_config_fails_before_starting_process(self):
        for content in ("unit-test-sensitive-invalid", "[]", '"allow"', '{"agent":[]}',
                        '{"agent":{"ayana-readonly":false}}'):
            with self.subTest(content_type=type(content).__name__):
                with patch.dict(os.environ, {"MIMOCODE_CONFIG_CONTENT": content}):
                    with patch("ayana.mimo_session.subprocess.run") as run:
                        with self.assertRaises(MimoSessionError) as caught:
                            MimoSessionClient(readonly_env=True).create(title="t", prompt="p")
                    run.assert_not_called()
                self.assertEqual(caught.exception.code, "readonly_config_invalid")
                self.assertNotIn("unit-test-sensitive-invalid", str(caught.exception))

    def test_nonreadonly_environment_and_agent_selection_unchanged(self):
        with patch.dict(os.environ, {
            "MIMOCODE_CONFIG_CONTENT": "invalid-but-unrelated",
            "MIMOCODE_PERMISSION": '{"*":"allow"}',
        }):
            client = MimoSessionClient(readonly_env=False)
            self.assertEqual(client._environment(), dict(os.environ))
            self.assertNotIn("--agent", client._argv(["inspect"]))

    def test_default_client_does_not_add_directory_argument(self):
        client = MimoSessionClient(mimo_bin="mimo-test", model="unit-test-model")
        self.assertNotIn("--dir", client._argv(["inspect"]))


if __name__ == "__main__":
    unittest.main()
