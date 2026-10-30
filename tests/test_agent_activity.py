"""Native activity is a bounded read-only projection, never model narration."""
import asyncio
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from ayana.agent_activity import project_native_activity, read_native_activity


def user(identity="user-new", at=20):
    return {"info": {"role": "user", "id": identity, "time": {"created": at}}, "parts": []}


def assistant(parts, parent="user-new", at=21):
    return {"info": {"role": "assistant", "parentID": parent, "sessionID": "native", "time": {"created": at}}, "parts": parts}


def tool(identity="tool-1", status="completed", at=22, **state):
    return {"type": "tool", "id": identity, "tool": "ayana_host_exec", "state": {"status": status, "time": {"start": at}, **state}}


class NativeActivityTests(unittest.TestCase):
    def test_current_round_only_and_no_reasoning_commands_outputs_or_secrets(self):
        messages = [user("user-old", 1), assistant([tool("old", "running")], parent="user-old"), user(),
                    assistant([{"type": "reasoning", "text": "SECRET reasoning"}, {"type": "text", "text": "SECRET narrative"},
                               tool(status="running", input={"asset_id": "nerv", "channel": "read", "command": "SECRET command"},
                                    output="SECRET output", metadata={"password": "SECRET password"})])]
        result = project_native_activity(messages, remote_id="native")
        self.assertEqual([row["id"] for row in result["tools"]], ["tool-1"])
        self.assertEqual(result["current"]["target"], "nerv")
        self.assertEqual(result["current"]["channel"], "read")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("output", json.dumps(result))

    def test_real_mcp_tool_use_wrapper_projects_registered_name_target_and_channel_only(self):
        wrapped = tool(status="running", input={
            "name": "ayana_host_exec", "asset_id": "incorrect-top-level", "channel": "write",
            "arguments": {"asset_id": "nerv", "channel": "read", "command": "SECRET command", "value": "SECRET value"},
        })
        wrapped["tool"] = "mcp_tool_use"
        result = project_native_activity([user(), assistant([wrapped])])
        current = result["current"]
        self.assertEqual(current["tool"], "ayana_host_exec")
        self.assertEqual(current["target"], "nerv")
        self.assertEqual(current["channel"], "read")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("incorrect-top-level", json.dumps(result))
        self.assertNotIn("arguments", json.dumps(result))

    def test_real_check_wrapper_retains_safe_structured_refusal(self):
        wrapped = tool(status="error", input={"name": "ayana_config_check_add", "arguments": {
            "asset_id": "nerv", "kind": "command", "params": {"argv": ["SECRET"]}}},
            error={"code": "unsafe_command", "message": "SECRET command rejected"})
        wrapped["tool"] = "mcp_tool_use"
        result = project_native_activity([user(), assistant([wrapped])])
        item = result["latest_error"]
        self.assertEqual(item["tool"], "ayana_config_check_add")
        self.assertEqual(item["target"], "nerv")
        self.assertEqual(item["error"]["code"], "unsafe_command")
        self.assertNotIn("SECRET", json.dumps(result))

    def test_wrapper_never_guesses_unknown_tools_or_json_string_arguments(self):
        for name, arguments in (("bash", {"asset_id": "SECRET"}), ("ayana_not_registered", {"asset_id": "SECRET"}),
                                ("ayana_host_exec", json.dumps({"asset_id": "SECRET", "command": "SECRET"}))):
            with self.subTest(name=name):
                wrapped = tool(status="running", input={"name": name, "arguments": arguments})
                wrapped["tool"] = "mcp_tool_use"
                result = project_native_activity([user(), assistant([wrapped])])
                self.assertNotIn("SECRET", json.dumps(result))
                if name != "ayana_host_exec":
                    self.assertEqual(result["tools"], [])
                else:
                    self.assertEqual(result["current"]["target"], "")

    def test_queued_new_parent_does_not_show_previous_turn_tools(self):
        messages = [user("old", 1), assistant([tool(status="running")], parent="old"), user("new", 30)]
        result = project_native_activity(messages, parent_id="new")
        self.assertTrue(result["available"])
        self.assertEqual(result["tools"], [])
        self.assertIsNone(result["current"])
        stale = project_native_activity(messages, parent_id="old")
        self.assertFalse(stale["available"])
        self.assertEqual(stale["tools"], [])

    def test_durable_parent_filters_history_when_user_is_outside_the_page(self):
        result = project_native_activity([assistant([tool()], parent="new"), assistant([tool("old")], parent="old")], parent_id="new")
        self.assertEqual([row["id"] for row in result["tools"]], ["tool-1"])
        self.assertFalse(project_native_activity([assistant([tool()])])["available"])

    def test_conflicting_user_and_missing_durable_parent_never_reuse_old_steps(self):
        result = project_native_activity([user("another", 30), assistant([tool()], parent="expected")], parent_id="expected")
        self.assertFalse(result["available"])
        self.assertEqual(result["tools"], [])

    def test_optional_prometheus_source_is_a_notice_not_a_tool_failure(self):
        output = {"ok": False, "available": False, "source": "prometheus", "error": "prometheus_unavailable",
                  "optional": True, "fatal": False, "result": None}
        wrapped = {"content": [{"type": "text", "text": json.dumps(output)}]}
        result = project_native_activity([user(), assistant([tool(output=json.dumps(wrapped))])])
        self.assertEqual(result["tools"][0]["status"], "completed")
        self.assertIn("Prometheus", result["tools"][0]["notice"])
        self.assertIsNone(result["latest_error"])
        wrapped["isError"] = True
        explicit = project_native_activity([user(), assistant([tool(output=json.dumps(wrapped))])])
        self.assertEqual(explicit["tools"][0]["status"], "error")

    def test_recovery_excludes_prior_assistants_even_with_the_same_parent(self):
        old = assistant([tool("old-tool", "running")])
        old["info"]["id"] = "assistant-before-recovery"
        new = assistant([tool("new-tool", "running")])
        new["info"]["id"] = "assistant-after-recovery"
        result = project_native_activity([old, new], parent_id="user-new", exclude_message_ids=["assistant-before-recovery"])
        self.assertEqual([item["id"] for item in result["tools"]], ["new-tool"])

    def test_tools_and_latest_error_are_sorted_by_real_time_not_response_order(self):
        result = project_native_activity([user(), assistant([tool("late", "error", 40, error={"code": "unknown_field", "message": "SECRET"}),
                                                            tool("active", "running", 50), tool("early", "error", 30)])])
        self.assertEqual([row["id"] for row in result["tools"]], ["early", "late", "active"])
        self.assertEqual(result["latest_error"]["id"], "late")
        self.assertEqual(result["current"]["id"], "active")
        self.assertEqual(result["latest_error"]["error"]["code"], "unknown_field")
        self.assertNotIn("SECRET", json.dumps(result))

    def test_structured_mcp_rejection_in_completed_part_is_an_error(self):
        output = {"content": [{"type": "text", "text": json.dumps({"ok": False, "error": "unsafe_command", "message": "SECRET"})}]}
        result = project_native_activity([user(), assistant([tool(output=json.dumps(output))])])
        self.assertEqual(result["tools"][0]["status"], "error")
        self.assertEqual(result["latest_error"]["error"]["code"], "unsafe_command")
        self.assertNotIn("SECRET", json.dumps(result))

    def test_business_return_code_is_not_mislabeled_as_tool_rejection_or_recovery(self):
        result = project_native_activity([user(), assistant([tool(output=json.dumps({"ok": False, "returncode": 3, "output": "SECRET service state"}))])])
        self.assertEqual(result["tools"][0]["status"], "completed")
        self.assertIsNone(result["latest_error"])
        self.assertNotIn("SECRET", json.dumps(result))

    def test_unknown_error_text_never_leaks_and_malformed_parts_are_ignored(self):
        result = project_native_activity([user(), assistant([tool(error="SECRET command or credential", status="error"),
                                                           {"type": "tool", "tool": "x", "state": {"status": {"bad": True}}}])])
        self.assertEqual(len(result["tools"]), 1)
        self.assertEqual(result["latest_error"]["error"]["code"], "tool_error")
        self.assertNotIn("SECRET", json.dumps(result))

    def test_wrong_remote_session_is_not_used(self):
        result = project_native_activity([user(), assistant([tool()])], remote_id="different")
        self.assertEqual(result["tools"], [])


class NativeActivityReadTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_has_page_limit_and_timeout_without_replay(self):
        calls = []
        class Client:
            async def messages(self, identity, *, limit):
                calls.append((identity, limit))
                await asyncio.sleep(1)
        result = await read_native_activity(Client(), "native", timeout=.01)
        self.assertEqual(calls, [("native", 20)])
        self.assertFalse(result["available"])
        self.assertEqual(result["tools"], [])

    async def test_read_failure_is_explicit_and_cannot_change_task_state(self):
        class Client:
            async def messages(self, *args, **kwargs):
                raise RuntimeError("SECRET upstream error")
        result = await read_native_activity(Client(), "native")
        self.assertFalse(result["available"])
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("task_state", result)


class NativeActivityWebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from ayana.db import Database
        from ayana.duty_session import DutySessionManager
        from ayana.web import WebApp
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "activity.db")
        self.duty = DutySessionManager(self.db)
        self.sid = self.duty.create(origin="manual")["session_id"]
        self.db.execute("UPDATE duty_sessions SET remote_session_id='native' WHERE id=?", (self.sid,))
        self.duty.record_native_turn(self.sid, "native", "new", "accepted")
        self.duty.set_runtime_state(self.sid, "unknown", receipt_status="unknown")
        self.calls = []
        async def messages(identity, *, limit):
            self.calls.append((identity, limit))
            wrapped = tool("current-tool", "error", input={"name": "ayana_config_check_add", "arguments": {"asset_id": "nerv", "params": {"cmd": "SECRET"}}}, error={"code": "unsafe_command", "message": "SECRET"})
            wrapped["tool"] = "mcp_tool_use"
            return [user("old", 1), assistant([tool("old-tool", "running")], parent="old"),
                    user("new", 30), assistant([wrapped], parent="new")]
        self.handler = WebApp.__new__(WebApp)
        self.handler.db = self.db
        self.handler._require_auth = lambda request: {"is_admin": True}
        self.handler._duty = lambda: self.duty
        self.handler._agent_session_require = lambda session, identity: self.duty.get(identity)
        self.handler._bridge = lambda: None
        self.handler.mimo_serve = SimpleNamespace(client=lambda: SimpleNamespace(messages=messages))
        self.handler.agent_tui = None

    async def asyncTearDown(self):
        self.db.close()
        self.tmp.cleanup()

    async def test_session_detail_projects_current_round_without_mutating_unknown(self):
        before = [tuple(row) for row in self.db.query("SELECT * FROM agent_native_submissions")]
        response = await self.handler.api_agent_session_detail(SimpleNamespace(match_info={"sid": self.sid}))
        data = json.loads(response.text)
        self.assertEqual(data["task_state"], "unknown")
        self.assertEqual([item["id"] for item in data["native_activity"]["tools"]], ["current-tool"])
        self.assertEqual(data["native_activity"]["latest_error"]["tool"], "ayana_config_check_add")
        self.assertEqual(data["native_activity"]["latest_error"]["target"], "nerv")
        self.assertNotIn("SECRET", json.dumps(data["native_activity"]))
        self.assertEqual(self.calls, [("native", 20)])
        self.assertEqual([tuple(row) for row in self.db.query("SELECT * FROM agent_native_submissions")], before)

    async def test_session_detail_read_failure_preserves_authoritative_task_state(self):
        async def failed(*args, **kwargs):
            raise RuntimeError("SECRET transport error")
        self.handler.mimo_serve = SimpleNamespace(client=lambda: SimpleNamespace(messages=failed))
        response = await self.handler.api_agent_session_detail(SimpleNamespace(match_info={"sid": self.sid}))
        data = json.loads(response.text)
        self.assertEqual(data["task_state"], "unknown")
        self.assertFalse(data["native_activity"]["available"])
        self.assertNotIn("SECRET", json.dumps(data["native_activity"]))
