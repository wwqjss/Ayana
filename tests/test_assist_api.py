"""Form drafts stay read-only, use server context, and survive real submission."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from aiohttp import web

from ayana import formspec
from ayana.checks import CheckService
from ayana.db import Database
from ayana.web import WebApp

class RecordingLLM:
    enabled = True

    def __init__(self, response):
        self.response = response
        self.calls = []

    async def chat_raw(self, messages, **kwargs):
        self.calls.append({"messages": copy.deepcopy(messages), **kwargs})
        return {"content": json.dumps(self.response, ensure_ascii=False), "status": 200, "finish_reason": "stop"}

class NoExecutionTransport:
    def __init__(self):
        self.calls = []

    async def probe(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("drafting a form must not execute a probe")

def request_json(body):
    return SimpleNamespace(json=AsyncMock(return_value=body), rel_url=SimpleNamespace(query={}))

def response_json(response):
    return json.loads(response.body)

def model_draft(**overrides):
    fields = {"asset_id": "romi", "kind": "service", "name": "网站服务运行情况", "params.unit": "nginx", "interval_sec": 60, "fail_threshold": 2, "severity": "warning"}
    fields.update(overrides)
    return {"route": "checks_form", "fields": fields}

class AssistAPITest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "test.db")
        for ident, display_name, enabled in (("romi", "网站主机", 1), ("archive", "停用主机", 0)):
            self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,enabled,created_at,updated_at) VALUES(?,?,?,?,?,1,1)", (ident, display_name, ident, ident + "-exec", enabled))
        self.db.execute("INSERT INTO objects(id,asset_id,kind,name,unit,created_at) VALUES('obj-web','romi','service','网站服务','nginx',1)")
        self.transport = NoExecutionTransport()
        self.checks = CheckService(self.db, self.transport)
        self.app = WebApp(self.db, None, Mock(), None, None, None, None, static_dir=Path(self.tmp.name), transport=self.transport, checks=self.checks, llm=RecordingLLM(model_draft()))
        self.session = {"username": "admin", "is_admin": True}
        self.app._require_auth = Mock(return_value=self.session)
        self.app._check_csrf = Mock()
        self.app._check_read = Mock(return_value=self.session)
        self.app._check_write = Mock(return_value=self.session)
        self.app._require_admin = Mock(return_value=self.session)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def count(self, table):
        return self.db.query_one("SELECT COUNT(*) AS n FROM " + table)["n"]

    async def draft(self, **body):
        request_body = {"domain": "checks", "text": "监控网站主机的网站服务运行情况"}
        request_body.update(body)
        return await self.app.api_assist_configure(request_json(request_body))

    async def test_server_inventory_display_labels_and_real_objects_ground_prompt(self):
        response = await self.draft(context={"assets": [{"id": "forged-host", "display_name": "伪造主机"}], "capabilities": ["root.everything"]})
        self.assertTrue(response_json(response)["ok"], response_json(response))
        scene = json.loads(self.app.llm.calls[0]["messages"][-1]["content"])["scene"]
        asset_context = str(scene["context"]["assets"])
        self.assertIn("romi", asset_context)
        self.assertIn("网站主机", asset_context)
        self.assertIn("nginx", asset_context)
        self.assertNotIn("archive", asset_context)
        self.assertNotIn("forged-host", str(scene))
        self.assertNotIn("root.everything", str(scene))

    async def test_draft_does_not_create_checks_change_permissions_or_execute(self):
        permissions_before = self.count("permissions")
        response = await self.draft()
        self.assertTrue(response_json(response)["ok"], response_json(response))
        self.assertEqual(self.count("checks"), 0)
        self.assertEqual(self.count("permissions"), permissions_before)
        self.assertEqual(self.transport.calls, [])

    async def test_semantic_unknown_answer_remains_a_question_and_resolved_reply_is_validated(self):
        original = "观察处理请求的那个组件"
        model_response = {"route": "checks_form", "fields": {"asset_id": "romi", "kind": "service"}, "clarifications": [{"id": "target_component", "label": "检查对象", "question": "你说的是处理网页请求的组件，还是处理后台任务的组件？", "options": [{"label": "网页请求", "value": "负责处理网页请求的组件"}, {"label": "不清楚", "value": "我还不清楚，请解释两者的区别"}]}], "missing": [{"field": "params.unit", "question": "服务名称是什么？"}], "confirm_question": "确认尚未确定的服务名称吗？"}
        self.app.llm = RecordingLLM(model_response)
        first = response_json(await self.draft(text=original))
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["status"], "needs_input")
        self.assertIsNone(first["payload"])
        self.assertFalse(first["ready_to_submit"])
        self.assertFalse(first["confirm_question"])
        self.assertEqual({item["field"] for item in first["missing"]}, {"clarification.target_component"})
        self.assertTrue(all(option["mode"] == "answer" for option in first["missing"][0]["options"]))
        unknown_answer = "我还不清楚，请解释两者的区别"
        second = response_json(await self.draft(text=original, context={"draft": {"fields": first["fields"], "original_text": original}, "answers": [{"field": "clarification.target_component", "text": unknown_answer}]}))
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["status"], "needs_input")
        self.assertIsNone(second["payload"])
        self.assertNotIn("params.unit", second["fields"])
        scene = json.loads(self.app.llm.calls[-1]["messages"][-1]["content"])["scene"]
        self.assertEqual(scene["context"]["extra"]["answers"][-1], {"field": "clarification.target_component", "text": unknown_answer})
        self.assertEqual(self.count("checks"), 0)
        self.assertEqual(self.count("permissions"), 0)
        self.assertEqual(self.transport.calls, [])
        self.app.llm.response = model_draft()
        resolved_answer = "我要观察网站主机上已经登记的网站服务"
        third = response_json(await self.draft(text=original, context={"draft": {"fields": second["fields"], "original_text": original}, "answers": [{"field": "clarification.target_component", "text": unknown_answer}, {"field": "clarification.target_component", "text": resolved_answer}]}))
        self.assertTrue(third["ok"], third)
        self.assertEqual(third["status"], "ready")
        self.assertTrue(third["ready_to_submit"])
        checked = response_json(await self.app.api_checks_validate(request_json({"fields": third["fields"]})))
        self.assertTrue(checked["ok"], checked)
        self.assertEqual(third["payload"], checked["payload"])
        self.assertEqual(self.count("checks"), 0)
        self.assertEqual(self.transport.calls, [])

    async def test_semantic_metadata_cannot_bypass_visible_asset_or_field_validation(self):
        for overrides in ({"asset_id": "archive"}, {"params.unit": "nginx;id"}, {"interval_sec": True}):
            with self.subTest(overrides=overrides):
                model_response = model_draft(**overrides)
                model_response["clarifications"] = [{"id": "success_criterion", "label": "成功标准", "question": "你想观察服务运行，还是观察它完成工作？"}]
                self.app.llm = RecordingLLM(model_response)
                result = response_json(await self.draft())
                self.assertFalse(result["ok"], result)
                self.assertTrue(result["message"], result)
                self.assertIsNone(result.get("payload"))
                self.assertEqual(len(self.app.llm.calls), 2)
                self.assertEqual(result["diagnostics"]["model_result"], model_response)
        self.assertEqual(self.count("checks"), 0)
        self.assertEqual(self.count("permissions"), 0)
        self.assertEqual(self.transport.calls, [])

    async def test_malformed_semantic_metadata_returns_readable_failure_without_effects(self):
        for clarification in ({"id": "target.component", "question": "哪个对象？"}, {"id": "target", "question": {}}, {"id": "target", "question": "哪个对象？", "options": [{"label": "执行", "value": "立即执行", "mode": "field_value"}]}):
            with self.subTest(clarification=clarification):
                model_response = model_draft()
                model_response["clarifications"] = [clarification]
                self.app.llm = RecordingLLM(model_response)
                response = await self.draft()
                result = response_json(response)
                self.assertEqual(response.status, 200, result)
                self.assertFalse(result["ok"], result)
                self.assertTrue(result["message"], result)
                self.assertNotEqual(result["message"], result["error"])
                self.assertEqual(result["diagnostics"]["model_result"], model_response)
        self.assertEqual(self.count("checks"), 0)
        self.assertEqual(self.count("permissions"), 0)
        self.assertEqual(self.transport.calls, [])

    async def test_user_confirmed_edited_draft_survives_real_create(self):
        response = await self.draft()
        result = response_json(response)
        self.assertTrue(result["ok"], result)
        fields = dict(result["fields"])
        fields["name"] = "值班人员修改后的服务检查"
        fields["interval_sec"] = 120
        contract = formspec.validate_fields("checks", fields, assets=["romi"], partial=False)
        self.assertTrue(contract["valid"], contract)
        self.assertEqual(self.count("checks"), 0)
        response = await self.app.api_checks_create(request_json(contract["payload"]))
        created = response_json(response)
        self.assertEqual(response.status, 200, created)
        self.assertTrue(created["ok"], created)
        self.assertEqual(created["check"]["name"], "值班人员修改后的服务检查")
        self.assertEqual(created["check"]["interval_sec"], 120)
        self.assertEqual(created["check"]["params"], {"unit": "nginx"})
        self.assertEqual(self.count("checks"), 1)
        self.assertEqual(self.transport.calls, [])

    async def test_retired_permission_assist_never_calls_model_or_saves_rules(self):
        response = await self.draft(domain="permissions", text="重启服务需要确认")
        result = response_json(response)
        self.assertEqual(response.status, 410)
        self.assertEqual(result["error"], "legacy_permissions_retired")
        self.assertIn("Agent", result["message"])
        self.assertEqual(self.app.llm.calls, [])
        self.assertEqual(self.count("permissions"), 0)
        self.assertEqual(self.count("checks"), 0)
        self.assertEqual(self.transport.calls, [])

    async def test_auth_csrf_and_check_read_permission_gate_model_call(self):
        gates = ("_require_auth", "_check_csrf", "_check_read")
        for gate in gates:
            with self.subTest(gate=gate):
                original = getattr(self.app, gate)
                setattr(self.app, gate, Mock(side_effect=web.HTTPForbidden(text="blocked")))
                self.app.llm.calls.clear()
                with self.assertRaises(web.HTTPForbidden):
                    await self.draft()
                self.assertEqual(self.app.llm.calls, [])
                setattr(self.app, gate, original)

    async def test_invalid_request_bodies_are_readable_failures(self):
        for body in ([], "text", None, {"domain": "checks", "text": {}}, {"domain": "execute", "text": "do it"}):
            with self.subTest(body=body):
                response = await self.app.api_assist_configure(request_json(body))
                payload = response_json(response)
                self.assertEqual(response.status, 400, payload)
                self.assertFalse(payload["ok"], payload)
                self.assertTrue(payload.get("message"), payload)
        self.assertEqual(self.app.llm.calls, [])

    async def test_invalid_json_is_readable_failure(self):
        request = SimpleNamespace(json=AsyncMock(side_effect=ValueError("JSON decoding failed")))
        response = await self.app.api_assist_configure(request)
        payload = response_json(response)
        self.assertEqual(response.status, 400)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload.get("message"), payload)
        self.assertEqual(self.app.llm.calls, [])

    async def test_disabled_or_unknown_asset_cannot_produce_success(self):
        for asset in ("archive", "forged-host"):
            with self.subTest(asset=asset):
                self.app.llm = RecordingLLM(model_draft(asset_id=asset))
                result = response_json(await self.draft())
                self.assertFalse(result["ok"], result)
                self.assertTrue(result.get("message") or result.get("issues"), result)
                self.assertEqual(self.count("checks"), 0)

    async def test_create_permission_still_required_after_ai_draft(self):
        draft = response_json(await self.draft())
        payload = formspec.validate_fields("checks", draft["fields"], assets=["romi"], partial=False)["payload"]
        self.app._check_write.side_effect = web.HTTPForbidden(text="approval_required")
        with self.assertRaises(web.HTTPForbidden):
            await self.app.api_checks_create(request_json(payload))
        self.assertEqual(self.count("checks"), 0)

    async def test_invalid_create_explains_error_and_never_persists(self):
        for changes in ({"name": "x" * 65}, {"params": {"unit": "nginx;id"}}, {"asset_id": "missing"}, {"interval_sec": 0}):
            with self.subTest(changes=changes):
                payload = {"asset_id": "romi", "kind": "service", "name": "网站服务", "params": {"unit": "nginx"}, "interval_sec": 60}
                payload.update(changes)
                response = await self.app.api_checks_create(request_json(payload))
                result = response_json(response)
                self.assertEqual(response.status, 400, result)
                self.assertFalse(result["ok"])
                self.assertTrue(result.get("message"), result)
                self.assertNotEqual(result["message"], result.get("error"))
                self.assertEqual(self.count("checks"), 0)

    async def test_failed_update_has_readable_reason_without_partial_mutation(self):
        item = self.checks.create_check(asset_id="romi", kind="service", name="原始服务检查", params={"unit": "nginx"})
        response = await self.app.api_checks_update(request_json({"id": item["id"], "name": "更新后的名称", "interval_sec": 0}))
        result = response_json(response)
        self.assertEqual(response.status, 400, result)
        self.assertFalse(result["ok"])
        self.assertTrue(result.get("message"), result)
        current = self.checks.get_check(item["id"])
        self.assertEqual(current["name"], "原始服务检查")
        self.assertEqual(current["interval_sec"], 60)

    async def test_preflight_form_fields_and_actual_payload_are_equivalent(self):
        cases = (
            {"asset_id": "romi", "kind": "service", "name": "服务检查", "params.unit": "nginx"},
            {"asset_id": "romi", "kind": "port", "name": "监听检查", "params.port": 8443, "params.proto": "tcp"},
            # B1: command 检查仅允许 exit0 期望（contains/not_contains 已禁用）；curl 必须 -q/--disable 开头
            {"asset_id": "romi", "kind": "command", "name": "健康检查", "params.cmd": "curl -q -f http://127.0.0.1/health", "expect.mode": "exit0"},
        )
        for fields in cases:
            with self.subTest(kind=fields["kind"]):
                first = response_json(await self.app.api_checks_validate(request_json({"fields": fields})))
                self.assertTrue(first["ok"], first)
                second = response_json(await self.app.api_checks_validate(request_json(first["payload"])))
                self.assertTrue(second["ok"], second)
                self.assertEqual(first["fields"], second["fields"])
                self.assertEqual(first["payload"], second["payload"])
        self.assertEqual(self.count("checks"), 0)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.app.llm.calls, [])

    async def test_preflight_incomplete_or_invalid_fields_do_not_create(self):
        for fields in ({"asset_id": "romi", "kind": "service"}, {"asset_id": "romi", "kind": "port", "params.port": 99999}, {"asset_id": "romi", "kind": "service", "params.unit": "nginx", "params.runtime": "docker"}):
            with self.subTest(fields=fields):
                result = response_json(await self.app.api_checks_validate(request_json({"fields": fields})))
                self.assertFalse(result["ok"], result)
                self.assertIsNone(result["payload"])
                self.assertTrue(result["issues"] or result["missing"])
                self.assertTrue(result["message"])
                self.assertEqual(self.count("checks"), 0)
        self.assertEqual(self.transport.calls, [])

    async def test_preflight_read_and_csrf_gates_apply_without_write_permission(self):
        body = {"fields": model_draft()["fields"]}
        self.app._check_write.side_effect = web.HTTPForbidden(text="write denied")
        result = response_json(await self.app.api_checks_validate(request_json(body)))
        self.assertTrue(result["ok"], result)
        self.app._check_write.assert_not_called()
        for gate in ("_check_read", "_check_csrf"):
            with self.subTest(gate=gate):
                original = getattr(self.app, gate)
                setattr(self.app, gate, Mock(side_effect=web.HTTPForbidden(text="blocked")))
                with self.assertRaises(web.HTTPForbidden):
                    await self.app.api_checks_validate(request_json(body))
                setattr(self.app, gate, original)
        self.assertEqual(self.count("checks"), 0)

    async def test_preflight_rejects_invisible_assets_from_actual_and_flat_fields(self):
        self.app._visible_asset_ids = Mock(return_value=set())
        fields = model_draft()["fields"]
        payload = formspec.validate_fields("checks", fields, assets=["romi"], partial=False)["payload"]
        for body in ({"fields": fields}, payload):
            with self.subTest(body=body):
                result = response_json(await self.app.api_checks_validate(request_json(body)))
                self.assertFalse(result["ok"], result)
                self.assertIsNone(result["payload"])
                self.assertTrue(any(issue["field"] == "asset_id" for issue in result["issues"]))
        self.assertEqual(self.count("checks"), 0)

if __name__ == "__main__":
    unittest.main()
