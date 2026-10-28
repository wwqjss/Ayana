"""Natural-language drafts use model interpretation and the real form contract."""
from __future__ import annotations

import copy
import json
import unittest

from ayana import assist, formspec


class FakeLLM:
    enabled = True

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    async def chat_raw(self, messages, **kwargs):
        self.calls.append({"messages": copy.deepcopy(messages), **kwargs})
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        if isinstance(response, Exception):
            raise response
        if response is None:
            return None
        if isinstance(response, str):
            return {"content": response, "status": 200}
        if "content" in response:
            return copy.deepcopy(response)
        return {"content": json.dumps(response, ensure_ascii=False), "status": 200}


def envelope(fields, **metadata):
    return {"route": "checks_form", "fields": fields, **metadata}


def service_fields(**overrides):
    fields = {
        "asset_id": "romi", "kind": "service", "name": "网站服务运行情况",
        "params.unit": "nginx", "interval_sec": 60, "fail_threshold": 2,
        "severity": "warning",
    }
    fields.update(overrides)
    return fields


class AssistConfigureTest(unittest.IsolatedAsyncioTestCase):
    async def configure(self, response, **kwargs):
        llm = response if isinstance(response, FakeLLM) else FakeLLM(response)
        args = {"domain": "checks", "text": "观察这台网站服务器的服务状态", "assets": ["romi", "nerv"], "llm": llm}
        args.update(kwargs)
        return await assist.configure(**args)

    def assert_human_failure(self, result):
        self.assertFalse(result["ok"], result)
        self.assertTrue(result.get("message") or result.get("issues"), result)
        self.assertNotEqual(result.get("source"), "rules")
        self.assertFalse(result.get("ready_to_submit", False))

    async def test_disabled_model_does_not_pretend_keyword_understanding(self):
        for llm in (None, type("Disabled", (), {"enabled": False})()):
            result = await assist.configure(domain="checks", text="给 romi 检查 8080 端口", assets=["romi"], llm=llm)
            self.assert_human_failure(result)
            self.assertFalse(result.get("fields"))

    async def test_model_failure_does_not_fall_back_even_with_obvious_keywords(self):
        for response in (None, RuntimeError("gateway down"), "not JSON", "[]"):
            with self.subTest(response=response):
                self.assert_human_failure(await self.configure(FakeLLM(response), text="检查 romi 的 8080 端口"))

    async def test_service_draft_preserves_natural_language_name_and_real_payload(self):
        result = await self.configure(envelope(service_fields()))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["source"], "llm")
        self.assertEqual(result["fields"]["name"], "网站服务运行情况")
        checked = formspec.validate_fields("checks", result["fields"], assets=["romi", "nerv"], partial=False)
        self.assertTrue(checked["valid"], checked)
        self.assertEqual(checked["payload"]["params"], {"unit": "nginx"})
        self.assertIn("网站服务运行情况", result["summary"])

    async def test_other_asset_and_service_are_model_driven(self):
        result = await self.configure(envelope(service_fields(asset_id="edge-west", name="边缘代理健康", **{"params.unit": "haproxy"})), assets=["edge-west"], text="替西侧边缘机盯一下代理有没有停")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["fields"]["asset_id"], "edge-west")
        self.assertEqual(result["fields"]["params.unit"], "haproxy")

    async def test_nested_fields_map_to_actual_port_payload(self):
        result = await self.configure(envelope({"asset_id": "nerv", "kind": "port", "name": "解析服务监听", "params": {"port": 5353, "proto": "udp"}}))
        self.assertTrue(result["ok"], result)
        checked = formspec.validate_fields("checks", result["fields"], assets=["nerv"], partial=False)
        self.assertTrue(checked["valid"], checked)
        self.assertEqual(checked["payload"]["params"], {"port": 5353, "protocol": "udp"})

    async def test_safe_command_expectation_maps_to_real_submission(self):
        result = await self.configure(envelope({"asset_id": "romi", "kind": "command", "name": "应用健康页面", "params.cmd": "curl -q --disable -f http://127.0.0.1:8080/health", "expect.mode": "exit0"}))
        self.assertTrue(result["ok"], result)
        checked = formspec.validate_fields("checks", result["fields"], assets=["romi"], partial=False)
        self.assertTrue(checked["valid"], checked)
        self.assertEqual(checked["payload"]["params"]["argv"], ["curl", "-q", "--disable", "-f", "http://127.0.0.1:8080/health"])
        self.assertEqual(checked["payload"]["expect"], {"exit_code": 0})

    async def test_missing_target_asks_only_for_target(self):
        result = await self.configure(envelope({"asset_id": "romi", "kind": "service"}))
        self.assertTrue(result["ok"], result)
        missing = {item.get("field") or item.get("key") for item in result["missing"]}
        self.assertEqual(missing, {"params.unit"})
        self.assertEqual(result.get("status"), "needs_input")
        self.assertFalse(result.get("ready_to_submit", False))

    async def test_selected_asset_keeps_defaults_and_removes_unnecessary_questions(self):
        response = envelope({"kind": "service", "params.unit": "nginx"}, missing=[{"field": "asset_id", "question": "要选择哪台主机？"}, {"field": "interval_sec", "question": "多久检查一次？"}])
        result = await self.configure(response, assets=[{"id": "romi", "display_name": "网站主机"}], context={"asset_id": "romi"})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["fields"]["asset_id"], "romi")
        self.assertEqual(result["fields"]["interval_sec"], 60)
        self.assertEqual(result["fields"]["fail_threshold"], 2)
        self.assertEqual(result["fields"]["severity"], "warning")
        self.assertIn("网站主机", result["fields"]["name"])
        self.assertTrue({"interval_sec", "fail_threshold", "severity", "name"}.issubset(result["defaulted"]), result)
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["status"], "ready")

    async def test_semantic_clarification_defers_technical_fields_and_confirmation(self):
        question = {"id": "target_component", "label": "检查对象", "question": "你希望观察处理请求的服务，还是处理后台任务的服务？", "options": [{"label": "处理请求的服务", "value": "我要观察处理网页请求的服务", "description": "反映网页请求是否有人处理"}, {"label": "后台任务服务", "value": "我要观察处理后台任务的服务", "description": "反映排队任务是否有人处理"}, {"label": "我不清楚", "value": "我不清楚具体服务，请继续解释区别"}]}
        response = envelope({"asset_id": "romi", "kind": "service"}, clarifications=[question], confirm_question="请确认还未确定的服务名称。")
        result = await self.configure(response)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "needs_input")
        self.assertFalse(result["ready_to_submit"])
        self.assertIsNone(result["payload"])
        self.assertNotIn("params.unit", result["fields"])
        self.assertEqual({item["field"] for item in result["missing"]}, {"clarification.target_component"})
        self.assertFalse(result["confirm_question"])
        options = result["missing"][0]["options"]
        self.assertEqual([item["value"] for item in options], [item["value"] for item in question["options"]])
        self.assertTrue(all(item["mode"] == "answer" for item in options))
        self.assertEqual(result["diagnostics"]["model_result"], response)

    async def test_semantic_reply_returns_valid_full_draft_through_model_context(self):
        original = "观察后台处理任务的那个服务"
        first_response = envelope({"asset_id": "romi", "kind": "service"}, clarifications=[{"id": "target_component", "label": "检查对象", "question": "是排队任务处理器，还是定时任务调度器？"}])
        first = await self.configure(first_response, text=original)
        self.assertEqual(first["status"], "needs_input")
        self.assertIsNone(first["payload"])
        answer = "是负责处理排队任务的服务，登记名称是 report-worker"
        llm = FakeLLM(envelope(service_fields(**{"params.unit": "report-worker", "name": "后台任务处理服务"})))
        result = await self.configure(llm, text=original, context={"draft": {"fields": first["fields"], "original_text": original}, "answers": [{"field": "clarification.target_component", "text": answer}]})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["ready_to_submit"])
        self.assertEqual(result["fields"]["params.unit"], "report-worker")
        self.assertEqual(result["payload"]["params"], {"unit": "report-worker"})
        self.assertIn(answer, llm.calls[0]["messages"][-1]["content"])
        self.assertIn(original, llm.calls[0]["messages"][-1]["content"])

    async def test_semantic_question_never_assigns_candidate_answer_to_form_field(self):
        fields = service_fields(**{"params.unit": "report-worker"})
        response = envelope(fields, clarifications=[{"id": "success_criterion", "label": "成功标准", "question": "只观察服务运行，还是希望进一步观察它完成任务？", "options": [{"label": "暂不确定", "value": "暂不确定，请解释两种检查的区别"}]}])
        result = await self.configure(response)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["fields"], fields)
        self.assertFalse(result["ready_to_submit"])
        self.assertIsNone(result["payload"])
        self.assertEqual(result["missing"][0]["field"], "clarification.success_criterion")

    async def test_semantic_question_presentation_humanizes_labels_without_changing_answers(self):
        answer = "我想确认 romi 的 params.unit 是什么用途"
        response = envelope({"asset_id": "romi", "kind": "service"}, clarifications=[{"id": "target_component", "label": "romi 的 params.unit", "question": "你要观察 romi 的 params.unit 吗？", "options": [{"label": "romi 的 params.unit", "value": answer, "description": "kind=service 表示系统服务的运行状态"}]}])
        result = await self.configure(response, assets=[{"id": "romi", "display_name": "网站主机"}])
        self.assertTrue(result["ok"], result)
        question = result["missing"][0]
        text = question["label"] + question["question"] + question["options"][0]["label"] + question["options"][0]["description"]
        for internal in ("romi", "params.unit", "kind=service"):
            self.assertNotIn(internal, text)
        self.assertIn("网站主机", text)
        self.assertEqual(question["options"][0]["value"], answer)
        self.assertEqual(result["diagnostics"]["model_result"], response)

    async def test_schema_question_answer_mode_accepts_natural_text_without_assignment(self):
        response = envelope({"asset_id": "romi", "kind": "service"}, missing=[{"field": "params.unit", "question": "你说的组件主要负责什么？", "options": [{"label": "处理后台任务", "value": "我说的是处理后台任务的组件", "mode": "answer"}, {"label": "还不清楚", "value": "我不知道服务名，希望先了解区别", "mode": "answer"}]}])
        result = await self.configure(response)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "needs_input")
        self.assertIsNone(result["payload"])
        self.assertNotIn("params.unit", result["fields"])
        self.assertTrue(all(item["mode"] == "answer" for item in result["missing"][0]["options"]))

    async def test_schema_question_option_modes_reject_empty_values_and_unbounded_answers(self):
        for option in ({"label": "空值", "value": ""}, {"label": "空值", "value": "", "mode": "field_value"}, {"label": "空回答", "value": " ", "mode": "answer"}, {"label": "过长回答", "value": "回答" * 3000, "mode": "answer"}, {"label": "非法模式", "value": "nginx", "mode": "execute"}):
            with self.subTest(option=option):
                response = envelope({"asset_id": "romi", "kind": "service"}, missing=[{"field": "params.unit", "question": "请选择检查对象", "options": [option]}])
                self.assert_human_failure(await self.configure(response))

    async def test_model_questions_cannot_require_fields_inapplicable_to_selected_kind(self):
        for key in ("params.port", "params.proto", "params.cmd", "expect.mode", "expect.value"):
            with self.subTest(key=key):
                llm = FakeLLM(envelope(service_fields(), missing=[{"field": key, "question": "请补充这个字段"}]))
                self.assert_human_failure(await self.configure(llm))
                self.assertEqual(len(llm.calls), 2)

    async def test_malformed_semantic_clarifications_fail_explicitly(self):
        invalid = (
            False, {}, "question", ["question"],
            [{"id": "target.component", "label": "检查对象", "question": "哪个对象？"}],
            [{"id": "target", "label": {}, "question": "哪个对象？"}],
            [{"id": "target", "label": "检查对象", "question": " "}],
            [{"id": "target", "label": "检查对象", "question": "哪个对象？", "options": {}}],
            [{"id": "target", "label": "检查对象", "question": "哪个对象？", "options": [{"label": "候选", "value": ""}]}],
            [{"id": "target", "label": "检查对象", "question": "哪个对象？", "options": [{"label": "候选", "value": {"execute": True}}]}],
        )
        for clarifications in invalid:
            with self.subTest(clarifications=clarifications):
                response = envelope(service_fields(), clarifications=clarifications)
                result = await self.configure(response)
                self.assert_human_failure(result)
                self.assertEqual(result["diagnostics"]["model_result"], response)

    async def test_semantic_questions_do_not_bypass_invalid_model_field_constraints(self):
        response = envelope(service_fields(**{"params.unit": "report-worker;id"}), clarifications=[{"id": "target", "label": "检查对象", "question": "希望检查哪个组件？"}])
        self.assert_human_failure(await self.configure(response))

    async def test_semantic_question_does_not_hide_inapplicable_fields_or_invalid_assignable_choices(self):
        for fields, missing in (
            (service_fields(), {"field": "params.port", "question": "监听哪个端口？"}),
            ({"asset_id": "romi", "kind": "service"}, {"field": "params.unit", "question": "选择服务", "options": [{"label": "非法对象", "value": "worker;id", "mode": "field_value"}]}),
        ):
            with self.subTest(missing=missing):
                response = envelope(fields, missing=[missing], clarifications=[{"id": "target_component", "label": "检查对象", "question": "你希望观察处理请求的组件，还是处理后台任务的组件？"}])
                llm = FakeLLM(response)
                result = await self.configure(llm)
                self.assert_human_failure(result)
                self.assertEqual(len(llm.calls), 2)
                self.assertEqual(result["diagnostics"]["model_result"], response)

    async def test_unknown_asset_visible_failure_including_empty_inventory(self):
        for assets in (["romi"], []):
            with self.subTest(assets=assets):
                self.assert_human_failure(await self.configure(envelope(service_fields(asset_id="made-up-host")), assets=assets))

    async def test_unknown_fields_not_silently_discarded_as_success(self):
        self.assert_human_failure(await self.configure(envelope(service_fields(**{"sudo_password": "do-not-use", "params.runtime": "docker"}))))

    async def test_invalid_types_limits_values_not_truncated_or_clamped(self):
        for override in ({"interval_sec": True}, {"interval_sec": 15.2}, {"interval_sec": 0}, {"interval_sec": 3601}, {"fail_threshold": 0}, {"severity": "fatal"}, {"name": "测" * 65}, {"params.unit": "nginx;shutdown"}):
            with self.subTest(override=override):
                self.assert_human_failure(await self.configure(envelope(service_fields(**override))))

    async def test_unsafe_or_unsupported_command_cannot_be_successful_draft(self):
        for cmd in ("rm -rf /", "sh -c id", "curl http://x;id", "curl http://x | grep ok", "crictl pods"):
            with self.subTest(cmd=cmd):
                self.assert_human_failure(await self.configure(envelope({"asset_id": "romi", "kind": "command", "name": "探测", "params.cmd": cmd})))

    async def test_required_output_match_string_not_omitted(self):
        # P1-07: contains 不再支持，必须显式失败而不是要求 expect.value
        result = await self.configure(envelope({"asset_id": "romi", "kind": "command", "params.cmd": "echo healthy", "expect.mode": "contains"}))
        self.assert_human_failure(result)
        issues = {item.get("field") or item.get("key") for item in (result.get("issues") or [])}
        self.assertIn("expect.mode", issues)

    async def test_invalid_route_metadata_shapes_explicit_failure(self):
        for override in (
            {"route": "run_commands"}, {"route": "perm_defaults"},
            {"notes": "text-not-array"}, {"notes": [42]},
            {"inferred": {"field": "params.unit"}}, {"inferred": False},
            {"inferred": [{"field": "params.unit", "reason": {"execute": True}, "confidence": "medium"}]},
            {"missing": "asset_id"}, {"missing": False},
            {"confirm_question": {"execute": True}}, {"unsupported": "maybe"},
            {"unsupported": {"reason": "限制", "alternatives": [{"execute": "probe"}]}},
            {"missing": [{"field": "params.unit", "question": "请选择服务", "options": [{"label": "网站服务", "value": "nginx", "description": {"execute": True}}]}]},
            {"fields": []}, {"fields": "fill all"},
        ):
            with self.subTest(override=override):
                response = envelope(service_fields())
                response.update(override)
                self.assert_human_failure(await self.configure(response))

    async def test_one_bounded_model_correction_can_resolve_invalid_output(self):
        llm = FakeLLM(envelope(service_fields(**{"interval_sec": 999999})), envelope(service_fields(interval_sec=120)))
        result = await self.configure(llm)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["fields"]["interval_sec"], 120)
        self.assertEqual(len(llm.calls), 2)

    async def test_repeated_invalid_output_stops_after_bounded_repair(self):
        llm = FakeLLM(envelope(service_fields(**{"params.unit": "../../nginx"})))
        self.assert_human_failure(await self.configure(llm))
        self.assertLessEqual(len(llm.calls), 2)

    async def test_truncated_output_cannot_be_synthetically_completed(self):
        llm = FakeLLM({"content": '{"route":"checks_form","fields":{"asset_id":"romi","kind":"service","params.unit":"nginx"}', "finish_reason": "length"})
        self.assert_human_failure(await self.configure(llm))
        self.assertLessEqual(len(llm.calls), 2)

    async def test_length_finish_reason_retries_even_for_valid_json(self):
        llm = FakeLLM({"content": json.dumps(envelope(service_fields())), "finish_reason": "length"})
        self.assert_human_failure(await self.configure(llm))

    async def test_inferred_object_requires_user_confirmation(self):
        result = await self.configure(envelope(service_fields(**{"params.unit": "containerd"}), inferred=[{"field": "params.unit", "reason": "根据组件用途推断，实际服务名称尚未核实", "confidence": "medium"}], confirm_question="你说的是容器运行时服务吗？请确认。"))
        self.assertTrue(result["ok"], result)
        self.assertTrue(result.get("confirm_question"))
        self.assertFalse(result.get("ready_to_submit", False))

    async def test_exact_user_confirmation_resolves_unchanged_inference_without_loop(self):
        fields = service_fields(**{"params.unit": "report-worker"})
        question = "你说的是处理后台任务的已登记服务吗？"
        response = envelope(fields, inferred=[{"field": "params.unit", "reason": "仍保留原先的用途推断", "confidence": "medium"}], confirm_question="")
        result = await self.configure(response, context={"draft": {"fields": fields, "confirm_question": question}, "answers": [{"field": "confirmation", "text": "确认：" + question}]})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["ready_to_submit"])
        self.assertFalse(result["confirm_question"])
        self.assertNotIn("params.unit", result["inferred"])
        self.assertEqual(result["payload"]["params"], {"unit": "report-worker"})
        self.assertEqual(result["diagnostics"]["model_result"], response)

    async def test_confirmation_does_not_cover_changed_fields_or_other_questions(self):
        original_fields = service_fields(**{"params.unit": "report-worker"})
        question = "你说的是处理后台任务的服务吗？"
        for fields, answer in ((service_fields(**{"params.unit": "report-scheduler"}), "确认：" + question), (original_fields, "确认：这是另一个尚未询问的问题"), (original_fields, "确认")):
            with self.subTest(fields=fields, answer=answer):
                response = envelope(fields, inferred=[{"field": "params.unit", "reason": "根据用途提出候选对象", "confidence": "medium"}], confirm_question="")
                result = await self.configure(response, context={"draft": {"fields": original_fields, "confirm_question": question}, "answers": [{"field": "confirmation", "text": answer}]})
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["status"], "needs_confirmation")
                self.assertFalse(result["ready_to_submit"])
                self.assertIsNone(result["payload"])
                self.assertTrue(result["confirm_question"])
                self.assertIn("params.unit", result["inferred"])

    async def test_model_prose_uses_form_labels_and_asset_display_name(self):
        fields = service_fields(name="用户名称里的 params.unit 原样保留")
        response = envelope(fields, inferred=[{"field": "params.unit", "reason": "asset_id romi 的 params.unit nginx，kind=service 使用 systemctl is-active nginx；另用 systemctl is-active 判定状态。", "confidence": "medium"}], confirm_question="请确认 asset_id romi 的 kind=service 与 params.unit nginx，底层 systemctl is-failed nginx。")
        result = await self.configure(response, assets=[{"id": "romi", "display_name": "网站主机"}])
        self.assertTrue(result["ok"], result)
        text = result["inferred_detail"][0]["reason"] + result["confirm_question"]
        labels = {item["name"]: item["label"] for item in formspec.get_form("checks")["fields"]}
        for key in ("asset_id", "kind", "params.unit"):
            self.assertNotIn(key, text)
            self.assertIn(labels[key], text)
        self.assertIn("网站主机", text)
        self.assertNotIn("systemctl", text)
        self.assertIn("系统服务 nginx 的运行状态", text)
        self.assertEqual(result["fields"]["name"], fields["name"])
        self.assertEqual(result["fields"]["params.unit"], "nginx")
        self.assertEqual(result["diagnostics"]["model_result"], response)

    async def test_chinese_adjacent_identifiers_are_humanized_without_losing_meaning(self):
        response = envelope(service_fields(), inferred=[{"field": "params.unit", "reason": "请在romi上配置kind=service并确认params.unit；使用systemctl is-active nginx观察。", "confidence": "medium"}], confirm_question="确认在romi检查params.unit吗？")
        result = await self.configure(response, assets=[{"id": "romi", "display_name": "网站主机"}])
        self.assertTrue(result["ok"], result)
        text = result["inferred_detail"][0]["reason"] + result["confirm_question"]
        self.assertNotIn("romi", text)
        self.assertNotIn("kind=service", text)
        self.assertNotIn("params.unit", text)
        self.assertNotIn("systemctl", text)
        self.assertIn("网站主机上", text)
        self.assertIn("服务运行状态", text)
        self.assertIn("并确认", text)
        self.assertIn("nginx", text)
        self.assertEqual(result["diagnostics"]["model_result"], response)

    async def test_questions_options_and_unsupported_explanations_hide_internal_identifiers(self):
        response = envelope({"asset_id": "romi", "kind": "service"}, missing=[{"field": "params.unit", "question": "请为romi选择params.unit。", "options": [{"label": "romi 的 params.unit nginx", "value": "nginx", "description": "kind=service 使用 systemctl is-active nginx 检查。"}]}])
        result = await self.configure(response, assets=[{"id": "romi", "display_name": "网站主机"}])
        self.assertTrue(result["ok"], result)
        question = result["missing"][0]
        text = question["question"] + question["options"][0]["label"] + question["options"][0]["description"]
        for token in ("romi", "params.unit", "kind=service", "systemctl"):
            self.assertNotIn(token, text)
        self.assertEqual(question["options"][0]["value"], "nginx")
        self.assertEqual(result["diagnostics"]["model_result"], response)
        unsupported = envelope({"asset_id": "romi"}, unsupported={"reason": "romi 无法使用 kind=service 检查这个对象。", "alternatives": ["在 romi 选择 kind=port。"]})
        result = await self.configure(unsupported, assets=[{"id": "romi", "display_name": "网站主机"}])
        self.assertTrue(result["ok"], result)
        text = result["unsupported"]["reason"] + "".join(result["unsupported"]["alternatives"])
        self.assertIn("网站主机", text)
        self.assertNotIn("romi", text)
        self.assertNotIn("kind=", text)
        self.assertEqual(result["diagnostics"]["model_result"], unsupported)

    async def test_unsupported_target_explained_without_ready_submission(self):
        result = await self.configure(envelope({"asset_id": "romi"}, unsupported={"reason": "此表单不能检查工作负载对象", "alternatives": ["检查对应主机的服务状态"]}))
        self.assertTrue(result.get("message") or result.get("unsupported") or result.get("notes"), result)
        self.assertFalse(result.get("ready_to_submit", False))

    async def test_empty_optional_unsupported_normalizes_without_changing_form_values(self):
        fields = {"asset_id": "romi", "kind": "port", "name": "域名服务监听", "params.port": 53, "params.proto": "udp"}
        expected = formspec.validate_fields("checks", fields, assets=["romi"], partial=False)
        for optional in ({}, {"reason": "", "alternatives": []}):
            with self.subTest(optional=optional):
                result = await self.configure(envelope(fields, unsupported=optional))
                self.assertTrue(result["ok"], result)
                self.assertIsNone(result["unsupported"])
                self.assertEqual(result["status"], "ready")
                self.assertEqual(result["fields"], expected["fields"])
                self.assertEqual(result["payload"], expected["payload"])
                self.assertIn("empty_optional_unsupported", result["diagnostics"]["format_normalizations"])

    async def test_nonempty_unsupported_alternative_needs_a_real_reason(self):
        for optional in ({"reason": "", "alternatives": ["改用端口检查"]}, {"reason": " ", "alternatives": []}, {"reason": None, "alternatives": []}, {"execute": True}):
            with self.subTest(optional=optional):
                self.assert_human_failure(await self.configure(envelope(service_fields(), unsupported=optional)))

    async def test_prompt_contains_live_form_constraints_inventory(self):
        llm = FakeLLM(envelope(service_fields()))
        await self.configure(llm, context={"current_fields": {"severity": "critical"}})
        prompt = json.loads(llm.calls[0]["messages"][-1]["content"])
        scene = prompt["scene"]
        self.assertEqual(scene["form"]["id"], formspec.get_form("checks")["id"])
        self.assertEqual({field["name"] for field in scene["form"]["fields"]}, {field["name"] for field in formspec.get_form("checks")["fields"]})
        self.assertIn("romi", str(scene["context"]["assets"]))
        self.assertTrue(scene["form"]["constraints"])

    async def test_followup_retains_original_intent_prior_draft_and_answer(self):
        original = "监控网站主机上的网页服务"
        first = await self.configure(envelope({"asset_id": "romi", "kind": "service"}), text=original)
        llm = FakeLLM(envelope(service_fields()))
        context = {
            "draft": {"fields": first["fields"], "original_text": original, "confirm_question": ""},
            "answers": [{"field": "params.unit", "text": "就是网站服务 nginx"}],
        }
        result = await self.configure(llm, text="就是网站服务 nginx", context=context)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["fields"]["asset_id"], "romi")
        self.assertEqual(result["fields"]["params.unit"], "nginx")
        prompt = llm.calls[0]["messages"][-1]["content"]
        self.assertIn(original, prompt)
        self.assertIn("就是网站服务 nginx", prompt)

    async def test_changed_intent_is_not_overwritten_by_original_keyword_rules(self):
        context = {
            "draft": {"fields": service_fields(), "original_text": "监控 romi 的 nginx 服务", "confirm_question": ""},
            "answers": [{"text": "改为只查看 8443 端口是否监听"}],
        }
        fields = {"asset_id": "romi", "kind": "port", "name": "HTTPS 端口监听", "params.port": 8443, "params.proto": "tcp"}
        result = await self.configure(envelope(fields), text="改为只查看 8443 端口是否监听", context=context)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["fields"]["kind"], "port")
        self.assertEqual(result["fields"]["params.port"], 8443)
        self.assertNotIn("params.unit", result["fields"])

    async def test_permission_routes_cannot_silently_change_authorization_scope(self):
        for route, fields in (
            ("perm_defaults", {"asset_id": "romi", "capability": "service.logs", "state": "auto"}),
            ("perm_defaults", {"scope": "exception", "asset_id": "romi", "capability": "service.logs", "state": "auto"}),
            ("perm_exceptions", {"scope": "default", "capability": "service.logs", "state": "auto"}),
        ):
            with self.subTest(route=route, fields=fields):
                self.assert_human_failure(await self.configure(FakeLLM({"route": route, "fields": fields}), domain="permissions", capabilities=["service.logs"]))

    async def test_unknown_capability_not_invented_permission(self):
        response = {"route": "perm_defaults", "fields": {"capability": "root.everything", "state": "auto", "scope": "default"}}
        self.assert_human_failure(await self.configure(FakeLLM(response), domain="permissions", capabilities=["service.logs"]))

    async def test_permission_domain_configure_is_retired(self):
        """Stored-grant permission forms are gone: the domain fails before any model call."""
        for route in ("perm_defaults", "perm_exceptions", "perm_effective", "perm_workbench", "perm_ceiling"):
            llm = FakeLLM({"route": route, "fields": {}})
            self.assert_human_failure(await self.configure(llm, domain="permissions", capabilities=["service.logs"]))
            self.assertEqual(llm.calls, [])

    async def test_empty_unknown_domain_fail_without_model_call(self):
        for kwargs in ({"text": " "}, {"domain": "execute"}):
            llm = FakeLLM(envelope(service_fields()))
            self.assert_human_failure(await self.configure(llm, **kwargs))
            self.assertEqual(llm.calls, [])


class AssistJSONTest(unittest.TestCase):
    def test_complete_fenced_json_trailing_comma_supported(self):
        raw = '```json\n{"route":"checks_form","fields":{"name":"中文名称",},}\n```'
        self.assertEqual(assist._extract_json_object(raw)["fields"]["name"], "中文名称")

    def test_apostrophes_comma_brackets_inside_strings_preserved(self):
        fields = {"name": "O'Brien ,} 服务", "params.cmd": "echo O'Brien"}
        self.assertEqual(assist._extract_json_object(json.dumps(envelope(fields), ensure_ascii=False))["fields"], fields)

    def test_truncated_python_literal_not_repaired_as_json(self):
        for raw in ('{"fields":{"kind":"service"}', '{"fields":{"name":"unfinished', "{'fields': {'kind': 'service'}}", "null", "[]"):
            with self.subTest(raw=raw):
                self.assertIsNone(assist._extract_json_object(raw))


if __name__ == "__main__":
    unittest.main()
