"""草稿、真实表单和持久化接口共同使用的契约。"""

from __future__ import annotations

import unittest

from ayana.checks import CheckError, build_tokens
from ayana.formspec import (
    check_payload, condition_applicability, condition_dependencies, condition_matches,
    field_applicability, get_form, payload_to_fields,
    validate_check_payload, validate_fields,
)


ASSETS = [{"id": "romi", "display_name": "ROMI", "enabled": True}]


class TestFormContract(unittest.TestCase):
    def service(self, **extra):
        return {"asset_id": "romi", "kind": "service", "name": "监控 ROMI 的 nginx 服务",
                "params.unit": "nginx.service", **extra}

    def test_service_draft_matches_real_execution_and_preserves_name(self):
        result = validate_fields("checks", self.service(), assets=ASSETS)
        self.assertTrue(result["valid"])
        self.assertEqual(result["fields"]["name"], "监控 ROMI 的 nginx 服务")
        self.assertEqual(result["payload"]["expect"], {"active_state": "active"})
        self.assertEqual(build_tokens(result["payload"]["kind"], result["payload"]["params"]),
                         [["systemctl", "is-active", "nginx.service"]])
        self.assertEqual(set(result["defaulted"]), {"interval_sec", "fail_threshold", "severity"})

    def test_port_adapter_uses_backend_protocol(self):
        payload = check_payload({"asset_id": "romi", "kind": "port", "params": {"port": "53", "proto": "udp"}}, assets=ASSETS)
        self.assertEqual(payload["params"], {"port": 53, "protocol": "udp"})
        self.assertEqual(build_tokens("port", payload["params"])[0][1], "-lnu")
        fields = payload_to_fields(payload)
        self.assertEqual(fields["params.proto"], "udp")
        self.assertEqual(check_payload(fields, assets=ASSETS), payload)

    def test_command_expectation_roundtrip(self):
        # P1-07: 仅 exit0；contains/not_contains 必须拒绝
        fields = {"asset_id": "romi", "kind": "command",
                  "params.cmd": "curl -q --disable http://127.0.0.1/health",
                  "expect.mode": "exit0"}
        payload = check_payload(fields, assets=ASSETS)
        self.assertEqual(payload["expect"], {"exit_code": 0})
        self.assertEqual(payload["params"]["argv"],
                         ["curl", "-q", "--disable", "http://127.0.0.1/health"])
        self.assertEqual(check_payload(payload_to_fields(payload), assets=ASSETS), payload)
        for mode in ("contains", "not_contains"):
            bad = {**fields, "expect.mode": mode, "expect.value": "正常"}
            with self.subTest(mode=mode):
                result = validate_fields("checks", bad, assets=ASSETS, partial=False)
                self.assertFalse(result["valid"])

    def test_partial_draft_does_not_guess_kind_or_target(self):
        result = validate_fields("checks", {"asset_id": "romi"}, assets=ASSETS)
        self.assertFalse(result["valid"])
        self.assertNotIn("kind", result["fields"])
        self.assertNotIn("name", result["fields"])
        self.assertEqual(result["issues"], [])
        self.assertEqual([item["field"] for item in result["missing"]], ["kind"])
        self.assertIsNone(result["payload"])

    def test_missing_target_is_question_not_invalid_model_output(self):
        result = validate_fields("checks", {"asset_id": "romi", "kind": "service"}, assets=ASSETS)
        self.assertEqual(result["issues"], [])
        self.assertEqual([item["field"] for item in result["missing"]], ["params.unit"])

    def test_invalid_integer_is_not_truncated_clamped_or_defaulted(self):
        for field, values in {"params.port": [True, 80.5, "80.5", 0, 65536],
                              "interval_sec": [True, 60.5, "60.0", 14, 3601],
                              "fail_threshold": [False, 2.5, "2.1", 0, 11]}.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    fields = {"asset_id": "romi", "kind": "port", "params.port": 80, field: value}
                    result = validate_fields("checks", fields, assets=ASSETS)
                    self.assertFalse(result["valid"])
                    self.assertIn(field, [i["field"] for i in result["issues"]])
                    self.assertNotIn(field, result["fields"])
                    self.assertNotIn(field, result["defaulted"])

    def test_unknown_and_duplicate_fields_are_visible_failures(self):
        for fields in (self.service(restart=True),
                       {**self.service(), "params": {"unit": "other"}},
                       {**self.service(), "params.proto": "udp"}):
            result = validate_fields("checks", fields, assets=ASSETS)
            self.assertFalse(result["valid"])
            self.assertTrue(result["issues"])
            self.assertIsNone(result["payload"])

    def test_invalid_asset_not_changed_to_default_asset(self):
        for asset in ("missing", "romi"):
            assets = ASSETS if asset == "missing" else [{**ASSETS[0], "enabled": False}]
            result = validate_fields("checks", self.service(asset_id=asset), assets=assets)
            self.assertEqual(result["issues"][0]["field"], "asset_id")
            self.assertNotIn("asset_id", result["fields"])

    def test_name_length_and_control_characters_rejected_without_truncation(self):
        for name in ("检" * 65, "监控\nnginx", "nginx\x00", "nginx\n"):
            result = validate_fields("checks", self.service(name=name), assets=ASSETS)
            self.assertFalse(result["valid"])
            self.assertNotIn("name", result["fields"])
            self.assertNotIn("name", result["defaulted"])

    def test_omitted_optional_name_gets_readable_display_default(self):
        fields = self.service()
        fields.pop("name")
        result = validate_fields("checks", fields, assets=ASSETS)
        self.assertEqual(result["fields"]["name"], "ROMI · nginx.service 运行状态")
        self.assertIn("name", result["defaulted"])
        unusual_assets = [{**ASSETS[0], "display_name": "ROMI\n网站主机"}]
        payload = check_payload(fields, assets=unusual_assets)
        self.assertEqual(payload["name"], "ROMI 网站主机 · nginx.service 运行状态")
        self.assertTrue(validate_check_payload(payload, assets=unusual_assets)["valid"])

    def test_unsafe_command_or_match_text_missing_blocks_submit(self):
        for command in ("rm -rf /", "sh -c id", "curl http://x;id", "curl " + "x" * 121,
                        "curl -X POST http://127.0.0.1/health", "wget http://127.0.0.1/health", "ss -K",
                        "curl http://127.0.0.1/health"):
            result = validate_fields("checks", {"asset_id": "romi", "kind": "command", "params.cmd": command}, assets=ASSETS)
            self.assertIn("params.cmd", [i["field"] for i in result["issues"]])
            self.assertIsNone(result["payload"])
        # P1-07: contains 不再要求 expect.value，而是直接拒绝
        result = validate_fields("checks", {"asset_id": "romi", "kind": "command", "params.cmd": "true", "expect.mode": "contains"}, assets=ASSETS)
        self.assertFalse(result["valid"])
        self.assertIn("expect.mode", [i["field"] for i in result["issues"]])

    def test_actual_payload_invalid_expectation_not_silently_dropped(self):
        base = {"asset_id": "romi", "name": "健康检查", "kind": "command", "params": {"argv": ["true"]}}
        for expect in ({"exit_code": True}, {"exit_code": 0.0}, {"exit_code": 1},
                       {"exit_code": 0, "output_contains": "ok"}, {"mode": "contains"},
                       {"output_contains": ""}):
            result = validate_check_payload({**base, "expect": expect}, assets=ASSETS)
            self.assertFalse(result["valid"])
            self.assertIsNone(result["payload"])

    def test_actual_payload_rejects_unrepresentable_command_tokens(self):
        for argv in (["echo", "a b"], ["true", ""], ["true", False], "true"):
            result = validate_check_payload({"asset_id": "romi", "kind": "command", "name": "检查", "params": {"argv": argv}}, assets=ASSETS)
            self.assertFalse(result["valid"])

    def test_actual_payload_rejects_wrong_internal_field_names(self):
        for payload in ({"kind": "port", "params": {"port": 80, "proto": "tcp"}},
                        {"kind": "command", "params": {"cmd": "true"}},
                        {"kind": "service", "params": {"unit": "nginx"}, "expect": {"active_state": "inactive"}}):
            result = validate_check_payload({"asset_id": "romi", "name": "检查", **payload}, assets=ASSETS)
            self.assertFalse(result["valid"])
            self.assertTrue(result["issues"])

    def test_malformed_actual_payload_returns_issues_without_throwing(self):
        for malformed in (None, [], "text", {"kind": {}}, {"kind": ["service"]},
                          {"kind": "service", "params": []}, {"kind": "service", "expect": []},
                          {1: "unknown", "kind": "service", "params": {1: "nginx"}},
                          {"kind": "service", "params": {"unit": []}}):
            with self.subTest(payload=malformed):
                result = validate_check_payload(malformed, assets=ASSETS)
                self.assertFalse(result["valid"])
                self.assertTrue(result["issues"])
                self.assertIsNone(result["payload"])

    def test_prompt_and_frontend_metadata_describe_real_contract(self):
        form = get_form("checks")
        fields = {f["name"]: f for f in form["fields"]}
        self.assertEqual(fields["params.proto"]["submit_path"], "params.protocol")
        self.assertEqual(fields["params.cmd"]["control_id"], "chk-cmd")
        self.assertNotIn("default", fields["kind"])
        self.assertNotIn("pattern", fields["name"])
        self.assertIn("curl", fields["params.cmd"]["allowed_programs"])
        self.assertIn("不支持 Docker", form["capability_boundary"]["service"])
        self.assertIn("GET/HEAD", form["command_boundary"]["curl"])
        self.assertIn("-O -", form["command_boundary"]["wget"])

    def test_applicability_is_structured_and_matches_actual_required_fields(self):
        fields = {f["name"]: f for f in get_form("checks")["fields"]}
        self.assertEqual(fields["params.unit"]["applicable_if"], {"field": "kind", "equals": "service"})
        self.assertFalse(condition_matches(fields["params.unit"]["applicable_if"], {"kind": "port"}))
        self.assertTrue(condition_matches(fields["expect.value"]["required_when"], {"kind": "command", "expect.mode": "contains"}))
        self.assertFalse(condition_matches(fields["expect.value"]["applicable_if"], {"kind": "command", "expect.mode": "exit0"}))

    def test_check_payload_error_has_friendly_field_issues(self):
        with self.assertRaises(CheckError) as raised:
            check_payload(self.service(interval_sec=5), assets=ASSETS)
        self.assertIn("15 到 3600", raised.exception.detail)
        self.assertEqual(raised.exception.issues[0]["field"], "interval_sec")

    def test_clarification_applicability_preserves_unknown_selectors(self):
        self.assertIsNone(field_applicability("checks", "params.unit", {}))
        self.assertIsNone(field_applicability("checks", "params.unit", {"kind": None}))
        self.assertIsNone(field_applicability("checks", "params.unit", {"kind": ""}))
        self.assertTrue(field_applicability("checks", "params.unit", {"kind": "service"}))
        self.assertFalse(field_applicability("checks", "params.unit", {"kind": "port"}))
        self.assertTrue(field_applicability("checks", "name", {}))
        self.assertFalse(field_applicability("checks", "made_up", {}))

    def test_compound_applicability_false_takes_precedence_over_unknown(self):
        condition = next(field for field in get_form("checks")["fields"] if field["name"] == "expect.value")["applicable_if"]
        self.assertIsNone(condition_applicability(condition, {}))
        self.assertIsNone(condition_applicability(condition, {"kind": "command"}))
        self.assertFalse(condition_applicability(condition, {"kind": "service"}))
        self.assertFalse(condition_applicability(condition, {"expect.mode": "exit0"}))
        self.assertTrue(condition_applicability(condition, {"kind": "command", "expect.mode": "contains"}))
        self.assertFalse(condition_applicability(condition, {"kind": "command", "expect.mode": "exit0"}))

    def test_option_context_is_derived_from_actual_condition_dependencies(self):
        condition = {"all": [{"field": "kind", "equals": "command"},
                             {"all": [{"field": "expect.mode", "in": ["contains", "not_contains"]},
                                      {"field": "kind", "equals": "command"}]}]}
        self.assertEqual(condition_dependencies(condition), ["kind", "expect.mode"])
        fields = {field["name"]: field for field in get_form("checks")["fields"]}
        for field in fields.values():
            if field.get("applicable_if"):
                self.assertEqual(field["validation_context"], condition_dependencies(field["applicable_if"]))
        self.assertEqual(fields["params.unit"]["validation_context"], ["kind"])
        self.assertEqual(fields["expect.value"]["validation_context"], ["kind", "expect.mode"])
        draft = {"kind": "port", "params.port": 443}
        context = {key: draft[key] for key in fields["params.unit"]["validation_context"] if key in draft}
        candidate = validate_fields("checks", {**context, "params.unit": "example.service"}, assets=ASSETS)
        self.assertEqual(candidate["issues"][0]["code"], "irrelevant_field")


if __name__ == "__main__":
    unittest.main()
