"""assist：NL 填表意图（只查询填写，不保存）。"""
from __future__ import annotations

import asyncio
import unittest

from ayana import assist


class AssistParseTest(unittest.TestCase):
    def test_check_fill_port(self):
        r = asyncio.run(
            assist.configure(
                domain="checks",
                text="给 kanata 的 8080 端口做一个检查，每 60 秒一次，连续 2 次失败就严重告警",
                assets=["kanata", "nerv"],
                existing_names=[],
            )
        )
        self.assertTrue(r["ok"])
        f = r["fields"]
        self.assertEqual(f.get("asset_id"), "kanata")
        self.assertEqual(f.get("kind"), "port")
        self.assertEqual(f.get("params.port"), 8080)
        self.assertEqual(f.get("interval_sec"), 60)
        self.assertEqual(f.get("fail_threshold"), 2)
        self.assertEqual(f.get("severity"), "critical")
        self.assertIn("添加检查", r["summary"])
        self.assertIn("kanata", r["summary"])

    def test_check_missing_port(self):
        r = asyncio.run(
            assist.configure(
                domain="checks",
                text="给 nerv 加个端口检查",
                assets=["nerv"],
            )
        )
        keys = {m["key"] for m in r["missing"]}
        self.assertIn("params.port", keys)

    def test_schema_rejects_unknown(self):
        fields, unknown = assist._validate_fields(
            {"kind": "port", "evil": "1", "interval_sec": 99999},
            assist.CHECK_FIELDS,
        )
        self.assertIn("evil", unknown)
        self.assertNotIn("interval_sec", fields)  # 超上限丢弃

    def test_perm_route_exceptions(self):
        r = asyncio.run(
            assist.configure(
                domain="permissions",
                text="查看哪些资产有特殊授权",
                assets=["nerv"],
                capabilities=["service.restart", "service.logs"],
            )
        )
        self.assertTrue(r["ok"])
        self.assertEqual(r["route"], "perm_exceptions")

    def test_perm_fill_state(self):
        r = asyncio.run(
            assist.configure(
                domain="permissions",
                text="修改 KANATA 的容器重启权限，改成需要确认",
                assets=["kanata", "nerv"],
                capabilities=["container.restart", "service.restart"],
            )
        )
        self.assertTrue(r["ok"])
        f = r["fields"]
        self.assertEqual(f.get("asset_id"), "kanata")
        self.assertEqual(f.get("state"), "confirm")
        self.assertEqual(f.get("capability"), "container.restart")

    def test_perm_ceiling_route(self):
        r = asyncio.run(
            assist.configure(
                domain="permissions",
                text="查看 Agent 权限上限",
                assets=[],
                capabilities=[],
            )
        )
        self.assertEqual(r["route"], "perm_ceiling")

    def test_summary_is_template_not_llm(self):
        s = assist.build_check_summary(
            {
                "asset_id": "nerv",
                "name": "http",
                "kind": "command",
                "params.cmd": "curl -f http://x",
                "interval_sec": 30,
                "fail_threshold": 3,
                "severity": "warning",
            }
        )
        self.assertIn("nerv", s)
        self.assertIn("30", s)
        self.assertIn("连续 3 次", s)
        self.assertIn("添加检查", s)

    def test_process_wanted_not_invent_port(self):
        """「程序是否正常运行」→ service，禁止臆造端口 8080。"""
        r = asyncio.run(
            assist.configure(
                domain="checks",
                text="检查control上的运行pod的那个底层的c开头的程序是否正常运行",
                assets=["control", "kanata"],
            )
        )
        self.assertTrue(r["ok"])
        f = r["fields"]
        self.assertNotIn("params.port", f)
        self.assertNotEqual(f.get("kind"), "port")
        self.assertEqual(f.get("asset_id"), "control")
        # 无 LLM 时不应假装理解出 containerd
        self.assertNotEqual(f.get("params.unit"), "containerd")
        self.assertTrue(r["missing"] or r.get("confirm_question") or r.get("notes"))

    def test_json_repair_extracts_object(self):
        raw = "好的：\n```json\n{\"route\":\"checks_form\",\"fields\":{\"kind\":\"service\"},}\n```"
        data = assist._extract_json_object(raw)
        self.assertEqual(data["route"], "checks_form")

    def test_llm_infer_containerd_confirm(self):
        class FakeLLM:
            enabled = True

            async def chat(self, messages, max_tokens=600):
                return (
                    '{"route":"checks_form",'
                    '"fields":{"asset_id":"control","kind":"service","params.unit":"containerd","name":"containerd"},'
                    '"inferred":["params.unit","name"],'
                    '"confirm_question":"你说的应该是 containerd，是否需要检查 control 上的 containerd 服务运行状态？",'
                    '"missing":[],"notes":[]}'
                )

        r = asyncio.run(
            assist.configure(
                domain="checks",
                text="检查control上的运行pod的那个底层的c开头的程序是否正常运行",
                llm=FakeLLM(),
                assets=["control", "kanata"],
            )
        )
        self.assertEqual(r["source"], "llm")
        self.assertEqual(r["fields"].get("params.unit"), "containerd")
        self.assertEqual(r["fields"].get("kind"), "service")
        self.assertIn("containerd", r.get("confirm_question") or "")
        self.assertNotIn("params.port", r["fields"])


if __name__ == "__main__":
    unittest.main()
