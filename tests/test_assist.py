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


if __name__ == "__main__":
    unittest.main()
