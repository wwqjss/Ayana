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

    def test_llm_structured_fill_without_names_in_prompt(self):
        """模型用自身知识推断；脚本侧不写 containerd 等标准答案。"""
        import inspect
        from ayana import assist as A

        src = inspect.getsource(A._llm_intent)
        self.assertNotIn("containerd", src.lower())
        self.assertNotIn("calico", src.lower())
        self.assertNotIn("crictl", src.lower())

        class FakeLLM:
            enabled = True

            async def chat_raw(self, messages, max_tokens=800, json_mode=False, temperature=0.2):
                # 验证 payload 含表单定义与资产，且无答案级示例
                body = messages[-1]["content"]
                assert "form.fields" in body or "fields" in body
                assert "control" in body
                assert "containerd" not in messages[0]["content"].lower()
                return {
                    "content": (
                        '{"route":"checks_form",'
                        '"fields":{"asset_id":"control","kind":"service","params.unit":"containerd"},'
                        '"inferred":[{"field":"params.unit","reason":"容器运行时","confidence":"high"}],'
                        '"confirm_question":"你说的应该是 containerd，是否检查其服务状态？",'
                        '"missing":[],"unsupported":null,"notes":[]}'
                    ),
                    "raw": {},
                    "status": 200,
                }

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
        self.assertIn("params.unit", r.get("inferred") or [])
        self.assertIn("containerd", r.get("confirm_question") or "")

    def test_llm_unsupported_k8s_pod_as_systemd(self):
        class FakeLLM:
            enabled = True

            async def chat_raw(self, messages, max_tokens=800, json_mode=False, temperature=0.2):
                return {
                    "content": (
                        '{"route":"checks_form","fields":{"asset_id":"control","kind":"command",'
                        '"params.cmd":"command -v crictl && crictl pods | grep mypod"},'
                        '"inferred":[],'
                        '"confirm_question":"Pod 不能当 systemd 服务，是否用命令检查？",'
                        '"missing":[],'
                        '"unsupported":{"reason":"K8s Pod 不是 systemd unit","alternatives":["command"]},'
                        '"notes":["建议 command"]}'
                    ),
                    "raw": {},
                    "status": 200,
                }

        r = asyncio.run(
            assist.configure(
                domain="checks",
                text="检查 mypod 这个 pod 是否在运行",
                llm=FakeLLM(),
                assets=["control"],
            )
        )
        self.assertEqual(r["fields"].get("kind"), "command")
        self.assertTrue(any("不支持" in n or "Pod" in n for n in r.get("notes") or []))

    def test_llm_cannot_invent_asset(self):
        class FakeLLM:
            enabled = True

            async def chat_raw(self, messages, max_tokens=800, json_mode=False, temperature=0.2):
                return {
                    "content": '{"route":"checks_form","fields":{"asset_id":"hacked","kind":"port","params.port":22},"inferred":[],"missing":[],"notes":[]}',
                    "raw": {},
                    "status": 200,
                }

        r = asyncio.run(
            assist.configure(
                domain="checks",
                text="随便检查",
                llm=FakeLLM(),
                assets=["control", "kanata"],
            )
        )
        self.assertNotIn("asset_id", r["fields"])  # 未知资产被剥掉


if __name__ == "__main__":
    unittest.main()
