"""统一消息入口、错误引导、Agent 查询、受控命令（不触网）。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.msgentry import (
    ERR_TARGET_UNAVAILABLE,
    classify_command,
    classify_write,
    error_reply,
    parse_entry,
    usage_hint_for_controlled,
)
from ayana.agent_query import parse_query, QueryIntent


class TestParseEntry(unittest.TestCase):
    def test_wake_word_slash(self):
        e = parse_entry("@Ayana /help")
        self.assertEqual(e.kind, "slash")
        self.assertEqual(e.slash_cmd, "/help")

    def test_wake_word_case(self):
        e = parse_entry("@ayana /status")
        self.assertEqual(e.kind, "slash")
        self.assertEqual(e.slash_cmd, "/status")

    def test_wake_word_controlled(self):
        e = parse_entry("@Ayana -c nerv systemctl status nginx")
        self.assertEqual(e.kind, "controlled")
        self.assertEqual(e.host, "nerv")
        self.assertEqual(e.cmd_tokens, ["systemctl", "status", "nginx"])
        self.assertFalse(e.is_write)

    def test_controlled_write(self):
        e = parse_entry("@Ayana -c nerv systemctl restart nginx")
        self.assertEqual(e.kind, "controlled")
        self.assertTrue(e.is_write)

    def test_controlled_missing_args(self):
        e = parse_entry("@Ayana -c nerv")
        self.assertEqual(e.kind, "unknown")
        self.assertEqual(e.error, "missing_args")

    def test_controlled_syntax_error(self):
        e = parse_entry("@Ayana -c nerv echo 'unclosed")
        self.assertEqual(e.kind, "unknown")
        self.assertEqual(e.error, "syntax_error")

    def test_controlled_unsafe_token(self):
        e = parse_entry("@Ayana -c nerv cat /etc/passwd; rm -rf /")
        self.assertEqual(e.kind, "unknown")
        self.assertEqual(e.error, "unsafe_token")

    def test_nl_query(self):
        e = parse_entry("@Ayana 查询 NERV 状态")
        self.assertEqual(e.kind, "nl")
        self.assertIn("NERV", e.nl_text)

    def test_no_wake_word_slash(self):
        e = parse_entry("/help")
        self.assertEqual(e.kind, "slash")

    def test_no_wake_word_nl(self):
        e = parse_entry("查询 NERV CPU")
        self.assertEqual(e.kind, "nl")

    def test_empty(self):
        self.assertEqual(parse_entry("").kind, "empty")
        self.assertEqual(parse_entry("@Ayana").kind, "empty")
        self.assertEqual(parse_entry("   ").kind, "empty")


class TestClassifyWrite(unittest.TestCase):
    def test_read_verbs(self):
        self.assertFalse(classify_write(["systemctl", "status", "nginx"]))
        self.assertFalse(classify_write(["systemctl", "is-active", "nginx"]))
        self.assertFalse(classify_write(["docker", "ps"]))
        self.assertFalse(classify_write(["df", "-h"]))
        self.assertFalse(classify_write(["free", "-m"]))
        self.assertFalse(classify_write(["uptime"]))

    def test_write_verbs(self):
        self.assertTrue(classify_write(["systemctl", "restart", "nginx"]))
        self.assertTrue(classify_write(["systemctl", "stop", "nginx"]))
        self.assertTrue(classify_write(["systemctl", "start", "nginx"]))
        self.assertTrue(classify_write(["docker", "restart", "web"]))

    def test_empty(self):
        self.assertFalse(classify_write([]))
        self.assertEqual(classify_command([]), "unknown")


class TestClassifyCommand(unittest.TestCase):
    """S07: 三态分类 read/write/unknown，未知默认拒绝。"""

    def test_read(self):
        self.assertEqual(classify_command(["systemctl", "status", "nginx"]), "read")
        self.assertEqual(classify_command(["docker", "ps"]), "read")
        self.assertEqual(classify_command(["df", "-h"]), "read")
        self.assertEqual(classify_command(["free", "-m"]), "read")
        self.assertEqual(classify_command(["uptime"]), "read")
        self.assertEqual(classify_command(["hostname"]), "read")
        self.assertEqual(classify_command(["journalctl", "-u", "nginx"]), "read")

    def test_write(self):
        self.assertEqual(classify_command(["systemctl", "restart", "nginx"]), "write")
        self.assertEqual(classify_command(["systemctl", "stop", "nginx"]), "write")
        self.assertEqual(classify_command(["docker", "restart", "web"]), "write")

    def test_unknown_rejected(self):
        """S07: 未知程序/动词 → unknown，不放行。"""
        self.assertEqual(classify_command(["python3", "-c", "print(1)"]), "unknown")
        self.assertEqual(classify_command(["bash", "-c", "id"]), "unknown")
        self.assertEqual(classify_command(["nc", "host", "1234"]), "unknown")
        self.assertEqual(classify_command(["curl", "--help"]), "read")  # curl 在白名单
        self.assertEqual(classify_command(["systemctl", "unknown-verb", "x"]), "unknown")
        self.assertEqual(classify_command(["rm", "-rf", "/"]), "write")  # 写动词
        self.assertEqual(classify_command(["sed", "-i", "s/a/b/"]), "unknown")

    def test_docker_start_stop_not_restart(self):
        """S21: docker start/stop 不悄悄映射成 restart。"""
        self.assertEqual(classify_command(["docker", "start", "web"]), "write")
        self.assertEqual(classify_command(["docker", "stop", "web"]), "write")
        self.assertEqual(classify_command(["docker", "restart", "web"]), "write")


class TestErrorGuidance(unittest.TestCase):
    def test_no_asset_names_in_hint(self):
        """错误提示不得列资产名、别名、数量或内部配置。"""
        hint = error_reply("missing_args")
        self.assertIn("<host>", hint)
        self.assertIn("<command>", hint)
        # 不得含真实资产名
        for name in ("nerv", "kanata", "sora", "yomi", "NERV", "KANATA"):
            self.assertNotIn(name, hint)

    def test_target_unavailable_unified(self):
        """目标不存在与无权限统一文案。"""
        self.assertEqual(error_reply("not_found"), ERR_TARGET_UNAVAILABLE)
        self.assertEqual(error_reply("denied"), ERR_TARGET_UNAVAILABLE)
        self.assertEqual(error_reply("bad_host"), ERR_TARGET_UNAVAILABLE)

    def test_controlled_usage_placeholder(self):
        hint = usage_hint_for_controlled()
        self.assertIn("<host>", hint)
        self.assertIn("<command>", hint)
        for name in ("nerv", "kanata", "NERV"):
            self.assertNotIn(name, hint)


class TestParseQuery(unittest.TestCase):
    def test_host_metric(self):
        intent = parse_query("查询 NERV 的 CPU", ["nerv", "kanata"])
        self.assertEqual(intent.host, "nerV".replace("nerV", "nerv"))
        self.assertEqual(intent.metric, "cpu")

    def test_time_range(self):
        intent = parse_query("最近 24 小时 KANATA 内存", ["nerv", "kanata"])
        self.assertEqual(intent.range_key, "24h")
        self.assertEqual(intent.metric, "memory")

    def test_swap(self):
        intent = parse_query("KANATA swap 状态", ["nerv", "kanata"])
        self.assertEqual(intent.metric, "swap")
        self.assertTrue(intent.want_status)

    def test_compare(self):
        intent = parse_query("对比 NERV 和 KANATA 的 CPU", ["nerv", "kanata"])
        self.assertIn("nerv", intent.compare_hosts)
        self.assertIn("kanata", intent.compare_hosts)

    def test_unknown_host_not_listed(self):
        """未在 known_hosts 中的主机不被识别。"""
        intent = parse_query("查询 UNKNOWN 状态", ["nerv", "kanata"])
        self.assertEqual(intent.host, "")


if __name__ == "__main__":
    unittest.main()
