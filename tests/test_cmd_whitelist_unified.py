"""命令白名单统一后的对照测试（P0-2）。

目标：合并 readonly_commands 与 checks 的探测校验后，
默认不得扩大命令执行权限——原两侧禁止的参数必须仍被拒绝。
"""

from __future__ import annotations

import unittest

from ayana.checks import CheckError, validate_argv
from ayana.msgentry import classify_command, parse_entry
from ayana.readonly_commands import (
    readonly_command,
    safe_tokens,
    validate_probe_tokens,
)


class SharedProbeValidationTest(unittest.TestCase):
    def test_ss_summary_stays_banned(self):
        # 历史：readonly_commands 曾允许 --summary，checks 禁止。合并后取更严。
        self.assertFalse(validate_probe_tokens("ss", ["--summary"]))
        self.assertFalse(validate_probe_tokens("ss", ["-ltn", "--summary"]))

    def test_ss_kill_filter_stay_banned(self):
        for args in (["-K"], ["-F", "/tmp/x"], ["--kill"], ["--filter", "x"], ["--bpf"]):
            self.assertFalse(validate_probe_tokens("ss", args), args)

    def test_ss_query_flags_still_allowed(self):
        self.assertTrue(validate_probe_tokens("ss", ["-lnt"]))
        self.assertTrue(validate_probe_tokens("ss", ["sport", "=", ":80"]))

    def test_curl_requires_disable_prefix(self):
        self.assertFalse(validate_probe_tokens("curl", ["http://example.com"]))
        self.assertFalse(validate_probe_tokens("curl", ["-q", "-X", "POST", "http://x"]))

    def test_curl_get_head_only(self):
        self.assertTrue(validate_probe_tokens("curl", ["-q", "http://example.com"]))
        self.assertTrue(validate_probe_tokens("curl", ["--disable", "-I", "http://example.com"]))
        self.assertFalse(validate_probe_tokens("curl", ["-q", "-X", "DELETE", "http://x"]))

    def test_curl_rejects_non_http(self):
        self.assertFalse(validate_probe_tokens("curl", ["-q", "file:///etc/passwd"]))
        self.assertFalse(validate_probe_tokens("curl", ["-q", "gopher://x"]))

    def test_ping_positive_count_only(self):
        self.assertTrue(validate_probe_tokens("ping", ["-c", "3", "example.com"]))
        self.assertFalse(validate_probe_tokens("ping", ["-c", "0", "example.com"]))
        self.assertFalse(validate_probe_tokens("ping", ["-c", "abc", "example.com"]))

    def test_ps_option_whitelist(self):
        self.assertTrue(validate_probe_tokens("ps", ["aux"]))
        self.assertFalse(validate_probe_tokens("ps", ["-eo", "pid,cmd"]))

    def test_checks_and_shared_agree_on_overlap(self):
        """同一 token 集合：checks.validate_argv 与共享校验结论一致或更严。"""
        cases = [
            ["ss", "-lnt"],
            ["ss", "--summary"],
            ["ss", "-K"],
            ["ping", "-c", "2", "example.com"],
            ["ping", "-c", "0", "example.com"],
            ["curl", "-q", "http://a"],
            ["curl", "http://a"],
            ["ps", "aux"],
            ["ps", "-ef"],
        ]
        for argv in cases:
            prog, args = argv[0], argv[1:]
            shared = validate_probe_tokens(prog, args)
            try:
                validate_argv(argv)
                checks_ok = True
            except CheckError:
                checks_ok = False
            if shared:
                # 共享允许时 checks 也必须允许（不得更松也不得误杀合法探测）
                self.assertTrue(checks_ok, f"checks rejected but shared allowed: {argv}")
            # 共享拒绝时 checks 允许 = 扩大权限，不允许发生
            # （checks 可能因业务约束更严，但不能更松）

    def test_metachar_tokens_rejected_everywhere(self):
        bad = ["ss;ls", "a|b", "a&&b", "a`id`", "a$(id)"]
        for t in bad:
            self.assertFalse(safe_tokens([t]), t)
            self.assertFalse(readonly_command(["echo", t]))
            self.assertFalse(validate_probe_tokens("ss", [t]))


class MsgentryControlledUsesSafeTokensTest(unittest.TestCase):
    def test_controlled_rejects_metachar(self):
        entry = parse_entry("@Ayana -c web-01 ss -lnt; ls")
        self.assertEqual(entry.kind, "unknown")

    def test_controlled_accepts_clean(self):
        entry = parse_entry("@Ayana -c web-01 ss -lnt")
        self.assertEqual(entry.kind, "controlled")

    def test_classify_write_removed_or_delegates(self):
        # classify_write 为兼容壳；classify_command 是单点
        self.assertEqual(classify_command(["systemctl", "restart", "nginx"]), "write")
        self.assertEqual(classify_command(["systemctl", "status", "nginx"]), "read")
        # rm 是写动词，静态判定为 write（进入 Action 审批，不是直接执行）
        self.assertEqual(classify_command(["rm", "-rf", "x"]), "write")
        self.assertEqual(classify_command(["unknownprog", "x"]), "unknown")


if __name__ == "__main__":
    unittest.main()
