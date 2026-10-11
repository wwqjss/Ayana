"""host_health 聚合语义（P0 健康统一）。"""
from __future__ import annotations

import unittest

from ayana.health import host_health


class HostHealthTest(unittest.TestCase):
    def test_empty_is_no_data(self):
        h = host_health()
        self.assertEqual(h["state"], "no_data")
        self.assertEqual(h["cls"], "dim")

    def test_ok_stays_green(self):
        h = host_health(metric_state="ok", required_state="healthy", check_states=["ok"])
        self.assertEqual(h["state"], "ok")

    def test_collect_error_wins(self):
        h = host_health(
            metric_state="collect_error",
            collect_error="prom down",
            required_state="healthy",
            firing_severities=["critical"],
        )
        self.assertEqual(h["state"], "collect_error")
        self.assertEqual(h["cls"], "err")
        self.assertIn("prom down", h["reasons"])

    def test_critical_firing_turns_red(self):
        h = host_health(metric_state="ok", firing_severities=["critical"])
        self.assertEqual(h["state"], "bad")

    def test_warning_firing_turns_yellow(self):
        h = host_health(metric_state="ok", firing_severities=["warning"])
        self.assertEqual(h["state"], "warn")

    def test_zero_value_is_not_no_data(self):
        # value=0 是有效样本：metric ok 即使业务上“为零”也应是绿
        h = host_health(metric_state="ok")
        self.assertEqual(h["state"], "ok")

    def test_no_data_is_gray_not_green(self):
        h = host_health(metric_state="no_data")
        self.assertEqual(h["state"], "no_data")

    def test_check_bad_raises_red(self):
        h = host_health(metric_state="ok", check_states=["ok", "bad"])
        self.assertEqual(h["state"], "bad")

    def test_historical_incident_not_sticky(self):
        # 未结案 Incident 不进入参数；监控恢复后应为 ok
        h = host_health(metric_state="ok", required_state="healthy")
        self.assertEqual(h["state"], "ok")


if __name__ == "__main__":
    unittest.main()
