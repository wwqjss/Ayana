"""system_health_ratio：唯一分数 + MAGI 分项拆解。"""
from __future__ import annotations

import unittest

from ayana.health import system_health_ratio


class SystemHealthRatioTest(unittest.TestCase):
    def test_empty_shows_dash(self):
        h = system_health_ratio()
        self.assertIsNone(h["ratio"])
        self.assertEqual(h["label"], "—")
        self.assertEqual(h["total"], 0)
        for s in h["sources"]:
            self.assertEqual(s["state"], "na")

    def test_single_score_not_three(self):
        h = system_health_ratio(
            metric_items=[{"state": "healthy"}] * 12 + [{"state": "unhealthy"}] * 2,
            check_items=[{"state": "ok"}] * 3,
            alert_items=[],
        )
        # 15/17
        self.assertEqual(h["healthy"], 15)
        self.assertEqual(h["total"], 17)
        self.assertAlmostEqual(h["ratio"], round(15 * 100 / 17, 1))
        # 分项加总 = 主分数
        self.assertEqual(sum(s["healthy"] for s in h["sources"]), h["healthy"])
        self.assertEqual(sum(s["total"] for s in h["sources"]), h["total"])

    def test_unknown_not_healthy(self):
        h = system_health_ratio(metric_items=[{"state": "unknown"}, {"state": "collect_error"}, {"state": "healthy"}])
        self.assertEqual(h["healthy"], 1)
        self.assertEqual(h["total"], 3)

    def test_zero_total_source_excluded(self):
        h = system_health_ratio(check_items=[{"state": "ok"}, {"state": "bad"}])
        self.assertEqual(h["total"], 2)
        self.assertEqual(h["healthy"], 1)
        self.assertEqual(h["sources"][2]["state"], "na")

    def test_firing_alerts_drag_score(self):
        h = system_health_ratio(
            metric_items=[{"state": "healthy"}] * 5,
            alert_items=[{"state": "unhealthy"}] * 2,
        )
        self.assertEqual(h["healthy"], 5)
        self.assertEqual(h["total"], 7)
        self.assertLess(h["ratio"], 100)
        self.assertEqual(h["sources"][2]["healthy"], 0)
        self.assertEqual(h["sources"][2]["total"], 2)

    def test_full_green(self):
        h = system_health_ratio(
            metric_items=[{"state": "healthy"}],
            check_items=[{"state": "ok"}],
        )
        self.assertEqual(h["ratio"], 100.0)
        self.assertEqual(h["label"], "100%")
        self.assertEqual(h["color"], "ok")


if __name__ == "__main__":
    unittest.main()
