"""主机监控：状态判定与 Prometheus 解析（不触网）。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.monitor import HostMonitor, _state_from_value, RANGES
from ayana.prom import PromError


class FakeProm:
    def __init__(self):
        self.queries = []
        self.instant = {}
        self.range = {}
        self.fail = False

    async def query(self, expr):
        self.queries.append(expr)
        if self.fail:
            raise PromError("down")
        return {"result": self.instant.get(expr, [])}

    async def query_range_raw(self, expr, *, start, end, step=15.0):
        if self.fail:
            raise PromError("down")
        return list(self.range.get(expr, []))


class TestMonitor(unittest.TestCase):
    def test_threshold_states(self):
        self.assertEqual(_state_from_value("cpu", 10), "ok")
        self.assertEqual(_state_from_value("cpu", 85), "warn")
        self.assertEqual(_state_from_value("cpu", 96), "bad")
        self.assertEqual(_state_from_value("memory", None), "no_data")
        self.assertEqual(_state_from_value("load1", 99), "ok")

    def test_ranges_present(self):
        for k in ("15m", "1h", "6h", "24h", "7d"):
            self.assertIn(k, RANGES)

    def test_overview_no_data(self):
        async def run():
            prom = FakeProm()
            mon = HostMonitor(prom)
            res = await mon.host_overview("kanata")
            self.assertEqual(res["state"], "no_data")

        import asyncio

        asyncio.run(run())

    def test_overview_collect_error(self):
        async def run():
            prom = FakeProm()
            prom.fail = True
            mon = HostMonitor(prom)
            res = await mon.host_overview("kanata")
            self.assertEqual(res["state"], "collect_error")

        import asyncio

        asyncio.run(run())

    def test_overview_ok_cpu(self):
        async def run():
            prom = FakeProm()
            mon = HostMonitor(prom)
            # 任意 expr：FakeProm 按 key 返回；用统一映射
            async def query(expr):
                if "cpu_seconds_total" in expr:
                    return {
                        "result": [
                            {
                                "metric": {"asset": "kanata"},
                                "value": 25.5,
                            }
                        ]
                    }
                if "MemAvailable" in expr:
                    return {
                        "result": [
                            {"metric": {"asset": "kanata"}, "value": 40.0}
                        ]
                    }
                return {"result": []}

            prom.query = query
            res = await mon.host_overview("kanata")
            self.assertEqual(res["metrics"]["cpu"]["value"], 25.5)
            self.assertEqual(res["metrics"]["cpu"]["state"], "ok")
            self.assertEqual(res["metrics"]["memory"]["value"], 40.0)

        import asyncio

        asyncio.run(run())

    def test_history_points(self):
        async def run():
            prom = FakeProm()
            mon = HostMonitor(prom)
            expr_cpu = mon._history_exprs("kanata")["cpu"]

            async def query(expr):
                return {"result": []}

            async def qrange(expr, *, start, end, step=15.0):
                if expr == expr_cpu:
                    return [
                        {"metric": {"asset": "kanata"}, "sample_at": start + 30, "value": 10},
                        {"metric": {"asset": "kanata"}, "sample_at": start + 60, "value": 20},
                    ]
                return []

            prom.query = query
            prom.query_range_raw = qrange
            res = await mon.host_history("kanata", "1h")
            pts = res["metrics"]["cpu"]["points"]
            self.assertEqual(len(pts), 2)
            self.assertEqual(pts[-1]["v"], 20)

        import asyncio

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
