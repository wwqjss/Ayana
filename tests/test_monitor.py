"""主机监控：状态判定与 Prometheus 解析（不触网）。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.monitor import HostMonitor, _state_from_value, _swap_state_and_value, RANGES
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

    def test_swap_not_enabled(self):
        """Swap 总量为 0 → 未启用，不计算使用率、不标异常。"""
        state, val = _swap_state_and_value(0.0, None)
        self.assertEqual(state, "not_enabled")
        self.assertIsNone(val)
        state, val = _swap_state_and_value(0.0, 100.0)
        self.assertEqual(state, "not_enabled")
        self.assertIsNone(val)

    def test_swap_enabled_ok(self):
        """Swap 已启用且使用率低 → 正常。"""
        state, val = _swap_state_and_value(2147483648.0, 10.0)
        self.assertEqual(state, "ok")
        self.assertEqual(val, 10.0)

    def test_swap_enabled_warn(self):
        state, val = _swap_state_and_value(2147483648.0, 60.0)
        self.assertEqual(state, "warn")

    def test_swap_enabled_bad(self):
        state, val = _swap_state_and_value(2147483648.0, 90.0)
        self.assertEqual(state, "bad")

    def test_swap_no_data(self):
        """Swap 总量未知 → 暂无数据。"""
        state, val = _swap_state_and_value(None, None)
        self.assertEqual(state, "no_data")

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

    def test_overview_swap_not_enabled(self):
        """KANATA 场景：Swap 总量为 0 → 未启用，不显示 100% 异常。"""

        async def run():
            prom = FakeProm()
            mon = HostMonitor(prom)

            async def query(expr):
                if "SwapTotal" in expr:
                    return {"result": [{"metric": {"asset": "kanata"}, "value": 0.0}]}
                if "SwapFree" in expr:
                    return {"result": [{"metric": {"asset": "kanata"}, "value": 0.0}]}
                if "cpu_seconds_total" in expr:
                    return {"result": [{"metric": {"asset": "kanata"}, "value": 25.0}]}
                if "MemAvailable" in expr:
                    return {"result": [{"metric": {"asset": "kanata"}, "value": 40.0}]}
                return {"result": []}

            prom.query = query
            res = await mon.host_overview("kanata")
            swap = res["metrics"]["swap"]
            self.assertEqual(swap["state"], "not_enabled")
            self.assertIsNone(swap["value"])
            # 整体状态不应因 Swap 未启用而异常
            self.assertNotEqual(res["state"], "bad")
            self.assertNotEqual(res["state"], "warn")

        import asyncio

        asyncio.run(run())

    def test_overview_swap_enabled(self):
        """已启用 Swap 主机：正常使用率计算。"""

        async def run():
            prom = FakeProm()
            mon = HostMonitor(prom)

            async def query(expr):
                if "SwapTotal" in expr and "SwapFree" not in expr:
                    return {"result": [{"metric": {"asset": "nerv"}, "value": 2147483648.0}]}
                if "SwapFree" in expr:
                    # swap 使用率表达式：100 * (1 - free/total) ≈ 10%
                    return {"result": [{"metric": {"asset": "nerv"}, "value": 10.0}]}
                if "cpu_seconds_total" in expr:
                    return {"result": [{"metric": {"asset": "nerv"}, "value": 10.0}]}
                if "MemAvailable" in expr:
                    return {"result": [{"metric": {"asset": "nerv"}, "value": 50.0}]}
                return {"result": []}

            prom.query = query
            res = await mon.host_overview("nerv")
            swap = res["metrics"]["swap"]
            self.assertEqual(swap["state"], "ok")
            self.assertAlmostEqual(swap["value"], 10.0, places=1)

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


class TestExporterAvailability(unittest.IsolatedAsyncioTestCase):
    async def test_host_strip_and_detail_share_memory_threshold_not_only_cpu(self):
        prom = FakeProm()
        monitor = HostMonitor(prom)

        async def query(expr):
            if expr.startswith("up{"):
                value = 1.0
            elif "MemAvailable" in expr:
                value = 97.0
            elif "SwapTotal" in expr and "SwapFree" not in expr:
                value = 0.0
            else:
                value = 12.0
            return {"result": [{"metric": {"asset": "edge"}, "value": value}]}

        prom.query = query
        summary = (await monitor.hosts_status([{"id": "edge"}]))[0]
        detail = await monitor.host_overview("edge")
        self.assertEqual(summary["state"], "bad")
        self.assertEqual(detail["state"], "bad")
        self.assertEqual(detail["metrics"]["cpu"]["state"], "ok")
        self.assertEqual(detail["metrics"]["memory"]["state"], "bad")

    async def test_registered_job_type_failure_is_visible_in_list_and_detail(self):
        prom = FakeProm()
        monitor = HostMonitor(prom)

        async def query(expr):
            if expr.startswith("up{"):
                if 'job_type="node_exporter"' in expr:
                    return {"result": [{"metric": {"asset": "EDGE-PROBE", "job": "custom-exporters", "job_type": "node_exporter"}, "value": 0.0}]}
                return {"result": []}
            if "cpu_seconds_total" in expr:
                return {"result": [{"metric": {"asset": "EDGE-PROBE"}, "value": 12.0}]}
            return {"result": []}

        prom.query = query
        asset = {"id": "edge", "display_name": "边缘主机", "prom_asset": "EDGE-PROBE"}
        summary = (await monitor.hosts_status([asset]))[0]
        detail = await monitor.host_overview(asset["prom_asset"])
        self.assertEqual(summary["asset_id"], "edge")
        self.assertEqual(summary["state"], "collect_error")
        self.assertEqual(detail["state"], "collect_error")
        self.assertEqual(summary["error"], "node_exporter_down")
        self.assertEqual(detail["error"], "node_exporter_down")

    async def test_legacy_node_job_failure_remains_visible(self):
        prom = FakeProm()
        monitor = HostMonitor(prom)

        async def query(expr):
            if expr.startswith("up{") and 'job=~"node.*"' in expr:
                return {"result": [{"metric": {"asset": "legacy", "job": "node-exporter"}, "value": 0.0}]}
            return {"result": []}

        prom.query = query
        summary = (await monitor.hosts_status([{"id": "legacy"}]))[0]
        self.assertEqual(summary["state"], "collect_error")
        self.assertEqual(summary["summary"]["up"], 0.0)

    async def test_healthy_exporter_with_cpu_rate_warming_is_partial_not_empty(self):
        prom = FakeProm()
        monitor = HostMonitor(prom)

        async def query(expr):
            if expr.startswith("up{"):
                return {"result": [{"metric": {"asset": "new-host", "job_type": "node_exporter"}, "value": 1.0}]}
            return {"result": []}

        prom.query = query
        summary = (await monitor.hosts_status([{"id": "new-host"}]))[0]
        self.assertEqual(summary["state"], "partial_no_data")
        self.assertIsNone(summary["summary"]["cpu"])
        self.assertEqual(summary["summary"]["up"], 1.0)

    async def test_zero_swap_with_nan_usage_is_not_failed_collection(self):
        prom = FakeProm()
        monitor = HostMonitor(prom)

        async def query(expr):
            value = float("nan") if "SwapFree" in expr else 0.0 if "SwapTotal" in expr else 10.0
            return {"result": [{"metric": {"asset": "edge"}, "value": value}]}

        prom.query = query
        overview = await monitor.host_overview("edge")
        self.assertEqual(overview["state"], "ok")
        self.assertEqual(overview["metrics"]["swap"]["state"], "not_enabled")
        self.assertIsNone(overview["metrics"]["swap"]["value"])
        self.assertEqual(overview["metrics"]["swap"]["points"], [])

    async def test_available_history_with_missing_metrics_is_partial(self):
        prom = FakeProm()
        monitor = HostMonitor(prom)

        async def query(expr):
            if "cpu_seconds_total" in expr:
                return {"result": [{"metric": {"asset": "edge"}, "value": 0.0}]}
            return {"result": []}

        async def query_range(expr, *, start, end, step):
            if "cpu_seconds_total" in expr:
                return [{"metric": {"asset": "edge"}, "sample_at": end - step, "value": 0.0}]
            return []

        prom.query = query
        prom.query_range_raw = query_range
        history = await monitor.host_history("edge")
        self.assertEqual(history["state"], "partial_no_data")
        self.assertEqual(history["metrics"]["cpu"]["value"], 0.0)
        self.assertEqual(history["metrics"]["cpu"]["state"], "ok")
        self.assertEqual(history["metrics"]["memory"]["state"], "no_data")
        self.assertEqual(len(history["metrics"]["cpu"]["points"]), 1)


if __name__ == "__main__":
    unittest.main()
