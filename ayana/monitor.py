"""主机资源监控：Prometheus + Node Exporter 查询（不本地存时序）。

状态：
- ok / warn / bad  有数据且阈值判定
- not_enabled      功能未启用（如 Swap 总量为 0）
- no_data          查询成功但无样本
- collect_error    Prometheus 不可达 / 查询失败
"""

from __future__ import annotations

import time
import json
import re
from typing import Any

from .prom import PromClient, PromError

# 时间范围（秒）→ 步长
RANGES: dict[str, tuple[float, float]] = {
    "15m": (15 * 60, 30),
    "1h": (60 * 60, 60),
    "6h": (6 * 3600, 300),
    "24h": (24 * 3600, 900),
    "7d": (7 * 24 * 3600, 3600),
}

# 阈值：warn / bad（百分比或负载）
THRESHOLDS = {
    "cpu": (80.0, 95.0),
    "memory": (85.0, 95.0),
    "swap": (50.0, 80.0),
    "disk": (85.0, 95.0),
}


def _state_from_value(metric: str, value: float | None) -> str:
    if value is None:
        return "no_data"
    warn, bad = THRESHOLDS.get(metric, (None, None))
    if warn is None:
        return "ok"
    if value >= bad:
        return "bad"
    if value >= warn:
        return "warn"
    return "ok"


def _swap_state_and_value(
    swap_total: float | None, swap_used: float | None
) -> tuple[str, float | None]:
    """Swap 状态：总量为 0 → 未启用；否则按使用率阈值判定。"""
    if swap_total is None:
        return "no_data", None
    if swap_total <= 0:
        return "not_enabled", None
    if swap_used is None:
        return "no_data", None
    return _state_from_value("swap", swap_used), swap_used


def _agg_max(samples: list[dict]) -> float | None:
    vals = [s.get("value") for s in samples if s.get("value") is not None]
    if not vals:
        return None
    nums = [float(v) for v in vals]
    nums = [n for n in nums if n == n]  # drop NaN
    if not nums:
        return None
    return max(nums)


def _agg_sum_latest(samples: list[dict]) -> float | None:
    """按序列取最新再求和（多网卡/多挂载点）。"""
    by_series: dict[str, dict] = {}
    for s in samples:
        key = json_key(s.get("metric") or {})
        old = by_series.get(key)
        if not old or (s.get("sample_at") or 0) >= (old.get("sample_at") or 0):
            by_series[key] = s
    vals = [s.get("value") for s in by_series.values() if s.get("value") is not None]
    if not vals:
        return None
    nums = [float(v) for v in vals]
    nums = [n for n in nums if n == n]
    if not nums:
        return None
    return sum(nums)


def json_key(metric: dict) -> str:
    import json

    m = {k: v for k, v in (metric or {}).items() if not str(k).startswith("__")}
    return json.dumps(m, sort_keys=True)


def _pick_series(samples: list[dict], prefer: str = "") -> list[dict]:
    return samples


def asset_label_selector(asset_id: str, *aliases: str) -> str:
    """Match one configured Prometheus asset label, including case aliases."""
    names = list(dict.fromkeys((asset_id, *aliases)))
    exact = re.escape(names[0]) if len(names) == 1 else "(?:" + "|".join(re.escape(name) for name in names) + ")"
    pattern = "(?i)^" + exact + "$"
    return "asset=~" + json.dumps(pattern)


class HostMonitor:
    def __init__(self, prom: PromClient):
        self.prom = prom

    def _asset_sel(self, asset_id: str) -> str:
        # 标签大小写不敏感：romi / ROMI / Romi 视为同一资产
        return asset_label_selector(asset_id)

    def _history_exprs(self, asset_id: str) -> dict[str, str]:
        sel = self._asset_sel(asset_id)
        return {
            "cpu": f'100 - (avg(rate(node_cpu_seconds_total{{{sel},mode="idle"}}[2m])) * 100)',
            "memory": f'100 * (1 - (node_memory_MemAvailable_bytes{{{sel}}} / node_memory_MemTotal_bytes{{{sel}}}))',
            "swap_total": f'node_memory_SwapTotal_bytes{{{sel}}}',
            "swap": (
                f'100 * (1 - (node_memory_SwapFree_bytes{{{sel}}} /'
                f' node_memory_SwapTotal_bytes{{{sel}}}))'
            ),
            "disk": (
                f'100 * (1 - (node_filesystem_avail_bytes{{{sel},fstype!~"tmpfs|overlay|squashfs|ramfs"}} /'
                f' clamp_min(node_filesystem_size_bytes{{{sel},fstype!~"tmpfs|overlay|squashfs|ramfs"}}, 1)))'
            ),
            "disk_read": f'sum(rate(node_disk_read_bytes_total{{{sel}}}[2m]))',
            "disk_write": f'sum(rate(node_disk_written_bytes_total{{{sel}}}[2m]))',
            "net_rx": (
                f'sum(rate(node_network_receive_bytes_total{{{sel},'
                f'device!~"lo|veth.*|br-.*|docker.*|virbr.*"}}[2m]))'
            ),
            "net_tx": (
                f'sum(rate(node_network_transmit_bytes_total{{{sel},'
                f'device!~"lo|veth.*|br-.*|docker.*|virbr.*"}}[2m]))'
            ),
            "load1": f'node_load1{{{sel}}}',
            "load5": f'node_load5{{{sel}}}',
            "load15": f'node_load15{{{sel}}}',
        }

    def _instant_exprs(self, asset_id: str) -> dict[str, str]:
        return self._history_exprs(asset_id)

    def _exporter_up_expr(self, asset_id: str) -> str:
        sel = self._asset_sel(asset_id)
        return f'up{{{sel},job=~"node.*"}} or up{{{sel},job_type="node_exporter"}}'

    async def _query_instant(self, expr: str) -> list[dict]:
        data = await self.prom.query(expr)
        return list(data.get("result") or [])

    async def _query_series(
        self, expr: str, *, start: float, end: float, step: float
    ) -> list[dict]:
        return await self.prom.query_range_raw(expr, start=start, end=end, step=step)

    def _metric_block(
        self,
        name: str,
        *,
        samples: list[dict],
        series: list[dict],
        unit: str,
        label: str,
        state_metric: bool = False,
    ) -> dict[str, Any]:
        cur = _agg_sum_latest(samples) if name.startswith(("disk_read", "disk_write", "net_", "disk")) else _agg_max(samples)
        if name == "disk":
            cur = _agg_max(samples)
        if name.startswith("load"):
            cur = _agg_max(samples)
        if name in ("cpu", "memory", "swap"):
            cur = _agg_max(samples)
        state = _state_from_value(name if not state_metric else "", cur if cur is not None else None)
        if name not in THRESHOLDS:
            state = "ok" if cur is not None else "no_data"
        elif cur is None:
            state = "no_data"
        points = [
            {"t": s.get("sample_at"), "v": s.get("value")}
            for s in sorted(series, key=lambda x: x.get("sample_at") or 0)
            if s.get("sample_at") is not None and s.get("value") is not None and s.get("value") == s.get("value")
        ]
        return {
            "key": name,
            "label": label,
            "unit": unit,
            "value": cur,
            "state": state,
            "points": points,
            "updated_at": time.time(),
        }

    def _swap_metric_block(
        self,
        *,
        total_samples: list[dict],
        used_samples: list[dict],
        series: list[dict],
    ) -> dict[str, Any]:
        """Swap 专用：总量为 0 → 未启用，不计算使用率、不标异常。"""
        swap_total = _agg_max(total_samples)
        swap_used = _agg_max(used_samples)
        state, value = _swap_state_and_value(swap_total, swap_used)
        points = []
        if state != "not_enabled":
            points = [
                {"t": s.get("sample_at"), "v": s.get("value")}
                for s in sorted(series, key=lambda x: x.get("sample_at") or 0)
                if s.get("sample_at") is not None
                and s.get("value") is not None
                and s.get("value") == s.get("value")
            ]
        return {
            "key": "swap",
            "label": "Swap 使用率",
            "unit": "%",
            "value": value,
            "state": state,
            "points": points,
            "updated_at": time.time(),
            "total": swap_total,
        }

    async def host_overview(self, asset_id: str) -> dict[str, Any]:
        """当前数值一览（轻量 instant 查询）。"""
        exprs = self._instant_exprs(asset_id)
        result: dict[str, Any] = {
            "asset_id": asset_id,
            "state": "ok",
            "metrics": {},
            "error": "",
            "collected_at": time.time(),
        }
        try:
            cpu = await self._query_instant(exprs["cpu"])
            mem = await self._query_instant(exprs["memory"])
            swap_total = await self._query_instant(exprs["swap_total"])
            swap = await self._query_instant(exprs["swap"])
            disk = await self._query_instant(exprs["disk"])
            load = await self._query_instant(exprs["load1"])
            load5 = await self._query_instant(exprs["load5"])
            up = await self._query_instant(self._exporter_up_expr(asset_id))
        except PromError as e:
            result["state"] = "collect_error"
            result["error"] = str(e)[:200]
            return result

        def blk(key, samples, unit, label, thresh_key=None):
            cur = _agg_max(samples)
            sk = thresh_key or key
            if sk in THRESHOLDS:
                st = "no_data" if cur is None else _state_from_value(sk, cur)
            else:
                st = "ok" if cur is not None else "no_data"
            return {"key": key, "label": label, "unit": unit, "value": cur, "state": st}

        swap_blk = self._swap_metric_block(
            total_samples=swap_total, used_samples=swap, series=[]
        )
        metrics = {
            "cpu": blk("cpu", cpu, "%", "CPU 使用率"),
            "memory": blk("memory", mem, "%", "内存使用率"),
            "swap": swap_blk,
            "disk": blk("disk", disk, "%", "磁盘使用率(最大)"),
            "load1": blk("load1", load, "", "负载 1m", thresh_key=None),
            "load5": blk("load5", load5, "", "负载 5m", thresh_key=None),
        }
        # node exporter 是否在采
        up_val = _agg_max(up)
        result["exporter_up"] = up_val
        if up_val is None and not any(m["value"] is not None for m in metrics.values()):
            result["state"] = "no_data"
        elif up_val is not None and up_val < 1:
            result["state"] = "collect_error"
            result["error"] = "node_exporter_down"
        else:
            # 汇总最差状态（not_enabled 不参与告警）
            order = {"ok": 0, "not_enabled": 0, "partial_no_data": 1, "no_data": 1, "warn": 2, "bad": 3, "collect_error": 4}
            states = [m["state"] for m in metrics.values() if m["state"] != "not_enabled"]
            has_data = up_val == 1 or any(m["value"] is not None for m in metrics.values())
            no_data_count = sum(1 for s in states if s == "no_data")
            if no_data_count and has_data:
                # S20: 部分缺测 → partial_no_data，不改成 ok
                worst_partial = max(
                    (s for s in states if s != "no_data"),
                    key=lambda s: order.get(s, 0),
                    default="ok",
                )
                result["state"] = worst_partial if order.get(worst_partial, 0) > 1 else "partial_no_data"
            else:
                worst = max(states, key=lambda s: order.get(s, 0), default="ok")
                result["state"] = worst
            if not has_data:
                result["state"] = "no_data"
        result["metrics"] = metrics
        return result

    async def host_history(self, asset_id: str, range_key: str = "1h") -> dict[str, Any]:
        span, step = RANGES.get(range_key, RANGES["1h"])
        end = time.time()
        start = end - span
        exprs = self._history_exprs(asset_id)
        out: dict[str, Any] = {
            "asset_id": asset_id,
            "range": range_key,
            "start": start,
            "end": end,
            "step": step,
            "state": "ok",
            "error": "",
            "metrics": {},
        }
        labels = {
            "cpu": ("%", "CPU 使用率"),
            "memory": ("%", "内存使用率"),
            "swap": ("%", "Swap 使用率"),
            "disk": ("%", "磁盘使用率(最大)"),
            "disk_read": ("B/s", "磁盘读"),
            "disk_write": ("B/s", "磁盘写"),
            "net_rx": ("B/s", "网络接收"),
            "net_tx": ("B/s", "网络发送"),
            "load1": ("", "负载 1m"),
            "load5": ("", "负载 5m"),
            "load15": ("", "负载 15m"),
        }
        metrics: dict[str, Any] = {}
        collect_err = ""
        swap_total_samples: list[dict] = []
        swap_used_series: list[dict] = []
        swap_used_instant: list[dict] = []
        for key, expr in exprs.items():
            if key == "swap_total":
                try:
                    swap_total_samples = await self._query_instant(expr)
                except PromError as e:
                    collect_err = str(e)[:200]
                continue
            unit, label = labels.get(key, ("", key))
            try:
                series = await self._query_series(expr, start=start, end=end, step=step)
                # 即时值：区间最后一段
                instant = await self._query_instant(expr)
            except PromError as e:
                collect_err = str(e)[:200]
                metrics[key] = {
                    "key": key,
                    "label": label,
                    "unit": unit,
                    "value": None,
                    "state": "collect_error",
                    "points": [],
                    "error": collect_err,
                }
                continue
            if key == "swap":
                swap_used_series = series
                swap_used_instant = instant
                continue
            if key.startswith(("disk_read", "disk_write", "net_")):
                cur = _agg_sum_latest(instant)
            else:
                cur = _agg_max(instant)
            if key in THRESHOLDS:
                st = "no_data" if cur is None else _state_from_value(key, cur)
            else:
                st = "ok" if cur is not None else "no_data"
            # 历史曲线：按序列求和/取最大，压成一条便于画图
            by_t: dict[float, float] = {}
            for s in series:
                t = float(s.get("sample_at") or 0)
                v = s.get("value")
                if v is None or v != v:
                    continue
                if key.startswith(("disk_read", "disk_write", "net_", "disk")) or key in ("cpu", "memory"):
                    # 多序列：同刻求和（disk 取 max）
                    if key == "disk" or key in ("cpu", "memory"):
                        prev = by_t.get(t)
                        by_t[t] = max(prev, float(v)) if prev is not None else float(v)
                    else:
                        by_t[t] = by_t.get(t, 0.0) + float(v)
                else:
                    prev = by_t.get(t)
                    by_t[t] = max(prev, float(v)) if prev is not None else float(v)
            points = [{"t": t, "v": by_t[t]} for t in sorted(by_t)]
            metrics[key] = {
                "key": key,
                "label": label,
                "unit": unit,
                "value": cur,
                "state": st,
                "points": points,
            }
        # Swap 专用块：总量为 0 → 未启用
        swap_blk = self._swap_metric_block(
            total_samples=swap_total_samples,
            used_samples=swap_used_instant,
            series=swap_used_series,
        )
        metrics["swap"] = swap_blk
        out["metrics"] = metrics
        if collect_err and all(m.get("state") == "collect_error" for m in metrics.values()):
            out["state"] = "collect_error"
            out["error"] = collect_err
        elif all(m.get("value") is None and m.get("state") != "not_enabled" for m in metrics.values()):
            out["state"] = "no_data"
        else:
            order = {"ok": 0, "not_enabled": 0, "no_data": 1, "warn": 2, "bad": 3, "collect_error": 4}
            states = [m.get("state") for m in metrics.values() if m.get("state") != "not_enabled"]
            out["state"] = max(
                states,
                key=lambda s: order.get(s, 0),
                default="ok",
            )
            if out["state"] == "no_data" and any(m.get("value") is not None for m in metrics.values()):
                out["state"] = "partial_no_data"
        return out

    async def hosts_status(self, assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """资产列表 + 每台 node 指标可用性（轻量）。"""
        out = []
        for a in assets:
            asset_id = str(a.get("id") or a.get("prom_asset") or "")
            prom_asset = str(a.get("prom_asset") or asset_id)
            item = {
                "asset_id": asset_id,
                "display_name": a.get("display_name") or asset_id,
                "prom_asset": prom_asset,
                "state": "no_data",
                "error": "",
                "summary": {},
            }
            overview = await self.host_overview(prom_asset)
            item["state"] = overview["state"]
            item["error"] = overview.get("error") or ""
            item["summary"] = {"cpu": (overview.get("metrics", {}).get("cpu") or {}).get("value"),
                               "up": overview.get("exporter_up")}
            out.append(item)
        return out
