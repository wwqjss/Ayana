"""Prometheus HTTP API。

采样值与采样时间必须来自同一响应（range raw），禁止两次查询拼对。
"""

from __future__ import annotations

import asyncio
import json
import math
import time
from typing import Any
from urllib.parse import quote


class PromError(Exception):
    pass


class PromClient:
    def __init__(self, base_url: str, timeout: float = 8.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # 失败熔断：连续失败后短路，避免 overview 等路径被慢连接拖死
        self._fail_streak = 0
        self._open_until = 0.0
        self.last_status = "unknown"  # S20: 维护真实 last_status

    def _circuit_open(self) -> bool:
        return time.time() < self._open_until

    def _note_fail(self) -> None:
        self._fail_streak += 1
        self.last_status = "unavailable"
        if self._fail_streak >= 2:
            # 30s 内不再连 Prom，立刻返回错误
            self._open_until = time.time() + 30.0

    def _note_ok(self) -> None:
        self._fail_streak = 0
        self._open_until = 0.0
        self.last_status = "available"

    async def _get(self, path: str, params: dict | None = None) -> dict[str, Any]:
        import aiohttp

        if self._circuit_open():
            raise PromError("circuit_open: prometheus unavailable")
        url = f"{self.base_url}{path}"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as session:
                async with session.get(url, params=params) as resp:
                    text = await resp.text()
                    if resp.status != 200:
                        self._note_fail()
                        raise PromError(f"http {resp.status}: {text[:200]}")
                    try:
                        data = json.loads(text)
                    except (json.JSONDecodeError, ValueError) as e:
                        self._note_fail()
                        raise PromError(f"bad_json:{str(e)[:80]}") from e
                    self._note_ok()
                    return data
        except asyncio.TimeoutError as e:
            self._note_fail()
            raise PromError(f"timeout:{str(e)[:80]}") from e
        except aiohttp.ClientError as e:
            self._note_fail()
            raise PromError(str(e)) from e

    async def query(self, expr: str) -> dict[str, Any]:
        data = await self._get("/api/v1/query", {"query": expr})
        if not isinstance(data, dict) or data.get("status") != "success":
            raise PromError("query_failed")
        payload = data.get("data")
        if not isinstance(payload, dict):
            raise PromError("invalid_query_response")
        result = payload.get("result", [])
        kind = payload.get("resultType", "vector")
        if kind == "scalar":
            if not isinstance(result, list) or len(result) != 2:
                raise PromError("invalid_scalar_response")
            try:
                raw = float(result[1])
            except (TypeError, ValueError):
                raise PromError("invalid_scalar_response") from None
            return {"result": [{"metric": {}, "value": raw}], "evaluated_at": time.time()}
        if kind != "vector" or not isinstance(result, list):
            raise PromError("unsupported_query_result")
        samples = []
        for item in result:
            if not isinstance(item, dict):
                raise PromError("invalid_vector_response")
            metric = item.get("metric", {})
            value = item.get("value", [None, None])
            raw = None
            if isinstance(value, (list, tuple)) and len(value) >= 2:
                try:
                    raw = float(value[1])
                except (TypeError, ValueError):
                    raw = None
            samples.append({"metric": metric, "value": raw})
        return {"result": samples, "evaluated_at": time.time()}

    async def query_range_vector(
        self, expr: str, *, at: float, window_sec: float = 120.0
    ) -> list[dict[str, Any]]:
        """Instant query + range vector selector → 真实 [sample_ts, value]。

        `expr[120s]` 在 instant API 中返回 matrix，其中 values 是
        **样本时间**与值的原始对，不是评估点。lookback 重复同一旧样本
        会在同一 ts 上出现，按 ts 去重即可。
        """
        window = max(30.0, float(window_sec))
        range_expr = f"{expr}[{int(window)}s]"
        data = await self._get(
            "/api/v1/query",
            {"query": range_expr, "time": str(at)},
        )
        if data.get("status") != "success":
            raise PromError(str(data)[:200])
        result = data.get("data", {}).get("result", [])
        out: list[dict[str, Any]] = []
        if data.get("data", {}).get("resultType") != "matrix":
            # 回退：若服务端把 [N] 展成 vector，拒绝当采样用
            raise PromError("expected matrix from range vector selector")
        for series in result:
            metric = series.get("metric") or {}
            for pair in series.get("values") or []:
                if not pair or len(pair) < 2:
                    continue
                try:
                    ts = float(pair[0])
                    val = float(pair[1])
                except (TypeError, ValueError):
                    continue
                out.append({"metric": metric, "sample_at": ts, "value": val})
        return out

    async def query_range_raw(
        self, expr: str, *, start: float, end: float, step: float = 15.0
    ) -> list[dict[str, Any]]:
        """保留给历史比较；验证路径请用 query_range_vector。"""
        if end <= start:
            end = start + 1
        data = await self._get(
            "/api/v1/query_range",
            {
                "query": expr,
                "start": str(start),
                "end": str(end),
                "step": str(step),
            },
        )
        if data.get("status") != "success":
            raise PromError(str(data)[:200])
        out: list[dict[str, Any]] = []
        for series in data.get("data", {}).get("result", []) or []:
            metric = series.get("metric") or {}
            for pair in series.get("values") or []:
                if not pair or len(pair) < 2:
                    continue
                try:
                    ts = float(pair[0])
                    val = float(pair[1])
                except (TypeError, ValueError):
                    continue
                out.append({"metric": metric, "sample_at": ts, "value": val})
        return out

    async def targets(self) -> list[dict[str, Any]]:
        data = await self._get("/api/v1/targets")
        if data.get("status") != "success":
            raise PromError(str(data)[:200])
        return list(data.get("data", {}).get("activeTargets", []))

    async def alerts(self) -> list[dict[str, Any]]:
        data = await self._get("/api/v1/alerts")
        if data.get("status") != "success":
            raise PromError(str(data)[:200])
        return list(data.get("data", {}).get("alerts", []))

    async def probe_success_since(
        self,
        asset: str,
        service: str = "",
        *,
        start: float,
        end: float | None = None,
        step: float = 15.0,
        window_sec: float | None = None,
        max_window_sec: float = 600.0,
    ) -> list[dict[str, Any]]:
        """精确序列的真实采样（range vector，样本时间来自 values）。

        只返回 sample_at > start 的样本；按 (labels, sample_at) 去重。
        查询窗口有界，不随时间无限膨胀。
        """
        if service:
            sel = f'probe_success{{asset="{quote(asset)}", service="{quote(service)}"}}'
        else:
            sel = f'probe_success{{asset="{quote(asset)}"}}'
        end = end if end is not None else time.time()
        if window_sec is not None:
            span = min(float(window_sec), max_window_sec)
        else:
            span = min(max(120.0, (end - start) + 60.0), max_window_sec)
        raw = await self.query_range_vector(sel, at=end, window_sec=span)
        by_key: dict[tuple[str, float], dict] = {}
        for s in raw:
            ts = s.get("sample_at")
            if ts is None or float(ts) <= float(start):
                continue
            key = (series_key(s.get("metric") or {}), round(float(ts), 3))
            by_key[key] = s
        return sorted(by_key.values(), key=lambda x: x.get("sample_at") or 0)

    async def probe_success(self, asset: str, service: str = "") -> dict[str, Any]:
        """向后兼容：最近一小段真实采样。"""
        end = time.time()
        samples = await self.probe_success_since(
            asset, service, start=end - 120, end=end, window_sec=120
        )
        return {"result": samples, "evaluated_at": end}

    async def up_metric(self, asset: str) -> dict[str, Any]:
        end = time.time()
        samples = await self.query_range_vector(
            f'up{{asset="{quote(asset)}"}}', at=end, window_sec=120
        )
        return {"result": samples, "evaluated_at": end}

    async def node_exporter_present(self) -> bool:
        try:
            data = await self.query('up{job=~"node.*"}')
            return bool(data.get("result"))
        except PromError:
            return False


def summarize_probe(data: dict[str, Any]) -> dict[str, Any]:
    from .health import sample_state

    samples = data.get("result") or []
    if not samples:
        return {"state": "unknown", "reason": "no_samples", "value": None, "age_sec": None}
    usable = [s for s in samples if s.get("sample_at") is not None]
    if not usable:
        return {"state": "unknown", "reason": "sample_time_unknown", "value": None, "age_sec": None}
    # 不得用最新样本掩盖稍旧失败（P0-06）
    now_ts = time.time()
    # summarize_probe 不做 freshness 收紧（窗口由 probe_success 界定）；判定走统一样本词表
    states = [sample_state(s, math.inf, at=now_ts) for s in usable]
    if "fail" in states:
        latest_fail = max(
            (s for s, st in zip(usable, states) if st == "fail"),
            key=lambda x: x.get("sample_at") or 0,
        )
        ts = latest_fail.get("sample_at")
        age = (now_ts - ts) if ts else None
        return {
            "state": "fail",
            "reason": "failure_sample_present",
            "value": 0,
            "sample_at": ts,
            "age_sec": age,
            "labels": latest_fail.get("metric") or {},
        }
    s = max(usable, key=lambda x: x.get("sample_at") or 0)
    ts = s.get("sample_at")
    age = (now_ts - ts) if ts else None
    val = s.get("value")
    st = sample_state(s, math.inf, at=now_ts)
    # 对外保留历史词 unknown（= 统一词表 no_data）
    state = {"ok": "ok", "fail": "fail", "stale": "stale", "no_data": "unknown"}.get(st, "unknown")
    return {
        "state": state,
        "reason": "",
        "value": val,
        "sample_at": ts,
        "age_sec": age,
        "labels": s.get("metric") or {},
    }


def series_key(metric: dict) -> str:
    m = {k: v for k, v in (metric or {}).items() if not k.startswith("__")}
    return json.dumps(m, sort_keys=True)


def match_series(samples: list[dict], *, asset: str, service: str = "") -> list[dict]:
    """精确匹配：asset 必须相等；service 给定时也必须相等。"""
    out = []
    for s in samples:
        labels = s.get("metric") or {}
        if labels.get("asset") != asset:
            continue
        if service and labels.get("service") != service:
            continue
        out.append(s)
    return out


def group_by_series(samples: list[dict]) -> dict[str, list[dict]]:
    """按完整标签分组，时间相同的多序列不互相覆盖。"""
    groups: dict[str, list[dict]] = {}
    for s in samples:
        groups.setdefault(series_key(s.get("metric") or {}), []).append(s)
    for v in groups.values():
        v.sort(key=lambda x: x.get("sample_at") or 0)
    return groups
