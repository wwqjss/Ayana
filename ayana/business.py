"""Read-only business observations from Prometheus and Ayana checks."""
from __future__ import annotations

import asyncio
import hashlib
import math
import time
from typing import Any

from .health import REQUIRED_CHECKS, host_health, sample_state
from .monitor import asset_label_selector
from .prom import series_key


def _matches(labels: dict, selector: dict, aliases: set[str]) -> bool:
    if labels.get("asset") is not None and str(labels["asset"]).casefold() not in aliases:
        return False
    for key, value in selector.items():
        if key == "asset":
            if str(labels.get(key, "")).casefold() not in aliases:
                return False
        elif labels.get(key) != value:
            return False
    return True


def _latest_series(samples: list[dict]) -> list[dict]:
    latest = {}
    for sample in samples:
        key = series_key(sample.get("metric") or {})
        old = latest.get(key)
        if old is None or _finite(sample.get("sample_at"), 0) >= _finite(old.get("sample_at"), 0):
            latest[key] = sample
    return list(latest.values())


def _finite(value: Any, default=None):
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError):
        return default


async def prometheus_checks(prom: Any, asset: dict) -> tuple[list[dict], list[dict]]:
    """Display configured requirements and discovered probes with actual sample times.

    Component names describe objects; only the registered selectors select series.
    Global metrics are exposed solely for selectors belonging to this asset.
    """
    asset_id = asset["id"]
    prom_asset = str(asset.get("prom_asset") or asset_id)
    aliases = {str(asset_id).casefold(), prom_asset.casefold()}
    requirements = REQUIRED_CHECKS.get(asset_id, [])
    metrics = {
        "probe_success",
        "mysql_up",
        "mysql_slave_status_replica_io_running",
        "mysql_slave_status_replica_sql_running",
    } | {item["metric"] for item in requirements if item.get("metric")}
    at = time.time()

    async def fetch(metric: str):
        expression = metric + "{" + asset_label_selector(prom_asset, asset_id) + "}" if metric == "probe_success" else metric
        try:
            samples = await prom.query_range_vector(expression, at=at, window_sec=600)
            return metric, list(samples), ""
        except Exception:
            return metric, [], "暂时无法获取 Prometheus 业务检查，请稍后刷新。"

    results = await asyncio.gather(*(fetch(metric) for metric in sorted(metrics)))
    by_metric = {metric: samples for metric, samples, _ in results}
    failed = {metric for metric, _, error in results if error}
    errors = [{"source": "prometheus", "message": error, "metric": metric}
              for metric, _, error in results if error]
    items, claimed = [], set()

    def append_item(metric: str, name: str, samples: list[dict], selector: dict,
                    *, required: bool, freshness: float = 120, kind: str = "probe"):
        latest = _latest_series(samples)
        states = [sample_state(sample, freshness, at=at) for sample in latest]
        rank = {"ok": 0, "no_data": 1, "stale": 2, "fail": 3}
        state = max(states, key=lambda value: rank[value]) if states else "no_data"
        if metric in failed:
            state = "collect_error"
        candidates = [sample for sample in latest if sample_state(sample, freshness, at=at) == state] or latest
        sample = max(candidates, key=lambda value: _finite(value.get("sample_at"), 0)) if candidates else {}
        labels = sample.get("metric") or selector
        fingerprint = metric + ":" + name + ":" + series_key(selector)
        items.append({"id": "prom_" + hashlib.sha256(fingerprint.encode()).hexdigest()[:16],
                      "asset_id": asset_id, "name": name, "source": "prometheus",
                      "kind": kind,
                      "metric": metric, "labels": labels, "state": state,
                      "last_at": _finite(sample.get("sample_at"), 0), "value": _finite(sample.get("value")),
                      "required": required})

    for requirement in requirements:
        metric, selector = requirement.get("metric", "probe_success"), requirement.get("selector") or {}
        samples = [sample for sample in by_metric.get(metric, [])
                   if _matches(sample.get("metric") or {}, selector, aliases)]
        claimed.update((metric, series_key(sample.get("metric") or {})) for sample in samples)
        append_item(metric, requirement.get("object") or selector.get("service") or metric,
                    samples, selector, required=True, freshness=float(requirement.get("freshness_sec") or 120),
                    kind=str(requirement.get("kind") or "probe"))

    # Probe series need not have a statically declared required check to appear.
    for sample in _latest_series(by_metric.get("probe_success", [])):
        labels = sample.get("metric") or {}
        if str(labels.get("asset", "")).casefold() not in aliases:
            continue
        if ("probe_success", series_key(labels)) in claimed:
            continue
        name = str(labels.get("service") or labels.get("object") or labels.get("target") or labels.get("instance") or "外部探测")
        append_item("probe_success", name, [sample], labels, required=False)

    # MySQL exporter series: instance health is not replica health.
    for metric, name in (
        ("mysql_up", "MySQL 实例"),
        ("mysql_slave_status_replica_io_running", "MySQL 复制 IO"),
        ("mysql_slave_status_replica_sql_running", "MySQL 复制 SQL"),
    ):
        for sample in _latest_series(by_metric.get(metric, [])):
            labels = sample.get("metric") or {}
            if str(labels.get("asset", "")).casefold() not in aliases:
                continue
            if (metric, series_key(labels)) in claimed:
                continue
            append_item(metric, name, [sample], labels, required=False, freshness=180, kind="mysql")
    return items, errors


def native_check_items(checks: list[dict]) -> list[dict]:
    at = time.time()
    items = []
    for check in checks:
        state = check.get("last_state") or "no_data"
        if not check.get("enabled", True):
            state = "disabled"
        elif not check.get("last_at"):
            state = "no_data"
        elif at - float(check["last_at"]) > max(120, 2 * int(check.get("interval_sec") or 60)):
            state = "stale"
        items.append({**check, "source": "ayana", "state": state, "last_at": check.get("last_at") or 0})
    return items


def required_health(items: list[dict]) -> str:
    states = [item["state"] for item in items if item.get("required")]
    if not states:
        return ""
    if "collect_error" in states:
        return "collect_error"
    if "fail" in states:
        return "unhealthy"
    if "stale" in states:
        return "stale"
    if "no_data" in states:
        return "unknown"
    return "healthy"


# 对象/样本词 → overview.health.objects 的对外词（API 兼容）
_STATE_NAMES = {
    "ok": "healthy",
    "fail": "unhealthy",
    "stale": "stale",
    "no_data": "unknown",
    "collect_error": "unknown",
}


def host_health_view(
    *,
    prom_items: list[dict],
    native_states: list[str] | None = None,
    metric_state: str = "",
    metric_error: str = "",
    firing_severities: list[str] | None = None,
) -> dict[str, Any]:
    """统一 host_health 拼装（P2-1）：overview / hosts / host 三 endpoint 共用。

    返回各 endpoint 所需切片，调用方按既有 JSON 形状裁剪：
      health         overview 的 required 聚合（objects/coverage）
      health_dot     health.host_health 小圆点结论（hosts/host 的 health 字段）
      business_summary
      required_state / firing
    """
    required_state = required_health(prom_items)
    check_states = [item["state"] for item in prom_items if not item.get("required")]
    check_states.extend(native_states or [])
    firing = list(firing_severities or [])
    dot = host_health(
        metric_state=metric_state,
        metric_error=metric_error,
        required_state=required_state,
        check_states=check_states,
        firing_severities=firing,
        collect_error=metric_error if metric_state == "collect_error" else "",
    )
    required_items = [item for item in prom_items if item.get("required")]
    health = {
        "state": required_state or "unknown",
        "coverage": f"required {len(required_items)}",
        "objects": [
            {"object": item["name"], "state": _STATE_NAMES.get(item["state"], "unknown")}
            for item in required_items
        ],
    }
    all_states = [item["state"] for item in prom_items] + list(native_states or [])
    business_summary = {
        "total": len(all_states),
        "healthy": all_states.count("ok"),
        "failed": all_states.count("fail"),
        "unknown": sum(state not in ("ok", "fail") for state in all_states),
    }
    return {
        "health": health,
        "health_dot": dot,
        "business_summary": business_summary,
        "required_state": required_state,
        "firing": firing,
    }
