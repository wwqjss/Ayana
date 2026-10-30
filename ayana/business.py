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
    # One unavailable optional source is one notice, not one failure per query.
    errors = [{"source": "prometheus", "message": "Prometheus 暂不可用；原生业务检查仍可独立使用。",
               "metrics": sorted(failed), "optional": True, "fatal": False}] if failed else []
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
        last_at = _finite(check.get("last_at"), 0)
        interval = _finite(check.get("interval_sec"), 60)
        if not check.get("enabled", True):
            state = "disabled"
        elif last_at <= 0 or last_at > at:
            state = "no_data"
        elif at - last_at > max(120, 2 * interval):
            state = "stale"
        elif state not in ("ok", "fail"):
            state = "no_data"
        items.append({**check, "source": "ayana", "state": state, "last_at": last_at})
    return items


def native_check_summary(items: list[dict]) -> dict[str, Any]:
    """Summarize observed enabled checks; disabled rows never prove health."""
    active = [item for item in items if item.get("enabled", True) and item.get("state") != "disabled"]
    states = [item.get("state") or "no_data" for item in active]
    failed = sum(state in ("fail", "bad", "unhealthy") for state in states)
    healthy = states.count("ok")
    stale = states.count("stale")
    unknown = len(states) - healthy - failed - stale
    state = "bad" if failed else "stale" if stale else "no_data" if unknown or not active else "ok"
    return {"source": "native", "state": state,
            "label": {"ok": "原生检查正常", "bad": "原生检查异常", "stale": "原生检查已过期", "no_data": "原生检查尚未观测"}[state],
            "total": len(items), "enabled": len(active), "healthy": healthy,
            "failed": failed, "stale": stale, "unknown": unknown,
            "disabled": len(items) - len(active), "fresh": healthy + failed,
            "last_at": max((_finite(item.get("last_at"), 0) for item in active), default=0)}


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
    native_items: list[dict] | None = None,
    metric_state: str = "",
    metric_error: str = "",
    firing_severities: list[str] | None = None,
    prom_errors: list[dict] | None = None,
) -> dict[str, Any]:
    """统一 host_health 拼装（P2-1）：overview / hosts / host 三 endpoint 共用。

    返回各 endpoint 所需切片，调用方按既有 JSON 形状裁剪：
      health         overview 的 required 聚合（objects/coverage）
      health_dot     health.host_health 小圆点结论（hosts/host 的 health 字段）
      business_summary
      required_state / firing
    """
    required_state = required_health(prom_items)
    native = native_items if native_items is not None else [{"state": state} for state in (native_states or [])]
    native_summary = native_check_summary(native)
    active_native_states = [item.get("state") or "no_data" for item in native
                            if item.get("enabled", True) and item.get("state") != "disabled"]
    check_states = [item["state"] for item in prom_items if not item.get("required")]
    check_states.extend(active_native_states)
    firing = list(firing_severities or [])
    dot = host_health(
        metric_state=metric_state,
        metric_error=metric_error,
        required_state=required_state,
        check_states=check_states,
        firing_severities=firing,
        collect_error=metric_error if metric_state == "collect_error" else "",
    )
    raw_sources = dot["sources"]
    if native_summary["enabled"]:
        # Native checks and Node metrics are independent observations. Missing
        # optional Prometheus data must not erase a known native result. Actual
        # resource warnings/failures, failed probes and firing alerts still count.
        dot = host_health(
            metric_state=metric_state if metric_state in ("ok", "warn", "bad") else "",
            check_states=[item["state"] for item in prom_items if item["state"] in ("ok", "fail")]
                         + active_native_states,
            firing_severities=firing,
        )
        dot["sources"] = raw_sources
    prom_observed = metric_state in ("ok", "warn", "bad", "partial_no_data") or any(
        item["state"] in ("ok", "fail") for item in prom_items)
    source = ("mixed" if prom_observed else "native") if native_summary["enabled"] else "prometheus" if prom_observed else "none"
    dot["source"] = source
    dot["source_label"] = {"native": "原生检查", "prometheus": "Prometheus", "mixed": "原生检查与 Prometheus", "none": "尚未观测"}[source]
    if dot["state"] == "ok" and source == "native":
        dot["label"] = native_summary["label"]
    unavailable = metric_state in ("no_data", "not_configured", "collect_error", "partial_no_data") or bool(prom_errors)
    warnings = [{"source": "prometheus", "optional": True, "fatal": False,
                 "message": "Prometheus 资源指标暂不可用或观测不全；原生业务检查独立呈现。"}] if unavailable else []
    source_state = metric_state or ("collect_error" if prom_errors else "ok" if prom_observed else "no_data")
    monitor_sources = {
        "native": native_summary,
        "prometheus": {"state": source_state, "error": metric_error, "optional": True,
                       "business_errors": list(prom_errors or [])},
    }
    required_items = [item for item in prom_items if item.get("required")]
    health = {
        "state": required_state or "unknown",
        "coverage": f"required {len(required_items)}",
        "objects": [
            {"object": item["name"], "state": _STATE_NAMES.get(item["state"], "unknown")}
            for item in required_items
        ],
    }
    all_states = [item["state"] for item in prom_items] + active_native_states
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
        "overall": dot,
        "native_summary": native_summary,
        "monitor_sources": monitor_sources,
        "warnings": warnings,
    }
