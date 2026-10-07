"""对象/资产健康语义（P0-06）。

healthy / degraded / unhealthy / unknown / stale
required checks 缺失或过期不得标 healthy；无 Incident ≠ healthy。
Web 只渲染本模块结论。
"""

from __future__ import annotations

import time
from typing import Any

# 每对象 required checks：metric + selector + freshness
# 可按 asset 表达
REQUIRED_CHECKS: dict[str, list[dict[str, Any]]] = {
    "nerv": [
        {"object": "frps", "metric": "probe_success", "selector": {"asset": "nerv", "service": "frps"}, "freshness_sec": 120},
        {"object": "nginx", "metric": "probe_success", "selector": {"asset": "nerv", "service": "nginx"}, "freshness_sec": 120},
    ],
    "sora": [
        {"object": "google", "metric": "hysteria_proxy_up", "selector": {"target": "google"}, "freshness_sec": 180},
        {"object": "youtube", "metric": "hysteria_proxy_up", "selector": {"target": "youtube"}, "freshness_sec": 180},
        {"object": "hysteria-server", "metric": "probe_success", "selector": {"asset": "sora", "service": "hysteria"}, "freshness_sec": 180},
    ],
    "kanata": [
        {"object": "harbor-core", "metric": "probe_success", "selector": {"asset": "kanata", "service": "harbor"}, "freshness_sec": 180},
    ],
    "yomi": [],
}

FRESHNESS_DEFAULT = 120.0


def _sample_state(sample: dict | None, freshness: float, *, expect_ok: bool = True) -> str:
    if not sample:
        return "unknown"
    ts = sample.get("sample_at")
    if ts is None:
        return "unknown"
    age = time.time() - float(ts)
    if age > freshness:
        return "stale"
    val = sample.get("value")
    if val is None:
        return "unknown"
    ok = (val == 1) if expect_ok else (val == 0)
    return "healthy" if ok else "unhealthy"


def object_health(
    *,
    asset_id: str,
    object_name: str,
    samples: list[dict],
    open_incidents: int = 0,
    required: list[dict] | None = None,
) -> dict[str, Any]:
    """单对象健康：required checks 聚合，不以 Incident 作为健康证据。"""
    checks = required if required is not None else [
        c for c in REQUIRED_CHECKS.get(asset_id, []) if c.get("object") == object_name
    ]
    # 若该对象没有声明 required check 且无样本 → unknown/unobserved
    if not checks:
        if not samples:
            return {
                "state": "unknown",
                "reason": "no_required_checks_or_samples",
                "label": "未观测",
                "checks": [],
                "open_incidents": open_incidents,
            }
        # 无声明但有样本：用样本最近值，过期则 stale
        latest = max(samples, key=lambda s: s.get("sample_at") or 0)
        st = _sample_state(latest, FRESHNESS_DEFAULT)
        return {
            "state": st,
            "reason": "undeclared_check_last_sample",
            "label": {"healthy": "正常", "unhealthy": "异常", "stale": "过期", "unknown": "未知"}.get(st, st),
            "checks": [],
            "open_incidents": open_incidents,
        }

    results = []
    states = []
    for c in checks:
        sel = c.get("selector") or {}
        matched = []
        for s in samples:
            m = s.get("metric") or {}
            if all(m.get(k) == v for k, v in sel.items()):
                matched.append(s)
        latest = max(matched, key=lambda x: x.get("sample_at") or 0) if matched else None
        st = _sample_state(latest, float(c.get("freshness_sec") or FRESHNESS_DEFAULT))
        results.append({
            "object": object_name,
            "metric": c.get("metric"),
            "selector": sel,
            "state": st,
            "sample_at": (latest or {}).get("sample_at"),
            "value": (latest or {}).get("value"),
        })
        states.append(st)

    if not states:
        state = "unknown"
    elif "unhealthy" in states:
        state = "unhealthy"
    elif "stale" in states:
        state = "stale"
    elif "unknown" in states:
        state = "unknown"
    elif all(s == "healthy" for s in states):
        state = "healthy"
    else:
        state = "degraded"

    # 有 open incident 不改成 healthy；也不单独判 unhealthy（用 checks）
    label = {
        "healthy": "正常",
        "unhealthy": "异常",
        "degraded": "降级",
        "stale": "过期",
        "unknown": "未观测",
    }.get(state, state)
    reason = ""
    if state == "unknown":
        reason = "required check missing samples"
    elif state == "stale":
        reason = "required check samples stale"
    elif state == "unhealthy":
        reason = "required check failed"
    return {
        "state": state,
        "label": label,
        "reason": reason,
        "checks": results,
        "open_incidents": open_incidents,
    }


def asset_health(
    *,
    asset_id: str,
    objects: list[dict],
    samples_by_metric: dict[str, list[dict]],
    open_incidents: int = 0,
) -> dict[str, Any]:
    """资产聚合：任一 required 不健康 → 异常；缺测/过期 → 不可判 healthy。"""
    req = REQUIRED_CHECKS.get(asset_id, [])
    if not req:
        return {
            "state": "unknown",
            "label": "未观测",
            "reason": "no required checks",
            "coverage": "无探测项",
            "objects": [],
        }
    obj_rows = []
    states = []
    for c in req:
        metric = c.get("metric") or "probe_success"
        samples = samples_by_metric.get(metric, [])
        h = object_health(
            asset_id=asset_id,
            object_name=c.get("object") or "",
            samples=samples,
            open_incidents=open_incidents,
            required=[c],
        )
        obj_rows.append({"object": c.get("object"), **h})
        states.append(h["state"])

    if "unhealthy" in states:
        overall = "unhealthy"
    elif "stale" in states:
        overall = "stale"
    elif "unknown" in states or "degraded" in states:
        overall = "unknown" if "unknown" in states else "degraded"
    elif all(s == "healthy" for s in states):
        overall = "healthy"
    else:
        overall = "degraded"

    label = {
        "healthy": "正常",
        "unhealthy": "异常",
        "degraded": "降级",
        "stale": "过期",
        "unknown": "观测不全",
    }.get(overall, overall)
    return {
        "state": overall,
        "label": label,
        "coverage": f"required {len(req)}",
        "objects": obj_rows,
        "open_incidents": open_incidents,
    }
