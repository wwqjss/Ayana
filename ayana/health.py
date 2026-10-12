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


# ── 统一主机健康（小圆点唯一来源）────────────────────────────────
# 五态对外：ok / warn / bad / no_data / collect_error
# 聚合优先级：collect_error > bad > warn > no_data > ok
# 不变量：历史未结案 Incident 不反向染色；0 ≠ 无数据。

_HOST_DOT = {
    "collect_error": {"state": "collect_error", "label": "采集故障", "cls": "err"},
    "bad": {"state": "bad", "label": "严重异常", "cls": "bad"},
    "warn": {"state": "warn", "label": "警告", "cls": "warn"},
    "no_data": {"state": "no_data", "label": "暂无数据", "cls": "dim"},
    "ok": {"state": "ok", "label": "正常", "cls": "ok"},
}

_HOST_RANK = {
    "collect_error": 5,
    "bad": 4,
    "warn": 3,
    "stale": 3,
    "no_data": 2,
    "unknown": 2,
    "partial_no_data": 2,
    "ok": 1,
    "healthy": 1,
    "unhealthy": 4,
    "degraded": 3,
    "not_enabled": 0,
    "": 0,
}


def _norm_host_state(raw: str) -> str:
    """把各来源状态压到五态。"""
    r = (raw or "").strip()
    if r in ("collect_error",):
        return "collect_error"
    if r in ("bad", "fail", "unhealthy", "critical", "down"):
        return "bad"
    if r in ("warn", "warning", "degraded", "stale", "partial_no_data"):
        return "warn"
    if r in ("no_data", "unknown", "unobserved"):
        return "no_data"
    if r in ("ok", "healthy", "up", "pass", "passed", "not_enabled", "disabled", ""):
        return "ok" if r in ("ok", "healthy", "up", "pass", "passed") else "ok"
    return "warn"


def _worst(states: list[str]) -> str:
    best = "ok"
    for s in states:
        if _HOST_RANK.get(s, 0) > _HOST_RANK.get(best, 0):
            best = s
    return best


def host_health(
    *,
    metric_state: str = "",
    metric_error: str = "",
    required_state: str = "",
    check_states: list[str] | None = None,
    firing_severities: list[str] | None = None,
    collect_error: str = "",
) -> dict[str, Any]:
    """主机小圆点结论。Web / QQ / 总览 / 资源只消费此结果。

    参数：
      metric_state      monitor 指标层（ok/warn/bad/no_data/collect_error）
      required_state    health.asset_health 聚合（healthy/unhealthy/...）
      check_states      业务检查最近结论（ok/bad/...）
      firing_severities 当前 firing 告警的 severity（critical/warning/info）
      collect_error     采集链路错误（查询失败等）
    """
    states: list[str] = []
    reasons: list[str] = []

    if collect_error or _norm_host_state(metric_state) == "collect_error":
        states.append("collect_error")
        reasons.append(collect_error or metric_error or "采集失败")
    elif metric_state:
        states.append(_norm_host_state(metric_state))

    if required_state:
        # healthy→ok, unhealthy→bad, degraded/stale→warn, unknown→no_data
        mapping = {
            "healthy": "ok",
            "unhealthy": "bad",
            "degraded": "warn",
            "stale": "warn",
            "unknown": "no_data",
        }
        states.append(mapping.get(required_state, _norm_host_state(required_state)))

    for s in check_states or []:
        states.append(_norm_host_state(s))

    # 当前 firing 告警可抬升；info 不抬升到红
    for sev in firing_severities or []:
        sev = (sev or "").lower()
        if sev in ("critical", "fatal", "disaster"):
            states.append("bad")
        elif sev in ("warning", "warn"):
            states.append("warn")

    overall = _worst(states) if states else "no_data"
    partial = metric_state == "partial_no_data" or (
        "no_data" in states and any(state in ("ok", "warn", "bad") for state in states)
    )
    if partial:
        reasons.append("部分监控项暂无当前样本，已有观测仍可查看。")
        if overall == "no_data":
            overall = "warn"
    # 全部 not_enabled/ok 且无任何样本语义时，若输入为空给 no_data
    if not states:
        overall = "no_data"

    dot = _HOST_DOT[overall]
    return {
        "state": dot["state"],
        "label": "部分未观测" if partial and overall == "warn" and "warn" not in states else dot["label"],
        "cls": dot["cls"],
        "reasons": reasons,
        "partial": partial,
        "sources": {
            "metric": _norm_host_state(metric_state) if metric_state else "",
            "required": required_state or "",
            "checks": [_norm_host_state(s) for s in (check_states or [])],
            "firing": list(firing_severities or []),
        },
    }


# ── 系统健康度（驾驶舱唯一分数）────────────────────────────────
# 公式：健康监控项 ÷ 总监控项 × 100%
# MAGI 三行只是分项拆解（分子/母项按来源摊开），不是三套独立评分。
# 采集失败 / 状态未知 → 计入总数但不计入健康；某来源总数为 0 → 显示 —。
# 已恢复未关闭的历史事件不进入统计（只认当前 firing）。

def _ratio_color(ratio: float | None) -> str:
    if ratio is None:
        return "dim"
    if ratio >= 100:
        return "ok"
    if ratio >= 90:
        return "ok"
    if ratio >= 70:
        return "warn"
    return "bad"


def system_health_ratio(
    *,
    metric_items: list[dict[str, Any]] | None = None,
    check_items: list[dict[str, Any]] | None = None,
    alert_items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """汇总驾驶舱「系统健康度」。

    metric_items: [{"state": "healthy|unhealthy|stale|unknown|collect_error"}]
                  通常来自 REQUIRED_CHECKS / 探测项
    check_items:  [{"state": "ok|bad|unknown|..."}] 业务检查 last_state
    alert_items:  当前 status=firing 的告警条目；有则全部不健康
                  （已恢复未关闭历史事件不应传入）
    """

    def _bucket(items: list[dict[str, Any]] | None, key: str, label: str, code: str) -> dict[str, Any]:
        rows = items or []
        total = len(rows)
        healthy = 0
        for r in rows:
            st = (r.get("state") or "").lower()
            # 仅明确健康才计入分子；unknown / collect_error / stale / 无数据都不算健康
            if st in ("healthy", "ok", "up", "pass", "passed"):
                healthy += 1
        if total == 0:
            state = "na"
        elif healthy >= total:
            state = "ok"
        elif healthy == 0:
            state = "bad"
        else:
            state = "warn"
        return {
            "key": key,
            "label": label,
            "code": code,
            "healthy": healthy,
            "total": total,
            "state": state,
        }

    sources = [
        _bucket(metric_items, "metrics", "指标采集", "MELCHIOR-1"),
        _bucket(check_items, "checks", "业务检查", "BALTHASAR-2"),
        _bucket(alert_items, "alerts", "告警状态", "CASPER-3"),
    ]

    # 唯一分数：对 total>0 的来源求和；total=0 的来源不参与（显示 —）
    healthy = sum(s["healthy"] for s in sources if s["total"] > 0)
    total = sum(s["total"] for s in sources if s["total"] > 0)
    if total == 0:
        ratio = None
    else:
        ratio = round(healthy * 100.0 / total, 1)

    return {
        "ratio": ratio,
        "healthy": healthy,
        "total": total,
        "color": _ratio_color(ratio),
        "label": "—" if ratio is None else (f"{ratio:.1f}%" if ratio < 100 else "100%"),
        "sources": sources,
    }
