"""对象/资产健康语义（P0-06）。

healthy / degraded / unhealthy / unknown / stale
required checks 缺失或过期不得标 healthy；无 Incident ≠ healthy。
Web 只渲染本模块结论。
"""

from __future__ import annotations

import math
import time
from typing import Any

# 每对象 required checks：metric + selector + freshness
# 可按 asset 表达。
# 正式发行版不得内置任何个人/特定环境的资产与业务检查。
# 默认为空；运行时由 config.required_checks 注入（见 apply_required_checks）。
REQUIRED_CHECKS: dict[str, list[dict[str, Any]]] = {}

FRESHNESS_DEFAULT = 120.0


def apply_required_checks(cfg_checks: Any) -> dict[str, list[dict[str, Any]]]:
    """把 config.required_checks 合并进 REQUIRED_CHECKS（启动时调用）。

    原地更新，保证 `from .health import REQUIRED_CHECKS` 的调用方可见。
    仅接受 {asset_id: [ {object, metric, selector, freshness_sec}, ... ]}。
    """
    out: dict[str, list[dict[str, Any]]] = {}
    if isinstance(cfg_checks, dict):
        for asset_id, items in cfg_checks.items():
            if not isinstance(asset_id, str) or not isinstance(items, list):
                continue
            cleaned = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                cleaned.append(
                    {
                        "object": str(item.get("object") or ""),
                        "metric": str(item.get("metric") or "probe_success"),
                        "selector": dict(item.get("selector") or {}),
                        "freshness_sec": float(item.get("freshness_sec") or 120),
                        "kind": str(item.get("kind") or "probe"),
                    }
                )
            if cleaned:
                out[asset_id] = cleaned
    REQUIRED_CHECKS.clear()
    REQUIRED_CHECKS.update(out)
    return out


# ── 统一样本判定词表（P2-1）────────────────────────────────────
# 单样本：ok / fail / stale / no_data
# collect_error 由采集链路（查询失败等）在聚合层表达，不是样本本身的状态。
# object_health 等对外仍映射到 healthy/unhealthy/... 兼容词，前端形状不变。

SAMPLE_STATES = ("ok", "fail", "stale", "no_data", "collect_error")


def sample_state(
    sample: dict | None,
    freshness: float,
    *,
    at: float | None = None,
    expect_ok: bool = True,
) -> str:
    """单样本判定（唯一词表）：ok / fail / stale / no_data。

    expect_ok=True 时 value==1 为 ok；False 时 value==0 为 ok（计数型指标）。
    缺样本/缺时间/不可解析/非有限值 → no_data；过期 → stale；其余有限值 → fail。
    """
    if not sample or sample.get("sample_at") is None:
        return "no_data"
    try:
        ts = float(sample["sample_at"])
        raw = sample.get("value")
        if raw is None:
            return "no_data"
        val = float(raw)
    except (KeyError, TypeError, ValueError):
        return "no_data"
    if not (math.isfinite(ts) and math.isfinite(val)):
        return "no_data"
    if (time.time() if at is None else float(at)) - ts > float(freshness):
        return "stale"
    ok = (val == 1) if expect_ok else (val == 0)
    return "ok" if ok else "fail"


# 对象健康对外词（API 兼容）；内核统一走 sample_state
_OBJ_STATE_FROM_SAMPLE = {
    "ok": "healthy",
    "fail": "unhealthy",
    "stale": "stale",
    "no_data": "unknown",
    "collect_error": "unknown",
}


def _sample_state(sample: dict | None, freshness: float, *, expect_ok: bool = True) -> str:
    """object_health 兼容入口：统一词表 → 对象健康词。"""
    return _OBJ_STATE_FROM_SAMPLE.get(
        sample_state(sample, freshness, expect_ok=expect_ok), "unknown"
    )


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
    "not_configured": {"state": "not_configured", "label": "监控未接入", "cls": "dim"},
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
    "not_configured": 2,
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
    if r in ("not_configured",):
        return "not_configured"
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

    metric_norm = _norm_host_state(metric_state) if metric_state else ""
    if collect_error or metric_norm == "collect_error":
        err_l = (collect_error or metric_error or "").lower()
        conn_down = any(
            k in err_l
            for k in (
                "circuit_open",
                "timeout",
                "cannot connect",
                "connection refused",
                "connectorerror",
                "clientconnector",
                "all connection attempts failed",
                "prometheus unavailable",
                "not_configured",
            )
        )
        if metric_norm == "not_configured" or (
            "node_exporter_down" not in err_l and conn_down
        ):
            states.append("not_configured")
            reasons.append("监控未接入或 Prometheus 不可达")
        else:
            states.append("collect_error")
            reasons.append(collect_error or metric_error or "采集失败")
    elif metric_state:
        states.append(metric_norm or _norm_host_state(metric_state))

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
