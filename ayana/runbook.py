"""Runbook：固定查表，零自由度执行。

Agent 思考可自由；执行只能走 runbook 匹配到的预登记动作。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RunbookRule:
    id: str
    name: str
    # 匹配条件
    asset_id: str = "*"
    object_name: str = "*"
    alertname: str = "*"
    category: str = "*"  # LLM 分类可作辅助条件
    # 执行动作（固定）
    capability: str = ""
    reason: str = ""
    # 前置条件：全部满足才执行
    require_probe_fail: bool = True  # 要求探测失败
    # 限制
    max_per_day: int = 3
    cooldown_sec: int = 1800  # 30 分钟


# 默认 runbook 表
RUNBOOK: list[RunbookRule] = [
    RunbookRule(
        id="rb_frps_down_restart",
        name="frps 不可达 → 重启",
        asset_id="nerv",
        object_name="frps",
        alertname="TargetDown",
        capability="service.restart",
        reason="runbook: frps 探测失败自动重启",
        require_probe_fail=True,
        max_per_day=3,
        cooldown_sec=1800,
    ),
    RunbookRule(
        id="rb_nginx_down_restart",
        name="nginx 不可达 → 重启",
        asset_id="nerv",
        object_name="nginx",
        alertname="TargetDown",
        capability="service.restart",
        reason="runbook: nginx 探测失败自动重启",
        require_probe_fail=True,
        max_per_day=3,
        cooldown_sec=1800,
    ),
    RunbookRule(
        id="rb_hy2_down_restart",
        name="hysteria-server 不可达 → 重启",
        asset_id="sora",
        object_name="hysteria-server",
        alertname="TargetDown",
        capability="service.restart",
        reason="runbook: hysteria 探测失败自动重启",
        require_probe_fail=True,
        max_per_day=3,
        cooldown_sec=1800,
    ),
]


def match_runbook(
    *,
    asset_id: str,
    object_name: str,
    alertname: str,
    category: str = "",
    runbook: list[RunbookRule] | None = None,
) -> RunbookRule | None:
    """查表匹配。多条件取最具体的规则。"""
    rules = runbook if runbook is not None else RUNBOOK
    best = None
    best_score = -1
    for r in rules:
        score = 0
        if r.asset_id != "*" and r.asset_id != asset_id:
            continue
        if r.object_name != "*" and r.object_name != object_name:
            continue
        if r.alertname != "*" and r.alertname != alertname:
            continue
        if r.category != "*" and r.category != category:
            continue
        # 精确匹配加分
        if r.asset_id == asset_id:
            score += 3
        if r.object_name == object_name:
            score += 3
        if r.alertname == alertname:
            score += 2
        if r.category == category and category:
            score += 1
        if score > best_score:
            best_score = score
            best = r
    return best


def list_runbook() -> list[dict[str, Any]]:
    return [
        {
            "id": r.id,
            "name": r.name,
            "asset_id": r.asset_id,
            "object_name": r.object_name,
            "alertname": r.alertname,
            "capability": r.capability,
            "max_per_day": r.max_per_day,
            "cooldown_sec": r.cooldown_sec,
        }
        for r in RUNBOOK
    ]
