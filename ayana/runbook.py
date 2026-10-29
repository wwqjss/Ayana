"""Runbook：固定查表 + 确定性前置判据（P0-03）。

执行权 = 查表匹配 × 前置 satisfied × Policy × 主机闸。
前置只返回 satisfied / unsatisfied / unknown，并给出原因。
LLM 任何文字都不能扩大可执行集合。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable

# 控制面对象不得进入自动重启集合
CONTROL_PLANE_MARKERS = ("ayana",)


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
    require_probe_fail: bool = True  # 要求新鲜失败探测
    require_service_state: str = ""  # e.g. "active" | "" = 不强制
    # 限制
    max_per_day: int = 3
    cooldown_sec: int = 1800  # 30 分钟
    # 人工-only 模板（无 runbook 自动路径）
    manual_only: bool = False

    @property
    def rev(self) -> str:
        blob = "|".join(
            [
                self.id,
                self.name,
                self.asset_id,
                self.object_name,
                self.alertname,
                self.category,
                self.capability,
                str(self.require_probe_fail),
                self.require_service_state,
                str(self.manual_only),
                str(self.max_per_day),
                str(self.cooldown_sec),
            ]
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]

    def check_preconditions(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """返回 {status: satisfied|unsatisfied|unknown, reasons: [...]}。

        ctx 键（可选，缺失按 unknown/unsatisfied 处理）：
          asset_id, object_name, object_ref
          probe_failed_recent: bool | None  # 最近失败探测
          probe_samples_ok: bool | None
          service_state: str | None
          exec_channel_ok: bool | None
          verification_ready: bool | None
          global_pause: bool | None
          policy_allowed: bool | None
          budget_ok: bool | None
          object_locked: bool | None
          control_plane: bool | None
        """
        reasons: list[str] = []
        blockers: list[str] = []
        status = "satisfied"

        def need(cond: Any, label: str, on_false: str = "unsatisfied") -> None:
            nonlocal status
            if cond is True:
                return
            blockers.append(label)
            if cond is None:
                reasons.append(f"{label}: unknown")
                if status == "satisfied":
                    status = "unknown"
            else:
                reasons.append(f"{label}: {on_false}")
                status = "unsatisfied"

        # 控制面禁止自动
        if ctx.get("control_plane") or any(
            m in (ctx.get("object_name") or "").lower() or m in (ctx.get("object_ref") or "").lower()
            for m in CONTROL_PLANE_MARKERS
        ):
            return {
                "status": "unsatisfied",
                "reasons": ["control_plane_object: must not auto-remediate Ayana itself"],
                "blockers": ["control_plane_object"],
            }

        need(ctx.get("asset_id") == self.asset_id or self.asset_id == "*", "asset_match", "mismatch")
        need(
            ctx.get("object_name") in (self.object_name, "*") or self.object_name == "*",
            "object_match",
            "mismatch",
        )
        if self.require_probe_fail:
            need(ctx.get("probe_failed_recent"), "fresh_failed_probe", "missing or not failed")
        if self.require_service_state:
            need(
                None if ctx.get("service_state") is None else ctx["service_state"] == self.require_service_state,
                "service_state",
                f"want {self.require_service_state}",
            )
        need(ctx.get("exec_channel_ok"), "exec_channel")
        need(ctx.get("verification_ready"), "verification_contract")
        need(ctx.get("global_pause") is False, "global_pause", "paused")
        need(ctx.get("policy_allowed"), "policy")
        need(ctx.get("budget_ok"), "budget")
        need(ctx.get("object_locked") is False, "object_lock", "locked")
        if ctx.get("write_result_unknown"):
            need(False, "write_result_unknown", "human adjudication required")

        return {
            "status": status,
            "reasons": reasons,
            "blockers": blockers,
            "budget_reason": ctx.get("budget_reason", ""),
            "retry_at": ctx.get("budget_retry_at"),
        }


@dataclass
class ManualTemplate:
    id: str
    name: str
    capability: str
    rev: str = ""

    def __post_init__(self) -> None:
        if not self.rev:
            self.rev = hashlib.sha256(
                f"{self.id}|{self.name}|{self.capability}".encode("utf-8")
            ).hexdigest()[:12]


# 默认 runbook 表：发行版不得内置针对特定资产的自动处置规则。
# 运行时由 config.runbook_rules 注入（见 apply_runbook_rules）。
RUNBOOK: list[RunbookRule] = []


def apply_runbook_rules(cfg_rules: Any) -> list[RunbookRule]:
    """把 config.runbook_rules 解析为 RunbookRule 列表并替换 RUNBOOK（原地）。"""
    out: list[RunbookRule] = []
    if isinstance(cfg_rules, list):
        for raw in cfg_rules:
            if not isinstance(raw, dict):
                continue
            rid = str(raw.get("id") or "").strip()
            if not rid:
                continue
            out.append(
                RunbookRule(
                    id=rid,
                    name=str(raw.get("name") or rid),
                    asset_id=str(raw.get("asset_id") or "*"),
                    object_name=str(raw.get("object_name") or "*"),
                    alertname=str(raw.get("alertname") or "*"),
                    category=str(raw.get("category") or "*"),
                    capability=str(raw.get("capability") or ""),
                    reason=str(raw.get("reason") or ""),
                    require_probe_fail=bool(raw.get("require_probe_fail", True)),
                    require_service_state=str(raw.get("require_service_state") or ""),
                    # 显式 0 = 不限制；缺省才回落默认 3 / 1800
                    max_per_day=(
                        3
                        if raw.get("max_per_day") is None
                        else int(raw.get("max_per_day"))
                    ),
                    cooldown_sec=(
                        1800
                        if raw.get("cooldown_sec") is None
                        else int(raw.get("cooldown_sec"))
                    ),
                    manual_only=bool(raw.get("manual_only", False)),
                )
            )
    RUNBOOK.clear()
    RUNBOOK.extend(out)
    return list(RUNBOOK)


def get_runbook_rule(rule_id: str, runbook: list[RunbookRule] | None = None) -> RunbookRule | None:
    rules = runbook if runbook is not None else RUNBOOK
    for r in rules:
        if r.id == rule_id:
            return r
    return None


def list_runbook() -> list[dict[str, Any]]:
    out = []
    for r in RUNBOOK:
        out.append(
            {
                "id": r.id,
                "name": r.name,
                "asset_id": r.asset_id,
                "object_name": r.object_name,
                "alertname": r.alertname,
                "capability": r.capability,
                "max_per_day": r.max_per_day,
                "cooldown_sec": r.cooldown_sec,
                "rev": r.rev,
                "require_probe_fail": r.require_probe_fail,
            }
        )
    return out
