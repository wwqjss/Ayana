"""VerificationProfile（P0-05）：受控检查契约，禁止 LLM 自由 PromQL。

只有 profile 声明的检查可执行；unsupported profile 阻止自动派发。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VerificationProfile:
    id: str
    name: str
    # 目标
    capability: str  # e.g. service.restart / service.stop
    object_kind: str = "service"
    # 检查来源：prom metric 或确定性检查
    checks: tuple[dict, ...] = ()
    warmup_sec: float = 30.0
    continuous_success_sec: float = 90.0
    max_sample_gap_sec: float = 20.0
    # 固定 deadline（相对动作完成）
    deadline_sec: float = 180.0
    # stop 类：期望服务 inactive 而非 probe=1
    expect: str = "up"  # up|down

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "capability": self.capability,
            "checks": list(self.checks),
            "warmup_sec": self.warmup_sec,
            "continuous_success_sec": self.continuous_success_sec,
            "max_sample_gap_sec": self.max_sample_gap_sec,
            "deadline_sec": self.deadline_sec,
            "expect": self.expect,
        }


# 受控 profile 表（审查后追加，不允许模型写入）
# 发行版仅保留通用契约，不绑定特定资产/服务名。
PROFILES: dict[str, VerificationProfile] = {
    "svc.recover": VerificationProfile(
        id="svc.recover",
        name="服务恢复（通用）",
        capability="service.restart",
        object_kind="service",
        checks=(
            {
                "kind": "prom_range",
                "metric": "probe_success",
                "selector": {"asset": "*", "service": "*"},
                "success_value": 1,
            },
        ),
        warmup_sec=20.0,
        continuous_success_sec=90.0,
        max_sample_gap_sec=20.0,
        deadline_sec=180.0,
        expect="up",
    ),
    "svc.stop": VerificationProfile(
        id="svc.stop",
        name="服务停止（人工）",
        capability="service.stop",
        object_kind="service",
        checks=(
            {
                "kind": "prom_range",
                "metric": "probe_success",
                "selector": {"asset": "*", "service": "*"},
                "success_value": 0,
                "optional": True,
            },
        ),
        warmup_sec=5.0,
        continuous_success_sec=15.0,
        max_sample_gap_sec=30.0,
        deadline_sec=60.0,
        expect="down",
    ),
}

# capability → 默认 profile（仅无歧义的通用能力）
CAP_PROFILE = {
    "service.restart": "svc.recover",
    "service.stop": "svc.stop",
}


def get_profile(profile_id: str) -> VerificationProfile | None:
    return PROFILES.get(profile_id)


def profile_for_action(*, capability: str, asset_id: str = "", object_id: str = "") -> VerificationProfile | None:
    """按 capability 解析通用 profile；未知返回 None（阻止自动）。"""
    if capability in CAP_PROFILE:
        return PROFILES.get(CAP_PROFILE[capability])
    return None


def assert_supported(profile: VerificationProfile | None) -> None:
    if profile is None:
        raise ValueError("unsupported_verification_profile")
