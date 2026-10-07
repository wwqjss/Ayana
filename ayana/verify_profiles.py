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
PROFILES: dict[str, VerificationProfile] = {
    "frps.recover": VerificationProfile(
        id="frps.recover",
        name="NERV frps 恢复",
        capability="service.restart",
        object_kind="service",
        checks=(
            {
                "kind": "prom_range",
                "metric": "probe_success",
                "selector": {"asset": "nerv", "service": "frps"},
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

# capability → 默认 profile
CAP_PROFILE = {
    "service.restart": "frps.recover",
    "service.stop": "svc.stop",
}


def get_profile(profile_id: str) -> VerificationProfile | None:
    return PROFILES.get(profile_id)


def profile_for_action(*, capability: str, asset_id: str = "", object_id: str = "") -> VerificationProfile | None:
    """按 capability + 资产解析 profile；未知返回 None（阻止自动）。"""
    if capability == "service.restart" and asset_id == "nerv" and (
        "frps" in (object_id or "") or object_id.endswith("frps")
    ):
        return PROFILES["frps.recover"]
    if capability == "service.stop":
        return PROFILES["svc.stop"]
    # 其余：仅当 capability 有唯一映射且对象不歧义
    pid = CAP_PROFILE.get(capability)
    if pid and capability == "service.stop":
        return PROFILES[pid]
    return None


def assert_supported(profile: VerificationProfile | None) -> None:
    if profile is None:
        raise ValueError("unsupported_verification_profile")
