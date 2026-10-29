"""兼容再导出：结构化动作执行层已退役。

最终决议删除 ActionService、能力目录、逐动作审批与独立验证器。
原始执行事实与审计助手在 `ayana.exec_facts`；写入口为 MCP `host.exec`。
本模块仅保留旧导入路径兼容，不包含任何执行能力。
"""
from __future__ import annotations

from .exec_facts import (
    AUTO_RETRYABLE_BLOCKS,
    UNKNOWN_HINTS,
    WRITE_NO_REPLAY_STATES,
    ActionError,
    action_generation_block,
    action_incident_block,
    announce_irreversible,
    classify_exec_result,
    legacy_action_block,
    looks_irreversible,
    write_may_dispatch,
)

__all__ = [
    "ActionError",
    "UNKNOWN_HINTS",
    "WRITE_NO_REPLAY_STATES",
    "AUTO_RETRYABLE_BLOCKS",
    "write_may_dispatch",
    "legacy_action_block",
    "action_incident_block",
    "action_generation_block",
    "looks_irreversible",
    "announce_irreversible",
    "classify_exec_result",
]
