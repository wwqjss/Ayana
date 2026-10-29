"""执行事实与结果分类：host.exec / 历史动作校验共用，不依赖 ActionService。

最终决议：删除独立动作执行层后，原始执行事实（含 unknown）与审计仍由此模块
提供纯函数；不再有提案、审批、能力目录或自动重试决策。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


class NTError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass
class NTResult:
    ok: bool
    output: str
    returncode: int = -1
    timed_out: bool = False
    mode: str = ""
    account: str = ""
    account_group: str = ""

    def clipped(self, limit: int = 4000) -> str:
        t = self.output or ""
        return t if len(t) <= limit else t[:limit] + "\n…[truncated]"


class ActionError(Exception):
    def __init__(self, code: str, message: str = "", *, context: dict | None = None):
        self.code = code
        self.detail = message
        self.context = context or {}
        super().__init__(f"{code}: {message}" if message else code)


UNKNOWN_HINTS = (
    "timeout",
    "connection reset",
    "connection refused",
    "broken pipe",
    "connection closed",
    "no route to host",
    "network is unreachable",
    "connection aborted",
    "killed",
)

# 结果不明的写操作不得自动重放；unknown/dispatched/已终止一律禁止再次派发
WRITE_NO_REPLAY_STATES = frozenset(
    {"unknown", "dispatched", "success", "failure", "cancelled", "expired", "rejected"}
)

AUTO_RETRYABLE_BLOCKS = frozenset({
    "cooldown", "budget_exhausted", "global_pause", "object_locked", "source_unavailable",
})
TEMPORARY_SESSION_BLOCKS = frozenset({"session_paused", "work_already_running"})


def write_may_dispatch(state: str) -> bool:
    """仅 approved 可进入派发；其余（含 unknown）一律不可。"""
    return state == "approved"


def legacy_action_block(action: Any) -> tuple[str, str] | None:
    """持久化的旧自治授权不得变成人工写。autonomous 是 MiMoCode 闭环路径。"""
    row = dict(action)
    mode = str(row.get("mode") or "manual").strip().lower()
    if (mode in ("auto", "reviewed") or row.get("council_grant_id")
            or row.get("council_step", -1) not in (-1, None)
            or str(row.get("decision_channel") or "").strip().lower() == "council"):
        return "legacy_autonomy_retired", "Legacy autonomous authorization is permanently retired"
    if mode not in ("manual", "autonomous"):
        return "bad_mode", "Only manual or autonomous actions may execute"
    return None


def action_incident_block(store: Any, action: Any) -> tuple[str, str] | None:
    """历史动作关联的 Incident 仍须校验代次与对象未漂移。"""
    row = dict(action)
    incident_id = row.get("incident_id") or ""
    if not incident_id:
        return None
    incident = store.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not incident:
        return ("incident_not_found", "关联事件不存在")
    if incident["status"] != "open":
        return ("incident_not_open", "关联事件已恢复或关闭")
    if incident["asset_id"] and incident["asset_id"] != row["asset_id"]:
        return ("incident_mismatch", "关联事件的资产已改变")
    obj = store.execute(
        "SELECT id,name FROM objects WHERE asset_id=? AND (id=? OR name=?)",
        (row["asset_id"], row["object_id"], row["object_id"]),
    ).fetchone()
    expected = (incident["object_id"] or "").strip()
    if expected and obj and expected not in (obj["id"], obj["name"]):
        return ("incident_mismatch", "关联事件的对象已改变")
    return action_generation_block(store, row)


def action_generation_block(store: Any, action: Any) -> tuple[str, str] | None:
    """用持久化事件序号判定代次，避免 Windows 同秒时间戳歧义。"""
    row = dict(action)
    incident_id = row.get("incident_id") or ""
    if not incident_id:
        return None
    generation = store.execute(
        "SELECT id,at FROM events WHERE incident_id=? AND type IN"
        " ('generation_bumped','incident_reopened','incident_opened') ORDER BY id DESC LIMIT 1",
        (incident_id,),
    ).fetchone()
    if generation:
        proposed = store.execute(
            "SELECT id FROM events WHERE incident_id=? AND type='action_proposed'"
            " AND json_valid(payload_json) AND json_extract(payload_json,'$.action_id')=?"
            " ORDER BY id DESC LIMIT 1", (incident_id, row["id"]),
        ).fetchone()
        stale = (int(proposed["id"]) < int(generation["id"])) if proposed else (
            float(row["created_at"]) < float(generation["at"])
        )
        if stale:
            return ("stale_generation", "此操作属于上次故障，请处理当前故障的操作")
    return None


IRREVERSIBLE_TOKENS = frozenset({
    "rm", "rmdir", "mkfs", "mke2fs", "mkswap", "dd", "wipefs", "shred", "truncate",
    "parted", "shutdown", "reboot", "halt", "poweroff", "drop", "del",
})


def looks_irreversible(command_or_tokens: Any) -> bool:
    """不可逆操作提示（仅用于提前通知，绝不作为审批或安全保证）。"""
    import re

    if isinstance(command_or_tokens, (list, tuple)):
        text = " ".join(str(x) for x in command_or_tokens)
    else:
        text = str(command_or_tokens or "")
    tokens = re.split(r"[^A-Za-z0-9_./-]+", text.lower())
    return any(tok in IRREVERSIBLE_TOKENS for tok in tokens)


def announce_irreversible(db: Any, notifier: Any, *, asset_id: str, command: Any,
                          action_id: str = "", incident_id: str = "") -> None:
    """尽可能提前通知：时间线落事件，通知器可用时推送；失败不影响执行。"""
    detail = (command if isinstance(command, str) else " ".join(str(x) for x in command or []))[:300]
    try:
        db.event(
            "irreversible_write_notice",
            f"即将执行不可逆操作 @ {asset_id}",
            incident_id=incident_id or "",
            payload={"asset_id": asset_id, "command": detail, "action_id": action_id,
                     "note": "提前通知非审批，不阻断执行"},
        )
    except Exception:  # noqa: BLE001
        pass
    if notifier is not None:
        try:
            notifier.on_event({
                "type": "irreversible_write_notice",
                "incident_id": incident_id or "",
                "title": f"即将执行不可逆操作 @ {asset_id}",
                "payload_json": json.dumps(
                    {"asset_id": asset_id, "command": detail, "action_id": action_id,
                     "note": "提前通知非审批，不阻断执行"},
                    ensure_ascii=False,
                ),
            })
        except Exception:  # noqa: BLE001
            pass


def classify_exec_result(res) -> tuple[str, str]:
    """原始执行结果 → success|failure|unknown。结果不明必须记 unknown。"""
    detail = (res.output or "")[:2000]
    if getattr(res, "timed_out", False):
        return "unknown", "timeout"
    rc = getattr(res, "returncode", -1)
    low = detail.lower()
    # 负退出码 = 本地被信号终止，不能证明远端未执行
    if rc is not None and rc < 0:
        return "unknown", detail or f"returncode={rc}"
    if rc == 255:
        return "unknown", detail or f"returncode={rc}"
    # A successful SSH exit is an observed result. Diagnostic stdout can
    # legitimately quote old transport errors, timeouts or killed workers.
    if rc == 0 and getattr(res, "ok", False):
        return "success", detail
    if any(h in low for h in UNKNOWN_HINTS):
        return "unknown", detail or f"returncode={rc}"
    if getattr(res, "ok", False):
        return "success", detail
    if "denied" in low or "not-allowlisted" in low or "blocked" in low or "rejected" in low:
        return "failure", detail
    if rc is not None and rc != 0:
        return "failure", detail
    return "unknown", detail or f"returncode={rc}"
