"""Read-only native tool facts for the workbench; never copy model reasoning."""
from __future__ import annotations

import asyncio
import json
import math
import re
from typing import Any


_ERRORS = {
    "unknown_field": "参数字段不符合当前工具要求。",
    "required": "缺少必填参数。",
    "bad_request": "工具参数不完整或格式不正确。",
    "bad_fields": "检查参数格式不正确。",
    "unsafe_command": "命令不符合检查白名单或参数规则。",
    "unsafe_command_option": "命令参数不符合只读探测规则。",
    "argv_program_not_allowed": "该程序不在原生检查白名单中。",
    "check_validation_failed": "检查配置未通过校验。",
    "bad_argv": "命令必须使用受支持的参数数组。",
    "bad_argv_token": "命令含不受支持的参数或格式。",
    "bad_expect": "检查期望不符合支持的格式。",
    "unsupported_expect": "原生命令检查仅支持退出码期望。",
    "unknown_asset": "目标主机不存在、已停用或不可用。",
    "readonly_mode_rejects_write": "当前会话只读，工具拒绝变更。",
    "write_not_allowed_on_read_channel": "命令未通过只读通道校验。",
    "endpoint_missing": "缺少当前账号组的目标连接。",
    "work_already_running": "目标已有任务执行中，未重复派发。",
    "idempotent_block": "已有执行记录，未重复派发；请核对原结果。",
    "incident_not_open": "指定工单已关闭。",
    "session_paused": "会话已暂停。",
    "execution_unknown": "执行结果待核对，请勿重复派发。",
}


def _text(value: Any, limit: int = 120) -> str:
    return value[:limit] if isinstance(value, str) and not any(ord(c) < 32 for c in value) else ""


def _clock(value: Any) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        return 0
    return value / 1000 if value > 100_000_000_000 else max(0, value)


def _object(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _tool_identity(tool: str, inputs: dict) -> tuple[str, dict]:
    if tool != "mcp_tool_use":
        return tool, inputs
    # MiMo's native wrapper contains the actual Ayana tool and its arguments.
    # Only this verified shape and the current registered tool names qualify;
    # never recursively search arbitrary arguments, command text or outputs.
    from .mcp_tools import TOOL_SPECS
    allowed = {"ayana_" + spec["name"].replace(".", "_") for spec in TOOL_SPECS}
    name = inputs.get("name")
    if not isinstance(name, str) or name not in allowed:
        return "", {}
    return name, _object(inputs.get("arguments"))


def _error_code(value: Any) -> str:
    """Read structured MCP errors without forwarding arbitrary output or secrets."""
    if isinstance(value, str):
        if value in _ERRORS:
            return value
        if len(value) > 16000:
            return ""
        try:
            return _error_code(json.loads(value))
        except (ValueError, TypeError):
            return ""
    if not isinstance(value, dict):
        return ""
    if _optional_source(value):
        return ""
    code = value.get("error") or value.get("code")
    if isinstance(code, dict):
        return _error_code(code)
    if isinstance(code, str) and code:
        return code if code in _ERRORS else "tool_error"
    for block in (value.get("content") or [])[:3] if isinstance(value.get("content"), list) else []:
        if isinstance(block, dict) and block.get("type") == "text":
            code = _error_code(block.get("text"))
            if code:
                return code
    return "tool_error" if value.get("isError") is True else ""


def _optional_source(value: Any) -> bool:
    if isinstance(value, str) and len(value) <= 16000:
        try:
            return _optional_source(json.loads(value))
        except (ValueError, TypeError):
            return False
    if not isinstance(value, dict):
        return False
    if value.get("isError") is True:
        return False
    if (value.get("source") == "prometheus" and value.get("error") == "prometheus_unavailable"
            and value.get("optional") is True and value.get("fatal") is False and value.get("available") is False):
        return True
    content = value.get("content")
    return (isinstance(content, list) and len(content) == 1 and isinstance(content[0], dict)
            and content[0].get("type") == "text" and _optional_source(content[0].get("text")))


def project_native_activity(messages: Any, *, parent_id: str = "", remote_id: str = "", exclude_message_ids: Any = None) -> dict:
    if not isinstance(messages, list):
        return {"available": False, "tools": [], "message": "原生步骤暂不可读。"}
    rows = [m for m in messages if isinstance(m, dict) and isinstance(m.get("info"), dict)]
    excluded = {identity for identity in exclude_message_ids if isinstance(identity, str)} if isinstance(exclude_message_ids, list) else set()
    users = [m for m in rows if m["info"].get("role") == "user" and isinstance(m["info"].get("id"), str) and m["info"]["id"]]
    latest = max(users, key=lambda m: (_clock(_object(m["info"].get("time")).get("created")), m["info"]["id"])) if users else None
    if parent_id and latest and latest["info"]["id"] != parent_id:
        expected = next((m for m in users if m["info"]["id"] == parent_id), None)
        if expected is None or _clock(_object(latest["info"].get("time")).get("created")) > _clock(_object(expected["info"].get("time")).get("created")):
            return {"available": False, "tools": [], "message": "当前回合已变化，等待步骤记录同步。"}
    if not parent_id:
        if not users:
            return {"available": not rows, "tools": [], "message": "尚未确认当前回合的步骤。"}
        parent_id = str(latest["info"].get("id") or "")
    tools = []
    for message in rows:
        info = message["info"]
        if info.get("role") != "assistant" or info.get("parentID") != parent_id:
            continue
        if isinstance(info.get("id"), str) and info["id"] in excluded:
            continue
        if remote_id and info.get("sessionID") and info["sessionID"] != remote_id:
            continue
        for part in message.get("parts") if isinstance(message.get("parts"), list) else []:
            if not isinstance(part, dict) or part.get("type") != "tool":
                continue
            tool = _text(part.get("tool"), 100)
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", tool):
                continue
            state = part.get("state") if isinstance(part.get("state"), dict) else {}
            status = state.get("status")
            if not isinstance(status, str) or status not in {"pending", "running", "completed", "error"}:
                continue
            inputs = state.get("input") if isinstance(state.get("input"), dict) else {}
            tool, inputs = _tool_identity(tool, inputs)
            if not tool:
                continue
            clock = state.get("time") if isinstance(state.get("time"), dict) else {}
            code = _error_code(state.get("error")) or _error_code(state.get("output"))
            if code:
                status = "error"
            item = {
                "id": _text(part.get("id")), "tool": tool, "status": status,
                "target": _text(inputs.get("asset_id")),
                "channel": inputs.get("channel") if inputs.get("channel") in ("read", "write") else "",
                "at": _clock(clock.get("end")) or _clock(clock.get("start")) or _clock(_object(info.get("time")).get("created")),
            }
            if status == "error":
                item["error"] = {"code": code or "tool_error", "message": _ERRORS.get(code, "工具返回错误，详情请查看原生记录。")}
            elif _optional_source(state.get("output")):
                item["notice"] = "Prometheus 暂不可用，可继续使用原生业务检查。"
            tools.append(item)
    tools.sort(key=lambda item: (item["at"], item["id"]))
    return {
        "available": True, "tools": tools[-8:],
        "current": next((item for item in reversed(tools) if item["status"] in {"pending", "running"}), None),
        "latest_error": next((item for item in reversed(tools) if item["status"] == "error"), None),
    }


async def read_native_activity(client: Any, remote_id: str, *, parent_id: str = "", exclude_message_ids: Any = None, timeout: float = .8) -> dict:
    try:
        messages = await asyncio.wait_for(client.messages(remote_id, limit=20), timeout=timeout)
        return project_native_activity(messages, parent_id=parent_id, remote_id=remote_id, exclude_message_ids=exclude_message_ids)
    except Exception:
        return {"available": False, "tools": [], "message": "原生步骤暂不可读；任务状态仍以执行记录为准。"}
