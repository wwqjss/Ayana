"""统一消息入口：QQ / 企业微信共用 Ayana 唤醒词。

路由：
- `@Ayana /help` 等斜杠命令 → 现有业务分发
- `@Ayana -c <host> <cmd...>` → 受控命令执行（跳过 Agent，禁止改写）
- `@Ayana 查询 NERV 状态` → Agent 自然语言理解并调用工具

错误引导：
- 缺目标 / 参数错 / 语法错 → 生成通用使用提示，不执行
- 目标不存在与无权限统一「目标不可用或无访问权限」，防资产枚举
- 不列真实资产名、别名、数量、内部配置
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from .readonly_commands import readonly_command, safe_tokens

log = logging.getLogger("ayana.msgentry")

# 唤醒词：@Ayana / @ayana / Ayana（行首或 @ 后）
WAKE_RE = re.compile(
    r"^(?:@?(?:Ayana|ayana|AYANA)\b[\s:：]*)(.*)$",
    re.DOTALL,
)

# 通用占位符（不得替换为真实资产名）
PH_HOST = "<host>"
PH_CMD = "<command>"
PH_METRIC = "<metric>"

# 写动词（静态判定，不依赖 Agent）
_WRITE_VERBS = frozenset(
    {
        "start",
        "stop",
        "restart",
        "reload",
        "enable",
        "disable",
        "kill",
        "mask",
        "unmask",
        "reset-failed",
        "rm",
        "rmi",
        "kill",
    }
)
_WRITE_PROGRAMS = frozenset({"systemctl", "docker", "podman", "service"})

# 只读动词（明确排除写）
_READ_VERBS = frozenset(
    {
        "status",
        "is-active",
        "is-enabled",
        "is-failed",
        "show",
        "list",
        "ls",
        "ps",
        "top",
        "inspect",
        "logs",
        "stats",
        "df",
        "free",
        "uptime",
        "ss",
        "netstat",
        "journalctl",
        "version",
        "info",
        "port",
        "ping",
    }
)

# 只读程序（精确白名单，S07: 未知程序默认拒绝）
# P1-02: 移除 cat/head/tail/grep 任意文件读取与 docker inspect（环境变量泄露）
_READ_PROGRAMS = frozenset(
    {
        "systemctl",
        "docker",
        "podman",
        "service",
        "hostname",
        "uname",
        "whoami",
        "id",
        "date",
        "uptime",
        "free",
        "df",
        "ls",
        "ps",
        "ss",
        "netstat",
        "journalctl",
        "curl",
        "ping",
    }
)


@dataclass
class ParsedEntry:
    """解析结果。"""

    kind: str  # slash | controlled | nl | empty | unknown
    text: str = ""
    slash_cmd: str = ""
    slash_args: list[str] = field(default_factory=list)
    host: str = ""
    cmd_tokens: list[str] = field(default_factory=list)
    is_write: bool = False
    nl_text: str = ""
    error: str = ""
    error_hint: str = ""


def parse_entry(raw: str) -> ParsedEntry:
    """解析统一消息入口，不接触资产库、不做权限判定。"""
    text = (raw or "").strip()
    if not text:
        return ParsedEntry(kind="empty")

    # 去唤醒词（若存在）
    m = WAKE_RE.match(text)
    if m:
        text = m.group(1).strip()
    if not text:
        return ParsedEntry(kind="empty")

    # 斜杠命令
    if text.startswith("/"):
        parts = text.split()
        return ParsedEntry(
            kind="slash",
            text=text,
            slash_cmd=parts[0].lower(),
            slash_args=parts[1:],
        )

    # 受控命令：-c <host> <cmd...>
    if text.startswith("-c ") or text == "-c":
        return _parse_controlled(text)

    # 自然语言
    return ParsedEntry(kind="nl", text=text, nl_text=text)


def _parse_controlled(text: str) -> ParsedEntry:
    """解析 `-c <host> <cmd...>`。语法错 → 结构化错误，不执行。"""
    try:
        tokens = shlex.split(text)
    except ValueError:
        return ParsedEntry(
            kind="unknown",
            error="syntax_error",
            error_hint=(
                f"用法: -c {PH_HOST} {PH_CMD}\n"
                f"示例: -c {PH_HOST} systemctl status {PH_CMD}"
            ),
        )
    # tokens[0] == "-c"
    if len(tokens) < 3:
        return ParsedEntry(
            kind="unknown",
            error="missing_args",
            error_hint=(
                f"缺少目标或命令。\n"
                f"用法: -c {PH_HOST} {PH_CMD}\n"
                f"示例: -c {PH_HOST} systemctl status {PH_CMD}"
            ),
        )
    host = tokens[1]
    cmd_tokens = tokens[2:]
    if not host or not cmd_tokens:
        return ParsedEntry(
            kind="unknown",
            error="missing_args",
            error_hint=f"用法: -c {PH_HOST} {PH_CMD}",
        )
    # 令牌安全校验（禁止 shell 元字符）
    for t in cmd_tokens:
        if any(ch in t for ch in " ;|&$`\n\t<>()"):
            return ParsedEntry(
                kind="unknown",
                error="unsafe_token",
                error_hint=f"命令包含非法字符。\n用法: -c {PH_HOST} {PH_CMD}",
            )
    is_write = classify_write(cmd_tokens)
    return ParsedEntry(
        kind="controlled",
        text=text,
        host=host,
        cmd_tokens=cmd_tokens,
        is_write=is_write,
    )


def classify_write(tokens: list[str]) -> bool:
    """静态判定只读/写入。仅用于兼容旧接口；未知命令请用 classify_command。"""
    return classify_command(tokens) == "write"


def classify_command(tokens: list[str]) -> str:
    """S07: 三态分类 read | write | unknown。未知命令默认拒绝，不再当只读。

    只接受可精确映射到目录能力的语法，不扩展"任意命令只读判断"。
    """
    if not tokens:
        return "unknown"
    if not safe_tokens(tokens):
        return "unknown"
    prog = tokens[0]

    # 写程序 + 写动词 → write
    if prog in _WRITE_PROGRAMS and len(tokens) >= 2:
        verb = tokens[1].lower()
        if verb in _WRITE_VERBS:
            return "write"

    # 裸写动词（如 kill）→ write
    if prog in _WRITE_VERBS:
        return "write"

    # 完整程序 + 参数语法白名单；未知参数不得继承程序名的读取权限。
    if readonly_command(tokens):
        return "read"

    # 未知程序 → 拒绝（S07 核心修复）
    return "unknown"


# ---------------------------------------------------------------------------
# 错误引导（资产保护）
# ---------------------------------------------------------------------------

# 目标不可用与无权限统一文案（防资产枚举）
ERR_TARGET_UNAVAILABLE = "目标不可用或无访问权限"

GENERIC_HINTS = {
    "syntax_error": f"命令语法错误。\n用法: -c {PH_HOST} {PH_CMD}",
    "missing_args": f"缺少目标或命令。\n用法: -c {PH_HOST} {PH_CMD}",
    "unsafe_token": f"命令包含非法字符。\n用法: -c {PH_HOST} {PH_CMD}",
    "denied": ERR_TARGET_UNAVAILABLE,
    "not_found": ERR_TARGET_UNAVAILABLE,
    "bad_host": ERR_TARGET_UNAVAILABLE,
}


def error_reply(code: str, hint: str = "") -> str:
    """生成不泄露资产信息的错误回复。"""
    base = GENERIC_HINTS.get(code, "处理失败")
    if hint:
        # hint 只允许通用占位符，不得含真实资产名
        return f"{base}\n{hint}"
    return base


def usage_hint_for_controlled() -> str:
    """受控命令通用用法（占位符）。"""
    return (
        f"受控命令用法: -c {PH_HOST} {PH_CMD}\n"
        f"读示例: -c {PH_HOST} systemctl status {PH_CMD}\n"
        f"写示例: -c {PH_HOST} systemctl restart {PH_CMD}\n"
        f"写操作需审批。"
    )
