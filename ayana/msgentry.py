"""统一消息入口：QQ / 企业微信共用 Ayana 唤醒词。

路由：
- `@Ayana /help` 等斜杠命令 → 现有业务分发
- `@Ayana -c <host> <cmd...>` → 受控命令执行（跳过 Agent，禁止改写）
- `@Ayana 查询 demo-01 状态` → Agent 自然语言理解并调用工具

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

# 关键词唤醒（可独立于 @）：紧急呼叫 / 设置 / 守望探针
# 可选前置 @Ayana；探针可带「紧急呼叫」前缀，便于群内人话触发。
_WATCH_PING_RE = re.compile(
    r"^(?:@?(?:Ayana|ayana|AYANA)\b[\s:：]*)?(?:紧急呼叫[\s:：]*)?"
    r"AYANA-WATCH-PING\s+(\S+)\s*$",
    re.DOTALL | re.IGNORECASE,
)
_URGENT_RE = re.compile(
    r"^(?:@?(?:Ayana|ayana|AYANA)\b[\s:：]*)?紧急呼叫\b[\s:：]*(.*)$",
    re.DOTALL,
)
_SETTINGS_RE = re.compile(
    r"^(?:@?(?:Ayana|ayana|AYANA)\b[\s:：]*)?设置\b[\s:：]*(.*)$",
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

    kind: str  # slash | controlled | nl | approval | empty | unknown | urgent | settings | watch_ping
    text: str = ""
    slash_cmd: str = ""
    slash_args: list[str] = field(default_factory=list)
    host: str = ""
    cmd_tokens: list[str] = field(default_factory=list)
    is_write: bool = False
    nl_text: str = ""
    error: str = ""
    error_hint: str = ""
    request_id: str = ""
    approval_decision: str = ""


def parse_entry(raw: str) -> ParsedEntry:
    """解析统一消息入口，不接触资产库、不做权限判定。"""
    text = (raw or "").strip()
    if not text:
        return ParsedEntry(kind="empty")

    # 守望探针（最高优先，必须整包匹配 request_id）
    m = _WATCH_PING_RE.match(text)
    if m:
        return ParsedEntry(
            kind="watch_ping",
            text=text,
            request_id=m.group(1).strip(),
        )

    # 关键词：紧急呼叫 / 设置（可带 @Ayana 前缀）
    m = _URGENT_RE.match(text)
    if m:
        return ParsedEntry(kind="urgent", text=text, nl_text=m.group(1).strip())
    m = _SETTINGS_RE.match(text)
    if m:
        return ParsedEntry(kind="settings", text=text, nl_text=m.group(1).strip())

    # 去唤醒词（若存在）
    m = WAKE_RE.match(text)
    if m:
        text = m.group(1).strip()
    if not text:
        return ParsedEntry(kind="empty")

    # 授权答复必须整句匹配，不能把引用、否定或讨论文字误当指令。
    from .approval import parse_approval_reply
    decision = parse_approval_reply(text)
    if decision:
        return ParsedEntry(kind="approval", text=text, approval_decision=decision)

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
    # 令牌安全校验（复用 readonly_commands.safe_tokens，禁止 shell 元字符）
    if not safe_tokens(cmd_tokens):
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


# ---- P4.2: shell 行级读写分类（exec_shell 用）----

_SHELL_WRITE_TOKENS = frozenset({
    "rm", "mv", "cp", "install", "chmod", "chown", "chgrp", "truncate", "dd",
    "mkfs", "fdisk", "parted", "mount", "umount", "systemctl", "service",
    "kill", "killall", "pkill", "reboot", "shutdown", "poweroff", "halt",
    "useradd", "userdel", "usermod", "groupadd", "passwd", "visudo",
    "iptables", "nft", "ufw", "sysctl", "modprobe", "insmod", "rmmod",
    "docker", "podman", "crontab", "timedatectl", "hostnamectl",
    "update-alternatives", "alternatives", "swapoff", "swapon",
})

_SHELL_WRITE_VERBS = frozenset({
    "restart", "start", "stop", "reload", "enable", "disable", "mask", "unmask",
    "reset-failed", "kill", "isolate", "daemon-reload", "edit",
    "pull", "push", "rm", "rmi", "run", "create", "update", "start", "stop",
    "restart", "kill", "exec", "cp", "mv", "rename",
})

_SHELL_WRITE_HINTS = re.compile(
    r"(?:^|[\s;|&])(?:rm|mv|cp|install|chmod|chown|dd|mkfs|mount|umount|"
    r"useradd|userdel|usermod|passwd|reboot|shutdown|kill|killall|pkill|"
    r"systemctl\s+(?:restart|start|stop|reload|enable|disable|mask|unmask|reset-failed)|"
    r"service\s+\S+\s+(?:restart|start|stop|reload)|"
    r"docker\s+(?:rm|rmi|run|start|stop|restart|exec|pull|push|create)|"
    r"crontab|iptables|ufw\s+|sysctl\s+-w|tee\s+|>>?|"
    r"echo\s+.*>>?|cat\s+.*>>?|sed\s+-i|perl\s+-pi|python3?\s+-c)",
    re.IGNORECASE,
)


def classify_shell_command(command: str) -> str:
    """对任意 shell 命令行做 read|write|unknown 三态分类。

    - 含重定向/管道副作用/写动词 → write
    - 明确只读常见命令 → read
    - 其余 → unknown（默认按写处理，禁止经 read 通道偷跑）
    """
    if not isinstance(command, str) or not command.strip():
        return "unknown"
    # 结构性写特征：重定向到文件、追加、in-place 编辑
    if re.search(r"(?:^|[^>])>>?|sed\s+-i|tee\s+|crontab\s+-", command):
        return "write"
    if _SHELL_WRITE_HINTS.search(command):
        return "write"
    first = re.split(r"\s+", command.strip(), maxsplit=1)[0]
    # 去掉可能的 sudo/env 前缀
    parts = re.split(r"\s+", command.strip())
    i = 0
    while i < len(parts) and parts[i] in ("sudo", "env", "command", "nice", "ionice", "stdbuf"):
        i += 1
    if i < len(parts):
        prog = parts[i]
        rest = parts[i + 1:]
        if prog in _SHELL_WRITE_VERBS:
            return "write"
        if prog in _SHELL_WRITE_TOKENS and rest:
            verb = rest[0].lower().lstrip("-")
            # systemctl/docker 等：动词是写则 write
            if verb in _SHELL_WRITE_VERBS or prog in ("reboot", "shutdown", "poweroff", "halt", "swapoff", "swapon"):
                return "write"
            if prog in ("rm", "mv", "cp", "chmod", "chown", "dd", "install", "mkfs", "mount", "umount", "kill", "killall", "pkill", "useradd", "userdel", "usermod", "passwd", "crontab"):
                return "write"
        if prog in (
            "uptime", "date", "hostname", "uname", "whoami", "id", "pwd",
            "ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "wc",
            "ps", "top", "df", "du", "free", "ss", "netstat", "ip", "ifconfig",
            "systemctl", "journalctl", "dmesg", "env", "printenv", "which",
            "stat", "file", "lsof", "dig", "ping", "traceroute", "curl", "wget",
            "test", "true", "false", "echo", "printf", "sha256sum", "md5sum",
        ):
            # systemctl 非写动词 → read；其它白名单 → read
            if prog == "systemctl" and rest:
                verb = rest[0].lower()
                if verb in _SHELL_WRITE_VERBS:
                    return "write"
                if verb in ("status", "is-active", "is-enabled", "is-failed", "show", "list-units", "list-timers", "cat", "list-unit-files", "show-property"):
                    return "read"
                return "unknown"
            return "read"
        return "unknown"
    return "unknown"
