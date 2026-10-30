"""统一消息入口：QQ / 企业微信共用 Ayana 唤醒词。

路由：
- `@Ayana /help` 等斜杠命令 → 现有业务分发
- `@Ayana -c <host> <cmd...>` → 兼容识别旧语法，由渠道返回退役提示
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

    kind: str  # slash | controlled | nl | empty | unknown | urgent | settings | watch_ping
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
        f"旧受控命令语法: -c {PH_HOST} {PH_CMD}\n"
        "此入口已退役，请通过 MiMoCode 会话操作。"
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


def _readonly_diagnostic_shell(command: str) -> bool:
    """Recognize bounded diagnostic chains, including harmless output redirects.

    This is only the read/write shell classifier. Automatic read-only sessions
    still require the separate single-command ``readonly_command`` grammar.
    Every command in a chain must pass validation; trusting the first executable
    would allow a later command to inherit its read permission.
    """
    if len(command) > 8192 or any(c in command for c in "$`\n\r\0<(){}#\\"):
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens or len(tokens) > 256:
        return False

    def valid_simple(argv: list[str], *, piped_input: bool) -> bool:
        if readonly_command(argv):
            return True
        if not safe_tokens(argv):
            return False
        prog, args = argv[0], argv[1:]
        if prog in {"true", "false"}:
            return not args
        if prog == "which":
            if args[:1] == ["-a"]:
                args = args[1:]
            return bool(args) and all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*", a) for a in args)
        if prog == "nginx":
            return args in (["-v"], ["-V"])
        if prog == "getent":
            # Explicit host/service lookups only; no NSS override modules,
            # credentials databases, enumeration or arbitrary options.
            return (len(args) == 2 and args[0] in {"hosts", "ahosts", "ahostsv4", "ahostsv6", "services"}
                    and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,252}", args[1])))
        if prog == "head" and piped_input:
            # Only bound an existing pipeline's output; do not add file reads.
            count = (args[0][1:] if len(args) == 1 and re.fullmatch(r"-[1-9][0-9]{0,4}", args[0])
                     else args[1] if len(args) == 2 and args[0] == "-n" else "")
            return bool(re.fullmatch(r"[1-9][0-9]{0,4}", count)) and int(count) <= 10000
        return False

    argv: list[str] = []
    piped_input = False
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in {";", "&&", "||", "|"}:
            if not valid_simple(argv, piped_input=piped_input):
                return False
            argv = []
            piped_input = token == "|"
        elif token in {">", ">&"}:
            if i + 1 >= len(tokens):
                return False
            # Only stdout/stderr can be merged or discarded. File output,
            # append, input, arbitrary descriptors and process substitution
            # remain outside this grammar.
            if argv and argv[-1].isdigit():
                if argv[-1] not in {"1", "2"}:
                    return False
                argv.pop()
            target = tokens[i + 1]
            if (token == ">" and target != "/dev/null") or (token == ">&" and target not in {"1", "2"}):
                return False
            i += 1
        elif any(c in token for c in ";&|<>"):
            return False
        else:
            argv.append(token)
        i += 1
    return valid_simple(argv, piped_input=piped_input)


def classify_shell_command(command: str) -> str:
    """对任意 shell 命令行做 read|write|unknown 三态分类。

    - 已验证的诊断命令链（含标准输出/错误合并或丢弃）→ read
    - 含文件写重定向/管道副作用/写动词 → write
    - 明确只读常见命令 → read；未知复合语法不继承首命令权限
    - 其余 → unknown（默认按写处理，禁止经 read 通道偷跑）
    """
    if not isinstance(command, str) or not command.strip():
        return "unknown"
    if _readonly_diagnostic_shell(command):
        return "read"
    # 结构性写特征：重定向到文件、追加、in-place 编辑
    if re.search(r"(?:^|[^>])>>?|sed\s+-i|tee\s+|crontab\s+-", command):
        return "write"
    if _SHELL_WRITE_HINTS.search(command):
        return "write"
    # A failed compound/substitution parse must not fall back to trusting only
    # the first executable. Single-command compatibility continues below.
    if any(c in command for c in ";|&<>$`\n\r\0(){}\\"):
        return "unknown"
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
