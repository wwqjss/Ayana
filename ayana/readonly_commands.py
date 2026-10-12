"""消息受控读取命令的完整参数语法；不在声明范围内的参数一律拒绝。"""

from __future__ import annotations

import re
from typing import Callable
from urllib.parse import urlsplit

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}")
_POSITIVE = re.compile(r"[1-9][0-9]{0,5}")
_UNSIGNED = re.compile(r"[0-9]{1,6}")
_DECIMAL = re.compile(r"[0-9]{1,5}(?:\.[0-9]{1,3})?")


def safe_tokens(tokens: list[str]) -> bool:
    return (isinstance(tokens, list) and 0 < len(tokens) <= 32 and
            all(isinstance(t, str) and 0 < len(t) <= 512 and
                not any(ch in t for ch in " ;|&$`\n\r\t<>()\\") for t in tokens))


def _operand(value: str) -> bool:
    return bool(value) and not value.startswith("-")


def _name(value: str) -> bool:
    return bool(_NAME.fullmatch(value))


def _number(value: str) -> bool:
    return bool(_POSITIVE.fullmatch(value))


def _options(
    args: list[str], *, flags: set[str] = frozenset(), shorts: str = "",
    values: dict[str, Callable[[str], bool]] | None = None,
    operand: Callable[[str], bool] = _operand, minimum: int = 0, maximum: int = 32,
) -> bool:
    """只解析明确列出的选项；不接受长选项缩写或未知参数。"""
    values = values or {}
    count = 0
    i = 0
    while i < len(args):
        arg = args[i]
        key, sep, attached = arg.partition("=") if arg.startswith("--") else (arg, "", "")
        if arg in flags:
            pass
        elif key in values:
            if not sep:
                i += 1
                if i >= len(args):
                    return False
                attached = args[i]
            if not values[key](attached):
                return False
        elif (not arg.startswith("--") and len(arg) > 2 and arg[:2] in values):
            if not values[arg[:2]](arg[2:]):
                return False
        elif arg.startswith("-"):
            if arg.startswith("--") or len(arg) < 2 or not set(arg[1:]) <= set(shorts):
                return False
        else:
            if not operand(arg):
                return False
            count += 1
        i += 1
    return minimum <= count <= maximum


def _http_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return bool(parsed.scheme in {"http", "https"} and parsed.hostname and
                    not parsed.username and not parsed.password and
                    (parsed.port is None or 1 <= parsed.port <= 65535))
    except ValueError:
        return False


def readonly_command(tokens: list[str]) -> bool:
    if not safe_tokens(tokens):
        return False
    prog, args = tokens[0], tokens[1:]
    if prog in {"whoami", "uptime", "hostname"}:
        return not args or args == ["--help"] or args == ["--version"]
    if prog == "uname":
        return _options(args, shorts="asnrvmpio", flags={"--all", "--kernel-name", "--nodename", "--kernel-release", "--kernel-version", "--machine", "--processor", "--hardware-platform", "--operating-system", "--help", "--version"}, maximum=0)
    if prog == "id":
        return _options(args, shorts="ugGnrz", flags={"--user", "--group", "--groups", "--name", "--real", "--zero", "--help", "--version"}, operand=_name, maximum=1)
    if prog == "date":
        return _options(args, shorts="uR", flags={"--utc", "--universal", "--rfc-email", "--help", "--version", "--iso-8601"}, values={"--iso-8601": lambda v: v in {"date", "hours", "minutes", "seconds", "ns"}}, operand=lambda v: bool(re.fullmatch(r"\+[A-Za-z0-9%_:/.+-]+", v)), maximum=1)
    if prog == "free":
        return _options(args, shorts="bkmghwlt", flags={"--bytes", "--kibi", "--mebi", "--gibi", "--human", "--wide", "--lohi", "--total", "--help", "--version"}, maximum=0)
    if prog == "df":
        return _options(args, shorts="ahHiklPT", flags={"--all", "--human-readable", "--si", "--inodes", "--local", "--portability", "--print-type", "--help", "--version"}, values={"-B": lambda v: bool(re.fullmatch(r"[1-9][0-9]*[KMGTPEZY]?", v)), "--block-size": lambda v: bool(re.fullmatch(r"[1-9][0-9]*[KMGTPEZY]?", v)), "-t": _name, "--type": _name, "-x": _name, "--exclude-type": _name})
    if prog == "ls":
        return _options(args, shorts="aAbBcCdDfFghHiklLmnpqQrRsStuUvwx1", flags={"--all", "--almost-all", "--human-readable", "--numeric-uid-gid", "--recursive", "--directory", "--help", "--version"}, values={"--color": lambda v: v in {"always", "auto", "never"}, "--sort": lambda v: v in {"none", "size", "time", "version", "extension"}})
    # P1-02: 禁止 cat/head/tail/grep 任意文件读取
    if prog == "ps":
        return _options(args, shorts="aeflwx", flags={"--help", "--version"}, values={"-p": lambda v: bool(re.fullmatch(r"[0-9]+(?:,[0-9]+)*", v)), "-o": lambda v: bool(re.fullmatch(r"[A-Za-z0-9_,=:%.-]+", v))}, operand=lambda v: v in {"aux", "ax", "u", "a", "x"})
    if prog == "top":
        return _options(args, shorts="bHi", values={"-n": _number, "-d": lambda v: bool(_DECIMAL.fullmatch(v)), "-p": lambda v: bool(re.fullmatch(r"[0-9]+(?:,[0-9]+)*", v))}, maximum=0) and any(a == "-b" or a.startswith("-b") for a in args)
    if prog in {"ss", "netstat"}:
        return _options(args, shorts=("hVnraloemipsbEZztudwx46" if prog == "ss" else "aenloprtuwx46"), flags={"--help", "--version", "--numeric", "--all", "--listening", "--tcp", "--udp", "--unix", "--processes", "--summary", "--no-header"}, maximum=0)
    if prog == "journalctl":
        return _options(args, shorts="xebrk", flags={"--no-pager", "--quiet", "--utc", "--reverse", "--system", "--user", "--disk-usage", "--list-boots", "--help", "--version"}, values={"-u": _name, "--unit": _name, "-n": _number, "--lines": _number, "-p": lambda v: bool(re.fullmatch(r"[0-7]|emerg|alert|crit|err|warning|notice|info|debug", v)), "--priority": lambda v: bool(re.fullmatch(r"[0-7]|emerg|alert|crit|err|warning|notice|info|debug", v)), "-o": lambda v: v in {"short", "short-iso", "short-unix", "cat", "json", "json-pretty", "verbose"}, "--output": lambda v: v in {"short", "short-iso", "short-unix", "cat", "json", "json-pretty", "verbose"}}, operand=lambda v: bool(re.fullmatch(r"[A-Z_][A-Z_0-9]*=[A-Za-z0-9_.:@/-]+", v)))
    if prog == "curl":
        if args in [["--help"], ["--version"], ["-h"], ["-V"]]:
            return True
        # 必须禁用远端 .curlrc，否则其中的写入参数能绕过 argv 的只读语法。
        return bool(args and args[0] in {"-q", "--disable"} and _options(args, shorts="qfsSIkiv46", flags={"--disable", "--fail", "--fail-with-body", "--silent", "--show-error", "--head", "--include", "--verbose", "--no-progress-meter", "--insecure"}, values={"-X": lambda v: v in {"GET", "HEAD"}, "--request": lambda v: v in {"GET", "HEAD"}, "-m": lambda v: bool(_DECIMAL.fullmatch(v)) and float(v) > 0, "--max-time": lambda v: bool(_DECIMAL.fullmatch(v)) and float(v) > 0, "--connect-timeout": lambda v: bool(_DECIMAL.fullmatch(v)) and float(v) > 0}, operand=_http_url, minimum=1, maximum=1))
    if prog == "ping":
        return _options(args, shorts="nqv46", values={"-c": _number, "-W": _number, "-w": _number}, operand=lambda v: bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", v)), minimum=1, maximum=1)
    if prog == "systemctl" and args:
        verb, rest = args[0], args[1:]
        if verb in {"status", "is-active", "is-enabled", "is-failed", "show"}:
            return _options(rest, shorts="lq", flags={"--no-pager", "--full", "--quiet", "--all", "--value"}, values={"-p": _name, "--property": _name}, operand=_name, minimum=1)
        if verb in {"list-units", "list-unit-files", "list-jobs", "list-timers", "list-sockets"}:
            return _options(rest, flags={"--no-pager", "--no-legend", "--all", "--failed", "--plain"}, values={"--type": lambda v: v in {"service", "socket", "target", "timer", "mount", "path"}}, operand=_name)
    if prog == "service":
        return len(args) == 2 and _name(args[0]) and args[1] == "status"
    if prog in {"docker", "podman"} and args:
        verb, rest = args[0], args[1:]
        if verb in {"ps", "images"}:
            return _options(rest, shorts="aqs", flags={"--all", "--quiet", "--size", "--no-trunc"}, maximum=0)
        if verb in {"version", "info"}:
            return not rest
        # P1-02: 禁止 inspect（可能含环境变量/密钥）
        if verb == "port":
            return _options(rest, operand=_name, minimum=1)
        if verb == "logs":
            return _options(rest, shorts="t", flags={"--timestamps", "--details"}, values={"--tail": _number, "--since": _name, "--until": _name}, operand=_name, minimum=1, maximum=1)
        if verb == "stats":
            return "--no-stream" in rest and _options(rest, flags={"--no-stream", "--no-trunc", "--all"}, operand=_name)
    return False
