"""业务检查（轻量默认）：端口 / 服务 / 自定义命令。

不依赖 Prometheus。经受控 SSH 在目标主机执行固定形态命令，
连续失败达阈值 → 事件/通知（复用现有 Incident 链路）。

安全：
- 参数只生成固定 argv，禁止 shell 元字符
- 自定义命令仅 admin 创建，token 严格校验
- 不扩大主机权限
"""

from __future__ import annotations

import asyncio
import json
import posixpath
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

from .db import Database, new_id, now
from .formspec import UNIT_PATTERN

MAX_ARGV_TOKENS = 8
_TOKEN_BAD = re.compile(r"[ \t\n\r;|&$`\\'\"<>(){}\[\]*?~!#%^=+]")
# B1: 自定义命令仅允许无文件输入、无任意外发的探测程序
_CMD_ALLOW = {
    "curl",
    "wget",
    "ps",
    "ss",
    "echo",
    "true",
    "false",
    "nc",
    "ping",
}
_UNIT_RE = re.compile(UNIT_PATTERN)
_STANDARD_PROGRAM_DIRS = {"/bin", "/usr/bin", "/sbin", "/usr/sbin"}
_PROBE_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
_COMMAND_BOUNDARY = {
    "program_paths": "程序只能使用白名单名称，或 /bin、/usr/bin、/sbin、/usr/sbin 下的绝对路径。",
    "curl": "必须以 -q/--disable 开头，只支持 GET/HEAD 与 http(s) URL。",
    "wget": "必须使用 --spider 或 -O -，只支持 http(s) URL。",
    "nc": "只支持 -z 端口探测。",
    "ss": "只支持查询监听/连接状态；禁止写诊断文件（-F/--filter 等）。",
    "tokens": "最多 8 个参数，每个最多 120 字符；不允许 shell 表达式、重定向、管道、文件路径参数。",
    "url": "curl/wget 仅允许 http(s) 探测 URL，禁止 file/gopher 等协议。",
    "expect": "command 类检查仅允许 exit_code 期望，不得用输出内容做包含匹配。",
}
COMMAND_BOUNDARY = _COMMAND_BOUNDARY


class CheckError(Exception):
    def __init__(self, code: str, detail: str = "", *, issues: list[dict] | None = None):
        self.code = code
        self.detail = detail
        self.issues = issues or []
        super().__init__(f"{code}: {detail}" if detail else code)


def validate_unit(name: str) -> str:
    if not isinstance(name, str):
        raise CheckError("bad_unit", "请填写目标主机的实际服务名。")
    name = (name or "").strip()
    if not _UNIT_RE.fullmatch(name):
        raise CheckError("bad_unit", name)
    return name


def validate_port(port: Any) -> int:
    if isinstance(port, bool) or not (
        isinstance(port, int) or isinstance(port, str) and re.fullmatch(r"[+-]?\d{1,10}", port.strip())
    ):
        raise CheckError("bad_port", "端口必须是 1 到 65535 之间的整数。")
    try:
        p = int(port)
    except (TypeError, ValueError) as e:
        raise CheckError("bad_port", str(port)) from e
    if not (1 <= p <= 65535):
        raise CheckError("bad_port", str(p))
    return p


def validate_argv(argv: Any) -> list[str]:
    if not isinstance(argv, list) or not argv or len(argv) > MAX_ARGV_TOKENS:
        raise CheckError("bad_argv", "need 1..8 tokens")
    out = []
    for idx, t in enumerate(argv):
        if not isinstance(t, str) or not t or len(t) > 120:
            raise CheckError("bad_argv_token", str(t)[:40])
        if _TOKEN_BAD.search(t):
            raise CheckError("bad_argv_token", t[:40])
        # B1: 参数禁止文件路径形态（程序名本身可为标准目录绝对路径）
        if idx > 0 and (t.startswith("/") or t.startswith("./") or t.startswith("../") or t.startswith("~")):
            raise CheckError("bad_argv_token", "path_like")
        out.append(t)
    executable = out[0]
    if "/" in executable:
        if not executable.startswith("/") or posixpath.normpath(executable) != executable or posixpath.dirname(executable) not in _STANDARD_PROGRAM_DIRS:
            raise CheckError("argv_program_not_allowed", "请使用系统标准目录中的只读探测程序。")
    prog = executable.rsplit("/", 1)[-1]
    if prog not in _CMD_ALLOW:
        raise CheckError("argv_program_not_allowed", prog)
    _validate_probe_argv(prog, out[1:])
    return out


def _is_http_url(value: str) -> bool:
    if not _PROBE_URL_RE.match(value or ""):
        return False
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(value)
    except ValueError:
        return False
    return (
        parts.scheme.lower() in ("http", "https")
        and bool(parts.hostname)
        and not parts.username
        and not parts.password
    )


def _validate_probe_argv(prog: str, args: list[str]) -> None:
    """B1: 每个程序的参数语法白名单；禁止文件输入与未授权外发。"""
    if prog in {"true", "false"}:
        if args:
            raise CheckError("unsafe_command_option", "该程序不接受参数。")
        return
    if prog == "echo":
        # 仅允许无选项的短字面量，禁止指向文件/URL
        for a in args:
            if a.startswith("-") or "://" in a or a.startswith("/"):
                raise CheckError("unsafe_command_option", "echo 仅允许简单字面量。")
        return
    if prog == "ping":
        # ping [-c N] [-W N] hostname
        i = 0
        host = ""
        while i < len(args):
            a = args[i]
            if a in {"-c", "-W", "-w"}:
                i += 1
                if i >= len(args) or not re.fullmatch(r"\d{1,5}", args[i]) or int(args[i]) <= 0:
                    raise CheckError("unsafe_command_option", "ping 次数/超时必须为正整数。")
            elif a.startswith("-"):
                raise CheckError("unsafe_command_option", "ping 仅支持 -c/-W/-w。")
            else:
                if host:
                    raise CheckError("unsafe_command_option", "ping 仅允许一个目标。")
                host = a
            i += 1
        if not host or not _HOSTNAME_RE.match(host) or host.startswith("-"):
            raise CheckError("unsafe_command_option", "ping 目标无效。")
        return
    if prog == "nc":
        # 仅端口探测：nc -z [-w N] host port
        i = 0
        host = ""
        port = ""
        saw_z = False
        while i < len(args):
            a = args[i]
            if a == "-z":
                saw_z = True
            elif a in {"-w", "-i"}:
                i += 1
                if i >= len(args) or not re.fullmatch(r"\d{1,5}", args[i]):
                    raise CheckError("unsafe_command_option", "nc 超时无效。")
            elif a.startswith("-"):
                raise CheckError("unsafe_command_option", "nc 仅支持 -z/-w/-i。")
            elif not host:
                host = a
            elif not port:
                port = a
            else:
                raise CheckError("unsafe_command_option", "nc 参数过多。")
            i += 1
        if not saw_z or not host or not port:
            raise CheckError("unsafe_command_option", "nc 需要 -z host port。")
        if not _HOSTNAME_RE.match(host) or host.startswith("-"):
            raise CheckError("unsafe_command_option", "nc 主机无效。")
        if not re.fullmatch(r"\d{1,5}", port) or not (1 <= int(port) <= 65535):
            raise CheckError("unsafe_command_option", "nc 端口无效。")
        return
    if prog == "ss":
        # 只允许查询类；显式禁止 -F/--filter（写诊断文件）与 -K（断开连接）
        allowed = {
            "-h", "-V", "-n", "-r", "-a", "-l", "-o", "-e", "-m", "-p", "-i",
            "-s", "-b", "-E", "-Z", "-t", "-u", "-d", "-w", "-x", "-4", "-6",
            "--help", "--version", "--numeric", "--resolve", "--all", "--listening",
            "--tcp", "--udp", "--unix", "--no-header", "--oneline", "--processes",
        }
        banned = {"-K", "-F", "--kill", "--filter", "--summary", "--bpf", "--events",
                  "--context", "--contexts", "--cgroup", "--inet-sockopt", "-N", "--net"}
        for a in args:
            if a in banned:
                raise CheckError("unsafe_command_option", "连接状态检查禁止该参数。")
            if a.startswith("--"):
                if a not in allowed:
                    raise CheckError("unsafe_command_option", "连接状态检查不支持该长参数。")
            elif a.startswith("-"):
                if len(a) < 2 or not set(a[1:]) <= set("hVnraloemipstux46"):
                    raise CheckError("unsafe_command_option", "连接状态检查只支持查询参数。")
            # 允许 sport=/:port 形式的过滤表达式（port 检查生成）
        return
    if prog == "ps":
        for a in args:
            if a.startswith("-"):
                if not set(a[1:]) <= set("aeflwx"):
                    raise CheckError("unsafe_command_option", "ps 仅支持常用查询参数。")
            elif a not in {"aux", "ax", "u", "a", "x"}:
                raise CheckError("unsafe_command_option", "ps 参数无效。")
        return
    if prog in {"curl", "wget"}:
        _validate_readonly_options(prog, args)
        _validate_probe_urls(prog, args)
        return
    raise CheckError("argv_program_not_allowed", prog)


def _validate_probe_urls(prog: str, args: list[str]) -> None:
    """B1: curl/wget 目标必须是 http(s)，禁止 file/gopher/dict 等本地或危险协议。"""
    for arg in args:
        if arg.startswith("-"):
            continue
        if "://" in arg or arg.startswith("file:") or arg.startswith("/"):
            if not _is_http_url(arg):
                raise CheckError("unsafe_command_option", "网页检查仅支持 http(s) 探测 URL。")


def _validate_readonly_options(prog: str, args: list[str]) -> None:
    """限制具有写入/执行选项的探测程序，包含合并短选项的情况。"""
    if prog == "ss":
        return  # 已在 _validate_probe_argv 处理
    if prog not in {"curl", "wget"}:
        return
    if prog == "curl":
        # B1: 必须禁用远端 .curlrc（与消息入口一致）
        if not args or args[0] not in {"-q", "--disable"}:
            raise CheckError("unsafe_command_option", "curl 必须以 -q 或 --disable 开头。")
    safe_long = {
        "curl": {"--fail", "--fail-with-body", "--silent", "--show-error", "--head", "--location", "--insecure", "--include", "--verbose", "--no-progress-meter", "--disable"},
        "wget": {"--spider", "--quiet", "--server-response", "--no-check-certificate", "--no-config"},
    }[prog]
    safe_short = {"curl": set("qfsSILkiv46"), "wget": set("qS")}[prog]
    number_flags = {
        "curl": {"-m", "--max-time", "--connect-timeout"},
        "wget": {"-T", "--timeout", "-t", "--tries"},
    }[prog]
    stdout_or_spider = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in safe_long:
            if arg == "--spider":
                stdout_or_spider = True
        elif arg in number_flags:
            i += 1
            if i >= len(args) or not re.fullmatch(r"\d+(?:\.\d+)?", args[i]) or float(args[i]) <= 0:
                raise CheckError("unsafe_command_option", "探测等待时间或次数必须是正数。")
        elif prog == "curl" and (arg in {"-X", "--request"} or arg.startswith("-X")):
            if arg in {"-X", "--request"}:
                i += 1
                method = args[i] if i < len(args) else ""
            else:
                method = arg[2:]
            if method not in {"GET", "HEAD"}:
                raise CheckError("unsafe_command_option", "网页检查只支持读取请求（GET 或 HEAD）。")
        elif prog == "wget" and (arg in {"-O", "--output-document"} or arg.startswith("-O")):
            if arg in {"-O", "--output-document"}:
                i += 1
                target = args[i] if i < len(args) else ""
            else:
                target = arg[2:]
            if target != "-":
                raise CheckError("unsafe_command_option", "网页检查不能下载到文件，请使用 --spider 或 -O -。")
            stdout_or_spider = True
        elif arg.startswith("-"):
            if arg.startswith("--") or len(arg) < 2 or not set(arg[1:]) <= safe_short:
                raise CheckError("unsafe_command_option", "该参数不属于受支持的只读探测参数。")
        i += 1
    if prog == "wget" and not stdout_or_spider:
        raise CheckError("unsafe_command_option", "网页检查不能下载到文件，请使用 --spider 或 -O -。")


@dataclass
class CheckSpec:
    id: str
    asset_id: str
    name: str
    kind: str
    params: dict
    expect: dict
    interval_sec: int
    fail_threshold: int
    severity: str
    enabled: bool


def build_tokens(kind: str, params: dict) -> list[list[str]]:
    """生成探测 argv（可能多条，全部成功才算 ok）。禁止自由拼接。"""
    kind = (kind or "").strip()
    if kind == "port":
        port = validate_port(params.get("port"))
        proto = (params.get("protocol") or "tcp").lower()
        if proto not in ("tcp", "udp"):
            raise CheckError("bad_protocol", proto)
        flag = ["ss", "-lnu"] if proto == "udp" else ["ss", "-lnt"]
        return [flag + ["sport", "=", f":{port}"]]
    if kind == "service":
        unit = validate_unit(params.get("unit") or params.get("name") or "")
        return [
            ["systemctl", "is-active", unit],
        ]
    if kind == "command":
        argv = validate_argv(params.get("argv"))
        return [argv]
    raise CheckError("bad_kind", kind)


def evaluate(kind: str, outputs: list[dict[str, Any]], expect: dict) -> tuple[bool, str, str]:
    """按期望判定。返回 (ok, state, detail)。"""
    if not outputs:
        return False, "unknown", "no_output"
    # 任一条失败 → 不 ok（port 的 ss 无匹配会 returncode=0 但输出空）
    if kind == "port":
        out = outputs[0]
        rc = out.get("returncode")
        text = (out.get("output") or "").strip()
        # P1-08: 传输失败/表头/错误输出不得判正常
        if out.get("ok") is False or (rc is not None and int(rc) != 0):
            return False, "fail", (text[:200] or f"probe_exit={rc}")
        lines = [
            ln for ln in text.splitlines()
            if ln.strip() and not ln.lower().startswith(("netid", "state", "recv-q"))
        ]
        listening = [
            ln for ln in lines
            if ln.split()[:1] and ln.split()[0].upper() in {"LISTEN", "UNCONN", "ESTAB"}
            or ("LISTEN" in ln or ": " in ln and any(p.isdigit() for p in ln))
        ]
        # ss -lnt 输出：有数据行且非表头 → 监听中
        ok = bool(lines) and any("LISTEN" in ln.upper() or re.search(r":\d+", ln) for ln in lines)
        return ok, ("ok" if ok else "fail"), (text[:200] if text else "port_not_listening")
    if kind == "service":
        text = (outputs[0].get("output") or "").strip()
        want = (expect.get("active_state") or "active").strip()
        ok = text == want
        return ok, ("ok" if ok else "fail"), f"state={text or 'unknown'} want={want}"
    if kind == "command":
        raw_rc = outputs[0].get("returncode")
        rc = int(raw_rc) if raw_rc is not None else -1
        want_rc = expect.get("exit_code")
        if want_rc is not None:
            ok = rc == int(want_rc)
            return ok, ("ok" if ok else "fail"), f"exit={rc} want={want_rc}"
        # B1: 禁止 output_contains / output_not_contains 布尔 oracle
        ok = rc == 0
        return ok, ("ok" if ok else "fail"), f"exit={rc}"
    return False, "unknown", f"bad_kind:{kind}"


class CheckService:
    def __init__(self, db: Database, transport: Any, notifier: Any | None = None, incidents: Any | None = None):
        self.db = db
        self.transport = transport
        self.notifier = notifier
        self.incidents = incidents

    # ---- CRUD ----

    def list_checks(self, asset_id: str = "") -> list[dict[str, Any]]:
        if asset_id:
            rows = self.db.query(
                "SELECT * FROM checks WHERE asset_id=? ORDER BY kind, name", (asset_id,)
            )
        else:
            rows = self.db.query("SELECT * FROM checks ORDER BY asset_id, kind, name")
        out = []
        for r in rows:
            d = dict(r)
            d["params"] = json.loads(d.get("params_json") or "{}")
            d["expect"] = json.loads(d.get("expect_json") or "{}")
            d["enabled"] = bool(d.get("enabled"))
            out.append(d)
        return out

    def get_check(self, check_id: str) -> dict[str, Any] | None:
        row = self.db.query_one("SELECT * FROM checks WHERE id=?", (check_id,))
        if not row:
            return None
        d = dict(row)
        d["params"] = json.loads(d.get("params_json") or "{}")
        d["expect"] = json.loads(d.get("expect_json") or "{}")
        d["enabled"] = bool(d.get("enabled"))
        return d

    def create_check(
        self,
        *,
        asset_id: str,
        kind: str,
        name: str,
        params: dict,
        expect: dict | None = None,
        interval_sec: int = 60,
        fail_threshold: int = 2,
        severity: str = "warning",
        actor: str = "web",
    ) -> dict[str, Any]:
        payload = self._validated_payload({
            "asset_id": asset_id, "kind": kind, "name": name,
            "params": params, "expect": {} if expect is None else expect,
            "interval_sec": interval_sec, "fail_threshold": fail_threshold, "severity": severity,
        })
        asset_id, kind, name = payload["asset_id"], payload["kind"], payload["name"]
        params, expect = payload["params"], payload["expect"]
        interval_sec, fail_threshold, severity = payload["interval_sec"], payload["fail_threshold"], payload["severity"]
        cid = new_id("chk")
        t = now()
        self.db.execute(
            "INSERT INTO checks(id, asset_id, name, kind, params_json, expect_json,"
            " interval_sec, fail_threshold, severity, enabled, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,1,?,?)",
            (
                cid,
                asset_id,
                name,
                kind,
                json.dumps(params, ensure_ascii=False),
                json.dumps(expect, ensure_ascii=False),
                interval_sec,
                fail_threshold,
                severity,
                t,
                t,
            ),
        )
        self.db.audit(
            "web_user",
            actor,
            "check_create",
            asset_id=asset_id,
            detail={"id": cid, "kind": kind, "name": name},
        )
        return self.get_check(cid) or {}

    def update_check(self, check_id: str, *, actor: str = "web", **fields) -> dict[str, Any]:
        cur = self.get_check(check_id)
        if not cur:
            raise CheckError("not_found", check_id)
        allowed = {"name", "params", "expect", "interval_sec", "fail_threshold", "severity", "enabled"}
        if set(fields) - allowed:
            raise CheckError("unknown_field", "更新内容包含当前表单不支持的配置项。")
        if "enabled" in fields and not isinstance(fields["enabled"], bool):
            raise CheckError("bad_enabled", "启用状态必须选择启用或停用。")
        if fields == {"enabled": False}:
            # 禁用旧检查不执行探测，也不改变旧参数；新增校验规则不能使旧配置无法停止。
            payload = {key: cur[key] for key in allowed - {"enabled"}}
        else:
            payload = self._validated_payload({
                "asset_id": cur["asset_id"], "kind": cur["kind"],
                **{key: fields.get(key, cur[key]) for key in allowed - {"enabled"}},
            }, allow_disabled_asset=fields.get("enabled") is False)
        name, params, expect = payload["name"], payload["params"], payload["expect"]
        self.db.execute(
            "UPDATE checks SET name=?, params_json=?, expect_json=?, interval_sec=?,"
            " fail_threshold=?, severity=?, enabled=?, updated_at=? WHERE id=?",
            (
                name,
                json.dumps(params, ensure_ascii=False),
                json.dumps(expect, ensure_ascii=False),
                payload["interval_sec"],
                payload["fail_threshold"],
                payload["severity"],
                1 if fields.get("enabled", cur["enabled"]) else 0,
                now(),
                check_id,
            ),
        )
        self.db.audit("web_user", actor, "check_update", asset_id=cur["asset_id"], detail={"id": check_id})
        return self.get_check(check_id) or {}

    def _validated_payload(self, payload: dict, *, allow_disabled_asset: bool = False) -> dict:
        """创建、更新和 AI 草稿共用同一契约，写入前一次完成校验。"""
        from .formspec import _validation_error, validate_check_payload
        assets = [dict(row) for row in self.db.query("SELECT id, display_name, enabled FROM assets")]
        # 已停用资产上的检查仍应能关闭，避免资产停用后无法清理旧检查。
        if allow_disabled_asset:
            assets = [{**asset, "enabled": True} for asset in assets]
        result = validate_check_payload(payload, assets=assets)
        if not result["valid"]:
            _validation_error(result)
        out = result["payload"]
        # P1-07: 不得静默把 output 匹配降级为 exit_code（假绿）
        if out.get("kind") == "command":
            expect = dict(out.get("expect") or {})
            if "output_contains" in expect or "output_not_contains" in expect:
                raise CheckError(
                    "unsupported_expect",
                    "command 类检查不支持输出内容匹配，请改用 exit_code。",
                    issues=[{"field": "expect", "message": "command 检查仅支持 exit_code 期望。"}],
                )
            if "exit_code" not in expect:
                expect["exit_code"] = 0
            out["expect"] = expect
        return out

    def delete_check(self, check_id: str, *, actor: str = "web") -> None:
        cur = self.get_check(check_id)
        if not cur:
            raise CheckError("not_found", check_id)
        self.db.execute("DELETE FROM checks WHERE id=?", (check_id,))
        self.db.audit("web_user", actor, "check_delete", asset_id=cur["asset_id"], detail={"id": check_id})

    def recent_results(self, check_id: str, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM check_results WHERE check_id=? ORDER BY at DESC LIMIT ?",
            (check_id, max(1, min(100, int(limit)))),
        )
        return [dict(r) for r in rows]

    def activity(self, limit: int = 50) -> list[dict[str, Any]]:
        """动态：最近检查结果 + 检查配置变更。"""
        results = self.db.query(
            "SELECT c.id AS check_id, c.name, c.asset_id, c.kind, r.at, r.ok, r.state, r.detail"
            " FROM check_results r JOIN checks c ON c.id=r.check_id"
            " ORDER BY r.at DESC LIMIT ?",
            (max(1, min(200, int(limit))), ),
        )
        return [dict(r) for r in results]

    # ---- 执行 ----

    async def run_one(self, check: dict[str, Any]) -> dict[str, Any]:
        kind = check["kind"]
        outputs = []
        ok = False
        detail = ""
        state = "unknown"
        try:
            plans = build_tokens(kind, check.get("params") or {})
            for tokens in plans:
                res = await self.transport.probe(check["asset_id"], tokens, timeout=12)
                outputs.append(
                    {
                        "ok": bool(getattr(res, "ok", False)),
                        "returncode": int(getattr(res, "returncode", -1)),
                        "output": (getattr(res, "output", "") or "")[:2000],
                    }
                )
            ok, state, detail = evaluate(kind, outputs, check.get("expect") or {})
        except CheckError as e:
            ok, state, detail = False, "unknown", e.detail or "检查配置不符合当前执行规则，请修改检查配置。"
        except Exception as e:
            ok, state, detail = False, "unknown", str(e)[:200]
        await self._record(check, ok=ok, state=state, detail=detail)
        return {"ok": ok, "state": state, "detail": detail}

    async def _record(self, check: dict[str, Any], *, ok: bool, state: str, detail: str) -> None:
        t = now()
        # 以库内 streak 为准，避免同一 dict 复用导致计数不增
        row = self.db.query_one("SELECT fail_streak, last_state FROM checks WHERE id=?", (check["id"],))
        prev_streak = int(row["fail_streak"] or 0) if row else 0
        streak = 0 if ok else prev_streak + 1
        self.db.execute(
            "UPDATE checks SET last_state=?, last_ok=?, last_at=?, last_detail=?, fail_streak=?, updated_at=?"
            " WHERE id=?",
            (state, 1 if ok else 0, t, detail, streak, t, check["id"]),
        )
        self.db.execute(
            "INSERT INTO check_results(check_id, at, ok, state, detail) VALUES(?,?,?,?,?)",
            (check["id"], t, 1 if ok else 0, state, detail),
        )
        # 超阈值 → 事件
        thr = int(check.get("fail_threshold") or 2)
        if streak == thr or (not ok and streak == 1 and thr == 1):
            await self._raise_alert(check, detail=detail, streak=streak)
        if ok and streak == 0 and check.get("was_failing"):
            await self._resolve_alert(check)

    async def _raise_alert(self, check: dict[str, Any], *, detail: str, streak: int) -> None:
        """写入 alert_episodes 并收敛为 Incident，发通知。"""
        from .alertmanager import fingerprint_of

        alertname = f"CheckFailed_{check.get('kind')}"
        labels = {
            "alertname": alertname,
            "asset": check.get("asset_id") or "",
            "check": check.get("name") or "",
            "check_kind": check.get("kind") or "",
            "severity": check.get("severity") or "warning",
            "source": "ayana_check",
        }
        fp = fingerprint_of(labels)
        t = now()
        ep_id = new_id("ep")
        try:
            self.db.execute(
                "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm,"
                " alertname, status, asset_id, object_id, first_seen, last_seen,"
                " receive_count, labels_json, annotations_json, source_state)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ep_id,
                    "ayana_check",
                    fp,
                    str(int(t)),
                    alertname,
                    "firing",
                    check.get("asset_id") or "",
                    "",
                    t,
                    t,
                    1,
                    json.dumps(labels, ensure_ascii=False),
                    json.dumps({"detail": detail, "check_id": check.get("id")}, ensure_ascii=False),
                    "firing",
                ),
            )
            inc_id = ""
            if self.incidents:
                try:
                    inc_id = self.incidents.upsert_from_episode(ep_id) or ""
                except Exception:
                    inc_id = ""
            if self.notifier:
                body = f"[{labels['severity']}] 检查失败 {labels['asset']}/{labels['check']}: {detail}"
                try:
                    self.notifier.enqueue(
                        dedup_key=f"check:{check.get('id')}:{int(t // 60)}",
                        target="",
                        body=body,
                        channel="qq",
                    )
                except Exception:
                    pass
            self.db.event(
                "check_failed",
                f"检查失败 {labels['asset']}/{labels['check']}",
                incident_id=inc_id,
                payload={"check_id": check.get("id"), "detail": detail, "streak": streak},
            )
        except Exception:
            pass

    async def _resolve_alert(self, check: dict[str, Any]) -> None:
        if not self.notifier:
            return
        try:
            self.notifier.enqueue(
                dedup_key=f"check_ok:{check.get('id')}:{int(now() // 60)}",
                target="",
                body=f"[恢复] 检查通过 {check.get('asset_id')}/{check.get('name')}",
                channel="qq",
            )
        except Exception:
            pass

    async def run_due(self, *, now_ts: float | None = None) -> int:
        """跑到期的启用检查。"""
        ts = now_ts if now_ts is not None else time.time()
        rows = self.list_checks()
        n = 0
        for c in rows:
            if not c.get("enabled"):
                continue
            last = float(c.get("last_at") or 0)
            interval = max(15, int(c.get("interval_sec") or 60))
            if last and (ts - last) < interval:
                continue
            # 记录失败前状态用于恢复判断
            c["was_failing"] = (c.get("fail_streak") or 0) > 0
            await self.run_one(c)
            n += 1
        return n
