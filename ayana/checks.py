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
import hashlib
import json
import posixpath
import re
import time
from typing import Any, Callable

from .db import Database, new_id, now
from .formspec import UNIT_PATTERN
from .readonly_commands import validate_probe_tokens

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
    def __init__(self, code: str, detail: str = "", *, issues: list[dict] | None = None,
                 dispatch_not_started: bool = False):
        self.code = code
        self.detail = detail
        self.issues = issues or []
        self.dispatch_not_started = dispatch_not_started
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
    """B1: 每个程序的参数语法白名单；禁止文件输入与未授权外发。

    curl/ping/ss/ps 复用 readonly_commands.validate_probe_tokens（两处规则取更严）。
    """
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
    if prog in {"ping", "ss", "ps", "curl"}:
        if not validate_probe_tokens(prog, args):
            raise CheckError("unsafe_command_option", f"{prog} 参数不符合只读探测语法。")
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
    if prog == "wget":
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
        out = outputs[0]
        text = (out.get("output") or "").strip()
        want = (expect.get("active_state") or "active").strip()
        ok = out.get("ok") is True and out.get("returncode") == 0 and text == want
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


def check_contract_digest(check: dict[str, Any]) -> str:
    """Bind a result to the actual check target and expectation, not its label."""
    definition = {
        "asset_id": check.get("asset_id"), "kind": check.get("kind"),
        "params": check.get("params") if "params" in check else json.loads(check.get("params_json") or "{}"),
        "expect": check.get("expect") if "expect" in check else json.loads(check.get("expect_json") or "{}"),
    }
    return hashlib.sha256(json.dumps(definition, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def check_recovery_evidence(db: Database, episode: dict, generation: int) -> dict[str, Any]:
    """Use only the latest fresh result of this exact source check and generation."""
    try:
        annotations = json.loads(episode.get("annotations_json") or "{}")
        check_id = annotations.get("check_id")
        row = db.query_one("SELECT * FROM checks WHERE id=?", (check_id,))
        if not row:
            return {"verdict": "none", "reason": "check_missing"}
        check = dict(row)
        kind = check["kind"]
        if kind not in ("service", "port"):
            return {"verdict": "no_contract", "contract": ""}
        base = {"contract": f"check.{kind}", "check_id": check_id}
        proof = annotations.get("check_recovery") or {}
        if (episode.get("source_id") != "ayana_check"
                or episode.get("alertname") != f"CheckFailed_{kind}"
                or check["asset_id"] != episode.get("asset_id") or not check["enabled"]
                or proof.get("episode_id") != episode.get("id")
                or proof.get("incident_id") != episode.get("incident_id")
                or proof.get("generation") != generation
                or proof.get("check_id") != check_id
                or proof.get("contract_digest") != check_contract_digest(check)):
            return {"verdict": "none", "reason": "check_contract_mismatch", **base}
        incident = db.query_one("SELECT generation FROM incidents WHERE id=?", (episode.get("incident_id"),))
        if not incident or int(incident["generation"] or 1) != generation:
            return {"verdict": "none", "reason": "stale_generation", **base}
        result = db.query_one(
            "SELECT * FROM check_results WHERE check_id=? ORDER BY at DESC,id DESC LIMIT 1", (check_id,)
        )
        t = now()
        if (not result or not 0 <= t - float(result["at"]) <= 120
                or float(result["at"]) < float(episode.get("first_seen") or 0)
                or float(check["last_at"] or 0) != float(result["at"])):
            return {"verdict": "none", "reason": "check_result_stale", **base}
        green = bool(result["ok"] and result["state"] == "ok" and check["last_ok"] and check["last_state"] == "ok")
        return {"verdict": "green" if green else "red", "source": "check_result",
                "result_id": result["id"], "sample_at": result["at"],
                "asset": check["asset_id"], "generation": generation,
                "contract_digest": proof["contract_digest"], **base}
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError):
        return {"verdict": "none", "reason": "invalid_check_evidence"}


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
            raise CheckError("not_found", check_id, dispatch_not_started=True)
        allowed = {"name", "params", "expect", "interval_sec", "fail_threshold", "severity", "enabled"}
        if set(fields) - allowed:
            raise CheckError("unknown_field", "更新内容包含当前表单不支持的配置项。", dispatch_not_started=True)
        if "enabled" in fields and not isinstance(fields["enabled"], bool):
            raise CheckError("bad_enabled", "启用状态必须选择启用或停用。", dispatch_not_started=True)
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
        try:
            return self._validate_payload_before_write(payload, allow_disabled_asset=allow_disabled_asset)
        except CheckError as exc:
            # Only this pure validation phase can certify that no mutation ran.
            # Database/audit failures after INSERT/UPDATE must remain unknown.
            exc.dispatch_not_started = True
            raise

    def _validate_payload_before_write(self, payload: dict, *, allow_disabled_asset: bool = False) -> dict:
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
            raise CheckError("not_found", check_id, dispatch_not_started=True)
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
        if ok:
            # Also repair an earlier missed source transition on subsequent
            # successes; _resolve_alert emits nothing when there is no episode.
            await self._resolve_alert(check)

    async def _raise_alert(self, check: dict[str, Any], *, detail: str, streak: int) -> None:
        """写入 alert_episodes 并收敛为 Incident，发通知。"""
        from .alertmanager import fingerprint_of, upsert_episode

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
        try:
            ep_id, _created, _prev, _new = upsert_episode(
                self.db,
                source_id="ayana_check",
                fingerprint=fp,
                labels=labels,
                annotations={"detail": detail, "check_id": check.get("id"),
                             "check_contract": check_contract_digest(check)},
                status="firing",
                source_state="firing",
                t=t,
                alertname=alertname,
                asset_id=check.get("asset_id") or "",
            )
            inc_id = ""
            if self.incidents:
                try:
                    inc_id = self.incidents.upsert_from_episode(ep_id) or ""
                except Exception:
                    inc_id = ""
            ev_id = self.db.event(
                "check_failed",
                f"检查失败 {labels['asset']}/{labels['check']}",
                incident_id=inc_id,
                payload={"check_id": check.get("id"), "detail": detail, "streak": streak},
            )
            if self.notifier and ev_id:
                body = f"[{labels['severity']}] 检查失败 {labels['asset']}/{labels['check']}: {detail}"
                try:
                    self.notifier.enqueue_for_event(ev_id, body=body, typ="check_failed")
                except Exception:
                    pass
        except Exception:
            pass

    async def _resolve_alert(self, check: dict[str, Any]) -> None:
        """Resolve only this check's current episode using persisted source evidence."""
        current = self.get_check(check["id"])
        if (not current or not current["enabled"]
                or check_contract_digest(current) != check_contract_digest(check)):
            return
        latest = self.db.query_one(
            "SELECT * FROM check_results WHERE check_id=? ORDER BY at DESC,id DESC LIMIT 1", (check["id"],)
        )
        if (not latest or not latest["ok"] or latest["state"] != "ok"
                or not 0 <= now() - float(latest["at"]) <= 120):
            return
        for row in self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ayana_check' AND status='firing'"
            " AND asset_id=? AND alertname=? AND json_valid(annotations_json)"
            " AND json_extract(annotations_json,'$.check_id')=?",
            (check["asset_id"], f"CheckFailed_{check['kind']}", check["id"]),
        ):
            episode = dict(row)
            incident_id = episode["incident_id"] or ""
            if (not self.incidents or not incident_id
                    or not self.incidents.episode_is_current(incident_id, episode)):
                continue
            incident = self.db.query_one("SELECT generation,status FROM incidents WHERE id=?", (incident_id,))
            if not incident or incident["status"] != "open":
                continue
            generation = int(incident["generation"] or 1)
            annotations = json.loads(episode["annotations_json"] or "{}")
            digest = check_contract_digest(current)
            if annotations.get("check_contract") not in (None, digest):
                continue
            # Older episodes did not save the check contract. Do not let a
            # later edit of that check certify the earlier target's recovery.
            if not annotations.get("check_contract") and self.db.query_one(
                "SELECT 1 FROM audit_log WHERE entry='check_update' AND at>?"
                " AND json_valid(detail_json) AND json_extract(detail_json,'$.id')=? LIMIT 1",
                (episode["first_seen"], check["id"]),
            ):
                continue
            annotations["check_recovery"] = {
                "episode_id": episode["id"], "incident_id": incident_id,
                "generation": generation, "check_id": check["id"],
                "contract_digest": digest,
            }
            episode["annotations_json"] = json.dumps(annotations, ensure_ascii=False)
            evidence = check_recovery_evidence(self.db, episode, generation)
            if evidence.get("verdict") not in ("green", "no_contract"):
                continue
            with self.db.tx() as conn:
                # Generation and source status are checked again under the
                # same write transaction as the lifecycle transition.
                live = conn.execute("SELECT generation,status FROM incidents WHERE id=?", (incident_id,)).fetchone()
                if not live or live["status"] != "open" or int(live["generation"] or 1) != generation:
                    continue
                evidence = check_recovery_evidence(self.db, episode, generation)
                if evidence.get("verdict") not in ("green", "no_contract"):
                    continue
                cur = conn.execute(
                    "UPDATE alert_episodes SET status='resolved',source_state='resolved',last_seen=?,"
                    " last_reconciled_at=?,annotations_json=? WHERE id=? AND status='firing'",
                    (latest["at"], latest["at"], episode["annotations_json"], episode["id"]),
                )
                if cur.rowcount != 1:
                    continue
                self.incidents.on_episode_resolved(episode["id"])
            body = f"[恢复] 检查通过 {check.get('asset_id')}/{check.get('name')}"
            ev_id = self.db.event(
                "check_recovered",
                f"检查恢复 {check.get('asset_id')}/{check.get('name')}",
                incident_id=incident_id, episode_id=episode["id"],
                payload={"check_id": check.get("id"), "body": body, "evidence": evidence,
                         "generation": generation},
            )
            if self.notifier and ev_id:
                self.notifier.enqueue_for_event(ev_id, body=body, typ="check_recovered")

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
