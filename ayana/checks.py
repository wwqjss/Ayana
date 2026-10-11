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
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

from .db import Database, new_id, now

MAX_ARGV_TOKENS = 8
_TOKEN_BAD = re.compile(r"[ \t\n\r;|&$`\\'\"<>(){}\[\]*?~!#%^=+]")
# 自定义命令仅允许探测类程序（只读意图），禁止 rm/shutdown 等
_CMD_ALLOW = {
    "curl",
    "wget",
    "pgrep",
    "ps",
    "ss",
    "cat",
    "head",
    "tail",
    "grep",
    "egrep",
    "echo",
    "test",
    "true",
    "false",
    "nc",
    "dig",
    "ping",
}
_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")


class CheckError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def validate_unit(name: str) -> str:
    name = (name or "").strip()
    if not _UNIT_RE.fullmatch(name):
        raise CheckError("bad_unit", name)
    return name


def validate_port(port: Any) -> int:
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
    for t in argv:
        if not isinstance(t, str) or not t or len(t) > 120:
            raise CheckError("bad_argv_token", str(t)[:40])
        if _TOKEN_BAD.search(t):
            raise CheckError("bad_argv_token", t[:40])
        out.append(t)
    prog = out[0].rsplit("/", 1)[-1].lower()
    if prog not in _CMD_ALLOW:
        raise CheckError("argv_program_not_allowed", prog)
    return out


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
        text = (outputs[0].get("output") or "").strip()
        ok = bool(text)
        return ok, ("ok" if ok else "fail"), (text[:200] if text else "port_not_listening")
    if kind == "service":
        text = (outputs[0].get("output") or "").strip()
        want = (expect.get("active_state") or "active").strip()
        ok = text == want
        return ok, ("ok" if ok else "fail"), f"state={text or 'unknown'} want={want}"
    if kind == "command":
        raw_rc = outputs[0].get("returncode")
        rc = int(raw_rc) if raw_rc is not None else -1
        text = outputs[0].get("output") or ""
        want_rc = expect.get("exit_code")
        if want_rc is not None:
            ok = rc == int(want_rc)
            return ok, ("ok" if ok else "fail"), f"exit={rc} want={want_rc}"
        contains = expect.get("output_contains")
        if contains:
            ok = str(contains) in text
            return ok, ("ok" if ok else "fail"), ("matched" if ok else "not_matched")
        not_contains = expect.get("output_not_contains")
        if not_contains:
            ok = str(not_contains) not in text
            return ok, ("ok" if ok else "fail"), ("ok" if ok else "forbidden_text")
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
        kind = (kind or "").strip()
        if kind not in ("port", "service", "command"):
            raise CheckError("bad_kind", kind)
        name = (name or "").strip()
        if not _NAME_RE.fullmatch(name):
            raise CheckError("bad_name", name)
        params = params or {}
        expect = expect or {}
        # 预生成 tokens 做校验
        build_tokens(kind, params)
        try:
            interval_sec = max(15, min(3600, int(interval_sec)))
            fail_threshold = max(1, min(10, int(fail_threshold)))
        except (TypeError, ValueError) as e:
            raise CheckError("bad_interval") from e
        if severity not in ("info", "warning", "critical"):
            raise CheckError("bad_severity", severity)
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
        params = fields.get("params", cur["params"])
        expect = fields.get("expect", cur["expect"])
        build_tokens(cur["kind"], params)
        name = fields.get("name", cur["name"])
        if not _NAME_RE.fullmatch(name or ""):
            raise CheckError("bad_name", name)
        self.db.execute(
            "UPDATE checks SET name=?, params_json=?, expect_json=?, interval_sec=?,"
            " fail_threshold=?, severity=?, enabled=?, updated_at=? WHERE id=?",
            (
                name,
                json.dumps(params, ensure_ascii=False),
                json.dumps(expect, ensure_ascii=False),
                int(fields.get("interval_sec", cur["interval_sec"])),
                int(fields.get("fail_threshold", cur["fail_threshold"])),
                fields.get("severity", cur["severity"]),
                1 if fields.get("enabled", cur["enabled"]) else 0,
                now(),
                check_id,
            ),
        )
        self.db.audit("web_user", actor, "check_update", asset_id=cur["asset_id"], detail={"id": check_id})
        return self.get_check(check_id) or {}

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
        plans = build_tokens(kind, check.get("params") or {})
        outputs = []
        ok = False
        detail = ""
        state = "unknown"
        try:
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
