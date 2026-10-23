"""外部事务：接入配置、Token、上报、执行记录、失联/超时检测。

- 不与具体业务（飞牛/MySQL）耦合；业务语义只在上报数据里
- 复用 alert_episodes → IncidentService → notification_outbox，不新增告警引擎
- 状态转换按 run_id 的合法状态机，防止迟到消息覆盖终态
- report_kind=collector 表示采集器/监控异常，不得记为业务失败，也不得默认成功
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import Database, new_id, now

# ---- 常量 ----

STATUSES = ("running", "success", "failure", "timeout", "unknown")
SEVERITIES = ("info", "warning", "critical")
REPORT_KINDS = ("run", "collector")
WATCH_MODES = ("off", "heartbeat", "schedule")

# 合法状态转换：旧 → 允许的新状态（含自身，便于补 detail）
# 终态 success 之后不再接受 failure/timeout/running/unknown，防止迟到失败覆盖成功。
LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    "": frozenset(STATUSES),
    "running": frozenset(("running", "success", "failure", "timeout", "unknown")),
    "unknown": frozenset(("running", "success", "failure", "timeout", "unknown")),
    "timeout": frozenset(("success", "failure", "unknown", "timeout")),
    "failure": frozenset(("success", "failure", "unknown")),
    "success": frozenset(("success",)),
}

TOKEN_PREFIX = "ext_"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
EVENT_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")

MAX_MESSAGE = 500
MAX_DETAIL = 2000
MAX_NAME = 120
MAX_DESC = 1000
MAX_SOURCE = 80

DEFAULT_GRACE_SEC = 300
MIN_INTERVAL_SEC = 30
MAX_INTERVAL_SEC = 30 * 86400
MIN_TIMEOUT_SEC = 30
MAX_TIMEOUT_SEC = 7 * 86400
# 恢复防抖：0=立即关闭；>0 成功后等待 N 秒再收 Incident，期间失败则取消
DEFAULT_RESOLVE_DELAY_SEC = 0
MAX_RESOLVE_DELAY_SEC = 86400

CRON_FIELD_RE = re.compile(r"^[0-9*/,?-]+$")

# 问题族（episode fingerprint 的稳定部分，不含 run_id，保证持续失败不重复通知）
PROBLEM_FAILURE = "failure"
PROBLEM_TIMEOUT = "timeout"
PROBLEM_MISSING = "missing"
PROBLEM_COLLECTOR = "collector"


class ExtTxError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def _as_str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def hash_token(raw: str, pepper: str = "") -> str:
    """Token 哈希：sha256(token+pepper)。与 recovery code 同思路，日志永不写明文。"""
    return hashlib.sha256((raw + (pepper or "")).encode("utf-8")).hexdigest()


def parse_ts(value: Any) -> float | None:
    """解析上报 timestamp：ISO-8601 或 epoch 数字。非法返回 None。"""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        if v > 1e12:  # 毫秒
            v /= 1000.0
        return v if 0 < v < 4102444800 else None
    s = str(value).strip()
    if not s:
        return None
    try:
        return parse_ts(float(s))
    except ValueError:
        pass
    # ISO-8601
    try:
        norm = s.replace("Z", "+00:00")
        if " " in norm and "T" not in norm:
            norm = norm.replace(" ", "T", 1)
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def validate_schedule(raw: Any) -> dict:
    """校验计划任务调度配置。

    kind:
      cron     {"kind":"cron","expr":"0 0 * * 1","tz":"UTC"}  标准五段式
      daily    {"kind":"daily","time":"HH:MM"}
      weekly   {"kind":"weekly","dow":1-7,"time":"HH:MM"}  (ISO: 1=周一)
      interval {"kind":"interval","interval_sec":N}
    也可直接给五段式 cron 字符串。
    """
    if raw is None or raw == "" or raw == {}:
        return {}
    if isinstance(raw, str):
        expr = raw.strip()
        if _is_cron5(expr):
            return {"kind": "cron", "expr": expr, "tz": "UTC"}
        try:
            raw = json.loads(raw)
        except Exception:
            raise ExtTxError("bad_schedule", "schedule must be json object or cron expr")
    if not isinstance(raw, dict):
        raise ExtTxError("bad_schedule", "schedule must be object")
    kind = str(raw.get("kind") or "").strip().lower()
    if not kind:
        # 允许 {"expr": "..."} 简写
        if raw.get("expr"):
            kind = "cron"
        else:
            return {}
    if kind == "cron":
        expr = str(raw.get("expr") or raw.get("cron") or "").strip()
        if not _is_cron5(expr):
            raise ExtTxError("bad_schedule", "cron must be standard 5-field expression")
        tz = str(raw.get("tz") or "UTC").strip() or "UTC"
        return {"kind": "cron", "expr": expr, "tz": tz}
    if kind == "daily":
        t = str(raw.get("time") or "").strip()
        if not TIME_RE.match(t):
            raise ExtTxError("bad_schedule", "daily requires time HH:MM")
        return {"kind": "daily", "time": t}
    if kind == "weekly":
        t = str(raw.get("time") or "").strip()
        if not TIME_RE.match(t):
            raise ExtTxError("bad_schedule", "weekly requires time HH:MM")
        try:
            dow = int(raw.get("dow"))
        except (TypeError, ValueError):
            raise ExtTxError("bad_schedule", "weekly requires dow 1-7")
        if not (1 <= dow <= 7):
            raise ExtTxError("bad_schedule", "dow must be 1-7 (ISO, 1=Monday)")
        return {"kind": "weekly", "dow": dow, "time": t}
    if kind == "interval":
        try:
            sec = int(raw.get("interval_sec"))
        except (TypeError, ValueError):
            raise ExtTxError("bad_schedule", "interval requires interval_sec")
        if not (MIN_INTERVAL_SEC <= sec <= MAX_INTERVAL_SEC):
            raise ExtTxError("bad_schedule", "interval_sec out of range")
        return {"kind": "interval", "interval_sec": sec}
    raise ExtTxError("bad_schedule", f"unknown kind: {kind}")


def _is_cron5(expr: str) -> bool:
    parts = (expr or "").split()
    if len(parts) != 5:
        return False
    return all(CRON_FIELD_RE.match(p) and p for p in parts)


def _cron_field_values(field: str, lo: int, hi: int) -> set[int] | None:
    """解析单个 cron 字段为取值集合；非法返回 None。"""
    out: set[int] = set()
    for piece in field.split(","):
        piece = piece.strip()
        if not piece:
            return None
        step = 1
        if "/" in piece:
            piece, step_s = piece.split("/", 1)
            if not step_s.isdigit() or int(step_s) <= 0:
                return None
            step = int(step_s)
        if piece in ("*", "?"):
            start, end = lo, hi
        elif "-" in piece:
            a, b = piece.split("-", 1)
            if not (a.lstrip("-").isdigit() and b.lstrip("-").isdigit()):
                return None
            start, end = int(a), int(b)
            if start > end:
                return None
        elif piece.isdigit():
            start = end = int(piece)
        else:
            return None
        if start < lo or end > hi:
            return None
        out.update(range(start, end + 1, step))
    return out or None


def _cron_match_dt(expr: str, dt: datetime) -> bool:
    parts = expr.split()
    minute = _cron_field_values(parts[0], 0, 59)
    hour = _cron_field_values(parts[1], 0, 23)
    dom = _cron_field_values(parts[2], 1, 31)
    month = _cron_field_values(parts[3], 1, 12)
    dow = _cron_field_values(parts[4], 0, 7)  # 0 和 7 都是周日
    if None in (minute, hour, dom, month, dow):
        return False
    if 7 in dow:
        dow = set(dow)
        dow.discard(7)
        dow.add(0)
    # cron 经典语义：dom 与 dow 均受限时取「或」；只有一侧受限则只看那一侧
    dom_star = parts[2] in ("*", "?")
    dow_star = parts[4] in ("*", "?")
    if dom_star and dow_star:
        day_ok = True
    elif dom_star:
        day_ok = dt.isoweekday() % 7 in dow
    elif dow_star:
        day_ok = dt.day in dom
    else:
        day_ok = (dt.day in dom) or (dt.isoweekday() % 7 in dow)
    if not day_ok:
        return False
    return dt.month in month and dt.hour in hour and dt.minute in minute


def _tzinfo(tz_name: str):
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(tz_name or "UTC")
    except Exception:
        return timezone.utc


def _cron_expected_times(expr: str, tz_name: str, *, now_ts: float, lookback_sec: float) -> list[float]:
    """按分钟精度回看，列出已到点的 cron 时刻（epoch）。"""
    if not _is_cron5(expr):
        return []
    tz = _tzinfo(tz_name)
    end = datetime.fromtimestamp(now_ts, tz=timezone.utc).astimezone(tz)
    start = datetime.fromtimestamp(now_ts - lookback_sec, tz=timezone.utc).astimezone(tz)
    # 对齐到分钟，从 start 起扫到 end
    cur = start.replace(second=0, microsecond=0)
    out: list[float] = []
    # 上限防呆：最多回看 32 天
    max_steps = 32 * 24 * 60
    steps = 0
    while cur <= end and steps < max_steps:
        if _cron_match_dt(expr, cur):
            out.append(cur.timestamp())
        cur += timedelta(minutes=1)
        steps += 1
    return out


def expected_run_times(schedule: dict, *, now_ts: float, lookback_sec: float) -> list[float]:
    """列出 lookback 窗口内「应当已经跑完」的计划时刻（epoch）。"""
    if not schedule:
        return []
    kind = schedule.get("kind")
    if kind == "cron":
        return _cron_expected_times(
            str(schedule.get("expr") or ""),
            str(schedule.get("tz") or "UTC"),
            now_ts=now_ts,
            lookback_sec=lookback_sec,
        )
    out: list[float] = []
    if kind == "interval":
        sec = int(schedule.get("interval_sec") or 0)
        if sec <= 0:
            return []
        # 从 now 往回找对齐点
        t = now_ts - (now_ts % sec)
        while t > now_ts - lookback_sec:
            out.append(t)
            t -= sec
        return out
    if kind in ("daily", "weekly"):
        tstr = schedule.get("time") or "00:00"
        m = TIME_RE.match(tstr)
        if not m:
            return []
        hour, minute = int(m.group(1)), int(m.group(2))
        # UTC 近似：按 UTC 计算计划时刻（跨时区任务请在采集端换算后比较）
        base = datetime.fromtimestamp(now_ts, tz=timezone.utc)
        days: list[datetime] = []
        for delta in range(0, int(lookback_sec // 86400) + 3):
            day = (base - timedelta(days=delta)).replace(
                hour=hour, minute=minute, second=0, microsecond=0
            )
            if kind == "weekly":
                if day.isoweekday() != int(schedule.get("dow") or 1):
                    continue
            days.append(day)
        for d in days:
            ts = d.timestamp()
            if now_ts - lookback_sec <= ts <= now_ts:
                out.append(ts)
        return sorted(out)
    return []


class ExtTxService:
    def __init__(
        self,
        db: Database,
        *,
        incidents=None,
        notifier=None,
        pepper: str = "",
    ):
        self.db = db
        self._incidents = incidents
        self._notifier = notifier
        self.pepper = pepper or ""

    def set_incidents(self, incidents) -> None:
        self._incidents = incidents

    def set_notifier(self, notifier) -> None:
        self._notifier = notifier

    # ------------------------------------------------------------------
    # 校验
    # ------------------------------------------------------------------

    def _validate_fields(self, data: dict, *, partial: bool = False) -> dict:
        out: dict[str, Any] = {}

        def need(key: str, default: Any = None) -> bool:
            return (not partial) or (key in data) or (default is not None and key not in data)

        if not partial or "event_key" in data:
            ek = _as_str(data.get("event_key")).strip()
            if not ek or not EVENT_KEY_RE.match(ek):
                raise ExtTxError("bad_event_key", "event_key required, [A-Za-z0-9._:-] max 128")
            out["event_key"] = ek

        if not partial or "name" in data:
            name = _as_str(data.get("name")).strip()
            if not name or len(name) > MAX_NAME:
                raise ExtTxError("bad_name", f"name required, max {MAX_NAME}")
            out["name"] = name

        if "description" in data or not partial:
            desc = _as_str(data.get("description")).strip()
            if len(desc) > MAX_DESC:
                raise ExtTxError("bad_description", f"description max {MAX_DESC}")
            out["description"] = desc

        if "source_label" in data or not partial:
            sl = _as_str(data.get("source_label")).strip()
            if len(sl) > MAX_SOURCE:
                raise ExtTxError("bad_source_label", f"source_label max {MAX_SOURCE}")
            out["source_label"] = sl

        for k in ("asset_id", "object_id"):
            if k in data or not partial:
                v = _as_str(data.get(k)).strip()
                if len(v) > 128:
                    raise ExtTxError("bad_field", f"{k} too long")
                out[k] = v

        if "enabled" in data or not partial:
            out["enabled"] = 1 if data.get("enabled", 1) else 0

        if "watch_mode" in data or not partial:
            wm = _as_str(data.get("watch_mode")).strip().lower() or "off"
            if wm not in WATCH_MODES:
                raise ExtTxError("bad_watch_mode", f"watch_mode must be one of {WATCH_MODES}")
            out["watch_mode"] = wm

        if "grace_sec" in data or not partial:
            try:
                g = int(data.get("grace_sec", DEFAULT_GRACE_SEC))
            except (TypeError, ValueError):
                raise ExtTxError("bad_grace_sec", "grace_sec must be int")
            if not (0 <= g <= 86400):
                raise ExtTxError("bad_grace_sec", "grace_sec 0..86400")
            out["grace_sec"] = g

        if "expect_interval_sec" in data or not partial:
            try:
                iv = int(data.get("expect_interval_sec") or 0)
            except (TypeError, ValueError):
                raise ExtTxError("bad_interval", "expect_interval_sec must be int")
            if iv and not (MIN_INTERVAL_SEC <= iv <= MAX_INTERVAL_SEC):
                raise ExtTxError("bad_interval", "expect_interval_sec out of range")
            out["expect_interval_sec"] = iv

        if "timeout_sec" in data or not partial:
            try:
                to = int(data.get("timeout_sec") or 0)
            except (TypeError, ValueError):
                raise ExtTxError("bad_timeout", "timeout_sec must be int")
            if to and not (MIN_TIMEOUT_SEC <= to <= MAX_TIMEOUT_SEC):
                raise ExtTxError("bad_timeout", "timeout_sec out of range")
            out["timeout_sec"] = to

        if "resolve_delay_sec" in data or not partial:
            try:
                rd = int(data.get("resolve_delay_sec", DEFAULT_RESOLVE_DELAY_SEC) or 0)
            except (TypeError, ValueError):
                raise ExtTxError("bad_resolve_delay", "resolve_delay_sec must be int")
            if not (0 <= rd <= MAX_RESOLVE_DELAY_SEC):
                raise ExtTxError("bad_resolve_delay", f"resolve_delay_sec 0..{MAX_RESOLVE_DELAY_SEC}")
            out["resolve_delay_sec"] = rd

        if "schedule" in data or not partial:
            out["schedule"] = validate_schedule(data.get("schedule"))

        for flag in (
            "alert_on_failure",
            "alert_on_recovery",
            "alert_on_timeout",
            "alert_on_missing",
            "alert_on_collector",
        ):
            if flag in data or not partial:
                out[flag] = 1 if data.get(flag, 1) else 0

        return out

    # ------------------------------------------------------------------
    # 事务 CRUD
    # ------------------------------------------------------------------

    def create_transaction(self, data: dict, *, actor: str = "") -> dict:
        f = self._validate_fields(data, partial=False)
        t = now()
        tid = new_id("ext")
        try:
            self.db.execute(
                "INSERT INTO ext_transactions("
                " id, event_key, name, description, source_label, asset_id, object_id,"
                " enabled, watch_mode, grace_sec, expect_interval_sec, timeout_sec,"
                " resolve_delay_sec, schedule_json,"
                " alert_on_failure, alert_on_recovery, alert_on_timeout, alert_on_missing,"
                " alert_on_collector,"
                " created_at, updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    tid,
                    f["event_key"],
                    f["name"],
                    f["description"],
                    f["source_label"],
                    f["asset_id"],
                    f["object_id"],
                    f["enabled"],
                    f["watch_mode"],
                    f["grace_sec"],
                    f["expect_interval_sec"],
                    f["timeout_sec"],
                    f.get("resolve_delay_sec", DEFAULT_RESOLVE_DELAY_SEC),
                    json.dumps(f["schedule"], ensure_ascii=False),
                    f["alert_on_failure"],
                    f["alert_on_recovery"],
                    f["alert_on_timeout"],
                    f["alert_on_missing"],
                    f["alert_on_collector"],
                    t,
                    t,
                ),
            )
        except Exception as e:
            if "UNIQUE" in str(e).upper():
                raise ExtTxError("event_key_taken", f["event_key"]) from e
            raise
        self.db.audit("web_user", actor, "ext_tx_create", detail={"transaction_id": tid, "event_key": f["event_key"]})
        return self.get_transaction(tid) or {}

    def update_transaction(self, tid: str, data: dict, *, actor: str = "") -> dict:
        cur = self.db.query_one("SELECT * FROM ext_transactions WHERE id=?", (tid,))
        if not cur:
            raise ExtTxError("not_found", tid)
        f = self._validate_fields(data, partial=True)
        if "event_key" in f:
            other = self.db.query_one(
                "SELECT id FROM ext_transactions WHERE event_key=? AND id<>?",
                (f["event_key"], tid),
            )
            if other:
                raise ExtTxError("event_key_taken", f["event_key"])
        sets = []
        params: list[Any] = []
        for k, col in (
            ("event_key", "event_key"),
            ("name", "name"),
            ("description", "description"),
            ("source_label", "source_label"),
            ("asset_id", "asset_id"),
            ("object_id", "object_id"),
            ("enabled", "enabled"),
            ("watch_mode", "watch_mode"),
            ("grace_sec", "grace_sec"),
            ("expect_interval_sec", "expect_interval_sec"),
            ("timeout_sec", "timeout_sec"),
            ("resolve_delay_sec", "resolve_delay_sec"),
            ("alert_on_failure", "alert_on_failure"),
            ("alert_on_recovery", "alert_on_recovery"),
            ("alert_on_timeout", "alert_on_timeout"),
            ("alert_on_missing", "alert_on_missing"),
            ("alert_on_collector", "alert_on_collector"),
        ):
            if k in f:
                sets.append(f"{col}=?")
                params.append(f[k])
        if "schedule" in f:
            sets.append("schedule_json=?")
            params.append(json.dumps(f["schedule"], ensure_ascii=False))
        if not sets:
            return self.get_transaction(tid) or {}
        sets.append("updated_at=?")
        params.append(now())
        params.append(tid)
        self.db.execute(f"UPDATE ext_transactions SET {', '.join(sets)} WHERE id=?", tuple(params))
        self.db.audit(
            "web_user", actor, "ext_tx_update",
            detail={"transaction_id": tid, "fields": sorted(f.keys())},
        )
        return self.get_transaction(tid) or {}

    def set_enabled(self, tid: str, enabled: bool, *, actor: str = "") -> dict:
        return self.update_transaction(tid, {"enabled": 1 if enabled else 0}, actor=actor)

    def delete_transaction(self, tid: str, *, actor: str = "") -> dict:
        cur = self.db.query_one("SELECT * FROM ext_transactions WHERE id=?", (tid,))
        if not cur:
            raise ExtTxError("not_found", tid)
        open_inc = self.db.query_one(
            "SELECT id FROM ext_transactions WHERE id=? AND open_incident_id!=''",
            (tid,),
        )
        if open_inc:
            raise ExtTxError("has_open_incident", "存在未关闭 Incident，请先处理或改为禁用")
        # 兜底：episode 仍关联 open incident
        ep_open = self.db.query_one(
            "SELECT e.id FROM alert_episodes e JOIN incidents i ON i.id=e.incident_id"
            " WHERE e.labels_json LIKE ? AND i.status='open' LIMIT 1",
            (f'%{cur["event_key"]}%',),
        )
        if ep_open:
            raise ExtTxError("has_open_incident", "存在未关闭 Incident，请先处理或改为禁用")
        with self.db.tx() as conn:
            conn.execute("DELETE FROM ext_tokens WHERE transaction_id=?", (tid,))
            conn.execute("DELETE FROM ext_watch_marks WHERE transaction_id=?", (tid,))
            conn.execute("DELETE FROM ext_runs WHERE transaction_id=?", (tid,))
            conn.execute("DELETE FROM ext_transactions WHERE id=?", (tid,))
        self.db.audit("web_user", actor, "ext_tx_delete", detail={"transaction_id": tid})
        return {"ok": True}

    def list_transactions(self) -> list[dict]:
        rows = self.db.query("SELECT * FROM ext_transactions ORDER BY created_at ASC")
        return [self._tx_row(r) for r in rows]

    def get_transaction(self, tid: str) -> dict | None:
        r = self.db.query_one("SELECT * FROM ext_transactions WHERE id=?", (tid,))
        return self._tx_row(r) if r else None

    def get_by_event_key(self, event_key: str) -> dict | None:
        r = self.db.query_one("SELECT * FROM ext_transactions WHERE event_key=?", (event_key,))
        return self._tx_row(r) if r else None

    def _tx_row(self, row) -> dict:
        d = dict(row)
        try:
            d["schedule"] = json.loads(d.get("schedule_json") or "{}")
        except Exception:
            d["schedule"] = {}
        d.pop("schedule_json", None)
        d["enabled"] = bool(d.get("enabled"))
        for k in (
            "alert_on_failure",
            "alert_on_recovery",
            "alert_on_timeout",
            "alert_on_missing",
            "alert_on_collector",
        ):
            d[k] = bool(d.get(k))
        # 附带 token 摘要（不含明文/哈希）
        toks = self.db.query(
            "SELECT id, token_hint, created_at, revoked_at, last_used_at FROM ext_tokens"
            " WHERE transaction_id=? ORDER BY created_at DESC",
            (d["id"],),
        )
        d["tokens"] = [
            {
                "id": t["id"],
                "token_hint": t["token_hint"],
                "created_at": t["created_at"],
                "revoked_at": t["revoked_at"],
                "last_used_at": t["last_used_at"],
                "active": not t["revoked_at"],
            }
            for t in toks
        ]
        return d

    # ------------------------------------------------------------------
    # Token
    # ------------------------------------------------------------------

    def issue_token(self, tid: str, *, actor: str = "", rotated_from: str = "") -> dict:
        tx = self.db.query_one("SELECT id, event_key FROM ext_transactions WHERE id=?", (tid,))
        if not tx:
            raise ExtTxError("not_found", tid)
        raw = TOKEN_PREFIX + pysecrets.token_urlsafe(24)
        th = hash_token(raw, self.pepper)
        tok_id = new_id("extk")
        self.db.execute(
            "INSERT INTO ext_tokens(id, transaction_id, token_hash, token_hint, created_at, rotated_from)"
            " VALUES(?,?,?,?,?,?)",
            (tok_id, tid, th, raw[-4:], now(), rotated_from),
        )
        self.db.audit(
            "web_user", actor, "ext_token_issue",
            detail={"transaction_id": tid, "token_id": tok_id, "hint": raw[-4:]},
        )
        # 明文仅此一次返回
        return {
            "ok": True,
            "token_id": tok_id,
            "token": raw,
            "token_hint": raw[-4:],
            "event_key": tx["event_key"],
        }

    def revoke_token(self, token_id: str, *, actor: str = "") -> dict:
        row = self.db.query_one("SELECT * FROM ext_tokens WHERE id=?", (token_id,))
        if not row:
            raise ExtTxError("not_found", token_id)
        if row["revoked_at"]:
            return {"ok": True, "already_revoked": True}
        self.db.execute(
            "UPDATE ext_tokens SET revoked_at=? WHERE id=?", (now(), token_id)
        )
        self.db.audit(
            "web_user", actor, "ext_token_revoke",
            detail={"token_id": token_id, "hint": row["token_hint"]},
        )
        return {"ok": True}

    def rotate_token(self, tid: str, old_token_id: str = "", *, actor: str = "") -> dict:
        """无中断轮换：先发新 Token，再吊销指定旧 Token（不指定则保留旧的）。"""
        new = self.issue_token(tid, actor=actor, rotated_from=old_token_id)
        revoked = False
        if old_token_id:
            self.revoke_token(old_token_id, actor=actor)
            revoked = True
        new["revoked_old"] = revoked
        new["old_token_id"] = old_token_id
        return new

    def authenticate_token(self, raw: str) -> dict:
        raw = (raw or "").strip()
        if not raw or not raw.startswith(TOKEN_PREFIX):
            raise ExtTxError("unauthorized", "bad token")
        th = hash_token(raw, self.pepper)
        row = self.db.query_one(
            "SELECT t.*, x.event_key, x.enabled, x.id AS tx_id"
            " FROM ext_tokens t JOIN ext_transactions x ON x.id=t.transaction_id"
            " WHERE t.token_hash=?",
            (th,),
        )
        if not row:
            raise ExtTxError("unauthorized", "unknown token")
        if row["revoked_at"]:
            raise ExtTxError("unauthorized", "token revoked")
        if not row["enabled"]:
            raise ExtTxError("transaction_disabled", row["event_key"])
        try:
            self.db.execute(
                "UPDATE ext_tokens SET last_used_at=? WHERE id=?", (now(), row["id"])
            )
        except Exception:
            pass
        return {
            "token_id": row["id"],
            "transaction_id": row["transaction_id"],
            "event_key": row["event_key"],
            "token_hint": row["token_hint"],
        }

    # ------------------------------------------------------------------
    # 上报
    # ------------------------------------------------------------------

    def report(self, body: dict, *, token_hint: str = "", received_at: float | None = None) -> dict:
        """处理一次上报。body 已通过 JSON 解析。

        received_at：服务端接收时刻（漏跑判断只认它，不用客户端时间）。
        """
        if not isinstance(body, dict):
            raise ExtTxError("bad_json", "body must be object")

        event_key = _as_str(body.get("event_key")).strip()
        status = _as_str(body.get("status")).strip().lower()
        severity = _as_str(body.get("severity")).strip().lower() or "warning"
        message = _as_str(body.get("message")).strip()
        detail = _as_str(body.get("detail")).strip()
        run_id = _as_str(body.get("run_id")).strip()
        report_kind = _as_str(body.get("report_kind")).strip().lower() or "run"

        if not event_key or not EVENT_KEY_RE.match(event_key):
            raise ExtTxError("bad_event_key", event_key[:40])
        if status not in STATUSES:
            raise ExtTxError("bad_status", status)
        if severity not in SEVERITIES:
            raise ExtTxError("bad_severity", severity)
        if report_kind not in REPORT_KINDS:
            raise ExtTxError("bad_report_kind", report_kind)
        if len(message) > MAX_MESSAGE:
            raise ExtTxError("bad_message", "message too long")
        if len(detail) > MAX_DETAIL:
            raise ExtTxError("bad_detail", "detail too long")
        if not run_id or not RUN_ID_RE.match(run_id):
            raise ExtTxError("bad_run_id", run_id[:40])

        client_ts = parse_ts(body.get("timestamp"))
        return self.apply_report(
            event_key=event_key,
            status=status,
            severity=severity,
            message=message,
            detail=detail,
            run_id=run_id,
            report_kind=report_kind,
            client_ts=client_ts,
            token_hint=token_hint,
            received_at=received_at if received_at is not None else now(),
        )

    def apply_report(
        self,
        *,
        event_key: str,
        status: str,
        severity: str = "warning",
        message: str = "",
        detail: str = "",
        run_id: str,
        report_kind: str = "run",
        client_ts: float | None = None,
        token_hint: str = "",
        received_at: float | None = None,
    ) -> dict:
        tx_row = self.db.query_one("SELECT * FROM ext_transactions WHERE event_key=?", (event_key,))
        if not tx_row:
            raise ExtTxError("not_found", event_key)
        if not tx_row["enabled"]:
            raise ExtTxError("transaction_disabled", event_key)
        if status not in STATUSES:
            raise ExtTxError("bad_status", status)
        tx = self._tx_row(tx_row)

        t = received_at or now()
        tid = tx["id"]
        existing = self.db.query_one(
            "SELECT * FROM ext_runs WHERE transaction_id=? AND run_id=?",
            (tid, run_id),
        )

        # ---- 状态机：拒绝非法/迟到覆盖 ----
        if existing:
            old_status = existing["status"]
            allowed = LEGAL_TRANSITIONS.get(old_status, frozenset())
            if status not in allowed:
                return {
                    "ok": True,
                    "run_id": run_id,
                    "status": old_status,
                    "deduped": True,
                    "rejected": "illegal_transition",
                    "kept_status": old_status,
                }
            content_hash = self._content_hash(
                status, severity, message, detail, report_kind, client_ts
            )
            if existing["content_hash"] == content_hash and status == old_status:
                return {
                    "ok": True,
                    "run_id": run_id,
                    "status": old_status,
                    "deduped": True,
                }
            # 合法转换或同状态更新 detail
            self.db.execute(
                "UPDATE ext_runs SET status=?, severity=?, message=?, detail=?,"
                " client_ts=?, reported_at=?, content_hash=?, updated_at=?"
                " WHERE id=?",
                (
                    status, severity, message, detail,
                    client_ts, t, content_hash, t, existing["id"],
                ),
            )
            created = False
            changed = status != old_status or existing["content_hash"] != content_hash
            run_db_id = existing["id"]
        else:
            content_hash = self._content_hash(
                status, severity, message, detail, report_kind, client_ts
            )
            run_db_id = new_id("run")
            self.db.execute(
                "INSERT INTO ext_runs("
                " id, transaction_id, run_id, status, severity, message, detail,"
                " report_kind, client_ts, reported_at, content_hash, created_at, updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run_db_id, tid, run_id, status, severity, message, detail,
                    report_kind, client_ts, t, content_hash, t, t,
                ),
            )
            created = True
            changed = True

        # ---- 事务缓存：只跟随最新一次接收 ----
        self.db.execute(
            "UPDATE ext_transactions SET last_status=?, last_run_id=?, last_report_at=?,"
            " last_success_at=?, last_failure_at=?, updated_at=? WHERE id=?",
            (
                status if report_kind == "run" else tx["last_status"],
                run_id,
                t,
                t if (report_kind == "run" and status == "success") else (tx["last_success_at"] or 0),
                t if (report_kind == "run" and status in ("failure", "timeout")) else (tx["last_failure_at"] or 0),
                t,
                tid,
            ),
        )
        # 收到上报即清除「失联」幂等标记，便于下次失联再次告警
        try:
            self.db.execute(
                "DELETE FROM ext_watch_marks WHERE transaction_id=?"
                " AND mark_key IN ('missing_hb','missing_sched')",
                (tid,),
            )
        except Exception:
            pass

        # ---- Episode / Incident / 通知 ----
        episode_id = ""
        try:
            if report_kind == "collector":
                episode_id = self._handle_collector(tx, status=status, severity=severity,
                                                    message=message, detail=detail,
                                                    run_id=run_id, t=t)
            else:
                episode_id = self._handle_business(
                    tx, status=status, severity=severity, message=message,
                    detail=detail, run_id=run_id, t=t,
                )
            self._refresh_tx_cache(tid, event_key)
        except Exception as e:
            # 收敛失败不影响上报入库；记审计便于排障（不含 Token）
            episode_id = ""
            try:
                self.db.audit(
                    "system", "exttx", "ext_episode_sync_error",
                    detail={"event_key": event_key, "run_id": run_id, "error": str(e)[:200]},
                )
            except Exception:
                pass
            # 尽力恢复缓存一致：以库内 episode 为准
            try:
                self._refresh_tx_cache(tid, event_key)
            except Exception:
                pass

        if episode_id:
            self.db.execute(
                "UPDATE ext_runs SET episode_id=? WHERE id=?", (episode_id, run_db_id)
            )

        return {
            "ok": True,
            "run_id": run_id,
            "status": status,
            "deduped": (not created) and (not changed),
            "episode_id": episode_id,
        }

    def _content_hash(
        self, status: str, severity: str, message: str, detail: str,
        report_kind: str, client_ts: float | None,
    ) -> str:
        raw = json.dumps(
            [status, severity, message, detail, report_kind, client_ts],
            ensure_ascii=False, separators=(",", ":"),
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    # ------------------------------------------------------------------
    # Episode 收敛
    # ------------------------------------------------------------------

    def _problem_fp(self, event_key: str, problem: str) -> str:
        """episode 指纹：不含 run_id / severity，持续失败共用同一 episode。"""
        from .alertmanager import fingerprint_of

        return fingerprint_of(
            {
                "alertname": f"ExtTx_{problem}",
                "ext_event_key": event_key,
                "ext_problem": problem,
                "source": "ext_tx",
            }
        )

    def _find_episode(self, event_key: str, problem: str) -> dict | None:
        fp = self._problem_fp(event_key, problem)
        row = self.db.query_one(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND fingerprint=?"
            " ORDER BY first_seen DESC LIMIT 1",
            (fp,),
        )
        return dict(row) if row else None

    def _upsert_episode(
        self,
        *,
        event_key: str,
        problem: str,
        status: str,
        severity: str,
        message: str,
        detail: str,
        t: float,
        labels_extra: dict | None = None,
    ) -> str:
        from .alertmanager import upsert_episode

        labels = {
            "alertname": f"ExtTx_{problem}",
            "ext_event_key": event_key,
            "ext_problem": problem,
            "severity": severity,
            "source": "ext_tx",
            "asset": (labels_extra or {}).get("asset", ""),
        }
        fp = self._problem_fp(event_key, problem)
        annotations = {
            "message": message,
            "detail": detail,
            "event_key": event_key,
            "problem": problem,
        }
        try:
            ep_id, _created, _prev, _new = upsert_episode(
                self.db,
                source_id="ext_tx",
                fingerprint=fp,
                labels=labels,
                annotations=annotations,
                status=status,
                source_state="firing" if status == "firing" else status,
                t=t,
                alertname=f"ExtTx_{problem}",
                asset_id=(labels_extra or {}).get("asset", ""),
                object_id=event_key,
            )
            return ep_id
        except Exception as e:
            raise ExtTxError("episode_insert_failed", f"{event_key}/{problem}") from e

    def _resolve_episode(self, event_key: str, problem: str, t: float) -> str:
        """把 problem episode 置 resolved，并走 on_episode_resolved。"""
        fp = self._problem_fp(event_key, problem)
        row = self.db.query_one(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND fingerprint=?"
            " AND status='firing' ORDER BY first_seen DESC LIMIT 1",
            (fp,),
        )
        if not row:
            return ""
        ep_id = row["id"]
        self.db.execute(
            "UPDATE alert_episodes SET status='resolved', source_state='resolved',"
            " last_seen=?, last_reconciled_at=? WHERE id=?",
            (t, t, ep_id),
        )
        inc_id = row["incident_id"] or ""
        if self._incidents and inc_id:
            try:
                self._incidents.on_episode_resolved(ep_id)
            except Exception:
                pass
            # 外部上报的成功即恢复证据：无 firing/无阻塞时收敛 Incident
            try:
                self._finalize_ext_recovery(inc_id, ep_id, t)
            except Exception:
                pass
        return ep_id

    def _finalize_ext_recovery(self, inc_id: str, episode_id: str, t: float) -> None:
        """外部事务成功 → 在无阻塞时把 Incident 标为 recovered。

        通用 reconcile 要求 verification passed 才自动恢复；
        外部上报的 success 本身就是恢复证据，这里补齐该语义，
        不改动全局 reconcile 规则。
        """
        if not inc_id:
            return
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not inc:
            return
        if inc["status"] == "open":
            # exttx 语义：proposed/approved 也阻塞自动恢复
            if self._incidents and self._incidents.has_blocking_obligations(
                inc_id, include_proposed=True
            ):
                return
            with self.db.tx() as conn:
                conn.execute(
                    "UPDATE incidents SET status='resolved', stage='done', outcome='recovered',"
                    " resolution_basis='ext_tx_success', resolved_at=?, updated_at=?"
                    " WHERE id=? AND status='open'",
                    (t, t, inc_id),
                )
                exists = conn.execute(
                    "SELECT 1 FROM events WHERE incident_id=? AND type='incident_resolved'"
                    " AND payload_json LIKE ?",
                    (inc_id, f"%{episode_id}%",),
                ).fetchone()
                if not exists:
                    conn.execute(
                        "INSERT INTO events(incident_id, at, type, title, payload_json)"
                        " VALUES(?,?,?,?,?)",
                        (
                            inc_id, t, "incident_resolved",
                            "external transaction recovered",
                            json.dumps(
                                {
                                    "episode_id": episode_id,
                                    "basis": "ext_tx_success",
                                },
                                ensure_ascii=False,
                            ),
                        ),
                    )
        # 无论上面收敛还是 on_episode_resolved 已闭环，都要发恢复通知
        self._notify_lifecycle(inc_id, "incident_resolved")

    def _notify_lifecycle(self, inc_id: str, event_type: str) -> None:
        if not self._notifier or not inc_id:
            return
        try:
            ev = self.db.query_one(
                "SELECT id FROM events WHERE incident_id=? AND type=?"
                " ORDER BY id DESC LIMIT 1",
                (inc_id, event_type),
            )
            if not ev:
                return
            body = f"[Ayana] 外部事务事件 {inc_id} {event_type}"
            self._notifier.enqueue_for_event(ev["id"], body=body, typ=event_type)
        except Exception:
            pass

    def _do_recover(self, tx: dict, t: float) -> None:
        """真正收敛：resolve episodes + 关 Incident + 清 pending。"""
        event_key = tx["event_key"]
        try:
            for problem in (PROBLEM_FAILURE, PROBLEM_TIMEOUT, PROBLEM_MISSING):
                self._resolve_episode(event_key, problem, t)
        finally:
            self.db.execute(
                "UPDATE ext_transactions SET pending_resolve_at=0,"
                " updated_at=? WHERE id=?",
                (t, tx["id"]),
            )
            self._refresh_tx_cache(tx["id"], event_key)

    def _cancel_pending_resolve(self, tid: str) -> None:
        """等待恢复期间再次失败：取消防抖，保持打开。"""
        self.db.execute(
            "UPDATE ext_transactions SET pending_resolve_at=0 WHERE id=? AND pending_resolve_at>0",
            (tid,),
        )

    def _refresh_tx_cache(self, tid: str, event_key: str) -> None:
        """按库内 episode 回写 open_incident_id，避免同步半途失败留下脏缓存。"""
        try:
            row = self.db.query_one(
                "SELECT incident_id FROM alert_episodes WHERE source_id='ext_tx'"
                " AND status='firing' AND incident_id!=''"
                " AND labels_json LIKE ? ORDER BY last_seen DESC LIMIT 1",
                (f'%{event_key}%',),
            )
            inc = (row["incident_id"] if row else "") or ""
            self.db.execute(
                "UPDATE ext_transactions SET open_incident_id=?, updated_at=? WHERE id=?",
                (inc, now(), tid),
            )
        except Exception:
            pass

    def _schedule_or_recover(self, tx: dict, *, problems: tuple[str, ...], t: float) -> None:
        """成功：resolve_delay_sec>0 则挂起防抖，否则立即收敛。"""
        delay = int(tx.get("resolve_delay_sec") or 0)
        if delay <= 0:
            try:
                for problem in problems:
                    self._resolve_episode(tx["event_key"], problem, t)
            finally:
                # 半途失败也要清 pending，缓存稍后统一刷新
                self.db.execute(
                    "UPDATE ext_transactions SET pending_resolve_at=0,"
                    " updated_at=? WHERE id=?",
                    (t, tx["id"]),
                )
                self._refresh_tx_cache(tx["id"], tx["event_key"])
            return
        self.db.execute(
            "UPDATE ext_transactions SET pending_resolve_at=?, updated_at=? WHERE id=?",
            (t + delay, t, tx["id"]),
        )
        self.db.event(
            "ext_recovery_pending",
            f"recovery pending {tx.get('event_key','')}",
            incident_id=tx.get("open_incident_id") or "",
            payload={
                "transaction_id": tx["id"],
                "event_key": tx.get("event_key"),
                "resolve_delay_sec": delay,
                "due_at": t + delay,
            },
        )

    def _handle_business(
        self,
        tx: dict,
        *,
        status: str,
        severity: str,
        message: str,
        detail: str,
        run_id: str,
        t: float,
    ) -> str:
        event_key = tx["event_key"]
        if status == "success":
            # 成功：收敛 failure / timeout / missing；可配置防抖延迟关闭
            self._schedule_or_recover(
                tx,
                problems=(PROBLEM_FAILURE, PROBLEM_TIMEOUT, PROBLEM_MISSING),
                t=t,
            )
            return ""

        if status in ("failure", "timeout"):
            # 失败立即取消未完成的恢复防抖
            self._cancel_pending_resolve(tx["id"])
            problem = PROBLEM_FAILURE if status == "failure" else PROBLEM_TIMEOUT
            # failure 时顺带清 timeout 旧 episode，避免双告警
            if status == "failure":
                self._resolve_episode(event_key, PROBLEM_TIMEOUT, t)
            alert_on = (
                tx.get("alert_on_failure", 1)
                if status == "failure"
                else tx.get("alert_on_timeout", 1)
            )
            ep_id = self._upsert_episode(
                event_key=event_key,
                problem=problem,
                status="firing",
                severity=severity,
                message=message,
                detail=detail,
                t=t,
                labels_extra={"asset": tx.get("asset_id") or ""},
            )
            if alert_on and self._incidents:
                try:
                    before = self.db.query_one(
                        "SELECT incident_id FROM alert_episodes WHERE id=?", (ep_id,)
                    )
                    inc_id = self._incidents.upsert_from_episode(ep_id) or ""
                    if inc_id:
                        self.db.execute(
                            "UPDATE ext_runs SET incident_id=? WHERE run_id=? AND transaction_id=?",
                            (inc_id, run_id, tx["id"]),
                        )
                        self.db.execute(
                            "UPDATE ext_transactions SET open_incident_id=? WHERE id=?",
                            (inc_id, tx["id"]),
                        )
                        self._notify_lifecycle(inc_id, "incident_opened")
                        self._notify_lifecycle(inc_id, "incident_reopened")
                except Exception:
                    pass
            return ep_id

        # running / unknown（业务侧）：不打断 failure 语义；unknown 仅记 run
        return ""

    def _handle_collector(
        self,
        tx: dict,
        *,
        status: str,
        severity: str,
        message: str,
        detail: str,
        run_id: str,
        t: float,
    ) -> str:
        """采集器健康上报：失败/unknown = 监控异常，成功 = 采集恢复。

        不得记为业务失败，也不得关闭业务 failure episode。
        """
        event_key = tx["event_key"]
        if status == "success":
            self._schedule_or_recover(tx, problems=(PROBLEM_COLLECTOR,), t=t)
            return ""
        if status in ("failure", "timeout", "unknown"):
            self._cancel_pending_resolve(tx["id"])
            alert_on = tx.get("alert_on_collector", 1)
            ep_id = self._upsert_episode(
                event_key=event_key,
                problem=PROBLEM_COLLECTOR,
                status="firing",
                severity=severity or "warning",
                message=message or "采集器异常",
                detail=detail,
                t=t,
                labels_extra={"asset": tx.get("asset_id") or ""},
            )
            if alert_on and self._incidents:
                try:
                    inc_id = self._incidents.upsert_from_episode(ep_id) or ""
                    if inc_id:
                        self.db.execute(
                            "UPDATE ext_transactions SET open_incident_id=? WHERE id=?",
                            (inc_id, tx["id"]),
                        )
                        self._notify_lifecycle(inc_id, "incident_opened")
                        self._notify_lifecycle(inc_id, "incident_reopened")
                except Exception:
                    pass
            return ep_id
        return ""

    # ------------------------------------------------------------------
    # Run 查询
    # ------------------------------------------------------------------

    def list_runs(self, tid: str, *, limit: int = 50) -> list[dict]:
        limit = max(1, min(200, int(limit)))
        rows = self.db.query(
            "SELECT * FROM ext_runs WHERE transaction_id=?"
            " ORDER BY reported_at DESC, id DESC LIMIT ?",
            (tid, limit),
        )
        return [dict(r) for r in rows]

    def get_run(self, tid: str, run_id: str) -> dict | None:
        r = self.db.query_one(
            "SELECT * FROM ext_runs WHERE transaction_id=? AND run_id=?",
            (tid, run_id),
        )
        return dict(r) if r else None

    # ------------------------------------------------------------------
    # 失联 / 超时检测
    # ------------------------------------------------------------------

    def _mark_once(self, tid: str, mark_key: str) -> bool:
        """幂等标记：True 表示首次，应告警。"""
        try:
            self.db.execute(
                "INSERT INTO ext_watch_marks(transaction_id, mark_key, created_at)"
                " VALUES(?,?,?)",
                (tid, mark_key, now()),
            )
            return True
        except Exception:
            return False

    def watch_tick(self, *, now_ts: float | None = None) -> dict:
        """后台扫描：episode 补偿 + running 超时 + 心跳失联 + 计划漏跑 + 恢复防抖到期。"""
        t = now_ts if now_ts is not None else now()
        result = {"timeouts": 0, "missing": 0, "missed": 0, "recovered": 0, "compensated": 0}
        rows = self.db.query("SELECT * FROM ext_transactions WHERE enabled=1")
        for row in rows:
            tx = self._tx_row(row)
            result["compensated"] += self._compensate_missing_episodes(tx, t=t)
            result["recovered"] += self._check_pending_resolve(tx, t=t)
            result["timeouts"] += self._check_timeouts(tx, t=t)
            mode = tx.get("watch_mode") or "off"
            if mode == "heartbeat":
                result["missing"] += self._check_heartbeat(tx, t=t)
            elif mode == "schedule":
                result["missed"] += self._check_schedule(tx, t=t)
        return result

    def _compensate_missing_episodes(self, tx: dict, *, t: float) -> int:
        """Run 已入账但 episode 同步失败：按最近失败 Run 补建 episode/Incident。

        只补「仍处于 failure/timeout 且没有 firing episode」的情况；
        历史失败若已被 success 收敛则不重建。
        """
        if tx.get("last_status") not in ("failure", "timeout"):
            return 0
        problem = PROBLEM_FAILURE if tx.get("last_status") == "failure" else PROBLEM_TIMEOUT
        fp = self._problem_fp(tx["event_key"], problem)
        firing = self.db.query_one(
            "SELECT id FROM alert_episodes WHERE source_id='ext_tx' AND fingerprint=?"
            " AND status='firing' LIMIT 1",
            (fp,),
        )
        if firing:
            return 0
        run = self.db.query_one(
            "SELECT * FROM ext_runs WHERE transaction_id=? AND status=?"
            " ORDER BY reported_at DESC LIMIT 1",
            (tx["id"], tx["last_status"]),
        )
        if not run:
            return 0
        try:
            ep_id = self._upsert_episode(
                event_key=tx["event_key"],
                problem=problem,
                status="firing",
                severity=run["severity"] or "warning",
                message=run["message"] or "compensated from run",
                detail=run["detail"] or f"run_id={run['run_id']}",
                t=t,
                labels_extra={"asset": tx.get("asset_id") or ""},
            )
            if ep_id:
                self.db.execute(
                    "UPDATE ext_runs SET episode_id=? WHERE id=? AND (episode_id IS NULL OR episode_id='')",
                    (ep_id, run["id"]),
                )
                if tx.get("alert_on_failure", 1) or tx.get("alert_on_timeout", 1):
                    inc_id = self._incidents.upsert_from_episode(ep_id) if self._incidents else ""
                    if inc_id:
                        self.db.execute(
                            "UPDATE ext_runs SET incident_id=? WHERE id=?", (inc_id, run["id"])
                        )
                        self._notify_lifecycle(inc_id, "incident_opened")
                        self._notify_lifecycle(inc_id, "incident_reopened")
                self._refresh_tx_cache(tx["id"], tx["event_key"])
                try:
                    self.db.audit(
                        "system", "exttx", "ext_episode_compensated",
                        detail={
                            "transaction_id": tx["id"],
                            "event_key": tx["event_key"],
                            "run_id": run["run_id"],
                            "episode_id": ep_id,
                        },
                    )
                except Exception:
                    pass
                return 1
        except Exception:
            return 0
        return 0

    def _check_pending_resolve(self, tx: dict, *, t: float) -> int:
        """恢复防抖到期：执行真正收敛。"""
        due = float(tx.get("pending_resolve_at") or 0)
        if due <= 0 or due > t:
            return 0
        # 再确认期间没有新失败（双保险）
        if tx.get("last_status") in ("failure", "timeout"):
            self._cancel_pending_resolve(tx["id"])
            return 0
        try:
            self._do_recover(tx, t)
            return 1
        except Exception:
            return 0

    def _check_timeouts(self, tx: dict, *, t: float) -> int:
        timeout_sec = int(tx.get("timeout_sec") or 0)
        if timeout_sec <= 0:
            return 0
        n = 0
        rows = self.db.query(
            "SELECT * FROM ext_runs WHERE transaction_id=? AND status='running'"
            " AND reported_at < ?",
            (tx["id"], t - timeout_sec),
        )
        for r in rows:
            mark = f"timeout:{r['run_id']}"
            if not self._mark_once(tx["id"], mark):
                continue
            try:
                self.apply_report(
                    event_key=tx["event_key"],
                    status="timeout",
                    severity="warning",
                    message=f"执行超时（>{timeout_sec}s）",
                    detail=f"run_id={r['run_id']} 超过 timeout_sec 未收到终态",
                    run_id=r["run_id"],
                    report_kind="run",
                    received_at=t,
                )
                n += 1
            except Exception:
                pass
        return n

    def _check_heartbeat(self, tx: dict, *, t: float) -> int:
        interval = int(tx.get("expect_interval_sec") or 0)
        if interval <= 0:
            return 0
        grace = int(tx.get("grace_sec") or DEFAULT_GRACE_SEC)
        last = float(tx.get("last_report_at") or 0)
        if last and (t - last) <= interval + grace:
            return 0
        if not last and (t - float(tx.get("created_at") or t)) <= interval + grace:
            return 0
        mark = "missing_hb"
        if not self._mark_once(tx["id"], mark):
            return 0
        if not tx.get("alert_on_missing", 1):
            return 0
        try:
            ep_id = self._upsert_episode(
                event_key=tx["event_key"],
                problem=PROBLEM_MISSING,
                status="firing",
                severity="warning",
                message="心跳失联",
                detail=f"超过 {interval + grace}s 未收到任何上报",
                t=t,
                labels_extra={"asset": tx.get("asset_id") or ""},
            )
            if self._incidents:
                inc_id = self._incidents.upsert_from_episode(ep_id) or ""
                if inc_id:
                    self.db.execute(
                        "UPDATE ext_transactions SET open_incident_id=? WHERE id=?",
                        (inc_id, tx["id"]),
                    )
                    self._notify_lifecycle(inc_id, "incident_opened")
                    self._notify_lifecycle(inc_id, "incident_reopened")
            return 1
        except Exception:
            return 0

    def _check_schedule(self, tx: dict, *, t: float) -> int:
        schedule = tx.get("schedule") or {}
        if not schedule:
            return 0
        grace = int(tx.get("grace_sec") or DEFAULT_GRACE_SEC)
        # 回看 2 个周期，避免扫描间隙漏检
        if schedule.get("kind") == "interval":
            lookback = int(schedule.get("interval_sec") or 3600) * 2
        elif schedule.get("kind") == "cron":
            # cron：回看 3 天，覆盖日/周任务
            lookback = 3 * 86400
        else:
            lookback = 2 * 86400
        expected = expected_run_times(schedule, now_ts=t, lookback_sec=lookback)
        n = 0
        for exp in expected:
            if t < exp + grace:
                continue  # 尚未到宽限截止
            # 该时刻附近是否有上报（含迟到 grace 内）
            window_start = exp - max(300, grace // 2)
            window_end = exp + grace
            hit = self.db.query_one(
                "SELECT id FROM ext_runs WHERE transaction_id=?"
                " AND (reported_at BETWEEN ? AND ? OR (client_ts IS NOT NULL AND client_ts BETWEEN ? AND ?))"
                " LIMIT 1",
                (tx["id"], window_start, window_end, window_start, window_end),
            )
            if hit:
                continue
            mark = f"missed:{int(exp)}"
            if not self._mark_once(tx["id"], mark):
                continue
            if not tx.get("alert_on_missing", 1):
                continue
            try:
                ep_id = self._upsert_episode(
                    event_key=tx["event_key"],
                    problem=PROBLEM_MISSING,
                    status="firing",
                    severity="warning",
                    message="计划任务漏跑",
                    detail=f"计划时刻 {datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()} 后 {grace}s 内无执行记录",
                    t=t,
                    labels_extra={"asset": tx.get("asset_id") or ""},
                )
                if self._incidents:
                    inc_id = self._incidents.upsert_from_episode(ep_id) or ""
                    if inc_id:
                        self.db.execute(
                            "UPDATE ext_transactions SET open_incident_id=? WHERE id=?",
                            (inc_id, tx["id"]),
                        )
                        self._notify_lifecycle(inc_id, "incident_opened")
                        self._notify_lifecycle(inc_id, "incident_reopened")
                n += 1
            except Exception:
                pass
        return n
