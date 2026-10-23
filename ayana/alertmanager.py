"""Alertmanager webhook 接收与状态对账（P1-03）。

分离三件事：
- 上游当前说什么（source_state / source_health）
- Ayana 最近观察到什么（last_seen / last_reconciled_at）
- Incident 自己最终判断什么（IncidentService.reconcile）

硬约束：
- AM 本次未看到 ≠ 恢复；只记录 not_seen / awaiting_confirmation
- 无效时间/无效 source 数据 → quarantine，阻止自动执行
- 时间统一 UTC 规范格式
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from .db import Database, new_id, now

MAX_ALERTS_PER_HOOK = 200

# alertname → problem family（确定性、可解释；不绑定特定环境业务名）
PROBLEM_FAMILY = {
    "targetdown": "availability",
    "prometheusjobmissing": "availability",
    "servicedown": "availability",
    "probe_failed": "availability",
    "instance_down": "availability",
    "diskusagehigh": "capacity",
    "memorylow": "capacity",
    "cpuhog": "capacity",
    "portbindfailed": "capacity",
    "mysqldown": "availability",
    "mysqlreplicationiorunning": "availability",
    "mysqlreplicationsqlrunning": "availability",
    "mysqlreplicationlag": "capacity",
    "mysqlmetricsmissing": "availability",
}
DEFAULT_FAMILY = "other"

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"(Z|[+-]\d{2}:?\d{2})?$"
)


def fingerprint_of(labels: dict) -> str:
    raw = json.dumps(labels, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def problem_family_of(alertname: str, labels: dict | None = None) -> str:
    key = (alertname or "").strip().lower().replace(" ", "").replace("_", "")
    # 先精确/别名，再前缀
    for k, v in PROBLEM_FAMILY.items():
        kk = k.replace("_", "").replace(" ", "")
        if key == kk:
            return v
    for k, v in PROBLEM_FAMILY.items():
        kk = k.replace("_", "").replace(" ", "")
        if key.startswith(kk) or kk in key:
            return v
    labels = labels or {}
    sev = (labels.get("severity") or "").lower()
    if sev in ("critical", "warning"):
        return "availability"
    return DEFAULT_FAMILY


def normalize_starts_at(starts_at: str) -> tuple[str, str]:
    """规范化 UTC startsAt。

    返回 (norm, status):
      norm:  'YYYY-MM-DDTHH:MM:SSZ' 或 'unknown:<raw>'
      status: 'ok' | 'unknown' | 'invalid'
    无效数据不得静默污染；调用方应 quarantine。
    """
    raw = (starts_at or "").strip()
    if not raw or raw.lower() in ("unknown", "none", "null"):
        return "unknown", "unknown"
    m = _ISO_RE.match(raw)
    if not m:
        return f"invalid:{raw[:40]}", "invalid"
    try:
        year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hour, minute, sec = int(m.group(4)), int(m.group(5)), int(m.group(6))
        frac = m.group(7) or "0"
        micro = int((frac + "000000")[:6])
        tz = m.group(8) or "Z"
        if tz == "Z":
            tzinfo = timezone.utc
        else:
            sign = 1 if tz[0] == "+" else -1
            tz = tz.replace(":", "")
            off_h = int(tz[1:3])
            off_m = int(tz[3:5]) if len(tz) >= 5 else 0
            from datetime import timedelta

            tzinfo = timezone(sign * timedelta(hours=off_h, minutes=off_m))
        dt = datetime(year, month, day, hour, minute, sec, micro, tzinfo=tzinfo)
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "ok"
    except Exception:
        return f"invalid:{raw[:40]}", "invalid"


def upsert_episode(
    db,
    *,
    source_id: str,
    fingerprint: str,
    labels: dict | None = None,
    annotations: dict | None = None,
    status: str = "firing",
    source_state: str = "firing",
    t: float,
    alertname: str = "",
    asset_id: str = "",
    object_id: str = "",
    source_health: str = "ok",
    problem_family: str = "",
    canonical_object: str = "",
    quarantine_reason: str = "",
    silenced: int = 0,
    inhibited: int = 0,
    starts_at: str = "",
    starts_at_norm: str = "",
) -> tuple[str, bool, str, str]:
    """统一 alert_episodes 写入入口（P1-1）。

    幂等：同 fingerprint 未解决时更新而不是新建。
    starts_at_norm 参与 UNIQUE(source_id, fingerprint, starts_at_norm)；
    无现成行可更新时用退避序列插入以避免同秒冲突。

    返回 (episode_id, created, prev_status, new_status)。
    """
    labels = dict(labels or {})
    annotations = dict(annotations or {})
    if not alertname:
        alertname = labels.get("alertname") or "unknown"
    if not asset_id:
        asset_id = labels.get("asset") or ""
    if not problem_family:
        problem_family = problem_family_of(alertname, labels)
    if not canonical_object:
        canonical_object = object_id or labels.get("service") or ""

    # starts_at_norm：仅当调用方显式传入时才做精确键命中（alertmanager 迟到告警场景）
    explicit_norm = bool(starts_at_norm)
    if not starts_at_norm:
        if starts_at:
            starts_at_norm, _st = normalize_starts_at(starts_at)
        else:
            starts_at_norm = str(int(t))

    def _fetch_one(sql: str, params: tuple):
        cur = db.execute(sql, params)
        return cur.fetchone()

    row = None
    if explicit_norm:
        # alertmanager 语义：精确唯一键命中（含 resolved → 不复活）
        row = _fetch_one(
            "SELECT * FROM alert_episodes WHERE source_id=? AND fingerprint=?"
            " AND starts_at_norm=?",
            (source_id, fingerprint, starts_at_norm),
        )
    else:
        # exttx/checks 语义：同 fingerprint 未解决 → 幂等更新（不新建）
        row = _fetch_one(
            "SELECT * FROM alert_episodes WHERE source_id=? AND fingerprint=?"
            " AND status='firing' ORDER BY first_seen DESC LIMIT 1",
            (source_id, fingerprint),
        )
    if row:
        row_d = dict(row)
        new_status = status
        # 已 resolved 的 episode 不因迟到 firing 自动复活
        if row_d["status"] == "resolved" and status == "firing":
            new_status = "resolved"
        prev_status = row_d["status"]
        db.execute(
            "UPDATE alert_episodes SET last_seen=?, receive_count=receive_count+1,"
            " status=?, source_state=?, annotations_json=?, labels_json=?,"
            " last_reconciled_at=?, silenced=?, inhibited=?, source_health=?,"
            " problem_family=?, canonical_object=?, quarantine_reason=?"
            " WHERE id=?",
            (
                t, new_status, source_state,
                json.dumps(annotations, ensure_ascii=False),
                json.dumps(labels, ensure_ascii=False),
                t, silenced, inhibited, source_health,
                problem_family, canonical_object, quarantine_reason,
                row_d["id"],
            ),
        )
        return row_d["id"], False, prev_status, new_status

    # 3) 新建：starts_at_norm 退避插入（同秒冲突时降级微秒 / 短后缀）
    eid = new_id("ep")
    insert_sql = (
        "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm,"
        " alertname, status, asset_id, object_id, first_seen, last_seen,"
        " receive_count, labels_json, annotations_json, source_state,"
        " last_reconciled_at, silenced, inhibited, source_health, problem_family,"
        " canonical_object, quarantine_reason)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    )
    base_args = [
        eid, source_id, fingerprint, starts_at_norm,
        alertname, status, asset_id, object_id, t, t, 1,
        json.dumps(labels, ensure_ascii=False),
        json.dumps(annotations, ensure_ascii=False),
        source_state, t, silenced, inhibited, source_health,
        problem_family, canonical_object, quarantine_reason,
    ]
    candidates = [starts_at_norm]
    if starts_at_norm == str(int(t)):
        candidates += [f"{t:.6f}", f"{t:.6f}:{eid[-4:]}"]
    else:
        candidates += [str(int(t)), f"{t:.6f}", f"{t:.6f}:{eid[-4:]}"]
    last_err: Exception | None = None
    for cand in candidates:
        args = list(base_args)
        args[3] = cand
        try:
            db.execute(insert_sql, tuple(args))
            return eid, True, "", status
        except Exception as e:
            last_err = e
            continue
    raise last_err if last_err else RuntimeError("episode_insert_failed")


class AlertIngest:
    def __init__(self, db: Database, source_id: str = "alertmanager", incidents=None, notifier=None):
        self.db = db
        self.source_id = source_id
        self._incidents = incidents
        self._notifier = notifier

    def set_incidents(self, incidents) -> None:
        self._incidents = incidents

    def set_notifier(self, notifier) -> None:
        self._notifier = notifier

    def _row_dict(self, row) -> dict:
        return dict(row) if row is not None else {}

    def _sync_incident(self, episode_id: str) -> None:
        """把 episode 同步到 Incident；转换与通知义务尽量同事务。

        opened 仅在真正新建/重开 Incident 时发出，不随 episode 附加重复发。
        """
        if not self._incidents:
            return
        try:
            ep = self._row_dict(
                self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (episode_id,))
            )
            if not ep:
                return
            # quarantine 不进入自动派发/自动收敛
            if ep.get("source_state") == "quarantine" or ep.get("source_health") == "quarantine":
                return
            if not ep.get("incident_id"):
                before_open = self.db.query_one(
                    "SELECT COUNT(*) AS n FROM incidents WHERE status='open'"
                    " AND asset_id=? AND object_id=?",
                    (ep.get("asset_id") or "", ep.get("object_id") or ""),
                )
                inc_id = self._incidents.upsert_from_episode(episode_id)
                ep = self._row_dict(
                    self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (episode_id,))
                )
                after_open = self.db.query_one(
                    "SELECT COUNT(*) AS n FROM incidents WHERE status='open'"
                    " AND asset_id=? AND object_id=?",
                    (ep.get("asset_id") or "", ep.get("object_id") or ""),
                )
                if inc_id:
                    last_type = self.db.query_one(
                        "SELECT type FROM events WHERE incident_id=? ORDER BY id DESC LIMIT 1",
                        (inc_id,),
                    )
                    is_reopen = bool(last_type and last_type["type"] == "incident_reopened")
                    if is_reopen:
                        # 生命周期事件都交给 Notifier 判断静默窗口，补偿也遵守同一意图。
                        self._notify_incident(inc_id, "reopened", episode_id=episode_id)
                    elif not before_open or after_open["n"] > before_open["n"]:
                        self._notify_incident(inc_id, "opened", episode_id=episode_id)
                    elif self._quiet_elapsed(inc_id, episode_id=episode_id):
                        # 并入已打开事件：安静满 1 小时后再响才推，避免同一事件刷屏
                        self._notify_refire(inc_id, episode_id=episode_id)
            if ep.get("status") == "resolved" and ep.get("incident_id"):
                before = self._row_dict(
                    self.db.query_one(
                        "SELECT status FROM incidents WHERE id=?", (ep["incident_id"],)
                    )
                )
                self._incidents.on_episode_resolved(episode_id)
                after = self._row_dict(
                    self.db.query_one(
                        "SELECT status FROM incidents WHERE id=?", (ep["incident_id"],)
                    )
                )
                if before.get("status") == "open" and after.get("status") == "resolved":
                    self._notify_incident(ep["incident_id"], "resolved", episode_id=episode_id)
        except Exception:
            pass

    def _quiet_elapsed(self, inc_id: str, *, episode_id: str = "", window_sec: float = 3600.0) -> bool:
        """事件安静超过 window 后，再次并入告警才值得推。"""
        row = self.db.query_one(
            "SELECT MAX(at) AS t FROM events WHERE incident_id=?"
            " AND type IN ('incident_opened','incident_reopened','incident_resolved',"
            " 'alert_fired','episode_attached','incident_refired')"
            " AND (?='' OR COALESCE(episode_id,'')!=?)",
            (inc_id, episode_id, episode_id),
        )
        last = float(row["t"] or 0) if row else 0.0
        if last <= 0:
            return True
        return (now() - last) >= window_sec

    def _notify_refire(self, inc_id: str, *, episode_id: str = "") -> None:
        """安静后再响：补一条 refire 事件并推送。"""
        try:
            from .fmt import fmt_incident_open

            inc = self._row_dict(
                self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
            )
            if not inc:
                return
            ev_id = self.db.event(
                "incident_refired",
                "告警复发",
                incident_id=inc_id,
                payload={"episode_id": episode_id, "quiet_window_sec": 3600},
            )
            body = fmt_incident_open(inc, at=now(), refire=True)
            self._notifier.enqueue_for_event(ev_id, body=body, typ="reopened")
        except Exception:
            pass

    def _notify_incident(self, inc_id: str, typ: str, *, episode_id: str = "") -> None:
        """以生命周期 Event 为源建立通知义务（幂等 ev:<id>）。"""
        if not self._notifier:
            return
        try:
            from .fmt import fmt_incident_open, fmt_incident_resolved

            event_type = {
                "opened": "incident_opened",
                "reopened": "incident_reopened",
                "resolved": "incident_resolved",
            }.get(typ, f"incident_{typ}")
            ev = self.db.query_one(
                "SELECT id FROM events WHERE incident_id=? AND type=?"
                " ORDER BY id DESC LIMIT 1",
                (inc_id, event_type),
            )
            if not ev:
                return
            inc = self._row_dict(
                self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
            )
            if typ == "resolved":
                body = fmt_incident_resolved(inc)
            else:
                body = fmt_incident_open(
                    inc,
                    at=now(),
                    refire=(typ == "reopened"),
                )
            self._notifier.enqueue_for_event(ev["id"], body=body, typ=typ)
        except Exception:
            pass

    def _upsert_episode_from_alert(
        self,
        conn,
        a: dict,
        *,
        t: float,
        source_state: str,
        status: str,
        source_health: str = "ok",
    ) -> tuple[str, bool, str, str]:
        """写入/更新 episode。返回 (episode_id, created, prev_status, new_status)。"""
        labels = a.get("labels") or {}
        annotations = a.get("annotations") or {}
        fp = labels.get("fingerprint") or fingerprint_of(labels)
        starts, starts_status = normalize_starts_at(a.get("startsAt"))
        alertname = labels.get("alertname") or "unknown"
        asset_id = labels.get("asset") or ""
        obj_name = labels.get("service") or ""
        family = problem_family_of(alertname, labels)
        # silenced / inhibited：上游 status 对象或标签
        status_obj = a.get("status") if isinstance(a.get("status"), dict) else {}
        silenced = 1 if (
            status_obj.get("silencedBy")
            or labels.get("silenced") in ("1", "true", "yes")
        ) else 0
        inhibited = 1 if (
            status_obj.get("inhibitedBy")
            or labels.get("inhibited") in ("1", "true", "yes")
        ) else 0
        quarantine_reason = ""
        if starts_status == "invalid":
            source_state = "quarantine"
            source_health = "quarantine"
            quarantine_reason = f"invalid_starts_at:{starts}"
        elif starts_status == "unknown":
            quarantine_reason = "unknown_starts_at"

        return upsert_episode(
            conn,
            source_id=self.source_id,
            fingerprint=fp,
            labels=labels,
            annotations=annotations,
            status=status,
            source_state=source_state,
            t=t,
            alertname=alertname,
            asset_id=asset_id,
            object_id=obj_name,
            source_health=source_health,
            problem_family=family,
            canonical_object=obj_name,
            quarantine_reason=quarantine_reason,
            silenced=silenced,
            inhibited=inhibited,
            starts_at_norm=starts,
        )

    def ingest_webhook(self, payload: dict, *, received_at: float | None = None) -> dict[str, Any]:
        alerts = payload.get("alerts") or []
        if not isinstance(alerts, list):
            raise ValueError("alerts must be list")
        if len(alerts) > MAX_ALERTS_PER_HOOK:
            raise ValueError(f"too many alerts: {len(alerts)}")
        t = received_at or now()
        created = 0
        updated = 0
        episodes: list[str] = []
        quarantined = 0
        with self.db.tx() as conn:
            for a in alerts:
                if not isinstance(a, dict):
                    continue
                labels = a.get("labels") or {}
                status = (a.get("status") or "firing").lower()
                if status not in ("firing", "resolved"):
                    status = "firing"
                source_state = "firing" if status == "firing" else "resolved"
                if labels.get("silenced") in ("1", "true", "yes") or (a.get("status") or "").lower() == "suppressed":
                    source_state = "suppressed"
                eid, is_new, prev_status, new_status = self._upsert_episode_from_alert(
                    conn, a, t=t, source_state=source_state, status=status
                )
                if is_new:
                    created += 1
                else:
                    updated += 1
                episodes.append(eid)

                starts, starts_status = normalize_starts_at(a.get("startsAt"))
                alertname = labels.get("alertname") or "unknown"
                asset_id = labels.get("asset") or ""
                if starts_status == "invalid":
                    quarantined += 1
                    conn.execute(
                        "INSERT INTO events(incident_id, episode_id, at, type, title,"
                        " payload_json, source_state) VALUES(?,?,?,?,?,?,?)",
                        (
                            "",
                            eid,
                            t,
                            "alert_quarantine",
                            f"{alertname} quarantine",
                            json.dumps(
                                {
                                    "alertname": alertname,
                                    "asset": asset_id,
                                    "episode_id": eid,
                                    "reason": f"invalid_starts_at:{starts}",
                                },
                                ensure_ascii=False,
                            ),
                            "quarantine",
                        ),
                    )
                    continue

                if is_new:
                    conn.execute(
                        "INSERT INTO events(incident_id, episode_id, at, type, title,"
                        " payload_json, source_state) VALUES(?,?,?,?,?,?,?)",
                        (
                            "",
                            eid,
                            t,
                            "alert_fired" if new_status == "firing" else "alert_resolved",
                            f"{alertname} {'firing' if new_status == 'firing' else 'resolved'}",
                            json.dumps(
                                {
                                    "alertname": alertname,
                                    "asset": asset_id,
                                    "labels": labels,
                                    "episode_id": eid,
                                    "starts_at_norm": starts,
                                    "problem_family": problem_family_of(alertname, labels),
                                },
                                ensure_ascii=False,
                            ),
                            source_state,
                        ),
                    )
                elif prev_status and prev_status != new_status:
                    # 状态跃迁才写事件（重复通知不重复制造）
                    conn.execute(
                        "INSERT INTO events(incident_id, episode_id, at, type, title,"
                        " payload_json, source_state) VALUES(?,?,?,?,?,?,?)",
                        (
                            "",
                            eid,
                            t,
                            "alert_resolved" if new_status == "resolved" else "alert_fired",
                            f"{alertname} {new_status}",
                            json.dumps(
                                {
                                    "alertname": alertname,
                                    "asset": asset_id,
                                    "episode_id": eid,
                                    "prev_status": prev_status,
                                    "new_status": new_status,
                                },
                                ensure_ascii=False,
                            ),
                            source_state,
                        ),
                    )
        for eid in episodes:
            self._sync_incident(eid)
        return {
            "created": created,
            "updated": updated,
            "episodes": episodes,
            "quarantined": quarantined,
        }

    def reconcile(self, alerts: list[dict], *, source_ok: bool = True) -> dict[str, Any]:
        """对账：区分「上游当前说什么」与「本次未看到」。

        - AM 当前存在 → 更新 episode / source observation
        - AM 本次未看到 → source_state=not_seen，不 recovered
        - source 失败 → source_health=unavailable，不制造 resolved
        """
        seen = 0
        imported = 0
        updated = 0
        not_seen = 0
        t = now()
        seen_fps: set[str] = set()
        sync_ids: list[str] = []

        if not source_ok:
            # 上游不可用：只标记 source_health，绝不把缺席当恢复
            self.db.execute(
                "UPDATE alert_episodes SET source_health='unavailable', last_reconciled_at=?"
                " WHERE status='firing' AND source_id=?",
                (t, self.source_id),
            )
            self.db.event(
                "reconcile_observed",
                "source unavailable; absence is not recovery",
                payload={
                    "source": self.source_id,
                    "source_health": "unavailable",
                    "note": "not_seen != recovered",
                },
            )
            return {
                "seen": 0,
                "imported": 0,
                "updated": 0,
                "not_seen": 0,
                "source_ok": False,
                "source_health": "unavailable",
                "at": t,
            }

        with self.db.tx() as conn:
            for a in alerts:
                labels = a.get("labels") or {}
                fp = labels.get("fingerprint") or fingerprint_of(labels)
                starts, starts_status = normalize_starts_at(a.get("startsAt"))
                seen_fps.add(f"{fp}|{starts}")
                status_obj = a.get("status") if isinstance(a.get("status"), dict) else {}
                am_state = status_obj.get("state") or a.get("status") or "active"
                if isinstance(am_state, dict):
                    am_state = am_state.get("state") or "active"
                am_state_l = str(am_state).lower()
                am_firing = am_state_l in ("active", "unprocessed", "suppressed", "firing")
                source_state = "firing" if am_firing else "resolved"
                if am_state_l in ("suppressed", "silenced"):
                    source_state = "suppressed"
                if starts_status == "invalid":
                    source_state = "quarantine"

                row = conn.execute(
                    "SELECT * FROM alert_episodes WHERE source_id=? AND fingerprint=?"
                    " AND starts_at_norm=?",
                    (self.source_id, fp, starts),
                ).fetchone()
                if row:
                    row_d = dict(row)
                    seen += 1
                    updated += 1
                    silenced = 1 if status_obj.get("silencedBy") else int(row_d.get("silenced") or 0)
                    inhibited = 1 if status_obj.get("inhibitedBy") else int(row_d.get("inhibited") or 0)
                    # 只更新 source observation；不因对账直接改 status=resolved
                    conn.execute(
                        "UPDATE alert_episodes SET last_seen=?, last_reconciled_at=?,"
                        " source_state=?, source_health=?, silenced=?, inhibited=?,"
                        " labels_json=?, annotations_json=?, receive_count=receive_count+1"
                        " WHERE id=?",
                        (
                            t,
                            t,
                            source_state,
                            "quarantine" if source_state == "quarantine" else "ok",
                            silenced,
                            inhibited,
                            json.dumps(labels, ensure_ascii=False),
                            json.dumps(a.get("annotations") or {}, ensure_ascii=False),
                            row_d["id"],
                        ),
                    )
                    sync_ids.append(row_d["id"])
                    continue

                if not am_firing:
                    continue
                eid, is_new, _prev, _new = self._upsert_episode_from_alert(
                    conn,
                    a,
                    t=t,
                    source_state=source_state,
                    status="firing",
                )
                if is_new:
                    imported += 1
                    conn.execute(
                        "INSERT INTO events(incident_id, episode_id, at, type, title,"
                        " payload_json, source_state) VALUES(?,?,?,?,?,?,?)",
                        (
                            "",
                            eid,
                            t,
                            "alert_fired",
                            f"{(labels.get('alertname') or 'unknown')} firing",
                            json.dumps(
                                {
                                    "alertname": labels.get("alertname") or "unknown",
                                    "asset": labels.get("asset") or "",
                                    "episode_id": eid,
                                    "via": "reconcile",
                                },
                                ensure_ascii=False,
                            ),
                            source_state,
                        ),
                    )
                sync_ids.append(eid)

            # 本地仍 firing、本次对账未见 → 只记 not_seen，绝不自动 recovered
            locals_firing = conn.execute(
                "SELECT id, incident_id, alertname FROM alert_episodes"
                " WHERE source_id=? AND status='firing'",
                (self.source_id,),
            ).fetchall()
            for r in locals_firing:
                row_full = conn.execute(
                    "SELECT fingerprint, starts_at_norm FROM alert_episodes WHERE id=?",
                    (r["id"],),
                ).fetchone()
                fp_key = f"{row_full['fingerprint']}|{row_full['starts_at_norm']}" if row_full else ""
                if fp_key and fp_key in seen_fps:
                    continue
                not_seen += 1
                conn.execute(
                    "UPDATE alert_episodes SET source_state='not_seen', last_reconciled_at=?"
                    " WHERE id=?",
                    (t, r["id"]),
                )
                exists = conn.execute(
                    "SELECT 1 FROM events WHERE episode_id=? AND type='reconcile_not_seen'"
                    " AND at > ?",
                    (r["id"], t - 3600),
                ).fetchone()
                if not exists:
                    conn.execute(
                        "INSERT INTO events(incident_id, episode_id, at, type, title,"
                        " payload_json, source_state) VALUES(?,?,?,?,?,?,?)",
                        (
                            r["incident_id"] or "",
                            r["id"],
                            t,
                            "reconcile_not_seen",
                            f"{r['alertname']} not_seen",
                            json.dumps(
                                {
                                    "episode_id": r["id"],
                                    "alertname": r["alertname"],
                                    "note": "AM absence is not recovery; awaiting confirmation",
                                },
                                ensure_ascii=False,
                            ),
                            "not_seen",
                        ),
                    )

        for eid in sync_ids:
            self._sync_incident(eid)

        return {
            "seen": seen,
            "imported": imported,
            "updated": updated,
            "not_seen": not_seen,
            "source_ok": True,
            "source_health": "ok",
            "at": t,
        }

    def mark_source_state(self, episode_id: str, source_state: str, *, note: str = "") -> None:
        """手工/测试：更新 source observation。不直接改 Incident outcome。"""
        t = now()
        self.db.execute(
            "UPDATE alert_episodes SET source_state=?, last_reconciled_at=? WHERE id=?",
            (source_state, t, episode_id),
        )
        self.db.event(
            "reconcile_observed",
            note or f"source_state={source_state}",
            episode_id=episode_id,
            payload={"episode_id": episode_id, "source_state": source_state},
            source_state=source_state,
        )

    async def fetch_am_alerts(self, am_url: str, timeout: float = 8.0) -> list[dict]:
        import aiohttp

        url = am_url.rstrip("/") + "/api/v2/alerts"
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.get(url) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"AM http {resp.status}: {text[:200]}")
                return await resp.json()
