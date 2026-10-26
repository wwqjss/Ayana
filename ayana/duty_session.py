"""值班/手动会话生命周期（SpeedSupreme Agent 工作台）。

职责：
- 自动值班会话：首条告警创建，后续告警进入同一会话；全部关联工单关闭后倒计时归档。
- 手动会话：用户主动创建，生命周期独立，可续接/归档。
- 会话标题自动生成与更新。
- 归档倒计时（默认 300s）可被新告警取消；重启后可恢复。
- 会话消息与过程事件落库，供工作台展示。

不做：Agent 决策、调度状态机、第二套 Runtime。
"""

from __future__ import annotations

import json
from typing import Any

from .db import new_id, now

log = __import__("logging").getLogger("ayana.duty_session")

DEFAULT_ARCHIVE_DELAY_SEC = 300


class DutySessionManager:
    def __init__(self, db: Any, *, archive_delay_sec: int | None = None):
        self.db = db
        self._archive_delay = archive_delay_sec

    # ---- 设置 ----

    def archive_delay_sec(self) -> float:
        if self._archive_delay is not None:
            return float(self._archive_delay)
        row = self.db.query_one(
            "SELECT value FROM agent_settings WHERE key='archive_delay_sec'"
        )
        try:
            return float(row["value"]) if row else DEFAULT_ARCHIVE_DELAY_SEC
        except Exception:
            return DEFAULT_ARCHIVE_DELAY_SEC

    def require_human_approval(self) -> bool:
        row = self.db.query_one(
            "SELECT value FROM agent_settings WHERE key='require_human_approval'"
        )
        if not row:
            return True
        return str(row["value"] or "1") not in ("0", "false", "False", "")

    def set_setting(self, key: str, value: str, *, actor: str = "web") -> dict[str, Any]:
        t = now()
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO agent_settings(key, value, updated_at, updated_by) VALUES(?,?,?,?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
                " updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (key, str(value), t, actor),
            )
        return {"ok": True, "key": key, "value": str(value)}

    def settings(self) -> dict[str, Any]:
        rows = self.db.query("SELECT key, value, updated_at, updated_by FROM agent_settings")
        out = {str(r["key"]): str(r["value"] or "") for r in rows}
        return {
            "require_human_approval": str(out.get("require_human_approval", "1")) not in ("0", "false", "False", ""),
            "archive_delay_sec": int(float(out.get("archive_delay_sec") or DEFAULT_ARCHIVE_DELAY_SEC)),
            "ssh_investigate_role": out.get("ssh_investigate_role", "read"),
            "ssh_execute_role": out.get("ssh_execute_role", "write"),
        }

    # ---- 查询 ----

    def get(self, session_id: str) -> dict[str, Any] | None:
        row = self.db.query_one("SELECT * FROM duty_sessions WHERE id=?", (session_id,))
        return dict(row) if row else None

    def list_sessions(
        self,
        *,
        status: str = "",
        origin: str = "",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM duty_sessions"
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(status)
        if origin:
            clauses.append("origin=?")
            params.append(origin)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(int(limit))
        return [dict(r) for r in self.db.query(sql, tuple(params))]

    def open_auto_session(self) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT * FROM duty_sessions WHERE origin='auto' AND status='open'"
            " ORDER BY created_at DESC LIMIT 1"
        )
        return dict(row) if row else None

    def incidents(self, session_id: str) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT si.incident_id, si.generation, si.joined_at, i.title, i.status, i.severity,"
            " i.asset_id, i.object_id, i.need_human, i.outcome, i.updated_at"
            " FROM session_incidents si LEFT JOIN incidents i ON i.id=si.incident_id"
            " WHERE si.session_id=? ORDER BY si.joined_at",
            (session_id,),
        )
        return [dict(r) for r in rows]

    def incident_ids(self, session_id: str) -> list[str]:
        rows = self.db.query(
            "SELECT incident_id FROM session_incidents WHERE session_id=?",
            (session_id,),
        )
        return [str(r["incident_id"]) for r in rows]

    def session_for_incident(self, incident_id: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT d.* FROM session_incidents si JOIN duty_sessions d ON d.id=si.session_id"
            " WHERE si.incident_id=? ORDER BY d.updated_at DESC LIMIT 1",
            (incident_id,),
        )
        return dict(row) if row else None

    # ---- 创建 / 加入 ----

    def create(
        self,
        *,
        origin: str = "manual",
        title: str = "",
        created_by: str = "",
        prompt: str = "",
    ) -> dict[str, Any]:
        origin = "manual" if origin != "auto" else "auto"
        t = now()
        sid = new_id("sess")
        title = (title or "").strip() or ("手动会话" if origin == "manual" else "自动值班")
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO duty_sessions("
                " id, title, origin, status, prompt, created_by, created_at, updated_at,"
                " last_activity_at, archive_due_at, archived_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,0)",
                (sid, title[:120], origin, "open", prompt or "", created_by, t, t, t, 0),
            )
        self.record_event(sid, type="session_created", title=title)
        return {"ok": True, "action": "created", "session_id": sid, "origin": origin, "title": title}

    def ensure_auto_session(self, incident_id: str = "") -> dict[str, Any]:
        """首条告警建自动值班会话；已有 open 的自动会话则复用。并发下收敛到单会话。"""
        existing = self.open_auto_session()
        if existing:
            self.cancel_archive(existing["id"])
            return {"ok": True, "action": "reused", **existing}
        try:
            return self.create(origin="auto", title="自动值班", created_by="system")
        except Exception:
            # 并发创建撞车：复用赢家
            existing = self.open_auto_session()
            if existing:
                self.cancel_archive(existing["id"])
                return {"ok": True, "action": "reused", **existing}
            raise

    def join_incident(
        self,
        session_id: str,
        incident_id: str,
        *,
        generation: int = 1,
    ) -> dict[str, Any]:
        if not session_id or not incident_id:
            return {"ok": False, "error": "session_id_and_incident_id_required"}
        t = now()
        with self.db.tx() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO session_incidents(session_id, incident_id, generation, joined_at)"
                " VALUES(?,?,?,?)",
                (session_id, incident_id, int(generation or 1), t),
            )
            conn.execute(
                "UPDATE duty_sessions SET updated_at=?, last_activity_at=?, archive_due_at=0 WHERE id=?",
                (t, t, session_id),
            )
        self.record_event(
            session_id,
            incident_id=incident_id,
            type="incident_joined",
            title=f"Incident {incident_id} 加入会话",
            payload={"generation": generation},
        )
        return {"ok": True, "session_id": session_id, "incident_id": incident_id}

    # ---- 标题 ----

    def update_title(self, session_id: str, title: str) -> dict[str, Any]:
        title = (title or "").strip()[:120]
        if not title:
            return {"ok": False, "error": "empty_title"}
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE duty_sessions SET title=?, updated_at=? WHERE id=?",
                (title, now(), session_id),
            )
        return {"ok": True, "session_id": session_id, "title": title}

    def auto_title_from_incidents(self, session_id: str) -> str:
        incs = self.incidents(session_id)
        open_incs = [i for i in incs if (i.get("status") or "") == "open"]
        pick = open_incs or incs
        if not pick:
            return "自动值班"
        titles = [str(i.get("title") or "").strip() for i in pick if str(i.get("title") or "").strip()]
        if not titles:
            return "自动值班"
        if len(titles) == 1:
            return titles[0][:80]
        return f"{titles[0][:40]} 等 {len(titles)} 个故障"[:80]

    # ---- 归档倒计时 ----

    def cancel_archive(self, session_id: str) -> None:
        row = self.get(session_id)
        if not row or float(row.get("archive_due_at") or 0) <= 0:
            return
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE duty_sessions SET archive_due_at=0, updated_at=? WHERE id=?",
                (now(), session_id),
            )
        self.record_event(session_id, type="archive_cancelled", title="新告警取消归档倒计时")

    def maybe_start_archive_countdown(self, session_id: str) -> dict[str, Any]:
        """关联 Incident 全部终态则启动倒计时；否则取消倒计时。"""
        sess = self.get(session_id)
        if not sess or sess.get("status") != "open":
            return {"ok": False, "error": "session_not_open"}
        incs = self.incidents(session_id)
        open_count = sum(1 for i in incs if (i.get("status") or "") == "open")
        if not incs:
            # 无关联工单的手动会话不自动归档
            return {"ok": True, "action": "noop", "reason": "no_incidents"}
        if open_count > 0:
            self.cancel_archive(session_id)
            return {"ok": True, "action": "keep_open", "open_incidents": open_count}
        t = now()
        delay = self.archive_delay_sec()
        due = t + delay
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE duty_sessions SET archive_due_at=?, updated_at=?, last_activity_at=? WHERE id=?",
                (due, t, t, session_id),
            )
        self.record_event(
            session_id,
            type="archive_scheduled",
            title=f"全部工单已关闭，{int(delay)}s 后归档",
            payload={"archive_due_at": due, "delay_sec": delay},
        )
        return {"ok": True, "action": "countdown", "archive_due_at": due, "delay_sec": delay}

    def tick_archives(self) -> dict[str, Any]:
        """到期归档。服务启动/定时调用。"""
        t = now()
        rows = self.db.query(
            "SELECT * FROM duty_sessions WHERE status='open' AND archive_due_at>0 AND archive_due_at<=?",
            (t,),
        )
        archived = []
        for row in rows:
            row = dict(row)
            sid = row["id"]
            with self.db.tx() as conn:
                conn.execute(
                    "UPDATE duty_sessions SET status='archived', archived_at=?, archive_due_at=0, updated_at=?"
                    " WHERE id=? AND status='open'",
                    (t, t, sid),
                )
            self.record_event(sid, type="session_archived", title="会话已归档")
            archived.append(sid)
        return {"ok": True, "archived": archived}

    def archive_session(self, session_id: str, *, reason: str = "manual") -> dict[str, Any]:
        t = now()
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE duty_sessions SET status='archived', archived_at=?, archive_due_at=0, updated_at=?"
                " WHERE id=? AND status='open'",
                (t, t, session_id),
            )
            changed = cur.rowcount == 1
        if changed:
            self.record_event(session_id, type="session_archived", title=f"会话归档（{reason}）")
        return {"ok": True, "changed": changed, "session_id": session_id}

    def recover(self) -> dict[str, Any]:
        """重启恢复：校验倒计时与状态一致性。"""
        t = now()
        self.db.execute(
            "UPDATE duty_sessions SET archive_due_at=0 WHERE status='archived' AND archive_due_at>0"
        )
        # 自动值班：若有 open 会话且关联工单全关但无倒计时，补启动
        rows = self.db.query(
            "SELECT id FROM duty_sessions WHERE origin='auto' AND status='open' AND archive_due_at=0"
        )
        restored = []
        for row in rows:
            sid = str(row["id"])
            res = self.maybe_start_archive_countdown(sid)
            if res.get("action") == "countdown":
                restored.append(sid)
        return {"ok": True, "countdown_restored": restored}

    # ---- 过程事件 / 消息 ----

    def record_event(
        self,
        session_id: str,
        *,
        type: str = "info",
        title: str = "",
        incident_id: str = "",
        payload: dict[str, Any] | None = None,
    ) -> int:
        try:
            with self.db.tx() as conn:
                cur = conn.execute(
                    "INSERT INTO session_events(session_id, incident_id, type, title, payload_json, created_at)"
                    " VALUES(?,?,?,?,?,?)",
                    (
                        session_id,
                        incident_id or "",
                        (type or "info")[:40],
                        (title or "")[:200],
                        json.dumps(payload or {}, ensure_ascii=False),
                        now(),
                    ),
                )
                conn.execute(
                    "UPDATE duty_sessions SET last_activity_at=?, updated_at=? WHERE id=?",
                    (now(), now(), session_id),
                )
                return int(cur.lastrowid or 0)
        except Exception as e:  # noqa: BLE001
            log.warning("record_event failed: %s", e)
            return 0

    def add_message(
        self,
        session_id: str,
        *,
        role: str = "assistant",
        kind: str = "text",
        title: str = "",
        body: str = "",
        payload: dict[str, Any] | None = None,
        incident_id: str = "",
    ) -> dict[str, Any]:
        mid = new_id("msg")
        t = now()
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO session_messages("
                " id, session_id, role, kind, title, body, payload_json, incident_id, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    mid,
                    session_id,
                    (role or "assistant")[:20],
                    (kind or "text")[:40],
                    (title or "")[:200],
                    (body or "")[:20000],
                    json.dumps(payload or {}, ensure_ascii=False),
                    incident_id or "",
                    t,
                ),
            )
            conn.execute(
                "UPDATE duty_sessions SET last_activity_at=?, updated_at=? WHERE id=?",
                (t, t, session_id),
            )
        return {"ok": True, "id": mid, "session_id": session_id}

    def messages(self, session_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM session_messages WHERE session_id=? ORDER BY created_at, id LIMIT ?",
            (session_id, int(limit)),
        )
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d.get("payload_json") or "{}")
            except Exception:
                d["payload"] = {}
            out.append(d)
        return out

    def events(self, session_id: str, *, after_id: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM session_events WHERE session_id=? AND id>? ORDER BY id LIMIT ?",
            (session_id, int(after_id), int(limit)),
        )
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d.get("payload_json") or "{}")
            except Exception:
                d["payload"] = {}
            out.append(d)
        return out
