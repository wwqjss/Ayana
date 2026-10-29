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

import asyncio
import contextvars
import json
import threading
import time
import uuid
from contextlib import contextmanager, asynccontextmanager
from pathlib import Path
from typing import Any

from .db import new_id, now

log = __import__("logging").getLogger("ayana.duty_session")

DEFAULT_ARCHIVE_DELAY_SEC = 300
_TURN_OWNERS = contextvars.ContextVar("ayana_session_turns", default={})
_RECEIPT_TERMINAL = frozenset(("completed","done","succeeded","success","failed","cancelled","canceled","aborted","error","rejected"))


class NativeTurnBusyError(RuntimeError):
    code = "session_busy"

    def __init__(self, blockers: list[str]):
        self.blockers = blockers
        super().__init__("session_busy: " + ",".join(blockers))


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

    def set_setting(self, key: str, value: str, *, actor: str = "web") -> dict[str, Any]:
        self.set_settings({key: value}, actor=actor)
        return {"ok": True, "key": key, "value": str(value)}

    def set_settings(self, changes: dict, *, actor: str = "web") -> dict[str, Any]:
        if "ssh_default_group" in changes:
            group = changes["ssh_default_group"]
            if not isinstance(group, str) or not group.strip() or len(group.strip()) > 32:
                raise ValueError("invalid_ssh_account_group")
            group = group.strip()
            if not self.db.query_one("SELECT 1 FROM ssh_account_groups WHERE name=?", (group,)):
                raise ValueError("ssh_account_group_not_found")
            changes = {**changes, "ssh_default_group": group}
        changes = {k: str(v) for k, v in changes.items()}
        if "auto_access_mode" in changes and changes["auto_access_mode"] not in ("readonly", "readwrite"):
            raise ValueError("invalid_access_mode")
        if "auto_approval_mode" in changes:
            if changes["auto_approval_mode"] not in ("manual", "automatic"):
                raise ValueError("invalid_approval_mode")
        changes.pop("require_human_approval", None)  # 旧全局审批开关已退役
        t = now()
        with self.db.tx() as conn:
            if not conn.in_transaction: conn.execute("BEGIN IMMEDIATE")
            for key, value in changes.items():
                conn.execute(
                "INSERT INTO agent_settings(key, value, updated_at, updated_by) VALUES(?,?,?,?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
                " updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                    (key, str(value), t, actor),
            )
            conn.execute("UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='agent_authority_revision'")
        return {"ok": True, "changed": changes}

    def settings(self) -> dict[str, Any]:
        rows = self.db.query("SELECT key, value, updated_at, updated_by FROM agent_settings")
        out = {str(r["key"]): str(r["value"] or "") for r in rows}
        return {
            "archive_delay_sec": int(float(out.get("archive_delay_sec") or DEFAULT_ARCHIVE_DELAY_SEC)),
            "ssh_default_group": out.get("ssh_default_group", "") or "default",
        }

    def set_session_account_group(self, session_id: str, group: str, *, actor: str = "web") -> dict[str, Any]:
        """Select this session's SSH group; an empty selection follows the global default."""
        if not isinstance(group, str) or len(group.strip()) > 32:
            raise ValueError("invalid_ssh_account_group")
        group = group.strip()
        with self.db.tx() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            session = conn.execute("SELECT * FROM duty_sessions WHERE id=?", (session_id,)).fetchone()
            if not session:
                raise ValueError("session_not_found")
            if session["deleted_at"]:
                raise ValueError("session_deleted")
            if session["delete_requested_at"]:
                raise ValueError("session_deleting")
            if session["status"] != "open":
                raise ValueError("session_not_open")
            if group and not conn.execute("SELECT 1 FROM ssh_account_groups WHERE name=?", (group,)).fetchone():
                raise ValueError("ssh_account_group_not_found")
            previous = session["ssh_account_group"]
            changed = previous != group
            if changed:
                conn.execute(
                    "UPDATE duty_sessions SET ssh_account_group=?,authority_revision=authority_revision+1,updated_at=? WHERE id=?",
                    (group, now(), session_id))
                self.db.audit("web_user", actor, "agent_session_account_group_changed", channel="agent",
                              detail={"session_id": session_id, "previous": previous, "selection": group})
            from .agent_authority import resolve_authority
            authority = resolve_authority(self.db, session_id, conn=conn)
        return {"ok": True, "changed": changed, "session_id": session_id,
                "ssh_account_group": authority["ssh_account_group"], "ssh_account_group_override": group,
                "ssh_account_group_source": authority["ssh_account_group_source"],
                "effective_permissions": authority}

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
        include_deleted: bool = False,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM duty_sessions"
        clauses: list[str] = []
        params: list[Any] = []
        if not include_deleted:
            clauses.append("deleted_at=0")
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
            "SELECT * FROM duty_sessions WHERE origin='auto' AND status='open' AND deleted_at=0"
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
            " WHERE si.incident_id=? ORDER BY"
            " CASE WHEN d.origin='auto' AND d.deleted_at=0 AND d.status='open' THEN 0"
            " WHEN d.origin IN ('auto','legacy_auto') AND d.deleted_at=0 THEN 1"
            " WHEN d.origin IN ('auto','legacy_auto') THEN 2 ELSE 3 END, d.updated_at DESC LIMIT 1",
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
            manual_default = conn.execute("SELECT value FROM agent_settings WHERE key='manual_approval_default'").fetchone()
            conn.execute("UPDATE duty_sessions SET access_mode='readwrite',approval_mode=? WHERE id=?",
                         (manual_default[0] if manual_default else "manual", sid))
        self.record_event(sid, type="session_created", title=title)
        return {"ok": True, "action": "created", "session_id": sid, "origin": origin, "title": title}

    def ensure_auto_session(self, incident_id: str = "") -> dict[str, Any]:
        """Reserve the one automatic slot in a SQLite write transaction."""
        with self.db.tx() as conn:
            if not conn.in_transaction: conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM duty_sessions WHERE origin='auto' AND status='open' AND deleted_at=0 ORDER BY created_at DESC LIMIT 1").fetchone()
            if existing:
                sid = existing["id"]
                conn.execute("UPDATE duty_sessions SET archive_due_at=0,updated_at=? WHERE id=?", (now(),sid))
                return {"ok":True,"action":"reused",**dict(existing),"session_id":sid,"archive_due_at":0}
            return self.create(origin="auto", title="自动值班", created_by="system")

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
            if not conn.in_transaction: conn.execute("BEGIN IMMEDIATE")
            sess = conn.execute("SELECT status,deleted_at,delete_requested_at FROM duty_sessions WHERE id=?", (session_id,)).fetchone()
            if not sess or sess["status"] != "open" or sess["deleted_at"] or sess["delete_requested_at"]:
                return {"ok":False,"error":"session_not_open"}
            conn.execute(
                "INSERT INTO session_incidents(session_id,incident_id,generation,joined_at) VALUES(?,?,?,?)"
                " ON CONFLICT(session_id,incident_id) DO UPDATE SET generation=excluded.generation",
                (session_id,incident_id,int(generation or 1),t),
            )
            conn.execute("UPDATE duty_sessions SET updated_at=?,last_activity_at=?,archive_due_at=0 WHERE id=?",(t,t,session_id))
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

    def pause_session(self, session_id: str, *, actor: str, reason: str = "user_pause") -> dict[str, Any]:
        with self.db.tx() as conn:
            if not conn.in_transaction: conn.execute("BEGIN IMMEDIATE")
            session = self.get(session_id)
            if not session or session.get("deleted_at"):
                return {"ok": False, "error": "session_unavailable"}
            if session["status"] != "open" or session.get("delete_requested_at"):
                return {"ok": False, "error": "session_not_open"}
            conn.execute("UPDATE duty_sessions SET paused_at=CASE WHEN paused_at>0 THEN paused_at ELSE ? END,pause_reason=?,archive_due_at=0,updated_at=? WHERE id=?", (now(),reason,now(),session_id))
            self.record_event(session_id,type="session_paused",title="自动调度已暂停" if session["origin"] == "auto" else "任务已暂停",payload={"actor":actor,"reason":reason})
            self.db.audit("web_user",actor,"agent_session_paused",detail={"session_id":session_id,"reason":reason},channel="web")
        return {"ok": True,"session_id":session_id,"paused":True,**self.task_info(session_id)}

    def resume_session(self, session_id: str, *, actor: str) -> dict[str, Any]:
        with self.db.tx() as conn:
            if not conn.in_transaction: conn.execute("BEGIN IMMEDIATE")
            session=self.get(session_id)
            if not session or session.get("deleted_at") or session.get("delete_requested_at") or session["status"] != "open":
                return {"ok":False,"error":"session_unavailable"}
            conn.execute("UPDATE duty_sessions SET paused_at=0,pause_reason='',human_message_revision=human_message_revision+1,updated_at=? WHERE id=?",(now(),session_id))
            self.record_event(session_id,type="session_resumed",title="自动调度已恢复" if session["origin"] == "auto" else "已解除暂停",payload={"actor":actor})
            self.db.audit("web_user",actor,"agent_session_resumed",detail={"session_id":session_id},channel="web")
        return {"ok":True,"session_id":session_id,"paused":False,**self.task_info(session_id)}

    def interrupt_business_work(self, session_id: str, *, actor: str):
        """An explicit stop ends the old worker; recovery belongs to the operator."""
        ids=self._owned_job_ids(session_id)
        if ids:
            marks=",".join("?" for _ in ids)
            self.db.execute("UPDATE investigation_jobs SET status='cancelled',phase='user_interrupted',last_error='operator_stopped',lease_expires_at=0,updated_at=? WHERE incident_id IN ("+marks+") AND status='running'",(now(),*ids))
        self.db.audit("web_user",actor,"agent_business_interrupted",detail={"session_id":session_id},channel="web")

    def _owned_job_ids(self, session_id: str) -> list[str]:
        session=self.get(session_id)
        if not session or session["origin"] != "auto":return []
        return [iid for iid in self.incident_ids(session_id)
                if (self.session_for_incident(iid) or {}).get("id") == session_id]

    def deletion_blockers(self, session_id: str) -> list[str]:
        """Only this session's active execution blocks deletion, not its Incidents."""
        session=self.get(session_id)
        if not session or session.get("deleted_at"):return []
        blockers=[b for b in self.native_admission_blockers(session_id) if b != "session_not_open"]
        runtime=self.db.query_one("SELECT state FROM agent_runtime_bindings WHERE session_id=?",(session_id,))
        if runtime and runtime["state"] not in ("idle","ready","stopped","archived"):
            blockers.append("native_runtime_busy")
        if self.db.query_one("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state IN ('submitting','recovering','unknown')",(session_id,)):
            blockers.append("submission_unknown")
        if self.db.query_one("SELECT 1 FROM agent_session_turns WHERE session_id=? AND expires_at>?",(session_id,now())):
            blockers.append("turn_active")
        if self.db.query_one("SELECT 1 FROM session_write_ops WHERE session_id=? AND status IN ('claimed','unknown')",(session_id,)):
            blockers.append("write_result_pending")
        if self.db.query_one("SELECT 1 FROM actions WHERE json_valid(params_json) AND json_extract(params_json,'$._ayana_session_id')=? AND state IN ('dispatched','unknown')",(session_id,)):
            blockers.append("action_result_pending")
        ids=self._owned_job_ids(session_id)
        if ids:
            marks=",".join("?" for _ in ids)
            if self.db.query_one("SELECT 1 FROM investigation_jobs WHERE incident_id IN ("+marks+") AND status IN ('queued','running')",tuple(ids)):
                blockers.append("business_task_running")
        return list(dict.fromkeys(blockers))

    def request_delete(self, session_id: str, *, actor: str, stop: bool = False) -> dict[str, Any]:
        with self.db.tx() as conn:
            if not conn.in_transaction:conn.execute("BEGIN IMMEDIATE")
            session=self.get(session_id)
            if not session:return {"ok":False,"error":"session_unavailable"}
            if session.get("deleted_at"):return {"ok":True,"deleted":True,"session_id":session_id}
            blockers=self.deletion_blockers(session_id)
            if blockers and not stop:
                msg = "会话仍有任务或结果待确认，可选择停止并删除。"
                if "write_result_pending" in blockers or "action_result_pending" in blockers:
                    msg = "存在待核销的执行结果，请先在执行与验证中人工核销；其余任务可停止后删除。"
                return {"ok":False,"error":"session_has_tasks","blockers":blockers,"message":msg}
            t=now()
            conn.execute("UPDATE duty_sessions SET delete_requested_at=CASE WHEN delete_requested_at>0 THEN delete_requested_at ELSE ? END,deleted_by=?,paused_at=CASE WHEN paused_at>0 THEN paused_at ELSE ? END,pause_reason='delete_requested',archive_due_at=0,delete_error='',updated_at=? WHERE id=?",(t,actor,t,t,session_id))
            # Cancel only not-yet-dispatched work owned by this session.
            conn.execute("UPDATE session_write_ops SET status='failed',result='cancelled:session_deleted',lease_expires_at=0,updated_at=? WHERE session_id=? AND status='awaiting_approval'",(t,session_id))
            conn.execute("UPDATE actions SET state='cancelled',result_detail='session_deleted',finished_at=? WHERE json_valid(params_json) AND json_extract(params_json,'$._ayana_session_id')=? AND state IN ('proposed','approved')",(t,session_id))
            ids=self._owned_job_ids(session_id)
            if ids:
                marks=",".join("?" for _ in ids)
                conn.execute("UPDATE investigation_jobs SET status='cancelled',phase='user_deleted',last_error='session_deleted',lease_expires_at=0,updated_at=? WHERE incident_id IN ("+marks+") AND status='queued'",(t,*ids))
            self.record_event(session_id,type="session_delete_requested",title="已请求停止并删除" if blockers else "已请求删除",payload={"actor":actor,"stop":stop})
            self.db.audit("web_user",actor,"agent_session_delete_requested",detail={"session_id":session_id,"stop":stop,"blockers":blockers},channel="web")
        self.tick_deletions(session_id=session_id)
        session=self.get(session_id)
        return {"ok":True,"session_id":session_id,"deleted":bool(session.get("deleted_at")),"pending":not bool(session.get("deleted_at")),"blockers":self.deletion_blockers(session_id),**self.task_info(session_id)}

    def tick_deletions(self, *, session_id: str = "") -> list[str]:
        sql="SELECT id FROM duty_sessions WHERE delete_requested_at>0 AND deleted_at=0"
        rows=self.db.query(sql+(" AND id=?" if session_id else ""),(session_id,) if session_id else ())
        deleted=[]
        for row in rows:
            sid=row["id"]
            with self.db.tx() as conn:
                if not conn.in_transaction:conn.execute("BEGIN IMMEDIATE")
                blockers=self.deletion_blockers(sid)
                if blockers:
                    conn.execute("UPDATE duty_sessions SET delete_error=? WHERE id=?",(",".join(blockers),sid));continue
                session=self.get(sid);t=now()
                conn.execute("UPDATE duty_sessions SET deleted_at=?,status='archived',archived_at=CASE WHEN archived_at>0 THEN archived_at ELSE ? END,archive_due_at=0,delete_error='',updated_at=? WHERE id=? AND deleted_at=0",(t,t,t,sid))
                conn.execute("UPDATE agent_runtime_bindings SET state='archived',updated_at=? WHERE session_id=?",(t,sid))
                from .agent_authority import reset_controls
                reset_controls(self.db,reason="session_deleted",session_id=sid)
                self.record_event(sid,type="session_deleted",title="会话已从列表删除，业务记录保留",payload={"actor":session.get("deleted_by")})
                self.db.audit("web_user",session.get("deleted_by") or "web","agent_session_deleted",detail={"session_id":sid,"history_preserved":True},channel="web")
                deleted.append(sid)
        return deleted

    def task_info(self, session_id: str) -> dict[str, Any]:
        session=self.get(session_id) or {}
        runtime=self.db.query_one("SELECT state,receipt_status FROM agent_runtime_bindings WHERE session_id=?",(session_id,))
        runtime=dict(runtime) if runtime else {}
        blockers=self.native_admission_blockers(session_id) if session.get("status") == "open" else []
        unknown=any("unknown" in b for b in blockers) or bool(self.db.query_one("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state='unknown'",(session_id,)))
        unknown = unknown or bool(self.db.query_one(
            "SELECT 1 FROM session_write_ops WHERE session_id=? AND status='unknown' LIMIT 1", (session_id,)))
        unknown = unknown or bool(self.db.query_one(
            "SELECT 1 FROM actions WHERE json_valid(params_json) AND json_extract(params_json,'$._ayana_session_id')=? AND state='unknown' LIMIT 1", (session_id,)))
        recovering=bool(self.db.query_one("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state IN ('submitting','recovering')",(session_id,)))
        busy=bool(blockers) or recovering
        interrupted_job = False
        owned = self._owned_job_ids(session_id)
        if owned:
            marks = ','.join('?' for _ in owned)
            jobs = self.db.query(
                "SELECT j.status,j.phase FROM investigation_jobs j JOIN incidents i ON i.id=j.incident_id"
                " WHERE j.incident_id IN (" + marks + ") AND j.generation=i.generation AND i.status='open'", tuple(owned))
            busy = busy or any(job["status"] in ("queued", "running") for job in jobs)
            interrupted_job = any(job["status"] == "failed" and job["phase"] == "interrupted" for job in jobs)
        if session.get("deleted_at"):state="deleted"
        elif session.get("delete_requested_at"):state="deleting"
        elif unknown:state="unknown"
        elif session.get("paused_at"):state="stopping" if busy else "paused"
        elif session.get("status") == "archived":state="archived"
        elif (runtime.get("receipt_status") in ("cancelled","canceled","aborted","interrupted","failed","error") or interrupted_job) and not busy:state="interrupted"
        elif busy:state="queued" if runtime.get("receipt_status") in ("queued","pending") else "running"
        else:state="idle"
        labels={"deleted":"会话已删除","deleting":"正在停止并删除" if busy else "正在删除","unknown":"执行结果待核对","stopping":"正在暂停，等待任务停止","paused":"已暂停","archived":"已归档","interrupted":"任务已中断，等待恢复","queued":"消息已排队","running":"任务执行中","idle":"空闲"}
        del_blockers = self.deletion_blockers(session_id)
        if state == "deleting" and "write_result_pending" in del_blockers:
            labels["deleting"] = "正在删除 · 执行结果待核销"
        recoverable=runtime.get("receipt_status") in ("cancelled","canceled","aborted","interrupted","failed","error") and not busy and not unknown and not session.get("delete_requested_at") and session.get("status") == "open"
        return {"task_state":state,"task_state_label":labels[state],"can_recover":bool(recoverable),"deletion_blockers":del_blockers}

    def archive_blockers(self, session_id: str) -> list[str]:
        """Business and runtime facts, never a UI-only busy flag."""
        blockers = []
        session=self.get(session_id) or {}
        if session.get("paused_at"):blockers.append("session_paused")
        if session.get("delete_requested_at"):blockers.append("deletion_pending")
        if self.db.query_one("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state IN ('submitting','recovering','unknown')",(session_id,)):
            blockers.append("submission_pending")
        if self.db.query_one("SELECT 1 FROM agent_runtime_bindings WHERE session_id=? AND controller_connection_id<>'' AND control_expires_at>?",(session_id,now())):
            blockers.append("human_control")
        incs = self.incidents(session_id)
        ids = [row["incident_id"] for row in incs]
        if any((row.get("status") or "open") == "open" for row in incs): blockers.append("open_incidents")
        if ids:
            placeholders = ",".join("?" for _ in ids)
            checks = (
                ("actions", "SELECT 1 FROM actions WHERE incident_id IN ("+placeholders+") AND state IN ('proposed','approved','dispatched','unknown') LIMIT 1"),
                ("pending_jobs", "SELECT 1 FROM investigation_jobs WHERE incident_id IN ("+placeholders+") AND status IN ('queued','running') LIMIT 1"),
                ("pending_verification", "SELECT 1 FROM verifications WHERE incident_id IN ("+placeholders+") AND status IN ('pending','running') LIMIT 1"),
            )
            for label,sql in checks:
                if self.db.query_one(sql,tuple(ids)): blockers.append(label)
            sql = "SELECT 1 FROM session_write_ops WHERE (session_id=? OR incident_id IN ("+placeholders+")) AND status IN ('awaiting_approval','claimed','unknown') LIMIT 1"
            if self.db.query_one(sql,(session_id,*ids)): blockers.append("pending_writes")
        elif self.db.query_one("SELECT 1 FROM session_write_ops WHERE session_id=? AND status IN ('awaiting_approval','claimed','unknown') LIMIT 1",(session_id,)):
            blockers.append("pending_writes")
        terminals=tuple(sorted(_RECEIPT_TERMINAL));marks=",".join("?" for _ in terminals)
        if self.db.query_one("SELECT 1 FROM agent_runtime_receipts WHERE session_id=? AND status NOT IN ("+marks+") LIMIT 1",(session_id,*terminals)):
            blockers.append("receipt_pending")
        runtime = self.db.query_one("SELECT state,receipt_status FROM agent_runtime_bindings WHERE session_id=?",(session_id,))
        if runtime:
            if runtime["state"] not in ("idle","ready","stopped","archived"): blockers.append("runtime_busy")
            if runtime["receipt_status"] and runtime["receipt_status"] not in ("completed","done","failed","cancelled","aborted","error","idle"):
                blockers.append("receipt_pending")
        if self.db.query_one("SELECT 1 FROM agent_session_turns WHERE session_id=? AND expires_at>?",(session_id,now())):
            blockers.append("turn_active")
        return blockers

    def maybe_start_archive_countdown(self, session_id: str) -> dict[str, Any]:
        """Only the automatic duty slot rotates; repeated closes preserve due time."""
        with self.db.tx() as conn:
            if not conn.in_transaction: conn.execute("BEGIN IMMEDIATE")
            sess = self.get(session_id)
            if not sess or sess.get("status") != "open": return {"ok":False,"error":"session_not_open"}
            if sess.get("origin") != "auto" or not self.incidents(session_id):
                return {"ok":True,"action":"noop","reason":"manual_or_no_incidents"}
            blockers = self.archive_blockers(session_id)
            if blockers:
                self.cancel_archive(session_id)
                return {"ok":True,"action":"keep_open","blockers":blockers}
            existing = float(sess.get("archive_due_at") or 0)
            if existing > 0:
                return {"ok":True,"action":"countdown","archive_due_at":existing,"delay_sec":self.archive_delay_sec()}
            t = now();delay = max(0,self.archive_delay_sec());due = t + delay
            conn.execute("UPDATE duty_sessions SET archive_due_at=?,updated_at=? WHERE id=? AND status='open' AND archive_due_at=0",(due,t,session_id))
            self.record_event(session_id,type="archive_scheduled",title=f"全部工单已结束，{int(delay)}s 后归档",payload={"archive_due_at":due,"delay_sec":delay})
            return {"ok":True,"action":"countdown","archive_due_at":due,"delay_sec":delay}

    def tick_archives(self) -> dict[str, Any]:
        from .agent_authority import reset_controls
        reset_controls(self.db, reason="lease_expired", expired_only=True)
        self.tick_deletions()
        archived = []
        for row in self.db.query("SELECT id FROM duty_sessions WHERE origin='auto' AND status='open' AND archive_due_at>0 AND archive_due_at<=?",(now(),)):
            sid=row["id"]
            with self.db.tx() as conn:
                if not conn.in_transaction: conn.execute("BEGIN IMMEDIATE")
                current = self.get(sid)
                if not current or current["status"] != "open" or not 0 < float(current["archive_due_at"] or 0) <= now(): continue
                if self.archive_blockers(sid): self.cancel_archive(sid);continue
                t=now()
                cur=conn.execute("UPDATE duty_sessions SET status='archived',archived_at=?,archive_due_at=0,updated_at=? WHERE id=? AND status='open' AND archive_due_at=?",(t,t,sid,current["archive_due_at"]))
                if cur.rowcount==1:
                    self.record_event(sid,type="session_archived",title="会话已归档");archived.append(sid)
        return {"ok":True,"archived":archived}

    def archive_session(self, session_id: str, *, reason: str = "manual") -> dict[str, Any]:
        with self.db.tx() as conn:
            if not conn.in_transaction: conn.execute("BEGIN IMMEDIATE")
            blockers=self.archive_blockers(session_id)
            if blockers:return {"ok":False,"error":"session_busy","blockers":blockers}
            t=now()
            cur=conn.execute("UPDATE duty_sessions SET status='archived',archived_at=?,archive_due_at=0,updated_at=? WHERE id=? AND status='open'",(t,t,session_id))
            changed=cur.rowcount==1
            if changed:self.record_event(session_id,type="session_archived",title=f"会话归档（{reason}）")
            return {"ok":True,"changed":changed,"session_id":session_id}

    def reopen_session(self, session_id: str, *, actor: str = "web", as_manual: bool = True) -> dict[str, Any]:
        with self.db.tx() as conn:
            if not conn.in_transaction: conn.execute("BEGIN IMMEDIATE")
            row=self.get(session_id)
            if not row:return {"ok":False,"error":"not_found"}
            if row.get("deleted_at") or row.get("delete_requested_at"):
                return {"ok":False,"error":"session_deleted"}
            if row["status"]=="open" and row["origin"]!="legacy_auto":return {"ok":True,"changed":False,"session_id":session_id}
            if not as_manual:return {"ok":False,"error":"history_requires_manual_reopen"}
            conn.execute("UPDATE duty_sessions SET status='open',origin='manual',archive_due_at=0,archived_at=0,updated_at=? WHERE id=?",(now(),session_id))
            self.record_event(session_id,type="session_reopened",title="手动续接历史会话",payload={"actor":actor})
            return {"ok":True,"changed":True,"session_id":session_id}

    def set_runtime_state(self, session_id: str, state: str, *, receipt_id: str = "", receipt_status: str = "") -> None:
        if not self.get(session_id): raise ValueError("session_not_found")
        t=now()
        self.db.execute("INSERT INTO agent_runtime_bindings(session_id,state,receipt_id,receipt_status,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET state=excluded.state,receipt_id=excluded.receipt_id,receipt_status=excluded.receipt_status,updated_at=excluded.updated_at",(session_id,str(state)[:40],str(receipt_id)[:200],str(receipt_status)[:40],t,t))

    def record_receipt(self, session_id: str, remote_session_id: str, receipt_id: str, *, status: str = "accepted", origin: str = "auto") -> None:
        if not session_id or not remote_session_id or not receipt_id:raise ValueError("receipt_binding_required")
        with self.db.tx() as conn:
            if not conn.in_transaction:conn.execute("BEGIN IMMEDIATE")
            current=conn.execute("SELECT session_id,remote_session_id FROM agent_runtime_receipts WHERE receipt_id=?",(receipt_id,)).fetchone()
            if current and (current["session_id"]!=session_id or current["remote_session_id"]!=remote_session_id):raise ValueError("receipt_binding_conflict")
            t=now()
            conn.execute("INSERT INTO agent_runtime_receipts(receipt_id,session_id,remote_session_id,status,origin,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(receipt_id) DO UPDATE SET updated_at=excluded.updated_at",(receipt_id,session_id,remote_session_id,str(status)[:40],str(origin)[:40],t,t))
            conn.execute("UPDATE duty_sessions SET archive_due_at=0,updated_at=? WHERE id=?",(t,session_id))

    def record_native_turn(self, session_id: str, remote_session_id: str, message_id: str,
                           state: str, *, receipt_id: str = "", engine: dict | None = None) -> None:
        """Persist automatic input identity before POST so observation never needs a replay."""
        if not message_id:
            raise ValueError("native_message_id_required")
        with self.db.tx() as conn:
            session = conn.execute("SELECT remote_session_id FROM duty_sessions WHERE id=?", (session_id,)).fetchone()
            if not session or session["remote_session_id"] != remote_session_id:
                raise ValueError("runtime_binding_changed")
            submission_id = "automatic_" + message_id
            existing = conn.execute(
                "SELECT payload_json FROM agent_native_submissions WHERE session_id=? AND submission_id=?",
                (session_id, submission_id)).fetchone()
            payload = json.loads(existing["payload_json"]) if existing else {"messageID": message_id, "engine": engine}
            t = now()
            conn.execute(
                "INSERT INTO agent_native_submissions(session_id,submission_id,kind,state,created_at,updated_at,"
                "remote_session_id,payload_json,receipt_id) VALUES(?,?,'automatic',?,?,?,?,?,?)"
                " ON CONFLICT(session_id,submission_id) DO UPDATE SET"
                " state=CASE WHEN agent_native_submissions.state IN ('completed','failed','cancelled')"
                " THEN agent_native_submissions.state ELSE excluded.state END,updated_at=excluded.updated_at,"
                " receipt_id=CASE WHEN excluded.receipt_id<>'' THEN excluded.receipt_id ELSE agent_native_submissions.receipt_id END",
                (session_id, submission_id, state, t, t, remote_session_id, json.dumps(payload), receipt_id))

    def finish_receipt(self, receipt_id: str, status: str) -> None:
        if status not in _RECEIPT_TERMINAL:raise ValueError("receipt_terminal_status_required")
        self.db.execute("UPDATE agent_runtime_receipts SET status=?,updated_at=? WHERE receipt_id=?",(status,now(),receipt_id))

    def native_admission_blockers(self, session_id: str, *, include_business: bool = False) -> list[str]:
        """Check durable model ownership while the caller holds this session's turn.

        A lease expiring, an HTTP timeout, or a disconnected viewer never proves
        the native task ended. Known receipts are reconciled without replay by
        the receipt monitor; missing receipts require explicit reconciliation.
        """
        session = self.get(session_id)
        if not session or session.get("status") != "open":
            return ["session_not_open"]
        terminals = tuple(sorted(_RECEIPT_TERMINAL))
        marks = ",".join("?" for _ in terminals)
        blockers = []
        if self.db.query_one("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state='unknown'",(session_id,)):
            blockers.append("native_turn_unknown")
        elif self.db.query_one("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state IN ('submitting','recovering')",(session_id,)):
            blockers.append("native_submission_pending")
        if self.db.query_one("SELECT 1 FROM agent_runtime_receipts WHERE session_id=? AND status='unknown' LIMIT 1", (session_id,)):
            blockers.append("native_turn_unknown")
        elif self.db.query_one(
            "SELECT 1 FROM agent_runtime_receipts WHERE session_id=? AND status NOT IN (" + marks + ") LIMIT 1",
            (session_id, *terminals),
        ):
            blockers.append("native_turn_pending")
        binding = self.db.query_one("SELECT state,receipt_status FROM agent_runtime_bindings WHERE session_id=?", (session_id,))
        if binding:
            state = str(binding["state"] or "")
            receipt_status = str(binding["receipt_status"] or "")
            if state == "unknown" or receipt_status == "unknown":
                blockers.append("native_turn_unknown")
            elif receipt_status and receipt_status not in _RECEIPT_TERMINAL and receipt_status != "idle":
                blockers.append("native_turn_pending")
            elif state in ("running", "busy", "retry") and receipt_status not in _RECEIPT_TERMINAL:
                blockers.append("native_turn_pending")
        if include_business and self.db.query_one(
            "SELECT 1 FROM investigation_jobs j JOIN session_incidents si ON si.incident_id=j.incident_id WHERE si.session_id=? AND j.status='running' LIMIT 1",
            (session_id,),
        ):
            blockers.append("business_task_running")
        return list(dict.fromkeys(blockers))

    def _turn_key(self, session_id: str):
        return (str(Path(self.db.path).resolve()),session_id)

    def _acquire_turn(self, session_id: str, owner: str, timeout: float, lease_sec: float) -> None:
        deadline=time.monotonic()+max(0,timeout)
        while True:
            t=now()
            with self.db.tx() as conn:
                if not conn.in_transaction:conn.execute("BEGIN IMMEDIATE")
                cur=conn.execute("INSERT INTO agent_session_turns(session_id,owner,expires_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at,updated_at=excluded.updated_at WHERE agent_session_turns.expires_at<=? OR agent_session_turns.owner=?",(session_id,owner,t+max(1,lease_sec),t,t,owner))
                if cur.rowcount==1:return
            if time.monotonic()>=deadline:raise TimeoutError("session_turn_busy")
            time.sleep(min(0.03,max(0,deadline-time.monotonic())))

    def _release_turn(self, session_id: str, owner: str) -> None:
        self.db.execute("DELETE FROM agent_session_turns WHERE session_id=? AND owner=?",(session_id,owner))

    @contextmanager
    def _renew_turn(self, session_id: str, owner: str, lease_sec: float):
        stop = threading.Event()
        duration = max(1, lease_sec)
        def heartbeat():
            while not stop.wait(min(30, duration / 3)):
                try:
                    t = now()
                    self.db.execute(
                        "UPDATE agent_session_turns SET expires_at=?,updated_at=? WHERE session_id=? AND owner=?",
                        (t + duration, t, session_id, owner),
                    )
                except Exception:
                    log.exception("session turn lease renewal failed session_id=%s", session_id)
        thread = threading.Thread(target=heartbeat, name="ayana-session-lease", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join(timeout=1)

    @contextmanager
    def turn(self, session_id: str, *, timeout: float = 120, lease_sec: float = 900, require_idle: bool = True):
        key=self._turn_key(session_id);existing=_TURN_OWNERS.get().get(key)
        if existing:
            yield existing;return
        owner=uuid.uuid4().hex;self._acquire_turn(session_id,owner,timeout,lease_sec)
        token=_TURN_OWNERS.set({**_TURN_OWNERS.get(),key:owner})
        try:
            blockers = self.native_admission_blockers(session_id) if require_idle else []
            if blockers: raise NativeTurnBusyError(blockers)
            with self._renew_turn(session_id, owner, lease_sec):
                yield owner
        finally:_TURN_OWNERS.reset(token);self._release_turn(session_id,owner)

    @asynccontextmanager
    async def async_turn(self, session_id: str, *, timeout: float = 120, lease_sec: float = 900, require_idle: bool = True):
        key=self._turn_key(session_id);existing=_TURN_OWNERS.get().get(key)
        if existing:
            yield existing;return
        owner=uuid.uuid4().hex
        task=asyncio.create_task(asyncio.to_thread(self._acquire_turn,session_id,owner,timeout,lease_sec))
        try:await asyncio.shield(task)
        except BaseException:
            try:await task
            finally:await asyncio.to_thread(self._release_turn,session_id,owner)
            raise
        token=_TURN_OWNERS.set({**_TURN_OWNERS.get(),key:owner})
        try:
            blockers = self.native_admission_blockers(session_id) if require_idle else []
            if blockers: raise NativeTurnBusyError(blockers)
            with self._renew_turn(session_id, owner, lease_sec):
                yield owner
        finally:
            _TURN_OWNERS.reset(token)
            await asyncio.to_thread(self._release_turn,session_id,owner)

    def recover(self) -> dict[str, Any]:
        """重启恢复：校验倒计时与状态一致性。"""
        from .agent_authority import reset_controls
        reset_controls(self.db)
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
