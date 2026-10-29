"""Session participation and active-work coordination, independent of chat history.

An automatic session remains the Incident's primary mapping. A manual session
can participate without replacing it; active work on the same target is exclusive.
All session IDs supplied here come from trusted runtime/Web context.
"""
from __future__ import annotations

from contextlib import contextmanager
import time
from typing import Any


class WorkScopeError(RuntimeError):
    def __init__(self, code: str, detail: dict | None = None):
        self.code = code
        self.detail = detail or {}
        self.dispatch_not_started = True
        super().__init__(str(self.detail.get("message") or code))


@contextmanager
def _snapshot(db, conn=None, *, write=False):
    if conn is not None:
        yield conn
        return
    with db.tx() as current:
        if not current.in_transaction:
            current.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        yield current


def normalise_object(conn, asset_id: str, object_id: str) -> str:
    if not object_id or object_id == "*":
        return "*"
    row = conn.execute("SELECT id FROM objects WHERE asset_id=? AND (id=? OR name=? OR unit=?) ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END LIMIT 1",
                       (asset_id, object_id, object_id, object_id, object_id)).fetchone()
    return str(row["id"]) if row else object_id


def resolve_incident_write_scope(db: Any, session_id: str, asset_id: str, *,
                                 incident_id: str = "", conn=None) -> dict:
    """Bind a write to trusted participation, never to an arbitrary model ID."""
    with _snapshot(db, conn) as current:
        session = current.execute("SELECT origin FROM duty_sessions WHERE id=?", (session_id,)).fetchone()
        if session is None:
            raise WorkScopeError("session_unavailable")
        manual = session["origin"] == "manual"
        rows = [dict(row) for row in current.execute(
            "SELECT i.id AS incident_id,i.asset_id,i.status,i.generation,si.generation AS joined_generation "
            "FROM session_incidents si JOIN incidents i ON i.id=si.incident_id WHERE si.session_id=?",
            (session_id,)).fetchall()]
        related = [row for row in rows if row["asset_id"] == asset_id]
        open_related = [row for row in related if row["status"] == "open"]
        if incident_id:
            selected = next((row for row in rows if row["incident_id"] == incident_id), None)
            if selected is None:
                raise WorkScopeError("incident_session_mismatch", {
                    "incident_id": incident_id, "session_id": session_id,
                    "next_tool": "ayana_session_claim", "message": "请先在当前会话关联该工单。"})
            if selected["asset_id"] != asset_id:
                raise WorkScopeError("incident_asset_mismatch", {"incident_id": incident_id, "asset_id": asset_id})
            if selected["status"] != "open":
                standalone = manual and not open_related
                raise WorkScopeError("incident_not_open", {
                    "incident_id": incident_id, "status": selected["status"],
                    "can_run_standalone": standalone,
                    "next_action": "omit_incident_id" if standalone else "select_open_incident" if open_related else "use_manual_session",
                    "message": ("该工单已关闭；省略 incident_id 可在当前手动会话执行独立任务，历史记录和幂等保护继续保留。"
                                if standalone else "该工单已关闭，请选择仍未关闭的关联工单。" if open_related
                                else "该工单已关闭，自动会话不能转为独立写任务；请使用手动会话处理后续任务。")})
            candidates = [selected]
        else:
            candidates = open_related
            if not candidates and related and not manual:
                raise WorkScopeError("incident_not_open", {
                    "incident_ids": [row["incident_id"] for row in related], "can_run_standalone": False,
                    "next_action": "use_manual_session",
                    "message": "关联工单已关闭，自动会话不能转为独立写任务；请使用手动会话处理后续任务。"})
        stale = [row for row in candidates if int(row["generation"] or 1) != int(row["joined_generation"] or 1)]
        if stale:
            raise WorkScopeError("incident_generation_stale", {
                "incident_ids": [row["incident_id"] for row in stale], "next_tool": "ayana_session_claim",
                "associations": [{"incident_id": row["incident_id"], "status": row["status"],
                                  "association_generation": int(row["joined_generation"] or 1),
                                  "current_generation": int(row["generation"] or 1)} for row in stale],
                "message": "未关闭工单的关联代次已过期，请先调用 session.claim 刷新关联，再继续处置。"})
        if len(candidates) > 1:
            raise WorkScopeError("incident_scope_required", {
                "candidate_incident_ids": sorted(row["incident_id"] for row in candidates),
                "message": "当前主机关联多个工单，请用 incident_id 明确本次写操作所属工单。"})
        if candidates:
            return {"incident_id": candidates[0]["incident_id"],
                    "generation": int(candidates[0]["generation"] or 1), "scope": "incident"}
        return {"incident_id": "", "generation": 0, "scope": "session"}


def session_has_work(db: Any, session_id: str, *, conn=None) -> bool:
    """Native uncertainty and dispatched writes remain owners until reconciled."""
    with _snapshot(db, conn) as current:
        session = current.execute("SELECT * FROM duty_sessions WHERE id=?", (session_id,)).fetchone()
        if not session:
            return False
        session = dict(session)
        # One check for this consistent snapshot covers all pending native
        # admissions, recovery and uncertainty. Never expire these into replay.
        native_submission = current.execute("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state IN ('submitting','recovering','unknown') LIMIT 1",(session_id,)).fetchone()
        if native_submission:
            return True
        if current.execute("SELECT 1 FROM session_write_ops WHERE session_id=? AND status IN ('claimed','unknown') LIMIT 1", (session_id,)).fetchone():
            return True
        if current.execute("SELECT 1 FROM actions WHERE state IN ('dispatched','unknown','verifying') AND json_valid(params_json) AND json_extract(params_json,'$._ayana_session_id')=? LIMIT 1", (session_id,)).fetchone():
            return True
        if current.execute("SELECT 1 FROM agent_runtime_receipts WHERE session_id=? AND status IN ('accepted','pending','queued','running','unknown') LIMIT 1", (session_id,)).fetchone():
            return True
        if current.execute("SELECT 1 FROM agent_runtime_bindings WHERE session_id=? AND state IN ('running','unknown','stopping') LIMIT 1", (session_id,)).fetchone():
            return True
        if current.execute("SELECT 1 FROM agent_session_turns WHERE session_id=? AND expires_at>? LIMIT 1", (session_id, time.time())).fetchone():
            return True
        if session["status"] != "open" or session.get("deleted_at") or session.get("delete_requested_at"):
            return False
        if session.get("origin") != "auto":
            return False
        states = ("running",) if session.get("paused_at") else ("running", "queued")
        placeholders = ",".join("?" for _ in states)
        return bool(current.execute(
            "SELECT 1 FROM investigation_jobs j JOIN session_incidents si ON si.incident_id=j.incident_id "
            f"WHERE si.session_id=? AND j.status IN ({placeholders}) LIMIT 1", (session_id, *states)).fetchone())


def _conflict(row: dict, *, incident_id: str = "", asset_id: str = "", object_id: str = "") -> dict:
    sid = str(row["id"])
    return {"error": "work_already_running", "stop_processing": True, "owner_session_id": sid,
            "owner_title": row.get("title") or sid, "owner_origin": row.get("origin") or "",
            "incident_id": incident_id, "asset_id": asset_id, "object_id": object_id,
            "session_path": "/api/agent/sessions/" + sid,
            "message": "该工单或目标已有任务正在处理，请停止重复处置并进入已有会话。"}


def find_work_conflict(db: Any, session_id: str, *, incident_id: str = "", asset_id: str = "", object_id: str = "", conn=None) -> dict | None:
    with _snapshot(db, conn) as current:
        if incident_id:
            incident = current.execute("SELECT asset_id,object_id FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if incident:
                asset_id = asset_id or str(incident["asset_id"] or "")
                object_id = object_id or str(incident["object_id"] or "")
        obj = normalise_object(current, asset_id, object_id) if asset_id else object_id
        peers: dict[str, dict] = {}
        rows = current.execute(
            "SELECT DISTINCT d.*,i.id AS related_incident,i.asset_id AS related_asset,i.object_id AS related_object "
            "FROM duty_sessions d JOIN session_incidents si ON si.session_id=d.id JOIN incidents i ON i.id=si.incident_id "
            "WHERE d.id<>? AND (i.id=? OR (?<>'' AND i.asset_id=?)) ORDER BY d.created_at,d.id",
            (session_id, incident_id, asset_id, asset_id)).fetchall()
        for raw in rows:
            row = dict(raw)
            same_incident = bool(incident_id and row["related_incident"] == incident_id)
            other_obj = normalise_object(current, asset_id, str(row.get("related_object") or ""))
            if same_incident or (asset_id and (obj in ("", "*") or other_obj in ("", "*") or obj == other_obj)):
                peers[row["id"]] = row
        if asset_id:
            for raw in current.execute(
                "SELECT d.* FROM agent_work_targets w JOIN duty_sessions d ON d.id=w.session_id "
                "WHERE w.asset_id=? AND w.session_id<>? AND (?='*' OR w.object_id='*' OR w.object_id=?) ORDER BY w.updated_at",
                (asset_id, session_id, obj or "*", obj or "*")).fetchall():
                peers.setdefault(raw["id"], dict(raw))
            # Pending/uncertain raw commands predate resource reservations and
            # remain visible even if their session had no Incident association.
            for raw in current.execute(
                "SELECT DISTINCT d.* FROM session_write_ops w JOIN duty_sessions d ON d.id=w.session_id "
                "WHERE w.target=? AND w.session_id<>? AND w.status IN ('claimed','unknown')",
                (asset_id, session_id)).fetchall():
                peers.setdefault(raw["id"], dict(raw))
        for row in peers.values():
            if session_has_work(db, row["id"], conn=current):
                return _conflict(row, incident_id=incident_id, asset_id=asset_id, object_id=obj)
        return None


def claim_target(db: Any, session_id: str, *, asset_id: str, object_id: str = "", incident_id: str = "", conn=None) -> None:
    if not session_id or not asset_id:
        return
    with _snapshot(db, conn, write=True) as current:
        session = current.execute("SELECT * FROM duty_sessions WHERE id=?", (session_id,)).fetchone()
        if not session or session["status"] != "open" or dict(session).get("deleted_at") or dict(session).get("delete_requested_at"):
            raise WorkScopeError("session_unavailable")
        conflict = find_work_conflict(db, session_id, incident_id=incident_id, asset_id=asset_id, object_id=object_id, conn=current)
        if conflict:
            db.audit("agent", "runtime", "agent_work_conflict", asset_id=asset_id, incident_id=incident_id,
                     detail={"session_id":session_id, **conflict}, channel="agent")
            raise WorkScopeError("work_already_running", conflict)
        obj = normalise_object(current, asset_id, object_id)
        # Only a reconciled idle owner may be replaced. An unknown result is
        # retained by session_has_work and cannot expire into a replay.
        for row in current.execute("SELECT object_id,session_id FROM agent_work_targets WHERE asset_id=? AND session_id<>?", (asset_id, session_id)).fetchall():
            if not session_has_work(db, row["session_id"], conn=current):
                current.execute("DELETE FROM agent_work_targets WHERE asset_id=? AND object_id=? AND session_id=?", (asset_id,row["object_id"],row["session_id"]))
        current.execute("INSERT INTO agent_work_targets(asset_id,object_id,session_id,updated_at) VALUES(?,?,?,?) "
                        "ON CONFLICT(asset_id,object_id) DO UPDATE SET session_id=excluded.session_id,updated_at=excluded.updated_at",
                        (asset_id,obj,session_id,time.time()))


def claim_incident(db: Any, session_id: str, incident_id: str) -> dict:
    with _snapshot(db, write=True) as current:
        session = current.execute("SELECT * FROM duty_sessions WHERE id=?", (session_id,)).fetchone()
        incident = current.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not session or session["status"] != "open" or dict(session).get("deleted_at") or dict(session).get("delete_requested_at"):
            raise WorkScopeError("session_unavailable")
        if not incident:
            raise WorkScopeError("incident_not_found")
        if incident["status"] != "open":
            raise WorkScopeError("incident_not_open")
        claim_target(db,session_id,asset_id=str(incident["asset_id"] or ""),object_id=str(incident["object_id"] or ""),incident_id=incident_id,conn=current)
        conflict = find_work_conflict(db,session_id,incident_id=incident_id,conn=current)
        if conflict:
            raise WorkScopeError("work_already_running",conflict)
        current.execute("INSERT INTO session_incidents(session_id,incident_id,generation,joined_at) VALUES(?,?,?,?) "
                        "ON CONFLICT(session_id,incident_id) DO UPDATE SET generation=excluded.generation",
                        (session_id,incident_id,int(incident["generation"] or 1),time.time()))
        db.audit("agent","runtime","agent_incident_participation_claimed",incident_id=incident_id,
                 detail={"session_id":session_id},channel="agent")
        return {"ok":True,"session_id":session_id,"incident_id":incident_id,"joined":True,
                "message":"已关联当前会话；后续处置仍受当前权限、审批和执行校验约束。"}
