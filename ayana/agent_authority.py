"""Trusted, live session authority shared by Web, MCP and final dispatch.

The model never selects its authority scope. Native MCP metadata identifies a
RID; only the persistent one-to-one Ayana binding can resolve its session.
"""
from __future__ import annotations

import time
from typing import Any


class AuthorityError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _one(db, conn, sql, params=()):
    return conn.execute(sql, params).fetchone() if conn is not None else db.query_one(sql, params)


def resolve_authority(db: Any, session_id: str, *, conn=None) -> dict:
    if conn is None:
        with db.tx() as snapshot:
            if not snapshot.in_transaction: snapshot.execute("BEGIN")
            return resolve_authority(db, session_id, conn=snapshot)
    session = _one(db, conn, "SELECT * FROM duty_sessions WHERE id=?", (session_id,))
    if session is None:
        raise AuthorityError("authority_session_unknown")
    session = dict(session)
    settings = dict((r["key"], r["value"]) for r in
        (conn.execute("SELECT key,value FROM agent_settings") if conn is not None else db.query("SELECT key,value FROM agent_settings")))
    approval = settings.get("auto_approval_mode", "automatic")
    if session["origin"] == "auto":
        access, source = settings.get("auto_access_mode", "readwrite"), "auto_global"
    else:
        access, approval, source = session["access_mode"], session["approval_mode"], "manual_session"
    binding = _one(db, conn, "SELECT * FROM agent_runtime_bindings WHERE session_id=?", (session_id,))
    binding = dict(binding) if binding is not None else {}
    active = bool(session["status"] == "open" and binding.get("controller") and binding.get("controller_connection_id")
        and float(binding.get("control_expires_at") or 0) > time.time())
    if active:
        access, approval, source = binding.get("override_access_mode"), binding.get("override_approval_mode"), "takeover"
    if access not in ("readonly", "readwrite") or approval not in ("manual", "automatic"):
        raise AuthorityError("authority_state_invalid")
    global_rev = _one(db, conn, "SELECT value FROM meta WHERE key='agent_authority_revision'")
    revision = int(global_rev["value"] if global_rev else 0) * 1000000000 + int(session["authority_revision"]) * 2 + (0 if active else 1)
    lifecycle_block = ("session_deleted" if session.get("deleted_at") else "session_deleting" if session.get("delete_requested_at")
                       else "session_paused" if session.get("paused_at") else "")
    return {"session_id": session_id, "access_mode": access, "approval_mode": approval,
        "source": source, "revision": revision, "controller_active": active,
        "lifecycle_block": lifecycle_block, "write_allowed": not lifecycle_block and access == "readwrite",
        "lease_expires_at": float(binding.get("control_expires_at") or 0) if active else 0}


def resolve_remote_authority(db: Any, remote_session_id: str) -> dict:
    if not isinstance(remote_session_id, str) or not remote_session_id:
        raise AuthorityError("trusted_session_context_required")
    rows = db.query("SELECT id FROM duty_sessions WHERE remote_session_id=?", (remote_session_id,))
    if len(rows) != 1:
        raise AuthorityError("authority_remote_unknown" if not rows else "authority_remote_ambiguous")
    binding = db.query_one("SELECT remote_session_id FROM agent_runtime_bindings WHERE session_id=?", (rows[0]["id"],))
    if binding and binding["remote_session_id"] not in ("", remote_session_id):
        raise AuthorityError("authority_binding_mismatch")
    return resolve_authority(db, rows[0]["id"])


def reset_controls(db: Any, *, reason: str = "service_restart", session_id: str = "", expired_only: bool = False) -> int:
    t = time.time()
    with db.tx() as conn:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        sql = "SELECT session_id,controller,controller_connection_id FROM agent_runtime_bindings WHERE controller_connection_id<>''"
        params = []
        if session_id:
            sql += " AND session_id=?"; params.append(session_id)
        if expired_only:
            sql += " AND control_expires_at<=?"; params.append(t)
        rows = conn.execute(sql, params).fetchall()
        for row in rows:
            conn.execute("UPDATE agent_runtime_bindings SET controller='',controller_connection_id='',control_expires_at=0,override_access_mode='',override_approval_mode='',updated_at=? WHERE session_id=?", (t, row["session_id"]))
            conn.execute("UPDATE duty_sessions SET authority_revision=authority_revision+1 WHERE id=?", (row["session_id"],))
            db.audit("system", "agent", "agent_permissions_restored", detail={**dict(row), "reason": reason}, channel="agent")
    return len(rows)
