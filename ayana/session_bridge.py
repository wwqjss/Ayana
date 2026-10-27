"""Incident → Session 薄桥（SpeedSupreme P2 + 工作台一会话多 Incident）。

分工：
- Incident 管事实（告警、状态、恢复证据）
- Session（duty_session）管调查上下文、过程、决策痕迹；一会话可关联多 Incident
- Execution 管动作（审批/执行/审计/验证 —— 仍由 ActionService 负责）

本模块只做：
1. 建/找会话并挂接 Incident（自动值班复用 open 会话）
2. 生成结构化 prompt
3. 记 session_id ↔ incident_id 映射（落库，重启可恢复）
4. 写操作幂等台账（同一 action_key 不重复执行已完成写）
5. 关联 MiMo 远端会话（按 session，不按 incident）

禁止：第二套 Agent Runtime / 调度状态机 / Planner / 自动处置决策。
"""

from __future__ import annotations

import json
import re
import threading
from typing import Any

from .db import new_id, now
from .duty_session import DutySessionManager


class SessionBridge:
    """薄桥：映射、复用、幂等。无调度、无决策。"""

    def __init__(self, db: Any, knowledge: Any = None, mimo: Any = None, duty: DutySessionManager | None = None):
        self.db = db
        self.knowledge = knowledge
        self.mimo = mimo  # MimoSessionClient | None
        self.duty = duty or DutySessionManager(db)
        self._ensure_lock = threading.Lock()

    # ---- 映射 / 会话 ----

    def get_mapping(self, incident_id: str) -> dict[str, Any] | None:
        """兼容旧接口：返回该 Incident 所属会话（含远端字段）。"""
        sess = self.duty.session_for_incident(incident_id)
        if not sess:
            return None
        inc = self.db.query_one("SELECT generation FROM incidents WHERE id=?", (incident_id,))
        inc_d = dict(inc) if inc else {}
        gen = int(inc_d.get("generation") or 1)
        return {
            "incident_id": incident_id,
            "generation": gen,
            "session_id": sess.get("id") or "",
            "status": "open" if sess.get("status") == "open" else "closed",
            "prompt": sess.get("prompt") or "",
            "created_at": sess.get("created_at") or 0,
            "updated_at": sess.get("updated_at") or 0,
            **self._remote_fields(sess),
        }

    def ensure_session(self, incident_id: str, *, generation: int | None = None) -> dict[str, Any]:
        """挂接 Incident 到自动值班会话（一会话多 Incident）。并发下收敛单会话。"""
        if not incident_id:
            raise ValueError("incident_id required")
        with self._ensure_lock:
            return self._ensure_session_locked(incident_id, generation=generation)

    def _ensure_session_locked(self, incident_id: str, *, generation: int | None = None) -> dict[str, Any]:
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not inc:
            return {"ok": False, "error": "incident_not_found", "incident_id": incident_id}
        gen = int(generation if generation is not None else (inc["generation"] or 1))

        existing = self.duty.session_for_incident(incident_id)
        if existing and existing.get("status") == "open" and existing.get("origin") == "auto":
            self.duty.cancel_archive(existing["id"])
            joined = self.duty.join_incident(existing["id"], incident_id, generation=gen)
            if not joined.get("ok"):
                return self._ensure_session_locked(incident_id, generation=gen)
            return {
                "ok": True,
                "action": "reused",
                "incident_id": incident_id,
                "generation": gen,
                "session_id": existing["id"],
                "status": "open",
                **self._remote_fields(existing),
            }

        # 新告警：进入 open 自动值班会话，没有则创建
        sess = self.duty.ensure_auto_session(incident_id)
        sid = sess.get("session_id") or sess.get("id") or ""
        if not sid:
            return {"ok": False, "error": "session_create_failed", "incident_id": incident_id}
        self.duty.cancel_archive(sid)
        joined = self.duty.join_incident(sid, incident_id, generation=gen)
        if not joined.get("ok"):
            return self._ensure_session_locked(incident_id, generation=gen)
        # Incident 时间线痕迹（兼容旧 session_opened 事件）
        try:
            self.db.event(
                "session_opened",
                f"session {sid}",
                incident_id=incident_id,
                payload={"session_id": sid, "generation": gen},
            )
        except Exception:
            pass
        prompt = self.build_prompt(incident_id)
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE duty_sessions SET prompt=?, updated_at=? WHERE id=?",
                (prompt, now(), sid),
            )
        return {
            "ok": True,
            "action": sess.get("action", "created"),
            "incident_id": incident_id,
            "generation": gen,
            "session_id": sid,
            "status": "open",
            "prompt": prompt,
            **self._remote_fields(self.duty.get(sid) or {}),
        }

    def close_session(self, incident_id: str, *, reason: str = "") -> dict[str, Any]:
        """兼容旧接口：Incident 关闭时推进会话归档倒计时，不立刻关会话。"""
        sess = self.duty.session_for_incident(incident_id)
        if not sess:
            return {"ok": False, "error": "not_found"}
        sid = sess["id"]
        res = self.duty.maybe_start_archive_countdown(sid)
        return {"ok": True, "action": "countdown_or_keep", "session_id": sid, **res}

    def archive_session(self, session_id: str, *, reason: str = "manual") -> dict[str, Any]:
        return self.duty.archive_session(session_id, reason=reason)

    def list_sessions(self, status: str = "", limit: int = 50) -> list[dict[str, Any]]:
        return self.duty.list_sessions(status=status, limit=limit)

    # ---- MiMo 远端会话（按 duty_session）----

    def _remote_fields(self, mapping: dict[str, Any]) -> dict[str, Any]:
        history = mapping.get("remote_history") or "[]"
        try:
            hist = json.loads(history) if isinstance(history, str) else (history or [])
        except Exception:
            hist = []
        return {
            "remote_session_id": mapping.get("remote_session_id") or "",
            "remote_status": mapping.get("remote_status") or "none",
            "remote_model": mapping.get("remote_model") or "",
            "remote_last_error": mapping.get("remote_last_error") or "",
            "remote_history": hist,
            "remote_updated_at": mapping.get("remote_updated_at") or 0,
        }

    def _set_remote(
        self,
        session_id: str,
        *,
        remote_session_id: str = "",
        status: str = "none",
        model: str = "",
        last_error: str = "",
        keep_history: bool = True,
    ) -> None:
        m = self.duty.get(session_id)
        if not m:
            return
        hist: list[dict[str, Any]] = []
        if keep_history:
            try:
                hist = json.loads(m.get("remote_history") or "[]")
            except Exception:
                hist = []
        old = m.get("remote_session_id") or ""
        if old and old != remote_session_id:
            hist.append({"id": old, "status": m.get("remote_status") or "", "at": now()})
        hist = hist[-10:]
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE duty_sessions SET remote_session_id=?, remote_status=?,"
                " remote_model=?, remote_last_error=?, remote_history=?, remote_updated_at=?, updated_at=?"
                " WHERE id=?",
                (
                    remote_session_id,
                    status,
                    model or "",
                    (last_error or "")[:300],
                    json.dumps(hist, ensure_ascii=False),
                    now(),
                    now(),
                    session_id,
                ),
            )

    def attach_remote(self, incident_id: str = "", *, session_id: str = "", title: str = "", prompt: str = "", force_new: bool = False, timeout: float | None = None) -> dict[str, Any]:
        if not session_id and incident_id:
            ensured=self.ensure_session(incident_id)
            if not ensured.get("ok"):return ensured
            session_id=str(ensured.get("session_id") or "")
        if not session_id:return {"ok":False,"error":"session_id_required"}
        with self.duty.turn(session_id,timeout=timeout or 120,lease_sec=max(900,(timeout or 120)+120)):
            return self._attach_remote_locked(incident_id,session_id=session_id,title=title,prompt=prompt,force_new=force_new,timeout=timeout)

    def _attach_remote_locked(
        self,
        incident_id: str = "",
        *,
        session_id: str = "",
        title: str = "",
        prompt: str = "",
        force_new: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """把会话关联到 MiMo 远端。incident_id 或 session_id 二选一。"""
        if not session_id and incident_id:
            ensured = self.ensure_session(incident_id)
            if not ensured.get("ok"):
                return ensured
            session_id = str(ensured.get("session_id") or "")
        if not session_id:
            return {"ok": False, "error": "session_id_required"}
        sess = self.duty.get(session_id)
        if not sess:
            return {"ok": False, "error": "session_not_found", "session_id": session_id}

        if sess.get("status") != "open":
            return {"ok":False,"error":"session_archived","session_id":session_id}
        base = {"local_session_id": session_id, "incident_id": incident_id, "session_id": session_id}
        if self.mimo is None:
            self._set_remote(session_id, status="none")
            return {**base, "ok": True, "action": "no_mimo", "remote_session_id": ""}

        rid = sess.get("remote_session_id") or ""
        if rid and not force_new:
            try:
                alive = self.mimo.exists(rid)
            except Exception as e:  # noqa: BLE001
                self._set_remote(session_id, remote_session_id=rid, status="error", last_error=str(e))
                return {**base, "ok": False, "action": "probe_failed", "remote_session_id": rid, "error": str(e)}
            if alive:
                self._set_remote(session_id, remote_session_id=rid, status="active", model=getattr(self.mimo, "model", ""))
                return {**base, "ok": True, "action": "reused", "remote_session_id": rid}
            self._set_remote(session_id, remote_session_id=rid, status="missing", last_error="remote missing")

        if not prompt:
            base_prompt = (sess.get("prompt") or "").strip()
            if not base_prompt:
                if incident_id:
                    base_prompt = self.build_prompt(incident_id)
                else:
                    base_prompt = self.build_session_prompt(session_id)
            prompt = base_prompt
        title = title or sess.get("title") or (f"inc:{incident_id}" if incident_id else "ayana-session")
        try:
            if callable(getattr(type(self.mimo), "allocate", None)):
                allocated = self.mimo.allocate(title=title, timeout=timeout)
                rid = str(getattr(allocated,"remote_session_id","") or "")
                if not rid:raise ValueError("mimo_session_allocation_failed")
                self._set_remote(session_id,remote_session_id=rid,status="active",model=getattr(allocated,"model","") or "")
                remote = self.mimo.resume(rid, prompt, timeout=timeout)
            else:
                remote = self.mimo.create(title=title, prompt=prompt, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", "error")
            self._set_remote(
                session_id,
                remote_session_id=rid,
                status="timeout" if code == "timeout" else "error",
                last_error=str(e),
            )
            return {
                **base,
                "ok": False,
                "action": "create_failed",
                "error": str(e),
                "code": code,
                "remote_session_id": rid,
            }

        self._set_remote(
            session_id,
            remote_session_id=getattr(remote, "remote_session_id", "") or "",
            status=getattr(remote, "status", "") or "active",
            model=getattr(remote, "model", "") or "",
            last_error=getattr(remote, "last_error", "") or "",
        )
        self.duty.add_message(
            session_id,
            role="assistant",
            kind="mimo_result",
            title="MiMo 会话已建立",
            body=(getattr(remote, "text", "") or "")[:8000],
            payload={"remote_session_id": getattr(remote, "remote_session_id", ""), "raw_events": (getattr(remote, "raw_events", None) or [])[:50]},
            incident_id=incident_id,
        )
        return {
            **base,
            "ok": True,
            "action": "created",
            "remote_session_id": getattr(remote, "remote_session_id", ""),
            "remote_status": getattr(remote, "status", "") or "active",
            "text": (getattr(remote, "text", "") or ""),
            "raw_events": getattr(remote, "raw_events", None) or [],
        }

    def prompt_remote(self, incident_id: str = "", prompt: str = "", *, session_id: str = "", timeout: float | None = None) -> dict[str, Any]:
        if not session_id and incident_id:
            mapped=self.duty.session_for_incident(incident_id)
            session_id=str((mapped or {}).get("id") or "")
            if not session_id:
                ensured=self.ensure_session(incident_id)
                if not ensured.get("ok"):return ensured
                session_id=str(ensured.get("session_id") or "")
        if not session_id:return {"ok":False,"error":"session_id_required"}
        with self.duty.turn(session_id,timeout=timeout or 120,lease_sec=max(900,(timeout or 120)+120)):
            return self._prompt_remote_locked(incident_id,prompt,session_id=session_id,timeout=timeout)

    def _prompt_remote_locked(
        self,
        incident_id: str = "",
        prompt: str = "",
        *,
        session_id: str = "",
        timeout: float | None = None,
    ) -> dict[str, Any]:
        if not session_id and incident_id:
            sess = self.duty.session_for_incident(incident_id)
            session_id = (sess or {}).get("id") or ""
            if not session_id:
                ensured = self.ensure_session(incident_id)
                session_id = str(ensured.get("session_id") or "")
        if not session_id:
            return {"ok": False, "error": "session_id_required"}
        if self.mimo is None:
            return {"ok": False, "error": "mimo_unavailable"}
        sess = self.duty.get(session_id)
        if not sess:
            return {"ok": False, "error": "not_found"}
        if sess.get("status") != "open":return {"ok":False,"error":"session_archived"}
        rid = sess.get("remote_session_id") or ""
        if not rid:
            attached = self.attach_remote(session_id=session_id, incident_id=incident_id, timeout=timeout)
            if not attached.get("ok"):
                return attached
            rid = attached.get("remote_session_id") or ""
        try:
            remote = self.mimo.resume(rid, prompt, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", "error")
            if code == "session_missing":
                self._set_remote(session_id, remote_session_id=rid, status="missing", last_error=str(e))
                return {"ok": False, "error": "session_missing", "remote_session_id": rid}
            self._set_remote(session_id, remote_session_id=rid, status="error", last_error=str(e))
            return {"ok": False, "error": code, "message": str(e)}
        self._set_remote(
            session_id,
            remote_session_id=getattr(remote, "remote_session_id", "") or rid,
            status=getattr(remote, "status", "") or "active",
            model=getattr(remote, "model", "") or "",
            last_error=getattr(remote, "last_error", "") or "",
        )
        text = getattr(remote, "text", "") or ""
        raw_events = getattr(remote, "raw_events", None) or []
        # 用户消息由调用方先落库；此处只记 Agent 响应
        self.duty.add_message(
            session_id,
            role="assistant",
            kind="mimo_result",
            title="MiMo 响应",
            body=text[:8000],
            payload={"raw_events": raw_events[:50], "remote_session_id": getattr(remote, "remote_session_id", "") or rid},
            incident_id=incident_id,
        )
        for ev in raw_events[:20]:
            et = str(ev.get("type") or "")
            if et in ("tool_call", "tool_use", "tool_result", "step", "error"):
                self.duty.record_event(
                    session_id,
                    type=et,
                    title=str(ev.get("part", {}).get("tool") or ev.get("tool") or et)[:80],
                    incident_id=incident_id,
                    payload=ev if isinstance(ev, dict) else {},
                )
        return {
            "ok": True,
            "session_id": session_id,
            "remote_session_id": getattr(remote, "remote_session_id", "") or rid,
            "text": text,
            "remote_status": getattr(remote, "status", "") or "",
            "raw_events": raw_events,
        }

    # ---- Prompt ----

    def build_prompt(self, incident_id: str) -> str:
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not inc:
            return f"incident {incident_id} not found"
        asset_id = inc["asset_id"] or ""
        object_id = inc["object_id"] or ""
        lines = [
            f"# Incident {incident_id}",
            f"title: {inc['title']}",
            f"asset: {asset_id}  object: {object_id}",
            f"severity: {inc['severity']}  status: {inc['status']}  stage: {inc['stage']}",
            f"generation: {inc['generation']}",
            "",
            "## 任务",
            "调查并恢复服务；SSH 成功 ≠ 恢复，必须指标/探针验证。",
            "流程：knowledge.query → host.exec(read) + metrics.query → 最小修复 → 验证 → incident.note。",
            "若发现与同一会话内其它故障同源，合并处理并在 note 中说明关联。",
            "",
        ]
        if self.knowledge is not None:
            try:
                ctx = self.knowledge.investigation_context(asset_id, object_id)
                text = (ctx.get("context_text") or "").strip()
                if text:
                    lines += ["## Knowledge 命中", text, ""]
                else:
                    lines += ["## Knowledge 命中", "（无 active 命中）", ""]
            except Exception:
                lines += ["## Knowledge 命中", "（检索失败）", ""]
        notes = self.db.query(
            "SELECT title, at FROM events WHERE incident_id=? AND type IN ('agent_note','session_opened')"
            " ORDER BY id DESC LIMIT 5",
            (incident_id,),
        )
        if notes:
            lines += ["## 既有记录"]
            for n in notes:
                lines.append(f"- {n['title']}")
            lines.append("")
        return "\n".join(lines)

    def build_session_prompt(self, session_id: str) -> str:
        incs = self.duty.incidents(session_id)
        if not incs:
            return "你是值班运维 Agent。用户将描述运维任务，请调查并给出可核对证据。"
        lines = ["# 值班会话", f"关联 Incident {len(incs)} 个：", ""]
        for i in incs:
            lines.append(
                f"- {i.get('incident_id')}: {i.get('title')} "
                f"[{i.get('severity')}/{i.get('status')}] asset={i.get('asset_id')} object={i.get('object_id')}"
            )
        lines += [
            "",
            "## 任务",
            "判断这些故障是否同源；同源合并处理，异源分别调查。",
            "SSH 成功 ≠ 恢复，必须指标/探针验证。写操作需按当前审批策略执行。",
        ]
        return "\n".join(lines)

    def refresh_prompt(self, incident_id: str) -> str:
        prompt = self.build_prompt(incident_id)
        sess = self.duty.session_for_incident(incident_id)
        if sess:
            with self.db.tx() as conn:
                conn.execute(
                    "UPDATE duty_sessions SET prompt=?, updated_at=? WHERE id=?",
                    (prompt, now(), sess["id"]),
                )
        return prompt

    # ---- 写操作幂等 ----

    def make_action_key(
        self,
        target: str,
        action: str,
        params: dict[str, Any] | None = None,
        *,
        context: str = "",
    ) -> str:
        import hashlib

        canonical = json.dumps(
            {
                "target": (target or "").strip(),
                "action": (action or "").strip(),
                "params": params or {},
                "context": (context or "").strip(),
            },
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        safe_target = re.sub(r"[^A-Za-z0-9._:-]", "_", (target or "t")[:32])
        safe_action = re.sub(r"[^A-Za-z0-9._:-]", "_", (action or "a")[:32])
        return f"{safe_target}:{safe_action}:{digest}"

    def _lease_seconds(self) -> float:
        return float(getattr(self, "lease_ttl_sec", 120.0))

    def _session_id_for(self, incident_id: str) -> str:
        sess = self.duty.session_for_incident(incident_id)
        return (sess or {}).get("id") or ""

    def claim_write(
        self,
        incident_id: str,
        action_key: str,
        *,
        target: str = "",
        params: dict[str, Any] | None = None,
        claimed_by: str = "",
        retry_safe: bool = False,
        authority_session_id: str = "",
    ) -> dict[str, Any]:
        if not incident_id or not action_key:
            raise ValueError("incident_id and action_key required")
        sid = authority_session_id or self._session_id_for(incident_id)
        if authority_session_id:
            from .agent_authority import resolve_authority
            authority = resolve_authority(self.db, authority_session_id)
            if authority["access_mode"] != "readwrite":
                return {"ok": False, "claimed": False, "error": "readonly_mode_rejects_write"}
        t = now()
        lease = t + self._lease_seconds()
        params_hash = ""
        if params:
            import hashlib

            params_hash = hashlib.sha256(
                json.dumps(params, sort_keys=True, ensure_ascii=False, default=str).encode()
            ).hexdigest()[:16]

        try:
            with self.db.tx() as conn:
                conn.execute(
                    "INSERT INTO session_write_ops("
                    " id, incident_id, session_id, action_key, status, result,"
                    " created_at, updated_at, lease_expires_at, target, params_hash, claimed_by)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        new_id("wop"),
                        incident_id,
                        sid,
                        action_key,
                        "claimed",
                        "",
                        t,
                        t,
                        lease,
                        (target or "")[:120],
                        params_hash,
                        (claimed_by or "")[:64],
                    ),
                )
            return {"ok": True, "claimed": True, "action_key": action_key, "already_done": False}
        except Exception:
            pass

        row = self.db.query_one(
            "SELECT * FROM session_write_ops WHERE incident_id=? AND action_key=?",
            (incident_id, action_key),
        )
        if not row:
            return {"ok": False, "error": "claim_failed", "action_key": action_key}
        st = row["status"] if "status" in row.keys() else ""
        lease_exp = float(row["lease_expires_at"] or 0) if "lease_expires_at" in row.keys() else 0.0

        if st == "done":
            return {
                "ok": False,
                "claimed": False,
                "already_done": True,
                "action_key": action_key,
                "status": st,
                "result": row["result"] or "",
            }
        if st == "unknown":
            return {
                "ok": False,
                "claimed": False,
                "already_done": False,
                "unknown": True,
                "action_key": action_key,
                "status": st,
                "result": row["result"] or "",
            }
        if st == "claimed":
            if lease_exp >= t:
                return {
                    "ok": False,
                    "claimed": False,
                    "in_flight": True,
                    "action_key": action_key,
                    "status": st,
                }
            with self.db.tx() as conn:
                conn.execute(
                    "UPDATE session_write_ops SET status='unknown', result=?, updated_at=?"
                    " WHERE incident_id=? AND action_key=? AND status='claimed' AND lease_expires_at<?",
                    ("lease_expired", now(), incident_id, action_key, t),
                )
            return {
                "ok": False,
                "claimed": False,
                "unknown": True,
                "action_key": action_key,
                "status": "unknown",
                "reason": "lease_expired",
            }
        if st == "failed" and not retry_safe:
            return {
                "ok": False,
                "claimed": False,
                "action_key": action_key,
                "status": st,
                "error": "retry_requires_confirmed_safe",
            }

        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE session_write_ops SET status='claimed', updated_at=?, lease_expires_at=?,"
                " claimed_by=? WHERE incident_id=? AND action_key=?"
                " AND status IN ('released','failed')",
                (now(), lease, (claimed_by or "")[:64], incident_id, action_key),
            )
            changed = cur.rowcount == 1
        if changed:
            return {"ok": True, "claimed": True, "action_key": action_key, "already_done": False, "retry": True}
        row2 = self.db.query_one(
            "SELECT status, result FROM session_write_ops WHERE incident_id=? AND action_key=?",
            (incident_id, action_key),
        )
        st2 = (row2["status"] if row2 else "") or ""
        return {
            "ok": False,
            "claimed": False,
            "in_flight": st2 == "claimed",
            "already_done": st2 == "done",
            "unknown": st2 == "unknown",
            "action_key": action_key,
            "status": st2,
        }

    def complete_write(
        self, incident_id: str, action_key: str, *, ok: bool, result: str = ""
    ) -> dict[str, Any]:
        status = "done" if ok else "failed"
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE session_write_ops SET status=?, result=?, updated_at=?, lease_expires_at=0"
                " WHERE incident_id=? AND action_key=? AND status='claimed'",
                (status, (result or "")[:2000], now(), incident_id, action_key),
            )
        return {"ok": True, "status": status, "action_key": action_key}

    def mark_unknown(
        self, incident_id: str, action_key: str, *, reason: str = "unknown_result"
    ) -> dict[str, Any]:
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE session_write_ops SET status='unknown', result=?, updated_at=?, lease_expires_at=0"
                " WHERE incident_id=? AND action_key=? AND status IN ('claimed','failed')",
                (f"unknown:{(reason or '')[:180]}", now(), incident_id, action_key),
            )
        return {"ok": True, "status": "unknown", "action_key": action_key}

    def release_write(
        self, incident_id: str, action_key: str, *, confirmed_safe: bool = False, reason: str = ""
    ) -> dict[str, Any]:
        row = self.db.query_one(
            "SELECT status FROM session_write_ops WHERE incident_id=? AND action_key=?",
            (incident_id, action_key),
        )
        st = (row["status"] if row else "") or ""
        if st == "done":
            return {"ok": False, "error": "already_done", "action_key": action_key}
        if st == "unknown" and not confirmed_safe:
            return {"ok": False, "error": "unknown_requires_manual_verify", "action_key": action_key}
        if st == "failed" and not confirmed_safe:
            return {"ok": False, "error": "retry_requires_confirmed_safe", "action_key": action_key}
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE session_write_ops SET status='released', updated_at=?, result=?"
                " WHERE incident_id=? AND action_key=? AND status IN ('claimed','failed','unknown')",
                (now(), (reason or "released")[:200], incident_id, action_key),
            )
        return {"ok": True, "action_key": action_key, "status": "released"}

    def is_write_done(self, incident_id: str, action_key: str) -> bool:
        row = self.db.query_one(
            "SELECT status FROM session_write_ops WHERE incident_id=? AND action_key=?",
            (incident_id, action_key),
        )
        return bool(row and row["status"] == "done")

    def write_ops(self, incident_id: str) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM session_write_ops WHERE incident_id=? ORDER BY created_at",
            (incident_id,),
        )
        return [dict(r) for r in rows]

    # ---- 人工审批挂起（工作台）----

    def pending_write(
        self,
        incident_id: str,
        action_key: str,
        *,
        target: str = "",
        params: dict[str, Any] | None = None,
        claimed_by: str = "",
        authority_session_id: str = "",
    ) -> dict[str, Any]:
        """登记待人工批准的写操作。已存在 pending/done 则不重复。"""
        if not incident_id or not action_key:
            raise ValueError("incident_id and action_key required")
        existing = self.db.query_one(
            "SELECT status FROM session_write_ops WHERE incident_id=? AND action_key=?",
            (incident_id, action_key),
        )
        if existing:
            st = existing["status"]
            if st == "awaiting_approval":
                return {"ok": True, "action": "already_pending", "action_key": action_key}
            return {"ok": False, "error": "already_exists", "status": st, "action_key": action_key}
        sid = authority_session_id or self._session_id_for(incident_id)
        if authority_session_id:
            from .agent_authority import resolve_authority
            authority = resolve_authority(self.db, authority_session_id)
            if authority["access_mode"] != "readwrite":
                return {"ok": False, "error": "readonly_mode_rejects_write"}
            params = {**(params or {}), "_ayana_session_id": authority_session_id}
        t = now()
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO session_write_ops("
                " id, incident_id, session_id, action_key, status, result,"
                " created_at, updated_at, lease_expires_at, target, params_hash, claimed_by)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    new_id("wop"),
                    incident_id,
                    sid,
                    action_key,
                    "awaiting_approval",
                    json.dumps(params or {}, ensure_ascii=False),
                    t,
                    t,
                    0,
                    (target or "")[:120],
                    "",
                    (claimed_by or "")[:64],
                ),
            )
        return {"ok": True, "action": "pending", "action_key": action_key}

    def list_pending_writes(self, *, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM session_write_ops WHERE status='awaiting_approval'"
            " ORDER BY created_at DESC LIMIT ?",
            (int(limit),),
        )
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["params"] = json.loads(d.get("result") or "{}")
            except Exception:
                d["params"] = {}
            out.append(d)
        return out

    def approve_pending_write(self, incident_id: str, action_key: str, *, approved_by: str = "") -> dict[str, Any]:
        """A successful atomic claim is the only authorization to dispatch."""
        with self.db.tx() as conn:
            if not conn.in_transaction:conn.execute("BEGIN IMMEDIATE")
            row=conn.execute("SELECT * FROM session_write_ops WHERE incident_id=? AND action_key=?",(incident_id,action_key)).fetchone()
            if not row:return {"ok":False,"error":"not_found"}
            state=row["status"]
            if state!="awaiting_approval":
                error="already_done" if state=="done" else "in_flight" if state=="claimed" else "not_pending"
                return {"ok":False,"error":error,"status":state,"action_key":action_key}
            params = self._params_of(row)
            authority_sid = str(params.get("_ayana_session_id") or "")
            if authority_sid:
                from .agent_authority import AuthorityError, resolve_authority
                if authority_sid != str(row["session_id"] or ""):
                    return {"ok": False, "error": "pending_session_mismatch"}
                try:
                    authority = resolve_authority(self.db, authority_sid, conn=conn)
                except AuthorityError as exc:
                    return {"ok": False, "error": exc.code}
                if authority["access_mode"] != "readwrite":
                    return {"ok": False, "error": "readonly_mode_rejects_write"}
            t=now()
            cur=conn.execute("UPDATE session_write_ops SET status='claimed',updated_at=?,lease_expires_at=?,claimed_by=? WHERE incident_id=? AND action_key=? AND status='awaiting_approval'",(t,t+self._lease_seconds(),(approved_by or "human")[:64],incident_id,action_key))
            if cur.rowcount!=1:return {"ok":False,"error":"in_flight","action_key":action_key}
            return {"ok":True,"claimed":True,"action_key":action_key,"params":self._params_of(row)}

    def reject_pending_write(
        self,
        incident_id: str,
        action_key: str,
        *,
        reason: str = "human_rejected",
    ) -> dict[str, Any]:
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE session_write_ops SET status='failed', result=?, updated_at=?"
                " WHERE incident_id=? AND action_key=? AND status='awaiting_approval'",
                (f"rejected:{(reason or '')[:120]}", now(), incident_id, action_key),
            )
        return {"ok": True, "status": "failed", "action_key": action_key}

    @staticmethod
    def _params_of(row: Any) -> dict[str, Any]:
        try:
            raw = row["result"] if "result" in row.keys() else ""
            data = json.loads(raw or "{}")
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
