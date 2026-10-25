"""Incident → Session 薄桥（SpeedSupreme P2）。

分工：
- Incident 管事实（告警、状态、恢复证据）
- Session 管调查（上下文、过程、决策痕迹）
- Execution 管动作（审批/执行/审计/验证 —— 仍由 ActionService 负责）

本模块只做四件事，多了算失败：
1. 建/找 session（同 incident 复用，不重复创建）
2. 生成结构化 prompt
3. 记 incident_id ↔ session_id 映射（落库，重启可恢复）
4. 写操作幂等台账（同一 action_key 不重复执行已完成写）

禁止：第二套 Agent Runtime / 调度状态机 / Planner / 自动处置决策。
旧 Council 自治保持禁用，不因 P2 重新启用。
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from .db import new_id, now


class SessionBridge:
    """薄桥：映射、复用、幂等。无调度、无决策。

    P3：本地 sess_* 为 Ayana 稳定标识；MiMo 远端 ses_* 单独记账。
    远端失效只重建远端，不丢本地调查记录，也不重放写操作。
    """

    def __init__(self, db: Any, knowledge: Any = None, mimo: Any = None):
        self.db = db
        self.knowledge = knowledge
        self.mimo = mimo  # MimoSessionClient | None

    # ---- 映射 / 会话 ----

    def get_mapping(self, incident_id: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT * FROM incident_session WHERE incident_id=?", (incident_id,)
        )
        return dict(row) if row else None

    def ensure_session(self, incident_id: str, *, generation: int | None = None) -> dict[str, Any]:
        """新 Incident 自动建 session；已有则复用（重复告警不重复创建）。"""
        if not incident_id:
            raise ValueError("incident_id required")
        existing = self.get_mapping(incident_id)
        if existing:
            if generation is not None and int(existing.get("generation") or 1) != int(generation):
                # 升级/新一代：保留同一 session，只推进 generation（可重复调查）
                with self.db.tx() as conn:
                    conn.execute(
                        "UPDATE incident_session SET generation=?, updated_at=? WHERE incident_id=?",
                        (int(generation), now(), incident_id),
                    )
                existing = self.get_mapping(incident_id)
            return {"ok": True, "action": "reused", **existing, **self._remote_fields(existing)}

        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not inc:
            return {"ok": False, "error": "incident_not_found", "incident_id": incident_id}
        gen = int(generation if generation is not None else (inc["generation"] or 1))
        sid = new_id("sess")
        prompt = self.build_prompt(incident_id)
        t = now()
        try:
            with self.db.tx() as conn:
                conn.execute(
                    "INSERT INTO incident_session(incident_id, generation, session_id, status, prompt,"
                    " created_at, updated_at) VALUES(?,?,?,?,?,?,?)",
                    (incident_id, gen, sid, "open", prompt, t, t),
                )
                conn.execute(
                    "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                    (
                        incident_id,
                        t,
                        "session_opened",
                        f"session {sid}",
                        json.dumps({"session_id": sid, "generation": gen}, ensure_ascii=False),
                    ),
                )
        except Exception:
            # 并发下 UNIQUE 撞车 → 复用已有，保证单会话
            existing = self.get_mapping(incident_id)
            if existing:
                return {"ok": True, "action": "reused", **existing, **self._remote_fields(existing)}
            raise
        created = self.get_mapping(incident_id) or {}
        return {"ok": True, "action": "created", **created, **self._remote_fields(created)}

    def close_session(self, incident_id: str, *, reason: str = "") -> dict[str, Any]:
        m = self.get_mapping(incident_id)
        if not m:
            return {"ok": False, "error": "not_found"}
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE incident_session SET status='closed', updated_at=? WHERE incident_id=?",
                (now(), incident_id),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    incident_id,
                    now(),
                    "session_closed",
                    reason or "closed",
                    json.dumps({"session_id": m.get("session_id")}, ensure_ascii=False),
                ),
            )
        return {"ok": True, "action": "closed", **self.get_mapping(incident_id)}

    def list_sessions(self, status: str = "", limit: int = 50) -> list[dict[str, Any]]:
        if status:
            rows = self.db.query(
                "SELECT * FROM incident_session WHERE status=? ORDER BY updated_at DESC LIMIT ?",
                (status, limit),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM incident_session ORDER BY updated_at DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in rows]

    # ---- MiMo 远端会话（P3）----

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
        incident_id: str,
        *,
        remote_session_id: str = "",
        status: str = "none",
        model: str = "",
        last_error: str = "",
        keep_history: bool = True,
    ) -> None:
        m = self.get_mapping(incident_id)
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
        # 只保留最近 10 条历史，且不含密钥
        hist = hist[-10:]
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE incident_session SET remote_session_id=?, remote_status=?,"
                " remote_model=?, remote_last_error=?, remote_history=?, remote_updated_at=?"
                " WHERE incident_id=?",
                (
                    remote_session_id,
                    status,
                    model or "",
                    (last_error or "")[:300],
                    json.dumps(hist, ensure_ascii=False),
                    now(),
                    incident_id,
                ),
            )

    def attach_remote(
        self,
        incident_id: str,
        *,
        title: str = "",
        prompt: str = "",
        force_new: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """本地 Session 关联 MiMo 远端会话。

        - 已有且存活 → 复用（重复告警/重启恢复）
        - 远端失效/缺失 → 保留历史，受控新建（绝不假装 resume）
        - mimo 未接入 → remote_status=none，不阻断事件主流程
        prompt 可覆盖首轮内容（默认用自动生成的调查 prompt）。
        """
        m = self.ensure_session(incident_id)
        if not m.get("ok"):
            return m
        base = {
            "local_session_id": m.get("session_id"),
            "incident_id": incident_id,
        }
        if self.mimo is None:
            self._set_remote(incident_id, status="none")
            return {**base, "ok": True, "action": "no_mimo", "remote_session_id": ""}

        rid = m.get("remote_session_id") or ""
        if rid and not force_new:
            try:
                alive = self.mimo.exists(rid)
            except Exception as e:  # noqa: BLE001
                self._set_remote(incident_id, remote_session_id=rid, status="error", last_error=str(e))
                return {**base, "ok": False, "action": "probe_failed", "remote_session_id": rid, "error": str(e)}
            if alive:
                self._set_remote(incident_id, remote_session_id=rid, status="active", model=getattr(self.mimo, "model", ""))
                return {**base, "ok": True, "action": "reused", "remote_session_id": rid}
            # 远端失效：保留历史后新建
            self._set_remote(incident_id, remote_session_id=rid, status="missing", last_error="remote missing")

        prompt = (prompt or "").strip() or m.get("prompt") or self.build_prompt(incident_id)
        title = title or f"inc:{incident_id}"
        try:
            remote = self.mimo.create(title=title, prompt=prompt, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", "error")
            self._set_remote(
                incident_id,
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
            incident_id,
            remote_session_id=getattr(remote, "remote_session_id", "") or "",
            status=getattr(remote, "status", "") or "active",
            model=getattr(remote, "model", "") or "",
            last_error=getattr(remote, "last_error", "") or "",
        )
        return {
            **base,
            "ok": True,
            "action": "created",
            "remote_session_id": getattr(remote, "remote_session_id", ""),
            "remote_status": getattr(remote, "status", ""),
            # P4.3 E2E：结论 JSON 可能很长，不能截断到 500
            "text": (getattr(remote, "text", "") or ""),
        }

    def prompt_remote(
        self,
        incident_id: str,
        prompt: str,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """向已关联远端会话追加调查 prompt（不重放历史工具调用）。"""
        m = self.get_mapping(incident_id)
        if not m:
            return {"ok": False, "error": "not_found"}
        if self.mimo is None:
            return {"ok": False, "error": "mimo_unavailable"}
        rid = m.get("remote_session_id") or ""
        if not rid:
            attached = self.attach_remote(incident_id, timeout=timeout)
            if not attached.get("ok"):
                return attached
            rid = attached.get("remote_session_id") or ""
        try:
            remote = self.mimo.resume(rid, prompt, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", "error")
            if code == "session_missing":
                self._set_remote(incident_id, remote_session_id=rid, status="missing", last_error=str(e))
                return {"ok": False, "error": "session_missing", "remote_session_id": rid}
            self._set_remote(incident_id, remote_session_id=rid, status="error", last_error=str(e))
            return {"ok": False, "error": code, "message": str(e)}
        self._set_remote(
            incident_id,
            remote_session_id=getattr(remote, "remote_session_id", "") or rid,
            status=getattr(remote, "status", "") or "active",
            model=getattr(remote, "model", "") or "",
            last_error=getattr(remote, "last_error", "") or "",
        )
        return {
            "ok": True,
            "remote_session_id": getattr(remote, "remote_session_id", "") or rid,
            "text": (getattr(remote, "text", "") or ""),
            "remote_status": getattr(remote, "status", ""),
        }

    # ---- Prompt ----

    def build_prompt(self, incident_id: str) -> str:
        """结构化 prompt：告警摘要、对象、knowledge 命中、上一阶段 note。"""
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
        # 上一阶段 note（最近 5 条 agent_note）
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

    def refresh_prompt(self, incident_id: str) -> str:
        prompt = self.build_prompt(incident_id)
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE incident_session SET prompt=?, updated_at=? WHERE incident_id=?",
                (prompt, now(), incident_id),
            )
        return prompt

    # ---- 写操作幂等（P4.1：unknown 态 / 租约 / 原子 claim）----

    def make_action_key(
        self,
        target: str,
        action: str,
        params: dict[str, Any] | None = None,
        *,
        context: str = "",
    ) -> str:
        """规范化幂等键：绑定目标 + 动作 + 参数 + 上下文，非 Agent 随意字符串。"""
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

    def claim_write(
        self,
        incident_id: str,
        action_key: str,
        *,
        target: str = "",
        params: dict[str, Any] | None = None,
        claimed_by: str = "",
        retry_safe: bool = False,
    ) -> dict[str, Any]:
        """占用一次写操作。语义：

        - claimed（租约有效）→ 拒绝（in_flight）
        - claimed（租约过期）→ 置 unknown 并拒绝（租约过期 ≠ 未执行）
        - done → 永久拒绝
        - unknown → 拒绝（需人工核验）
        - failed → 仅 retry_safe=True 才可再 claim
        - released → 可再 claim
        """
        if not incident_id or not action_key:
            raise ValueError("incident_id and action_key required")
        m = self.get_mapping(incident_id)
        sid = (m or {}).get("session_id") or ""
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
            # 租约过期 ≠ 未执行：转入 unknown，禁止自动重放
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

        # released / failed(retry_safe)：原子条件更新，防并发双 claim
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
        # 竞态失败：再读一次
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
        """记录确定结果。ok=False 仅用于「已确认失败/未生效」。"""
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
        """结果未知（超时/断连/进程异常）→ unknown，禁止自动重放。"""
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
        """释放以允许重试。仅 confirmed_safe=True 才放行 failed/unknown 之外的重试窗口。"""
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
