"""退役调度器的历史状态与带代次的恢复收尾。

现役执行由同一 MiMoCode 会话通过 host.exec 完成；此处的旧预算
不代表当前原生任务状态，也不控制 host.exec。历史记录继续保留。
"""

from __future__ import annotations

import json
from typing import Any

from .db import new_id, now

log = __import__("logging").getLogger("ayana.ops_loop")

# 软约束硬编码上限（与提示词一致，执行层强制）
MAX_NO_PROGRESS_ROUNDS = 3
MAX_SAME_PLAN_FAILURES = 2
# P6.2：执行前硬限制，防止无限自治循环
MAX_EXECUTE_ROUNDS = 8
# preflight（对象/档案/目标缺失等，未真正执行）不占执行失败预算，独立限次与冷却
MAX_PREFLIGHT_BLOCKS = 3
PREFLIGHT_COOLDOWN_SEC = 120.0
PREFLIGHT_CODES = frozenset({
    "object_not_registered", "object_missing", "object_binding",
    "unsupported_verification_profile", "target_not_found",
    "bad_params", "not_a_write_capability", "template_required",
    "runbook_required", "bad_mode",
})


def close_recovered(
    db: Any,
    incident_id: str,
    *,
    generation: int | None = None,
    result: str = "recovered",
    evidence: Any = None,
) -> bool:
    """恢复收尾：绑定 incident/generation，防旧代迟到回写。

    只有证据充分的恢复结论才走到这里；动作成功 ≠ 故障恢复。
    """
    with db.tx() as conn:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        inc = conn.execute("SELECT generation FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not inc:
            return False
        gen = int(inc["generation"] or 1)
        if generation is not None and int(generation) != gen:
            return False  # 迟到的旧代回写，丢弃
        row = conn.execute(
            "SELECT generation, status FROM ops_loop_state WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            return True  # 无 loop 记录：没有脏状态需要收尾
        if int(row["generation"] or 1) != gen:
            return False  # loop 记录属于旧代，交给代次重置
        conn.execute(
            "UPDATE ops_loop_state SET status='done', stop_reason='', last_result=?, updated_at=?"
            " WHERE incident_id=? AND generation=?",
            (result, now(), incident_id, gen),
        )
        return True


class OpsLoop:
    def __init__(
        self,
        db: Any,
        *,
        actions: Any = None,
        incidents: Any = None,
        bridge: Any = None,
        notifier: Any = None,
        constraints: Any = None,
    ):
        self.db = db
        self.actions = actions
        self.incidents = incidents
        self.bridge = bridge
        self.notifier = notifier
        self.constraints = constraints

    def _state(self, incident_id: str) -> dict[str, Any]:
        with self.db.tx() as conn:
            if not conn.in_transaction:conn.execute("BEGIN IMMEDIATE")
            incident=conn.execute("SELECT generation FROM incidents WHERE id=?",(incident_id,)).fetchone()
            generation=int(incident["generation"] or 1) if incident else 1
            row=conn.execute("SELECT * FROM ops_loop_state WHERE incident_id=?",(incident_id,)).fetchone()
            if row and int(row["generation"] or 1)==generation:return dict(row)
            if row:
                self.db.event("ops_loop_generation_reset","新一代工单使用新的处置预算",incident_id=incident_id,payload={"previous_generation":row["generation"],"generation":generation,"previous_status":row["status"],"previous_rounds":row["rounds"]})
            conn.execute("INSERT INTO ops_loop_state(incident_id,generation,rounds,no_progress_rounds,same_plan_failures,last_plan_sig,status,stop_reason,last_result,updated_at,preflight_blocks,preflight_at) VALUES(?,?,0,0,0,'','idle','','',?,0,0) ON CONFLICT(incident_id) DO UPDATE SET generation=excluded.generation,rounds=0,no_progress_rounds=0,same_plan_failures=0,last_plan_sig='',status='idle',stop_reason='',last_result='',updated_at=excluded.updated_at,preflight_blocks=0,preflight_at=0",(incident_id,generation,now()))
            return dict(conn.execute("SELECT * FROM ops_loop_state WHERE incident_id=?",(incident_id,)).fetchone())

    def _same_generation(self, incident_id: str, generation: int) -> bool:
        row=self.db.query_one("SELECT generation FROM incidents WHERE id=?",(incident_id,))
        return not row or int(row["generation"] or 1)==generation

    def _save(self, incident_id: str, **fields: Any) -> None:
        if not fields:
            return
        keys = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(
            f"UPDATE ops_loop_state SET {keys}, updated_at=? WHERE incident_id=?",
            (*fields.values(), now(), incident_id),
        )

    def note_round(
        self,
        incident_id: str,
        *,
        progressed: bool,
        plan_sig: str = "",
        write_ok: bool | None = None,
        result: str = "",
    ) -> dict[str, Any]:
        """记录一轮结果并返回是否应停止。软约束在此强制。"""
        st = self._state(incident_id)
        if st.get("status") in ("done", "stopped", "need_human"):
            return {"ok": True, "skipped": "loop_stopped", "stop": True,
                    "stop_reason": st.get("stop_reason") or ""}
        rounds = int(st.get("rounds") or 0) + 1
        no_prog = 0 if progressed else int(st.get("no_progress_rounds") or 0) + 1
        same_fail = int(st.get("same_plan_failures") or 0)
        last_sig = str(st.get("last_plan_sig") or "")
        if plan_sig and write_ok is False:
            if plan_sig == last_sig:
                same_fail += 1
            else:
                same_fail = 1
            last_sig = plan_sig
        elif plan_sig and write_ok is True:
            same_fail = 0
            last_sig = plan_sig

        stop_reason = ""
        if no_prog >= MAX_NO_PROGRESS_ROUNDS:
            stop_reason = "no_progress_3_rounds"
        elif same_fail >= MAX_SAME_PLAN_FAILURES:
            stop_reason = "same_plan_failed_twice"

        status = "stopped" if stop_reason else "running"
        self._save(
            incident_id,
            rounds=rounds,
            no_progress_rounds=no_prog,
            same_plan_failures=same_fail,
            last_plan_sig=last_sig,
            status=status,
            stop_reason=stop_reason or "",
            last_result=(result or "")[:500],
        )
        out = {
            "ok": True,
            "rounds": rounds,
            "no_progress_rounds": no_prog,
            "same_plan_failures": same_fail,
            "stop": bool(stop_reason),
            "stop_reason": stop_reason,
        }
        if stop_reason:
            self.escalate(incident_id, reason=stop_reason, detail=out)
        return out

    def escalate(self, incident_id: str, *, reason: str, detail: Any = None) -> dict[str, Any]:
        """转人工：记 need_human、写事件、通知。"""
        self._state(incident_id)  # 确保状态行存在
        if self.incidents:
            try:
                self.incidents.set_need_human(incident_id, reason)
            except Exception as e:  # noqa: BLE001
                log.warning("set_need_human failed: %s", e)
        self.db.event(
            "need_human",
            f"ops_loop:{reason}",
            incident_id=incident_id,
            payload={"reason": reason, "detail": detail or {}},
        )
        self._save(incident_id, status="need_human", stop_reason=reason)
        if self.notifier:
            try:
                self.notifier.on_event(
                    {
                        "type": "need_human",
                        "incident_id": incident_id,
                        "title": f"ops_loop 转人工: {reason}",
                        "payload_json": json.dumps({"reason": reason}, ensure_ascii=False),
                    }
                )
            except Exception as e:  # noqa: BLE001
                log.warning("notify failed: %s", e)
        return {"ok": True, "need_human": True, "reason": reason}

    def note_preflight_block(
        self, incident_id: str, *, plan_sig: str = "", code: str = ""
    ) -> dict[str, Any]:
        """preflight 拦截：不占执行失败预算，独立限次 + 冷却，原因精确记录。"""
        st = self._state(incident_id)
        if st.get("status") in ("need_human", "stopped", "done"):
            return {"blocked": True, "stop_reason": st.get("stop_reason") or ""}
        n = int(st.get("preflight_blocks") or 0) + 1
        self._save(
            incident_id,
            preflight_blocks=n,
            preflight_at=now(),
            last_result=f"preflight_blocked:{code}",
        )
        if n >= MAX_PREFLIGHT_BLOCKS:
            self.escalate(
                incident_id,
                reason=f"preflight_blocked:{code}",
                detail={"blocks": n, "plan_sig": plan_sig},
            )
            return {"blocked": True, "limit": n, "code": code}
        return {
            "blocked": False,
            "blocks": n,
            "code": code,
            "cooldown_until": now() + PREFLIGHT_COOLDOWN_SEC,
        }

    def record_action_progress(
        self, incident_id: str, *, plan_sig: str = "", result: str = "action_success",
        generation: int | None = None,
    ) -> None:
        """动作成功 ≠ 故障恢复：只推进度（清失败计数），不结案。"""
        with self.db.tx() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            if generation is not None and not self._same_generation(incident_id, generation):
                return
            st = self._state(incident_id)
            if st.get("status") in ("done", "stopped", "need_human"):
                return
            # 执行轮次由 run_action_and_verify 统一计数；hook 只记进度。
            self._save(incident_id, no_progress_rounds=0, same_plan_failures=0,
                       last_plan_sig=plan_sig or st.get("last_plan_sig") or "",
                       last_result=result[:500])

    async def run_action_and_verify(
        self,
        *,
        incident_id: str,
        asset_id: str,
        object_id: str,
        capability: str,
        params: dict | None = None,
        reason: str = "",
        plan_sig: str = "",
        authority_session_id: str = "",
    ) -> dict[str, Any]:
        """旧结构化动作执行已退役：MiMoCode 通过 host.exec 自行调查/修复/验证。"""
        return {
            "ok": False,
            "error": "action_service_retired",
            "message": "结构化动作执行已退役；请通过 host.exec 由 MiMoCode 自行处置",
        }

    def maybe_close(self, incident_id: str) -> dict[str, Any]:
        """验证通过且告警消失则结案；否则保留证据。"""
        if not self.incidents:
            return {"ok": False, "error": "incidents_unavailable"}
        try:
            rec = self.incidents.reconcile(incident_id)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)[:200]}
        if rec.get("outcome") == "recovered":
            closed = close_recovered(self.db, incident_id,
                                     generation=int(rec.get("generation") or 0) or None,
                                     result="recovered")
            return {"ok": True, "closed": closed, "reconcile": rec}
        return {"ok": True, "closed": False, "reconcile": rec}

    def status(self, incident_id: str) -> dict[str, Any]:
        """Read a legacy snapshot without creating or resetting scheduler state."""
        row = self.db.query_one("SELECT * FROM ops_loop_state WHERE incident_id=?", (incident_id,))
        if row is not None:
            return dict(row)
        inc = self.db.query_one("SELECT generation FROM incidents WHERE id=?", (incident_id,))
        return {"incident_id": incident_id, "generation": int(inc["generation"] or 1) if inc else 1,
                "status": "idle", "recorded": False}

    def observed_status(self, incident_id: str) -> dict[str, Any]:
        """Expose present incident facts separately from the retired scheduler."""
        with self.db.tx() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN")
            raw_inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            raw_loop = conn.execute("SELECT * FROM ops_loop_state WHERE incident_id=?", (incident_id,)).fetchone()
            source = dict(raw_inc) if raw_inc is not None else {}
            snapshot = dict(raw_loop) if raw_loop is not None else None
        fields = ("id", "generation", "status", "stage", "outcome", "need_human",
                  "need_human_reason", "resolution_basis", "resolved_at")
        incident = {key: source.get(key) for key in fields} if source else None
        return {"execution_mode": "session_host_exec", "retired": True, "status": "retired",
                "incident": incident,
                "legacy_loop": {"retired": True, "active": False, "snapshot": snapshot,
                                "same_generation": bool(source and snapshot and
                                    int(source["generation"] or 1) == int(snapshot["generation"] or 1))},
                "message": "旧 Action/OpsLoop 调度已退役，历史状态不代表当前任务或恢复结论；"
                           "当前执行请查看原生会话任务，故障恢复请核对本代证据。"}


def ensure_ops_loop_schema(db: Any) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS ops_loop_state (
          incident_id TEXT PRIMARY KEY,
          generation INTEGER NOT NULL DEFAULT 1,
          rounds INTEGER NOT NULL DEFAULT 0,
          no_progress_rounds INTEGER NOT NULL DEFAULT 0,
          same_plan_failures INTEGER NOT NULL DEFAULT 0,
          last_plan_sig TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'idle',
          stop_reason TEXT NOT NULL DEFAULT '',
          last_result TEXT NOT NULL DEFAULT '',
          updated_at REAL NOT NULL DEFAULT 0,
          preflight_blocks INTEGER NOT NULL DEFAULT 0,
          preflight_at REAL NOT NULL DEFAULT 0
        )
        """
    )
    existing = {row[1] for row in db.query("PRAGMA table_info(ops_loop_state)")}
    for column, definition in (
        ("preflight_blocks", "INTEGER NOT NULL DEFAULT 0"),
        ("preflight_at", "REAL NOT NULL DEFAULT 0"),
    ):
        if column not in existing:
            db.execute(f"ALTER TABLE ops_loop_state ADD COLUMN {column} {definition}")
