"""工单闭环：告警 → 调查 → 自主处置 → 验证 → 结案；失败转人工并通知。

硬保护复用 ActionService / session_write_ops / transport。
软约束文本由 OpsConstraints 提供，实际停止条件在本模块强制。
"""

from __future__ import annotations

import json
from typing import Any

from .db import new_id, now

log = __import__("logging").getLogger("ayana.ops_loop")

# 软约束硬编码上限（与提示词一致，执行层强制）
MAX_NO_PROGRESS_ROUNDS = 3
MAX_SAME_PLAN_FAILURES = 2


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
        row = self.db.query_one(
            "SELECT * FROM ops_loop_state WHERE incident_id=?", (incident_id,)
        )
        if row:
            return dict(row)
        self.db.execute(
            "INSERT INTO ops_loop_state(incident_id, generation, rounds, no_progress_rounds,"
            " same_plan_failures, last_plan_sig, status, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (incident_id, 1, 0, 0, 0, "", "idle", now()),
        )
        row = self.db.query_one(
            "SELECT * FROM ops_loop_state WHERE incident_id=?", (incident_id,)
        )
        return dict(row) if row else {
            "incident_id": incident_id,
            "generation": 1,
            "rounds": 0,
            "no_progress_rounds": 0,
            "same_plan_failures": 0,
            "last_plan_sig": "",
            "status": "idle",
        }

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
    ) -> dict[str, Any]:
        """自主写 + 验证。失败/unknown 记软约束。"""
        if not self.actions:
            return {"ok": False, "error": "actions_unavailable"}
        try:
            res = await self.actions.autonomous_execute(
                asset_id=asset_id,
                object_id=object_id,
                capability=capability,
                params=params,
                reason=reason or "ops_loop_autonomous",
                incident_id=incident_id,
            )
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", "exec_failed")
            self.note_round(
                incident_id, progressed=False, plan_sig=plan_sig or capability,
                write_ok=False, result=str(e)[:300],
            )
            return {"ok": False, "error": code, "message": str(e)[:300]}

        state = str(res.get("state") or "")
        action_id = res.get("id") or res.get("action_id") or ""
        ok = state == "success"
        verify: dict[str, Any] = {}
        if action_id and self.actions:
            try:
                verify = await self.actions.verify(action_id)
            except Exception as e:  # noqa: BLE001
                verify = {"ok": False, "error": str(e)[:200]}
        v_ok = bool(verify.get("ok")) or verify.get("status") == "passed"
        progressed = ok and v_ok
        self.note_round(
            incident_id,
            progressed=progressed,
            plan_sig=plan_sig or capability,
            write_ok=ok if state in ("success", "failure", "unknown") else None,
            result=f"{state}:{verify.get('status', '')}",
        )
        return {
            "ok": progressed,
            "action_id": action_id,
            "state": state,
            "verify": verify,
            "detail": res.get("detail", ""),
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
            self._save(incident_id, status="done")
            return {"ok": True, "closed": True, "reconcile": rec}
        return {"ok": True, "closed": False, "reconcile": rec}

    def status(self, incident_id: str) -> dict[str, Any]:
        return self._state(incident_id)


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
          updated_at REAL NOT NULL DEFAULT 0
        )
        """
    )
