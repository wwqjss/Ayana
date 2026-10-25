"""Human notification obligations and historical event compatibility.

Records exact action/generation obligations and delegates delivery to Notifier.
No planner, proposal creation, automatic dispatch or background scheduler lives here.
Historical event type names remain stable for outbox compensation.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from .actions import action_incident_block
from .db import now
from .runbook import RunbookRule

log = logging.getLogger("ayana.notification_obligations")


class NotificationObligations:
    def __init__(self, db, notifier):
        self.db = db
        self.notifier = notifier

    def _notify_awaiting_approval(
        self,
        inc_id: str,
        action_id: str,
        rule: RunbookRule,
        decision: dict,
        pre_result: dict,
        *,
        evidence_text: str = "",
    ) -> None:
        from .fmt import fmt_approve_request

        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        inc_d = dict(inc) if inc else {"id": inc_id, "title": "", "asset_id": "", "object_id": ""}
        reason = (
            f"awaiting_approval:{action_id} "
            f"decision={decision.get('decision')} "
            f"rule={rule.id}"
        )
        from .incidents import IncidentService

        IncidentService(self.db).set_need_human(inc_id, reason)
        self.db.execute(
            "UPDATE incidents SET stage='awaiting_approval', updated_at=? WHERE id=?",
            (now(), inc_id),
        )
        action = self.db.query_one("SELECT * FROM actions WHERE id=?", (action_id,))
        body = fmt_approve_request(inc_d, dict(action) if action else {
            "capability": rule.capability, "object_id": inc_d.get("object_id") or "",
        }, rule_name=rule.name)
        event_id = None
        payload = {}
        for event in self.db.query(
            "SELECT id,payload_json FROM events WHERE incident_id=? AND type='proposal_waiting'"
            " ORDER BY id DESC", (inc_id,),
        ):
            candidate = json.loads(event["payload_json"] or "{}")
            if candidate.get("action_id") == action_id:
                event_id, payload = event["id"], candidate
                break
        payload.update({
            "action_id": action_id, "rule": rule.id,
            "generation": int(inc_d.get("generation") or 1), "body": body,
            "decision": decision.get("decision"), "preconditions": pre_result.get("status"),
            "evidence_summary": (evidence_text or "")[:400],
        })
        if event_id is None:
            event_id = self.db.event(
                "proposal_waiting", "等待人工授权", incident_id=inc_id, payload=payload,
            )
        else:
            self.db.execute(
                "UPDATE events SET payload_json=? WHERE id=?",
                (json.dumps(payload, ensure_ascii=False), event_id),
            )
        self._notify_event(event_id, "proposal_waiting", body)


    def _notify_event(self, event_id: int | None, typ: str, body: str) -> None:
        """先落事件义务；发送异常由 outbox 补偿，不反向改变处置状态。"""
        try:
            if hasattr(self.notifier, "enqueue_for_event"):
                self.notifier.enqueue_for_event(event_id, body=body, typ=typ)
            else:
                # 兼容只收集文案的轻量测试替身。
                self.notifier.enqueue(dedup_key=f"ev:{event_id}", target="", body=body)
        except Exception:
            log.exception("notification deferred to compensation: %s", event_id)


    def _generation_cutoff(self, inc_id: str) -> float:
        row = self.db.query_one(
            "SELECT at FROM events WHERE incident_id=? AND type IN"
            " ('generation_bumped','incident_reopened','incident_opened')"
            " ORDER BY id DESC LIMIT 1", (inc_id,),
        )
        return float(row["at"]) if row else 0.0


    def _incident_context_current(self, inc: dict, result: dict | None = None) -> bool:
        """异步调查只属于启动时的故障代次，迟到上下文不能改写终态或新代。"""
        current = self.db.query_one("SELECT status,generation FROM incidents WHERE id=?", (inc["id"],))
        same = bool(current and current["status"] == "open"
                    and int(current["generation"] or 1) == int(inc.get("generation") or 1))
        if not same and result is not None:
            result["action"] = "skipped_incident_changed"
            result["skipped"] = "stale_generation" if current and (
                int(current["generation"] or 1) != int(inc.get("generation") or 1)
            ) else "not_open"
        return same


    def _current_actions(self, inc_id: str) -> list[Any]:
        rows = self.db.query(
            "SELECT * FROM actions WHERE incident_id=? AND created_at>=?"
            " AND state IN ('proposed','approved','dispatched','success','unknown')"
            " ORDER BY created_at DESC",
            (inc_id, self._generation_cutoff(inc_id)),
        )
        return [row for row in rows if not action_incident_block(self.db, row)]


    def _current_rejection(self, inc_id: str) -> Any | None:
        cutoff = self._generation_cutoff(inc_id)
        rows = self.db.query(
            "SELECT a.* FROM actions a JOIN audit_log l ON l.action_id=a.id"
            " WHERE a.incident_id=? AND a.created_at>=? AND l.at>=?"
            " AND l.entry='action_rejected' ORDER BY l.at DESC",
            (inc_id, cutoff, cutoff),
        )
        return next((row for row in rows if not action_incident_block(self.db, row)), None)


    def _waiting_state(self, inc: dict) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT id,payload_json FROM events WHERE incident_id=? AND type='agent_waiting'"
            " ORDER BY id DESC LIMIT 1", (inc["id"],),
        )
        if not row:
            return None
        try:
            payload = json.loads(row["payload_json"] or "{}")
            if int(payload.get("generation") or 1) == int(inc.get("generation") or 1):
                payload["_event_id"] = row["id"]
                return payload
        except (TypeError, ValueError):
            pass
        return None


    def _wait_for_preconditions(
        self, inc: dict, rule: RunbookRule | None, result: dict, pre_result: dict,
    ) -> dict[str, Any]:
        """记录有界的人工等待义务；不创建 Action、不调用模型、不调度执行。"""
        from .fmt import fmt_auto_wait

        if not self._incident_context_current(inc, result):
            return result
        blockers = pre_result.get("blockers") or [
            r.split(":", 1)[0] for r in pre_result.get("reasons") or []
        ]
        labels = {
            "fresh_failed_probe": "等待新鲜失败探测",
            "service_state": "等待服务状态满足处置条件",
            "exec_channel": "执行通道暂不可用，等待重试",
            "global_pause": "全局自动执行已暂停，等待恢复",
            "policy": "自动执行权限状态已变化，等待重新检查",
            "object_lock": "等待对象上的操作完成",
            "source_health": "告警来源暂不可用，等待恢复后重新检查",
            "budget": pre_result.get("budget_reason") or "自动处置限速中",
        }
        reason = "；".join(dict.fromkeys(labels.get(b, "等待处置条件满足") for b in blockers))
        retry_at = max(now() + 30, float(pre_result.get("retry_at") or 0))
        previous = self._waiting_state(inc)
        same_wait = bool(previous and previous.get("blockers") == blockers
                         and previous.get("rule") == (rule.id if rule else ""))
        payload = dict(previous) if same_wait else {}
        event_id = payload.pop("_event_id", None)
        body = fmt_auto_wait(inc, reason=reason, retry_at=retry_at)
        payload.update({
            "generation": int(inc.get("generation") or 1),
            "rule": rule.id if rule else "",
            "reasons": pre_result.get("reasons") or [],
            "blockers": blockers,
            "reason": reason,
            "retry_at": retry_at,
            "body": body,
        })
        self.db.execute(
            "UPDATE incidents SET stage='watching', updated_at=? WHERE id=? AND need_human=0"
            " AND status='open' AND generation=?",
            (now(), inc["id"], int(inc.get("generation") or 1)),
        )
        if event_id is None:
            event_id = self.db.event(
                "agent_waiting", reason, incident_id=inc["id"], payload=payload,
            )
        else:
            self.db.execute(
                "UPDATE events SET payload_json=? WHERE id=?",
                (json.dumps(payload, ensure_ascii=False), event_id),
            )
        # 同代次同一原因只通知一次；周期性重检仍记录准确的下次时间。
        if not same_wait:
            self._notify_event(event_id, "agent_waiting", body)
        result["action"] = "waiting_precondition"
        result["retry_at"] = retry_at
        result["reasons"] = payload["reasons"]
        return result


    def _escalate(self, inc: dict, reason: str, llm_result: dict | None = None) -> None:
        from .fmt import fmt_escalate

        if not self._incident_context_current(inc):
            return
        inc_id = inc["id"]
        inc_d = dict(inc)
        llm_summary = (llm_result or {}).get("summary", "")
        body = fmt_escalate(inc_d, reason, llm_summary)
        detail = reason
        if llm_result:
            detail += f" | llm: {llm_result.get('summary', '')[:80]}"
        from .incidents import IncidentService

        IncidentService(self.db).set_need_human(inc_id, detail)
        event_id = self.db.event(
            "agent_escalated",
            f"escalate: {reason}",
            incident_id=inc_id,
            payload={"reason": reason, "llm": llm_result, "body": body,
                     "generation": int(inc_d.get("generation") or 1)},
        )
        self._notify_event(event_id, "agent_escalated", body)

