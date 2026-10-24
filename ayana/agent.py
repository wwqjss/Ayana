"""Agent 闭环：调查 → LLM 分析 → runbook 查表 → Policy 三态 → 执行/等人。

执行权 = 查表（runbook）；思考权 = LLM 分析（仅建议）。
P1-01：自动调查与自动写操作解耦——auto remediation 关闭时仍可只读调查并形成 proposal。
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from .actions import AUTO_RETRYABLE_BLOCKS, ActionError, ActionService, action_incident_block
from .db import Database, now
from .investigation import InvestigationService
from .knowledge import KnowledgeBase
from .llm import LLMClient
from .notify import Notifier
from .policy import Policy
from .runbook import RunbookRule, auto_budget_state, match_runbook

log = logging.getLogger("ayana.agent")


class AgentLoop:
    def __init__(
        self,
        db: Database,
        investigation: InvestigationService,
        actions: ActionService,
        policy: Policy,
        llm: LLMClient,
        notifier: Notifier,
        *,
        auto_enabled: bool = False,
        knowledge: KnowledgeBase | None = None,
    ):
        self.db = db
        self.investigation = investigation
        self.actions = actions
        self.policy = policy
        self.llm = llm
        self.notifier = notifier
        self.auto_enabled = auto_enabled
        self.autonomy_enabled = lambda: False
        self.knowledge = knowledge or KnowledgeBase(db)
        # P4.0：默认锁定旧自治自动执行；仅 legacy_agent_loop 显式开启才解锁
        self.legacy_locked = True

    def set_auto_enabled(self, enabled: bool) -> None:
        # P4.0：legacy 锁定时拒绝打开旧自动执行（关闭请求始终允许）
        if enabled and getattr(self, "legacy_locked", True):
            self.auto_enabled = False
            try:
                self.db.execute(
                    "INSERT INTO meta(key, value) VALUES('agent_auto_enabled', ?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ("0",),
                )
                self.db.audit(
                    "system", "agent", "auto_remediation_blocked_legacy_locked",
                    detail={"requested": True},
                )
            except Exception:
                pass
            return
        self.auto_enabled = enabled
        # S22: 持久化到 meta，重启后不回退到配置默认值
        try:
            self.db.execute(
                "INSERT INTO meta(key, value) VALUES('agent_auto_enabled', ?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                ("1" if enabled else "0",),
            )
        except Exception:
            pass
        self.db.audit("system", "agent", f"auto_remediation_{'on' if enabled else 'off'}")

    async def handle_incident(self, inc_id: str) -> dict[str, Any]:
        """完整闭环：调查 → 分析 → 查表 → 三态分支（执行 / 提案等人 / 找人）。"""
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not inc:
            return {"ok": False, "error": "incident_not_found"}
        inc = dict(inc)
        if inc["status"] != "open":
            return {"ok": True, "skipped": "not_open"}
        from .incidents import IncidentService

        result: dict[str, Any] = {"incident_id": inc_id, "steps": []}
        blocked = IncidentService(self.db).source_block_reason(inc_id)
        if blocked:
            if blocked.startswith("unhealthy_source:"):
                return self._wait_for_preconditions(
                    inc, None, result, {"blockers": ["source_health"], "reasons": [blocked]},
                )
            self._escalate(inc, blocked, None)
            return {"ok": True, "incident_id": inc_id, "action": "escalated_source", "reason": blocked}

        # 本 generation 周期内已有有效 Action：交给人 / 验证 / reconcile，不重复调查提案。
        # 过期/取消/失败的历史 action 不算，否则一代过期就永远不再自动处置。
        rejected = self._current_rejection(inc_id)
        if rejected:
            result["action"] = "skipped_rejected"
            result["action_id"] = rejected["id"]
            return result
        current_actions = self._current_actions(inc_id)
        prior = current_actions[0] if current_actions else None
        if prior:
            result["steps"].append({
                "step": "skip_prior_action",
                "ok": True,
                "action_id": prior["id"],
                "state": prior["state"],
            })
            result["action"] = f"skipped_prior_{prior['state']}"
            result["action_id"] = prior["id"]
            return result

        waiting = self._waiting_state(inc)
        if waiting and float(waiting.get("retry_at") or 0) > now():
            result["action"] = "waiting_precondition"
            result["retry_at"] = waiting["retry_at"]
            result["reasons"] = waiting.get("reasons") or []
            return result

        # 0. 运维知识（Markdown）：主题正文 / 共同命中（含 extra_failures）
        extra_failures = self._related_failures(inc["asset_id"], inc.get("object_id") or "")
        knol = self.knowledge.investigation_context(
            inc["asset_id"], inc.get("object_id") or "", extra_failures=extra_failures
        )
        result["steps"].append({
            "step": "knowledge",
            "ok": bool(knol.get("docs")),
            "docs": [d.get("id") for d in (knol.get("docs") or [])],
            "shared": [d.get("id") for d in (knol.get("shared_docs") or [])],
            "revision": knol.get("revision", ""),
            "extra_failures": extra_failures,
        })
        knowledge_text = knol.get("context_text") or ""

        # 1. 证据驱动有限循环只读调查（与自动写解耦）
        evidence = []
        try:
            inv = await self.investigation.run_loop(
                asset_id=inc["asset_id"],
                object_id=inc.get("object_id") or "",
                incident_id=inc_id,
                actor_type="auto_rule",
                actor_id="agent",
                extra_failures=extra_failures,
            )
            if not self._incident_context_current(inc, result):
                return result
            evidence = inv.get("evidence") or []
            result["steps"].append({
                "step": "investigate",
                "ok": bool(inv.get("id")) and inv.get("stop_reason") != "all_tools_rejected",
                "count": len(evidence),
                "stop_reason": inv.get("stop_reason", ""),
                "rounds": inv.get("rounds", 0),
                "tool_calls": inv.get("tool_calls", 0),
                "confidence": inv.get("confidence", ""),
                "err": inv.get("error", ""),
            })
            evidence_text = self._evidence_text(evidence)
            inv_knol = inv.get("knowledge") or {}
            if inv_knol.get("context_text"):
                knowledge_text = inv_knol["context_text"]
            result["investigation_id"] = inv.get("id", "")
            result["investigation_stop_reason"] = inv.get("stop_reason", "")
            result["facts"] = inv.get("facts") or []
            result["hypotheses"] = inv.get("hypotheses") or []
            # 全工具失败 / transport 不可用：不得进入自动写
            if inv.get("stop_reason") in ("transport_unavailable", "tool_budget_exhausted"):
                if not any(
                    (e.get("classification") == "observed") for e in evidence
                ):
                    return self._wait_for_preconditions(
                        inc, None, result,
                        {"reasons": [f"investigation_{inv.get('stop_reason')}"],
                         "blockers": ["exec_channel"]},
                    )
        except Exception as e:
            if not self._incident_context_current(inc, result):
                return result
            result["steps"].append({"step": "investigate", "ok": False, "error": str(e)})
            evidence_text = ""

        # 2. LLM 分析（可选，仅建议）
        llm_result = None
        if self.llm.enabled:
            try:
                llm_result = await self.llm.analyze_incident(
                    title=inc.get("title", ""),
                    evidence_text=evidence_text,
                    alertname=inc.get("title", "").split(":")[-1].strip() if ":" in inc.get("title", "") else "",
                    knowledge_text=knowledge_text,
                )
                result["steps"].append({
                    "step": "llm_analyze",
                    "ok": llm_result is not None,
                    "category": (llm_result or {}).get("category"),
                    "confidence": (llm_result or {}).get("confidence"),
                })
            except Exception as e:
                result["steps"].append({"step": "llm_analyze", "ok": False, "error": str(e)})
            if not self._incident_context_current(inc, result):
                return result

        # 3. runbook 查表（零自由度）
        alertname = ""
        if ":" in (inc.get("title") or ""):
            alertname = inc["title"].split(":")[-1].strip()
        ep = self.db.query_one(
            "SELECT alertname FROM alert_episodes WHERE incident_id=? ORDER BY first_seen DESC LIMIT 1",
            (inc_id,),
        )
        if ep:
            alertname = ep["alertname"]

        category = (llm_result or {}).get("category", "")
        rule = match_runbook(
            asset_id=inc["asset_id"],
            object_name=inc.get("object_id") or "",
            alertname=alertname,
            category=category,
        )
        result["steps"].append({
            "step": "runbook_match",
            "ok": rule is not None,
            "rule": rule.id if rule else None,
        })

        if not rule:
            # A missing fast-path Runbook is not a human decision when the
            # autonomous investigator is enabled. Its own durable notices
            # handle model failures and manual adjudication.
            if self.autonomy_enabled():
                result["action"] = "delegated_autonomy"
                return result
            self._escalate(inc, "no_runbook_match", llm_result)
            result["action"] = "escalated"
            return result

        # 3b. 确定性前置判据（P0-03）
        pre = await self._precondition_context(inc, rule, evidence)
        if not self._incident_context_current(inc, result):
            return result
        pre_result = rule.check_preconditions(pre)
        result["steps"].append({
            "step": "preconditions",
            "ok": pre_result.get("status") == "satisfied",
            "status": pre_result.get("status"),
            "reasons": pre_result.get("reasons", []),
        })

        # 4. Policy 三态（服务端权威）
        obj_id = inc.get("object_id") or ""
        obj_row = self.db.query_one(
            "SELECT id FROM objects WHERE asset_id=? AND (id=? OR name=?)",
            (inc["asset_id"], obj_id, obj_id),
        )
        policy_obj = (obj_row["id"] if obj_row else obj_id) or "*"
        decision = self.policy.effective_decision(
            subject_type="auto_rule",
            subject_id="agent",
            capability=rule.capability,
            asset_id=inc["asset_id"],
            object_id=policy_obj,
            auto=False,
        )
        result["steps"].append({
            "step": "policy_decision",
            "decision": decision.get("decision"),
            "reason": decision.get("reason", ""),
            "matched": bool(decision.get("matched_rule")),
        })
        result["decision"] = decision.get("decision")

        if decision.get("decision") == "forbidden" or not decision.get("allowed"):
            self._escalate(inc, f"policy_denied:{decision.get('reason', '')}", llm_result)
            result["action"] = "escalated_policy"
            return result

        # 前置失败不是权限审批：临时阻塞等待重检，缺少执行契约则找人处理。
        # approval_required 的 policy blocker 只表示缺自动权，其他前置仍须满足。
        blockers = pre_result.get("blockers") or [
            r.split(":", 1)[0] for r in pre_result.get("reasons") or []
        ]
        runtime_blockers = [b for b in blockers if b != "policy"]
        if runtime_blockers:
            hard_stop = any(b in (
                "control_plane_object", "verification_contract", "asset_match", "object_match",
                "write_result_unknown",
            ) for b in runtime_blockers)
            if hard_stop:
                self._escalate(
                    inc,
                    f"precondition_{pre_result.get('status')}:{';'.join(pre_result.get('reasons') or [])}",
                    llm_result,
                )
                result["action"] = "escalated_precondition"
                return result
            return self._wait_for_preconditions(inc, rule, result, pre_result)

        # 唯有真实自动执行权不足或自动开关关闭才请求单次人工批准。
        if decision.get("decision") == "automatic" and self.auto_enabled:
            if pre_result.get("status") != "satisfied":
                return self._wait_for_preconditions(inc, rule, result, pre_result)
            return await self._auto_dispatch(inc, rule, result, decision, pre_result)

        return self._propose_for_human(
            inc, rule, result, decision, pre_result, llm_result, evidence_text
        )

    def _related_failures(self, asset_id: str, object_id: str) -> list[str]:
        """同一资产上其他仍在 firing 的对象 → shared dependency 线索。"""
        try:
            name = (object_id or "").split(":")[-1]
            rows = self.db.query(
                "SELECT DISTINCT object_id FROM alert_episodes"
                " WHERE asset_id=? AND status='firing' AND object_id != ?"
                " AND object_id != '' LIMIT 8",
                (asset_id, name or object_id or ""),
            )
            out = []
            for r in rows:
                oid = r["object_id"] or ""
                if oid and oid not in out:
                    out.append(oid)
            return out
        except Exception:
            return []

    def _evidence_text(self, evidence: list) -> str:
        parts = []
        for e in evidence or []:
            if e.get("classification") == "rejected":
                continue
            obs = e.get("observed") or {}
            line = (
                f"[{e.get('classification')}] {e.get('tool')} {e.get('object_id')}: "
                f"{obs.get('service_state') or obs.get('kind') or ''}"
            )
            raw = (obs.get("raw_output") or e.get("output") or "")[:200]
            if raw:
                line += f" | {raw}"
            parts.append(line)
        return "\n".join(parts)[:2500]

    def _propose_for_human(
        self,
        inc: dict,
        rule: RunbookRule,
        result: dict,
        decision: dict,
        pre_result: dict,
        llm_result: dict | None,
        evidence_text: str,
    ) -> dict[str, Any]:
        """创建 proposed Action，等待人工批准。零自动派发。"""
        if not self._incident_context_current(inc, result):
            return result
        inc_id = inc["id"]
        # 避免重复提案：同一 incident 已有 proposed 则复用
        existing = next((a for a in self._current_actions(inc_id)
                         if a["state"] == "proposed" and a["runbook_id"] == rule.id), None)
        if existing:
            result["steps"].append({
                "step": "propose",
                "ok": True,
                "action_id": existing["id"],
                "idempotent": True,
            })
            result["action"] = "awaiting_approval"
            result["action_id"] = existing["id"]
            self._notify_awaiting_approval(inc_id, existing["id"], rule, decision, pre_result)
            return result

        try:
            obj = self.db.query_one(
                "SELECT id FROM objects WHERE asset_id=? AND (id=? OR name=?)",
                (inc["asset_id"], inc.get("object_id") or "", inc.get("object_id") or ""),
            )
            obj_id = (obj["id"] if obj else inc.get("object_id") or "")
            prop = self.actions.propose(
                asset_id=inc["asset_id"],
                object_id=obj_id or inc.get("object_id") or "",
                capability=rule.capability,
                params={},
                reason=rule.reason,
                incident_id=inc_id,
                proposer_type="auto_rule",
                proposer_id="agent",
                mode="manual",
                runbook_id=rule.id,
                runbook_rev=rule.rev,
            )
            action_id = prop["id"]
            self.db.execute(
                "UPDATE incidents SET stage='awaiting_approval', updated_at=? WHERE id=?",
                (now(), inc_id),
            )
            result["steps"].append({"step": "propose", "ok": True, "action_id": action_id})
            result["action"] = "awaiting_approval"
            result["action_id"] = action_id
            self._notify_awaiting_approval(
                inc_id, action_id, rule, decision, pre_result, evidence_text=evidence_text,
            )
        except ActionError as e:
            if e.code == "object_locked":
                return self._wait_for_preconditions(
                    inc, rule, result, {"blockers": ["object_lock"], "reasons": [str(e)]},
                )
            result["steps"].append({"step": "propose", "ok": False, "error": str(e)})
            self._escalate(inc, f"propose_error:{e}", llm_result)
            result["action"] = "escalated_error"
        except Exception as e:
            result["steps"].append({"step": "propose", "ok": False, "error": str(e)})
            self._escalate(inc, f"propose_error:{e}", llm_result)
            result["action"] = "escalated_error"
        return result

    async def _auto_dispatch(
        self,
        inc: dict,
        rule: RunbookRule,
        result: dict,
        decision: dict,
        pre_result: dict,
    ) -> dict[str, Any]:
        """automatic + auto_enabled + 前置满足：唯一派发门内自动执行。"""
        if not self._incident_context_current(inc, result):
            return result
        inc_id = inc["id"]
        action_id = ""
        try:
            obj = self.db.query_one(
                "SELECT id FROM objects WHERE asset_id=? AND (id=? OR name=?)",
                (inc["asset_id"], inc.get("object_id") or "", inc.get("object_id") or ""),
            )
            obj_id = (obj["id"] if obj else inc.get("object_id") or "")
            # 硬约束：对象上存在结果不明的写操作 → 绝不自动重放
            stuck = self.db.query_one(
                "SELECT id FROM actions WHERE asset_id=? AND object_id=?"
                " AND state IN ('unknown','dispatched') LIMIT 1",
                (inc["asset_id"], obj_id or inc.get("object_id") or ""),
            )
            if stuck:
                self._escalate(
                    inc, f"no_replay_unknown:{stuck['id']}", None
                )
                result["steps"].append(
                    {
                        "step": "auto_dispatch",
                        "ok": False,
                        "error": "no_replay_unknown",
                        "blocking_action_id": stuck["id"],
                    }
                )
                result["action"] = "escalated_no_replay"
                return result
            prop = self.actions.propose(
                asset_id=inc["asset_id"],
                object_id=obj_id or inc.get("object_id") or "",
                capability=rule.capability,
                params={},
                reason=rule.reason,
                incident_id=inc_id,
                proposer_type="auto_rule",
                proposer_id="agent",
                mode="auto",
                runbook_id=rule.id,
                runbook_rev=rule.rev,
            )
            action_id = prop["id"]
            self.actions.approve(
                action_id,
                approver_type="auto_rule",
                approver_id="agent",
                channel="system",
                reason="automatic_policy",
            )
            exec_result = await self.actions.execute(
                action_id,
                actor_type="auto_rule",
                actor_id="agent",
            )
            result["steps"].append({
                "step": "execute",
                "ok": exec_result.get("state") == "success",
                "state": exec_result.get("state"),
                "action_id": action_id,
            })
            result["action"] = exec_result.get("state", "unknown")
            result["action_id"] = action_id

            self._record_usage(rule.id, inc["asset_id"], inc.get("object_id") or "")

            if exec_result.get("state") == "success":
                from .fmt import fmt_agent_exec

                inc_d = dict(self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,)) or {})
                body = fmt_agent_exec(inc_d, rule.name, rule.capability)
                event_id = self.db.event(
                    "agent_auto_exec",
                    f"runbook {rule.id} executed",
                    incident_id=inc_id,
                    payload={"action_id": action_id, "rule": rule.id,
                             "generation": int(inc.get("generation") or 1), "body": body},
                )
                self._notify_event(event_id, "agent_auto_exec", body)
            else:
                self._escalate(inc, f"exec_{exec_result.get('state')}", None)
        except ActionError as e:
            if not self._incident_context_current(inc, result):
                return result
            transient = {"cooldown": "budget", "budget_exhausted": "budget",
                         "global_pause": "global_pause", "object_locked": "object_lock",
                         "source_unavailable": "source_health"}
            if e.code in AUTO_RETRYABLE_BLOCKS:
                if action_id:
                    if not self.actions.safe_cancel_pending_auto(action_id, reason=e.code):
                        self._escalate(inc, f"no_replay_unknown:{action_id}", None)
                        result["action"] = "escalated_no_replay"
                        return result
                    from .incidents import IncidentService

                    service = IncidentService(self.db)
                    for kind in ("source_unavailable", "source_unhealthy"):
                        service.clear_action_obligation(inc_id, action_id, kind=kind)
                budget = auto_budget_state(self.db, rule, inc["asset_id"], inc.get("object_id") or "", at=now())
                return self._wait_for_preconditions(inc, rule, result, {
                    "blockers": [transient[e.code]], "reasons": [f"{e.code}:{e}"],
                    "budget_reason": budget["reason"], "retry_at": budget["retry_at"],
                })
            result["steps"].append({"step": "execute", "ok": False, "error": str(e)})
            self._escalate(inc, f"exec_error:{e}", None)
            result["action"] = "escalated_error"
        except Exception as e:
            if not self._incident_context_current(inc, result):
                return result
            result["steps"].append({"step": "execute", "ok": False, "error": str(e)})
            self._escalate(inc, f"exec_error:{e}", None)
            result["action"] = "escalated_error"
        return result

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
            log.exception("agent notification deferred to compensation: %s", event_id)

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

    def ready_incident_ids(self, limit: int = 3) -> list[str]:
        """跳过尚在等待的事件，避免冷却中的旧事件占满本轮处理名额。"""
        ready: list[str] = []
        rows = self.db.query(
            "SELECT * FROM incidents WHERE status='open' AND need_human=0"
            " AND stage IN ('pending','investigating','watching')"
            " ORDER BY updated_at ASC, created_at ASC"
        )
        t = now()
        for row in rows:
            if self._current_actions(row["id"]) or self._current_rejection(row["id"]):
                continue
            waiting = self._waiting_state(dict(row))
            if waiting and float(waiting.get("retry_at") or 0) > t:
                continue
            ready.append(row["id"])
            if len(ready) >= limit:
                break
        return ready

    def _wait_for_preconditions(
        self, inc: dict, rule: RunbookRule | None, result: dict, pre_result: dict,
    ) -> dict[str, Any]:
        """确定性等待；不建 Action、不请求授权，也不把事件永久踢出 Agent。"""
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

    async def _precondition_context(
        self, inc: dict, rule: Any, evidence: list
    ) -> dict[str, Any]:
        """组装前置判据上下文（确定性，不依赖 LLM）。"""
        asset_id = inc.get("asset_id") or ""
        object_id = inc.get("object_id") or ""
        obj = self.db.query_one(
            "SELECT * FROM objects WHERE asset_id=? AND (id=? OR name=?)",
            (asset_id, object_id, object_id),
        )
        object_name = (obj["name"] if obj else object_id) or ""
        object_ref = (obj["id"] if obj else object_id) or ""

        # 新鲜失败探测：最近 probe 全失败且样本新鲜
        probe_failed_recent = None
        probe_samples_ok = None
        try:
            samples = await self.investigation.prom.probe_success_since(
                asset_id, object_name or object_id, start=now() - 180
            )
            if samples:
                # 最近样本已经恢复时，窗口里较早的失败不能触发重启。
                latest = max(samples, key=lambda sample: float(sample.get("sample_at") or 0))
                value = latest.get("value")
                fresh = now() - 180 <= float(latest.get("sample_at") or 0) <= now() + 5
                probe_samples_ok = fresh and value == 1
                probe_failed_recent = (value == 0) if fresh and value in (0, 1) else None
            else:
                probe_failed_recent = None
        except Exception:
            probe_failed_recent = None

        service_state = None
        for item in reversed(evidence or []):
            if item.get("classification") != "observed":
                continue
            if item.get("object_id") not in (object_id, object_ref, object_name):
                continue
            observed = item.get("observed") or {}
            if observed.get("service_state"):
                service_state = observed["service_state"]
                break

        # 调查证据是否全部运输失败（只看真实 transport 结果，不含 rejected gap）
        transport_evs = [
            e for e in (evidence or [])
            if e.get("source") in ("ssh_probe", "nt_probe", "prometheus")
            or e.get("classification") in ("observed", "transport_failure", "tool_failure")
        ]
        transport_ok = any(e.get("ok") for e in transport_evs) if transport_evs else None

        stop = self.db.query_one("SELECT enabled FROM global_stops WHERE key='auto_dispatch'")
        policy = self.policy.check(
            subject_type="auto_rule",
            subject_id="agent",
            capability=rule.capability,
            asset_id=asset_id,
            object_id=object_ref or "*",
            auto=True,
        )
        budget_ok, budget_reason, budget_retry_at = self._budget_state(rule, asset_id, object_id)
        from .incidents import IncidentService as _ISvc
        object_locked = _ISvc(self.db).object_actions_locked(asset_id, object_ref)
        unknown_write = self.db.query_one(
            "SELECT id FROM actions WHERE asset_id=? AND object_id=? AND state='unknown' LIMIT 1",
            (asset_id, object_ref),
        )

        from .verify_profiles import profile_for_action
        from .capabilities import resolve_object_name

        profile = profile_for_action(
            capability=rule.capability, asset_id=asset_id,
            object_id=resolve_object_name(dict(obj)) if obj else "",
        )

        return {
            "asset_id": asset_id,
            "object_name": object_name,
            "object_ref": object_ref,
            "probe_failed_recent": probe_failed_recent,
            "probe_samples_ok": probe_samples_ok,
            "service_state": service_state,
            "exec_channel_ok": transport_ok if transport_ok is not None else True,
            "verification_ready": profile is not None,
            "global_pause": bool(stop and stop["enabled"]),
            "policy_allowed": policy.get("allowed") and bool(policy.get("auto_allowed")),
            "budget_ok": budget_ok,
            "budget_reason": budget_reason,
            "budget_retry_at": budget_retry_at,
            "object_locked": object_locked,
            "write_result_unknown": bool(unknown_write),
            "control_plane": "ayana" in (object_name + object_ref).lower(),
        }

    def _check_budget(self, rule: RunbookRule, asset_id: str, object_id: str) -> tuple[bool, str]:
        ok, reason, _ = self._budget_state(rule, asset_id, object_id)
        return ok, reason

    def _budget_state(
        self, rule: RunbookRule, asset_id: str, object_id: str,
    ) -> tuple[bool, str, float | None]:
        budget = auto_budget_state(self.db, rule, asset_id, object_id, at=now())
        return budget["ok"], budget["reason"], budget["retry_at"]

    def _record_usage(self, rule_id: str, asset_id: str, object_id: str) -> None:
        self.db.audit(
            "auto_rule",
            f"agent:{rule_id}",
            "agent_auto_exec",
            asset_id=asset_id,
            object_id=(object_id or "").split(":")[-1],
            detail={"rule": rule_id},
        )

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
