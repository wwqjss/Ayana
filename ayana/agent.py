"""Agent 闭环：调查 → LLM 分析 → runbook 查表 → Policy 三态 → 执行/等人。

执行权 = 查表（runbook）；思考权 = LLM 分析（仅建议）。
P1-01：自动调查与自动写操作解耦——auto remediation 关闭时仍可只读调查并形成 proposal。
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from .actions import ActionService
from .db import Database, now
from .investigation import InvestigationService
from .knowledge import KnowledgeBase
from .llm import LLMClient
from .notify import Notifier
from .policy import Policy
from .runbook import RunbookRule, match_runbook

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
        self.knowledge = knowledge or KnowledgeBase(db)

    def set_auto_enabled(self, enabled: bool) -> None:
        self.auto_enabled = enabled
        self.db.audit("system", "agent", f"auto_remediation_{'on' if enabled else 'off'}")

    async def handle_incident(self, inc_id: str) -> dict[str, Any]:
        """完整闭环：调查 → 分析 → 查表 → 三态分支（执行 / 提案等人 / 找人）。"""
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not inc:
            return {"ok": False, "error": "incident_not_found"}
        inc = dict(inc)
        if inc["status"] != "open":
            return {"ok": True, "skipped": "not_open"}

        result: dict[str, Any] = {"incident_id": inc_id, "steps": []}

        # 本 generation 周期内已有 Action：交给人 / 验证 / reconcile，不重复调查提案
        gen_ev = self.db.query_one(
            "SELECT at FROM events WHERE incident_id=? AND type IN"
            " ('generation_bumped','incident_reopened','incident_opened')"
            " ORDER BY id DESC LIMIT 1",
            (inc_id,),
        )
        cutoff = float(gen_ev["at"]) if gen_ev else 0.0
        prior = self.db.query_one(
            "SELECT id, state FROM actions WHERE incident_id=? AND created_at>=?"
            " ORDER BY created_at DESC LIMIT 1",
            (inc_id, cutoff),
        )
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
        try:
            inv = await self.investigation.run_loop(
                asset_id=inc["asset_id"],
                object_id=inc.get("object_id") or "",
                incident_id=inc_id,
                actor_type="auto_rule",
                actor_id="agent",
                extra_failures=extra_failures,
            )
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
                    self._escalate(inc_id, f"investigation_{inv.get('stop_reason')}", None)
                    result["action"] = "escalated_investigation"
                    return result
        except Exception as e:
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
            self._escalate(inc_id, "no_runbook_match", llm_result)
            result["action"] = "escalated"
            return result

        # 3b. 确定性前置判据（P0-03）
        pre = await self._precondition_context(inc, rule, evidence)
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
            self._escalate(inc_id, f"policy_denied:{decision.get('reason', '')}", llm_result)
            result["action"] = "escalated_policy"
            return result

        # 5. 分支：automatic 且允许自动派发 → 执行；否则形成 proposal 等人
        if decision.get("decision") == "automatic" and self.auto_enabled:
            reasons = pre_result.get("reasons") or []
            hard_stop = any(
                ("global_pause" in r) or ("control_plane" in r) for r in reasons
            )
            if pre_result.get("status") != "satisfied" and hard_stop:
                self._escalate(
                    inc_id,
                    f"precondition_{pre_result.get('status')}:{';'.join(reasons)}",
                    llm_result,
                )
                result["action"] = "escalated_precondition"
                return result
            if pre_result.get("status") != "satisfied":
                return self._propose_for_human(
                    inc, rule, result, decision, pre_result, llm_result, evidence_text
                )
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
        inc_id = inc["id"]
        # 避免重复提案：同一 incident 已有 proposed 则复用
        existing = self.db.query_one(
            "SELECT id, state FROM actions WHERE incident_id=? AND state='proposed'"
            " AND runbook_id=? ORDER BY created_at DESC LIMIT 1",
            (inc_id, rule.id),
        )
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
            self.db.event(
                "proposal_waiting",
                f"proposal {action_id} awaiting human approval",
                incident_id=inc_id,
                payload={
                    "action_id": action_id,
                    "rule": rule.id,
                    "decision": decision.get("decision"),
                    "preconditions": pre_result.get("status"),
                    "evidence_summary": (evidence_text or "")[:400],
                },
            )
            result["steps"].append({"step": "propose", "ok": True, "action_id": action_id})
            result["action"] = "awaiting_approval"
            result["action_id"] = action_id
            self._notify_awaiting_approval(inc_id, action_id, rule, decision, pre_result)
        except Exception as e:
            result["steps"].append({"step": "propose", "ok": False, "error": str(e)})
            self._escalate(inc_id, f"propose_error:{e}", llm_result)
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
        inc_id = inc["id"]
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
                    inc_id, f"no_replay_unknown:{stuck['id']}", None
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
                self.db.event(
                    "agent_auto_exec",
                    f"runbook {rule.id} executed",
                    incident_id=inc_id,
                    payload={"action_id": action_id, "rule": rule.id},
                )
                from .fmt import fmt_agent_exec

                inc_d = dict(self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,)) or {})
                self.notifier.enqueue(
                    dedup_key=f"agent:{inc_id}:{rule.id}:{int(now())}",
                    target="",
                    body=fmt_agent_exec(inc_d, rule.name, rule.capability),
                )
            else:
                self._escalate(inc_id, f"exec_{exec_result.get('state')}", None)
        except Exception as e:
            result["steps"].append({"step": "execute", "ok": False, "error": str(e)})
            self._escalate(inc_id, f"exec_error:{e}", None)
            result["action"] = "escalated_error"
        return result

    def _notify_awaiting_approval(
        self,
        inc_id: str,
        action_id: str,
        rule: RunbookRule,
        decision: dict,
        pre_result: dict,
    ) -> None:
        from .fmt import fmt_escalate

        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        inc_d = dict(inc) if inc else {"id": inc_id, "title": "", "asset_id": "", "object_id": ""}
        reason = (
            f"awaiting_approval:{action_id} "
            f"decision={decision.get('decision')} "
            f"rule={rule.id}"
        )
        self.db.execute(
            "UPDATE incidents SET need_human=1, need_human_reason=?, stage='awaiting_approval',"
            " updated_at=? WHERE id=?",
            (reason, now(), inc_id),
        )
        body = fmt_escalate(inc_d, reason, "")
        self.notifier.enqueue(
            dedup_key=f"agent:await:{inc_id}:{action_id}",
            target="",
            body=body,
        )

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
                probe_samples_ok = all(s.get("value") == 1 for s in samples)
                probe_failed_recent = any(s.get("value") == 0 for s in samples) or not probe_samples_ok
                # 要求「明确失败」：至少一条 value==0，或全非 1
                if not any(s.get("value") == 0 for s in samples):
                    if probe_samples_ok:
                        probe_failed_recent = False  # 已恢复
                    else:
                        probe_failed_recent = None
            else:
                probe_failed_recent = None
        except Exception:
            probe_failed_recent = None

        # 调查证据是否全部运输失败（只看真实 transport 结果，不含 rejected gap）
        transport_evs = [
            e for e in (evidence or [])
            if e.get("source") in ("nt_probe", "prometheus")
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
        budget_ok, _ = self._check_budget(rule, asset_id, object_id)
        locked = self.db.query_one(
            "SELECT COUNT(*) AS n FROM actions WHERE asset_id=? AND object_id=?"
            " AND (state IN ('unknown','dispatched')"
            "  OR (state='success' AND id IN (SELECT action_id FROM verifications"
            "      WHERE status='pending')))",
            (asset_id, object_id),
        )
        # 本事件自身刚 propose 的不算
        object_locked = bool(locked and locked["n"] > 0)

        return {
            "asset_id": asset_id,
            "object_name": object_name,
            "object_ref": object_ref,
            "probe_failed_recent": probe_failed_recent,
            "probe_samples_ok": probe_samples_ok,
            "service_state": None,
            "exec_channel_ok": transport_ok if transport_ok is not None else True,
            "verification_ready": True,
            "global_pause": bool(stop and stop["enabled"]),
            "policy_allowed": policy.get("allowed") and bool(policy.get("auto_allowed")),
            "budget_ok": budget_ok,
            "object_locked": object_locked,
            "control_plane": "ayana" in (object_name + object_ref).lower(),
        }

    def _check_budget(self, rule: RunbookRule, asset_id: str, object_id: str) -> tuple[bool, str]:
        # 同对象 24h 内最多 N 次
        since = now() - 86400
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM audit_log"
            " WHERE entry='agent_auto_exec' AND asset_id=? AND object_id=? AND at>?",
            (asset_id, object_id, since),
        )
        count = int(row["n"] if row else 0)
        if count >= rule.max_per_day:
            return False, f"max_per_day {count}/{rule.max_per_day}"
        # 冷却
        last = self.db.query_one(
            "SELECT at FROM audit_log WHERE entry='agent_auto_exec'"
            " AND asset_id=? AND object_id=? ORDER BY at DESC LIMIT 1",
            (asset_id, object_id),
        )
        if last and (now() - last["at"]) < rule.cooldown_sec:
            return False, f"cooldown {int(now() - last['at'])}s < {rule.cooldown_sec}s"
        return True, f"ok ({count}/{rule.max_per_day} today)"

    def _record_usage(self, rule_id: str, asset_id: str, object_id: str) -> None:
        self.db.audit(
            "auto_rule",
            f"agent:{rule_id}",
            "agent_auto_exec",
            asset_id=asset_id,
            object_id=object_id,
            detail={"rule": rule_id},
        )

    def _escalate(self, inc_id: str, reason: str, llm_result: dict | None = None) -> None:
        from .fmt import fmt_escalate

        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        inc_d = dict(inc) if inc else {"id": inc_id, "title": "", "asset_id": "", "object_id": ""}
        llm_summary = (llm_result or {}).get("summary", "")
        body = fmt_escalate(inc_d, reason, llm_summary)
        detail = reason
        if llm_result:
            detail += f" | llm: {llm_result.get('summary', '')[:80]}"
        self.db.execute(
            "UPDATE incidents SET need_human=1, need_human_reason=?, updated_at=? WHERE id=?",
            (detail, now(), inc_id),
        )
        self.db.event(
            "agent_escalated",
            f"escalate: {reason}",
            incident_id=inc_id,
            payload={"reason": reason, "llm": llm_result},
        )
        self.notifier.enqueue(
            dedup_key=f"agent:esc:{inc_id}:{int(now())}",
            target="",
            body=body,
        )
