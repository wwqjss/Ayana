"""Agent 闭环：调查 → LLM 分析 → runbook 查表 → Policy → 执行/找人。

执行权 = 查表（runbook）；思考权 = LLM 分析（仅建议）。
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
        """完整闭环：调查 → 分析 → 查表 → 执行或找人。"""
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not inc:
            return {"ok": False, "error": "incident_not_found"}
        inc = dict(inc)
        if inc["status"] != "open":
            return {"ok": True, "skipped": "not_open"}

        result: dict[str, Any] = {"incident_id": inc_id, "steps": []}

        # 0. 运维知识（Markdown）：主题正文 / 共同命中
        knol = self.knowledge.investigation_context(
            inc["asset_id"], inc.get("object_id") or ""
        )
        result["steps"].append({
            "step": "knowledge",
            "ok": bool(knol.get("docs")),
            "docs": [d.get("id") for d in (knol.get("docs") or [])],
            "shared": [d.get("id") for d in (knol.get("shared_docs") or [])],
        })
        knowledge_text = knol.get("context_text") or ""

        # 1. 固定只读调查（auto_rule 需要读权限）
        try:
            inv = await self.investigation.run(
                asset_id=inc["asset_id"],
                object_id=inc.get("object_id") or "",
                capability="asset.summary",
                incident_id=inc_id,
                actor_type="auto_rule",
                actor_id="agent",
            )
            evidence = inv.get("evidence") or []
            result["steps"].append({"step": "investigate", "ok": inv.get("ok", False), "count": len(evidence), "err": inv.get("error", "")})
            evidence_text = "\n".join(
                e.get("output", "")[:300] for e in evidence if e.get("output")
            )[:2000]
            # investigation 也可能带上知识（对象级）
            inv_knol = inv.get("knowledge") or {}
            if inv_knol.get("context_text"):
                knowledge_text = inv_knol["context_text"]
        except Exception as e:
            result["steps"].append({"step": "investigate", "ok": False, "error": str(e)})
            evidence_text = ""

        # 2. LLM 分析（可选，仅建议；注入知识语义）
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
        # 从 episode 拿 alertname
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
            # 无匹配 → 找人
            self._escalate(inc_id, "no_runbook_match", llm_result)
            result["action"] = "escalated"
            return result

        # 4. 检查预算/冷却
        budget_ok, budget_reason = self._check_budget(rule, inc["asset_id"], inc.get("object_id") or "")
        result["steps"].append({"step": "budget_check", "ok": budget_ok, "reason": budget_reason})
        if not budget_ok:
            self._escalate(inc_id, f"budget_exhausted:{budget_reason}", llm_result)
            result["action"] = "escalated_budget"
            return result

        # 5. Policy 检查（auto_rule 主体）
        # 对象 ID 需要解析为登记格式
        obj_id = inc.get("object_id") or ""
        obj_row = self.db.query_one(
            "SELECT id FROM objects WHERE asset_id=? AND (id=? OR name=?)",
            (inc["asset_id"], obj_id, obj_id),
        )
        policy_obj = (obj_row["id"] if obj_row else obj_id) or "*"
        decision = self.policy.check(
            subject_type="auto_rule",
            subject_id="agent",
            capability=rule.capability,
            asset_id=inc["asset_id"],
            object_id=policy_obj,
            auto=True,
        )
        result["steps"].append({
            "step": "policy_check",
            "ok": decision["allowed"],
            "reason": decision.get("reason", ""),
        })
        if not decision["allowed"]:
            self._escalate(inc_id, f"policy_denied:{decision['reason']}", llm_result)
            result["action"] = "escalated_policy"
            return result

        # 6. 全局开关
        if not self.auto_enabled:
            self._escalate(inc_id, "auto_remediation_disabled", llm_result)
            result["action"] = "escalated_disabled"
            return result

        # 7. 执行（走 Action 状态机）
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
            )
            action_id = prop["id"]
            self.actions.approve(
                action_id,
                approver_type="auto_rule",
                approver_id="agent",
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

            # 更新预算计数
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
                self._escalate(inc_id, f"exec_{exec_result.get('state')}", llm_result)
        except Exception as e:
            result["steps"].append({"step": "execute", "ok": False, "error": str(e)})
            self._escalate(inc_id, f"exec_error:{e}", llm_result)
            result["action"] = "escalated_error"

        return result

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
