"""Shared human decisions for notification replies and the incident console.

The caller authenticates the channel identity. Ordinary decisions still pass
through ActionService's policy checks; permanent consent additionally requires
an explicitly authenticated administrator and never changes an allow denial.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from .actions import ActionError, ActionService, action_incident_block
from .capabilities import get_capability
from .db import now
from .runbook import CONTROL_PLANE_MARKERS


_REPLIES = {
    "execute_once": ("执行一次", "执行这次", "仅执行一次", "只执行这次", "同意执行一次", "批准一次"),
    "reject": ("不执行", "不要执行", "取消执行", "拒绝执行", "跳过这次", "本次跳过"),
    "allow_always": ("永久允许执行", "永久允许", "始终允许执行", "以后自动执行", "允许以后自动执行"),
}


def parse_approval_reply(text: str) -> str | None:
    """Recognize a complete reply, never a quoted or negated substring."""
    normalized = unicodedata.normalize("NFKC", str(text or "")).strip()
    normalized = re.sub(r"[。.!！]+$", "", normalized).strip()
    for decision, replies in _REPLIES.items():
        if normalized == decision or normalized in replies:
            return decision
    return None


class ApprovalService:
    def __init__(self, actions: ActionService):
        self.actions = actions
        self.db = actions.db
        self.policy = actions.policy

    def select_action(self, *, action_id: str = "", incident_id: str = "") -> dict[str, Any]:
        """Select exactly one live proposal in the current incident generation.

        The absence of a reply binding is not permission to pick the latest
        proposal. Ambiguity requires an explicit action or incident selection.
        """
        if action_id:
            rows = self.db.query("SELECT * FROM actions WHERE id=?", (action_id,))
        elif incident_id:
            rows = self.db.query(
                "SELECT * FROM actions WHERE state='proposed' AND incident_id=?", (incident_id,),
            )
        else:
            rows = self.db.query("SELECT * FROM actions WHERE state='proposed'")
        candidates: list[dict[str, Any]] = []
        t = now()
        for raw in rows:
            row = dict(raw)
            if incident_id and row.get("incident_id") != incident_id:
                continue
            if row["state"] != "proposed":
                continue
            deadline = float(row.get("approval_deadline") or 0)
            if (deadline and t > deadline) or t - float(row["created_at"]) > self.actions.action_ttl:
                continue
            if action_incident_block(self.db, row):
                continue
            candidates.append(row)
        if not candidates:
            raise ActionError("approval_not_found", "没有可审批的当前操作，可能已处理、过期或目标已恢复")
        if len(candidates) != 1:
            raise ActionError("approval_ambiguous", "有多个操作等待审批，请在对应事件详情中选择操作")
        return candidates[0]

    async def decide(
        self,
        decision: str,
        *,
        actor_type: str,
        actor_id: str,
        channel: str = "web",
        action_id: str = "",
        incident_id: str = "",
        is_admin: bool = False,
        reason: str = "",
    ) -> dict[str, Any]:
        choice = parse_approval_reply(decision)
        if choice is None:
            raise ActionError("bad_approval_decision", "请选择执行一次、不执行或永久允许执行")
        if actor_type not in ("web_user", "qq_user", "wecom_user") or not str(actor_id).strip():
            raise ActionError("human_required", "此决定需要已认证的人类身份")
        row: dict[str, Any] | None = None
        granted = False
        try:
            # No network awaits inside this transaction. Selection, permission
            # grant and approval refer to the same current proposal.
            with self.db.tx():
                row = self.select_action(action_id=action_id, incident_id=incident_id)
                aid = row["id"]
                if choice == "reject":
                    result = self.actions.reject(
                        aid, actor_type=actor_type, actor_id=actor_id, channel=channel,
                        reason=reason or "human_rejected",
                    )
                    return {**result, "decision": choice, "permanent_granted": False}
                if choice == "allow_always":
                    self._check_permanent(row, is_admin=is_admin)
                approved = self.actions.approve(
                    aid, approver_type=actor_type, approver_id=actor_id,
                    channel=channel, reason=reason or choice,
                )
                if approved.get("already"):
                    return {**approved, "decision": choice, "permanent_granted": False}
                if choice == "allow_always":
                    self._grant_permanent(row, actor_type=actor_type, actor_id=actor_id, channel=channel)
                    granted = True
        except ActionError as exc:
            if row:
                self.db.audit(
                    actor_type, actor_id, "approval_decision_denied", action_id=row["id"],
                    asset_id=row["asset_id"], object_id=row["object_id"],
                    incident_id=row.get("incident_id") or "", channel=channel,
                    detail={"decision": choice, "reason": exc.code},
                )
            raise

        # Retain the human as approver and dispatcher. The existing execution
        # gate rechecks identity, policy, binding, deadlines and object locking.
        try:
            executed = await self.actions.execute(
                aid, actor_type=actor_type, actor_id=actor_id, is_admin=is_admin,
            )
            return {
                "id": aid, "state": executed.get("state"), "approved": True,
                "executed": True, "detail": executed.get("detail", ""), "channel": channel,
                "decision": choice, "permanent_granted": granted,
            }
        except ActionError as exc:
            state = self.actions._get(aid).get("state", "approved")
            return {
                "id": aid, "state": state, "execution_pending": state == "approved",
                "approved": True, "executed": False, "error": exc.code,
                "message": str(exc), "channel": channel, "decision": choice,
                "permanent_granted": granted,
            }

    def _check_permanent(self, row: dict[str, Any], *, is_admin: bool) -> None:
        if not is_admin:
            raise ActionError("admin_required", "永久允许执行需要管理员身份")
        if row.get("proposer_type") != "auto_rule" or row.get("proposer_id") != "agent":
            raise ActionError("permanent_agent_only", "永久允许仅适用于 Agent 提出的处置操作")
        obj = self.actions._object(row["asset_id"], row["object_id"])
        if not obj:
            raise ActionError("object_not_registered")
        names = " ".join(str(obj.get(k) or "") for k in ("id", "name", "unit", "container"))
        if any(marker in names.lower() for marker in CONTROL_PLANE_MARKERS):
            raise ActionError("control_plane_forbidden", "控制面对象不能设置自动执行")
        cap = get_capability(row["capability"])
        if cap.kind != "write" or not cap.auto_allowed:
            raise ActionError("auto_not_allowed", "此能力不允许自动执行")
        ceiling = self.policy.agent_ceiling.effective(row["capability"])
        if not ceiling["allowed"] or not ceiling["allow_auto"]:
            raise ActionError("denied_by_agent_ceiling", "Agent 权限上限不允许自动执行")
        current = self.policy.effective_decision(
            subject_type="auto_rule", subject_id="agent", capability=row["capability"],
            asset_id=row["asset_id"], object_id=obj["id"],
        )
        if not current["allowed"] or not (current.get("matched_rule") or {}).get("allow"):
            raise ActionError("permanent_allow_denied", "现有禁止项不能通过永久允许覆盖")

    def _grant_permanent(
        self, row: dict[str, Any], *, actor_type: str, actor_id: str, channel: str,
    ) -> None:
        # The targeted row may inherit allow from a broader positive rule.
        # Never modify the broader rule or a deny: the precheck requires an
        # already effective allow for this exact capability and target.
        current = self.policy.effective_decision(
            subject_type="auto_rule", subject_id="agent", capability=row["capability"],
            asset_id=row["asset_id"], object_id=row["object_id"],
        )
        before = current.get("matched_rule")
        after = {
            "subject_type": "auto_rule", "subject_id": "agent", "capability": row["capability"],
            "asset_id": row["asset_id"], "object_id": row["object_id"], "allow": True,
            "auto_allowed": True, "require_approval": False,
        }
        t = now()
        self.db.execute(
            "INSERT INTO permissions(subject_type,subject_id,asset_id,capability,object_id,"
            " allow,require_approval,auto_allowed,created_at,updated_at,created_by)"
            " VALUES('auto_rule','agent',?,?,?,1,0,1,?,?,?)"
            " ON CONFLICT(subject_type,subject_id,asset_id,capability,object_id) DO UPDATE SET"
            " auto_allowed=1,require_approval=0,updated_at=excluded.updated_at,"
            " created_by=excluded.created_by WHERE permissions.allow=1",
            (row["asset_id"], row["capability"], row["object_id"], t, t, actor_id),
        )
        effective = self.policy.effective_decision(
            subject_type="auto_rule", subject_id="agent", capability=row["capability"],
            asset_id=row["asset_id"], object_id=row["object_id"],
        )
        if effective.get("decision") != "automatic":
            raise ActionError("permanent_grant_failed", "自动权限未生效，操作未批准")
        detail = {
            "before": before, "after": after, "action_id": row["id"],
            "note": "Explicit permanent consent waives approval only for this capability and target",
        }
        self.db.execute(
            "INSERT INTO config_versions(kind,payload_json,created_at,created_by) VALUES(?,?,?,?)",
            ("permission", json.dumps(detail, ensure_ascii=False), t, actor_id),
        )
        self.db.audit(
            actor_type, actor_id, "permission_auto_allowed_granted", asset_id=row["asset_id"],
            object_id=row["object_id"], action_id=row["id"], detail=detail,
            incident_id=row.get("incident_id") or "", channel=channel,
        )
