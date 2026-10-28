"""Shared human decisions for notification replies and the incident console.

The caller authenticates the channel identity. ActionService rechecks account
access and live session authority. A human decision applies to one action only;
automatic execution is configured through Agent/session settings.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from .actions import ActionError, ActionService, action_incident_block
from .db import now


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
            raise ActionError("bad_approval_decision", "请选择执行一次或不执行")
        if actor_type not in ("web_user", "qq_user", "wecom_user") or not str(actor_id).strip():
            raise ActionError("human_required", "此决定需要已认证的人类身份")
        if choice == "allow_always":
            raise ActionError("permanent_permission_retired",
                              "逐项永久授权已移除；请在 Agent 设置或当前会话中调整审批模式")
        row: dict[str, Any] | None = None
        try:
            # Selection and one-action approval refer to the same current
            # proposal. No settings change or network await occurs here.
            with self.db.tx():
                row = self.select_action(action_id=action_id, incident_id=incident_id)
                aid = row["id"]
                if choice == "reject":
                    result = self.actions.reject(
                        aid, actor_type=actor_type, actor_id=actor_id, channel=channel,
                        reason=reason or "human_rejected",
                    )
                    return {**result, "decision": choice, "permanent_granted": False}
                approved = self.actions.approve(
                    aid, approver_type=actor_type, approver_id=actor_id,
                    channel=channel, reason=reason or choice,
                )
                if approved.get("already"):
                    return {**approved, "decision": choice, "permanent_granted": False}
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
        # gate rechecks identity, session authority, binding, deadlines and object locking.
        try:
            executed = await self.actions.execute(
                aid, actor_type=actor_type, actor_id=actor_id, is_admin=is_admin,
            )
            return {
                "id": aid, "state": executed.get("state"), "approved": True,
                "executed": True, "detail": executed.get("detail", ""), "channel": channel,
                "decision": choice, "permanent_granted": False,
            }
        except ActionError as exc:
            state = self.actions._get(aid).get("state", "approved")
            return {
                "id": aid, "state": state, "execution_pending": state == "approved",
                "approved": True, "executed": False, "error": exc.code,
                "message": str(exc), "channel": channel, "decision": choice,
                "permanent_granted": False,
            }

