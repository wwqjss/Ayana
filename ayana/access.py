"""Human account access; Agent writes use live, persisted session authority.

Stored capability grants, asset exceptions and configurable ceilings are retired.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

from .capabilities import get_capability


class PolicyDeny(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


_channel_operator: ContextVar[tuple[str, str] | None] = ContextVar(
    "ayana_authenticated_channel_operator", default=None,
)


@contextmanager
def authenticated_channel_operator(actor_type: str, actor_id: str) -> Iterator[None]:
    """Enter only after the channel validates its configured operator identity."""
    token = _channel_operator.set((actor_type, actor_id))
    try:
        yield
    finally:
        _channel_operator.reset(token)


class AccessControl:
    """Account roles only; unattended Agent authority requires a bound session."""

    def __init__(self, db: Any, *, admin_qq: str = "", admin_wecom_users=()):
        self.db = db
        self.admin_qq = str(admin_qq or "")
        self.admin_wecom_users = frozenset(
            user.strip() for user in admin_wecom_users if isinstance(user, str) and user.strip()
        ) if isinstance(admin_wecom_users, (list, tuple, set, frozenset)) else frozenset()

    def _role(self, subject_type: str, subject_id: str) -> str:
        if not isinstance(subject_id, str) or not subject_id.strip():
            return ""
        if subject_type == "web_user":
            user = self.db.query_one("SELECT is_admin FROM users WHERE username=?", (subject_id,))
            return ("admin" if user["is_admin"] else "viewer") if user else ""
        if subject_type in ("qq_user", "wecom_user"):
            if _channel_operator.get() == (subject_type, subject_id):
                return "admin"
            if subject_type == "qq_user" and self.admin_qq and subject_id == self.admin_qq:
                return "admin"
            if subject_type == "wecom_user" and subject_id in self.admin_wecom_users:
                return "admin"
        return ""

    def check(self, *, subject_type: str, subject_id: str, capability: str,
              asset_id: str = "", object_id: str = "", auto: bool = False, **_: Any) -> dict[str, Any]:
        try:
            cap = get_capability(capability)
        except KeyError:
            return self._result(False, "unknown_capability", "", "")
        role = self._role(subject_type, subject_id)
        if not role:
            reason = "trusted_session_context_required" if subject_type in ("agent", "auto_rule", "llm", "system") else "authenticated_account_required"
            return self._result(False, reason, cap.kind, "")
        write = cap.kind != "read"
        if write and role != "admin":
            return self._result(False, "admin_required", cap.kind, role)
        if auto and write:
            return self._result(False, "trusted_session_context_required", cap.kind, role)
        return self._result(True, "account_role", cap.kind, role)

    @staticmethod
    def _result(allowed: bool, reason: str, kind: str, role: str) -> dict[str, Any]:
        # Human writes require explicit action approval. Direct configuration
        # endpoints authenticate the administrator's submitted action themselves.
        approval = allowed and kind != "read"
        return {"allowed": allowed, "reason": reason, "kind": kind, "role": role,
                "decision": "approval_required" if approval else "automatic" if allowed else "forbidden",
                "require_approval": approval, "auto_allowed": allowed and not approval,
                "readable": "需要确认本次操作" if approval else "允许读取" if allowed else "禁止",
                "source": "account_role", "rule": None, "matched_rule": None}

    def effective_decision(self, **kwargs: Any) -> dict[str, Any]:
        return self.check(**kwargs)

    def _retired(self, *args: Any, **kwargs: Any):
        raise PolicyDeny("permission_model_retired: 请使用 Agent 设置或会话权限")

    # Import compatibility never revives old grants or old configuration writes.
    upsert_permission = delete_permission = preview = _retired
    model_view = effective_for = effective_summary = _retired
    default_policy = asset_exceptions = list_permissions = list_config_history = _retired
