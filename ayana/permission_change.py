"""Permission Change：改变权限边界的受控对象（0.4）。

安全语义（驾驶舱 / 操纵杆）：
- Agent 可以**提出**加权申请，不能批准自己的申请
- 人批准 + TOTP 只签发**这一笔** change_id
- 绝不产生「Agent 获得 N 秒管理员」的授权态
- TOTP 验证码不进入日志、不进入 LLM 上下文、不入库
- 目标 capability 必须在 Node ceiling 内，不能发明 shell.root

状态机：
  proposed → awaiting_mfa → applied
           ↘ rejected / expired
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .capabilities import ObjectBindingError, assert_within_ceiling
from .db import Database, new_id, now

VALID_STATES = ("proposed", "awaiting_mfa", "applied", "rejected", "expired")

# 只允许这些布尔目标值
_ALLOWED_TOGGLES = ("to_allow", "to_require_approval", "to_auto_allowed")


class PermissionChangeError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.detail = message
        super().__init__(f"{code}: {message}" if message else code)


class PermissionChangeService:
    """加权申请的唯一入口。"""

    def __init__(
        self,
        db: Database,
        policy: Any,
        *,
        ttl_sec: float = 86400.0,
        # 验证 TOTP：fn(username, code) -> bool；绝不把 code 传给 LLM
        totp_verifier: Callable[[str, str], bool] | None = None,
    ):
        self.db = db
        self.policy = policy
        self.ttl_sec = float(ttl_sec)
        self.totp_verifier = totp_verifier

    # ------------------------------------------------------------------
    # 提出（Agent / Web 均可；不自动生效）
    # ------------------------------------------------------------------

    def propose(
        self,
        *,
        subject_type: str,
        subject_id: str,
        capability: str,
        asset_id: str = "*",
        object_id: str = "*",
        to_allow: bool = True,
        to_require_approval: bool = True,
        to_auto_allowed: bool = False,
        reason: str = "",
        incident_id: str = "",
        created_by: str = "system",
        created_channel: str = "web",
    ) -> dict[str, Any]:
        # ceiling：能力不存在 → 拒绝，不得发明
        try:
            cap = assert_within_ceiling(capability)
        except ObjectBindingError as e:
            raise PermissionChangeError("not_in_ceiling", str(e)) from e
        if cap.kind != "write" and (to_allow and to_auto_allowed):
            # 读能力不走「自动写」语义；仍允许显式 allow
            pass

        if subject_type not in ("web_user", "qq_user", "qq_group", "auto_rule", "llm", "system"):
            raise PermissionChangeError("bad_subject", subject_type)

        # 现值快照
        existing = self.policy.check(
            subject_type=subject_type,
            subject_id=subject_id,
            capability=capability,
            asset_id=asset_id,
            object_id=object_id,
        )
        rule = existing.get("rule") or existing.get("matched_rule") or {}
        from_snap = {
            "allowed": existing.get("allowed"),
            "require_approval": existing.get("require_approval"),
            "auto_allowed": existing.get("auto_allowed"),
            "decision": existing.get("decision"),
            "matched_rule": existing.get("matched_rule"),
        }

        cid = new_id("pc")
        t = now()
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO permission_changes(id, subject_type, subject_id, capability,"
                " asset_id, object_id, to_allow, to_require_approval, to_auto_allowed,"
                " reason, incident_id, state, created_by, created_channel, created_at,"
                " from_snapshot_json)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    cid,
                    subject_type,
                    subject_id,
                    capability,
                    asset_id or "*",
                    object_id or "*",
                    1 if to_allow else 0,
                    1 if to_require_approval else 0,
                    1 if to_auto_allowed else 0,
                    (reason or "")[:500],
                    incident_id or "",
                    "proposed",
                    created_by,
                    created_channel,
                    t,
                    json.dumps(from_snap, ensure_ascii=False, default=str),
                ),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " detail_json, incident_id, channel, decision_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    t,
                    "system" if created_channel == "system" else "web_user",
                    created_by,
                    "permission_change_proposed",
                    asset_id or "*",
                    object_id or "*",
                    json.dumps(
                        {
                            "change_id": cid,
                            "capability": capability,
                            "to_allow": to_allow,
                            "to_require_approval": to_require_approval,
                            "to_auto_allowed": to_auto_allowed,
                            "reason": reason[:200],
                        },
                        ensure_ascii=False,
                    ),
                    incident_id or "",
                    created_channel,
                    cid,
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    incident_id or "",
                    t,
                    "permission_change_proposed",
                    f"permission change {cid}",
                    json.dumps(
                        {
                            "change_id": cid,
                            "capability": capability,
                            "target": f"{asset_id}/{object_id}",
                            "reason": reason[:200],
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        return {"id": cid, "state": "proposed", "capability": capability}

    # ------------------------------------------------------------------
    # 展示 diff（给管理员看的完整变更）
    # ------------------------------------------------------------------

    def present(self, change_id: str) -> dict[str, Any]:
        row = self._get(change_id)
        try:
            from_snap = json.loads(row.get("from_snapshot_json") or "{}")
        except Exception:
            from_snap = {}
        return {
            "id": row["id"],
            "state": row["state"],
            "subject": f"{row['subject_type']}:{row['subject_id']}",
            "target": f"{row['asset_id']}/{row['object_id']}",
            "capability": row["capability"],
            "from": from_snap,
            "to": {
                "allow": bool(row["to_allow"]),
                "require_approval": bool(row["to_require_approval"]),
                "auto_allowed": bool(row["to_auto_allowed"]),
            },
            "reason": row["reason"],
            "incident_id": row["incident_id"],
            "created_by": row["created_by"],
            "created_channel": row["created_channel"],
            "created_at": row["created_at"],
            "ttl_sec": self.ttl_sec,
            "note": "TOTP 仅放行本 change_id，不授予管理员会话",
        }

    # ------------------------------------------------------------------
    # 人审 + TOTP：只签这一笔
    # ------------------------------------------------------------------

    def authorize(
        self,
        change_id: str,
        *,
        actor_id: str,
        totp_code: str,
        channel: str = "web",
        is_admin: bool = False,
    ) -> dict[str, Any]:
        """验证 TOTP 并仅应用这一笔 Permission Change。"""
        row = self._get(change_id)
        if row["state"] not in ("proposed", "awaiting_mfa"):
            raise PermissionChangeError("bad_state", row["state"])
        if now() - float(row["created_at"] or 0) > self.ttl_sec:
            self._expire(change_id)
            raise PermissionChangeError("expired", change_id)

        if not is_admin:
            raise PermissionChangeError("admin_required", "permission change requires admin")
        if not totp_code or not str(totp_code).strip():
            raise PermissionChangeError("totp_required", "TOTP required")

        # TOTP 验证：仅本接口可见；失败不落库、不进事件正文
        verified = False
        if self.totp_verifier:
            try:
                verified = bool(self.totp_verifier(actor_id, str(totp_code).strip()))
            except Exception:
                verified = False
        if not verified:
            self.db.audit(
                "web_user",
                actor_id,
                "permission_change_totp_failed",
                action_id="",
                detail={"change_id": change_id},
                decision_id=change_id,
            )
            # 状态保持，可重试；绝不部分应用
            raise PermissionChangeError("totp_invalid", "TOTP verification failed")

        # ceiling 再校验（防 TOCTOU）
        try:
            assert_within_ceiling(row["capability"])
        except ObjectBindingError as e:
            raise PermissionChangeError("not_in_ceiling", str(e)) from e

        t = now()
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE permission_changes SET state='applied', decided_by=?, decided_channel=?,"
                " decided_at=?, totp_verified_at=?, applied_at=?"
                " WHERE id=? AND state IN ('proposed','awaiting_mfa')",
                (actor_id, channel, t, t, t, change_id),
            )
            if cur.rowcount != 1:
                fresh = conn.execute(
                    "SELECT state FROM permission_changes WHERE id=?", (change_id,)
                ).fetchone()
                raise PermissionChangeError(
                    "bad_state", fresh["state"] if fresh else "unknown"
                )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " detail_json, incident_id, channel, decision_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor_id,
                    "permission_change_applied",
                    row["asset_id"],
                    row["object_id"],
                    json.dumps(
                        {
                            "change_id": change_id,
                            "capability": row["capability"],
                            "subject": f"{row['subject_type']}:{row['subject_id']}",
                            "to_allow": bool(row["to_allow"]),
                            "to_require_approval": bool(row["to_require_approval"]),
                            "to_auto_allowed": bool(row["to_auto_allowed"]),
                            "channel": channel,
                            "scope": "this_change_only",
                        },
                        ensure_ascii=False,
                    ),
                    row["incident_id"] or "",
                    channel,
                    change_id,
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    row["incident_id"] or "",
                    t,
                    "permission_change_applied",
                    f"permission change applied {change_id}",
                    json.dumps(
                        {
                            "change_id": change_id,
                            "capability": row["capability"],
                            "note": "TOTP authorized this change only",
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        # 应用 Policy（在事务外调用，Policy 自写 audit）
        self.policy.upsert_permission(
            subject_type=row["subject_type"],
            subject_id=row["subject_id"],
            capability=row["capability"],
            asset_id=row["asset_id"],
            object_id=row["object_id"],
            allow=bool(row["to_allow"]),
            require_approval=bool(row["to_require_approval"]),
            auto_allowed=bool(row["to_auto_allowed"]),
            actor=actor_id,
        )
        return {
            "id": change_id,
            "state": "applied",
            "scope": "this_change_only",
            "capability": row["capability"],
        }

    def reject(
        self,
        change_id: str,
        *,
        actor_id: str,
        reason: str = "",
        channel: str = "web",
        is_admin: bool = False,
    ) -> dict[str, Any]:
        row = self._get(change_id)
        if row["state"] not in ("proposed", "awaiting_mfa"):
            raise PermissionChangeError("bad_state", row["state"])
        t = now()
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE permission_changes SET state='rejected', decided_by=?,"
                " decided_channel=?, decided_at=? WHERE id=? AND state IN ('proposed','awaiting_mfa')",
                (actor_id, channel, t, change_id),
            )
            if cur.rowcount != 1:
                raise PermissionChangeError("bad_state", "not_pending")
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json,"
                " incident_id, channel, decision_id) VALUES(?,?,?,?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor_id,
                    "permission_change_rejected",
                    json.dumps({"change_id": change_id, "reason": reason[:200]}, ensure_ascii=False),
                    row["incident_id"] or "",
                    channel,
                    change_id,
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    row["incident_id"] or "",
                    t,
                    "permission_change_rejected",
                    f"permission change rejected {change_id}",
                    json.dumps({"change_id": change_id, "reason": reason[:200]}, ensure_ascii=False),
                ),
            )
        return {"id": change_id, "state": "rejected"}

    def expire_stale(self) -> int:
        t = now()
        n = 0
        rows = self.db.query(
            "SELECT id, incident_id FROM permission_changes"
            " WHERE state IN ('proposed','awaiting_mfa') AND ? - created_at > ?",
            (t, self.ttl_sec),
        )
        for r in rows:
            if self._expire(r["id"]):
                n += 1
        return n

    def list_changes(self, state: str = "", limit: int = 50) -> list[dict[str, Any]]:
        if state:
            rows = self.db.query(
                "SELECT * FROM permission_changes WHERE state=? ORDER BY created_at DESC LIMIT ?",
                (state, limit),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM permission_changes ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in rows]

    def _expire(self, change_id: str) -> bool:
        t = now()
        cur = self.db.execute(
            "UPDATE permission_changes SET state='expired', decided_at=?"
            " WHERE id=? AND state IN ('proposed','awaiting_mfa')",
            (t, change_id),
        )
        return bool(cur and cur.rowcount)

    def _get(self, change_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM permission_changes WHERE id=?", (change_id,))
        if not row:
            raise PermissionChangeError("not_found", change_id)
        return dict(row)
