"""业务权限（Ayana 事实源）。

Web 可查看/修改，带审计与版本快照。
主机侧 commands.json 等仍是独立最终安全上限，本模块不能扩大主机边界。
"""

from __future__ import annotations

import json
from typing import Any

from .capabilities import get_capability, list_capabilities
from .db import Database, now

# 主体
SUBJECT_TYPES = ("web_user", "qq_user", "qq_group", "auto_rule", "llm", "system")


class PolicyDeny(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class Policy:
    def __init__(self, db: Database):
        self.db = db

    def list_permissions(self, filters: dict | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM permissions"
        params: list[Any] = []
        where = []
        if filters:
            for k in ("subject_type", "subject_id", "asset_id", "capability"):
                if filters.get(k):
                    where.append(f"{k}=?")
                    params.append(filters[k])
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY subject_type, subject_id, asset_id, capability"
        return [dict(r) for r in self.db.query(sql, tuple(params))]

    def upsert_permission(
        self,
        *,
        subject_type: str,
        subject_id: str,
        capability: str,
        allow: bool,
        asset_id: str = "*",
        object_id: str = "*",
        require_approval: bool = True,
        auto_allowed: bool = False,
        actor: str = "web",
    ) -> dict[str, Any]:
        if subject_type not in SUBJECT_TYPES:
            raise PolicyDeny(f"bad subject_type: {subject_type}")
        try:
            get_capability(capability)
        except KeyError:
            raise PolicyDeny(f"unknown capability: {capability}") from None
        t = now()
        payload = {
            "subject_type": subject_type,
            "subject_id": subject_id,
            "asset_id": asset_id,
            "capability": capability,
            "object_id": object_id,
            "allow": allow,
            "require_approval": require_approval,
            "auto_allowed": auto_allowed,
        }
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO permissions(subject_type, subject_id, asset_id, capability, object_id,"
                " allow, require_approval, auto_allowed, created_at, updated_at, created_by)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(subject_type, subject_id, asset_id, capability, object_id) DO UPDATE SET"
                " allow=excluded.allow, require_approval=excluded.require_approval,"
                " auto_allowed=excluded.auto_allowed, updated_at=excluded.updated_at,"
                " created_by=excluded.created_by",
                (
                    subject_type,
                    subject_id,
                    asset_id,
                    capability,
                    object_id,
                    1 if allow else 0,
                    1 if require_approval else 0,
                    1 if auto_allowed else 0,
                    t,
                    t,
                    actor,
                ),
            )
            conn.execute(
                "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
                " VALUES(?,?,?,?)",
                ("permission", json.dumps(payload, ensure_ascii=False), t, actor),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json) VALUES(?,?,?,?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor,
                    "permission_upsert",
                    asset_id,
                    object_id,
                    "",
                    json.dumps(
                        {
                            "subject_type": subject_type,
                            "subject_id": subject_id,
                            "capability": capability,
                            "allow": allow,
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        return {"ok": True}

    def delete_permission(self, perm_id: int, actor: str = "web") -> None:
        row = self.db.query_one("SELECT * FROM permissions WHERE id=?", (perm_id,))
        if not row:
            raise PolicyDeny("not found")
        with self.db.tx() as conn:
            conn.execute("DELETE FROM permissions WHERE id=?", (perm_id,))
            conn.execute(
                "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
                " VALUES(?,?,?,?)",
                ("permission_delete", json.dumps(dict(row), ensure_ascii=False), now(), actor),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json)"
                " VALUES(?,?,?,?,?)",
                (
                    now(),
                    "web_user",
                    actor,
                    "permission_delete",
                    json.dumps(dict(row), ensure_ascii=False),
                ),
            )

    def check(
        self,
        *,
        subject_type: str,
        subject_id: str,
        capability: str,
        asset_id: str = "",
        object_id: str = "",
        auto: bool = False,
    ) -> dict[str, Any]:
        """默认拒绝。返回是否允许、是否需批准、命中的规则。"""
        cap = get_capability(capability)
        rows = self.db.query(
            "SELECT * FROM permissions WHERE subject_type=? AND subject_id IN (?, '*')"
            " AND capability IN (?, '*') AND asset_id IN (?, '*', '')"
            " AND object_id IN (?, '*', '')",
            (subject_type, subject_id, capability, asset_id, object_id),
        )
        best = None
        for r in rows:
            # 优先精确匹配
            score = 0
            if r["asset_id"] == asset_id and asset_id:
                score += 2
            if r["object_id"] == object_id and object_id:
                score += 2
            if r["capability"] == capability:
                score += 3
            if r["subject_id"] == subject_id:
                score += 3
            if best is None or score > best[0]:
                best = (score, r)
        if not best or not best[1]["allow"]:
            return {
                "allowed": False,
                "reason": "denied_by_policy",
                "require_approval": True,
                "auto_allowed": False,
                "rule": None,
            }
        rule = dict(best[1])
        require_approval = bool(rule["require_approval"])
        auto_allowed = bool(rule["auto_allowed"]) and cap.auto_allowed
        if auto and not auto_allowed:
            return {
                "allowed": False,
                "reason": "auto_not_allowed",
                "require_approval": True,
                "auto_allowed": False,
                "rule": rule,
            }
        return {
            "allowed": True,
            "reason": "ok",
            "require_approval": require_approval and not auto,
            "auto_allowed": auto_allowed,
            "rule": rule,
        }

    def effective_summary(self) -> dict[str, Any]:
        return {
            "capabilities": list_capabilities(),
            "permissions": self.list_permissions(),
            "note": "主机侧 commands.json / forced-command / sudoers 为独立最终安全上限；"
            "此处仅管理 Ayana 业务授权。",
        }

    def export_snapshot(self) -> list[dict[str, Any]]:
        return self.list_permissions()
