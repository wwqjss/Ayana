"""业务权限（Ayana 事实源）。

Web 可查看/修改，带审计与版本快照。
主机侧 commands.json 等仍是独立最终安全上限，本模块不能扩大主机边界。

ceiling 双义（必须区分）：
- capability catalog ceiling：`capabilities.assert_within_ceiling`，源码固定表，禁止发明能力
- agent ceiling：用户可配的 Agent 权限上限（本模块 AgentCeiling），强制 ⊆ 源码目录
"""

from __future__ import annotations

import json
from typing import Any

from .capabilities import assert_within_ceiling, get_capability, list_capabilities
from .db import Database, now

# 主体
SUBJECT_TYPES = ("web_user", "qq_user", "qq_group", "wecom_user", "auto_rule", "llm", "system")

# 受 agent ceiling 约束的主体（无人在环决策面）
AGENT_SUBJECT_TYPES = ("auto_rule", "llm")


class PolicyDeny(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class AgentCeiling:
    """用户可配 Agent 权限上限。后端强制；不得突破源码能力目录。"""

    def __init__(self, db: Database):
        self.db = db

    def _rows(self) -> dict[str, dict[str, Any]]:
        return {r["capability"]: dict(r) for r in self.db.query("SELECT * FROM agent_ceiling")}

    def effective(self, capability: str) -> dict[str, Any]:
        """未配置时回落到源码目录；已配置时取用户上限，并与目录求交。"""
        cap = assert_within_ceiling(capability)
        row = self._rows().get(capability)
        if not row:
            return {
                "capability": capability,
                "allowed": True,
                "allow_auto": bool(cap.auto_allowed),
                "source": "catalog",
                "configured": False,
            }
        return {
            "capability": capability,
            "allowed": bool(row["allowed"]),
            "allow_auto": bool(row["allow_auto"]) and bool(cap.auto_allowed),
            "source": "agent_ceiling",
            "configured": True,
            "updated_at": row.get("updated_at"),
            "updated_by": row.get("updated_by") or "",
        }

    def set(
        self,
        capability: str,
        *,
        allowed: bool,
        allow_auto: bool = False,
        actor: str = "web",
    ) -> dict[str, Any]:
        """写入上限。未知能力直接拒绝（不能发明）。"""
        cap = assert_within_ceiling(capability)
        # 用户上限不得宽于源码目录
        allow_auto_eff = bool(allow_auto) and bool(cap.auto_allowed)
        t = now()
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO agent_ceiling(capability, allowed, allow_auto, updated_at, updated_by)"
                " VALUES(?,?,?,?,?)"
                " ON CONFLICT(capability) DO UPDATE SET"
                " allowed=excluded.allowed, allow_auto=excluded.allow_auto,"
                " updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (capability, 1 if allowed else 0, 1 if allow_auto_eff else 0, t, actor),
            )
            conn.execute(
                "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
                " VALUES(?,?,?,?)",
                (
                    "agent_ceiling",
                    json.dumps(
                        {
                            "capability": capability,
                            "allowed": bool(allowed),
                            "allow_auto": allow_auto_eff,
                        },
                        ensure_ascii=False,
                    ),
                    t,
                    actor,
                ),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json)"
                " VALUES(?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor,
                    "agent_ceiling_set",
                    json.dumps(
                        {
                            "capability": capability,
                            "allowed": bool(allowed),
                            "allow_auto": allow_auto_eff,
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        return self.effective(capability)

    def list(self) -> list[dict[str, Any]]:
        """目录全集 + 用户上限叠加，供 Web 操纵杆展示。"""
        from .capabilities import ceiling as catalog_names

        out: list[dict[str, Any]] = []
        rows = self._rows()
        for name in catalog_names():
            row = rows.get(name)
            if row:
                out.append(
                    {
                        "capability": name,
                        "allowed": bool(row["allowed"]),
                        "allow_auto": bool(row["allow_auto"]),
                        "configured": True,
                        "updated_at": row.get("updated_at"),
                        "updated_by": row.get("updated_by") or "",
                    }
                )
            else:
                out.append(
                    {
                        "capability": name,
                        "allowed": True,
                        "allow_auto": bool(get_capability(name).auto_allowed),
                        "configured": False,
                    }
                )
        return out


class Policy:
    def __init__(self, db: Database):
        self.db = db
        self.agent_ceiling = AgentCeiling(db)

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

    def default_policy(self, *, subject_type: str = "auto_rule", subject_id: str = "agent") -> dict[str, Any]:
        """按操作类型汇总默认策略（asset_id 为 * 或空）。"""
        rows = self.list_permissions({"subject_type": subject_type, "subject_id": subject_id})
        defaults: dict[str, Any] = {}
        for r in rows:
            aid = (r.get("asset_id") or "").strip()
            if aid not in ("*", ""):
                continue
            oid = (r.get("object_id") or "").strip()
            # 默认策略只认对象通配；具体对象的 * 资产规则算「通配对象例外」，仍作默认层
            if oid not in ("*", ""):
                continue
            defaults[r["capability"]] = self._perm_row_state(r)
        return defaults

    def asset_exceptions(
        self, *, subject_type: str = "auto_rule", subject_id: str = "agent"
    ) -> list[dict[str, Any]]:
        """资产/对象例外：asset_id 或 object_id 具体的规则。"""
        rows = self.list_permissions({"subject_type": subject_type, "subject_id": subject_id})
        out = []
        for r in rows:
            aid = (r.get("asset_id") or "").strip()
            oid = (r.get("object_id") or "").strip()
            if aid in ("*", "") and oid in ("*", ""):
                continue  # 默认层
            item = self._perm_row_state(r)
            item["source"] = "exception"
            out.append(item)
        out.sort(key=lambda x: (x.get("asset_id") or "", x.get("object_id") or "", x.get("capability") or ""))
        return out

    def _perm_row_state(self, r: dict[str, Any]) -> dict[str, Any]:
        allow = bool(r.get("allow"))
        require_approval = bool(r.get("require_approval"))
        auto_allowed = bool(r.get("auto_allowed"))
        # 三态与 UI 一致：禁止 / 需要确认 / 自动执行
        # 自动执行不要求 auto_allowed=True（读能力天然是自动）；auto_allowed 仅约束 Agent 无人自动派发
        if not allow:
            state = "deny"
        elif require_approval:
            state = "confirm"
        else:
            state = "auto"
        return {
            "id": r.get("id"),
            "capability": r.get("capability"),
            "asset_id": r.get("asset_id") or "*",
            "object_id": r.get("object_id") or "*",
            "allow": allow,
            "require_approval": require_approval,
            "auto_allowed": auto_allowed,
            "state": state,
            "source": "default",
            "updated_at": r.get("updated_at"),
            "updated_by": r.get("created_by") or "",
        }

    def model_view(self) -> dict[str, Any]:
        """权限首页模型：默认策略 + 资产例外 + 可配置操作目录。"""
        from .capabilities import list_capabilities

        caps = []
        for c in list_capabilities():
            caps.append(
                {
                    "capability": c["name"],
                    "kind": c.get("kind", ""),
                    "risk": c.get("risk", ""),
                    "description": c.get("description", ""),
                    "auto_allowed": bool(c.get("auto_allowed", False)),
                }
            )
        defaults = self.default_policy()
        # 目录内未显式配置的能力：保守为 deny（默认拒绝，不发明授权）
        for c in caps:
            if c["capability"] not in defaults:
                defaults[c["capability"]] = {
                    "capability": c["capability"],
                    "asset_id": "*",
                    "object_id": "*",
                    "allow": False,
                    "require_approval": True,
                    "auto_allowed": False,
                    "state": "deny",
                    "source": "implicit_deny",
                    "id": None,
                }
        return {
            "capabilities": caps,
            "defaults": defaults,
            "exceptions": self.asset_exceptions(),
        }

    def effective_for(
        self,
        *,
        capability: str,
        asset_id: str = "",
        object_id: str = "",
        subject_type: str = "auto_rule",
        subject_id: str = "agent",
    ) -> dict[str, Any]:
        """查看某对象最终生效权限（含命中来源）。"""
        rule = self._match_rule(
            subject_type=subject_type,
            subject_id=subject_id,
            capability=capability,
            asset_id=asset_id,
            object_id=object_id,
        )
        if not rule:
            return {
                "capability": capability,
                "asset_id": asset_id,
                "object_id": object_id,
                "state": "deny",
                "source": "implicit_deny",
                "decision": "forbidden",
                "readable": "禁止（无规则，默认拒绝）",
            }
        item = self._perm_row_state(dict(rule))
        aid = (rule.get("asset_id") or "").strip()
        oid = (rule.get("object_id") or "").strip()
        if aid in ("*", "") and oid in ("*", ""):
            item["source"] = "default"
        else:
            item["source"] = "exception"
        # 与 check 同源的三态结论
        cap = get_capability(capability)
        auto_allowed = bool(rule.get("auto_allowed")) and bool(cap.auto_allowed)
        decision = self._three_state(
            allow=bool(rule.get("allow")),
            require_approval=bool(rule.get("require_approval")),
            auto_allowed=auto_allowed,
        )
        item["decision"] = decision
        item["readable"] = {
            "forbidden": "禁止",
            "approval_required": "需要人工确认",
            "automatic": "允许自动执行",
        }.get(decision, decision)
        item["matched_rule"] = {
            "id": rule.get("id"),
            "asset_id": rule.get("asset_id"),
            "object_id": rule.get("object_id"),
        }
        return item

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
        if not subject_id or not str(subject_id).strip():
            raise PolicyDeny("bad subject_id")
        try:
            assert_within_ceiling(capability)
        except Exception:
            raise PolicyDeny(f"unknown capability: {capability}") from None
        # 用户不得通过 upsert 抬高超过源码目录的 auto
        cap = get_capability(capability)
        auto_allowed_eff = bool(auto_allowed) and bool(cap.auto_allowed)
        before = self._match_rule(
            subject_type=subject_type,
            subject_id=subject_id,
            capability=capability,
            asset_id=asset_id or "",
            object_id=object_id or "",
        )
        before_snap = (
            {
                "allow": bool(before.get("allow")),
                "require_approval": bool(before.get("require_approval")),
                "auto_allowed": bool(before.get("auto_allowed")),
                "id": before.get("id"),
            }
            if before
            else None
        )
        t = now()
        payload = {
            "subject_type": subject_type,
            "subject_id": subject_id,
            "asset_id": asset_id,
            "capability": capability,
            "object_id": object_id,
            "allow": allow,
            "require_approval": require_approval,
            "auto_allowed": auto_allowed_eff,
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
                    1 if auto_allowed_eff else 0,
                    t,
                    t,
                    actor,
                ),
            )
            conn.execute(
                "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
                " VALUES(?,?,?,?)",
                (
                    "permission",
                    json.dumps({"before": before_snap, "after": payload}, ensure_ascii=False),
                    t,
                    actor,
                ),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json, channel) VALUES(?,?,?,?,?,?,?,?,?)",
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
                            "before": before_snap,
                            "after": payload,
                        },
                        ensure_ascii=False,
                    ),
                    "web",
                ),
            )
        return {"ok": True, "before": before_snap, "after": payload}

    def list_config_history(self, *, kind: str = "permission", limit: int = 50) -> list[dict[str, Any]]:
        """权限/ceiling 变更历史（config_versions），变更前后可读。"""
        rows = self.db.query(
            "SELECT * FROM config_versions WHERE kind IN (?, 'permission_delete', 'agent_ceiling')"
            " ORDER BY created_at DESC LIMIT ?",
            (kind, limit),
        )
        out = []
        for r in rows:
            item = dict(r)
            try:
                item["payload"] = json.loads(item.get("payload_json") or "{}")
            except Exception:
                item["payload"] = {}
            out.append(item)
        return out

    def delete_permission(self, perm_id: int, actor: str = "web") -> None:
        row = self.db.query_one("SELECT * FROM permissions WHERE id=?", (perm_id,))
        if not row:
            raise PolicyDeny("not found")
        snapshot = dict(row)
        with self.db.tx() as conn:
            conn.execute("DELETE FROM permissions WHERE id=?", (perm_id,))
            conn.execute(
                "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
                " VALUES(?,?,?,?)",
                ("permission_delete", json.dumps(snapshot, ensure_ascii=False), now(), actor),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " detail_json, channel) VALUES(?,?,?,?,?,?,?,?)",
                (
                    now(),
                    "web_user",
                    actor,
                    "permission_delete",
                    snapshot.get("asset_id") or "",
                    snapshot.get("object_id") or "",
                    json.dumps({"before": snapshot}, ensure_ascii=False),
                    "web",
                ),
            )

    def preview(
        self,
        *,
        subject_type: str,
        subject_id: str,
        capability: str,
        asset_id: str = "",
        object_id: str = "",
        auto: bool = False,
    ) -> dict[str, Any]:
        """干跑：不落库，返回服务端权威判定（Web 预览 / 审批前核对）。"""
        try:
            assert_within_ceiling(capability)
        except Exception:
            raise PolicyDeny(f"unknown capability: {capability}") from None
        return self.effective_decision(
            subject_type=subject_type,
            subject_id=subject_id,
            capability=capability,
            asset_id=asset_id,
            object_id=object_id,
            auto=auto,
        )

    def _match_rule(
        self,
        *,
        subject_type: str,
        subject_id: str,
        capability: str,
        asset_id: str = "",
        object_id: str = "",
    ) -> dict[str, Any] | None:
        rows = self.db.query(
            "SELECT * FROM permissions WHERE subject_type=? AND subject_id IN (?, '*')"
            " AND capability IN (?, '*') AND asset_id IN (?, '*', '')"
            " AND object_id IN (?, '*', '')",
            (subject_type, subject_id, capability, asset_id, object_id),
        )
        best = None
        for r in rows:
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
        return dict(best[1]) if best else None

    def _agent_ceiling_gate(
        self, subject_type: str, capability: str
    ) -> dict[str, Any] | None:
        """Agent 主体的用户上限。非 Agent 主体返回 None。"""
        if subject_type not in AGENT_SUBJECT_TYPES:
            return None
        # 硬隔离：Agent 永不得使用人工交互终端
        if capability == "shell.interactive":
            return {
                "capability": capability,
                "allowed": False,
                "allow_auto": False,
                "source": "agent_terminal_forbidden",
                "configured": True,
            }
        return self.agent_ceiling.effective(capability)

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
        """默认拒绝。返回是否允许、是否需批准、命中的规则。

        Agent 主体额外受 agent ceiling 约束（后端强制，非前端展示）。
        """
        cap = get_capability(capability)
        ceil = self._agent_ceiling_gate(subject_type, capability)
        if ceil is not None and not ceil["allowed"]:
            return {
                "allowed": False,
                "reason": "denied_by_agent_ceiling",
                "require_approval": True,
                "auto_allowed": False,
                "rule": None,
                "decision": "forbidden",
                "agent_ceiling": ceil,
            }
        rule = self._match_rule(
            subject_type=subject_type,
            subject_id=subject_id,
            capability=capability,
            asset_id=asset_id,
            object_id=object_id,
        )
        if not rule or not rule["allow"]:
            return {
                "allowed": False,
                "reason": "denied_by_policy",
                "require_approval": True,
                "auto_allowed": False,
                "rule": rule,
                "decision": "forbidden",
            }
        require_approval = bool(rule["require_approval"])
        auto_allowed = bool(rule["auto_allowed"]) and cap.auto_allowed
        if ceil is not None:
            # 用户上限不得宽于策略/目录
            auto_allowed = auto_allowed and bool(ceil["allow_auto"])
        if auto and not auto_allowed:
            return {
                "allowed": False,
                "reason": "auto_not_allowed",
                "require_approval": True,
                "auto_allowed": False,
                "rule": rule,
                "decision": "forbidden",
                "agent_ceiling": ceil,
            }
        # S08: 不因 auto=True 隐藏 require_approval；派发门须看到真实审批要求
        decision = self._three_state(
            allow=True, require_approval=require_approval, auto_allowed=auto_allowed
        )
        # auto 模式下若仍需审批，拒绝自动派发
        if auto and decision != "automatic":
            return {
                "allowed": False,
                "reason": "approval_required",
                "require_approval": require_approval,
                "auto_allowed": auto_allowed,
                "rule": rule,
                "decision": decision,
                "agent_ceiling": ceil,
            }
        return {
            "allowed": True,
            "reason": "ok",
            "require_approval": require_approval,
            "auto_allowed": auto_allowed,
            "rule": rule,
            "decision": decision,
            "agent_ceiling": ceil,
        }

    @staticmethod
    def _three_state(*, allow: bool, require_approval: bool, auto_allowed: bool) -> str:
        """forbidden / approval_required / automatic（安全优先）。

        - allow=0 → forbidden
        - allow=1 且 auto_allowed 且 不 require_approval → automatic
        - 其余允许组合 → approval_required（含 auto+require_approval，必须等人）
        """
        if not allow:
            return "forbidden"
        if auto_allowed and not require_approval:
            return "automatic"
        return "approval_required"

    def effective_decision(
        self,
        *,
        subject_type: str,
        subject_id: str,
        capability: str,
        asset_id: str = "",
        object_id: str = "",
        auto: bool = False,
    ) -> dict[str, Any]:
        """服务端权威三态 + reason / matched rule。前端不得自行求优先级。"""
        cap = get_capability(capability)
        is_write = cap.kind == "write"
        ceil = self._agent_ceiling_gate(subject_type, capability)
        rule = self._match_rule(
            subject_type=subject_type,
            subject_id=subject_id,
            capability=capability,
            asset_id=asset_id,
            object_id=object_id,
        )
        if ceil is not None and not ceil["allowed"]:
            decision = "forbidden"
            reason = "denied_by_agent_ceiling"
            require_approval = True
            auto_allowed = False
            allowed = False
        elif not rule or not rule["allow"]:
            decision = "forbidden"
            reason = "denied_by_policy"
            require_approval = True
            auto_allowed = False
            allowed = False
        else:
            require_approval = bool(rule["require_approval"])
            auto_allowed = bool(rule["auto_allowed"]) and cap.auto_allowed
            if ceil is not None:
                auto_allowed = auto_allowed and bool(ceil["allow_auto"])
            decision = self._three_state(
                allow=True, require_approval=require_approval, auto_allowed=auto_allowed
            )
            if auto and decision != "automatic":
                decision = "forbidden"
                reason = "auto_not_allowed"
            else:
                reason = "ok"
            allowed = True
        # 读能力：只表达 允许读取 / 禁止，不伪装成可批准写操作
        if not is_write:
            if ceil is not None and not ceil["allowed"]:
                allowed = False
                decision = "forbidden"
                reason = "denied_by_agent_ceiling"
            else:
                allowed = bool(rule and rule["allow"])
                decision = "automatic" if allowed else "forbidden"
                reason = "ok_read" if allowed else reason
            require_approval = False
            auto_allowed = allowed
            readable = "允许读取" if allowed else "禁止"
        else:
            readable = {
                "forbidden": "禁止",
                "approval_required": "需要我确认",
                "automatic": "自动执行",
            }.get(decision, decision)
        return {
            "decision": decision,
            "allowed": allowed,
            "require_approval": require_approval,
            "auto_allowed": auto_allowed,
            "reason": reason,
            "rule": rule,
            "agent_ceiling": ceil,
            "matched_rule": (
                {
                    "id": rule.get("id"),
                    "subject_type": rule.get("subject_type"),
                    "subject_id": rule.get("subject_id"),
                    "asset_id": rule.get("asset_id"),
                    "object_id": rule.get("object_id"),
                    "capability": rule.get("capability"),
                    "allow": bool(rule.get("allow")),
                    "require_approval": bool(rule.get("require_approval")),
                    "auto_allowed": bool(rule.get("auto_allowed")),
                }
                if rule
                else None
            ),
            "kind": cap.kind,
            "readable": readable,
            "capability": capability,
            "subject": f"{subject_type}:{subject_id}",
            "target": f"{asset_id}/{object_id}",
        }

    def effective_summary(self) -> dict[str, Any]:
        return {
            "capabilities": list_capabilities(),
            "permissions": self.list_permissions(),
            "agent_ceiling": self.agent_ceiling.list(),
            "history": self.list_config_history(limit=20),
            "note": "主机侧 commands.json / forced-command / sudoers 为独立最终安全上限；"
            "此处仅管理 Ayana 业务授权。agent_ceiling 为 Agent 权限上限（后端强制）。",
        }

    def export_snapshot(self) -> list[dict[str, Any]]:
        return self.list_permissions()
