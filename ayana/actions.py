"""Action：提案 → 批准 → 受限执行 → 独立验证。

硬约束（二审）：
- 身份核验后的短事务内重查授权/期限/对象/占用，并记录实际派发者
- 执行结果、审计、验证义务、事件同事务提交
- 验证期间对象占用不释放
- 关闭 Incident 必须核对资产与规范化对象
- 采样按完整标签+时间保存，歧义序列拒绝通过
- 负退出码 / 运输不确定 → unknown
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any

from .capabilities import (
    ObjectBindingError,
    build_write_tokens,
    get_capability,
    object_matches_capability,
    resolve_object_name,
)
from .db import Database, new_id, now
from .ntsafe import IdentityGate, NTClient, NTError
from .policy import Policy
from .prom import PromClient, group_by_series, match_series, series_key

log = logging.getLogger("ayana.actions")


class ActionError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.detail = message
        super().__init__(f"{code}: {message}" if message else code)


UNKNOWN_HINTS = (
    "timeout",
    "connection reset",
    "connection refused",
    "broken pipe",
    "connection closed",
    "no route to host",
    "network is unreachable",
    "connection aborted",
    "killed",
)

# 全局硬约束：结果不明的写操作不得自动重放（v0.4.0 1a 起断言）
# unknown / dispatched / 已终结态一律禁止再次派发
WRITE_NO_REPLAY_STATES = frozenset(
    {"unknown", "dispatched", "success", "failure", "cancelled", "expired", "rejected"}
)

# These stop automatic dispatch temporarily; Agent owns the wait/retry path.
AUTO_RETRYABLE_BLOCKS = frozenset({
    "cooldown", "budget_exhausted", "global_pause", "object_locked", "source_unavailable",
})


def _source_block_code(reason: str) -> str:
    return "source_quarantined" if reason.startswith("quarantined_source:") else "source_unavailable"


def write_may_dispatch(state: str) -> bool:
    """仅 approved 可进入派发；其余（含 unknown）一律不可。"""
    return state == "approved"


def legacy_action_block(action: Any) -> tuple[str, str] | None:
    """Persisted autonomous authorization cannot become a manual write.

    Final architecture: mode=autonomous is the MiMoCode closed-loop path.
    Legacy council/auto/reviewed grants remain permanently retired.
    """
    row = dict(action)
    mode = str(row.get("mode") or "manual").strip().lower()
    if (mode in ("auto", "reviewed") or row.get("council_grant_id")
            or row.get("council_step", -1) not in (-1, None)
            or str(row.get("decision_channel") or "").strip().lower() == "council"):
        return "legacy_autonomy_retired", "Legacy autonomous authorization is permanently retired"
    if mode not in ("manual", "autonomous"):
        return "bad_mode", "Only manual or autonomous actions may execute"
    return None


def action_incident_block(store: Any, action: Any) -> tuple[str, str] | None:
    """Current incident validity for approval and the final dispatch claim.

    store may be Database or the caller's SQLite transaction. A generation
    change during identity verification must invalidate the old action.
    """
    row = dict(action)
    incident_id = row.get("incident_id") or ""
    if not incident_id:
        return None
    incident = store.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not incident:
        return ("incident_not_found", "关联事件不存在")
    if incident["status"] != "open":
        return ("incident_not_open", "关联事件已恢复或关闭")
    if incident["asset_id"] and incident["asset_id"] != row["asset_id"]:
        return ("incident_mismatch", "关联事件的资产已改变")
    obj = store.execute(
        "SELECT id,name FROM objects WHERE asset_id=? AND (id=? OR name=?)",
        (row["asset_id"], row["object_id"], row["object_id"]),
    ).fetchone()
    expected = (incident["object_id"] or "").strip()
    if expected and obj and expected not in (obj["id"], obj["name"]):
        return ("incident_mismatch", "关联事件的对象已改变")
    generation = store.execute(
        "SELECT id,at FROM events WHERE incident_id=? AND type IN"
        " ('generation_bumped','incident_reopened','incident_opened') ORDER BY id DESC LIMIT 1",
        (incident_id,),
    ).fetchone()
    if generation:
        proposed = store.execute(
            "SELECT id FROM events WHERE incident_id=? AND type='action_proposed'"
            " AND json_valid(payload_json) AND json_extract(payload_json,'$.action_id')=?"
            " ORDER BY id DESC LIMIT 1", (incident_id, row["id"]),
        ).fetchone()
        # Event ordering disambiguates equal clock timestamps (common on
        # Windows); old imported actions without an event use the cutoff.
        stale = (int(proposed["id"]) < int(generation["id"])) if proposed else (
            float(row["created_at"]) < float(generation["at"])
        )
        if stale:
            return ("stale_generation", "此操作属于上次故障，请处理当前故障的操作")
    return None


class ActionService:
    def __init__(
        self,
        db: Database,
        nt: NTClient,
        gate: IdentityGate,
        policy: Policy,
        prom: PromClient,
        *,
        transport: Any | None = None,
        action_ttl: int = 1800,
        approval_ttl: int = 900,
        verify_window: int = 90,
        verify_timeout: int = 300,
    ):
        self.db = db
        # self.nt 未使用；nt 仅作 transport 回退（见下行）
        self.gate = gate
        self.policy = policy
        self.prom = prom
        # 测试可传 Fake 作为 transport；生产为 SSH Router
        self.transport = transport if transport is not None else nt
        self.action_ttl = action_ttl
        self.approval_ttl = approval_ttl
        self.verify_window = verify_window
        self.verify_timeout = verify_timeout
        self._exec_lock = asyncio.Lock()
        # P4.2：可选幂等台账（SessionBridge）；未注入则退化为仅 FSM 防重放
        self.write_ops = None

    async def _write_channel(self, asset_id: str, tokens: list[str], timeout: float | None = None):
        """写通道：仅原生 SSH。NT 已移除。"""
        if self.transport is not None:
            return await self.transport.exec(asset_id, tokens, timeout=timeout)
        raise ActionError("ssh_required", "native SSH transport not configured")

    # ------------------------------------------------------------------
    # 提案
    # ------------------------------------------------------------------

    def propose(
        self,
        *,
        asset_id: str,
        object_id: str,
        capability: str,
        params: dict | None = None,
        reason: str = "",
        incident_id: str = "",
        proposer_type: str = "web_user",
        proposer_id: str = "system",
        mode: str = "manual",
        runbook_id: str = "",
        runbook_rev: str = "",
        template_id: str = "",
        council_grant_id: str = "",
        council_step: int = -1,
    ) -> dict[str, Any]:
        blocked = legacy_action_block({"mode": mode, "council_grant_id": council_grant_id,
                                       "council_step": council_step})
        if blocked:
            raise ActionError(*blocked)
        cap = get_capability(capability)
        if cap.kind != "write":
            raise ActionError("not_a_write_capability")
        # 自动必须带 runbook；人工必须带 template 或 runbook（显式契约）
        if mode == "auto" and not runbook_id:
            raise ActionError("runbook_required", "auto mode requires runbook_id")
        if mode == "manual" and not (runbook_id or template_id):
            from .runbook import CAPABILITY_TEMPLATE, get_manual_template

            guess = CAPABILITY_TEMPLATE.get(capability, "")
            if guess and get_manual_template(guess):
                template_id = guess
            else:
                raise ActionError(
                    "template_required", "manual write requires template_id or runbook_id"
                )
        # autonomous：MiMoCode 闭环写；契约=能力目录+对象绑定，不强制 template/runbook
        if mode == "autonomous":
            runbook_id = runbook_id or ""
            template_id = template_id or ""
        obj = self._object(asset_id, object_id)
        if not obj:
            raise ActionError("object_not_registered", object_id)
        try:
            object_matches_capability(capability, obj)
            tokens = build_write_tokens(capability, obj)
        except ObjectBindingError as e:
            raise ActionError("object_binding", str(e)) from e
        except Exception as e:
            raise ActionError("bad_params", str(e)) from e

        object_ref = obj["id"]
        params_digest = hashlib.sha256(
            json.dumps({"tokens": tokens, "params": params or {}}, sort_keys=True).encode()
        ).hexdigest()[:16]

        # Incident 关联校验：资产一致，对象要么空要么对应
        if incident_id:
            self._assert_incident_matches(incident_id, asset_id, obj)

        # 自动语义与人工语义分开（P1-01：服务端三态）
        # final: mode=autonomous 退役 Agent Ceiling 与三态自治限制；
        # 人工 Web/QQ 仍走 Policy。硬保护（能力目录/对象绑定/host key/幂等）不变。
        if mode == "autonomous":
            decision = {
                "decision": "automatic",
                "allowed": True,
                "require_approval": False,
                "auto_allowed": True,
                "reason": "autonomous_ceiling_and_three_state_retired",
                "rule": None,
                "agent_ceiling": None,
            }
        else:
            decision = self.policy.effective_decision(
                subject_type=proposer_type,
                subject_id=proposer_id,
                capability=capability,
                asset_id=asset_id,
                object_id=obj["id"],
                auto=(mode in ("auto", "reviewed")),
            )
        if decision.get("decision") == "forbidden" or not decision["allowed"]:
            if mode == "auto" and decision.get("reason") == "auto_not_allowed":
                raise ActionError("auto_not_allowed", decision.get("reason", ""))
            raise ActionError("denied", decision.get("reason") or "forbidden")
        if mode in ("auto", "reviewed") and decision.get("decision") != "automatic":
            raise ActionError("auto_not_allowed", decision.get("reason", ""))
        if mode in ("auto", "reviewed", "autonomous"):
            from .incidents import IncidentService
            from .verify_profiles import profile_for_action

            blocked = IncidentService(self.db).source_block_reason(incident_id) if incident_id else ""
            if blocked:
                raise ActionError(_source_block_code(blocked), blocked)
            if profile_for_action(
                capability=capability, asset_id=asset_id, object_id=resolve_object_name(obj),
            ) is None:
                if incident_id:
                    IncidentService(self.db).set_need_human(
                        incident_id, "unsupported_verification_profile",
                    )
                raise ActionError("unsupported_verification_profile")

        if self._object_locked(asset_id, obj["id"]):
            raise ActionError("object_locked", f"{asset_id}/{obj['id']}")

        aid = new_id("act")
        payload = {
            "params": params or {},
            "tokens": tokens,
            "object_name": resolve_object_name(obj),
            "object_kind": obj.get("kind") or "",
            "object_ref": object_ref,
            "params_digest": params_digest,
            "mode": mode,
            "runbook_id": runbook_id,
            "runbook_rev": runbook_rev,
            "template_id": template_id,
        }
        approval_deadline = now() + float(self.action_ttl)
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
                " params_json, reason, state, proposer_type, proposer_id, created_at,"
                " policy_snapshot_json, mode, runbook_id, runbook_rev, template_id,"
                " object_ref, params_digest, approval_deadline)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    aid,
                    incident_id,
                    asset_id,
                    obj["id"],
                    capability,
                    json.dumps(payload, ensure_ascii=False),
                    reason,
                    "proposed",
                    proposer_type,
                    proposer_id,
                    now(),
                    json.dumps(decision, ensure_ascii=False, default=str),
                    mode,
                    runbook_id,
                    runbook_rev,
                    template_id,
                    object_ref,
                    params_digest,
                    approval_deadline,
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    incident_id,
                    now(),
                    "action_proposed",
                    f"{capability} on {asset_id}/{obj['id']}",
                    json.dumps({"action_id": aid, "tokens": tokens, "mode": mode}, ensure_ascii=False),
                ),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json, incident_id, channel) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    now(),
                    proposer_type,
                    proposer_id,
                    "action_proposed",
                    asset_id,
                    obj["id"],
                    aid,
                    json.dumps(
                        {
                            "capability": capability,
                            "reason": reason,
                            "mode": mode,
                            "runbook_id": runbook_id,
                            "runbook_rev": runbook_rev,
                            "template_id": template_id,
                            "params_digest": params_digest,
                            "tokens": tokens,
                        },
                        ensure_ascii=False,
                    ),
                    incident_id or "",
                    "system" if mode in ("auto", "autonomous") else "web",
                ),
            )
        state = "proposed"
        require_approval = decision.get("require_approval", True)
        # autonomous：系统即批，无需常规人工审批（人工 Web/QQ 路径不变）
        if mode == "autonomous":
            require_approval = False
            self._system_approve_autonomous(
                aid, incident_id=incident_id, asset_id=asset_id, object_id=obj["id"],
                capability=capability, tokens=tokens,
            )
            state = "approved"
        return {
            "id": aid,
            "state": state,
            "tokens": tokens,
            "mode": mode,
            "runbook_id": runbook_id,
            "runbook_rev": runbook_rev,
            "template_id": template_id,
            "require_approval": require_approval,
            "decision": decision.get("decision", "approval_required"),
            "effective_decision": decision,
        }

    def _system_approve_autonomous(
        self,
        action_id: str,
        *,
        incident_id: str,
        asset_id: str,
        object_id: str,
        capability: str,
        tokens: list[str],
    ) -> None:
        """autonomous 系统批准：记审计与 decision 快照，不走人工 Policy。"""
        t = now()
        decision_id = new_id("dec")
        snapshot = {
            "decision": "automatic",
            "reason": "autonomous_ceiling_and_three_state_retired",
            "require_approval": False,
            "agent_ceiling": None,
        }
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE actions SET state='approved', approver_type='system',"
                " approver_id='autonomous', approved_at=?, decision_channel='autonomous',"
                " decision_reason='autonomous_ceiling_and_three_state_retired', decided_at=?,"
                " decision_id=?, decision_snapshot_json=? WHERE id=? AND state='proposed'",
                (t, t, decision_id, json.dumps(snapshot, ensure_ascii=False), action_id),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json, incident_id, channel) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    t, "system", "autonomous", "action_approved",
                    asset_id, object_id, action_id,
                    json.dumps({"capability": capability, "tokens": tokens, "mode": "autonomous"}),
                    incident_id or "", "autonomous",
                ),
            )

    async def autonomous_execute(
        self,
        *,
        asset_id: str,
        object_id: str,
        capability: str,
        params: dict | None = None,
        reason: str = "",
        incident_id: str = "",
        actor_id: str = "mimo_agent",
    ) -> dict[str, Any]:
        """MiMoCode 闭环：提案（系统批准）→ 执行。硬保护仍在 execute。"""
        proposed = self.propose(
            asset_id=asset_id,
            object_id=object_id,
            capability=capability,
            params=params,
            reason=reason,
            incident_id=incident_id,
            proposer_type="agent",
            proposer_id=actor_id,
            mode="autonomous",
        )
        return await self.execute(
            proposed["id"],
            actor_type="agent",
            actor_id=actor_id,
            is_admin=False,
        )

    def _assert_incident_matches(self, incident_id: str, asset_id: str, obj: dict) -> None:
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not inc:
            raise ActionError("incident_not_found", incident_id)
        if inc["status"] != "open":
            raise ActionError("incident_not_open", "关联事件已恢复或关闭")
        if inc["asset_id"] and inc["asset_id"] != asset_id:
            raise ActionError(
                "incident_mismatch",
                f"incident asset={inc['asset_id']} action asset={asset_id}",
            )
        inc_obj = (inc["object_id"] or "").strip()
        action_obj = (obj.get("name") or "").strip()
        if inc_obj and action_obj and inc_obj not in (obj["id"], action_obj):
            raise ActionError(
                "incident_mismatch",
                f"incident object={inc_obj} action object={action_obj}",
            )

    def authorize_reviewed(self, action_id: str, *, grant_id: str, ordinal: int) -> dict:
        raise ActionError("legacy_autonomy_retired")

    # ------------------------------------------------------------------
    # 批准 / 拒绝 / 取消（Web / QQ 共用；幂等）
    # ------------------------------------------------------------------

    def approve(
        self,
        action_id: str,
        *,
        approver_type: str = "web_user",
        approver_id: str = "system",
        channel: str = "web",
        reason: str = "",
    ) -> dict[str, Any]:
        """批准提案。幂等：已批准/已派发不重复产生第二次 dispatch。"""
        row = self._get(action_id)
        blocked = legacy_action_block(row)
        if blocked:
            raise ActionError(*blocked)
        state = row["state"]
        if state in ("approved", "dispatched", "success", "failure", "unknown"):
            return {
                "id": action_id,
                "state": state,
                "idempotent": True,
                "already": True,
            }
        if state != "proposed":
            raise ActionError("bad_state", state)
        if now() - row["created_at"] > self.action_ttl or (
            row.get("approval_deadline") and now() > float(row["approval_deadline"])
        ):
            self.db.execute(
                "UPDATE actions SET state='expired', finished_at=? WHERE id=? AND state='proposed'",
                (now(), action_id),
            )
            raise ActionError("expired")

        blocked = action_incident_block(self.db, row)
        if blocked:
            self.db.audit(
                approver_type, approver_id, "action_approve_denied",
                asset_id=row["asset_id"], object_id=row["object_id"], action_id=action_id,
                incident_id=row.get("incident_id") or "", channel=channel,
                detail={"reason": blocked[0], "channel": channel},
            )
            raise ActionError(*blocked)

        # B2: 职责分离——同一人类主体不得自批；admin web / auto_rule 自动链除外
        HUMAN_TYPES = {"web_user", "qq_user", "wecom_user"}
        proposer_type = row.get("proposer_type") or ""
        proposer_id = row.get("proposer_id") or ""
        if (
            approver_type in HUMAN_TYPES
            and proposer_type in HUMAN_TYPES
            and approver_id
            and approver_id == proposer_id
            and (approver_type == proposer_type or True)
        ):
            # 同名跨渠道也视为同一人（qq_user:admin 与 web_user:admin）
            approver_row = self.db.query_one(
                "SELECT is_admin FROM users WHERE username=?", (approver_id,)
            )
            if not (approver_row and approver_row["is_admin"]):
                self.db.audit(
                    approver_type,
                    approver_id,
                    "action_approve_denied",
                    asset_id=row["asset_id"],
                    object_id=row["object_id"],
                    action_id=action_id,
                    detail={"reason": "self_approve_denied", "channel": channel},
                    incident_id=row.get("incident_id") or "",
                    channel=channel,
                )
                raise ActionError("self_approve_denied", "proposer cannot approve own action")

        decision = self.policy.effective_decision(
            subject_type=approver_type,
            subject_id=approver_id,
            capability=row["capability"],
            asset_id=row["asset_id"],
            object_id=row["object_id"],
        )
        if not decision["allowed"] or decision.get("decision") == "forbidden":
            self.db.audit(
                approver_type,
                approver_id,
                "action_approve_denied",
                asset_id=row["asset_id"],
                object_id=row["object_id"],
                action_id=action_id,
                detail={
                    "reason": decision.get("reason", ""),
                    "decision": decision.get("decision"),
                    "channel": channel,
                    "capability": row.get("capability") or "",
                },
                incident_id=row.get("incident_id") or "",
                channel=channel,
            )
            raise ActionError("approve_denied", decision.get("reason", "forbidden"))

        t = now()
        decision_id = new_id("dec")
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE actions SET state='approved', approver_type=?, approver_id=?,"
                " approved_at=?, decision_channel=?, decision_reason=?, decided_at=?,"
                " decision_id=?, decision_snapshot_json=?"
                " WHERE id=? AND state='proposed'",
                (
                    approver_type,
                    approver_id,
                    t,
                    channel,
                    reason,
                    t,
                    decision_id,
                    json.dumps(decision, ensure_ascii=False, default=str),
                    action_id,
                ),
            )
            if cur.rowcount != 1:
                # 并发下已被别人批准/处理：幂等返回当前态
                fresh = conn.execute(
                    "SELECT state FROM actions WHERE id=?", (action_id,)
                ).fetchone()
                return {
                    "id": action_id,
                    "state": (fresh["state"] if fresh else "unknown"),
                    "idempotent": True,
                    "already": True,
                }
            payload_json = row.get("params_json") or "{}"
            try:
                tokens = (json.loads(payload_json) or {}).get("tokens") or []
            except Exception:
                tokens = []
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json, decision_id, incident_id, channel)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    t,
                    approver_type,
                    approver_id,
                    "action_approved",
                    row["asset_id"],
                    row["object_id"],
                    action_id,
                    json.dumps(
                        {
                            "channel": channel,
                            "reason": reason,
                            "capability": row.get("capability") or "",
                            "tokens": tokens,
                            "decision": decision.get("decision"),
                            "matched_rule": decision.get("matched_rule"),
                            "policy_snapshot": {
                                "allowed": decision.get("allowed"),
                                "require_approval": decision.get("require_approval"),
                                "auto_allowed": decision.get("auto_allowed"),
                                "reason": decision.get("reason"),
                            },
                        },
                        ensure_ascii=False,
                    ),
                    decision_id,
                    row.get("incident_id") or "",
                    channel,
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    row["incident_id"] or "",
                    t,
                    "action_approved",
                    f"approved {action_id}",
                    json.dumps(
                        {
                            "action_id": action_id,
                            "approver": f"{approver_type}:{approver_id}",
                            "channel": channel,
                            "reason": reason,
                            "decision": decision.get("decision"),
                            "decision_id": decision_id,
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
            from .incidents import IncidentService

            IncidentService(self.db).clear_awaiting_approval(row["incident_id"], action_id)
        return {
            "id": action_id,
            "state": "approved",
            "idempotent": False,
            "decision": decision.get("decision"),
            "decision_id": decision_id,
        }

    def reject(
        self,
        action_id: str,
        *,
        actor_type: str = "web_user",
        actor_id: str = "system",
        channel: str = "web",
        reason: str = "",
    ) -> dict[str, Any]:
        """拒绝提案：零派发。幂等。"""
        row = self._get(action_id)
        decision = self.policy.effective_decision(
            subject_type=actor_type, subject_id=actor_id, capability=row["capability"],
            asset_id=row["asset_id"], object_id=row["object_id"],
        )
        if not decision.get("allowed") or decision.get("decision") == "forbidden":
            self.db.audit(
                actor_type, actor_id, "action_reject_denied", asset_id=row["asset_id"],
                object_id=row["object_id"], action_id=action_id,
                detail={"reason": decision.get("reason", "forbidden"), "channel": channel},
                incident_id=row.get("incident_id") or "", channel=channel,
            )
            raise ActionError("reject_denied", decision.get("reason", "forbidden"))
        state = row["state"]
        if state in ("cancelled", "expired", "rejected"):
            return {"id": action_id, "state": state, "idempotent": True, "already": True}
        if state != "proposed":
            raise ActionError("bad_state", state)
        t = now()
        decision_id = new_id("dec")
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE actions SET state='cancelled', finished_at=?, result_detail=?,"
                " decision_channel=?, decision_reason=?, decided_at=?, decision_id=?"
                " WHERE id=? AND state='proposed'",
                (
                    t,
                    f"rejected:{reason or 'no reason'}",
                    channel,
                    reason,
                    t,
                    decision_id,
                    action_id,
                ),
            )
            if cur.rowcount != 1:
                fresh = conn.execute(
                    "SELECT state FROM actions WHERE id=?", (action_id,)
                ).fetchone()
                return {
                    "id": action_id,
                    "state": (fresh["state"] if fresh else "unknown"),
                    "idempotent": True,
                    "already": True,
                }
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json, decision_id, incident_id, channel)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    t,
                    actor_type,
                    actor_id,
                    "action_rejected",
                    row["asset_id"],
                    row["object_id"],
                    action_id,
                    json.dumps(
                        {
                            "channel": channel,
                            "reason": reason,
                            "capability": row.get("capability") or "",
                        },
                        ensure_ascii=False,
                    ),
                    decision_id,
                    row.get("incident_id") or "",
                    channel,
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    row["incident_id"] or "",
                    t,
                    "action_rejected",
                    f"rejected {action_id}",
                    json.dumps(
                        {
                            "action_id": action_id,
                            "actor": f"{actor_type}:{actor_id}",
                            "channel": channel,
                            "reason": reason,
                            "decision_id": decision_id,
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
            if row.get("incident_id"):
                from .incidents import IncidentService

                incidents = IncidentService(self.db)
                incidents.clear_awaiting_approval(row["incident_id"], action_id)
                incidents.set_need_human(row["incident_id"], f"action_rejected:{action_id}")
        return {"id": action_id, "state": "cancelled", "idempotent": False, "decision_id": decision_id}

    async def approve_and_execute(
        self,
        action_id: str,
        *,
        actor_type: str = "web_user",
        actor_id: str = "system",
        channel: str = "web",
        reason: str = "",
        is_admin: bool = False,
    ) -> dict[str, Any]:
        """Web / QQ 共用：批准并提交执行。恰好一次 dispatch。"""
        res = self.approve(
            action_id,
            approver_type=actor_type,
            approver_id=actor_id,
            channel=channel,
            reason=reason,
        )
        if res.get("already"):
            return res
        try:
            exec_res = await self.execute(
                action_id,
                actor_type=actor_type,
                actor_id=actor_id,
                is_admin=is_admin,
            )
            return {
                "id": action_id,
                "state": exec_res.get("state"),
                "approved": True,
                "executed": True,
                "detail": exec_res.get("detail", ""),
                "channel": channel,
            }
        except ActionError as e:
            return {
                "id": action_id,
                "state": self._get(action_id).get("state", "approved"),
                "approved": True,
                "executed": False,
                "error": e.code,
                "message": str(e),
                "channel": channel,
            }

    def cancel(
        self,
        action_id: str,
        *,
        actor_type: str = "web_user",
        actor_id: str = "system",
        is_admin: bool = False,
        channel: str = "web",
        reason: str = "",
    ) -> None:
        row = self._get(action_id)
        if row["state"] in ("success", "failure", "unknown", "dispatched"):
            raise ActionError("cannot_cancel", row["state"])
        if row["state"] in ("cancelled", "expired"):
            return
        if not is_admin and not (
            actor_type == row.get("proposer_type") and actor_id == row.get("proposer_id")
        ):
            self.db.audit(
                actor_type,
                actor_id,
                "action_cancel_denied",
                asset_id=row["asset_id"],
                object_id=row["object_id"],
                action_id=action_id,
                detail={"reason": "not_owner", "capability": row.get("capability") or ""},
                incident_id=row.get("incident_id") or "",
                channel=channel,
            )
            raise ActionError("cancel_denied", "not_owner")
        t = now()
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE actions SET state='cancelled', finished_at=?, result_detail=?,"
                " decision_channel=?, decision_reason=?, decided_at=?, decision_id=? WHERE id=?",
                (t, f"cancelled:{reason or ''}", channel, reason, t, new_id("dec"), action_id),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, action_id, asset_id, object_id,"
                " detail_json, incident_id, channel) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    t,
                    actor_type,
                    actor_id,
                    "action_cancelled",
                    action_id,
                    row["asset_id"],
                    row["object_id"],
                    json.dumps(
                        {
                            "channel": channel,
                            "reason": reason,
                            "capability": row.get("capability") or "",
                        },
                        ensure_ascii=False,
                    ),
                    row.get("incident_id") or "",
                    channel,
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    row["incident_id"] or "",
                    t,
                    "action_cancelled",
                    f"cancelled {action_id}",
                    json.dumps(
                        {"action_id": action_id, "reason": reason, "channel": channel},
                        ensure_ascii=False,
                    ),
                ),
            )

    def expire_stale_proposals(self) -> int:
        """TTL / approval_deadline 到期的 proposed/approved → expired。S14: 同步事件 need_human。"""
        t = now()
        rows = self.db.query(
            "SELECT id, incident_id FROM actions WHERE state IN ('proposed','approved')"
            " AND (approval_deadline IS NOT NULL AND ? > approval_deadline"
            "      OR ? - created_at > ?)",
            (t, t, float(self.action_ttl)),
        )
        n = 0
        for r in rows:
            with self.db.tx() as conn:
                cur = conn.execute(
                    "UPDATE actions SET state='expired', finished_at=?,"
                    " result_detail='approval_expired' WHERE id=? AND state IN ('proposed','approved')",
                    (t, r["id"]),
                )
                if cur.rowcount:
                    n += 1
                    conn.execute(
                        "INSERT INTO audit_log(at, actor_type, actor_id, entry, action_id,"
                        " detail_json) VALUES(?,?,?,?,?,?)",
                        (t, "system", "sweeper", "action_expired", r["id"],
                         json.dumps({"reason": "approval_deadline"})),
                    )
                    conn.execute(
                        "INSERT INTO events(incident_id, at, type, title, payload_json)"
                        " VALUES(?,?,?,?,?)",
                        (
                            r["incident_id"] or "",
                            t,
                            "action_expired",
                            f"proposal expired {r['id']}",
                            json.dumps({"action_id": r["id"]}, ensure_ascii=False),
                        ),
                    )
                    # S14: 到期同步事件为需人工
                    if r["incident_id"]:
                        incident = conn.execute(
                            "SELECT status FROM incidents WHERE id=?", (r["incident_id"],)
                        ).fetchone()
                        if incident and incident["status"] == "open":
                            from .incidents import IncidentService

                            IncidentService(self.db).clear_awaiting_approval(r["incident_id"], r["id"])
                            self._mark_need_human(r["incident_id"], f"approval_expired:{r['id']}")
        return n

    def cancel_pending_for_incident(self, incident_id: str, reason: str = "incident_recovered") -> int:
        """故障自然恢复 / 事件关闭后，取消不再必要的过时 proposal。"""
        if not incident_id:
            return 0
        t = now()
        n = 0
        rows = self.db.query(
            "SELECT id FROM actions WHERE incident_id=? AND state IN ('proposed','approved')",
            (incident_id,),
        )
        for r in rows:
            with self.db.tx() as conn:
                cur = conn.execute(
                    "UPDATE actions SET state='cancelled', finished_at=?, result_detail=?"
                    " WHERE id=? AND state IN ('proposed','approved')",
                    (t, f"stale:{reason}", r["id"]),
                )
                if cur.rowcount:
                    n += 1
                    conn.execute(
                        "INSERT INTO audit_log(at, actor_type, actor_id, entry, action_id,"
                        " detail_json) VALUES(?,?,?,?,?,?)",
                        (t, "system", "sweeper", "action_cancelled_stale", r["id"],
                         json.dumps({"reason": reason, "incident_id": incident_id})),
                    )
                    conn.execute(
                        "INSERT INTO events(incident_id, at, type, title, payload_json)"
                        " VALUES(?,?,?,?,?)",
                        (
                            incident_id,
                            t,
                            "action_cancelled",
                            f"stale proposal cancelled {r['id']}",
                            json.dumps(
                                {"action_id": r["id"], "reason": reason},
                                ensure_ascii=False,
                            ),
                        ),
                    )
        return n

    def safe_cancel_pending_auto(self, action_id: str, reason: str = "") -> bool:
        """Retire an unclaimed Agent auto proposal before scheduling a retry.

        A dispatched or uncertain operation must never be converted back into
        a retryable proposal, even when a caller observed an earlier state.
        """
        with self.db.tx() as conn:
            row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            if (not row or row["mode"] != "auto" or row["proposer_type"] != "auto_rule"
                    or row["proposer_id"] != "agent" or row["dispatched_at"] is not None
                    or row["state"] not in ("proposed", "approved", "cancelled")):
                return False
            if row["state"] != "cancelled":
                cur = conn.execute(
                    "UPDATE actions SET state='cancelled',finished_at=?,result_detail=?"
                    " WHERE id=? AND mode='auto' AND proposer_type='auto_rule' AND proposer_id='agent'"
                    " AND state IN ('proposed','approved') AND dispatched_at IS NULL",
                    (now(), f"auto_wait:{reason}", action_id),
                )
                if cur.rowcount != 1:
                    return False
                self.db.audit(
                    "auto_rule", "agent", "action_cancelled_for_retry", action_id=action_id,
                    asset_id=row["asset_id"], object_id=row["object_id"],
                    incident_id=row["incident_id"] or "", channel="system", detail={"reason": reason},
                )
                self.db.event(
                    "action_cancelled", "自动处置暂缓，等待条件恢复", incident_id=row["incident_id"] or "",
                    payload={"action_id": action_id, "reason": reason, "retryable": True},
                )
            if row["incident_id"]:
                from .incidents import IncidentService

                IncidentService(self.db).clear_action_obligation(
                    row["incident_id"], action_id, kind="execution_blocked",
                )
            return True

    # ------------------------------------------------------------------
    # 执行
    # ------------------------------------------------------------------

    async def execute(
        self,
        action_id: str,
        *,
        actor_type: str = "web_user",
        actor_id: str = "system",
        is_admin: bool = False,
    ) -> dict[str, Any]:
        async with self._exec_lock:
            try:
                return await self._execute_locked(
                    action_id, actor_type=actor_type, actor_id=actor_id, is_admin=is_admin
                )
            except ActionError as exc:
                if exc.code == "legacy_autonomy_retired":
                    raise
                row = self._get(action_id)
                retryable_auto = row.get("mode") == "auto" and exc.code in AUTO_RETRYABLE_BLOCKS
                if row["state"] == "approved" and not retryable_auto and not action_incident_block(self.db, row):
                    with self.db.tx():
                        self._mark_need_human(row.get("incident_id") or "", f"execution_blocked:{action_id}")
                        self.db.audit(
                            actor_type, actor_id, "action_execution_blocked", action_id=action_id,
                            asset_id=row["asset_id"], object_id=row["object_id"],
                            incident_id=row.get("incident_id") or "",
                            channel=row.get("decision_channel") or "system",
                            detail={"reason": exc.code, "state": "approved"},
                        )
                raise

    async def _execute_locked(
        self,
        action_id: str,
        *,
        actor_type: str = "web_user",
        actor_id: str = "system",
        is_admin: bool = False,
    ) -> dict[str, Any]:
        row = self._get(action_id)
        # 硬约束：结果不明 / 已派发 / 已终结的写操作不得重放
        if row["state"] == "unknown":
            raise ActionError("no_replay_unknown", action_id)
        if row["state"] in WRITE_NO_REPLAY_STATES:
            raise ActionError("no_replay", row["state"])
        if not write_may_dispatch(row["state"]):
            raise ActionError("bad_state", row["state"])
        blocked = legacy_action_block(row)
        if blocked:
            raise ActionError(*blocked)

        # 记录核验时使用的绑定快照，领取事务里逐项比对
        # SSH 路径：以 host_key 信任为准；NT 路径：保留 alias/host_id 绑定
        ssh_ep = None
        if self.transport is not None and hasattr(self.transport, "_endpoint"):
            try:
                ssh_ep = self.transport._endpoint(row["asset_id"], "write")
            except Exception:
                ssh_ep = None
        if ssh_ep is not None:
            if not ssh_ep.host_key_sha256 or not ssh_ep.host_key_trusted_at:
                raise ActionError("identity_gate", "host_key not trusted")
            snap = {
                "read_alias": "",
                "write_alias": "",
                "expected_host_id": ssh_ep.host_key_sha256,
                "asset_id": ssh_ep.asset_id,
            }
            ident = {
                "ok": True,
                "mode": "exec",
                "account": ssh_ep.username,
                "host_key": ssh_ep.host_key_sha256,
            }
        else:
            binding = self.gate.get(row["asset_id"])
            snap = {
                "read_alias": binding.read_alias,
                "write_alias": binding.write_alias,
                "expected_host_id": binding.expected_host_id,
                "asset_id": binding.asset_id,
            }

            # 身份核验（网络等待）——之后必须在短事务内重查，不得再等网络
            try:
                ident = await self.gate.verify_account(row["asset_id"], write=True)
            except NTError as e:
                raise ActionError("identity_gate", str(e)) from e
        if not ident.get("ok"):
            raise ActionError("identity_gate", ident.get("error") or "verify_account failed")
        if ident.get("mode") != "exec":
            raise ActionError("identity_gate", f"mode={ident.get('mode')}")
        if ssh_ep is None:
            if binding.host_id_verified_at is None or not binding.expected_host_id:
                raise ActionError("identity_gate", "host_id not registered/verified")

        # ---- 短事务：重查授权/期限/对象/占用/资产绑定 + 领取 ----
        dispatcher = ssh_ep.username if ssh_ep is not None else binding.write_alias
        reject: tuple[str, str] | None = None
        tokens: list[str] = []
        with self.db.tx() as conn:
            fresh = conn.execute(
                "SELECT * FROM actions WHERE id=?", (action_id,)
            ).fetchone()
            if not fresh or fresh["state"] != "approved":
                raise ActionError("bad_state", "not_approved")

            blocked = legacy_action_block(fresh)
            if blocked:
                raise ActionError(*blocked)
            reject = action_incident_block(conn, fresh)

            # 资产当前登记 vs 核验时快照
            asset_row = conn.execute(
                "SELECT * FROM assets WHERE id=?", (fresh["asset_id"],)
            ).fetchone()
            if reject is not None:
                pass
            elif not asset_row or not asset_row["enabled"]:
                reject = ("asset_disabled", "asset missing or disabled")
            elif ssh_ep is not None:
                # SSH：host key 信任快照比对
                ep_now = conn.execute(
                    "SELECT * FROM ssh_endpoints WHERE asset_id=? AND role='write'",
                    (fresh["asset_id"],),
                ).fetchone()
                if not ep_now or not ep_now["host_key_trusted_at"]:
                    reject = ("identity_gate", "host_key not trusted")
                elif (ep_now["host_key_sha256"] or "") != (snap.get("expected_host_id") or ""):
                    reject = ("binding_changed", "ssh host key changed during identity wait")
            elif not asset_row["host_id_verified_at"] or not asset_row["expected_host_id"]:
                reject = ("identity_gate", "host_id not registered/verified")
            elif (
                asset_row["read_alias"] != snap["read_alias"]
                or asset_row["write_alias"] != snap["write_alias"]
                or asset_row["expected_host_id"] != snap["expected_host_id"]
            ):
                reject = ("binding_changed", "asset binding changed during identity wait")

            if reject is None and now() - (fresh["approved_at"] or 0) > self.approval_ttl:
                reject = ("approval_expired", "approval_ttl")
            if reject is None and fresh["approval_deadline"] and now() > float(fresh["approval_deadline"]):
                reject = ("approval_expired", "approval_deadline")

            # 唯一派发门：当前 Policy 复查（P0-02）
            # autonomous：退役 Ceiling/三态，不在此复查 Policy；人工仍复查。
            action_mode = (fresh["mode"] or "manual") if "mode" in fresh.keys() else "manual"
            if reject is None and action_mode in ("auto", "reviewed") and fresh["incident_id"]:
                from .incidents import IncidentService

                blocked = IncidentService(self.db).source_block_reason(fresh["incident_id"])
                if blocked:
                    reject = (_source_block_code(blocked), blocked)
            if reject is None and action_mode != "autonomous":
                for subject_type, subject_id in (
                    (fresh["proposer_type"] or "web_user", fresh["proposer_id"] or "system"),
                    (fresh["approver_type"] or "", fresh["approver_id"] or ""),
                ):
                    if not subject_type or not subject_id:
                        continue
                    decision = self.policy.check(
                        subject_type=subject_type,
                        subject_id=subject_id,
                        capability=fresh["capability"],
                        asset_id=fresh["asset_id"],
                        object_id=fresh["object_id"],
                        auto=(action_mode in ("auto", "reviewed")),
                    )
                    if not decision["allowed"]:
                        reject = ("policy_revoked", f"{subject_type}:{subject_id}")
                        break
                    if action_mode in ("auto", "reviewed") and (not decision.get("auto_allowed") or decision.get("decision") != "automatic"):
                        reject = ("auto_revoked", f"{subject_type}:{subject_id}")
                        break

            # runbook / 模板版本未变（先于派发者检查，便于精确拒绝）
            if reject is None:
                rb_id = (fresh["runbook_id"] or "") if "runbook_id" in fresh.keys() else ""
                rb_rev = (fresh["runbook_rev"] or "") if "runbook_rev" in fresh.keys() else ""
                tmpl_id = (fresh["template_id"] or "") if "template_id" in fresh.keys() else ""
                from .runbook import get_manual_template, get_runbook_rule

                if rb_id:
                    rule = get_runbook_rule(rb_id)
                    if not rule:
                        reject = ("runbook_missing", rb_id)
                    elif rb_rev and rule.rev != rb_rev:
                        reject = ("runbook_changed", f"{rb_id} rev {rb_rev}->{rule.rev}")
                elif tmpl_id:
                    tmpl = get_manual_template(tmpl_id)
                    if not tmpl:
                        reject = ("template_missing", tmpl_id)
                elif action_mode not in ("reviewed", "autonomous"):
                    reject = ("template_required", "no runbook/template on action")

            # 实际派发人必须具备该能力（非管理员）；autonomous 跳过
            if reject is None and not is_admin and action_mode != "autonomous":
                d = self.policy.check(
                    subject_type=actor_type,
                    subject_id=actor_id,
                    capability=fresh["capability"],
                    asset_id=fresh["asset_id"],
                    object_id=fresh["object_id"],
                    auto=(action_mode in ("auto", "reviewed")),
                )
                if not d["allowed"] or (action_mode in ("auto", "reviewed") and not d.get("auto_allowed")):
                    reject = ("dispatcher_denied", f"{actor_type}:{actor_id}")

            # 全局暂停（P0-03）
            if reject is None:
                stop = conn.execute(
                    "SELECT enabled FROM global_stops WHERE key='auto_dispatch'"
                ).fetchone()
                if stop and stop["enabled"] and action_mode in ("auto", "reviewed"):
                    reject = ("global_pause", "auto_dispatch paused")

            if reject is None:
                obj = conn.execute(
                    "SELECT * FROM objects WHERE asset_id=? AND (id=? OR name=?)",
                    (fresh["asset_id"], fresh["object_id"], fresh["object_id"]),
                ).fetchone()
                if not obj:
                    reject = ("object_missing", fresh["object_id"])
                else:
                    obj_d = dict(obj)
                    if action_mode in ("auto", "reviewed"):
                        from .runbook import CONTROL_PLANE_MARKERS
                        from .verify_profiles import profile_for_action

                        names = " ".join(str(obj_d.get(k) or "") for k in ("id", "name", "unit", "container"))
                        if any(marker in names.lower() for marker in CONTROL_PLANE_MARKERS):
                            reject = ("control_plane_forbidden", "控制面对象不能自动执行")
                        elif profile_for_action(
                            capability=fresh["capability"], asset_id=fresh["asset_id"],
                            object_id=resolve_object_name(obj_d),
                        ) is None:
                            reject = ("unsupported_verification_profile", "no verification contract")
                    try:
                        object_matches_capability(fresh["capability"], obj_d)
                        tokens = build_write_tokens(fresh["capability"], obj_d)
                    except Exception as e:
                        reject = ("object_binding", str(e))
                    else:
                        payload = json.loads(fresh["params_json"] or "{}")
                        declared = payload.get("tokens") or []
                        if declared and declared != tokens:
                            reject = ("token_mismatch", "declared tokens diverge")

            if reject is None:
                if self._object_locked(
                    fresh["asset_id"], fresh["object_id"], exclude=action_id,
                ):
                    reject = ("object_locked", fresh["object_id"])

            # 预算：派发前原子占用（P0-03）；unknown 也计数
            if reject is None and action_mode in ("auto", "reviewed"):
                rb_id_b = (fresh["runbook_id"] or "") if "runbook_id" in fresh.keys() else ""
                from .runbook import RunbookRule, auto_budget_state, get_runbook_rule

                rule = get_runbook_rule(rb_id_b) if rb_id_b else None
                rules = [rule or RunbookRule(id="", name="")]
                for operation_rule in rules:
                    budget = auto_budget_state(
                        conn, operation_rule,
                        fresh["asset_id"], fresh["object_id"], at=now(), exclude_action_id=action_id,
                    )
                    if not budget["ok"]:
                        reject = (budget["code"], budget["reason"])
                        break

            if reject is not None:
                code, detail = reject
                fresh_d = dict(fresh)
                _dec = fresh_d.get("decision_id") or ""
                _aud = (
                    now(),
                    actor_type,
                    actor_id,
                    "action_dispatch_denied",
                    fresh_d["asset_id"],
                    fresh_d["object_id"],
                    action_id,
                    json.dumps(
                        {
                            "code": code,
                            "detail": detail,
                            "capability": fresh_d.get("capability") or "",
                            "tokens": tokens,
                        },
                        ensure_ascii=False,
                    ),
                    _dec,
                    fresh_d.get("incident_id") or "",
                    "system",
                )
                # 客观原因终止提案；调用者无权仅拒绝本次请求
                if code in ("dispatcher_denied",):
                    conn.execute(
                        "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                        " action_id, detail_json, decision_id, incident_id, channel)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        _aud,
                    )
                else:
                    conn.execute(
                        "UPDATE actions SET state='cancelled', result_detail=?, finished_at=?"
                        " WHERE id=? AND state='approved'",
                        (f"{code}:{detail}", now(), action_id),
                    )
                    conn.execute(
                        "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                        " action_id, detail_json, decision_id, incident_id, channel)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        _aud,
                    )
                if code in ("source_quarantined", "unsupported_verification_profile"):
                    self._mark_need_human(fresh_d.get("incident_id") or "", f"{code}:{action_id}")
            else:
                cur = conn.execute(
                    "UPDATE actions SET state='dispatched', dispatched_at=?, exec_account=?,"
                    " budget_claimed_at=? WHERE id=? AND state='approved'",
                    (now(), dispatcher, now(), action_id),
                )
                if cur.rowcount != 1:
                    reject = ("claim_failed", "")
                else:
                    if fresh["incident_id"]:
                        from .incidents import IncidentService

                        IncidentService(self.db).clear_action_obligation(
                            fresh["incident_id"], action_id, kind="execution_blocked",
                        )
                    conn.execute(
                        "INSERT INTO jobs(kind, payload_json, state, due_at, created_at, updated_at)"
                        " VALUES(?,?,?,?,?,?)",
                        (
                            "exec_intent",
                            json.dumps(
                                {
                                    "action_id": action_id,
                                    "dispatcher": dispatcher,
                                    "actor": f"{actor_type}:{actor_id}",
                                },
                                ensure_ascii=False,
                            ),
                            "done",
                            now(),
                            now(),
                            now(),
                        ),
                    )
        if reject is not None:
            code, detail = reject
            raise ActionError(code, detail)

        if row.get("incident_id"):
            from .incidents import IncidentService
            IncidentService(self.db).reconcile(row["incident_id"], resolution_basis="action_dispatched")

        # 网络：真正执行。S14: Transport 异常须收敛，不能卡在 dispatched
        wo_key = ""
        wo_incident = row.get("incident_id") or "_action_"
        if self.write_ops is not None:
            try:
                wo_key = self.write_ops.make_action_key(
                    row["asset_id"],
                    "action_dispatch",
                    {
                        "action_id": action_id,
                        "tokens": list(tokens or []),
                        "object_id": row.get("object_id") or "",
                    },
                    context="actions.execute",
                )
                claim = self.write_ops.claim_write(
                    wo_incident,
                    wo_key,
                    target=row["asset_id"],
                    params={"action_id": action_id, "tokens": list(tokens or [])[:20]},
                    claimed_by=f"{actor_type}:{actor_id}",
                )
                if not claim.get("claimed"):
                    raise ActionError("no_replay", f"write_ops:{claim.get('status')}")
            except ActionError:
                raise
            except Exception:
                wo_key = ""
        try:
            res = await self._write_channel(row["asset_id"], tokens, timeout=15.0)
            state, detail = classify_exec_result(res)
        except Exception as e:
            # 不能证明是否执行：收敛为 unknown + 需人工，保留对象锁防止重放。
            log.exception("action write_channel failed")
            state, detail = "unknown", f"exec_exception:{str(e)[:120]}"
            res = None
        if self.write_ops is not None and wo_key:
            try:
                if state == "unknown":
                    self.write_ops.mark_unknown(wo_incident, wo_key, reason=detail or "unknown")
                else:
                    self.write_ops.complete_write(
                        wo_incident, wo_key, ok=(state == "success"), result=(detail or "")[:500]
                    )
            except Exception:
                pass

        # ---- 同事务提交：结果 + 审计 + 验证义务/人工 + 事件 ----
        finished_at = now()
        vid = ""
        if state == "success":
            vid = new_id("ver")
        decision_id = (row.get("decision_id") or "") if isinstance(row, dict) else ""
        payload_now = {}
        try:
            payload_now = json.loads(row.get("params_json") or "{}") if isinstance(row, dict) else {}
        except Exception:
            payload_now = {}
        exec_tokens = list(tokens or payload_now.get("tokens") or [])
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE actions SET state=?, finished_at=?, result_detail=? WHERE id=?",
                (state, finished_at, detail, action_id),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json, decision_id, incident_id, channel)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    finished_at,
                    actor_type,
                    actor_id,
                    f"action_{state}",
                    row["asset_id"],
                    row["object_id"],
                    action_id,
                    json.dumps(
                        {
                            "returncode": res.returncode if res else -1,
                            "timed_out": res.timed_out if res else False,
                            "nt_account": dispatcher,
                            "actor": f"{actor_type}:{actor_id}",
                            "capability": row.get("capability") or "",
                            "tokens": exec_tokens,
                            "params_digest": row.get("params_digest") or "",
                            "result_detail": detail[:500],
                        },
                        ensure_ascii=False,
                    ),
                    decision_id or "",
                    row.get("incident_id") or "",
                    "system",
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    row["incident_id"],
                    finished_at,
                    f"action_{state}",
                    f"exec {state} {action_id}",
                    json.dumps({"action_id": action_id, "detail": detail[:500]}, ensure_ascii=False),
                ),
            )
            if state == "success":
                obj_row = conn.execute(
                    "SELECT * FROM objects WHERE asset_id=? AND (id=? OR name=?)",
                    (row["asset_id"], row["object_id"], row["object_id"]),
                ).fetchone()
                service = resolve_object_name(dict(obj_row)) if obj_row else ""
                from .verify_profiles import profile_for_action

                _prof = profile_for_action(
                    capability=row["capability"],
                    asset_id=row["asset_id"],
                    object_id=service,
                )
                profile_id_guess = _prof.id if _prof else ""
                _incg = conn.execute(
                    "SELECT generation FROM incidents WHERE id=?", (row["incident_id"],)
                ).fetchone() if row["incident_id"] else None
                gen_guess = int(_incg["generation"] if _incg else 1) or 1
                criteria = {
                    "window_sec": self.verify_window,
                    "timeout_sec": self.verify_timeout,
                    "require": [
                        "action_success",
                        "exact_series",
                        "fresh_raw_samples",
                        "stability",
                    ],
                    "asset_id": row["asset_id"],
                    "service": service,
                    "object_id": row["object_id"],
                    "incident_id": row["incident_id"],
                    "baseline_finished_at": finished_at,
                    "profile_id": profile_id_guess,
                }
                conn.execute(
                    "INSERT INTO verifications(id, action_id, incident_id, status,"
                    " criteria_json, started_at, profile_id, generation, deadline_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        vid,
                        action_id,
                        row["incident_id"],
                        "pending",
                        json.dumps(criteria, ensure_ascii=False),
                        finished_at,
                        profile_id_guess,
                        gen_guess,
                        finished_at + 180.0,
                    ),
                )
            elif state == "unknown":
                self._mark_need_human(row["incident_id"], f"exec_unknown:{action_id}")
            elif state == "failure":
                # 失败终态：尝试收敛仍被 hold 的 Incident
                pass

        # 终态后重新评估 hold
        if state in ("failure", "success", "unknown") and row.get("incident_id"):
            try:
                from .incidents import IncidentService

                IncidentService(self.db).reevaluate_after_action(row["incident_id"])
            except Exception:
                pass

        if state == "success" and vid:
            try:
                asyncio.create_task(self._run_verification(vid, action_id))
            except RuntimeError:
                await self._run_verification(vid, action_id)
        return {"id": action_id, "state": state, "detail": detail}

    # ------------------------------------------------------------------
    # 验证
    # ------------------------------------------------------------------

    async def verify(self, action_id: str) -> dict[str, Any]:
        row = self._get(action_id)
        if row["state"] != "success":
            raise ActionError("verify_requires_success", row["state"])
        existing = self.db.query_one(
            "SELECT id FROM verifications WHERE action_id=? AND status='pending'"
            " ORDER BY started_at DESC LIMIT 1",
            (action_id,),
        )
        if existing:
            return await self._run_verification(existing["id"], action_id)
        # 补建义务（也在短事务）
        vid = new_id("ver")
        service = self._registered_service_label(row)
        from .verify_profiles import profile_for_action

        _prof = profile_for_action(
            capability=row["capability"], asset_id=row["asset_id"],
            object_id=service,
        )
        criteria = {
            "window_sec": self.verify_window,
            "timeout_sec": self.verify_timeout,
            "require": ["action_success", "exact_series", "fresh_raw_samples", "stability"],
            "asset_id": row["asset_id"],
            "service": service,
            "object_id": row["object_id"],
            "incident_id": row["incident_id"],
            "baseline_finished_at": row.get("finished_at") or now(),
            "profile_id": _prof.id if _prof else "",
        }
        # 补验证沿用动作所属代次，不能硬编码 1，也不能借用当前新故障的代次。
        prior_verification = self.db.query_one(
            "SELECT generation FROM verifications WHERE action_id=? AND generation IS NOT NULL"
            " ORDER BY started_at DESC LIMIT 1", (action_id,),
        )
        action_generation = int(prior_verification["generation"] or 1) if prior_verification else 1
        if not prior_verification and row.get("incident_id"):
            generation_event = self.db.query_one(
                "SELECT type,payload_json FROM events WHERE incident_id=? AND at<=? AND type IN"
                " ('incident_opened','incident_reopened','generation_bumped') ORDER BY id DESC LIMIT 1",
                (row["incident_id"], row["created_at"]),
            )
            if generation_event:
                generation_payload = json.loads(generation_event["payload_json"] or "{}")
                action_generation = int(generation_payload.get("generation") or 1)
        self.db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, criteria_json,"
            " started_at, profile_id, generation) VALUES(?,?,?,?,?,?,?,?)",
            (
                vid,
                action_id,
                row["incident_id"],
                "pending",
                json.dumps(criteria, ensure_ascii=False),
                now(),
                _prof.id if _prof else "",
                action_generation,
            ),
        )
        return await self._run_verification(vid, action_id)

    async def _run_verification(self, vid: str, action_id: str) -> dict[str, Any]:
        row = self._get(action_id)
        if row["state"] != "success":
            self._finish_verification(vid, "failed", {}, "action_not_success")
            return {"id": vid, "status": "failed", "note": "action_not_success"}

        vrow = self.db.query_one("SELECT * FROM verifications WHERE id=?", (vid,))
        crit = json.loads(vrow["criteria_json"] or "{}") if vrow else {}
        baseline = float(crit.get("baseline_finished_at") or row.get("finished_at") or now())
        asset = crit.get("asset_id") or row["asset_id"]
        service = crit.get("service") or ""
        from .verify_profiles import get_profile, profile_for_action

        profile_id = (vrow["profile_id"] if vrow else "") or crit.get("profile_id") or ""
        profile = get_profile(profile_id) if profile_id else None
        if profile is None:
            profile = profile_for_action(
                capability=row["capability"], asset_id=asset,
                object_id=self._registered_service_label(row),
            )
        if profile is None:
            # unsupported：不得退回通用 probe_success 猜测
            with self.db.tx():
                self._finish_verification(vid, "unknown", {}, "unsupported_verification_profile")
                if row.get("incident_id"):
                    from .incidents import IncidentService
                    IncidentService(self.db).on_verification_finished(
                        row["incident_id"], action_id, vid,
                        int((vrow["generation"] if vrow else 1) or 1), "unknown",
                        reason=f"unsupported_verification_profile:{action_id}",
                    )
            return {"id": vid, "status": "unknown", "note": "unsupported_verification_profile"}

        # 固定 deadline：不因重试重新开始
        deadline_at = float(vrow["deadline_at"] or 0) if vrow else 0.0
        if not deadline_at:
            deadline_at = baseline + float(profile.deadline_sec)
            self.db.execute(
                "UPDATE verifications SET deadline_at=?, profile_id=? WHERE id=?",
                (deadline_at, profile.id, vid),
            )
        # 测试/配置可用 verify_timeout 提前截止（不小于 1s）
        if self.verify_timeout and self.verify_timeout < (deadline_at - now()):
            deadline_at = now() + max(1.0, float(self.verify_timeout))
            self.db.execute(
                "UPDATE verifications SET deadline_at=? WHERE id=?", (deadline_at, vid)
            )
        gen = int((vrow["generation"] if vrow else 1) or 1)

        by_series: dict[str, dict[float, dict]] = {}
        note = ""
        status = "inconclusive"
        warmup_end = baseline + float(profile.warmup_sec)
        need_span = float(profile.continuous_success_sec)
        max_gap = float(profile.max_sample_gap_sec)
        success_val = 1 if profile.expect == "up" else 0

        while time.time() < deadline_at:
            try:
                check = (profile.checks or [{}])[0]
                samples = await self.prom.probe_success_since(
                    asset,
                    service,
                    start=baseline,
                    end=deadline_at,
                    window_sec=min(600.0, max(120.0, deadline_at - baseline + 60.0)),
                )
                matched = match_series(samples, asset=asset, service=service)
                groups = group_by_series(matched)
                if len(groups) > 1:
                    status = "inconclusive"
                    note = f"ambiguous series: {len(groups)}"
                    break
                for key, arr in groups.items():
                    bucket = by_series.setdefault(key, {})
                    for s in arr:
                        ts = s.get("sample_at")
                        if ts is None:
                            continue
                        bucket[round(float(ts), 3)] = s

                if not by_series:
                    await asyncio.sleep(min(15, max(5, need_span // 4)))
                    continue

                key = next(iter(by_series))
                timeline = sorted(by_series[key].values(), key=lambda s: s["sample_at"])
                # warmup 后：连续成功窗口；失败样本重置
                post = [s for s in timeline if s["sample_at"] >= warmup_end]
                if not post:
                    await asyncio.sleep(min(15, max(5, need_span // 4)))
                    continue
                # 业务明确失败（期望 up 但看到 0）
                if any(s.get("value") != success_val for s in post):
                    # 若仍有后续连续成功可继续；否则等
                    fail_ts = max(s["sample_at"] for s in post if s.get("value") != success_val)
                    post = [s for s in post if s["sample_at"] > fail_ts]
                if len(post) >= 2:
                    # 连续成功跨度
                    span = post[-1]["sample_at"] - post[0]["sample_at"]
                    gaps_ok = all(
                        post[i]["sample_at"] - post[i - 1]["sample_at"] <= max_gap
                        for i in range(1, len(post))
                    )
                    all_ok = all(s.get("value") == success_val for s in post)
                    latest_age = time.time() - post[-1]["sample_at"]
                    if all_ok and span >= need_span and gaps_ok and latest_age <= max_gap:
                        status = "passed"
                        note = (
                            f"profile={profile.id} continuous_ok span={span:.1f}s>={need_span:.0f}s "
                            f"n={len(post)} gap<={max_gap:.0f}s age={latest_age:.1f}s"
                        )
                        break
            except Exception as e:
                note = f"prom error: {e}"
            await asyncio.sleep(min(15, max(5, need_span // 4)))
        else:
            all_samples = [s for b in by_series.values() for s in b.values()]
            if not all_samples:
                status = "unknown"
                note = "no samples / source unavailable"
            else:
                post = [s for s in all_samples if s.get("sample_at", 0) >= warmup_end]
                if any(s.get("value") != success_val for s in post) and post:
                    status = "failed"
                    note = "business failure observed"
                else:
                    status = "inconclusive"
                    note = f"deadline hit; stability not reached need={need_span}s"

        all_samples = sorted(
            [s for b in by_series.values() for s in b.values()],
            key=lambda s: s.get("sample_at") or 0,
        )
        evidence = {
            "baseline": baseline,
            "asset": asset,
            "service": service,
            "profile_id": profile.id,
            "warmup_sec": profile.warmup_sec,
            "need_span": need_span,
            "max_gap": max_gap,
            "deadline_at": deadline_at,
            "samples": all_samples[-40:],
            "series_keys": list(by_series.keys()),
            "action_id": action_id,
            "generation": gen,
        }

        with self.db.tx() as conn:
            vchk = conn.execute(
                "SELECT action_id, incident_id, status FROM verifications WHERE id=?", (vid,)
            ).fetchone()
            if not vchk or vchk["action_id"] != action_id or vchk["status"] != "pending":
                return {"id": vid, "status": "skipped", "note": "verification superseded"}
            a_now = conn.execute(
                "SELECT asset_id, object_id, incident_id, state FROM actions WHERE id=?",
                (action_id,),
            ).fetchone()
            if not a_now or a_now["state"] != "success":
                self._finish_verification(vid, "failed", evidence, "action_not_success")
                return {"id": vid, "status": "failed", "note": "action_not_success"}
            conn.execute(
                "UPDATE verifications SET status=?, evidence_json=?, note=?, finished_at=?,"
                " profile_id=?, generation=?, deadline_at=? WHERE id=?",
                (
                    status,
                    json.dumps(evidence, ensure_ascii=False, default=str),
                    note,
                    now(),
                    profile.id,
                    gen,
                    deadline_at,
                    vid,
                ),
            )
            inc_id = a_now["incident_id"]
            if inc_id:
                from .incidents import IncidentService

                IncidentService(self.db).on_verification_finished(
                    inc_id, action_id, vid, gen, status,
                )
        return {"id": vid, "status": status, "note": note, "profile": profile.id}
    def _finish_verification(self, vid: str, status: str, evidence: Any, note: str) -> None:
        self.db.execute(
            "UPDATE verifications SET status=?, evidence_json=?, note=?, finished_at=? WHERE id=?",
            (
                status,
                json.dumps(evidence, ensure_ascii=False, default=str),
                note,
                now(),
                vid,
            ),
        )

    def _mark_need_human(self, incident_id: str, reason: str) -> None:
        if not incident_id:
            return
        from .incidents import IncidentService

        service = IncidentService(self.db)
        service.set_need_human(incident_id, reason)
        self.db.execute(
            "UPDATE incidents SET stage='need_human', updated_at=? WHERE id=?",
            (now(), incident_id),
        )

    def resume_pending_verifications(self) -> int:
        """启动恢复：分批调度所有 pending 验证（游标遍历）。

        在无运行中事件循环的同步上下文里，记录待调度数量并保持 pending，
        由后续后台任务或下次启动处理。
        """
        total = 0
        cursor = ""
        seen: set[str] = set()
        while total < 200:
            if cursor:
                rows = self.db.query(
                    "SELECT id, action_id FROM verifications WHERE status='pending' AND id>?"
                    " ORDER BY id ASC LIMIT 50",
                    (cursor,),
                )
            else:
                rows = self.db.query(
                    "SELECT id, action_id FROM verifications WHERE status='pending'"
                    " ORDER BY id ASC LIMIT 50"
                )
            if not rows:
                break
            for r in rows:
                if r["id"] in seen:
                    continue
                seen.add(r["id"])
                cursor = r["id"]
                total += 1
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self._run_verification(r["id"], r["action_id"]))
                except RuntimeError:
                    # 同步上下文：计数但不调度，保持 pending
                    pass
                if total >= 200:
                    break
        return total

    def backfill_missing_verifications(self) -> int:
        """启动补查：success 但无任何 verification 的操作（分批）。"""
        total = 0
        while True:
            rows = self.db.query(
                "SELECT a.* FROM actions a WHERE a.state='success'"
                " AND NOT EXISTS (SELECT 1 FROM verifications v WHERE v.action_id=a.id)"
                " LIMIT 50"
            )
            if not rows:
                break
            for row in rows:
                row_d = dict(row)
                vid = new_id("ver")
                service = self._registered_service_label(row_d)
                criteria = {
                    "window_sec": self.verify_window,
                    "timeout_sec": self.verify_timeout,
                    "require": ["action_success", "exact_series", "fresh_raw_samples", "stability"],
                    "asset_id": row_d["asset_id"],
                    "service": service,
                    "object_id": row_d["object_id"],
                    "incident_id": row_d["incident_id"],
                    "baseline_finished_at": row_d.get("finished_at") or now(),
                }
                self.db.execute(
                    "INSERT INTO verifications(id, action_id, incident_id, status, criteria_json,"
                    " started_at) VALUES(?,?,?,?,?,?)",
                    (
                        vid,
                        row_d["id"],
                        row_d["incident_id"],
                        "pending",
                        json.dumps(criteria, ensure_ascii=False),
                        now(),
                    ),
                )
                total += 1
            if total >= 200:
                break
        return total

    def mark_unknown_unfinished(self) -> int:
        """重启恢复：dispatched 无确定结果 → unknown；绝不自动重放写。"""
        n = self.db.execute(
            "UPDATE actions SET state='unknown', result_detail='restart_recovery'"
            " WHERE state='dispatched'"
        ).rowcount
        for r in self.db.query(
            "SELECT id, incident_id FROM actions WHERE state='unknown'"
            " AND (adjudication IS NULL OR adjudication='')"
        ):
            self._mark_need_human(r["incident_id"], f"exec_unknown:{r['id']}")
        return int(n or 0)

    def restart_semantics(self) -> dict[str, Any]:
        """重启后各状态语义摘要（供 /ready 与测试）。"""
        rows = self.db.query("SELECT state, COUNT(*) AS n FROM actions GROUP BY state")
        counts = {r["state"]: int(r["n"]) for r in rows}
        return {
            "proposed_safe_to_wait": counts.get("proposed", 0),
            "approved_need_recheck": counts.get("approved", 0),
            "dispatched_to_unknown": counts.get("dispatched", 0),
            "unknown_need_adjudication": counts.get("unknown", 0),
            "terminal_no_replay": (
                counts.get("success", 0)
                + counts.get("failure", 0)
                + counts.get("cancelled", 0)
                + counts.get("expired", 0)
            ),
            "counts": counts,
        }

    def adjudicate(
        self,
        action_id: str,
        *,
        outcome: str,
        reason: str = "",
        actor_type: str = "web_user",
        actor_id: str = "system",
        channel: str = "web",
        evidence_note: str = "",
    ) -> dict[str, Any]:
        """人工核清 uncertain write。

        outcome: executed | not_executed | still_unknown
        不伪造原始执行结果；核清进入 audit + timeline。
        """
        if outcome not in ("executed", "not_executed", "still_unknown"):
            raise ActionError("bad_adjudication", outcome)
        row = self._get(action_id)
        if row["state"] != "unknown":
            raise ActionError("bad_state", row["state"])
        t = now()
        # still_unknown：保持锁，不结束占用
        if outcome == "still_unknown":
            with self.db.tx() as conn:
                conn.execute(
                    "UPDATE actions SET adjudication='still_unknown', adjudicated_at=?,"
                    " adjudication_reason=? WHERE id=?",
                    (t, reason or "still_unknown", action_id),
                )
                conn.execute(
                    "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                    " action_id, detail_json, incident_id, channel) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        t, actor_type, actor_id, "action_adjudicated",
                        row["asset_id"], row["object_id"], action_id,
                        json.dumps(
                            {
                                "outcome": "still_unknown",
                                "reason": reason,
                                "evidence_note": evidence_note[:500],
                                "note": "lock retained",
                            },
                            ensure_ascii=False,
                        ),
                        row.get("incident_id") or "",
                        channel,
                    ),
                )
                conn.execute(
                    "INSERT INTO events(incident_id, at, type, title, payload_json)"
                    " VALUES(?,?,?,?,?)",
                    (
                        row.get("incident_id") or "",
                        t,
                        "action_adjudicated",
                        f"adjudicated still_unknown {action_id}",
                        json.dumps(
                            {"action_id": action_id, "outcome": "still_unknown", "reason": reason},
                            ensure_ascii=False,
                        ),
                    ),
                )
            return {"id": action_id, "state": "unknown", "adjudication": "still_unknown"}

        # executed / not_executed：结束 unknown 占用，但不改写原始 result_detail
        # S15: executed 核清 ≠ 业务成功；须先建验证义务再释放
        release_state = "success" if outcome == "executed" else "cancelled"
        vid = new_id("ver") if outcome == "executed" else ""
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE actions SET adjudication=?, adjudicated_at=?, adjudication_reason=?,"
                " state=?, finished_at=COALESCE(finished_at, ?)"
                " WHERE id=? AND state='unknown'",
                (outcome, t, reason or outcome, release_state, t, action_id),
            )
            # S15: executed 核清时建立验证义务，不直接当 success 释放
            if vid and outcome == "executed":
                criteria = {
                    "checks": ["service_status", "stability"],
                    "asset_id": row["asset_id"],
                    "object_id": row["object_id"],
                    "incident_id": row.get("incident_id") or "",
                    "baseline_finished_at": t,
                    "source": "adjudicated_unknown",
                }
                conn.execute(
                    "INSERT INTO verifications(id, action_id, incident_id, status,"
                    " criteria_json, started_at, profile_id, generation, deadline_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (vid, action_id, row.get("incident_id") or "", "pending",
                     json.dumps(criteria, ensure_ascii=False), t, "", 0, t + 180.0),
                )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json, incident_id, channel) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    t, actor_type, actor_id, "action_adjudicated",
                    row["asset_id"], row["object_id"], action_id,
                    json.dumps(
                        {
                            "outcome": outcome,
                            "reason": reason,
                            "evidence_note": evidence_note[:500],
                            "released_to": release_state,
                            "original_result_detail": (row.get("result_detail") or "")[:200],
                        },
                        ensure_ascii=False,
                    ),
                    row.get("incident_id") or "",
                    channel,
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json)"
                " VALUES(?,?,?,?,?)",
                (
                    row.get("incident_id") or "",
                    t,
                    "action_adjudicated",
                    f"adjudicated {outcome} {action_id}",
                    json.dumps(
                        {
                            "action_id": action_id,
                            "outcome": outcome,
                            "reason": reason,
                            "released_to": release_state,
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        if row.get("incident_id"):
            try:
                from .incidents import IncidentService

                IncidentService(self.db).reevaluate_after_action(row["incident_id"])
            except Exception:
                pass
        return {
            "id": action_id,
            "state": release_state,
            "adjudication": outcome,
        }

    def _object_locked(self, asset_id: str, object_id: str, exclude: str = "", *, council_grant_id: str = "") -> bool:
        if council_grant_id:
            raise ActionError("legacy_autonomy_retired")
        from .incidents import IncidentService
        return IncidentService(self.db).object_actions_locked(
            asset_id, object_id, exclude=exclude
        )

    def _registered_service_label(self, row: dict) -> str:
        obj = self._object(row["asset_id"], row["object_id"])
        return resolve_object_name(obj) if obj else ""

    def list_actions(
        self, state: str = "", limit: int = 50, manual_only: bool = False
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM actions"
        args: list[Any] = []
        where = []
        if state:
            where.append("state=?")
            args.append(state)
        if manual_only:
            where.append("(incident_id IS NULL OR incident_id='')")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        rows = self.db.query(sql, tuple(args))
        return [dict(r) for r in rows]

    def get_action(self, action_id: str) -> dict[str, Any] | None:
        row = self.db.query_one("SELECT * FROM actions WHERE id=?", (action_id,))
        if not row:
            return None
        data = dict(row)
        data["verifications"] = [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM verifications WHERE action_id=? ORDER BY started_at DESC",
                (action_id,),
            )
        ]
        return data

    def _get(self, action_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM actions WHERE id=?", (action_id,))
        if not row:
            raise ActionError("not_found")
        return dict(row)

    def _object(self, asset_id: str, object_id: str) -> dict | None:
        row = self.db.query_one(
            "SELECT * FROM objects WHERE asset_id=? AND (id=? OR name=?)",
            (asset_id, object_id, object_id),
        )
        return dict(row) if row else None


def classify_exec_result(res) -> tuple[str, str]:
    detail = (res.output or "")[:2000]
    if getattr(res, "timed_out", False):
        return "unknown", "timeout"
    rc = getattr(res, "returncode", -1)
    low = detail.lower()
    # 负退出码 = 本地被信号终止，不能证明远端未执行
    if rc is not None and rc < 0:
        return "unknown", detail or f"returncode={rc}"
    if rc == 255 or any(h in low for h in UNKNOWN_HINTS):
        return "unknown", detail or f"returncode={rc}"
    if getattr(res, "ok", False):
        return "success", detail
    if "denied" in low or "not-allowlisted" in low or "blocked" in low or "rejected" in low:
        return "failure", detail
    if rc is not None and rc != 0:
        return "failure", detail
    return "unknown", detail or f"returncode={rc}"
