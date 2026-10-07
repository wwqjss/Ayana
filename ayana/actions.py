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


class ActionService:
    def __init__(
        self,
        db: Database,
        nt: NTClient,
        gate: IdentityGate,
        policy: Policy,
        prom: PromClient,
        *,
        action_ttl: int = 1800,
        approval_ttl: int = 900,
        verify_window: int = 90,
        verify_timeout: int = 300,
    ):
        self.db = db
        self.nt = nt
        self.gate = gate
        self.policy = policy
        self.prom = prom
        self.action_ttl = action_ttl
        self.approval_ttl = approval_ttl
        self.verify_window = verify_window
        self.verify_timeout = verify_timeout
        self._exec_lock = asyncio.Lock()

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
    ) -> dict[str, Any]:
        cap = get_capability(capability)
        if cap.kind != "write":
            raise ActionError("not_a_write_capability")
        if mode not in ("manual", "auto"):
            raise ActionError("bad_mode", mode)
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
        decision = self.policy.effective_decision(
            subject_type=proposer_type,
            subject_id=proposer_id,
            capability=capability,
            asset_id=asset_id,
            object_id=obj["id"],
            auto=(mode == "auto"),
        )
        if decision.get("decision") == "forbidden" or not decision["allowed"]:
            if mode == "auto" and decision.get("reason") == "auto_not_allowed":
                raise ActionError("auto_not_allowed", decision.get("reason", ""))
            raise ActionError("denied", decision.get("reason") or "forbidden")
        if mode == "auto" and decision.get("decision") != "automatic":
            raise ActionError("auto_not_allowed", decision.get("reason", ""))

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
                " action_id, detail_json) VALUES(?,?,?,?,?,?,?,?)",
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
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        return {
            "id": aid,
            "state": "proposed",
            "tokens": tokens,
            "mode": mode,
            "runbook_id": runbook_id,
            "runbook_rev": runbook_rev,
            "template_id": template_id,
            "require_approval": decision.get("require_approval", True),
            "decision": decision.get("decision", "approval_required"),
            "effective_decision": decision,
        }

    def _assert_incident_matches(self, incident_id: str, asset_id: str, obj: dict) -> None:
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not inc:
            raise ActionError("incident_not_found", incident_id)
        if inc["asset_id"] and inc["asset_id"] != asset_id:
            raise ActionError(
                "incident_mismatch",
                f"incident asset={inc['asset_id']} action asset={asset_id}",
            )
        inc_obj = (inc["object_id"] or "").strip()
        action_obj = (obj.get("name") or "").strip()
        if inc_obj and action_obj and inc_obj != action_obj:
            raise ActionError(
                "incident_mismatch",
                f"incident object={inc_obj} action object={action_obj}",
            )

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
                },
            )
            raise ActionError("approve_denied", decision.get("reason", "forbidden"))

        t = now()
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE actions SET state='approved', approver_type=?, approver_id=?,"
                " approved_at=?, decision_channel=?, decision_reason=?, decided_at=?,"
                " decision_snapshot_json=?"
                " WHERE id=? AND state='proposed'",
                (
                    approver_type,
                    approver_id,
                    t,
                    channel,
                    reason,
                    t,
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
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json) VALUES(?,?,?,?,?,?,?,?)",
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
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        return {"id": action_id, "state": "approved", "idempotent": False, "decision": decision.get("decision")}

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
        state = row["state"]
        if state in ("cancelled", "expired", "rejected"):
            return {"id": action_id, "state": state, "idempotent": True, "already": True}
        if state != "proposed":
            raise ActionError("bad_state", state)
        t = now()
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE actions SET state='cancelled', finished_at=?, result_detail=?,"
                " decision_channel=?, decision_reason=?, decided_at=?"
                " WHERE id=? AND state='proposed'",
                (
                    t,
                    f"rejected:{reason or 'no reason'}",
                    channel,
                    reason,
                    t,
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
                " action_id, detail_json) VALUES(?,?,?,?,?,?,?,?)",
                (
                    t,
                    actor_type,
                    actor_id,
                    "action_rejected",
                    row["asset_id"],
                    row["object_id"],
                    action_id,
                    json.dumps({"channel": channel, "reason": reason}, ensure_ascii=False),
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
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        return {"id": action_id, "state": "cancelled", "idempotent": False}

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
                detail={"reason": "not_owner"},
            )
            raise ActionError("cancel_denied", "not_owner")
        t = now()
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE actions SET state='cancelled', finished_at=?, result_detail=?,"
                " decision_channel=?, decision_reason=?, decided_at=? WHERE id=?",
                (t, f"cancelled:{reason or ''}", channel, reason, t, action_id),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, action_id, detail_json)"
                " VALUES(?,?,?,?,?,?)",
                (
                    t,
                    actor_type,
                    actor_id,
                    "action_cancelled",
                    action_id,
                    json.dumps({"channel": channel, "reason": reason}, ensure_ascii=False),
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
        """TTL / approval_deadline 到期的 proposed → expired。"""
        t = now()
        rows = self.db.query(
            "SELECT id, incident_id FROM actions WHERE state='proposed'"
            " AND (approval_deadline IS NOT NULL AND ? > approval_deadline"
            "      OR ? - created_at > ?)",
            (t, t, float(self.action_ttl)),
        )
        n = 0
        for r in rows:
            with self.db.tx() as conn:
                cur = conn.execute(
                    "UPDATE actions SET state='expired', finished_at=?,"
                    " result_detail='approval_expired' WHERE id=? AND state='proposed'",
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
        return n

    def cancel_pending_for_incident(self, incident_id: str, reason: str = "incident_recovered") -> int:
        """故障自然恢复 / 事件关闭后，取消不再必要的过时 proposal。"""
        if not incident_id:
            return 0
        t = now()
        n = 0
        rows = self.db.query(
            "SELECT id FROM actions WHERE incident_id=? AND state='proposed'",
            (incident_id,),
        )
        for r in rows:
            with self.db.tx() as conn:
                cur = conn.execute(
                    "UPDATE actions SET state='cancelled', finished_at=?, result_detail=?"
                    " WHERE id=? AND state='proposed'",
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
            return await self._execute_locked(
                action_id, actor_type=actor_type, actor_id=actor_id, is_admin=is_admin
            )

    async def _execute_locked(
        self,
        action_id: str,
        *,
        actor_type: str = "web_user",
        actor_id: str = "system",
        is_admin: bool = False,
    ) -> dict[str, Any]:
        row = self._get(action_id)
        if row["state"] != "approved":
            raise ActionError("bad_state", row["state"])

        # 记录核验时使用的绑定快照，领取事务里逐项比对
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
        if binding.host_id_verified_at is None or not binding.expected_host_id:
            raise ActionError("identity_gate", "host_id not registered/verified")

        # ---- 短事务：重查授权/期限/对象/占用/资产绑定 + 领取 ----
        dispatcher = binding.write_alias
        reject: tuple[str, str] | None = None
        tokens: list[str] = []
        with self.db.tx() as conn:
            fresh = conn.execute(
                "SELECT * FROM actions WHERE id=?", (action_id,)
            ).fetchone()
            if not fresh or fresh["state"] != "approved":
                raise ActionError("bad_state", "not_approved")

            # 资产当前登记 vs 核验时快照
            asset_row = conn.execute(
                "SELECT * FROM assets WHERE id=?", (fresh["asset_id"],)
            ).fetchone()
            if not asset_row or not asset_row["enabled"]:
                reject = ("asset_disabled", "asset missing or disabled")
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
            action_mode = (fresh["mode"] or "manual") if "mode" in fresh.keys() else "manual"
            if reject is None:
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
                        auto=(action_mode == "auto"),
                    )
                    if not decision["allowed"]:
                        reject = ("policy_revoked", f"{subject_type}:{subject_id}")
                        break
                    if action_mode == "auto" and not decision.get("auto_allowed"):
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
                else:
                    reject = ("template_required", "no runbook/template on action")

            # 实际派发人必须具备该能力（非管理员）
            if reject is None and not is_admin:
                d = self.policy.check(
                    subject_type=actor_type,
                    subject_id=actor_id,
                    capability=fresh["capability"],
                    asset_id=fresh["asset_id"],
                    object_id=fresh["object_id"],
                    auto=(action_mode == "auto"),
                )
                if not d["allowed"] or (action_mode == "auto" and not d.get("auto_allowed")):
                    reject = ("dispatcher_denied", f"{actor_type}:{actor_id}")

            # 全局暂停（P0-03）
            if reject is None:
                stop = conn.execute(
                    "SELECT enabled FROM global_stops WHERE key='auto_dispatch'"
                ).fetchone()
                if stop and stop["enabled"] and action_mode == "auto":
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
                locked = conn.execute(
                    "SELECT COUNT(*) AS n FROM actions"
                    " WHERE asset_id=? AND object_id=? AND id != ?"
                    " AND (state IN ('unknown','dispatched')"
                    "  OR (state='success' AND id IN (SELECT action_id FROM verifications"
                    "      WHERE status='pending')))",
                    (fresh["asset_id"], fresh["object_id"], action_id),
                ).fetchone()
                if locked and locked["n"] > 0:
                    reject = ("object_locked", fresh["object_id"])

            # 预算：派发前原子占用（P0-03）；unknown 也计数
            if reject is None and action_mode == "auto":
                rb_id_b = (fresh["runbook_id"] or "") if "runbook_id" in fresh.keys() else ""
                from .runbook import get_runbook_rule

                rule = get_runbook_rule(rb_id_b) if rb_id_b else None
                max_day = rule.max_per_day if rule else 3
                cooldown = rule.cooldown_sec if rule else 1800
                since = now() - 86400
                used = conn.execute(
                    "SELECT COUNT(*) AS n FROM actions"
                    " WHERE asset_id=? AND object_id=? AND mode='auto'"
                    " AND state IN ('dispatched','success','failure','unknown')"
                    " AND created_at > ?",
                    (fresh["asset_id"], fresh["object_id"], since),
                ).fetchone()
                n_used = int(used["n"] if used else 0)
                if n_used >= max_day:
                    reject = ("budget_exhausted", f"max_per_day {n_used}/{max_day}")
                else:
                    last = conn.execute(
                        "SELECT COALESCE(dispatched_at, created_at) AS at FROM actions"
                        " WHERE asset_id=? AND object_id=? AND mode='auto'"
                        " AND state IN ('dispatched','success','failure','unknown')"
                        " AND id != ? ORDER BY at DESC LIMIT 1",
                        (fresh["asset_id"], fresh["object_id"], action_id),
                    ).fetchone()
                    if last and (now() - float(last["at"] or 0)) < cooldown:
                        reject = ("cooldown", f"{int(now() - float(last['at']))}s < {cooldown}s")

            if reject is not None:
                code, detail = reject
                # 客观原因终止提案；调用者无权仅拒绝本次请求
                if code in ("dispatcher_denied",):
                    conn.execute(
                        "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                        " action_id, detail_json) VALUES(?,?,?,?,?,?,?,?)",
                        (
                            now(),
                            actor_type,
                            actor_id,
                            "action_dispatch_denied",
                            fresh["asset_id"],
                            fresh["object_id"],
                            action_id,
                            json.dumps({"code": code, "detail": detail}, ensure_ascii=False),
                        ),
                    )
                else:
                    conn.execute(
                        "UPDATE actions SET state='cancelled', result_detail=?, finished_at=?"
                        " WHERE id=? AND state='approved'",
                        (f"{code}:{detail}", now(), action_id),
                    )
                    conn.execute(
                        "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                        " action_id, detail_json) VALUES(?,?,?,?,?,?,?,?)",
                        (
                            now(),
                            actor_type,
                            actor_id,
                            "action_dispatch_denied",
                            fresh["asset_id"],
                            fresh["object_id"],
                            action_id,
                            json.dumps({"code": code, "detail": detail}, ensure_ascii=False),
                        ),
                    )
            else:
                cur = conn.execute(
                    "UPDATE actions SET state='dispatched', dispatched_at=?, exec_account=?,"
                    " budget_claimed_at=? WHERE id=? AND state='approved'",
                    (now(), dispatcher, now(), action_id),
                )
                if cur.rowcount != 1:
                    reject = ("claim_failed", "")
                else:
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

        # 网络：真正执行
        res = await self.nt.exec(dispatcher, tokens, timeout=15.0)
        state, detail = classify_exec_result(res)

        # ---- 同事务提交：结果 + 审计 + 验证义务/人工 + 事件 ----
        finished_at = now()
        vid = ""
        if state == "success":
            vid = new_id("ver")
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE actions SET state=?, finished_at=?, result_detail=? WHERE id=?",
                (state, finished_at, detail, action_id),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
                " action_id, detail_json) VALUES(?,?,?,?,?,?,?,?)",
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
                            "returncode": res.returncode,
                            "timed_out": res.timed_out,
                            "nt_account": dispatcher,
                            "actor": f"{actor_type}:{actor_id}",
                        },
                        ensure_ascii=False,
                    ),
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
                    "SELECT name FROM objects WHERE asset_id=? AND (id=? OR name=?)",
                    (row["asset_id"], row["object_id"], row["object_id"]),
                ).fetchone()
                service = (obj_row["name"] if obj_row else "") or ""
                from .verify_profiles import profile_for_action

                _prof = profile_for_action(
                    capability=row["capability"],
                    asset_id=row["asset_id"],
                    object_id=row["object_id"] or "",
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
                conn.execute(
                    "UPDATE incidents SET need_human=1, need_human_reason=?, stage='need_human',"
                    " updated_at=? WHERE id=?",
                    (f"exec_unknown:{action_id}", finished_at, row["incident_id"]),
                )
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
            object_id=row["object_id"] or "",
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
                1,
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
                capability=row["capability"], asset_id=asset, object_id=row.get("object_id") or ""
            )
        if profile is None:
            # unsupported：不得退回通用 probe_success 猜测
            self._finish_verification(vid, "unknown", {}, "unsupported_verification_profile")
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
            # 非 passed：标记需人工；若已 resolved 则重开（不得假 recovered）
            if status in ("failed", "inconclusive", "unknown") and inc_id:
                conn.execute(
                    "UPDATE incidents SET need_human=1, need_human_reason=?,"
                    " status=CASE WHEN status='resolved' THEN 'open' ELSE status END,"
                    " resolved_at=CASE WHEN status='resolved' THEN NULL ELSE resolved_at END,"
                    " outcome=CASE WHEN status='resolved' THEN 'unrecovered' ELSE outcome END,"
                    " updated_at=? WHERE id=?",
                    (f"verify_{status}:{vid}", now(), inc_id),
                )
            # 统一收敛：passed 不单独 recovered
            if inc_id:
                try:
                    from .incidents import IncidentService

                    IncidentService(self.db).reconcile(
                        inc_id, resolution_basis=f"verification:{vid}"
                    )
                except Exception:
                    pass
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
        self.db.execute(
            "UPDATE incidents SET need_human=1, need_human_reason=?, stage='need_human',"
            " updated_at=? WHERE id=?",
            (reason, now(), incident_id),
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
        release_state = "success" if outcome == "executed" else "cancelled"
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE actions SET adjudication=?, adjudicated_at=?, adjudication_reason=?,"
                " state=?, finished_at=COALESCE(finished_at, ?)"
                " WHERE id=? AND state='unknown'",
                (outcome, t, reason or outcome, release_state, t, action_id),
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

    def _object_locked(self, asset_id: str, object_id: str, exclude: str = "") -> bool:
        sql = (
            "SELECT COUNT(*) AS n FROM actions"
            " WHERE asset_id=? AND object_id=? AND id != ?"
            " AND (state IN ('unknown','dispatched')"
            "  OR (state='success' AND id IN (SELECT action_id FROM verifications"
            "      WHERE status='pending')))"
        )
        row = self.db.query_one(sql, (asset_id, object_id, exclude))
        return bool(row and row["n"] > 0)

    def _registered_service_label(self, row: dict) -> str:
        obj = self._object(row["asset_id"], row["object_id"])
        return (obj or {}).get("name") or ""

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
