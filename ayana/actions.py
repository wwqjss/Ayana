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
    ) -> dict[str, Any]:
        cap = get_capability(capability)
        if cap.kind != "write":
            raise ActionError("not_a_write_capability")
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

        # Incident 关联校验：资产一致，对象要么空要么对应
        if incident_id:
            self._assert_incident_matches(incident_id, asset_id, obj)

        decision = self.policy.check(
            subject_type=proposer_type,
            subject_id=proposer_id,
            capability=capability,
            asset_id=asset_id,
            object_id=obj["id"],
        )
        if not decision["allowed"]:
            raise ActionError("denied", decision["reason"])

        if self._object_locked(asset_id, obj["id"]):
            raise ActionError("object_locked", f"{asset_id}/{obj['id']}")

        aid = new_id("act")
        payload = {
            "params": params or {},
            "tokens": tokens,
            "object_name": resolve_object_name(obj),
            "object_kind": obj.get("kind") or "",
        }
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
                " params_json, reason, state, proposer_type, proposer_id, created_at,"
                " policy_snapshot_json)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
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
                ),
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    incident_id,
                    now(),
                    "action_proposed",
                    f"{capability} on {asset_id}/{obj['id']}",
                    json.dumps({"action_id": aid, "tokens": tokens}, ensure_ascii=False),
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
                    json.dumps({"capability": capability, "reason": reason}, ensure_ascii=False),
                ),
            )
        return {
            "id": aid,
            "state": "proposed",
            "tokens": tokens,
            "require_approval": decision.get("require_approval", True),
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
    # 批准 / 取消
    # ------------------------------------------------------------------

    def approve(
        self,
        action_id: str,
        *,
        approver_type: str = "web_user",
        approver_id: str = "system",
    ) -> dict[str, Any]:
        row = self._get(action_id)
        if row["state"] != "proposed":
            raise ActionError("bad_state", row["state"])
        if now() - row["created_at"] > self.action_ttl:
            self.db.execute("UPDATE actions SET state='expired' WHERE id=?", (action_id,))
            raise ActionError("expired")

        decision = self.policy.check(
            subject_type=approver_type,
            subject_id=approver_id,
            capability=row["capability"],
            asset_id=row["asset_id"],
            object_id=row["object_id"],
        )
        if not decision["allowed"]:
            self.db.audit(
                approver_type,
                approver_id,
                "action_approve_denied",
                asset_id=row["asset_id"],
                object_id=row["object_id"],
                action_id=action_id,
                detail={"reason": decision["reason"]},
            )
            raise ActionError("approve_denied", decision["reason"])

        self.db.execute(
            "UPDATE actions SET state='approved', approver_type=?, approver_id=?, approved_at=?"
            " WHERE id=? AND state='proposed'",
            (approver_type, approver_id, now(), action_id),
        )
        self.db.audit(
            approver_type,
            approver_id,
            "action_approved",
            asset_id=row["asset_id"],
            object_id=row["object_id"],
            action_id=action_id,
        )
        self.db.event(
            "action_approved",
            f"approved {action_id}",
            incident_id=row["incident_id"],
            payload={"action_id": action_id, "approver": approver_id},
        )
        return {"id": action_id, "state": "approved"}

    def cancel(
        self,
        action_id: str,
        *,
        actor_type: str = "web_user",
        actor_id: str = "system",
        is_admin: bool = False,
    ) -> None:
        row = self._get(action_id)
        if row["state"] in ("success", "failure", "unknown", "dispatched"):
            raise ActionError("cannot_cancel", row["state"])
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
        self.db.execute(
            "UPDATE actions SET state='cancelled', finished_at=? WHERE id=?",
            (now(), action_id),
        )
        self.db.audit(actor_type, actor_id, "action_cancelled", action_id=action_id)

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

            # 提案人、批准人当前授权复查
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
                    )
                    if not decision["allowed"]:
                        reject = ("policy_revoked", f"{subject_type}:{subject_id}")
                        break

            # 实际派发人必须具备该能力（非管理员）
            if reject is None and not is_admin:
                d = self.policy.check(
                    subject_type=actor_type,
                    subject_id=actor_id,
                    capability=fresh["capability"],
                    asset_id=fresh["asset_id"],
                    object_id=fresh["object_id"],
                )
                if not d["allowed"]:
                    reject = ("dispatcher_denied", f"{actor_type}:{actor_id}")

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
                    "UPDATE actions SET state='dispatched', dispatched_at=?, exec_account=?"
                    " WHERE id=? AND state='approved'",
                    (now(), dispatcher, action_id),
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
                }
                conn.execute(
                    "INSERT INTO verifications(id, action_id, incident_id, status,"
                    " criteria_json, started_at) VALUES(?,?,?,?,?,?)",
                    (
                        vid,
                        action_id,
                        row["incident_id"],
                        "pending",
                        json.dumps(criteria, ensure_ascii=False),
                        finished_at,
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
        criteria = {
            "window_sec": self.verify_window,
            "timeout_sec": self.verify_timeout,
            "require": ["action_success", "exact_series", "fresh_raw_samples", "stability"],
            "asset_id": row["asset_id"],
            "service": service,
            "object_id": row["object_id"],
            "incident_id": row["incident_id"],
            "baseline_finished_at": row.get("finished_at") or now(),
        }
        self.db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, criteria_json,"
            " started_at) VALUES(?,?,?,?,?,?)",
            (
                vid,
                action_id,
                row["incident_id"],
                "pending",
                json.dumps(criteria, ensure_ascii=False),
                now(),
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
        window = float(crit.get("window_sec") or self.verify_window)
        timeout = float(crit.get("timeout_sec") or self.verify_timeout)

        deadline = time.time() + timeout
        # 按完整序列保存：series_key -> {sample_at: sample}
        by_series: dict[str, dict[float, dict]] = {}
        note = ""
        status = "inconclusive"
        # 新鲜度上限：最新样本距 now 超过该值不得判恢复
        max_age_sec = max(60.0, min(window, 120.0))

        while time.time() < deadline:
            try:
                now_ts = time.time()
                samples = await self.prom.probe_success_since(
                    asset,
                    service,
                    start=baseline + 0.01,
                    end=now_ts,
                    window_sec=min(600.0, max(120.0, now_ts - baseline + 60.0)),
                )
                matched = match_series(samples, asset=asset, service=service)
                groups = group_by_series(matched)
                if len(groups) > 1:
                    status = "inconclusive"
                    note = f"ambiguous series: {len(groups)} distinct label sets"
                    break
                for key, arr in groups.items():
                    bucket = by_series.setdefault(key, {})
                    for s in arr:
                        ts = s.get("sample_at")
                        if ts is None:
                            continue
                        bucket[round(float(ts), 3)] = s

                if not by_series:
                    await asyncio.sleep(min(15, max(5, window // 3)))
                    continue

                key = next(iter(by_series))
                timeline = sorted(by_series[key].values(), key=lambda s: s["sample_at"])
                if len(timeline) >= 2 and all(s.get("value") == 1 for s in timeline):
                    span = timeline[-1]["sample_at"] - timeline[0]["sample_at"]
                    latest_age = now_ts - timeline[-1]["sample_at"]
                    # 恢复必须是「现在」仍新鲜：最新样本在 max_age_sec 内
                    if (
                        span >= min(15.0, window / 3)
                        and timeline[-1]["sample_at"] - timeline[-2]["sample_at"] >= 5
                        and latest_age <= max_age_sec
                    ):
                        status = "passed"
                        note = (
                            f"exact series ok x{len(timeline)} span={span:.1f}s "
                            f"service={service or '-'} age={latest_age:.1f}s"
                        )
                        break
            except Exception as e:
                note = f"prom error: {e}"
            await asyncio.sleep(min(15, max(5, window // 3)))
        else:
            all_samples = [s for b in by_series.values() for s in b.values()]
            if not all_samples:
                status = "failed"
                note = "no fresh samples"
            elif any(s.get("value") != 1 for s in all_samples):
                status = "failed"
                note = "fresh samples include failures"
            else:
                # 有样本但不新鲜 / 不稳定：不得宣布恢复
                latest = max((s.get("sample_at") or 0) for s in all_samples)
                age = time.time() - latest
                if age > max_age_sec:
                    status = "inconclusive"
                    note = f"stale samples age={age:.0f}s > {max_age_sec:.0f}s"
                else:
                    status = "inconclusive"
                    note = f"stability not reached; samples={len(all_samples)}"

        all_samples = sorted(
            [s for b in by_series.values() for s in b.values()],
            key=lambda s: s.get("sample_at") or 0,
        )
        evidence = {
            "baseline": baseline,
            "asset": asset,
            "service": service,
            "samples": all_samples[-30:],
            "series_keys": list(by_series.keys()),
            "action_id": action_id,
            "window_sec": window,
        }

        # 终态提交：核对验证仍属于该 Action 且 Incident 匹配
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
                "UPDATE verifications SET status=?, evidence_json=?, note=?, finished_at=?"
                " WHERE id=?",
                (
                    status,
                    json.dumps(evidence, ensure_ascii=False, default=str),
                    note,
                    now(),
                    vid,
                ),
            )
            inc_id = a_now["incident_id"]
            if status == "passed" and inc_id:
                inc = conn.execute(
                    "SELECT * FROM incidents WHERE id=?", (inc_id,)
                ).fetchone()
                # 关闭前必须核对资产与对象
                ok_inc = False
                if inc and inc["status"] == "open":
                    if (not inc["asset_id"] or inc["asset_id"] == a_now["asset_id"]) and (
                        not inc["object_id"]
                        or inc["object_id"] == a_now["object_id"]
                        or inc["object_id"] == (crit.get("service") or "")
                    ):
                        ok_inc = True
                if ok_inc:
                    conn.execute(
                        "UPDATE incidents SET stage='done', status='resolved', resolved_at=?,"
                        " updated_at=? WHERE id=?",
                        (now(), now(), inc_id),
                    )
                    conn.execute(
                        "INSERT INTO events(incident_id, at, type, title, payload_json)"
                        " VALUES(?,?,?,?,?)",
                        (
                            inc_id,
                            now(),
                            "verified_recovered",
                            f"verified {action_id}",
                            json.dumps({"verification_id": vid, "note": note}, ensure_ascii=False),
                        ),
                    )
                    # 验证恢复通知义务与转换同事务
                    try:
                        ev = conn.execute(
                            "SELECT id FROM events WHERE incident_id=?"
                            " AND type='verified_recovered' ORDER BY id DESC LIMIT 1",
                            (inc_id,),
                        ).fetchone()
                        if ev:
                            conn.execute(
                                "INSERT OR IGNORE INTO notification_outbox(id, dedup_key,"
                                " channel, target, body, state, created_at, last_try_at,"
                                " next_try_at) VALUES(?,?,?,?,?,?,?,?,?)",
                                (
                                    new_id("ntf"),
                                    f"ev:{ev['id']}",
                                    "qq",
                                    "",
                                    f"[Ayana] verified_recovered {inc_id}",
                                    "pending",
                                    now(),
                                    0,
                                    0,
                                ),
                            )
                    except Exception:
                        pass
                else:
                    conn.execute(
                        "INSERT INTO events(incident_id, at, type, title, payload_json)"
                        " VALUES(?,?,?,?,?)",
                        (
                            inc_id,
                            now(),
                            "verify_passed_incident_skipped",
                            f"verified {action_id} but incident not closed",
                            json.dumps(
                                {
                                    "verification_id": vid,
                                    "reason": "incident_mismatch_or_not_open",
                                },
                                ensure_ascii=False,
                            ),
                        ),
                    )
            elif status != "passed" and inc_id:
                # 验证失败：若 Incident 已被误关，恢复 open 并转人工
                conn.execute(
                    "UPDATE incidents SET need_human=1, need_human_reason=?,"
                    " status=CASE WHEN status='resolved' THEN 'open' ELSE status END,"
                    " stage='need_human', updated_at=?,"
                    " resolved_at=CASE WHEN status='resolved' THEN NULL ELSE resolved_at END"
                    " WHERE id=?",
                    (f"verify_{status}:{action_id}", now(), inc_id),
                )
                conn.execute(
                    "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                    (
                        inc_id,
                        now(),
                        "verify_not_passed",
                        f"verify {status} {action_id}",
                        json.dumps({"verification_id": vid, "note": note}, ensure_ascii=False),
                    ),
                )
        return {"id": vid, "status": status, "note": note, "evidence": evidence}

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
        n = self.db.execute(
            "UPDATE actions SET state='unknown', result_detail='restart_recovery'"
            " WHERE state='dispatched'"
        ).rowcount
        for r in self.db.query("SELECT id, incident_id FROM actions WHERE state='unknown'"):
            self._mark_need_human(r["incident_id"], f"exec_unknown:{r['id']}")
        return int(n or 0)

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
