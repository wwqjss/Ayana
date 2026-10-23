"""Deterministic council. Models submit evidence and opinions, never permissions.

Only the orchestrator calls begin_review with its configured client identity.
The returned receipt binds that one request to an immutable plan. Neither model
output nor an ordinary Action approval can manufacture a council authorization.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

from .actions import ActionError, ActionService
from .capabilities import build_write_tokens, get_capability, object_matches_capability, resolve_object_name
from .db import Database, new_id, now

REVIEW_ROLES = ("reviewer_kimi", "reviewer_deepseek")
REPAIR_GOAL = "restore_registered_object"


class CouncilError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code, self.detail = code, message
        super().__init__(f"{code}: {message}" if message else code)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _text(value: Any, label: str, maximum: int = 8000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise CouncilError("invalid_plan", f"{label} must be a nonempty bounded string")
    return value.strip()


def _structured(value: Any, label: str) -> Any:
    if not isinstance(value, (str, dict, list)) or not value or not _json(value).strip('" '):
        raise CouncilError("invalid_plan", f"missing {label}")
    if len(_json(value)) > 48000:
        raise CouncilError("invalid_plan", f"{label} too large")
    return json.loads(_json(value))


def reviewed_runtime_block(store: Any) -> tuple[str, str] | None:
    """Persisted operator switches are rechecked after identity network waits.

    Legacy databases/tests may not have a ProviderRegistry row yet; their
    in-memory configuration is checked by the orchestrator. A persisted stop
    always wins and cannot be overridden by a previously issued grant.
    """
    automatic = store.execute("SELECT value FROM meta WHERE key='agent_auto_enabled'").fetchone()
    if automatic and automatic["value"] != "1":
        return "agent_auto_disabled", "automatic dispatch was disabled by an administrator"
    registry = store.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ai_provider_config'").fetchone()
    if registry:
        config = store.execute("SELECT value_json FROM ai_provider_config WHERE id=1").fetchone()
        if config:
            try:
                enabled = json.loads(config["value_json"]).get("enabled") is True
            except (ValueError, AttributeError):
                enabled = False
            if not enabled:
                return "autonomy_disabled", "autonomous model dispatch was disabled by an administrator"
    return None


def current_plan_block(store: Any, plan: Any) -> tuple[str, str] | None:
    """Recheck all bindings without a network wait, usable in Action's claim tx."""
    p = dict(plan)
    inc = store.execute("SELECT * FROM incidents WHERE id=?", (p["incident_id"],)).fetchone()
    if not inc or inc["status"] != "open":
        return "incident_not_open", "incident recovered or closed"
    if int(inc["generation"] or 1) != int(p["generation"]):
        return "stale_generation", "plan belongs to a previous fault generation"
    if inc["asset_id"] != p["asset_id"]:
        return "incident_mismatch", "incident asset changed"
    obj = store.execute("SELECT * FROM objects WHERE id=? AND asset_id=?", (p["object_id"], p["asset_id"])).fetchone()
    if not obj or inc["object_id"] not in (obj["id"], obj["name"]):
        return "incident_mismatch", "registered incident object changed"
    if resolve_object_name(dict(obj)) != p["canonical_object"]:
        return "object_binding_changed", "registered command target changed"
    if now() >= float(p["expires_at"]):
        return "plan_expired", "plan validity window elapsed"
    content = json.loads(p["plan_json"])
    if _digest(content) != p["digest"]:
        return "plan_digest_mismatch", "immutable plan digest does not match"
    latest = store.execute("SELECT MAX(version) AS version FROM council_plans WHERE goal_id=?", (p["goal_id"],)).fetchone()
    if latest and int(latest["version"]) != int(p["version"]):
        return "plan_superseded", "a newer immutable plan exists"
    goal = store.execute("SELECT * FROM council_goals WHERE id=?", (p["goal_id"],)).fetchone()
    if not goal or goal["manual_required"]:
        return "manual_adjudication_required", "repair goal is held for an administrator"
    # A human rejection is a deliberate stop; a technical verification failure
    # instead returns evidence to the planner and does not grant extra authority.
    reasons = (inc["need_human_reason"] or "").splitlines()
    if any(reason.strip().startswith(("action_rejected:", "exec_unknown:")) for reason in reasons):
        return "manual_adjudication_required", "unresolved human rejection or uncertain write"
    for step in content["steps"]:
        try:
            tokens = build_write_tokens(step["capability"], dict(obj))
        except Exception as exc:
            return "object_binding_changed", str(exc)
        if tokens != step["tokens"]:
            return "token_mismatch", "registered command changed since deliberation"
    from .verify_profiles import bound_contract, profile_for_action
    contracts = []
    for step in content["steps"]:
        profile = profile_for_action(capability=step["capability"], asset_id=p["asset_id"], object_id=p["canonical_object"])
        if not profile:
            return "unsupported_verification_profile", "independent verification contract is unavailable"
        contracts.append({"ordinal": step["ordinal"], "profile": bound_contract(profile, asset_id=p["asset_id"], service=p["canonical_object"])})
    if contracts != content.get("verification_contracts"):
        return "verification_contract_changed", "independent validation differs from the reviewed plan"
    return None


def reviewed_action_block(store: Any, action: Any) -> tuple[str, str] | None:
    """Exact authorization check performed again at the only SSH dispatch gate."""
    a = dict(action)
    gid, ordinal = a.get("council_grant_id") or "", a.get("council_step", -1)
    grant = store.execute("SELECT * FROM council_grants WHERE id=?", (gid,)).fetchone()
    if not grant or grant["state"] != "executing" or not grant["claimed_at"]:
        return "council_grant_invalid", "grant is not in its one claimed execution"
    if now() >= float(grant["expires_at"]):
        return "council_grant_expired", "grant expired before dispatch"
    plan = store.execute("SELECT * FROM council_plans WHERE id=?", (grant["plan_id"],)).fetchone()
    if not plan or grant["plan_digest"] != plan["digest"]:
        return "council_grant_invalid", "plan binding diverged"
    blocked = current_plan_block(store, plan)
    if blocked:
        return blocked
    binding = store.execute("SELECT * FROM council_steps WHERE grant_id=? AND ordinal=?", (gid, ordinal)).fetchone()
    if not binding or binding["state"] != "prepared" or binding["action_id"] != a["id"]:
        return "council_step_consumed", "step is not reserved for this action"
    steps = json.loads(plan["plan_json"])["steps"]
    if not isinstance(ordinal, int) or not 0 <= ordinal < len(steps):
        return "council_step_invalid", "invalid ordinal"
    step = steps[ordinal]
    payload = json.loads(a["params_json"])
    if (a["incident_id"] != plan["incident_id"] or a["asset_id"] != plan["asset_id"]
            or a["object_id"] != plan["object_id"] or a["capability"] != step["capability"]
            or payload.get("params") != step["params"] or payload.get("tokens") != step["tokens"]):
        return "council_step_mismatch", "action differs from the reviewed exact operation"
    previous = store.execute("SELECT state FROM council_steps WHERE grant_id=? AND ordinal<?", (gid, ordinal)).fetchall()
    if len(previous) != ordinal or any(row["state"] != "success" for row in previous):
        return "council_step_order", "earlier operations have not completed successfully"
    return None


class CouncilService:
    def __init__(self, db: Database, actions: ActionService):
        self.db, self.actions = db, actions
        self._lock = asyncio.Lock()

    def _emit(self, kind: str, incident_id: str, payload: dict, title: str = "") -> None:
        self.db.event(kind, title or kind, incident_id=incident_id, payload=payload)
        self.db.audit("system", "council", kind, incident_id=incident_id, channel="system", detail=payload)

    def create_plan(self, incident_id: str, *, steps: list[dict], evidence: list,
                    rationale: str, scope: Any, rollback: Any, verification: Any,
                    ttl: float = 600, repair_goal: str = REPAIR_GOAL, **unsupported: Any) -> dict:
        if unsupported:
            raise CouncilError("invalid_plan", f"unknown fields: {','.join(unsupported)}")
        if type(ttl) not in (float, int) or not 0 < ttl <= 1800:
            raise CouncilError("invalid_plan", "ttl must be 0..1800 seconds")
        if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
            raise CouncilError("invalid_plan", "one to eight exact steps required")
        if not isinstance(evidence, list) or not evidence or len(evidence) > 80:
            raise CouncilError("invalid_plan", "bounded evidence references required")
        rationale = _text(rationale, "rationale")
        scope, rollback, verification = (_structured(value, name) for value, name in (
            (scope, "scope"), (rollback, "rollback"), (verification, "verification")))
        evidence = _structured(evidence, "evidence")
        with self.db.tx() as conn:
            inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not inc or inc["status"] != "open":
                raise CouncilError("incident_not_open")
            obj = conn.execute("SELECT * FROM objects WHERE asset_id=? AND (id=? OR name=?)",
                               (inc["asset_id"], inc["object_id"], inc["object_id"])).fetchone()
            if not obj:
                raise CouncilError("object_not_registered")
            obj = dict(obj)
            canonical = resolve_object_name(obj)
            from .runbook import CONTROL_PLANE_MARKERS
            if any(marker in " ".join(str(obj.get(k) or "") for k in ("id", "name", "unit", "container")).lower()
                   for marker in CONTROL_PLANE_MARKERS):
                raise CouncilError("control_plane_forbidden")
            fixed_steps, contracts, policy_evidence = [], [], []
            from .verify_profiles import bound_contract, profile_for_action
            for ordinal, step in enumerate(steps):
                if not isinstance(step, dict) or set(step) - {"capability", "params"}:
                    raise CouncilError("invalid_plan", "steps accept only capability and params")
                capability = step.get("capability")
                params = step.get("params", {})
                if not isinstance(params, dict) or params:
                    # Existing fixed catalog has no write parameter inputs.
                    raise CouncilError("invalid_plan", "fixed catalog operations accept no parameter overrides")
                try:
                    cap = get_capability(capability)
                    if cap.kind != "write" or not cap.write_tokens or not cap.auto_allowed:
                        raise CouncilError("capability_not_autonomous", str(capability))
                    object_matches_capability(capability, obj)
                    tokens = build_write_tokens(capability, obj)
                except CouncilError:
                    raise
                except Exception as exc:
                    raise CouncilError("invalid_capability", str(exc)) from exc
                decision = self.actions.policy.effective_decision(subject_type="auto_rule", subject_id="agent",
                    capability=capability, asset_id=inc["asset_id"], object_id=obj["id"], auto=True)
                if not decision.get("allowed") or decision.get("decision") != "automatic":
                    raise CouncilError("policy_denied", decision.get("reason", "default_deny"))
                policy_evidence.append({"ordinal":ordinal, "capability":capability,
                    "subject":"auto_rule:agent", "asset_id":inc["asset_id"], "object_id":obj["id"],
                    "decision":decision["decision"], "matched_rule":decision.get("matched_rule"),
                    "agent_ceiling":decision.get("agent_ceiling")})
                profile = profile_for_action(capability=capability, asset_id=inc["asset_id"], object_id=canonical)
                if profile is None:
                    raise CouncilError("unsupported_verification_profile")
                fixed_steps.append({"ordinal": ordinal, "capability": capability, "params": {}, "tokens": tokens})
                contracts.append({"ordinal": ordinal, "profile": bound_contract(profile, asset_id=inc["asset_id"], service=canonical)})
            gen, t = int(inc["generation"] or 1), now()
            goal = conn.execute("SELECT * FROM council_goals WHERE incident_id=? AND generation=? AND asset_id=?"
                " AND object_id=? AND repair_goal=?", (incident_id, gen, inc["asset_id"], obj["id"], REPAIR_GOAL)).fetchone()
            if not goal:
                goal_id = new_id("goal")
                conn.execute("INSERT INTO council_goals(id,incident_id,generation,asset_id,object_id,repair_goal,created_at,updated_at)"
                    " VALUES(?,?,?,?,?,?,?,?)", (goal_id, incident_id, gen, inc["asset_id"], obj["id"], REPAIR_GOAL, t, t))
            else:
                goal_id = goal["id"]
                if goal["manual_required"]:
                    raise CouncilError("manual_adjudication_required", goal_id)
            active = conn.execute("SELECT id FROM council_grants WHERE goal_id=? AND state IN ('executing','verifying')", (goal_id,)).fetchone()
            if active:
                raise CouncilError("goal_in_progress", active["id"])
            v = conn.execute("SELECT COALESCE(MAX(version),0)+1 AS v FROM council_plans WHERE goal_id=?", (goal_id,)).fetchone()["v"]
            pid, expires_at = new_id("plan"), t + float(ttl)
            content = {"incident_id": incident_id, "generation": gen, "goal_id": goal_id, "version": int(v),
                "asset_id": inc["asset_id"], "object_id": obj["id"], "canonical_object": canonical,
                "repair_goal": REPAIR_GOAL, "scope": {"asset_id": inc["asset_id"], "object_id": obj["id"], "description": scope},
                "evidence": evidence, "rationale": rationale, "rollback": rollback,
                "verification": verification, "verification_contracts": contracts,
                "policy_at_draft":policy_evidence,
                "backend_preconditions":{
                    "enforced_by":"ActionService; these are backend gates, not extra model steps",
                    "policy_snapshot_is_not_execution_authorization":True,
                    "rechecked_before_dispatch":["incident_open_and_same_generation", "one_use_unexpired_authorization",
                        "registered_target_and_exact_argv", "current_policy_and_agent_ceiling", "automatic_and_autonomy_switches",
                        "source_health", "global_pause", "object_lock", "semantic_operation_budget", "ssh_identity_and_host_trust", "step_order"]},
                "steps": fixed_steps, "expires_at": expires_at}
            conn.execute("UPDATE council_plans SET state='superseded' WHERE goal_id=? AND state IN ('drafted','reviewing','approved')", (goal_id,))
            conn.execute("UPDATE council_grants SET state='revoked',finished_at=? WHERE goal_id=? AND state='granted'", (t, goal_id))
            conn.execute("INSERT INTO council_plans(id,incident_id,generation,goal_id,version,digest,asset_id,object_id,canonical_object,plan_json,created_at,expires_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (pid, incident_id, gen, goal_id, int(v), _digest(content), inc["asset_id"], obj["id"], canonical, _json(content), t, expires_at))
            self._emit("council_plan_created", incident_id, {"plan_id": pid, "version": int(v), "digest": _digest(content), "goal_id": goal_id}, "拟旨：修复方案已固定")
        return self.get_plan(pid)

    def get_plan(self, plan_id: str) -> dict:
        row = self.db.query_one("SELECT * FROM council_plans WHERE id=?", (plan_id,))
        if not row:
            raise CouncilError("plan_not_found", plan_id)
        result = dict(row)
        result["plan"] = json.loads(result.pop("plan_json"))
        return result

    def begin_review(self, plan_id: str, role: str, provider: str, model: str, *, timeout: float = 90) -> dict:
        expected = {"reviewer_kimi": {"kimi", "moonshot"}, "reviewer_deepseek": {"deepseek"}}
        if role not in expected or provider.lower() not in expected[role]:
            raise CouncilError("reviewer_identity_invalid", role)
        _text(model, "model", 160)
        if type(timeout) not in (int, float) or not 0 < timeout <= 600:
            raise CouncilError("invalid_review_timeout")
        with self.db.tx() as conn:
            plan = conn.execute("SELECT * FROM council_plans WHERE id=?", (plan_id,)).fetchone()
            if not plan:
                raise CouncilError("plan_not_found")
            blocked = current_plan_block(conn, plan)
            if blocked:
                raise CouncilError(*blocked)
            if plan["state"] not in ("drafted", "reviewing"):
                raise CouncilError("plan_not_reviewable", plan["state"])
            prior = conn.execute("SELECT * FROM council_reviews WHERE plan_id=? AND role=?", (plan_id, role)).fetchone()
            if prior:
                raise CouncilError("review_already_requested", prior["id"])
            rid, t = new_id("review"), now()
            conn.execute("INSERT INTO council_reviews(id,plan_id,plan_digest,role,provider,model,requested_at,deadline_at)"
                " VALUES(?,?,?,?,?,?,?,?)", (rid, plan_id, plan["digest"], role, provider.lower(), model, t, min(t + timeout, plan["expires_at"])))
            conn.execute("UPDATE council_plans SET state='reviewing' WHERE id=?", (plan_id,))
            self._emit("council_review_requested", plan["incident_id"], {"plan_id": plan_id, "review_id": rid, "role": role, "provider": provider, "model": model}, "会审：独立委员审议")
        return dict(self.db.query_one("SELECT * FROM council_reviews WHERE id=?", (rid,)))

    def record_review(self, ticket_id: str, result: dict | None = None, *, error: str = "") -> dict:
        with self.db.tx() as conn:
            row = conn.execute("SELECT * FROM council_reviews WHERE id=?", (ticket_id,)).fetchone()
            if not row:
                raise CouncilError("review_ticket_not_found")
            if row["state"] != "pending":
                return self._review_dict(row)
            state, approve, reason, missing, revision = "complete", None, "", [], ""
            if error:
                state, reason = "failed", str(error)[:1000]
            elif now() >= float(row["deadline_at"]):
                state, reason = "timeout", "review response arrived after its deadline"
            elif (not isinstance(result, dict)
                  or set(result) != {"approve", "reason", "missing_evidence", "suggested_revision"}
                  or type(result.get("approve")) is not bool
                  or not isinstance(result.get("reason"), str) or not result["reason"].strip()
                  or len(result["reason"]) > 8000
                  or not isinstance(result.get("missing_evidence"), list) or len(result["missing_evidence"]) > 40
                  or any(not isinstance(item, str) or not item.strip() or len(item) > 2000 for item in result["missing_evidence"])
                  or not isinstance(result.get("suggested_revision"), str) or len(result["suggested_revision"]) > 8000):
                state, reason = "invalid", "review did not conform to the strict result schema"
            else:
                approve, reason, missing, revision = int(result["approve"]), result["reason"].strip(), result["missing_evidence"], result["suggested_revision"]
            conn.execute("UPDATE council_reviews SET state=?,approve=?,reason=?,missing_json=?,suggested_revision=?,finished_at=? WHERE id=? AND state='pending'",
                (state, approve, reason, _json(missing), revision, now(), ticket_id))
            plan = conn.execute("SELECT incident_id FROM council_plans WHERE id=?", (row["plan_id"],)).fetchone()
            self._emit("council_review_recorded", plan["incident_id"], {"plan_id": row["plan_id"], "review_id": ticket_id, "role": row["role"], "state": state, "approve": bool(approve) if approve is not None else None, "reason": reason}, "会审意见已记录")
        return self._review_dict(self.db.query_one("SELECT * FROM council_reviews WHERE id=?", (ticket_id,)))

    def tally(self, plan_id: str) -> dict:
        with self.db.tx() as conn:
            previous = conn.execute("SELECT * FROM council_ballots WHERE plan_id=?", (plan_id,)).fetchone()
            if previous:
                return dict(previous)
            plan = conn.execute("SELECT * FROM council_plans WHERE id=?", (plan_id,)).fetchone()
            if not plan:
                raise CouncilError("plan_not_found")
            for review in conn.execute("SELECT * FROM council_reviews WHERE plan_id=? AND state='pending' AND deadline_at<=?", (plan_id, now())).fetchall():
                self.record_review(review["id"], error="review_deadline_elapsed")
            reviews = conn.execute("SELECT * FROM council_reviews WHERE plan_id=?", (plan_id,)).fetchall()
            blocked = current_plan_block(conn, plan)
            roles = {r["role"] for r in reviews}
            if blocked:
                decision, reason = "stale", blocked[0]
            elif len(reviews) != 2 or roles != set(REVIEW_ROLES) or any(r["state"] == "pending" for r in reviews):
                return {"plan_id": plan_id, "decision": "pending", "reason": "waiting for both independently requested reviews", "grant_id": ""}
            elif any(r["plan_digest"] != plan["digest"] for r in reviews):
                decision, reason = "failed", "review_plan_digest_mismatch"
            elif any(r["state"] == "complete" and r["approve"] == 0 for r in reviews):
                decision, reason = "vetoed", "; ".join(f"{r['role']}: {r['reason']}" for r in reviews if r["state"] == "complete" and r["approve"] == 0)
            elif any(r["state"] != "complete" or r["approve"] != 1 for r in reviews):
                decision, reason = "failed", "; ".join(f"{r['role']}: {r['state']} {r['reason']}" for r in reviews if r["state"] != "complete" or r["approve"] != 1)
            else:
                decision, reason = "approved", "both designated independent reviewers approved this exact immutable version"
            gid, t = "", now()
            if decision == "approved":
                gid = new_id("grant")
                conn.execute("INSERT INTO council_grants(id,plan_id,plan_digest,incident_id,generation,goal_id,asset_id,object_id,created_at,expires_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)", (gid, plan_id, plan["digest"], plan["incident_id"], plan["generation"], plan["goal_id"], plan["asset_id"], plan["object_id"], t, plan["expires_at"]))
                for step in json.loads(plan["plan_json"])["steps"]:
                    conn.execute("INSERT INTO council_steps(grant_id,ordinal) VALUES(?,?)", (gid, step["ordinal"]))
                conn.execute("UPDATE council_goals SET consecutive_vetoes=0,updated_at=? WHERE id=?", (t, plan["goal_id"]))
            elif decision == "vetoed":
                conn.execute("UPDATE council_goals SET consecutive_vetoes=consecutive_vetoes+1,updated_at=? WHERE id=?", (t, plan["goal_id"]))
                goal = conn.execute("SELECT * FROM council_goals WHERE id=?", (plan["goal_id"],)).fetchone()
                if goal["consecutive_vetoes"] >= 3:
                    self._manual(plan, "three_substantive_veto_rounds")
            conn.execute("INSERT INTO council_ballots(id,plan_id,decision,reason,grant_id,at) VALUES(?,?,?,?,?,?)", (new_id("ballot"), plan_id, decision, reason, gid, t))
            conn.execute("UPDATE council_plans SET state=? WHERE id=?", (decision, plan_id))
            self._emit("council_ballot", plan["incident_id"], {"plan_id": plan_id, "goal_id": plan["goal_id"], "decision": decision, "reason": reason, "grant_id": gid}, "准奏" if decision == "approved" else "封驳：方案未获执行授权")
        return dict(self.db.query_one("SELECT * FROM council_ballots WHERE plan_id=?", (plan_id,)))

    def _manual(self, plan: Any, reason: str) -> None:
        self.db.execute("UPDATE council_goals SET manual_required=1,manual_reason=?,updated_at=? WHERE id=?", (reason, now(), plan["goal_id"]))
        from .incidents import IncidentService
        IncidentService(self.db).set_need_human(plan["incident_id"], f"council_manual:{plan['goal_id']}")
        self._emit("council_manual_required", plan["incident_id"], {"goal_id": plan["goal_id"], "reason": reason, "plan_id": plan["id"]}, "三轮封驳或执行不明，等待人工裁决")

    def request_manual_adjudication(self, incident_id: str, *, reason: str) -> dict:
        """Persist a planner-requested human stop on the server canonical goal."""
        reason = _text(reason, "manual adjudication reason", 8000)
        with self.db.tx() as conn:
            inc = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not inc or inc["status"] != "open":
                raise CouncilError("incident_not_open")
            obj = conn.execute("SELECT * FROM objects WHERE asset_id=? AND (id=? OR name=?)",
                               (inc["asset_id"], inc["object_id"], inc["object_id"])).fetchone()
            if not obj:
                raise CouncilError("object_not_registered")
            goal = conn.execute("SELECT * FROM council_goals WHERE incident_id=? AND generation=? AND asset_id=? AND object_id=? AND repair_goal=?",
                (incident_id, inc["generation"], inc["asset_id"], obj["id"], REPAIR_GOAL)).fetchone()
            if goal:
                gid = goal["id"]
            else:
                gid, t = new_id("goal"), now()
                conn.execute("INSERT INTO council_goals(id,incident_id,generation,asset_id,object_id,repair_goal,created_at,updated_at)"
                    " VALUES(?,?,?,?,?,?,?,?)", (gid, incident_id, inc["generation"], inc["asset_id"], obj["id"], REPAIR_GOAL, t, t))
            self._manual({"id": "", "goal_id": gid, "incident_id": incident_id}, reason)
            conn.execute("UPDATE council_grants SET state='revoked',finished_at=? WHERE goal_id=? AND state='granted'", (now(), gid))
            result = dict(conn.execute("SELECT * FROM council_goals WHERE id=?", (gid,)).fetchone())
            result["manual_required"] = bool(result["manual_required"])
        return result

    def release_manual_barrier(self, incident_id: str, goal_id: str, *, actor: str = "admin") -> dict:
        # Called exclusively by the existing authenticated admin endpoint. It
        # releases the goal for NEW reviews; never rewrites a vote or a grant.
        with self.db.tx() as conn:
            goal = conn.execute("SELECT * FROM council_goals WHERE id=? AND incident_id=?", (goal_id, incident_id)).fetchone()
            if not goal:
                raise CouncilError("goal_not_found")
            inc = conn.execute("SELECT status,generation,asset_id,object_id FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not inc or inc["status"] != "open":
                raise CouncilError("incident_not_open")
            if int(inc["generation"] or 1) != goal["generation"]:
                raise CouncilError("stale_generation")
            obj = conn.execute("SELECT id,name FROM objects WHERE id=? AND asset_id=?", (goal["object_id"], goal["asset_id"])).fetchone()
            if not obj or inc["asset_id"] != goal["asset_id"] or inc["object_id"] not in (obj["id"],obj["name"]):
                raise CouncilError("incident_mismatch")
            conn.execute("UPDATE council_goals SET manual_required=0,manual_reason='',consecutive_vetoes=0,updated_at=? WHERE id=?", (now(), goal_id))
            self.db.audit("web_user", actor, "council_manual_barrier_released", incident_id=incident_id, detail={"goal_id": goal_id})
            from .incidents import IncidentService
            service = IncidentService(self.db)
            # Exact obligation only, do not clear uncertain SSH adjudication.
            service.clear_action_obligation(incident_id, goal_id, kind="council_manual")
            self._emit("council_manual_released", incident_id, {"goal_id": goal_id, "actor": actor}, "人工已允许重新拟旨会审")
        return {"goal_id": goal_id, "manual_required": False, "requires_new_reviews": True}

    async def execute_grant(self, grant_id: str) -> dict:
        async with self._lock:
            with self.db.tx() as conn:
                grant = conn.execute("SELECT * FROM council_grants WHERE id=?", (grant_id,)).fetchone()
                if not grant:
                    raise CouncilError("grant_not_found")
                if grant["state"] != "granted":
                    raise CouncilError("grant_already_consumed", grant["state"])
                plan = conn.execute("SELECT * FROM council_plans WHERE id=?", (grant["plan_id"],)).fetchone()
                blocked = current_plan_block(conn, plan)
                if blocked:
                    raise CouncilError(*blocked)
                runtime_block = reviewed_runtime_block(conn)
                if runtime_block:
                    raise CouncilError(*runtime_block)
                if now() >= float(grant["expires_at"]):
                    raise CouncilError("grant_expired")
                cur = conn.execute("UPDATE council_grants SET state='executing',claimed_at=? WHERE id=? AND state='granted' AND claimed_at IS NULL", (now(), grant_id))
                if cur.rowcount != 1:
                    raise CouncilError("grant_already_consumed")
                conn.execute("UPDATE council_plans SET state='executing' WHERE id=?", (plan["id"],))
                self._emit("council_execution_started", plan["incident_id"], {"grant_id": grant_id, "plan_id": plan["id"]}, "奉旨执行")
            content = json.loads(plan["plan_json"])
            results, state = [], "verifying"
            try:
                for step in content["steps"]:
                    with self.db.tx() as conn:
                        proposed = self.actions.propose(asset_id=plan["asset_id"], object_id=plan["object_id"],
                            capability=step["capability"], params=step["params"], incident_id=plan["incident_id"],
                            reason=content["rationale"], proposer_type="auto_rule", proposer_id="agent", mode="reviewed",
                            council_grant_id=grant_id, council_step=step["ordinal"])
                        self.actions.authorize_reviewed(proposed["id"], grant_id=grant_id, ordinal=step["ordinal"])
                    result = await self.actions.execute(proposed["id"], actor_type="auto_rule", actor_id="agent")
                    results.append(result)
                    self.db.execute("UPDATE council_steps SET state=?,result_json=?,finished_at=? WHERE grant_id=? AND ordinal=?", (result["state"], _json(result), now(), grant_id, step["ordinal"]))
                    if result["state"] != "success":
                        state = "manual" if result["state"] == "unknown" else "failed"
                        break
            except (CouncilError, ActionError) as exc:
                state = "failed"
                results.append({"state": "blocked", "error": exc.code, "detail": str(exc)})
            except asyncio.CancelledError:
                # A cancellation during network dispatch is not proof that no
                # write happened. Startup recovery preserves the same barrier.
                self._manual(plan, "execution_cancelled_or_unknown")
                self.db.execute("UPDATE council_grants SET state='manual',finished_at=? WHERE id=?", (now(), grant_id))
                raise
            except Exception as exc:
                state = "manual"
                results.append({"state": "unknown", "error": type(exc).__name__})
            with self.db.tx() as conn:
                conn.execute("UPDATE council_grants SET state=?,finished_at=?,result_json=? WHERE id=?", (state, now(), _json({"results": results}), grant_id))
                conn.execute("UPDATE council_plans SET state=? WHERE id=?", (state, plan["id"]))
                if state == "manual":
                    self._manual(plan, "execution_unknown")
                self._emit("council_execution_finished", plan["incident_id"], {"grant_id": grant_id, "state": state, "results": results}, "执行完成，等待独立验证" if state == "verifying" else "执行未完成，回奏证据")
            # Verification belongs to Action, never to an LLM. Intermediate
            # operations retain pending verification locks until all writes end.
            for row in self.db.query("SELECT v.id,v.action_id FROM verifications v JOIN actions a ON a.id=v.action_id"
                                     " WHERE a.council_grant_id=? AND v.status='pending'", (grant_id,)):
                asyncio.create_task(self.actions._run_verification(row["id"], row["action_id"]))
            return {"grant_id": grant_id, "plan_id": plan["id"], "state": state, "results": results}

    def finish_verification(self, grant_id: str, *, recovered: bool, evidence: Any = None) -> dict:
        """Read persisted independent verification; caller cannot assert recovery."""
        with self.db.tx() as conn:
            grant = conn.execute("SELECT * FROM council_grants WHERE id=?", (grant_id,)).fetchone()
            if not grant or grant["state"] != "verifying":
                raise CouncilError("grant_not_verifying")
            rows = conn.execute("SELECT v.status FROM verifications v JOIN actions a ON a.id=v.action_id WHERE a.council_grant_id=?", (grant_id,)).fetchall()
            if not rows or any(row["status"] == "pending" for row in rows):
                return {"grant_id": grant_id, "state": "verifying"}
            passed = all(row["status"] == "passed" for row in rows)
            state = "completed" if passed else "verification_failed"
            conn.execute("UPDATE council_grants SET state=?,finished_at=? WHERE id=?", (state, now(), grant_id))
            conn.execute("UPDATE council_plans SET state=? WHERE id=?", (state, grant["plan_id"]))
            if passed:
                # A newer independent success can supersede a technical failed
                # validation on this same target and generation. It never
                # adjudicates an uncertain write or overrides a human stop.
                plan = conn.execute("SELECT * FROM council_plans WHERE id=?", (grant["plan_id"],)).fetchone()
                inc = conn.execute("SELECT * FROM incidents WHERE id=?", (grant["incident_id"],)).fetchone()
                obj = conn.execute("SELECT * FROM objects WHERE id=? AND asset_id=?", (grant["object_id"], grant["asset_id"])).fetchone()
                same_target = bool(inc and obj and int(inc["generation"] or 1) == grant["generation"]
                    and inc["asset_id"] == grant["asset_id"] and inc["object_id"] in (obj["id"], obj["name"])
                    and resolve_object_name(dict(obj)) == plan["canonical_object"])
                if same_target:
                    from .incidents import IncidentService
                    service = IncidentService(self.db)
                    old = conn.execute("SELECT v.id,v.status FROM verifications v JOIN actions a ON a.id=v.action_id"
                        " WHERE v.incident_id=? AND v.generation=? AND a.asset_id=? AND a.object_id IN (?,?)"
                        " AND v.status IN ('failed','inconclusive') AND v.started_at<=? AND a.council_grant_id!=?",
                        (grant["incident_id"], grant["generation"], grant["asset_id"], obj["id"], obj["name"], grant["created_at"], grant_id)).fetchall()
                    for previous in old:
                        service.clear_action_obligation(grant["incident_id"], previous["id"], kind=f"verify_{previous['status']}")
                    if old:
                        self._emit("council_verification_superseded", grant["incident_id"],
                            {"grant_id": grant_id, "verification_ids": [previous["id"] for previous in old]},
                            "新独立验证已核销同目标旧技术验证义务")
                    legacy = conn.execute("SELECT need_human_reason,stage FROM incidents WHERE id=?", (grant["incident_id"],)).fetchone()
                    reasons = [reason for reason in (legacy["need_human_reason"] or "").splitlines() if reason]
                    superseded = [reason for reason in reasons if reason == "no_runbook_match"
                                  or reason.startswith("no_runbook_match | llm:")]
                    if superseded:
                        remaining = [reason for reason in reasons if reason not in superseded]
                        stage = legacy["stage"]
                        if stage in ("need_human", "awaiting_approval"):
                            stage = "need_human" if remaining else "pending"
                        conn.execute("UPDATE incidents SET need_human=?,need_human_reason=?,stage=?,updated_at=? WHERE id=?",
                            (int(bool(remaining)), "\n".join(remaining), stage, now(), grant["incident_id"]))
                        self._emit("council_legacy_obligation_superseded", grant["incident_id"],
                            {"grant_id": grant_id, "generation": grant["generation"], "reasons": superseded},
                            "自治修复独立验证通过，已核销旧 Runbook 能力不足义务")
                    service.reconcile(grant["incident_id"], resolution_basis=f"council_verification:{grant_id}")
            self._emit("council_verification_finished", grant["incident_id"], {"grant_id": grant_id, "state": state, "verification_passed": passed}, "回奏：独立验证通过" if passed else "回奏：验证未通过，继续调查")
        return {"grant_id": grant_id, "state": state, "verification_passed": passed}

    def recover_inflight(self) -> dict:
        counts = {"reviews_interrupted": 0, "executions_held": 0, "grants_revoked": 0}
        with self.db.tx() as conn:
            for review in conn.execute("SELECT * FROM council_reviews WHERE state='pending'").fetchall():
                self.record_review(review["id"], error="process_restarted_during_review")
                counts["reviews_interrupted"] += 1
            for plan in conn.execute("SELECT * FROM council_plans WHERE state IN ('drafted','reviewing')").fetchall():
                self.tally(plan["id"])
                conn.execute("UPDATE council_plans SET state='interrupted' WHERE id=? AND state IN ('drafted','reviewing')", (plan["id"],))
            for grant in conn.execute("SELECT * FROM council_grants WHERE state IN ('executing','granted')").fetchall():
                plan = conn.execute("SELECT * FROM council_plans WHERE id=?", (grant["plan_id"],)).fetchone()
                if grant["state"] == "executing":
                    conn.execute("UPDATE actions SET state='unknown',result_detail='council_restart_recovery',finished_at=? WHERE council_grant_id=? AND state='dispatched'", (now(), grant["id"]))
                    conn.execute("UPDATE actions SET state='cancelled',result_detail='council_restart_recovery',finished_at=? WHERE council_grant_id=? AND state IN ('proposed','approved')", (now(), grant["id"]))
                    self._manual(plan, "restart_during_execution_no_replay")
                    counts["executions_held"] += 1
                    state = "manual"
                else:
                    counts["grants_revoked"] += 1
                    state = "revoked"
                conn.execute("UPDATE council_grants SET state=?,finished_at=? WHERE id=?", (state, now(), grant["id"]))
                conn.execute("UPDATE council_plans SET state=? WHERE id=?", (state, plan["id"]))
                self._emit("council_restart_recovery", plan["incident_id"], {"grant_id": grant["id"], "state": state}, "重启恢复：未完成授权不自动重放")
        return counts

    @staticmethod
    def _review_dict(row: Any) -> dict:
        result = dict(row)
        result["approve"] = bool(result["approve"]) if result["approve"] is not None else None
        result["missing_evidence"] = json.loads(result.pop("missing_json"))
        return result

    def snapshot(self, incident_id: str) -> dict:
        inc = self.db.query_one("SELECT generation FROM incidents WHERE id=?", (incident_id,))
        gen = int(inc["generation"] or 1) if inc else 0
        goals = [dict(r) for r in self.db.query("SELECT * FROM council_goals WHERE incident_id=? ORDER BY created_at", (incident_id,))]
        plans = []
        for row in self.db.query("SELECT id FROM council_plans WHERE incident_id=? ORDER BY created_at DESC", (incident_id,)):
            p = self.get_plan(row["id"])
            p["reviews"] = [self._review_dict(r) for r in self.db.query("SELECT * FROM council_reviews WHERE plan_id=? ORDER BY role", (p["id"],))]
            ballot = self.db.query_one("SELECT * FROM council_ballots WHERE plan_id=?", (p["id"],))
            p["ballot"] = dict(ballot) if ballot else None
            grant = self.db.query_one("SELECT * FROM council_grants WHERE plan_id=?", (p["id"],))
            p["grant"] = dict(grant) if grant else None
            if grant:
                p["grant"]["result"] = json.loads(p["grant"].pop("result_json"))
                p["grant"]["steps"] = []
                for step in self.db.query("SELECT * FROM council_steps WHERE grant_id=? ORDER BY ordinal", (grant["id"],)):
                    s = dict(step)
                    s["result"] = json.loads(s.pop("result_json"))
                    p["grant"]["steps"].append(s)
            plans.append(p)
        for goal in goals:
            goal["manual_required"] = bool(goal["manual_required"])
        return {"plans": plans, "goals": goals, "current_generation": gen,
                "manual_required": any(g["manual_required"] and g["generation"] == gen for g in goals)}
