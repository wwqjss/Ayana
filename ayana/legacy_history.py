"""Read-only access to retired autonomy records; never constructs old clients."""
from __future__ import annotations

import json
from typing import Any


class RetiredAutonomyError(RuntimeError):
    code = "legacy_autonomy_retired"

    def __init__(self, *args, **kwargs):
        super().__init__("Legacy autonomy is permanently retired; historical records are read-only")


def _decode(value: Any, default: Any) -> Any:
    try:
        decoded = json.loads(value)
    except (ValueError, TypeError):
        return default
    return decoded if isinstance(decoded, type(default)) else default


class LegacyHistory:
    def __init__(self, db: Any):
        self.db = db

    def _exists(self, table: str) -> bool:
        return bool(self.db.query_one(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ))

    def public_config(self) -> dict:
        # Retired keys/settings are neither loaded nor decrypted for display.
        return {"enabled": False, "retired": True, "read_only": True,
                "status": "retired", "roles": {}}

    def usage_summary(self, incident_id: str | None = None) -> dict:
        rows = []
        if self._exists("ai_calls"):
            where = " WHERE incident_id=?" if incident_id is not None else ""
            rows = [dict(r) for r in self.db.query(
                "SELECT id,incident_id,generation,role,provider,model,purpose,started_at,finished_at,"
                "status,error,input_tokens,output_tokens,cost_cny,reserved_cny,input_price,output_price,"
                "account_charge_cny FROM ai_calls" + where + " ORDER BY started_at,id",
                (incident_id,) if incident_id is not None else (),
            )]

        def aggregate(items):
            known = sum(r.get("cost_cny") or 0 for r in items)
            unknown = sum(r.get("cost_cny") is None for r in items)
            return {"calls": len(items), "input_tokens": sum(r.get("input_tokens") or 0 for r in items),
                    "output_tokens": sum(r.get("output_tokens") or 0 for r in items),
                    "cost_cny": None if unknown else known, "known_cost_cny": known,
                    "reserved_cny": sum(r.get("reserved_cny") or 0 for r in items),
                    "unknown_usage_calls": unknown, "complete": unknown == 0,
                    "account_charge_cny": None, "cost_basis": "historical_provider_usage_configured_price"}

        roles = sorted({"planner", "reviewer_kimi", "reviewer_deepseek"} | {r["role"] for r in rows})
        providers = sorted({"mimo", "kimi", "deepseek"} | {r["provider"] for r in rows})
        return {"enabled": False, "retired": True, "read_only": True,
                "overall": aggregate(rows),
                "by_role": {role: aggregate([r for r in rows if r["role"] == role]) for role in roles},
                "by_provider": {name: aggregate([r for r in rows if r["provider"] == name]) for name in providers},
                "budget": {"budget_cny": None, "committed_cny": None, "remaining_cny": None,
                           "warning": False, "exhausted": False, "account_balance_cny": None},
                "calls": rows}

    def snapshot(self, incident_id: str) -> dict:
        inc = self.db.query_one("SELECT status,generation FROM incidents WHERE id=?", (incident_id,))
        generation = int(inc["generation"] or 1) if inc else 0
        goals = [dict(r) for r in self.db.query(
            "SELECT * FROM council_goals WHERE incident_id=? ORDER BY created_at,id", (incident_id,)
        )] if self._exists("council_goals") else []
        for goal in goals:
            goal["manual_required"] = bool(goal["manual_required"])
        plans = []
        if self._exists("council_plans"):
            for row in self.db.query(
                "SELECT * FROM council_plans WHERE incident_id=? ORDER BY created_at DESC,id", (incident_id,)
            ):
                plan = dict(row)
                plan["plan"] = _decode(plan.pop("plan_json"), {})
                reviews = []
                if self._exists("council_reviews"):
                    for r in self.db.query("SELECT * FROM council_reviews WHERE plan_id=? ORDER BY role", (plan["id"],)):
                        review = dict(r)
                        review["approve"] = bool(review["approve"]) if review["approve"] is not None else None
                        review["missing_evidence"] = _decode(review.pop("missing_json"), [])
                        reviews.append(review)
                plan["reviews"] = reviews
                ballot = self.db.query_one("SELECT * FROM council_ballots WHERE plan_id=?", (plan["id"],)) if self._exists("council_ballots") else None
                plan["ballot"] = dict(ballot) if ballot else None
                grant = self.db.query_one("SELECT * FROM council_grants WHERE plan_id=?", (plan["id"],)) if self._exists("council_grants") else None
                plan["grant"] = dict(grant) if grant else None
                if grant:
                    plan["grant"]["result"] = _decode(plan["grant"].pop("result_json"), {})
                    steps = []
                    if self._exists("council_steps"):
                        for r in self.db.query("SELECT * FROM council_steps WHERE grant_id=? ORDER BY ordinal", (grant["id"],)):
                            step = dict(r)
                            step["result"] = _decode(step.pop("result_json"), {})
                            steps.append(step)
                    plan["grant"]["steps"] = steps
                plans.append(plan)
        state = self.db.query_one(
            "SELECT phase,context_json,next_retry_at FROM autonomy_state WHERE incident_id=? AND generation=?",
            (incident_id, generation),
        ) if self._exists("autonomy_state") else None
        context = _decode(state["context_json"], {}) if state else {}
        verifications = [dict(r) for r in self.db.query(
            "SELECT * FROM verifications WHERE incident_id=? ORDER BY started_at,id", (incident_id,)
        )] if self._exists("verifications") else []
        return {**self.public_config(), "current_generation": generation,
                "plans": plans, "goals": goals,
                "manual_required": any(g["manual_required"] and g["generation"] == generation for g in goals),
                "phase": "closed" if inc and inc["status"] != "open" else (state["phase"] if state else "received"),
                "evidence": context.get("evidence", []), "feedback": context.get("feedback", []),
                "draft": context.get("draft"), "write_barrier": context.get("write_barrier", ""),
                "attempts": context.get("attempts", []), "verifications": verifications,
                "next_retry_at": state["next_retry_at"] if state else 0,
                "last_error": context.get("last_error", "") if inc and inc["status"] == "open" else "",
                "usage": self.usage_summary(incident_id)}
