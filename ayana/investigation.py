"""目标化只读调查：固定模板 + 能力 → NT probe。

- 必须通过 Policy
- 对象必须已登记（不构造临时对象）
- 结果带来源与时间
"""

from __future__ import annotations

import json
from typing import Any

from .capabilities import (
    ObjectBindingError,
    build_probe_plans,
    get_capability,
    object_matches_capability,
)
from .db import Database, new_id, now
from .knowledge import KnowledgeBase
from .ntsafe import IdentityGate, NTClient, NTResult
from .policy import Policy
from .prom import PromClient, summarize_probe


class InvestigationError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.detail = message
        super().__init__(f"{code}: {message}" if message else code)


class InvestigationService:
    def __init__(
        self,
        db: Database,
        nt: NTClient,
        gate: IdentityGate,
        prom: PromClient,
        policy: Policy,
        knowledge: KnowledgeBase | None = None,
    ):
        self.db = db
        self.nt = nt
        self.gate = gate
        self.prom = prom
        self.policy = policy
        self.knowledge = knowledge or KnowledgeBase(db)

    async def run(
        self,
        *,
        asset_id: str,
        object_id: str = "",
        capability: str = "asset.summary",
        params: dict | None = None,
        incident_id: str = "",
        actor_type: str = "web_user",
        actor_id: str = "system",
    ) -> dict[str, Any]:
        inv_id = new_id("inv")
        self.db.execute(
            "INSERT INTO investigations(id, incident_id, asset_id, object_id, status, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (inv_id, incident_id, asset_id, object_id, "running", now()),
        )
        try:
            return await self._run_inner(
                inv_id,
                asset_id=asset_id,
                object_id=object_id,
                capability=capability,
                params=params or {},
                incident_id=incident_id,
                actor_type=actor_type,
                actor_id=actor_id,
            )
        except Exception as e:
            self._finish(inv_id, "failed", [], str(e)[:500])
            if isinstance(e, InvestigationError):
                return {"id": inv_id, "ok": False, "error": e.code, "detail": e.detail}
            return {"id": inv_id, "ok": False, "error": str(e)}

    async def _run_inner(
        self,
        inv_id: str,
        *,
        asset_id: str,
        object_id: str,
        capability: str,
        params: dict,
        incident_id: str,
        actor_type: str,
        actor_id: str,
    ) -> dict[str, Any]:
        # 统一授权（资产级能力允许 object_id 为空）
        obj = self._resolve_object(asset_id, object_id) if object_id else None
        policy_object = (obj or {}).get("id") or object_id or "*"
        decision = self.policy.check(
            subject_type=actor_type,
            subject_id=actor_id,
            capability=capability,
            asset_id=asset_id,
            object_id=policy_object,
        )
        if not decision["allowed"]:
            raise InvestigationError("denied", decision["reason"])

        try:
            cap = get_capability(capability)
        except KeyError as e:
            raise InvestigationError("unknown_capability", capability) from e
        if cap.kind != "read":
            raise InvestigationError("not_read_capability", capability)

        binding = self.gate.get(asset_id)
        evidence: list[dict[str, Any]] = []

        # 业务语义知识（长期知识，不含实时状态）
        knol = self.knowledge.investigation_context(asset_id, object_id)

        if capability == "probe.status":
            service = (obj or {}).get("name") or params.get("service") or object_id or ""
            data = await self.prom.probe_success(asset_id, service)
            summary = summarize_probe(data)
            evidence.append(
                {
                    "source": "prometheus",
                    "capability": capability,
                    "observed_at": now(),
                    "summary": summary,
                    "raw": data,
                }
            )
            self._finish(inv_id, "done", evidence, summary.get("state", ""))
            self._audit(inv_id, asset_id, object_id, capability, actor_type, actor_id, incident_id)
            return {
                "id": inv_id,
                "ok": True,
                "evidence": evidence,
                "summary": summary,
                "knowledge": knol,
            }

        # 资产级能力：不需要 Object，可直接对 Asset 执行
        asset_level = {"asset.summary", "disk.usage", "memory.available", "load.current"}
        if capability in asset_level:
            obj = obj or {"kind": "asset", "name": asset_id}
        elif obj is None:
            raise InvestigationError("object_not_registered", object_id or "-")

        try:
            object_matches_capability(capability, obj)
            plans = build_probe_plans(capability, obj)
        except ObjectBindingError as e:
            raise InvestigationError("object_binding", str(e)) from e
        except Exception as e:
            raise InvestigationError("bad_plan", str(e)) from e

        for tokens in plans:
            res: NTResult = await self.nt.probe(binding.read_alias, tokens, timeout=cap.timeout_sec)
            evidence.append(
                {
                    "source": "nt_probe",
                    "capability": capability,
                    "cmd": tokens,
                    "ok": res.ok,
                    "returncode": res.returncode,
                    "timed_out": res.timed_out,
                    "observed_at": now(),
                    "output": res.clipped(cap.max_output),
                }
            )
        self._finish(inv_id, "done", evidence, "")
        self._audit(inv_id, asset_id, object_id, capability, actor_type, actor_id, incident_id)
        self.db.event(
            "investigation",
            f"investigate {asset_id} {capability}",
            incident_id=incident_id,
            payload={
                "investigation_id": inv_id,
                "capability": capability,
                "knowledge_ids": [d.get("id") for d in (knol.get("docs") or [])],
            },
        )
        return {"id": inv_id, "ok": True, "evidence": evidence, "knowledge": knol}

    def _resolve_object(self, asset_id: str, object_id: str) -> dict | None:
        if not object_id:
            return None
        row = self.db.query_one(
            "SELECT * FROM objects WHERE asset_id=? AND (id=? OR name=?)",
            (asset_id, object_id, object_id),
        )
        return dict(row) if row else None

    def _finish(self, inv_id: str, status: str, evidence: list, conclusion: str) -> None:
        self.db.execute(
            "UPDATE investigations SET status=?, evidence_json=?, conclusion=?, finished_at=?"
            " WHERE id=?",
            (
                status,
                json.dumps(evidence, ensure_ascii=False),
                conclusion,
                now(),
                inv_id,
            ),
        )

    def _audit(
        self,
        inv_id: str,
        asset_id: str,
        object_id: str,
        capability: str,
        actor_type: str,
        actor_id: str,
        incident_id: str,
    ) -> None:
        self.db.audit(
            actor_type,
            actor_id,
            "investigation",
            asset_id=asset_id,
            object_id=object_id,
            detail={
                "investigation_id": inv_id,
                "capability": capability,
                "incident_id": incident_id,
            },
        )

    def list_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM investigations WHERE incident_id=? ORDER BY created_at DESC",
                (incident_id,),
            )
        ]
