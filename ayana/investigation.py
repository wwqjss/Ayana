"""证据驱动、对象化、有限循环的只读调查（P1-02）。

流程：
  Incident → 初始证据 → hypothesis → evidence gap
  → 选择受限只读 capability → 新证据 → 更新 hypothesis
  → 继续或停止 → 结构化 Investigation result

硬约束：
- 最多 3 轮 / 每轮最多 2 工具 / 总 6 次工具 / 约 90s deadline
- LLM 只能提出“下一步想获取什么证据”；程序验证工具请求
- 只读 capability + 登记对象；写能力/任意 shell/改 Policy 一律拒绝
- transport / observed / interpretation 分层，interpretation 不得覆盖 observed
- transport 失败 ≠ 服务失败；systemctl inactive 是有效负观察
"""

from __future__ import annotations

import json
import time
from typing import Any

from .capabilities import (
    CAPABILITIES,
    ObjectBindingError,
    build_probe_plans,
    get_capability,
    object_matches_capability,
)
from .db import Database, new_id, now
from .knowledge import KnowledgeBase
from .exec_facts import NTResult
from .access import AccessControl as Policy
from .prom import PromClient, summarize_probe

# 停止条件（禁止“模型觉得差不多了”作为唯一条件）
STOP_ENOUGH = "enough_evidence"
STOP_NEED_MORE = "need_more_evidence"
STOP_NEED_HUMAN = "need_human"
STOP_TRANSPORT = "transport_unavailable"
STOP_DEADLINE = "deadline_reached"
STOP_BUDGET = "tool_budget_exhausted"
STOP_NO_PROGRESS = "no_progress"
STOP_REJECTED = "all_tools_rejected"

# 证据分类
EV_OBSERVED = "observed"
EV_TOOL_FAILURE = "tool_failure"
EV_TRANSPORT_FAILURE = "transport_failure"
EV_UNKNOWN = "unknown"

# 有限循环预算
MAX_ROUNDS = 3
MAX_TOOLS_PER_ROUND = 2
MAX_TOOL_CALLS = 6
DEFAULT_DEADLINE_SEC = 90.0

# systemd is-active 等：rc 0/3/4 表示有效观察（含负观察）
VALID_OBSERVE_RC = {0, 3, 4}


class InvestigationError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.detail = message
        super().__init__(f"{code}: {message}" if message else code)


def _safe_name(token: str) -> bool:
    return bool(token) and not any(ch in token for ch in " ;|&$`\n\t")


def classify_transport(res: NTResult) -> dict[str, Any]:
    """transport 层：SSH/NT 是否成功。与业务是否健康无关。"""
    detail = (getattr(res, "output", "") or "")[:400]
    low = detail.lower()
    timed_out = bool(getattr(res, "timed_out", False))
    rc = getattr(res, "returncode", None)
    if timed_out:
        return {"ok": False, "returncode": rc, "timed_out": True, "error": "timeout", "layer": EV_TRANSPORT_FAILURE}
    if rc is not None and rc < 0:
        return {"ok": False, "returncode": rc, "timed_out": False, "error": f"signal:{rc}", "layer": EV_TRANSPORT_FAILURE}
    if rc == 255 or any(
        h in low
        for h in (
            "connection reset",
            "connection refused",
            "broken pipe",
            "no route to host",
            "network is unreachable",
            "connection aborted",
            "connection closed",
        )
    ):
        return {"ok": False, "returncode": rc, "timed_out": False, "error": detail[:200] or "transport", "layer": EV_TRANSPORT_FAILURE}
    return {"ok": True, "returncode": rc, "timed_out": False, "error": "", "layer": EV_OBSERVED}


def classify_evidence(capability: str, tokens: list[str], res: NTResult) -> dict[str, Any]:
    """把一次工具结果分成 transport / observed / tool_failure。

    - transport 失败 → 没有观察，不能解释为服务失败
    - 工具契约内的负观察（如 is-active inactive rc=3）→ observed
    - 工具本身失败（语法/权限/未知命令）→ tool_failure
    """
    transport = classify_transport(res)
    if transport["layer"] == EV_TRANSPORT_FAILURE:
        return {
            "classification": EV_TRANSPORT_FAILURE,
            "transport": transport,
            "observed": None,
        }

    output = (getattr(res, "output", "") or "")
    rc = transport.get("returncode")
    cap_kind = "other"
    if capability.startswith("service.status") or tokens[:2] == ["systemctl", "is-active"]:
        cap_kind = "service_status"
    elif capability.startswith("service.logs") or (tokens and tokens[0] == "journalctl"):
        cap_kind = "service_logs"
    elif capability.startswith("port."):
        cap_kind = "port"
    elif capability.startswith("asset.") or capability in ("disk.usage", "memory.available", "load.current"):
        cap_kind = "asset"
    elif capability.startswith("probe."):
        cap_kind = "probe"

    # systemctl is-active: 0=active 3=inactive/failed 4=unknown → 有效观察
    if cap_kind == "service_status" and tokens[:2] == ["systemctl", "is-active"]:
        state = output.strip().splitlines()[0].strip() if output.strip() else ""
        if rc in VALID_OBSERVE_RC or state in ("active", "inactive", "failed", "activating", "degraded", "unknown"):
            return {
                "classification": EV_OBSERVED,
                "transport": transport,
                "observed": {
                    "kind": "service_state",
                    "service_state": state or "unknown",
                    "healthy": state == "active",
                    "raw_output": output[:2000],
                    "truncated": len(output) > 2000,
                },
            }
        return {
            "classification": EV_TOOL_FAILURE,
            "transport": transport,
            "observed": {"kind": "tool_failure", "raw_output": output[:1000], "truncated": False},
        }

    if cap_kind == "service_status" and tokens[:2] == ["systemctl", "is-enabled"]:
        state = output.strip().splitlines()[0].strip() if output.strip() else ""
        return {
            "classification": EV_OBSERVED if rc in VALID_OBSERVE_RC or state else EV_TOOL_FAILURE,
            "transport": transport,
            "observed": {
                "kind": "service_enabled",
                "enabled_state": state or "unknown",
                "raw_output": output[:1000],
                "truncated": False,
            },
        }

    if cap_kind == "service_status" and tokens[:1] == ["systemctl"] and tokens[1:2] == ["show"]:
        return {
            "classification": EV_OBSERVED if transport["ok"] and rc == 0 else (
                EV_OBSERVED if output.strip() else EV_TOOL_FAILURE
            ),
            "transport": transport,
            "observed": {
                "kind": "service_props",
                "raw_output": output[:2000],
                "truncated": len(output) > 2000,
            },
        }

    if cap_kind == "service_logs":
        # journalctl/docker logs：工具成功即拿到日志片段；空日志也是观察
        return {
            "classification": EV_OBSERVED if transport["ok"] else EV_TOOL_FAILURE,
            "transport": transport,
            "observed": {
                "kind": "log_excerpt",
                "lines": len(output.splitlines()),
                "raw_output": output[:4000],
                "truncated": len(output) > 4000,
            },
        }

    if cap_kind == "port":
        # ss：输出含端口 → listening；rc=0 空/无匹配 → valid negative
        return {
            "classification": EV_OBSERVED if transport["ok"] else EV_TOOL_FAILURE,
            "transport": transport,
            "observed": {
                "kind": "port_listen",
                "listening": bool(output.strip()) and ("LISTEN" in output or "UNCONN" in output or ":" in output),
                "raw_output": output[:2000],
                "truncated": len(output) > 2000,
            },
        }

    # 默认：transport ok 即 observed（含负观察），rc 异常且无输出 → tool_failure
    if transport["ok"] and (rc == 0 or output.strip()):
        return {
            "classification": EV_OBSERVED,
            "transport": transport,
            "observed": {
                "kind": "raw",
                "raw_output": output[:3000],
                "truncated": len(output) > 3000,
            },
        }
    return {
        "classification": EV_TOOL_FAILURE if transport["ok"] else EV_UNKNOWN,
        "transport": transport,
        "observed": {
            "kind": "tool_failure" if transport["ok"] else "unknown",
            "raw_output": output[:1000],
            "truncated": False,
        },
    }


def default_tools_for_object(obj: dict | None, asset_id: str) -> list[dict[str, str]]:
    """LLM 不可用时的确定性只读调查计划（对象类型驱动）。"""
    obj = obj or {}
    kind = obj.get("kind") or ""
    name = obj.get("name") or ""
    out: list[dict[str, str]] = []
    if kind == "service":
        out.append({"capability": "service.status", "object_id": name, "why": "service state"})
        out.append({"capability": "service.logs", "object_id": name, "why": "recent logs"})
        if name in ("mysql", "mysqld", "mariadb") or "mysql" in name:
            out.append({"capability": "mysql.replica.status", "object_id": name,
                        "why": "replica IO/SQL threads; instance health is not replica health"})
        if obj.get("port"):
            out.append({"capability": "port.listen", "object_id": name, "why": "listening port"})
        if obj.get("external_probe"):
            out.append({"capability": "probe.status", "object_id": name, "why": "external probe"})
    elif kind == "container":
        out.append({"capability": "service.status", "object_id": name, "why": "container state"})
        out.append({"capability": "service.logs", "object_id": name, "why": "container logs"})
    elif kind == "port":
        out.append({"capability": "port.listen", "object_id": name, "why": "port state"})
    elif kind == "probe":
        out.append({"capability": "probe.status", "object_id": name, "why": "external probe"})
    else:
        out.append({"capability": "asset.summary", "object_id": "", "why": "host summary"})
        out.append({"capability": "disk.usage", "object_id": "", "why": "disk"})
    return out


class InvestigationService:
    def __init__(
        self,
        db: Database,
        nt: Any,
        gate: Any,
        prom: PromClient,
        policy: Policy,
        knowledge: KnowledgeBase | None = None,
        *,
        transport: Any | None = None,
        max_rounds: int = MAX_ROUNDS,
        max_tool_calls: int = MAX_TOOL_CALLS,
        deadline_sec: float = DEFAULT_DEADLINE_SEC,
        llm: Any = None,
    ):
        self.db = db
        self.nt = nt
        self.gate = gate
        self.prom = prom
        self.policy = policy
        self.transport = transport if transport is not None else nt
        self.knowledge = knowledge or KnowledgeBase(db)
        self.max_rounds = max(1, int(max_rounds))
        self.max_tool_calls = max(1, int(max_tool_calls))
        self.deadline_sec = float(deadline_sec)
        self.llm = llm

    async def _probe_channel(self, asset_id: str, tokens: list[str], timeout: float | None = None):
        if self.transport is not None:
            return await self.transport.probe(asset_id, tokens, timeout=timeout)
        raise RuntimeError("ssh_required: native SSH transport not configured")

    # ------------------------------------------------------------------
    # 一次性手动调查（Web / QQ）：仍走同一证据模型
    # ------------------------------------------------------------------

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
        started = time.time()
        try:
            knol = self.knowledge.investigation_context(asset_id, object_id)
            obj = self._resolve_object(asset_id, object_id) if object_id else None
            err, plans = self._validate_tool(
                capability=capability,
                asset_id=asset_id,
                object_id=object_id,
                obj=obj,
                actor_type=actor_type,
                actor_id=actor_id,
            )
            if err:
                self._finish(
                    inv_id,
                    "done",
                    [],
                    conclusion="denied",
                    stop_reason=STOP_REJECTED,
                    facts=[],
                    hypotheses=[],
                    missing=[err],
                    knowledge=knol,
                    rounds=1,
                    tool_calls=0,
                )
                return {
                    "id": inv_id,
                    "ok": False,
                    "error": err,
                    "evidence": [],
                    "knowledge": knol,
                    "stop_reason": STOP_REJECTED,
                }
            evidence = await self._exec_plans(
                capability=capability,
                asset_id=asset_id,
                object_id=object_id or (obj or {}).get("id") or "",
                plans=plans,
                inv_id=inv_id,
                round_no=1,
            )
            self._finish(
                inv_id,
                "done",
                evidence,
                conclusion="",
                stop_reason=STOP_ENOUGH,
                facts=self._facts_from(evidence),
                hypotheses=[],
                missing=[],
                knowledge=knol,
                rounds=1,
                tool_calls=len(evidence),
            )
            self._audit(inv_id, asset_id, object_id, capability, actor_type, actor_id, incident_id)
            self.db.event(
                "investigation",
                f"investigate {asset_id} {capability}",
                incident_id=incident_id,
                payload={
                    "investigation_id": inv_id,
                    "capability": capability,
                    "knowledge_refs": knol.get("knowledge_refs") or [],
                    "knowledge_revision": knol.get("revision", ""),
                },
            )
            return {
                "id": inv_id,
                "ok": True,
                "evidence": evidence,
                "knowledge": knol,
                "stop_reason": STOP_ENOUGH,
                "facts": self._facts_from(evidence),
            }
        except Exception as e:
            self._finish(
                inv_id,
                "failed",
                [],
                conclusion=str(e)[:500],
                stop_reason=STOP_NEED_HUMAN,
                facts=[],
                hypotheses=[],
                missing=[],
                knowledge=None,
                rounds=0,
                tool_calls=0,
            )
            if isinstance(e, InvestigationError):
                return {"id": inv_id, "ok": False, "error": e.code, "detail": e.detail}
            return {"id": inv_id, "ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    # 有限循环（Agent / Incident）
    # ------------------------------------------------------------------

    async def run_loop(
        self,
        *,
        asset_id: str,
        object_id: str = "",
        incident_id: str = "",
        actor_type: str = "auto_rule",
        actor_id: str = "agent",
        extra_failures: list[str] | None = None,
        max_rounds: int | None = None,
        deadline_sec: float | None = None,
    ) -> dict[str, Any]:
        inv_id = new_id("inv")
        self.db.execute(
            "INSERT INTO investigations(id, incident_id, asset_id, object_id, status, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (inv_id, incident_id, asset_id, object_id, "running", now()),
        )
        started = time.time()
        deadline = started + float(deadline_sec or self.deadline_sec)
        rounds_limit = max(1, int(max_rounds or self.max_rounds))
        tool_budget = min(self.max_tool_calls, rounds_limit * MAX_TOOLS_PER_ROUND)

        knol = self.knowledge.investigation_context(
            asset_id, object_id, extra_failures=extra_failures
        )
        all_evidence: list[dict[str, Any]] = []
        rejected_tools: list[dict[str, Any]] = []
        hypotheses: list[dict[str, Any]] = []
        missing: list[str] = []
        stop_reason = STOP_NEED_MORE
        tool_calls = 0
        rounds = 0
        used_tools: set[str] = set()

        obj = self._resolve_object(asset_id, object_id) if object_id else None

        # Round 1 起点：确定性初始证据（对象驱动，不靠 LLM）
        pending = default_tools_for_object(obj, asset_id)
        if not pending:
            pending = [{"capability": "asset.summary", "object_id": "", "why": "host"}]

        for rnd in range(1, rounds_limit + 1):
            rounds = rnd
            if time.time() >= deadline:
                stop_reason = STOP_DEADLINE
                break
            if tool_calls >= tool_budget:
                stop_reason = STOP_BUDGET
                break

            round_tools: list[dict[str, Any]] = []
            if rnd == 1:
                round_tools = pending[:MAX_TOOLS_PER_ROUND]
                pending = pending[MAX_TOOLS_PER_ROUND:]
            else:
                # LLM 提议下一步（仅建议）；程序验证
                proposal = await self._llm_propose(
                    asset_id=asset_id,
                    object_id=object_id,
                    evidence=all_evidence,
                    hypotheses=hypotheses,
                    missing=missing,
                    knol=knol,
                    extra_failures=extra_failures or [],
                )
                if proposal.get("stop") and proposal.get("stop_reason"):
                    stop_reason = self._norm_stop(proposal.get("stop_reason"))
                    if stop_reason != STOP_NEED_MORE:
                        break
                hypotheses = proposal.get("hypotheses") or hypotheses
                missing = proposal.get("missing_evidence") or missing
                llm_tools = proposal.get("next_tools") or []
                if not llm_tools:
                    llm_tools = pending[:MAX_TOOLS_PER_ROUND]
                    pending = pending[MAX_TOOLS_PER_ROUND:]
                round_tools = llm_tools[:MAX_TOOLS_PER_ROUND]

            if not round_tools:
                stop_reason = STOP_NO_PROGRESS if tool_calls else STOP_ENOUGH
                break

            executed_this_round = 0
            rejected = 0
            for req in round_tools:
                if tool_calls >= tool_budget:
                    stop_reason = STOP_BUDGET
                    break
                if executed_this_round >= MAX_TOOLS_PER_ROUND:
                    break
                if time.time() >= deadline:
                    stop_reason = STOP_DEADLINE
                    break

                cap_name = (req or {}).get("capability") or ""
                req_obj = (req or {}).get("object_id") or object_id
                dedup_key = f"{cap_name}:{req_obj}"
                if dedup_key in used_tools:
                    rejected += 1
                    missing.append(f"duplicate_tool_skipped:{dedup_key}")
                    continue

                target_obj = self._resolve_object(asset_id, req_obj) if req_obj else obj
                err, plans = self._validate_tool(
                    capability=cap_name,
                    asset_id=asset_id,
                    object_id=req_obj,
                    obj=target_obj,
                    actor_type=actor_type,
                    actor_id=actor_id,
                )
                if err:
                    # 拒绝该工具请求：记 gap，不进 evidence（避免污染 transport）
                    rejected += 1
                    missing.append(f"tool_rejected:{cap_name}:{err}")
                    rejected_tools.append(
                        {
                            "round": rnd,
                            "capability": cap_name,
                            "object_id": req_obj,
                            "reason": err,
                            "why": (req or {}).get("why", ""),
                        }
                    )
                    continue

                used_tools.add(dedup_key)
                tool_calls += 1
                executed_this_round += 1
                batch = await self._exec_plans(
                    capability=cap_name,
                    asset_id=asset_id,
                    object_id=req_obj,
                    plans=plans,
                    inv_id=inv_id,
                    round_no=rnd,
                )
                all_evidence.extend(batch)

            # 每轮结束后判断
            summary = self._summarize(all_evidence)
            if summary["transport_failures"] and not summary["observations"]:
                stop_reason = STOP_TRANSPORT
                break
            if summary["observations"] and not missing and rnd >= 2:
                stop_reason = STOP_ENOUGH
                break
            if rejected and executed_this_round == 0 and not pending:
                stop_reason = STOP_REJECTED
                break
            if tool_calls >= tool_budget:
                stop_reason = STOP_BUDGET
                break
            if time.time() >= deadline:
                stop_reason = STOP_DEADLINE
                break

        # 最终结构化结论（interpretation 不覆盖 observed）
        facts = self._facts_from(all_evidence)
        summary = self._summarize(all_evidence)
        if stop_reason == STOP_NEED_MORE and summary["observations"]:
            stop_reason = STOP_ENOUGH
        if stop_reason == STOP_ENOUGH and not summary["observations"]:
            stop_reason = STOP_NEED_HUMAN

        # 全工具失败 / 全 transport 失败 → 不得高置信根因
        confidence = "low"
        if summary["observations"] and summary["transport_failures"] == 0 and summary["tool_failures"] == 0:
            confidence = "medium"
        if summary["transport_failures"] and not summary["observations"]:
            confidence = "low"
            stop_reason = STOP_TRANSPORT

        final_hyps = hypotheses or self._deterministic_hypotheses(facts, knol)
        result = {
            "id": inv_id,
            "ok": True,
            "evidence": all_evidence,
            "rejected_tools": rejected_tools,
            "facts": facts,
            "hypotheses": final_hyps,
            "missing_evidence": missing,
            "confidence": confidence,
            "stop_reason": stop_reason,
            "rounds": rounds,
            "tool_calls": tool_calls,
            "knowledge": knol,
            "knowledge_refs": knol.get("knowledge_refs") or [],
            "knowledge_revision": knol.get("revision", ""),
            "suggested_action": (final_hyps[0].get("suggested_action") if final_hyps else ""),
            "ok_for_auto_write": False,
        }
        self._finish(
            inv_id,
            "done",
            all_evidence,
            conclusion=json.dumps(
                {
                    "stop_reason": stop_reason,
                    "confidence": confidence,
                    "facts": facts[:20],
                    "hypotheses": final_hyps[:5],
                    "missing": missing[:10],
                },
                ensure_ascii=False,
            )[:4000],
            stop_reason=stop_reason,
            facts=facts,
            hypotheses=final_hyps,
            missing=missing,
            knowledge=knol,
            rounds=rounds,
            tool_calls=tool_calls,
        )
        self._audit(inv_id, asset_id, object_id, "investigation.loop", actor_type, actor_id, incident_id)
        self.db.event(
            "investigation",
            f"loop investigate {asset_id} {object_id}",
            incident_id=incident_id,
            payload={
                "investigation_id": inv_id,
                "stop_reason": stop_reason,
                "rounds": rounds,
                "tool_calls": tool_calls,
                "confidence": confidence,
                "knowledge_refs": knol.get("knowledge_refs") or [],
                "knowledge_revision": knol.get("revision", ""),
            },
        )
        return result

    # ------------------------------------------------------------------
    # 工具验证 / 执行
    # ------------------------------------------------------------------

    def _validate_tool(
        self,
        *,
        capability: str,
        asset_id: str,
        object_id: str,
        obj: dict | None,
        actor_type: str,
        actor_id: str,
    ) -> tuple[str, list[list[str]]]:
        """程序验证工具请求。返回 (error_code, plans)。"""
        try:
            cap = get_capability(capability)
        except KeyError:
            return "unknown_capability", []
        if cap.kind != "read":
            return "not_read_capability", []

        policy_object = (obj or {}).get("id") or object_id or "*"
        decision = self.policy.check(
            subject_type=actor_type,
            subject_id=actor_id,
            capability=capability,
            asset_id=asset_id,
            object_id=policy_object,
        )
        if not decision["allowed"]:
            return f"denied:{decision.get('reason', '')}", []

        asset_level = {"asset.summary", "disk.usage", "memory.available", "load.current"}
        if capability in asset_level:
            obj = obj or {"kind": "asset", "name": asset_id, "id": asset_id}
        elif obj is None:
            return "object_not_registered", []

        try:
            object_matches_capability(capability, obj)
            if capability == "probe.status":
                # Prometheus 查询，无 shell plan
                return "", [["prom.probe"]]
            plans = build_probe_plans(capability, obj)
        except ObjectBindingError as e:
            return f"object_binding:{e}", []
        except Exception as e:
            return f"bad_plan:{e}", []
        if not plans:
            return "empty_plan", []
        return "", plans

    async def _exec_plans(
        self,
        *,
        capability: str,
        asset_id: str,
        object_id: str,
        plans: list[list[str]],
        inv_id: str,
        round_no: int,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        identity = asset_id

        if capability == "probe.status":
            service = (object_id or "").split(":")[-1] or object_id
            data = await self.prom.probe_success(asset_id, service)
            summary = summarize_probe(data)
            out.append(
                {
                    "evidence_id": new_id("ev"),
                    "round": round_no,
                    "tool": capability,
                    "capability": capability,
                    "asset_id": asset_id,
                    "object_id": object_id,
                    "source": "prometheus",
                    "observed_at": now(),
                    "classification": EV_OBSERVED,
                    "transport": {"ok": True, "returncode": 0, "timed_out": False, "error": "", "identity": identity},
                    "observed": {
                        "kind": "probe",
                        "summary": summary,
                        "raw": data,
                        "truncated": False,
                    },
                    "interpretation": None,
                }
            )
            return out

        for tokens in plans:
            res: NTResult = await self._probe_channel(asset_id, tokens, timeout=10.0)
            classified = classify_evidence(capability, tokens, res)
            transport = dict(classified.get("transport") or {})
            transport["identity"] = identity
            ev = {
                "evidence_id": new_id("ev"),
                "round": round_no,
                "tool": capability,
                "capability": capability,
                "asset_id": asset_id,
                "object_id": object_id,
                "source": "ssh_probe",
                "cmd": tokens,
                "observed_at": now(),
                "classification": classified["classification"],
                "transport": transport,
                "observed": classified.get("observed"),
                "interpretation": None,
                # 兼容旧字段（agent 读 output）
                "ok": transport.get("ok", False),
                "returncode": transport.get("returncode"),
                "timed_out": transport.get("timed_out", False),
                "output": ((classified.get("observed") or {}).get("raw_output") or (res.output or ""))[:2000],
            }
            out.append(ev)
        return out

    # ------------------------------------------------------------------
    # LLM：只提出下一步证据需求，不决定执行
    # ------------------------------------------------------------------

    async def _llm_propose(
        self,
        *,
        asset_id: str,
        object_id: str,
        evidence: list[dict],
        hypotheses: list[dict],
        missing: list[str],
        knol: dict,
        extra_failures: list[str],
    ) -> dict[str, Any]:
        """LLM 不可用 / timeout / malformed → 空提议，回落确定性计划。"""
        if not self.llm or not getattr(self.llm, "enabled", False):
            return {
                "hypotheses": hypotheses,
                "missing_evidence": missing,
                "next_tools": [],
                "stop": False,
                "stop_reason": "",
            }
        try:
            # 旧第二套 AI 调查已退役：MiMoCode 是唯一 AI 大脑（core-012/013）
            return {
                "hypotheses": hypotheses,
                "missing_evidence": missing,
                "next_tools": [],
                "stop": True,
                "stop_reason": "need_human",
            }
        except Exception:
            return {
                "hypotheses": hypotheses,
                "missing_evidence": missing,
                "next_tools": [],
                "stop": False,
                "stop_reason": "",
            }

    def _parse_llm_proposal(
        self, text: str, *, hypotheses: list, missing: list
    ) -> dict[str, Any]:
        data: dict[str, Any] = {}
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                data = json.loads(text[start : end + 1])
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}

        hyps = data.get("hypotheses") or []
        if not isinstance(hyps, list):
            hyps = []
        clean_hyps = []
        for h in hyps[:5]:
            if isinstance(h, dict):
                clean_hyps.append(
                    {
                        "text": str(h.get("text") or h.get("hypothesis") or "")[:300],
                        "confidence": str(h.get("confidence") or "low")[:20],
                        "supporting": list(h.get("supporting") or [])[:8],
                        "contradicting": list(h.get("contradicting") or [])[:8],
                    }
                )
            elif isinstance(h, str):
                clean_hyps.append({"text": h[:300], "confidence": "low", "supporting": [], "contradicting": []})

        nxt = data.get("next_tools") or []
        if not isinstance(nxt, list):
            nxt = []
        tools = []
        for t in nxt[:MAX_TOOLS_PER_ROUND]:
            if not isinstance(t, dict):
                continue
            tools.append(
                {
                    "capability": str(t.get("capability") or "")[:64],
                    "object_id": str(t.get("object_id") or "")[:64],
                    "why": str(t.get("why") or "")[:200],
                }
            )

        miss = data.get("missing_evidence") or missing
        if not isinstance(miss, list):
            miss = missing

        stop = bool(data.get("stop", False))
        stop_reason = str(data.get("stop_reason") or "")
        return {
            "hypotheses": clean_hyps or hypotheses,
            "missing_evidence": [str(x)[:200] for x in miss[:10]],
            "next_tools": tools,
            "stop": stop,
            "stop_reason": stop_reason,
        }

    # ------------------------------------------------------------------
    # 事实 / 假设
    # ------------------------------------------------------------------

    def _facts_from(self, evidence: list[dict]) -> list[dict[str, Any]]:
        facts = []
        for e in evidence:
            obs = e.get("observed") or {}
            if e.get("classification") == "rejected":
                continue
            if e.get("classification") == EV_TRANSPORT_FAILURE:
                facts.append(
                    {
                        "kind": "transport_failure",
                        "evidence_id": e.get("evidence_id"),
                        "object_id": e.get("object_id"),
                        "tool": e.get("tool"),
                        "detail": (e.get("transport") or {}).get("error", ""),
                        "note": "没有观察，不能解释为服务失败",
                    }
                )
                continue
            if not obs:
                continue
            kind = obs.get("kind") or "raw"
            if kind == "service_state":
                facts.append(
                    {
                        "kind": "service_state",
                        "evidence_id": e.get("evidence_id"),
                        "object_id": e.get("object_id"),
                        "service_state": obs.get("service_state"),
                        "healthy": obs.get("healthy"),
                        "tool": e.get("tool"),
                    }
                )
            elif kind == "port_listen":
                facts.append(
                    {
                        "kind": "port_listen",
                        "evidence_id": e.get("evidence_id"),
                        "object_id": e.get("object_id"),
                        "listening": obs.get("listening"),
                        "tool": e.get("tool"),
                    }
                )
            elif kind == "probe":
                facts.append(
                    {
                        "kind": "probe",
                        "evidence_id": e.get("evidence_id"),
                        "object_id": e.get("object_id"),
                        "summary": obs.get("summary"),
                        "tool": e.get("tool"),
                    }
                )
            elif kind == "log_excerpt":
                facts.append(
                    {
                        "kind": "log_excerpt",
                        "evidence_id": e.get("evidence_id"),
                        "object_id": e.get("object_id"),
                        "lines": obs.get("lines"),
                        "truncated": obs.get("truncated"),
                        "tool": e.get("tool"),
                    }
                )
            else:
                facts.append(
                    {
                        "kind": kind,
                        "evidence_id": e.get("evidence_id"),
                        "object_id": e.get("object_id"),
                        "tool": e.get("tool"),
                        "truncated": obs.get("truncated"),
                    }
                )
        return facts

    def _summarize(self, evidence: list[dict]) -> dict[str, int]:
        s = {
            "observations": 0,
            "transport_failures": 0,
            "tool_failures": 0,
            "rejected": 0,
            "unknown": 0,
        }
        for e in evidence:
            c = e.get("classification")
            if c == EV_OBSERVED:
                s["observations"] += 1
            elif c == EV_TRANSPORT_FAILURE:
                s["transport_failures"] += 1
            elif c == EV_TOOL_FAILURE:
                s["tool_failures"] += 1
            elif c == "rejected":
                s["rejected"] += 1
            else:
                s["unknown"] += 1
        return s

    def _deterministic_hypotheses(self, facts: list[dict], knol: dict) -> list[dict[str, Any]]:
        """无 LLM 时的确定性假设（不授予执行权）。"""
        hyps: list[dict[str, Any]] = []
        states = [f for f in facts if f.get("kind") == "service_state"]
        ports = [f for f in facts if f.get("kind") == "port_listen"]
        probes = [f for f in facts if f.get("kind") == "probe"]
        transports = [f for f in facts if f.get("kind") == "transport_failure"]

        inactive = [f for f in states if f.get("service_state") in ("inactive", "failed")]
        if inactive:
            hyps.append(
                {
                    "text": f"服务处于 {inactive[0].get('service_state')} 状态",
                    "confidence": "medium",
                    "supporting": [f.get("evidence_id") for f in inactive],
                    "contradicting": [],
                    "suggested_action": "check service start conditions / manual start decision",
                }
            )
        active_but_no_port = [
            f for f in ports if f.get("listening") is False
        ]
        if any(f.get("healthy") for f in states) and active_but_no_port:
            hyps.append(
                {
                    "text": "服务进程在但期望端口未监听",
                    "confidence": "medium",
                    "supporting": [f.get("evidence_id") for f in active_but_no_port],
                    "contradicting": [f.get("evidence_id") for f in states if f.get("healthy")],
                    "suggested_action": "inspect listen config / port conflict",
                }
            )
        shared = (knol.get("common") or {}).get("shared_ids") or []
        if shared:
            hyps.append(
                {
                    "text": f"多对象异常共同命中知识 {shared}，优先考虑共同依赖（仅 hypothesis）",
                    "confidence": "low",
                    "supporting": [],
                    "contradicting": [],
                    "suggested_action": "investigate shared dependency first",
                }
            )
        if transports and not states and not ports:
            hyps.append(
                {
                    "text": "调查通道不可用，没有获得目标观察",
                    "confidence": "high",
                    "supporting": [f.get("evidence_id") for f in transports],
                    "contradicting": [],
                    "suggested_action": "check NT/SSH connectivity; need_human",
                }
            )
        if not hyps:
            hyps.append(
                {
                    "text": "证据不足，无法形成可靠根因",
                    "confidence": "low",
                    "supporting": [],
                    "contradicting": [],
                    "suggested_action": "need_human",
                }
            )
        return hyps

    @staticmethod
    def _norm_stop(reason: str) -> str:
        r = (reason or "").strip()
        known = {
            STOP_ENOUGH,
            STOP_NEED_MORE,
            STOP_NEED_HUMAN,
            STOP_TRANSPORT,
            STOP_DEADLINE,
            STOP_BUDGET,
            STOP_NO_PROGRESS,
            STOP_REJECTED,
        }
        return r if r in known else STOP_NEED_MORE

    def _resolve_object(self, asset_id: str, object_id: str) -> dict | None:
        if not object_id:
            return None
        row = self.db.query_one(
            "SELECT * FROM objects WHERE asset_id=? AND (id=? OR name=?)",
            (asset_id, object_id, object_id),
        )
        return dict(row) if row else None

    def _finish(
        self,
        inv_id: str,
        status: str,
        evidence: list,
        *,
        conclusion: str = "",
        stop_reason: str = "",
        facts: list | None = None,
        hypotheses: list | None = None,
        missing: list | None = None,
        knowledge: dict | None = None,
        rounds: int = 0,
        tool_calls: int = 0,
    ) -> None:
        knol = knowledge or {}
        refs = knol.get("knowledge_refs") or []
        self.db.execute(
            "UPDATE investigations SET status=?, evidence_json=?, conclusion=?, finished_at=?,"
            " stop_reason=?, facts_json=?, hypotheses_json=?, missing_json=?,"
            " knowledge_refs_json=?, knowledge_revision=?, rounds=?, tool_calls=?"
            " WHERE id=?",
            (
                status,
                json.dumps(evidence, ensure_ascii=False, default=str)[:200000],
                conclusion,
                now(),
                stop_reason,
                json.dumps(facts or [], ensure_ascii=False)[:50000],
                json.dumps(hypotheses or [], ensure_ascii=False)[:50000],
                json.dumps(missing or [], ensure_ascii=False)[:20000],
                json.dumps(refs, ensure_ascii=False)[:20000],
                str(knol.get("revision") or ""),
                rounds,
                tool_calls,
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
