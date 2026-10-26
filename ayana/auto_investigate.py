"""P4.3 无人值守只读调查闭环。

Alertmanager → Incident → SessionBridge → MiMo(只读) → 结论 → Incident 时间线。

硬约束：
- 只读：写操作在 MCP 执行层被拒（readonly 模式），不靠提示词。
- 单飞：同 Incident 不并发多轮；重复 firing 只补事实。
- 代次：Incident 复发（generation+1）才允许再调查。
- 有界：全局并发、单调查超时、最大轮次、冷却；失败不无限重试。
- 可恢复：状态落 investigation_jobs，重启后租约过期任务置 failed，不永久卡死。
- 调查完成 ≠ 恢复；不自动 close，不触发修复/审批/旧 Council。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .db import new_id, now

log = __import__("logging").getLogger("ayana.auto_investigate")

VALID_JOB_STATUS = {"queued", "running", "done", "failed", "partial", "timeout", "cancelled"}


@dataclass
class InvestConfig:
    enabled: bool = True
    closed_loop: bool = True
    max_concurrent: int = 2
    per_incident_concurrent: int = 1
    timeout_sec: float = 300.0
    max_rounds: int = 3
    cooldown_sec: float = 60.0
    mimo_model: str = ""
    mimo_bin: str = "mimo"
    lease_ttl_sec: float = 600.0
    decision_timeout_sec: float = 180.0

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "InvestConfig":
        d = d or {}
        return cls(
            enabled=bool(d.get("enabled", True)),
            closed_loop=bool(d.get("closed_loop", True)),
            max_concurrent=max(1, int(d.get("max_concurrent") or 2)),
            per_incident_concurrent=max(1, int(d.get("per_incident_concurrent") or 1)),
            timeout_sec=float(d.get("timeout_sec") or 300),
            max_rounds=max(1, int(d.get("max_rounds") or 3)),
            cooldown_sec=float(d.get("cooldown_sec") or 60),
            mimo_model=str(d.get("mimo_model") or ""),
            mimo_bin=str(d.get("mimo_bin") or "mimo"),
            lease_ttl_sec=float(d.get("lease_ttl_sec") or 600),
            decision_timeout_sec=float(d.get("decision_timeout_sec") or 180),
        )


CONCLUSION_PROMPT = """你是值班运维调查助手（只读，禁止修复）。
目标：调查该 Incident，收集证据并给出结构化结论。不要重启服务、不要改配置、不要写文件。

## 软约束（必须遵守）
1. 无进展 3 轮停止：连续 3 轮未产生新证据 → 停止并输出 partial/failed。
2. 同方案失败 2 次停止：同一修复意图不得重复尝试超过 2 次。
3. 证据不足转人工：根因不明或探测无样本 → root_cause=unknown，next_steps 标明需人工。

只允许使用只读 MCP 工具（实际工具名使用下划线）：
- ayana_knowledge_query / ayana_knowledge_get
- ayana_metrics_query
- ayana_incident_list / ayana_incident_get
- ayana_asset_list
- ayana_host_exec（仅 channel=read 且命令必须是只读，如 uptime / systemctl status）
禁止：ayana_host_exec 写模式、ayana_knowledge_upsert、ayana_incident_close、ayana_session_remote、ayana_action_execute。
若工具拒绝写操作，记录该事实，不得绕过。

必须实际调用至少一次上述只读工具，并把工具返回内容写入 facts.evidence；不要编造命令输出或工具结果。

最后必须输出一个 JSON 对象（可包在 ```json 代码块），**放在回答的最末尾**，字段：
{
  "status": "completed|partial|failed|timeout",
  "symptoms": "故障现象",
  "facts": [{"claim": "已确认事实", "evidence": "工具返回的证据来源"}],
  "hypotheses": [{"claim": "可能原因", "confidence": "high|medium|low"}],
  "unconfirmed": ["未确认事项"],
  "next_steps": ["建议的下一步只读/需授权操作"],
  "root_cause": "unknown 或简述（无证据必须 unknown）"
}

要求：事实/推测/建议严格分开；无证据不得写 root_cause 已确认。
"""

# P6.1：调查后的自治决策（写权限受控阶段）。执行仍由 ActionService 完成。
DECISION_PROMPT = """你是值班运维处置计划助手。本阶段只生成计划，不执行修复。
基于调查结论决定是否应修复；禁止调用 action.execute、host.exec 写模式或本机写工具。
Ayana 会在计划返回后统一通过 OpsLoop → ActionService 执行、验证并审计。

## 软约束（必须遵守）
1. 无进展 3 轮停止：连续 3 轮未改善 → decision=human。
2. 同方案失败 2 次停止：同一 plan_sig 不得再选 → decision=human。
3. 证据不足转人工：evidence_ok=false 或 root_cause=unknown 且无明确处置 → decision=human。

只输出一个 JSON 对象（可放 ```json 代码块），放在回答最末尾：
{
  "decision": "execute|human|observe",
  "capability": "service.restart 等（execute 时必填）",
  "object_id": "登记对象 id 或 name",
  "plan_sig": "简短方案签名，如 restart-mysql",
  "reason": "理由",
  "evidence_ok": true,
  "params": {}
}

decision=observe 表示继续观察不写；decision=human 表示转人工并说明缺失证据。
"""


def _extract_json(text: str) -> dict[str, Any] | None:
    """Return the last complete JSON object, including fenced/nested conclusions.

    Track JSON string escapes while balancing braces so braces in evidence do
    not terminate a candidate, and nested objects are never parsed in isolation.
    """
    if not text:
        return None
    result = None
    depth = 0
    start = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if depth == 0:
            if char == "{":
                start = index
                depth = 1
                in_string = False
                escaped = False
            continue
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    data = json.loads(text[start : index + 1])
                except (TypeError, ValueError):
                    continue
                if isinstance(data, dict):
                    result = data
    return result


def _safe_excerpt(text: str, limit: int = 1500) -> str:
    t = (text or "").replace("\x00", "")
    return t if len(t) <= limit else t[:limit] + "…[truncated]"


class AutoInvestigator:
    """调度只读调查。无写权限、无审批、无自动修复。"""

    def __init__(
        self,
        db: Any,
        *,
        knowledge: Any = None,
        mimo: Any = None,
        bridge: Any = None,
        config: InvestConfig | None = None,
        ops_loop: Any = None,
        actions: Any = None,
        incidents: Any = None,
        mimo_write: Any = None,
        readiness_callback: Callable[[], bool] | None = None,
    ):
        self.db = db
        self.knowledge = knowledge
        self.mimo = mimo
        self.bridge = bridge  # SessionBridge（调查阶段，通常 readonly）
        self.config = config or InvestConfig()
        # P6.1 闭环：调查后决策→autonomous 执行→验证→结案
        self.ops_loop = ops_loop
        self.actions = actions
        self.incidents = incidents
        self.mimo_write = mimo_write  # 兼容字段名；运行装配使用只产计划的专用会话
        self.readiness_callback = readiness_callback
        self._sem = asyncio.Semaphore(self.config.max_concurrent)
        self._running: dict[str, asyncio.Task] = {}
        self._stop = asyncio.Event()

    # ---- 队列状态 ----

    def _row(self, incident_id: str) -> dict[str, Any] | None:
        r = self.db.query_one(
            "SELECT * FROM investigation_jobs WHERE incident_id=?", (incident_id,)
        )
        return dict(r) if r else None

    def offer(self, incident_id: str, *, generation: int | None = None) -> dict[str, Any]:
        """新 Incident / 复发进入待调查。重复 firing 幂等，不重复排队。"""
        if not self.config.enabled:
            return {"ok": True, "skipped": "disabled"}
        if not incident_id:
            return {"ok": False, "error": "bad_request"}
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not inc:
            return {"ok": False, "error": "incident_not_found"}
        if inc["status"] != "open":
            return {"ok": True, "skipped": "not_open"}
        gen = int(generation if generation is not None else (inc["generation"] or 1))
        t = now()
        row = self._row(incident_id)
        if row:
            if int(row.get("generation") or 1) == gen and row.get("status") in (
                "queued",
                "running",
                "done",
                "partial",
            ):
                # 同代：不重复启动；running 时只让事件事实更新
                return {
                    "ok": True,
                    "action": "noop",
                    "status": row.get("status"),
                    "generation": gen,
                }
            if int(row.get("generation") or 1) == gen and row.get("status") in ("failed", "timeout"):
                # 同代失败：冷却后才允许再排队（防无限重试）
                cooldown_until = float(row.get("updated_at") or 0) + self.config.cooldown_sec
                if t < cooldown_until:
                    return {"ok": True, "action": "cooldown", "retry_after": cooldown_until}
            # New generations get a fresh budget; retries keep the same budget.
            new_generation = int(row.get("generation") or 1) != gen
            with self.db.tx() as conn:
                conn.execute(
                    "UPDATE investigation_jobs SET generation=?, status='queued', rounds=?,"
                    " last_error=?, last_result_status=?, last_conclusion_json=?,"
                    " lease_expires_at=0, updated_at=? WHERE incident_id=?",
                    (
                        gen,
                        0 if new_generation else int(row.get("rounds") or 0),
                        "" if new_generation else (row.get("last_error") or ""),
                        "" if new_generation else (row.get("last_result_status") or ""),
                        "" if new_generation else (row.get("last_conclusion_json") or ""),
                        t,
                        incident_id,
                    ),
                )
            return {"ok": True, "action": "requeued", "generation": gen}
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO investigation_jobs(incident_id, generation, status, rounds,"
                " lease_expires_at, updated_at, created_at) VALUES(?,?,?,?,?,?,?)",
                (incident_id, gen, "queued", 0, 0.0, t, t),
            )
        return {"ok": True, "action": "queued", "generation": gen}

    def recover(self) -> dict[str, Any]:
        """重启恢复：running 且租约过期 → failed（不自动重放，避免卡死/重复）。"""
        t = now()
        rows = self.db.query(
            "SELECT * FROM investigation_jobs WHERE status='running'"
        )
        n = 0
        for r in rows:
            if float(r["lease_expires_at"] or 0) < t:
                self.db.execute(
                    "UPDATE investigation_jobs SET status='failed', last_error=?, updated_at=?"
                    " WHERE incident_id=? AND status='running'",
                    ("lease_expired_after_restart", t, r["incident_id"]),
                )
                n += 1
        return {"ok": True, "expired": n}

    def ready_jobs(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM investigation_jobs WHERE status='queued'"
            " ORDER BY updated_at ASC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    # ---- 执行 ----

    def _runtime_ready(self) -> bool:
        if self.readiness_callback is None:
            return True
        try:
            return bool(self.readiness_callback())
        except Exception:
            return False

    def _incident_is_current(self, incident_id: str, generation: int) -> bool:
        inc = self.db.query_one("SELECT status,generation FROM incidents WHERE id=?", (incident_id,))
        return bool(inc and inc["status"] == "open" and int(inc["generation"] or 1) == generation)

    async def tick_once(self) -> int:
        """处理若干排队任务，返回完成数。"""
        if not self.config.enabled or self._stop.is_set():
            return 0
        # Missing/changed credentials leave jobs queued without consuming a round.
        if not self._runtime_ready():
            return 0
        handled = 0
        for job in self.ready_jobs(limit=self.config.max_concurrent):
            inc_id = job["incident_id"]
            if inc_id in self._running:
                continue
            # 原子占用
            t = now()
            with self.db.tx() as conn:
                cur = conn.execute(
                    "UPDATE investigation_jobs SET status='running', lease_expires_at=?,"
                    " updated_at=? WHERE incident_id=? AND status='queued' AND generation=?",
                    (t + self.config.lease_ttl_sec, t, inc_id, job["generation"]),
                )
                if cur.rowcount != 1:
                    continue
            self._running[inc_id] = asyncio.create_task(self._run_job(inc_id, job))
            handled += 1
            if handled >= self.config.max_concurrent:
                break
        # 收割完成的
        for inc_id, task in list(self._running.items()):
            if task.done():
                await asyncio.gather(task, return_exceptions=True)
                del self._running[inc_id]
        return handled

    async def run_forever(self) -> None:
        self.recover()
        while not self._stop.is_set():
            try:
                await self.tick_once()
            except Exception:
                log.exception("auto_investigate tick failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()

    async def _run_job(self, incident_id: str, job: dict[str, Any]) -> None:
        async with self._sem:
            generation = int(job.get("generation") or 1)
            current = self._row(incident_id)
            if (
                not current
                or int(current.get("generation") or 1) != generation
                or current.get("status") != "running"
            ):
                return
            started = now()
            rounds = int(job.get("rounds") or 0)
            if rounds >= self.config.max_rounds:
                self._finish(incident_id, "failed", generation=generation, reason="max_rounds_exceeded", rounds=rounds)
                return
            try:
                result = await asyncio.wait_for(
                    self._investigate(incident_id, round_no=rounds + 1),
                    timeout=self.config.timeout_sec,
                )
            except asyncio.TimeoutError:
                self._finish(
                    incident_id,
                    "timeout",
                    generation=generation,
                    reason=f"timeout:{self.config.timeout_sec}s",
                    rounds=rounds + 1,
                )
                return
            except Exception as e:  # noqa: BLE001
                self._finish(
                    incident_id,
                    "failed",
                    generation=generation,
                    reason=f"{type(e).__name__}:{e}",
                    rounds=rounds + 1,
                )
                return
            status = result.get("status") or "partial"
            job_status = {
                "completed": "done",
                "partial": "partial",
                "failed": "failed",
                "timeout": "timeout",
            }.get(status, "partial")
            accepted = self._finish(
                incident_id,
                job_status,
                generation=generation,
                conclusion=result,
                rounds=rounds + 1,
                duration=now() - started,
            )
            # P6.1：调查完成 → 同一 Incident 进入自治决策/处置/结案
            if accepted and self.config.closed_loop and status in ("completed", "partial"):
                try:
                    await self._close_loop(incident_id, result, generation=generation)
                except Exception as e:  # noqa: BLE001
                    log.warning("close_loop failed for %s: %s", incident_id, e)
                    try:
                        if self.ops_loop:
                            self.ops_loop.escalate(
                                incident_id, reason="close_loop_error", detail=str(e)[:200]
                            )
                    except Exception:
                        pass

    async def _investigate(self, incident_id: str, *, round_no: int) -> dict[str, Any]:
        if self.mimo is None or self.bridge is None:
            return {
                "status": "failed",
                "symptoms": "",
                "facts": [],
                "hypotheses": [],
                "unconfirmed": ["mimo/bridge unavailable"],
                "next_steps": [],
                "root_cause": "unknown",
            }
        prompt = self._build_invest_prompt(incident_id, round_no=round_no)
        attached = await asyncio.to_thread(
            self.bridge.attach_remote, incident_id,
            title=f"inv:{incident_id}",
            prompt=prompt,
            timeout=self.config.timeout_sec,
        )
        if not attached.get("ok"):
            return {
                "status": "failed",
                "symptoms": "",
                "facts": [],
                "hypotheses": [],
                "unconfirmed": [f"attach_remote failed: {attached.get('error') or attached.get('code')}"],
                "next_steps": [],
                "root_cause": "unknown",
            }
        text = (attached.get("text") or "") if attached.get("action") == "created" else ""
        if attached.get("action") in ("reused",):
            sent = await asyncio.to_thread(
                self.bridge.prompt_remote, incident_id, prompt, timeout=self.config.timeout_sec
            )
            text = (sent.get("text") or "") if sent.get("ok") else (sent.get("message") or sent.get("error") or "")
        parsed = _extract_json(text) or {}
        # Tool result objects and malformed conclusion fields are not success.
        if parsed.get("status") not in ("completed", "partial", "failed", "timeout"):
            parsed = {}
        if any(
            key in parsed and not isinstance(parsed[key], list)
            for key in ("facts", "hypotheses", "unconfirmed", "next_steps")
        ) or any(
            not isinstance(item, dict)
            for key in ("facts", "hypotheses")
            for item in parsed.get(key, [])
        ):
            parsed = {}
        if not parsed:
            # 取最后一段非空文本作摘要（模型可能先出前言再出 JSON）
            tail = ""
            for line in (text or "").strip().splitlines()[::-1]:
                if line.strip():
                    tail = line.strip()
                    break
            return {
                "status": "partial" if text else "failed",
                "symptoms": _safe_excerpt(tail or text, 400),
                "facts": [],
                "hypotheses": [],
                "unconfirmed": ["MiMo 输出未含有效结构化结论 JSON；保留原始摘要"],
                "next_steps": ["人工查看会话记录"],
                "root_cause": "unknown",
                "raw_excerpt": _safe_excerpt(text, 4000),
            }
        has_evidence = any(
            str(fact.get("evidence") or "").strip()
            for fact in parsed.get("facts", [])
        )
        if not has_evidence or not str(parsed.get("root_cause") or "").strip():
            parsed["root_cause"] = "unknown"
        parsed["round"] = round_no
        parsed["remote_session_id"] = attached.get("remote_session_id") or ""
        return parsed

    def _build_invest_prompt(self, incident_id: str, *, round_no: int) -> str:
        inc_row = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        inc = dict(inc_row) if inc_row else {}
        from .settings_admin import PromptSettings
        prompts = PromptSettings(self.db)
        lines = [
            prompts.current("investigation")["text"],
            "\n## 当前生效的运维软约束",
            prompts.current("constraints")["text"],
            f"\n## Incident {incident_id} (round {round_no})",
            f"title: {inc.get('title')}",
            f"asset: {inc.get('asset_id')}  object: {inc.get('object_id')}",
            f"severity: {inc.get('severity')} status: {inc.get('status')}"
            f" stage: {inc.get('stage')}",
            f"generation: {inc.get('generation')}",
        ]
        if self.knowledge is not None:
            try:
                ctx = self.knowledge.investigation_context(
                    inc.get("asset_id") or "", inc.get("object_id") or ""
                )
                text = (ctx.get("context_text") or "").strip()
                lines += ["", "## Knowledge（仅 active 事实）", text or "（无）"]
            except Exception:
                lines += ["", "## Knowledge", "（检索失败）"]
        # 既有时间线摘要
        ev = self.db.query(
            "SELECT type, title, at FROM events WHERE incident_id=? ORDER BY id DESC LIMIT 8",
            (incident_id,),
        )
        if ev:
            lines += ["", "## 近期事件"]
            for e in ev:
                lines.append(f"- [{e['type']}] {e['title']}")
        return "\n".join(lines)

    # ---- P6.1 闭环：调查 → 决策 → autonomous 执行 → 验证 → 结案 ----

    def _build_decision_prompt(self, incident_id: str, conclusion: dict[str, Any]) -> str:
        inc = dict(self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,)) or {})
        from .settings_admin import PromptSettings
        prompts = PromptSettings(self.db)
        return "\n".join(
            [
                prompts.current("decision")["text"],
                "\n## 当前生效的运维软约束",
                prompts.current("constraints")["text"],
                f"\n## Incident {incident_id}",
                f"title: {inc.get('title')}",
                f"asset: {inc.get('asset_id')}  object: {inc.get('object_id')}",
                f"generation: {inc.get('generation')}",
                "",
                "## 调查结论",
                json.dumps(conclusion, ensure_ascii=False, default=str)[:6000],
            ]
        )

    def _parse_decision(self, text: str, conclusion: dict[str, Any]) -> dict[str, Any]:
        data = _extract_json(text or "") or {}
        decision = str(data.get("decision") or "").strip().lower()
        if decision not in ("execute", "human", "observe"):
            # 无合法决策：证据不足 → 人工
            data = {
                "decision": "human",
                "reason": "invalid_or_missing_decision_json",
                "evidence_ok": False,
                "plan_sig": "",
            }
        else:
            data["decision"] = decision
        if decision == "execute":
            if not data.get("capability") or not data.get("object_id"):
                data["decision"] = "human"
                data["reason"] = data.get("reason") or "execute_missing_capability_or_object"
            if data.get("evidence_ok") is not True:
                data["decision"] = "human"
                data["reason"] = data.get("reason") or "evidence_insufficient"
            if not isinstance(data.get("params", {}), dict):
                data["decision"] = "human"
                data["reason"] = "execute_invalid_params"
        if not data.get("plan_sig"):
            data["plan_sig"] = str(data.get("capability") or "plan") + ":" + str(data.get("object_id") or "")
        data["conclusion_root_cause"] = conclusion.get("root_cause") or ""
        return data

    async def _decide_remediation(
        self, incident_id: str, conclusion: dict[str, Any], *, generation: int
    ) -> dict[str, Any]:
        """同一 Incident/Session 进入决策；写权限受控 MCP 会话产出 JSON 计划。"""
        # Deterministic suggestions pass the same evidence/shape validation.
        suggested = conclusion.get("suggested_action") or {}
        if isinstance(suggested, dict) and suggested.get("capability") and suggested.get("object_id"):
            decision = self._parse_decision(json.dumps({
                **suggested, "decision": "execute",
                "reason": suggested.get("reason") or "conclusion_suggested_action",
            }, ensure_ascii=False), conclusion)
            decision["source"] = "conclusion"
            return decision
        client = self.mimo_write or self.mimo
        rid = str(conclusion.get("remote_session_id") or "")
        text = ""
        if client is not None:
            prompt = self._build_decision_prompt(incident_id, conclusion)
            try:
                if rid and hasattr(client, "resume"):
                    sent = await asyncio.to_thread(client.resume, rid, prompt, timeout=self.config.decision_timeout_sec)
                else:
                    sent = await asyncio.to_thread(client.create, title=f"ops:{incident_id}", prompt=prompt,
                                                   timeout=self.config.decision_timeout_sec)
                # Production returns RemoteSession; test adapters may return dict.
                if isinstance(sent, dict):
                    if sent.get("ok") is not False and sent.get("status") != "error":
                        text = str(sent.get("text") or "")
                elif getattr(sent, "status", "active") not in ("error", "timeout"):
                    text = str(getattr(sent, "text", "") or "")
            except Exception as exc:  # noqa: BLE001
                return {
                    "decision": "human", "reason": f"decision_session_failed:{type(exc).__name__}",
                    "evidence_ok": False, "plan_sig": "",
                }
        decision = self._parse_decision(text, conclusion)
        decision["source"] = "mimo_write" if text else "fallback_human"
        return decision

    async def _close_loop(
        self, incident_id: str, conclusion: dict[str, Any], *, generation: int
    ) -> dict[str, Any]:
        """调查后闭环：决策 → ActionService.autonomous → 验证 → 结案 / 转人工。"""
        out: dict[str, Any] = {"incident_id": incident_id, "generation": generation}
        if self.ops_loop is None:
            out["skipped"] = "ops_loop_unavailable"
            return out
        if not self._incident_is_current(incident_id, generation):
            return {**out, "skipped": "incident_changed"}
        if not self._runtime_ready():
            return {**out, "skipped": "provider_not_verified"}
        decision = await self._decide_remediation(incident_id, conclusion, generation=generation)
        out["decision"] = decision
        if not self._incident_is_current(incident_id, generation):
            return {**out, "skipped": "incident_changed"}
        if not self._runtime_ready():
            return {**out, "skipped": "provider_not_verified"}
        kind = decision.get("decision")
        if kind == "observe":
            if self.incidents:
                try:
                    self.incidents.reconcile(incident_id)
                except Exception:
                    pass
            out["result"] = "observed"
            return out
        if kind == "human":
            self.ops_loop.escalate(
                incident_id,
                reason=str(decision.get("reason") or "decision_human")[:120],
                detail=decision,
            )
            out["result"] = "need_human"
            return out
        # execute → ops_loop（记轮次 + autonomous + 验证）
        inc_row = self.db.query_one("SELECT asset_id FROM incidents WHERE id=?", (incident_id,))
        asset_id = str(decision.get("asset_id") or "")
        if not asset_id and inc_row is not None:
            asset_id = str(inc_row["asset_id"] or "")
        res = await self.ops_loop.run_action_and_verify(
            incident_id=incident_id,
            asset_id=asset_id,
            object_id=str(decision.get("object_id") or ""),
            capability=str(decision.get("capability") or ""),
            params=decision.get("params") or {},
            reason=str(decision.get("reason") or "closed_loop_remediate")[:200],
            plan_sig=str(decision.get("plan_sig") or ""),
        )
        out["action"] = res
        if res.get("approval_required"):
            out["result"] = "awaiting_approval"
            out["action_id"] = res.get("action_id") or ""
            # 不 escalate：等人批后再继续
            return out
        closed = self.ops_loop.maybe_close(incident_id)
        out["close"] = closed
        # 证据不足 / 失败且未恢复 → 转人工
        if not res.get("ok") and not closed.get("closed"):
            st = self.ops_loop.status(incident_id)
            if st.get("stop") or st.get("status") == "need_human" or not res.get("ok"):
                if st.get("status") != "need_human":
                    self.ops_loop.escalate(
                        incident_id,
                        reason="remediation_failed_or_unverified",
                        detail={"action": res, "close": closed},
                    )
        return out

    def _finish(
        self,
        incident_id: str,
        status: str,
        *,
        generation: int,
        conclusion: dict[str, Any] | None = None,
        reason: str = "",
        rounds: int = 0,
        duration: float = 0.0,
    ) -> bool:
        t = now()
        payload = conclusion or {}
        try:
            summary = {
                "round": payload.get("round") or rounds,
                "generation": generation,
                "status": status if not payload.get("status") else payload.get("status"),
                "root_cause": payload.get("root_cause") or "unknown",
                "symptoms": payload.get("symptoms") or "",
                "fact_count": len(payload.get("facts") or []),
                "hypothesis_count": len(payload.get("hypotheses") or []),
                "next_steps": payload.get("next_steps") or [],
                "remote_session_id": payload.get("remote_session_id") or "",
                "duration_sec": round(duration, 2),
                "reason": reason,
            }
        except Exception:
            summary = {"status": status, "reason": reason}
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE investigation_jobs SET status=?, rounds=?, last_error=?,"
                " last_result_status=?, last_conclusion_json=?, lease_expires_at=0, updated_at=?"
                " WHERE incident_id=? AND generation=? AND status='running'",
                (
                    status,
                    rounds,
                    (reason or payload.get("raw_excerpt") or "")[:300],
                    str(payload.get("status") or status),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    t,
                    incident_id,
                    generation,
                ),
            )
            if cur.rowcount != 1:
                # A newer generation owns the job; discard stale results and knowledge.
                return False
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    incident_id,
                    t,
                    "auto_investigation",
                    f"investigation {status}: {(payload.get('root_cause') or reason or '')[:80]}",
                    json.dumps(summary, ensure_ascii=False),
                ),
            )
        # 知识联动：仅 completed 且明确 verified 才尝试；失败不阻塞
        if payload.get("status") == "completed" and payload.get("knowledge_write"):
            try:
                self._maybe_write_knowledge(incident_id, payload)
            except Exception as e:  # noqa: BLE001
                log.warning("knowledge write failed: %s", e)
        return True

    def _maybe_write_knowledge(self, incident_id: str, payload: dict[str, Any]) -> None:
        """只允许 verified=result 且带恢复证据；否则 speculation。"""
        if self.knowledge is None:
            return
        kw = payload.get("knowledge_write") or {}
        if not kw.get("enabled"):
            return
        # No unattended investigation can establish a verified recovery fact.
        verified = "speculation"
        # Explicitly separate auto drafts from similarly named verified documents.
        doc_id = "auto-investigation-" + hashlib.sha256(incident_id.encode("utf-8")).hexdigest()[:24]
        existing = self.knowledge.get(doc_id)
        if existing is not None and existing.verified != "speculation":
            log.warning("refusing to overwrite non-speculative knowledge for %s", incident_id)
            return
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        inc_d = dict(inc) if inc else {}
        title = str(kw.get("title") or (payload.get("symptoms") or f"investigation {incident_id}"))[:120]
        self.knowledge.upsert(
            title=title,
            type="issue",
            objects=[f"{inc_d.get('asset_id')}:{inc_d.get('object_id')}"],
            tags=["auto-investigation"],
            body=str(kw.get("body") or payload.get("symptoms") or "")[:2000],
            verified=verified,
            doc_id=doc_id,
            root_cause=str(payload.get("root_cause") or "unknown")[:80],
            source_incident=incident_id,
        )
