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


CONCLUSION_PROMPT = """你是值班运维 Agent（MiMoCode）。Ayana 只负责监控、Incident、SSH 凭据与审计；你是唯一 AI 大脑。

对本 Incident 在同一会话内自行完成：调查 → 修复 → 验证，并决定是否重试、继续或结束。
不要把修复拆给第二套 AI；不要等待 Ayana 再替你做执行决策。

## 软约束（必须遵守）
1. 无进展 3 轮停止：连续 3 轮未产生新证据或改善 → 停止并输出 partial/failed。
2. 同方案失败 2 次停止：同一修复意图不得重复尝试超过 2 次。
3. 证据不足转人工：根因不明或探测无样本 → root_cause=unknown，next_steps 标明需人工。

可用工具（实际工具名使用下划线）：
- ayana_knowledge_query / ayana_knowledge_get / ayana_knowledge_upsert
- ayana_metrics_query
- ayana_incident_list / ayana_incident_get / ayana_incident_note / ayana_incident_close
- ayana_asset_list
- ayana_host_exec（channel=read 标注调查用途，channel=write 标注变更用途；都使用当前会话账号组，未指定时继承全局默认；权限=目标机 SSH 账户）

执行要求：
- 先用只读工具收集证据，再决定是否修复。
- 修复命令用 host.exec channel=write；结果不明（unknown）时自行检查目标状态再决定是否重试，不得假设成功。
- 修复后必须用指标/探针验证是否真实恢复（SSH 成功 ≠ 恢复）。
- 已验证恢复后写知识（区分已验证/推测），并用 incident_note 提交最终报告。

最后必须输出一个 JSON 对象（可包在 ```json 代码块），**放在回答的最末尾**，字段：
{
  "status": "completed|partial|failed|timeout",
  "symptoms": "故障现象",
  "facts": [{"claim": "已确认事实", "evidence": "工具返回的证据来源"}],
  "hypotheses": [{"claim": "可能原因", "confidence": "high|medium|low"}],
  "unconfirmed": ["未确认事项"],
  "next_steps": ["建议的下一步"],
  "root_cause": "unknown 或简述（无证据必须 unknown）",
  "actions_taken": [{"command": "...", "channel": "write", "result": "success|failure|unknown"}],
  "verified_recovered": false
}

要求：事实/推测/建议严格分开；无证据不得写 root_cause 已确认；verified_recovered 必须以监控证据为准。
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
        deleted=self.db.query_one("SELECT 1 FROM session_incidents si JOIN duty_sessions d ON d.id=si.session_id WHERE si.incident_id=? AND si.generation=? AND d.origin='auto' AND d.deleted_at>0",(incident_id,gen))
        if deleted:return {"ok":True,"skipped":"session_deleted"}
        t = now()
        row = self._row(incident_id)
        if row:
            if int(row.get("generation") or 1)==gen and row.get("status")=="cancelled":
                return {"ok":True,"skipped":"operator_stopped"}
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
        """Recover expired owners without replaying uncertain execution."""
        t=now();expired=0;resumed=0
        for row in self.db.query("SELECT * FROM investigation_jobs WHERE status='running'"):
            incident_id=row["incident_id"]
            if incident_id in self._running or float(row["lease_expires_at"] or 0)>=t:continue
            phase=str(row["phase"] or "")
            has_action=self.db.query_one("SELECT 1 FROM actions WHERE incident_id=? LIMIT 1",(incident_id,))
            has_write=self.db.query_one("SELECT 1 FROM session_write_ops WHERE incident_id=? LIMIT 1",(incident_id,))
            duty = getattr(self.bridge, "duty", None)
            mapped = duty.session_for_incident(incident_id) if duty else None
            native_blocked = bool(mapped and duty.native_admission_blockers(mapped["id"]))
            safe_decision=(phase=="decision" and not has_action and not has_write and not native_blocked and self._incident_is_current(incident_id,int(row["generation"] or 1)))
            if safe_decision:
                self.db.execute("UPDATE investigation_jobs SET status='queued',phase='resume_decision',lease_expires_at=0,last_error='resume_readonly_decision_after_restart',updated_at=? WHERE incident_id=? AND status='running' AND lease_expires_at<?",(t,incident_id,t));resumed+=1
            else:
                reason="closed_loop_interrupted_requires_review" if phase in ("decision","execution") else "lease_expired_after_restart"
                self.db.execute("UPDATE investigation_jobs SET status='failed',phase='interrupted',last_error=?,lease_expires_at=0,updated_at=? WHERE incident_id=? AND status='running' AND lease_expires_at<?",(reason,t,incident_id,t))
                if phase in ("decision","execution") and self.ops_loop:
                    try:self.ops_loop.escalate(incident_id,reason=reason)
                    except Exception:log.exception("failed to escalate interrupted closed loop")
            expired+=1
        return {"ok":True,"expired":expired,"resumed_readonly_decisions":resumed}

    def ready_jobs(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM investigation_jobs WHERE status='queued' AND NOT EXISTS (SELECT 1 FROM session_incidents si JOIN duty_sessions d ON d.id=si.session_id WHERE si.incident_id=investigation_jobs.incident_id AND d.origin='auto' AND d.status='open' AND (d.paused_at>0 OR d.delete_requested_at>0 OR d.deleted_at>0))"
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
        self.recover()
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
        current=self._row(incident_id);generation=int(job.get("generation") or 1)
        if not current or current.get("status")!="running" or int(current.get("generation") or 1)!=generation:return
        if not self._incident_is_current(incident_id,generation):
            self._finish(incident_id,"failed",generation=generation,reason="incident_changed_before_run",rounds=int(job.get("rounds") or 0));return
        duty=getattr(self.bridge,"duty",None)
        if duty is None:
            await self._run_job_locked(incident_id,job);return
        mapping=await asyncio.to_thread(self.bridge.ensure_session,incident_id,generation=int(job.get("generation") or 1))
        if not mapping.get("ok"):return
        sid=mapping["session_id"]
        current_session=duty.get(sid) or {}
        if current_session.get("paused_at") or current_session.get("delete_requested_at") or current_session.get("deleted_at"):
            self.db.execute("UPDATE investigation_jobs SET status='queued',lease_expires_at=0,updated_at=? WHERE incident_id=? AND status='running'",(now(),incident_id));return
        from .duty_session import NativeTurnBusyError
        try:
            async with duty.async_turn(sid,timeout=max(self.config.lease_ttl_sec,900),lease_sec=max(self.config.lease_ttl_sec,self.config.timeout_sec+self.config.decision_timeout_sec+600)):
                await self._run_job_locked(incident_id,job)
        except (NativeTurnBusyError, TimeoutError):
            # Keep the queued business work, without sending a second model turn
            # into a still-running or uncertain native owner.
            self.db.execute(
                "UPDATE investigation_jobs SET status='queued',lease_expires_at=0,last_error='shared_session_busy',updated_at=? WHERE incident_id=? AND generation=? AND status='running'",
                (now(), incident_id, generation),
            )

    async def _run_job_locked(self, incident_id: str, job: dict[str, Any]) -> None:
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
            mapping=self.bridge.get_mapping(incident_id) if self.bridge and hasattr(self.bridge,"get_mapping") else None
            human_sid=(mapping or {}).get("session_id") or ""
            human_before=int(((getattr(self.bridge,"duty",None).get(human_sid) if human_sid and getattr(self.bridge,"duty",None) else {}) or {}).get("human_message_revision") or 0)
            def human_intervened():
                session = (getattr(self.bridge, "duty", None).get(human_sid)
                           if human_sid and getattr(self.bridge, "duty", None) else {}) or {}
                return bool(session.get("paused_at") or session.get("delete_requested_at")
                            or int(session.get("human_message_revision") or 0) != human_before)
            rounds = int(job.get("rounds") or 0)
            if rounds >= self.config.max_rounds:
                self._finish(incident_id, "failed", generation=generation, reason="max_rounds_exceeded", rounds=rounds)
                return
            resume_decision = current.get("phase") == "resume_decision"
            try:
                if resume_decision:
                    result = json.loads(current.get("last_conclusion_json") or "{}")
                    if not isinstance(result,dict) or result.get("status") not in ("completed","partial"):raise ValueError("invalid_decision_checkpoint")
                else:
                    self.db.execute("UPDATE investigation_jobs SET phase='investigation' WHERE incident_id=? AND generation=? AND status='running'",(incident_id,generation))
                    result = await asyncio.wait_for(
                        self._investigate(incident_id, round_no=rounds + 1),
                        timeout=self.config.timeout_sec,
                    )
            except asyncio.TimeoutError:
                self._finish(
                    incident_id,
                    "partial" if human_intervened() else "timeout",
                    generation=generation,
                    reason="human_guidance" if human_intervened() else f"timeout:{self.config.timeout_sec}s",
                    rounds=rounds + 1,
                )
                return
            except Exception as e:  # noqa: BLE001
                self._finish(
                    incident_id,
                    "partial" if human_intervened() else "failed",
                    generation=generation,
                    reason="human_guidance" if human_intervened() else f"{type(e).__name__}:{e}",
                    rounds=rounds + 1,
                )
                return
            status = result.get("status") or "partial"
            if human_intervened():
                self._finish(incident_id,"partial",generation=generation,reason="human_guidance",conclusion=result,rounds=rounds+1,duration=now()-started)
                return
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
                rounds=rounds if resume_decision else rounds + 1,
                duration=now() - started,
                continue_loop=False,
            )
            # core-008：单 MiMoCode 会话自行调查/修复/验证；不再二次决策派发
            if accepted and self.config.closed_loop and status in ("completed", "partial"):
                self.db.execute("UPDATE investigation_jobs SET status=?,phase='complete',lease_expires_at=0,updated_at=? WHERE incident_id=? AND generation=? AND status='running'",(job_status,now(),incident_id,generation))

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
        continue_loop: bool = False,
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
                " last_result_status=?, last_conclusion_json=?, phase=?, lease_expires_at=CASE WHEN ? THEN lease_expires_at ELSE 0 END, updated_at=?"
                " WHERE incident_id=? AND generation=? AND status='running'",
                (
                    "running" if continue_loop else status,
                    rounds,
                    (reason or payload.get("raw_excerpt") or "")[:300],
                    str(payload.get("status") or status),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    "decision" if continue_loop else "complete",
                    int(continue_loop),
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
