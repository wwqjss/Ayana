"""Headless on-call worker using the existing incident queue and execution ledger.

There is no terminal, native MiMo session or second SSH execution path. The
service owns model turns independently of the Web process.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import signal
import time
import uuid
from typing import Any

from .auto_investigate import AutoInvestigator, InvestConfig
from .db import now
from .mcp_tools import McpToolError, OpsTools
from .transport import session_dispatch_guard, session_ssh_scope

log = logging.getLogger("ayana.lite_worker")

LITE_TOOLS = frozenset({
    "host.exec", "metrics.query", "incident.get", "incident.note",
    "knowledge.query", "knowledge.get", "asset.list", "config.check_list",
    "ops.constraints",
})
VERIFY_SPEC = {
    "name": "incident.verify",
    "description": "重新运行当前工单关联的已启用原生检查，并核对真实恢复证据。命令成功或模型结论不能代替恢复；无原生检查时使用既有证据规则核对。",
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    "annotations": {"readOnlyHint": True},
}
LITE_INSTRUCTIONS = """你是 Ayana 的后台自动值班 Agent，没有聊天界面或人工终端。
只处理当前工单及其故障代次，先调查证据，再用当前 SSH 账号组执行必要修复。
实际提供的工具是唯一可调用范围。不要创建其他会话、修改监控配置、接入来源或自行更改权限。
修复后调用 ayana_incident_verify 重新核对原生检查和恢复证据。
不能用 incident.close 或模型自报的 verified_recovered 来结案。
同一失败方案最多两次，无进展必须停止；写结果未知时立即停止并通知，禁止盲目重放。
结束时输出提示中要求的结构化结论。未确认恢复时诚实记录 partial/failed。
"""


class LiteStopped(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _bounded(config: dict, key: str, default: int, low: int, high: int) -> int:
    value = config.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"invalid lite_agent.{key}")
    return value


def model_client(cfg: dict, db):
    """Read the same saved model settings each turn; never copy API keys to events."""
    from .lite_agent import LiteLLMClient
    values = {key: str(cfg.get(key) or "") for key in ("llm_api_key", "llm_base_url", "llm_model")}
    for row in db.query("SELECT key,value FROM meta WHERE key IN ('llm_api_key','llm_base_url','llm_model')"):
        if row and str(row["value"] or "").strip():
            values[row["key"]] = str(row["value"]).strip()
    settings = cfg.get("lite_agent") or {}
    timeout = _bounded(settings, "request_timeout_sec", 60, 5, 180)
    return LiteLLMClient(values["llm_api_key"], values["llm_base_url"], values["llm_model"],
                         timeout=timeout, secure_network=True)


class LiteInvestigator(AutoInvestigator):
    """Reuse persistent job admission, session serialization and generation checks."""

    def __init__(self, cfg: dict, tools: OpsTools, *, client_factory=None, runner_factory=None):
        self.cfg = cfg
        self.tools = tools
        self.client_factory = client_factory or (lambda: model_client(cfg, tools.ctx.db))
        if runner_factory is None:
            from .lite_agent import LiteAgentRunner
            runner_factory = LiteAgentRunner
        self.runner_factory = runner_factory
        self.settings = cfg.get("lite_agent") or {}
        self.limits = {
            "max_rounds": _bounded(self.settings, "max_rounds", 12, 1, 40),
            "max_tool_calls": _bounded(self.settings, "max_tool_calls", 40, 1, 100),
            "max_tokens": _bounded(self.settings, "max_tokens", 2048, 128, 8192),
            "max_context_chars": _bounded(self.settings, "max_context_chars", 80000, 4000, 200000),
        }
        ctx = tools.ctx
        config = InvestConfig.from_dict(cfg.get("auto_investigate") or {})
        # The lease must outlive the bounded turn. Renewal prevents a second
        # owner while a slow model or serialized session is still active.
        config.lease_ttl_sec = max(config.lease_ttl_sec, config.timeout_sec + 60)
        ctx.readonly = ctx.readonly or not config.closed_loop
        super().__init__(ctx.db, knowledge=ctx.knowledge, bridge=ctx.session_bridge,
                         config=config, incidents=ctx.incidents, ops_loop=ctx.ops_loop,
                         readiness_callback=self.model_ready)

    def model_ready(self) -> bool:
        try:
            client = self.client_factory()
            return bool(client.enabled and client.model and client._endpoint_allowed())
        except Exception:
            return False

    def resume_verified_writes(self) -> int:
        """Resume a lite turn stopped specifically for an objectively settled write.

        Queue admission keeps the original budget, cooldown and all operator
        controls. Each verification can trigger at most one continuation.
        """
        if (self.cfg.get("agent_mode") != "lite" or not self.config.enabled
                or self._stop.is_set()):
            return 0
        stamp = now()
        resumed = 0
        rows = self.db.query("SELECT * FROM investigation_jobs WHERE status IN ('partial','failed','timeout') ORDER BY updated_at LIMIT 100")
        for row in rows:
            try:
                conclusion = json.loads(row["last_conclusion_json"] or "{}")
                stop_reason = (conclusion.get("lite_agent") or {}).get("stop_reason")
            except (TypeError, ValueError, AttributeError):
                continue
            if stop_reason not in ("tool_result_unknown", "write_result_unknown") or row["last_error"] == "human_guidance":
                continue
            if int(row["rounds"] or 0) >= self.config.max_rounds or stamp < float(row["updated_at"] or 0) + self.config.cooldown_sec:
                continue
            iid, generation = row["incident_id"], int(row["generation"] or 1)
            with self.db.tx() as conn:
                if not conn.in_transaction:
                    conn.execute("BEGIN IMMEDIATE")
                current = conn.execute("SELECT status,generation,need_human FROM incidents WHERE id=?", (iid,)).fetchone()
                if not current or current["status"] != "open" or int(current["generation"] or 1) != generation or current["need_human"]:
                    continue
                session = conn.execute("SELECT d.* FROM duty_sessions d JOIN session_incidents si ON d.id=si.session_id "
                    "WHERE si.incident_id=? AND si.generation=? AND d.origin='auto' AND d.status='open' "
                    "AND d.paused_at=0 AND d.delete_requested_at=0 AND d.deleted_at=0 ORDER BY d.created_at DESC LIMIT 1", (iid, generation)).fetchone()
                if not session or session["human_message_revision"]:
                    continue
                sid = session["id"]
                if self.bridge.duty.native_admission_blockers(sid, include_business=True):
                    continue
                if conn.execute("SELECT 1 FROM session_write_ops WHERE (session_id=? OR incident_id=?) AND status IN ('claimed','unknown')", (sid, iid)).fetchone():
                    continue
                if conn.execute("SELECT 1 FROM actions WHERE (incident_id=? OR (json_valid(params_json) AND json_extract(params_json,'$._ayana_session_id')=?)) "
                                "AND state IN ('proposed','approved','dispatched','unknown','verifying')", (iid, sid)).fetchone():
                    continue
                evidence = conn.execute("SELECT id,adjudicated_at FROM session_write_ops WHERE incident_id=? AND session_id=? "
                    "AND adjudication IN ('auto_verified','auto_not_executed','auto_retry_safe') AND adjudicated_at>=? ORDER BY adjudicated_at DESC", (iid, sid, row["created_at"])).fetchall()
                unused = []
                for write in evidence:
                    key = f"lite_write_resume:{iid}:{generation}:{write['id']}:{write['adjudicated_at']}"
                    if not conn.execute("SELECT 1 FROM meta WHERE key=?", (key,)).fetchone():
                        unused.append((key, write["id"]))
                if not unused:
                    continue
                changed = conn.execute("UPDATE investigation_jobs SET status='queued',phase='verified_write_resume',lease_expires_at=0,updated_at=? "
                    "WHERE incident_id=? AND generation=? AND status IN ('partial','failed','timeout') AND updated_at=? AND rounds=?",
                    (stamp, iid, generation, row["updated_at"], row["rounds"])).rowcount
                if not changed:
                    continue
                for key, _ in unused:
                    conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", (key, str(stamp)))
                detail = {"generation": generation, "rounds": row["rounds"], "write_ids": [write_id for _, write_id in unused],
                          "previous_status": row["status"], "stop_reason": stop_reason}
                self.db.audit("system", "lite_agent", "lite_resumed_after_write_verification", incident_id=iid,
                              detail=detail, channel="agent")
                self.bridge.duty.record_event(sid, type="lite_write_verified_resume", title="执行结果已自动确认，值班任务继续排队处理。",
                                              incident_id=iid, payload=detail)
                resumed += 1
        return resumed

    async def tick_once(self) -> int:
        self.resume_verified_writes()
        return await super().tick_once()

    def recover_interrupted(self) -> int:
        """Called only after acquiring the independent runtime's exclusive lock."""
        rows = self.db.query("SELECT * FROM investigation_jobs WHERE status='running' AND phase='lite'")
        for row in rows:
            mapping = self.bridge.get_mapping(row["incident_id"]) or {}
            sid = mapping.get("session_id") or ""
            if sid:
                self._mark_claims_unknown(sid)
                self.bridge.duty.set_runtime_state(sid, "idle", receipt_status="failed")
            self._finish(row["incident_id"], "failed", generation=int(row["generation"] or 1),
                         reason="lite_interrupted_requires_review", rounds=int(row["rounds"] or 0))
        return len(rows)

    def _mark_claims_unknown(self, sid: str) -> None:
        # Cancellation cannot prove an SSH dispatch did not reach its target.
        with self.db.tx() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("SELECT id FROM session_write_ops WHERE session_id=? AND status='claimed'", (sid,)).fetchall()
            conn.execute("UPDATE session_write_ops SET status='unknown',result='lite_worker_interrupted',updated_at=? "
                         "WHERE session_id=? AND status='claimed'", (now(), sid))
            for row in rows:
                self.db.audit("system", "lite_agent", "lite_write_interrupted", channel="agent",
                              detail={"session_id": sid, "write_id": row["id"], "status": "unknown"})

    def _pending_write(self, sid: str) -> bool:
        return bool(self.db.query_one("SELECT 1 FROM session_write_ops WHERE session_id=? AND status IN ('claimed','unknown') LIMIT 1", (sid,)))

    def _check_active(self, incident_id: str, generation: int, sid: str, *, allow_settled=False) -> None:
        if self._stop.is_set():
            raise LiteStopped("lite_stopping")
        session = self.bridge.duty.get(sid) or {}
        if session.get("status") != "open" or session.get("origin") != "auto":
            raise LiteStopped("session_not_open")
        if session.get("paused_at") or session.get("delete_requested_at") or session.get("deleted_at"):
            raise LiteStopped("session_paused")
        job = self._row(incident_id) or {}
        if job.get("status") != "running" or int(job.get("generation") or 1) != generation:
            raise LiteStopped("job_owner_changed")
        incident = self.db.query_one("SELECT status,generation,outcome FROM incidents WHERE id=?", (incident_id,))
        if not incident or int(incident["generation"] or 1) != generation:
            raise LiteStopped("incident_generation_changed")
        if self._pending_write(sid):
            raise LiteStopped("write_result_unknown")
        if incident["status"] != "open" and not allow_settled:
            raise LiteStopped("incident_recovered" if incident["outcome"] == "recovered" else "incident_closed")

    async def _verify(self, incident_id: str, generation: int, sid: str) -> dict:
        results = []
        # Only existing checks that contributed to this exact incident may be
        # rerun. The check service keeps contract and generation verification.
        episodes = self.db.query("SELECT * FROM alert_episodes WHERE incident_id=? AND source_id='ayana_check' "
                                 "ORDER BY CASE status WHEN 'firing' THEN 0 ELSE 1 END,last_seen DESC", (incident_id,))
        seen = set()
        for row in episodes:
            if not self.incidents.episode_is_current(incident_id, dict(row)):
                continue
            try:
                annotations = json.loads(row["annotations_json"] or "{}")
            except (TypeError, ValueError):
                continue
            check_id = annotations.get("check_id") if isinstance(annotations, dict) else None
            if not isinstance(check_id, str) or check_id in seen:
                continue
            check = self.tools.ctx.checks.get_check(check_id)
            if not check or not check["enabled"] or check["asset_id"] != row["asset_id"]:
                continue
            self._check_active(incident_id, generation, sid)
            seen.add(check_id)
            with session_dispatch_guard(self.db, sid, asset_id=check["asset_id"], incident_id=incident_id,
                                        incident_generation=generation, write_scope="incident"), session_ssh_scope(self.db, sid):
                result = await self.tools.ctx.checks.run_one(
                    check, record_guard=lambda: self._check_active(incident_id, generation, sid))
            results.append({"check_id": check_id, "ok": bool(result.get("ok")), "state": result.get("state")})
            if self.db.query_one("SELECT 1 FROM incidents WHERE id=? AND status<>'open'", (incident_id,)):
                break
            if len(seen) >= 8:
                break
        self.incidents.reconcile(incident_id)
        incident = self.db.query_one("SELECT status,outcome,generation FROM incidents WHERE id=?", (incident_id,))
        return {"ok": True, "checks": results, "incident": dict(incident) if incident else {},
                "verified_recovered": bool(incident and int(incident["generation"] or 1) == generation
                                           and incident["status"] == "resolved" and incident["outcome"] == "recovered")}

    async def _investigate(self, incident_id: str, *, round_no: int) -> dict[str, Any]:
        mapping = self.bridge.get_mapping(incident_id) or {}
        sid = mapping.get("session_id") or ""
        row = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not row or not sid:
            raise LiteStopped("incident_session_missing")
        generation = int(row["generation"] or 1)
        asset_id = row["asset_id"] or ""
        self._check_active(incident_id, generation, sid)
        self.db.execute("UPDATE investigation_jobs SET phase='lite' WHERE incident_id=? AND generation=? AND status='running'", (incident_id, generation))
        self.bridge.duty.set_runtime_state(sid, "running", receipt_status="running")
        specs = [spec for spec in self.tools.specs() if spec["name"] in LITE_TOOLS]
        specs.append(VERIFY_SPEC)
        if not self.config.closed_loop:
            specs = [spec for spec in specs if spec["name"] != "incident.note"]
        prompt = LITE_INSTRUCTIONS + "\n" + self._build_invest_prompt(incident_id, round_no=round_no)

        def check_active():
            self._check_active(incident_id, generation, sid)

        def event(kind, payload):
            # Payloads are projected by the runner: no command, output, key or
            # private reasoning is persisted in progress events.
            allowed = {key: value for key, value in payload.items() if key in ("tool", "round", "index", "state", "reason", "rounds", "tool_calls", "error", "stop_reason", "status")}
            titles = {"model_started": "正在分析故障", "tool_started": "正在执行工具",
                      "tool_finished": "工具执行结束", "finished": "本轮分析结束"}
            self.bridge.duty.record_event(sid, type="lite_" + kind, title="轻量值班：" + titles.get(kind, "任务状态更新"),
                                          incident_id=incident_id, payload=allowed)

        async def call_tool(name, arguments):
            check_active()
            if name == "incident.verify":
                return await self._verify(incident_id, generation, sid)
            if name not in LITE_TOOLS:
                raise McpToolError("unknown_tool")
            args = dict(arguments)
            if name in ("incident.get", "incident.note"):
                if args.get("incident_id", incident_id) != incident_id:
                    raise McpToolError("incident_session_mismatch", dispatch_not_started=True)
                args["incident_id"] = incident_id
            if name in ("host.exec", "config.check_list"):
                if not asset_id or args.get("asset_id", asset_id) != asset_id:
                    raise McpToolError("incident_asset_mismatch", dispatch_not_started=True)
                args["asset_id"] = asset_id
            if name == "host.exec":
                if args.get("incident_id", incident_id) != incident_id:
                    raise McpToolError("incident_session_mismatch", dispatch_not_started=True)
                args["incident_id"] = incident_id
                if not self.config.closed_loop:
                    args["channel"] = "read"
            result = await self.tools.call_for_session(name, args, authority_session_id=sid)
            if self._pending_write(sid):
                return {**result, "exec_state": "unknown", "stop_processing": True}
            return result

        try:
            result = await self.runner_factory(self.client_factory(), **self.limits).run(
                prompt, tools=specs, call_tool=call_tool, check_active=check_active, on_event=event)
        except LiteStopped as exc:
            result = {"status": "completed" if exc.code == "incident_recovered" else "partial",
                      "root_cause": "unknown", "facts": [], "unconfirmed": [] if exc.code == "incident_recovered" else [exc.code],
                      "lite_agent": {"stop_reason": exc.code}}
        except BaseException:
            self._mark_claims_unknown(sid)
            raise
        finally:
            self.bridge.duty.set_runtime_state(sid, "idle", receipt_status="completed")
        current = self.db.query_one("SELECT status,outcome,generation FROM incidents WHERE id=?", (incident_id,))
        result["verified_recovered"] = bool(current and int(current["generation"] or 1) == generation
                                             and current["status"] == "resolved" and current["outcome"] == "recovered"
                                             and not self._pending_write(sid))
        if result["verified_recovered"]:
            result["status"] = "completed"
        elif result.get("status") == "completed":
            result["status"] = "partial"
            result.setdefault("unconfirmed", []).append("尚无当前工单的有效恢复证据")
        result["round"] = round_no
        if not any(isinstance(fact, dict) and str(fact.get("evidence") or "").strip() for fact in result.get("facts", [])):
            result["root_cause"] = "unknown"
        return result

    def _finish(self, incident_id: str, status: str, **kwargs) -> bool:
        with self.db.tx() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("SELECT generation,title,asset_id FROM incidents WHERE id=?", (incident_id,)).fetchone()
            if not current or int(current["generation"] or 1) != kwargs["generation"]:
                conn.execute("UPDATE investigation_jobs SET status='cancelled',phase='superseded',lease_expires_at=0,updated_at=? "
                             "WHERE incident_id=? AND generation=? AND status='running'",
                             (now(), incident_id, kwargs["generation"]))
                return False
            accepted = super()._finish(incident_id, status, **kwargs)
        if not accepted:
            return False
        mapping = self.bridge.get_mapping(incident_id) or {}
        payload = kwargs.get("conclusion") or {}
        reason = kwargs.get("reason") or (payload.get("lite_agent") or {}).get("stop_reason") or ""
        message = ("已核对恢复" if payload.get("verified_recovered") else "未确认恢复")
        explanations = {"incident_recovered": "恢复检查已通过", "completed": "模型分析结束",
                        "tool_result_unknown": "工具执行结果未确认，已停止重复执行",
                        "write_result_unknown": "存在未确认的写操作，已停止重复执行",
                        "round_budget_exhausted": "已达到分析轮数上限", "tool_budget_exhausted": "已达到工具调用上限",
                        "context_budget_exhausted": "已达到上下文上限", "session_paused": "任务已暂停"}
        label = f"{current['title'][:120]}（{current['asset_id'] or '未绑定主机'}）"
        body = f"轻量值班 · {label}：{message}。" + (f"{explanations.get(reason, reason)}。" if reason else "")
        if mapping.get("session_id"):
            self.bridge.duty.add_message(mapping["session_id"], kind="lite_result", title="轻量值班结果",
                                         body=body, incident_id=incident_id,
                                         payload={"status": status, "verified_recovered": bool(payload.get("verified_recovered"))})
        event_id = self.db.event("lite_duty_finished", "轻量值班处理结束", incident_id=incident_id,
                                 payload={"generation": kwargs["generation"], "status": status, "body": body,
                                          "verified_recovered": bool(payload.get("verified_recovered"))})
        if self.tools.ctx.notifier:
            self.tools.ctx.notifier.enqueue_for_event(event_id, body=body, typ="lite_duty_finished")
        return True


def build_worker(cfg: dict) -> LiteInvestigator:
    from .mcp_server import build_ops_context
    from .notify import Notifier
    from .notify_channels import ChannelStore
    ctx = build_ops_context(cfg, environment_bindings=False)
    ctx.managed_context = True
    ctx.readonly = not InvestConfig.from_dict(cfg.get("auto_investigate") or {}).closed_loop
    ctx.incidents.prom = ctx.prom
    ctx.notifier = Notifier(ctx.db, default_target=f"user:{cfg['admin_qq']}" if cfg.get("admin_qq") else "")
    ctx.notifier.set_channel_store(ChannelStore(ctx.db, master_key=cfg.get("notify_channel_key") or cfg.get("ssh_credential_key") or ""))
    ctx.checks.notifier = ctx.notifier
    ctx.ops_loop.notifier = ctx.notifier
    worker = LiteInvestigator(cfg, OpsTools(ctx))
    ctx.incidents.auto_investigator = worker
    return worker


def process_start() -> str:
    # Field 22, after removing the parenthesized comm (which can contain spaces).
    return Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]


def write_attestation(path: Path, status: str) -> None:
    if path.is_symlink():
        raise RuntimeError("unsafe_lite_attestation_path")
    value = {"mode": "lite", "owner_pid": os.getpid(), "owner_start": process_start(),
             "updated_at": time.time(), "status": status}
    temp = path.with_name(".lite-attestation-" + uuid.uuid4().hex)
    try:
        with temp.open("x", encoding="utf-8") as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


async def run(cfg: dict) -> None:
    from .instance import acquire_single_instance_lock
    from .mimo_runtime_config import runtime_paths
    state_dir = Path(runtime_paths(cfg)["state_dir"])
    if state_dir.is_symlink():
        raise RuntimeError("unsafe_runtime_path")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.umask(0o077)
    lock = acquire_single_instance_lock(state_dir / "lite-runtime.lock", nofollow=True)
    attestation = state_dir / "lite-attestation.json"
    worker = None
    task = None
    stop = asyncio.Event()
    try:
        write_attestation(attestation, "waiting_configuration")
        worker = build_worker(cfg)
        worker.recover_interrupted()
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        task = asyncio.create_task(worker.run_forever())
        while not stop.is_set():
            if task.done():
                await task
                raise RuntimeError("lite_worker_stopped")
            status = "busy" if worker._running else "idle" if worker.model_ready() else "waiting_configuration"
            write_attestation(attestation, status)
            try:
                await asyncio.wait_for(stop.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
    finally:
        if worker is not None:
            worker.stop()
        running = ([task] if task is not None else []) + (list(worker._running.values()) if worker else [])
        for pending in running:
            pending.cancel()
        await asyncio.gather(*running, return_exceptions=True)
        if worker is not None:
            worker.recover_interrupted()
        try:
            write_attestation(attestation, "stopped")
        finally:
            if worker is not None:
                worker.db.close()
            lock.close()
