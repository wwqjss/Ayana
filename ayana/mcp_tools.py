"""Ayana MCP 工具集（薄层）。

工具命名对齐 HANDOFF：host.exec / metrics.query / incident.* / knowledge.*。
复用现有服务、SSH 凭据、审批与审计；受管调用逐次核对会话实际权限。
"""

from __future__ import annotations

import json
import shlex
from copy import copy
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .ntsafe import NTResult
from .transport import TransportError, session_dispatch_guard, session_ssh_scope


class McpToolError(Exception):
    def __init__(self, code: str, message: str = "", detail: dict | None = None):
        self.code = code
        self.message = message or code
        self.detail = detail if isinstance(detail,dict) else {}
        super().__init__(self.message)


def _clip(text: str, limit: int = 8000) -> str:
    t = text or ""
    return t if len(t) <= limit else t[:limit] + "\n…[truncated]"


def _result_payload(res: NTResult) -> dict[str, Any]:
    return {
        "ok": res.ok,
        "output": res.clipped(8000),
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "mode": res.mode,
        "account": res.account,
    }


@dataclass
class OpsContext:
    """MCP 工具运行所需的最小服务面。"""

    transport: Any
    prom: Any
    incidents: Any
    knowledge: Any
    db: Any = None
    notifier: Any = None
    session_bridge: Any = None
    # P4.3：只读模式（自动调查用）——执行层拒写，不靠提示词
    readonly: bool = False
    # 最终架构：自治写 / 配置 / 闭环 / 软约束
    actions: Any = None
    promconfig: Any = None
    ops_loop: Any = None
    constraints: Any = None
    managed_context: bool = False


TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "host.exec",
        "description": (
            "在资产上执行通用 shell 命令（调查与变更统一入口）。"
            "权限=目标机 SSH 账户。channel=write(默认)|read 决定读/写端点。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_id": {"type": "string", "description": "资产 ID"},
                "command": {"type": "string", "description": "远端 shell 命令行"},
                "timeout_sec": {"type": "number", "description": "超时秒，默认 12"},
                "channel": {
                    "type": "string",
                    "enum": ["write", "read"],
                    "description": "写或读通道，默认 write",
                },
            },
            "required": ["asset_id", "command"],
        },
    },
    {
        "name": "metrics.query",
        "description": "任意 PromQL 即时查询（不设白名单）。返回样本列表。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "PromQL 表达式"},
                "timeout_sec": {"type": "number", "description": "超时秒，默认 8"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "incident.list",
        "description": "列出事件（默认全部，可按 status 过滤 open/closed）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "open|closed，空=全部"},
                "limit": {"type": "integer", "description": "条数，默认 20"},
            },
        },
    },
    {
        "name": "incident.get",
        "description": "事件摘要 + 时间线证据 + 关联动作/调查。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string"},
            },
            "required": ["incident_id"],
        },
    },
    {
        "name": "incident.note",
        "description": "向事件时间线追加调查笔记（结论、证据、下一步）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string"},
                "text": {"type": "string", "description": "笔记正文"},
            },
            "required": ["incident_id", "text"],
        },
    },
    {
        "name": "incident.close",
        "description": "结案。reason 必填；已验证恢复才写 verified，否则如实记录。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string"},
                "reason": {"type": "string", "description": "结案原因/恢复说明"},
            },
            "required": ["incident_id", "reason"],
        },
    },
    {
        "name": "knowledge.query",
        "description": "检索知识库（Markdown）。可按资产/对象/关键词/标签过滤。仅 active 可作调查依据。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_id": {"type": "string"},
                "object": {"type": "string", "description": "对象名，如 mysql"},
                "query": {"type": "string", "description": "词面关键词"},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "标签列表（任一命中）",
                },
                "status": {"type": "string", "description": "默认 active；可查历史"},
                "limit": {"type": "integer", "description": "条数，默认 10"},
            },
        },
    },
    {
        "name": "knowledge.get",
        "description": "按 doc_id 取知识全文（front matter + 正文）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "doc_id": {"type": "string"},
            },
            "required": ["doc_id"],
        },
    },
    {
        "name": "knowledge.upsert",
        "description": (
            "写入/更新知识（自动积累）。恢复已验证 → verified=result 且 status=active；"
            "纯推测 → verified=speculation（不进自动上下文）。"
            "相似条目自动合并并 revision+1，不重复建文档。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "type": {
                    "type": "string",
                    "enum": ["system", "issue", "procedure", "note"],
                },
                "objects": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "如 [kanata:mysql]",
                },
                "tags": {"type": "array", "items": {"type": "string"}},
                "body": {"type": "string", "description": "Markdown 正文"},
                "verified": {
                    "type": "string",
                    "enum": ["result", "speculation", "none"],
                    "description": "result=恢复已验证；speculation=纯推测",
                },
                "root_cause": {"type": "string", "description": "可 unknown"},
                "source_incident": {"type": "string"},
                "verified_at": {"type": "string", "description": "ISO8601"},
                "doc_id": {"type": "string", "description": "指定更新已有文档"},
                "change_note": {"type": "string", "description": "本次变更说明"},
            },
            "required": ["title", "objects"],
        },
    },
    {
        "name": "asset.list",
        "description": "列出资产（id/名称/Prometheus 标签/启用状态）。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "session.get",
        "description": "取 Incident 的调查 Session（映射/prompt）。无则自动创建（同 Incident 复用）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string"},
            },
            "required": ["incident_id"],
        },
    },
    {
        "name": "session.write_ops",
        "description": "查该 Incident 的写操作台账（防重复执行）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string"},
            },
            "required": ["incident_id"],
        },
    },
    {
        "name": "session.claim",
        "description": "在当前真实原生会话中申请参与工单。若同一工单或目标已有任务，停止重复处置并返回已有会话；不会替换自动值班主会话。",
        "inputSchema": {"type":"object","properties":{"incident_id":{"type":"string"}},"required":["incident_id"]},
    },
    {
        "name": "session.remote",
        "description": (
            "受管原生模式将工单关联到当前真实会话，返回已有RID，不另起任务；新任务输入使用当前CLI。"
            "兼容独立旧客户端的远端会话创建接口。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {"type": "string"},
                "prompt": {"type": "string", "description": "首轮调查 prompt；空则用自动生成"},
                "force_new": {"type": "boolean", "description": "强制新建远端会话"},
            },
            "required": ["incident_id"],
        },
    },
    {
        "name": "action.execute",
        "description": (
            "自主执行已登记对象上的受控写能力（service.restart 等），"
            "退役 Ceiling/三态后系统自动批准；仍受能力目录/对象绑定/host key/幂等/unknown 保护。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_id": {"type": "string"},
                "object_id": {"type": "string"},
                "capability": {"type": "string"},
                "incident_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["incident_id", "asset_id", "object_id", "capability"],
        },
    },
    {
        "name": "ops.constraints",
        "description": "读取当前生效的 MiMoCode 运维软约束文本（无进展/同方案失败/转人工）。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "ops.loop_status",
        "description": "查询工单闭环软约束状态（轮次/无进展/停止原因）。",
        "inputSchema": {
            "type": "object",
            "properties": {"incident_id": {"type": "string"}},
            "required": ["incident_id"],
        },
    },
    {
        "name": "config.prom_target_add",
        "description": "自然语言配置：向 Prometheus file_sd 增加采集目标（校验+备份+回滚）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "labels": {"type": "object"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "config.prom_target_update",
        "description": "更新 Prometheus 采集目标。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "new_address": {"type": "string"},
                "labels": {"type": "object"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "config.prom_target_delete",
        "description": "删除 Prometheus 采集目标。",
        "inputSchema": {
            "type": "object",
            "properties": {"address": {"type": "string"}},
            "required": ["address"],
        },
    },
]


_MANAGED_MUTATIONS = frozenset({
    "incident.note", "incident.close", "knowledge.upsert", "session.remote",
    "config.prom_target_add", "config.prom_target_update", "config.prom_target_delete",
})


class OpsTools:
    """把 HANDOFF §4 工具映射到 Ayana 服务。"""

    def __init__(self, ctx: OpsContext):
        self.ctx = ctx

    def specs(self) -> list[dict[str, Any]]:
        return [dict(s) for s in TOOL_SPECS]

    def _with_authority(self, session_id: str, *, approved: bool = False) -> "OpsTools":
        from .agent_authority import AuthorityError, resolve_authority

        try:
            authority = resolve_authority(self.ctx.db, session_id)
        except AuthorityError as exc:
            raise McpToolError(exc.code, str(exc)) from exc
        scoped = copy(self.ctx)
        scoped.readonly = self.ctx.readonly or authority["access_mode"] == "readonly"
        scoped.authority_session_id = session_id
        scoped.authority_approval_mode = authority["approval_mode"]
        scoped.authority_revision = authority.get("revision")
        scoped.effective_permissions = authority
        scoped.approved_write = approved
        scoped.mcp_incident_scope = f"_session:{session_id}"
        return OpsTools(scoped)

    async def call(
        self, name: str, arguments: dict[str, Any] | None = None, *,
        invocation_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.ctx.managed_context:
            from .agent_authority import AuthorityError, resolve_remote_authority

            if not isinstance(invocation_context, dict) or not all(
                isinstance(invocation_context.get(key), str) and invocation_context[key].strip()
                for key in ("sessionId", "turnId", "actorId")
            ):
                raise McpToolError("trusted_session_context_required")
            try:
                authority = resolve_remote_authority(self.ctx.db, invocation_context["sessionId"])
            except AuthorityError as exc:
                raise McpToolError(exc.code, str(exc)) from exc
            scoped = self._with_authority(authority["session_id"])
            with session_ssh_scope(self.ctx.db,authority["session_id"]):
                return await scoped._call(name, arguments)
        return await self._call(name, arguments)

    async def call_approved(
        self, name: str, arguments: dict[str, Any], *, authority_session_id: str,
    ) -> dict[str, Any]:
        """Internal Web approval dispatch; never derived from model arguments."""
        if name not in _MANAGED_MUTATIONS:
            raise McpToolError("invalid_pending_tool", name)
        scoped = self._with_authority(authority_session_id, approved=True)
        with session_ssh_scope(self.ctx.db,authority_session_id):
            return await scoped._call(name, arguments)

    def _validate_incident_scope(self, args: dict[str, Any]) -> None:
        sid = getattr(self.ctx, "authority_session_id", "")
        incident_id = args.get("incident_id") or args.get("source_incident")
        if sid and incident_id:
            from .agent_work_scope import find_work_conflict
            conflict = find_work_conflict(self.ctx.db,sid,incident_id=str(incident_id))
            if conflict:
                raise McpToolError("work_already_running",conflict["message"],conflict)
            row = self.ctx.db.query_one(
                "SELECT 1 FROM session_incidents WHERE session_id=? AND incident_id=?",
                (sid, str(incident_id)),
            )
            if not row:
                owner = self._bridge().get_mapping(str(incident_id)) or {}
                raise McpToolError("incident_session_mismatch",
                    "当前会话尚未关联该工单；先调用 ayana_session_claim 申请参与，已有任务时进入原会话。",
                    {"current_session_id":sid,"owner_session_id":owner.get("session_id") or "",
                     "incident_id":str(incident_id),"next_tool":"ayana_session_claim","stop_processing":True})

    async def _call(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        args = arguments or {}
        handlers: dict[str, Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]] = {
            "host.exec": self.host_exec,
            "metrics.query": self.metrics_query,
            "incident.list": self.incident_list,
            "incident.get": self.incident_get,
            "incident.note": self.incident_note,
            "incident.close": self.incident_close,
            "knowledge.query": self.knowledge_query,
            "knowledge.get": self.knowledge_get,
            "knowledge.upsert": self.knowledge_upsert,
            "asset.list": self.asset_list,
            "session.get": self.session_get,
            "session.write_ops": self.session_write_ops,
            "session.remote": self.session_remote,
            "session.claim": self.session_claim,
            "action.execute": self.action_execute,
            "ops.constraints": self.ops_constraints,
            "ops.loop_status": self.ops_loop_status,
            "config.prom_target_add": self.config_prom_target_add,
            "config.prom_target_update": self.config_prom_target_update,
            "config.prom_target_delete": self.config_prom_target_delete,
        }
        fn = handlers.get(name)
        if not fn:
            raise McpToolError("unknown_tool", name)
        try:
            if name == "session.remote" and getattr(self.ctx,"authority_session_id",""):
                return await fn(args)
            if name in _MANAGED_MUTATIONS and getattr(self.ctx, "authority_session_id", ""):
                self._require_write_mode(name)
                self._validate_incident_scope(args)
                return await self._managed_mutation(name, args, fn)
            if name == "action.execute":
                self._require_write_mode(name)
                self._validate_incident_scope(args)
            return await fn(args)
        except McpToolError:
            raise
        except TransportError as e:
            raise McpToolError(e.code, str(e),getattr(e,"detail",{})) from e
        except Exception as e:  # noqa: BLE001 — 工具边界统一成结构化错误
            raise McpToolError("internal", f"{type(e).__name__}: {e}") from e

    async def _managed_mutation(self, name: str, args: dict[str, Any], fn: Any) -> dict[str, Any]:
        self._require_write_mode(name)
        sid = self.ctx.authority_session_id
        approved = bool(getattr(self.ctx, "approved_write", False))
        br = self._bridge()
        incident_id = self.ctx.mcp_incident_scope
        action_key = br.make_action_key(sid, name, args, context="mcp-tool-write")
        payload = {"_ayana_session_id": sid, "_ayana_tool": name, "_ayana_arguments": args}
        if not approved:
            if self.ctx.authority_approval_mode == "manual":
                pending = br.pending_write(incident_id, action_key, target=str(args.get("asset_id") or ""),
                                           params=payload, claimed_by="mcp_agent", authority_session_id=sid)
                if not pending.get("ok"):
                    return {"ok": False, "error": "idempotent_block", "detail": pending, "action_key": action_key}
                self._audit_write("", name, "awaiting_approval", sid)
                return {"ok": False, "error": "approval_required", "pending": True,
                        "action_key": action_key, "incident_id": incident_id}
            claim = br.claim_write(incident_id, action_key, params=payload, claimed_by="mcp_agent", authority_session_id=sid)
            if not claim.get("claimed"):
                return {"ok": False, "error": "idempotent_block", "detail": claim, "action_key": action_key}
        try:
            with session_dispatch_guard(self.ctx.db, sid, require_automatic=not approved,
                    asset_id=str(args.get("asset_id") or ""),object_id=str(args.get("object_id") or ""),
                    incident_id=str(args.get("incident_id") or args.get("source_incident") or "")):
                out = await fn(args)
        except Exception as exc:
            if not approved:
                if getattr(exc, "dispatch_not_started", False):
                    br.release_write(incident_id, action_key, confirmed_safe=True, reason=exc.code)
                else:
                    br.mark_unknown(incident_id, action_key, reason=type(exc).__name__)
            raise
        if not approved:
            br.complete_write(incident_id, action_key, ok=out.get("ok", True), result=json.dumps(out, default=str))
        self._audit_write("", name, "success" if out.get("ok", True) else "failed", sid)
        return out

    # ---- host ----

    async def host_exec(self, args: dict[str, Any]) -> dict[str, Any]:
        from .msgentry import classify_shell_command

        asset_id = str(args.get("asset_id") or "").strip()
        command = args.get("command")
        if not asset_id:
            raise McpToolError("bad_request", "asset_id required")
        if not isinstance(command, str) or not command.strip():
            raise McpToolError("bad_request", "command required")
        channel = str(args.get("channel") or "write")
        if channel not in ("write", "read"):
            raise McpToolError("bad_request", "channel must be write|read")
        timeout = args.get("timeout_sec")
        try:
            timeout_f = float(timeout) if timeout is not None else None
        except (TypeError, ValueError) as e:
            raise McpToolError("bad_request", "timeout_sec must be a number") from e

        cls = classify_shell_command(command)
        # 自动调查复用严格的只读参数语法；首命令分类不足以约束复合 shell。
        if getattr(self.ctx, "readonly", False):
            from .readonly_commands import readonly_command

            try:
                tokens = shlex.split(command)
            except ValueError:
                tokens = []
            if cls != "read" or not readonly_command(tokens):
                self._audit_write(asset_id, command, "rejected_readonly", cls)
                raise McpToolError(
                    "readonly_mode_rejects_write",
                    f"当前会话为只读，命令未通过既有只读语法校验；classified={cls}",
                    {"effective_permissions":getattr(self.ctx,"effective_permissions",{}),"classified":cls},
                )
            # 重新引用参数，避免让原始 shell 字符串引入额外解释。
            command = shlex.join(tokens)
        # read 通道不得跑写/未知命令，防 shell 包装绕过
        if channel == "read" and cls != "read":
            raise McpToolError(
                "write_not_allowed_on_read_channel",
                f"classified={cls}; use channel=write for controlled execution",
            )
        # 只读模式：只要分类是 read 就走读通道，不进写台账
        if getattr(self.ctx, "readonly", False):
            res = await self.ctx.transport.exec_shell(
                asset_id, command, timeout_f, channel="read"
            )
            return {**_result_payload(res), "classified": cls, "readonly": True}
        # write 通道或未知类别的写 → 受控执行（台账+审计+unknown 语义）
        if channel == "write" or cls != "read":
            return await self._controlled_write(
                asset_id=asset_id,
                command=command,
                timeout=timeout_f,
                channel=channel,
                classified=cls,
            )
        res = await self.ctx.transport.exec_shell(
            asset_id, command, timeout_f, channel="read"
        )
        return {**_result_payload(res), "classified": "read"}

    async def _controlled_write(
        self,
        *,
        asset_id: str,
        command: str,
        timeout: float | None,
        channel: str,
        classified: str,
    ) -> dict[str, Any]:
        """统一受控写：审批门 → claim → 执行 → 确定结果/unknown → 审计。"""
        from .actions import classify_exec_result

        self._require_write_mode("host.exec")
        authority_sid = getattr(self.ctx,"authority_session_id","")
        if authority_sid:
            from .agent_work_scope import WorkScopeError,claim_target
            try:
                claim_target(self.ctx.db,authority_sid,asset_id=asset_id)
            except WorkScopeError as exc:
                raise McpToolError(exc.code,str(exc),exc.detail) from exc

        br = getattr(self.ctx, "session_bridge", None)
        duty = getattr(self.ctx, "duty", None)
        require_human = True
        if duty is not None:
            try:
                require_human = bool(duty.require_human_approval())
            except Exception:
                require_human = True
        else:
            db = getattr(self.ctx, "db", None)
            try:
                row = db.query_one("SELECT value FROM agent_settings WHERE key='require_human_approval'") if db else None
                if row is not None:
                    require_human = str(row["value"] or "1") not in ("0", "false", "False", "")
            except Exception:
                require_human = True
        authority_sid = getattr(self.ctx, "authority_session_id", "")
        if authority_sid:
            # The mode is trusted per-call state, separate from global defaults.
            require_human = self.ctx.authority_approval_mode == "manual"
        incident_id = str(getattr(self.ctx, "mcp_incident_scope", "") or "_mcp_")
        action_key = ""
        if br is not None:
            try:
                action_key = br.make_action_key(
                    asset_id,
                    "exec_shell",
                    {"command": command, "channel": channel, "classified": classified},
                    context="mcp-host-exec",
                )
                if require_human:
                    pending = br.pending_write(
                        incident_id,
                        action_key,
                        target=asset_id,
                        params={"command": command, "channel": channel, "timeout": timeout,
                                **({"_ayana_session_id": authority_sid} if authority_sid else {})},
                        claimed_by="mcp_agent",
                        **({"authority_session_id": authority_sid} if authority_sid else {}),
                    )
                    if not pending.get("ok") and pending.get("error") != "already_pending":
                        return {
                            "ok": False,
                            "error": pending.get("error") or "pending_failed",
                            "detail": pending,
                            "action_key": action_key,
                        }
                    self._audit_write(asset_id, command, "awaiting_approval", "human approval required")
                    return {
                        "ok": False,
                        "error": "approval_required",
                        "message": "写操作已记录，等待人工批准后执行",
                        "action_key": action_key,
                        "pending": True,
                        "incident_id": incident_id,
                    }
                claim = br.claim_write(
                    incident_id,
                    action_key,
                    target=asset_id,
                    params={"command": command, "channel": channel,
                            **({"_ayana_session_id": authority_sid} if authority_sid else {})},
                    claimed_by="mcp_agent",
                    **({"authority_session_id": authority_sid} if authority_sid else {}),
                )
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": "claim_failed", "message": str(e)}
            if not claim.get("claimed"):
                return {
                    "ok": False,
                    "error": "idempotent_block",
                    "detail": claim,
                    "action_key": action_key,
                }
        try:
            with session_dispatch_guard(self.ctx.db, authority_sid, require_automatic=bool(authority_sid),asset_id=asset_id):
                res = await self.ctx.transport.exec_shell(
                    asset_id, command, timeout, channel=channel
                )
        except Exception as e:  # noqa: BLE001
            if getattr(e, "dispatch_not_started", False):
                if br is not None and action_key:
                    br.release_write(incident_id, action_key, confirmed_safe=True, reason=e.code)
                self._audit_write(asset_id, command, "rejected_before_dispatch", e.code)
                return {"ok": False, "error": e.code, "action_key": action_key,**(getattr(e,"detail",{}) if isinstance(getattr(e,"detail",{}),dict) else {})}
            if br is not None and action_key:
                br.mark_unknown(incident_id, action_key, reason=f"exception:{type(e).__name__}")
            self._audit_write(asset_id, command, "unknown", str(e)[:200])
            return {"ok": False, "error": "exec_error", "message": str(e), "action_key": action_key}

        state, detail = classify_exec_result(res)
        if br is not None and action_key:
            if state == "unknown":
                br.mark_unknown(incident_id, action_key, reason=detail or "unknown")
            else:
                br.complete_write(
                    incident_id,
                    action_key,
                    ok=(state == "success"),
                    result=(detail or "")[:500],
                )
        self._audit_write(asset_id, command, state, (detail or "")[:200])
        return {
            **_result_payload(res),
            "classified": classified,
            "exec_state": state,
            "action_key": action_key,
            "idempotent_incident": incident_id,
        }

    def _audit_write(self, asset_id: str, command: str, state: str, result: str) -> None:
        db = getattr(self.ctx, "db", None)
        if db is None:
            return
        try:
            db.audit(
                "agent",
                "mcp_agent",
                "mcp_host_exec_write",
                asset_id=asset_id,
                detail={
                    "command": command[:300],
                    "state": state,
                    "result": result[:200],
                    "authority_session_id": getattr(self.ctx, "authority_session_id", ""),
                    "authority_approval_mode": getattr(self.ctx, "authority_approval_mode", ""),
                    "authority_revision": getattr(self.ctx, "authority_revision", None),
                    "approved_write": bool(getattr(self.ctx, "approved_write", False)),
                },
                channel="mcp",
            )
        except Exception:
            pass

    # ---- metrics ----

    async def metrics_query(self, args: dict[str, Any]) -> dict[str, Any]:
        query = str(args.get("query") or "").strip()
        if not query:
            raise McpToolError("bad_request", "query required")
        timeout = args.get("timeout_sec")
        try:
            timeout_f = float(timeout) if timeout is not None else 8.0
        except (TypeError, ValueError) as e:
            raise McpToolError("bad_request", "timeout_sec must be a number") from e
        prom = self.ctx.prom
        if hasattr(prom, "timeout"):
            prom.timeout = timeout_f
        data = await prom.query(query)
        return {"ok": True, "result": data}

    # ---- incident ----

    def _require_incident(self, inc_id: str) -> dict[str, Any]:
        if not inc_id:
            raise McpToolError("bad_request", "incident_id required")
        inc = self.ctx.incidents.get_incident(inc_id)
        if not inc:
            raise McpToolError("not_found", inc_id)
        return inc

    async def incident_list(self, args: dict[str, Any]) -> dict[str, Any]:
        status = str(args.get("status") or "").strip()
        if status and status not in ("open", "closed"):
            raise McpToolError("bad_request", "status must be open|closed")
        limit = int(args.get("limit") or 20)
        limit = max(1, min(limit, 100))
        rows = self.ctx.incidents.list_incidents(status=status, limit=limit)
        out = []
        for r in rows:
            out.append(
                {
                    "id": r.get("id"),
                    "title": r.get("title"),
                    "status": r.get("status"),
                    "stage": r.get("stage"),
                    "asset_id": r.get("asset_id"),
                    "object_id": r.get("object_id"),
                    "severity": r.get("severity"),
                    "updated_at": r.get("updated_at"),
                    "outcome": r.get("outcome"),
                }
            )
        return {"ok": True, "incidents": out}

    async def incident_get(self, args: dict[str, Any]) -> dict[str, Any]:
        inc_id = str(args.get("incident_id") or "").strip()
        inc = self._require_incident(inc_id)
        events = inc.get("events") or []
        # 时间线摘要：保留最新 30 条
        timeline = [
            {
                "id": e.get("id"),
                "at": e.get("at"),
                "type": e.get("type"),
                "title": e.get("title"),
            }
            for e in events[:30]
        ]
        return {
            "ok": True,
            "incident": {
                "id": inc.get("id"),
                "title": inc.get("title"),
                "status": inc.get("status"),
                "stage": inc.get("stage"),
                "asset_id": inc.get("asset_id"),
                "object_id": inc.get("object_id"),
                "severity": inc.get("severity"),
                "opened_at": inc.get("created_at"),
                "updated_at": inc.get("updated_at"),
                "outcome": inc.get("outcome"),
                "need_human": inc.get("need_human"),
                "need_human_reason": inc.get("need_human_reason"),
            },
            "timeline": timeline,
            "actions": [
                {
                    "id": a.get("id"),
                    "kind": a.get("kind"),
                    "status": a.get("status"),
                    "summary": a.get("summary") or a.get("title"),
                }
                for a in (inc.get("actions") or [])[:20]
            ],
            "investigations": [
                {
                    "id": i.get("id"),
                    "created_at": i.get("created_at"),
                    "hypothesis": i.get("hypothesis"),
                    "status": i.get("status"),
                }
                for i in (inc.get("investigations") or [])[:10]
            ],
        }

    async def incident_note(self, args: dict[str, Any]) -> dict[str, Any]:
        if getattr(self.ctx, "readonly", False):
            self._audit_write("", str(args.get("incident_id") or ""), "rejected_readonly", "incident.note")
            raise McpToolError("readonly_mode_rejects_write", "incident.note disabled in readonly mode")
        inc_id = str(args.get("incident_id") or "").strip()
        text = str(args.get("text") or "").strip()
        if not text:
            raise McpToolError("bad_request", "text required")
        self._require_incident(inc_id)
        db = self.ctx.db
        if db is None:
            raise McpToolError("internal", "db not available")
        ev_id = db.event(
            "agent_note",
            _clip(text, 2000),
            incident_id=inc_id,
            payload={"source": "mcp", "via": "incident.note"},
        )
        return {"ok": True, "event_id": ev_id, "incident_id": inc_id}

    async def incident_close(self, args: dict[str, Any]) -> dict[str, Any]:
        if getattr(self.ctx, "readonly", False):
            self._audit_write("", str(args.get("incident_id") or ""), "rejected_readonly", "incident.close")
            raise McpToolError("readonly_mode_rejects_write", "incident.close disabled in readonly mode")
        inc_id = str(args.get("incident_id") or "").strip()
        reason = str(args.get("reason") or "").strip()
        if not reason:
            raise McpToolError("bad_request", "reason required")
        self._require_incident(inc_id)
        res = self.ctx.incidents.close_manual(
            inc_id, reason, actor="mcp_agent", actor_type="agent"
        )
        if not res.get("ok"):
            raise McpToolError(res.get("error") or "close_failed", reason)
        return {"ok": True, "incident_id": inc_id, "outcome": res.get("outcome")}

    # ---- knowledge ----

    async def knowledge_query(self, args: dict[str, Any]) -> dict[str, Any]:
        kb = self.ctx.knowledge
        asset_id = str(args.get("asset_id") or "").strip()
        obj = str(args.get("object") or "").strip()
        q = str(args.get("query") or "").strip()
        status = str(args.get("status") or "active").strip()
        limit = max(1, min(int(args.get("limit") or 10), 50))
        tags = args.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        tag_set = {str(t).strip().lower() for t in tags if str(t).strip()}

        if asset_id and obj:
            docs = kb.docs_for_object(asset_id, obj, include_inactive=True)
        else:
            docs = kb.list_docs(status="", q="")
            if asset_id:
                docs = [
                    d
                    for d in docs
                    if asset_id in d.asset_ids()
                    or any(o.startswith(asset_id + ":") or o == asset_id for o in d.objects)
                ]

        if status:
            docs = [d for d in docs if d.status == status]
        if tag_set:
            docs = [d for d in docs if tag_set & {t.lower() for t in d.tags}]
        if q:
            ql = q.lower()
            docs = [
                d
                for d in docs
                if ql in " ".join([d.id, d.title, d.body, *d.tags, *d.objects]).lower()
            ]

        items = []
        for d in docs[:limit]:
            pub = d.to_public()
            # 列表不塞全文，避免撑爆上下文
            body = pub.pop("body", "")
            pub["excerpt"] = _clip(body, 400)
            items.append(pub)
        return {"ok": True, "docs": items, "revision": getattr(kb, "revision", "")}

    async def knowledge_get(self, args: dict[str, Any]) -> dict[str, Any]:
        doc_id = str(args.get("doc_id") or "").strip()
        if not doc_id:
            raise McpToolError("bad_request", "doc_id required")
        doc = self.ctx.knowledge.get(doc_id)
        if not doc:
            raise McpToolError("not_found", doc_id)
        return {"ok": True, "knowledge": doc.to_public()}

    async def knowledge_upsert(self, args: dict[str, Any]) -> dict[str, Any]:
        if getattr(self.ctx, "readonly", False):
            self._audit_write("", str(args.get("title") or "")[:80], "rejected_readonly", "knowledge.upsert")
            raise McpToolError("readonly_mode_rejects_write", "knowledge.upsert disabled in readonly mode")
        title = str(args.get("title") or "").strip()
        objects = args.get("objects") or []
        if isinstance(objects, str):
            objects = [objects]
        tags = args.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        if not title:
            raise McpToolError("bad_request", "title required")
        if not objects:
            raise McpToolError("bad_request", "objects required")
        verified = str(args.get("verified") or "result").lower()
        try:
            res = self.ctx.knowledge.upsert(
                title=title,
                type=str(args.get("type") or "issue"),
                objects=[str(o) for o in objects],
                tags=[str(t) for t in tags],
                body=str(args.get("body") or ""),
                verified=verified,
                root_cause=str(args.get("root_cause") or ""),
                source_incident=str(args.get("source_incident") or ""),
                verified_at=str(args.get("verified_at") or ""),
                doc_id=str(args.get("doc_id") or ""),
                change_note=str(args.get("change_note") or ""),
            )
        except ValueError as e:
            raise McpToolError("bad_request", str(e)) from e
        return res

    # ---- session (P2 薄桥) ----

    def _bridge(self):
        br = getattr(self.ctx, "session_bridge", None)
        if br is None:
            raise McpToolError("unavailable", "session bridge not wired")
        return br

    async def session_get(self, args: dict[str, Any]) -> dict[str, Any]:
        inc_id = str(args.get("incident_id") or "").strip()
        if not inc_id:
            raise McpToolError("bad_request", "incident_id required")
        sid = getattr(self.ctx,"authority_session_id","")
        if sid:
            from .agent_work_scope import find_work_conflict
            mapping = self._bridge().get_mapping(inc_id)
            linked = self.ctx.db.query_one("SELECT 1 FROM session_incidents WHERE session_id=? AND incident_id=?",(sid,inc_id))
            return {"ok":True,**(mapping or {"incident_id":inc_id,"session_id":""}),
                    "current_session_id":sid,"current_session_linked":bool(linked),
                    "active_owner":find_work_conflict(self.ctx.db,sid,incident_id=inc_id),
                    "next_tool":"" if linked else "ayana_session_claim"}
        return self._bridge().ensure_session(inc_id)

    async def session_claim(self, args: dict[str, Any]) -> dict[str, Any]:
        sid = getattr(self.ctx,"authority_session_id","")
        if not sid:
            raise McpToolError("trusted_session_context_required")
        self._require_write_mode("session.claim")
        inc_id = str(args.get("incident_id") or "").strip()
        if not inc_id:
            raise McpToolError("bad_request","incident_id required")
        from .agent_work_scope import WorkScopeError,claim_incident
        try:
            return claim_incident(self.ctx.db,sid,inc_id)
        except WorkScopeError as exc:
            raise McpToolError(exc.code,str(exc),exc.detail) from exc

    async def session_write_ops(self, args: dict[str, Any]) -> dict[str, Any]:
        inc_id = str(args.get("incident_id") or "").strip()
        if not inc_id:
            raise McpToolError("bad_request", "incident_id required")
        return {"ok": True, "write_ops": self._bridge().write_ops(inc_id)}

    async def session_remote(self, args: dict[str, Any]) -> dict[str, Any]:
        sid = getattr(self.ctx,"authority_session_id","")
        if sid:
            self._require_write_mode("session.remote")
            if args.get("force_new") or str(args.get("prompt") or "").strip():
                raise McpToolError("use_current_session_input",
                    "当前任务已绑定原生会话；请在当前CLI输入新指导，工单关联使用 ayana_session_claim，不重建RID或嵌套启动任务。",
                    {"current_session_id":sid,"next_tool":"ayana_session_claim"})
            result = await self.session_claim(args)
            current = self.ctx.db.query_one("SELECT remote_session_id FROM duty_sessions WHERE id=?",(sid,))
            return {**result,"remote_session_id":current["remote_session_id"] if current else "","action":"associated_current_native"}
        if getattr(self.ctx, "readonly", False):
            self._audit_write("", str(args.get("incident_id") or ""), "rejected_readonly", "session.remote")
            raise McpToolError("readonly_mode_rejects_write", "session.remote disabled in readonly mode")
        inc_id = str(args.get("incident_id") or "").strip()
        if not inc_id:
            raise McpToolError("bad_request", "incident_id required")
        br = self._bridge()
        force = bool(args.get("force_new"))
        if force:
            return br.attach_remote(inc_id, force_new=True)
        prompt = str(args.get("prompt") or "").strip()
        if prompt:
            # 先确保存在远端，再追加 prompt
            attached = br.attach_remote(inc_id)
            if not attached.get("ok"):
                return attached
            sent = br.prompt_remote(inc_id, prompt)
            return {**attached, "prompt_result": sent}
        return br.attach_remote(inc_id)

    # ---- asset ----

    async def asset_list(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self.ctx.db
        if db is None:
            raise McpToolError("internal", "db not available")
        rows = db.query(
            "SELECT id, display_name, prom_asset, host, enabled FROM assets ORDER BY id"
        )
        return {
            "ok": True,
            "assets": [
                {
                    "id": r["id"],
                    "display_name": r["display_name"],
                    "prom_asset": r["prom_asset"],
                    "host": r["host"],
                    "enabled": bool(r["enabled"]),
                }
                for r in rows
            ],
        }

    # ---- final architecture: autonomous action / ops / config ----

    def _require_write_mode(self, tool: str) -> None:
        authority = getattr(self.ctx,"effective_permissions",{})
        if authority.get("lifecycle_block"):
            raise McpToolError(authority["lifecycle_block"],"当前会话已暂停或正在删除；请在原会话明确恢复后继续。",{"effective_permissions":authority})
        if getattr(self.ctx, "readonly", False):
            self._audit_write("", "", "rejected_readonly", tool)
            raise McpToolError("readonly_mode_rejects_write", f"当前会话为只读，拒绝 {tool}；请核对当前会话权限。",{"effective_permissions":authority})

    async def action_execute(self, args: dict[str, Any]) -> dict[str, Any]:
        self._require_write_mode("action.execute")
        loop = getattr(self.ctx, "ops_loop", None)
        if loop is None:
            raise McpToolError("unavailable", "OpsLoop not wired")
        asset_id = str(args.get("asset_id") or "").strip()
        object_id = str(args.get("object_id") or "").strip()
        capability = str(args.get("capability") or "").strip()
        incident_id = str(args.get("incident_id") or "").strip()
        if not asset_id or not object_id or not capability or not incident_id:
            raise McpToolError("bad_request", "incident_id, asset_id, object_id, capability required")
        params = args.get("params") or {}
        if not isinstance(params, dict):
            raise McpToolError("bad_request", "params must be an object")
        # The MCP entry shares the same hard round/stop boundary as the worker.
        res = await loop.run_action_and_verify(
            incident_id=incident_id, asset_id=asset_id, object_id=object_id,
            capability=capability, params=params,
            reason=str(args.get("reason") or "mcp_action_execute"),
            plan_sig=str(args.get("plan_sig") or f"{capability}:{object_id}"),
            **({"authority_session_id": self.ctx.authority_session_id}
               if getattr(self.ctx, "authority_session_id", "") else {}),
        )
        self._audit_write(asset_id, capability, str(res.get("state") or res.get("error") or ""),
                          str(res.get("detail") or "")[:200])
        return {**res, "id": res.get("action_id") or ""}

    async def ops_constraints(self, args: dict[str, Any]) -> dict[str, Any]:
        c = getattr(self.ctx, "constraints", None)
        if c is None:
            raise McpToolError("unavailable", "constraints not wired")
        return {"ok": True, "constraints": c.current()}

    async def ops_loop_status(self, args: dict[str, Any]) -> dict[str, Any]:
        loop = getattr(self.ctx, "ops_loop", None)
        inc_id = str(args.get("incident_id") or "").strip()
        if loop is None:
            raise McpToolError("unavailable", "ops_loop not wired")
        if not inc_id:
            raise McpToolError("bad_request", "incident_id required")
        return {"ok": True, "loop": loop.status(inc_id)}

    async def config_prom_target_add(self, args: dict[str, Any]) -> dict[str, Any]:
        self._require_write_mode("config.prom_target_add")
        pc = getattr(self.ctx, "promconfig", None)
        if pc is None:
            raise McpToolError("unavailable", "promconfig not wired")
        try:
            return await pc.add_target(
                address=str(args.get("address") or ""),
                labels=args.get("labels") or {},
                actor="mcp_agent",
            )
        except Exception as e:  # noqa: BLE001
            raise McpToolError(getattr(e, "code", "promconfig_failed"), str(e)[:300]) from e

    async def config_prom_target_update(self, args: dict[str, Any]) -> dict[str, Any]:
        self._require_write_mode("config.prom_target_update")
        pc = getattr(self.ctx, "promconfig", None)
        if pc is None:
            raise McpToolError("unavailable", "promconfig not wired")
        try:
            return await pc.update_target(
                address=str(args.get("address") or ""),
                new_address=args.get("new_address") or None,
                labels=args.get("labels"),
                actor="mcp_agent",
            )
        except Exception as e:  # noqa: BLE001
            raise McpToolError(getattr(e, "code", "promconfig_failed"), str(e)[:300]) from e

    async def config_prom_target_delete(self, args: dict[str, Any]) -> dict[str, Any]:
        self._require_write_mode("config.prom_target_delete")
        pc = getattr(self.ctx, "promconfig", None)
        if pc is None:
            raise McpToolError("unavailable", "promconfig not wired")
        try:
            return await pc.delete_target(
                address=str(args.get("address") or ""),
                actor="mcp_agent",
            )
        except Exception as e:  # noqa: BLE001
            raise McpToolError(getattr(e, "code", "promconfig_failed"), str(e)[:300]) from e


def tool_result(ok: bool, data: dict[str, Any] | None = None, error: str = "") -> dict[str, Any]:
    """统一工具返回，便于 MCP content 序列化。"""
    if ok:
        return {"ok": True, **(data or {})}
    return {"ok": False, "error": error or "failed"}
