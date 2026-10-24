"""Ayana MCP 工具集（薄层）。

工具命名对齐 HANDOFF：host.exec / metrics.query / incident.* / knowledge.*。
只做参数校验与结果整形，能力边界 = SSH 账户 + 现有服务；不引入 Policy/审批。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .ntsafe import NTResult
from .transport import TransportError


class McpToolError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.message = message or code
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
        "name": "asset.list",
        "description": "列出资产（id/名称/Prometheus 标签/启用状态）。",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class OpsTools:
    """把 HANDOFF §4 工具映射到 Ayana 服务。"""

    def __init__(self, ctx: OpsContext):
        self.ctx = ctx

    def specs(self) -> list[dict[str, Any]]:
        return [dict(s) for s in TOOL_SPECS]

    async def call(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
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
            "asset.list": self.asset_list,
        }
        fn = handlers.get(name)
        if not fn:
            raise McpToolError("unknown_tool", name)
        try:
            return await fn(args)
        except McpToolError:
            raise
        except TransportError as e:
            raise McpToolError(e.code, str(e)) from e
        except Exception as e:  # noqa: BLE001 — 工具边界统一成结构化错误
            raise McpToolError("internal", f"{type(e).__name__}: {e}") from e

    # ---- host ----

    async def host_exec(self, args: dict[str, Any]) -> dict[str, Any]:
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
        res = await self.ctx.transport.exec_shell(
            asset_id, command, timeout_f, channel=channel
        )
        return _result_payload(res)

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


def tool_result(ok: bool, data: dict[str, Any] | None = None, error: str = "") -> dict[str, Any]:
    """统一工具返回，便于 MCP content 序列化。"""
    if ok:
        return {"ok": True, **(data or {})}
    return {"ok": False, "error": error or "failed"}
