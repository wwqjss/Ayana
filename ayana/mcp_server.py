"""Ayana 薄 MCP 服务（stdio · JSON-RPC 2.0）。

供常驻 MiMo Code ops agent 调用。只暴露 HANDOFF §4 的最小工具集；
不启 Web/机器人，不引入 Policy/Council/审批。

启动：
    python -m ayana.mcp_server [config_dir]
默认 config_dir 为当前目录（读取 config.json / secrets.json / ayana.db）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import threading
from pathlib import Path
from typing import Any

from .config import load_config
from .credentials import CredentialStore
from .db import Database
from .incidents import IncidentService
from .knowledge import KnowledgeBase
from .mcp_tools import McpToolError, OpsContext, OpsTools
from .prom import PromClient
from .transport import SSHAssetStore, SSHTransport

log = logging.getLogger("ayana.mcp")

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "ayana-mcp", "version": "0.1.0"}


def build_ops_context(cfg: dict[str, Any]) -> OpsContext:
    """装配 MCP 最小服务面（与 App 共用模块，不拉起 Web/自治）。"""
    db = Database(cfg["db_path"])
    knowledge = KnowledgeBase(db)
    try:
        row = db.query_one("SELECT value FROM meta WHERE key='prometheus_url'")
        if row and str(row["value"] or "").strip():
            prom = PromClient(str(row["value"]).strip().rstrip("/"))
        else:
            prom = PromClient(cfg.get("prometheus_url", "http://127.0.0.1:9090"))
    except Exception:
        prom = PromClient(cfg.get("prometheus_url", "http://127.0.0.1:9090"))
    incidents = IncidentService(db)
    creds = CredentialStore(db, master_key=cfg.get("ssh_credential_key") or "")
    ssh_store = SSHAssetStore(db)
    transport = SSHTransport(ssh_store, creds)
    return OpsContext(
        transport=transport,
        prom=prom,
        incidents=incidents,
        knowledge=knowledge,
        db=db,
    )


class McpStdioServer:
    """极简 MCP：initialize / tools/list / tools/call。"""

    def __init__(self, tools: OpsTools):
        self.tools = tools
        self._initialized = False

    async def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """处理一条 JSON-RPC 消息；通知无 id 则返回 None。"""
        mid = msg.get("id")
        method = msg.get("method") or ""
        params = msg.get("params") or {}

        if method == "initialize":
            self._initialized = True
            return _result(
                mid,
                {
                    "protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": SERVER_INFO,
                },
            )
        if method == "notifications/initialized":
            return None
        if method == "ping":
            return _result(mid, {})
        if method == "tools/list":
            return _result(mid, {"tools": self.tools.specs()})
        if method == "tools/call":
            name = str(params.get("name") or "")
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                return _error(mid, -32602, "arguments must be object")
            try:
                out = await self.tools.call(name, args)
            except McpToolError as e:
                return _result(
                    mid,
                    {
                        "content": [{"type": "text", "text": json.dumps({"ok": False, "error": e.code, "message": e.message}, ensure_ascii=False)}],
                        "isError": True,
                    },
                )
            except Exception as e:  # noqa: BLE001
                log.exception("tool crash: %s", name)
                return _result(
                    mid,
                    {
                        "content": [{"type": "text", "text": json.dumps({"ok": False, "error": "internal", "message": str(e)}, ensure_ascii=False)}],
                        "isError": True,
                    },
                )
            return _result(
                mid,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(out, ensure_ascii=False, default=str),
                        }
                    ],
                    "isError": False,
                },
            )
        if mid is None:
            return None
        return _error(mid, -32601, f"method not found: {method}")

    async def run_stdio(self) -> None:
        # 用线程读行再投递，兼容 pipe / 重定向文件（connect_read_pipe 只吃真管道）
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[str | None] = asyncio.Queue()

        def _reader() -> None:
            try:
                for raw in sys.stdin:
                    loop.call_soon_threadsafe(queue.put_nowait, raw)
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        threading.Thread(target=_reader, daemon=True).start()
        while True:
            line = await queue.get()
            if line is None:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if not isinstance(msg, dict):
                continue
            try:
                resp = await self.handle(msg)
            except Exception:
                log.exception("handle failed")
                resp = _error(msg.get("id"), -32603, "internal error")
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()


def _result(mid: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    args = list(argv if argv is not None else sys.argv[1:])
    base = Path(args[0]).resolve() if args else Path.cwd()
    cfg = load_config(base)
    ctx = build_ops_context(cfg)
    tools = OpsTools(ctx)
    server = McpStdioServer(tools)
    log.info("ayana-mcp ready (base=%s)", base)
    asyncio.run(server.run_stdio())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
