"""OneBot v11 反向 WS：echo 关联、单连接发送、事件去重、命令分发。"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Awaitable, Callable

from aiohttp import web, WSMsgType

log = logging.getLogger("ayana.onewbot")

RECENT_TTL = 300


class OneBotServer:
    def __init__(self, token: str, self_id: int = 0):
        self.token = token
        self.self_id = int(self_id or 0)
        self._connections: dict[str, web.WebSocketResponse] = {}
        self._echo_counter = 0
        self._pending: dict[str, asyncio.Future] = {}
        self._recent_msgs: dict[str, float] = {}
        self._on_message: Callable[[dict], Awaitable[None]] | None = None

    def set_message_handler(self, handler: Callable[[dict], Awaitable[None]]) -> None:
        self._on_message = handler

    @property
    def connected(self) -> bool:
        return any(not ws.closed for ws in self._connections.values())

    def connection_count(self) -> int:
        return sum(1 for ws in self._connections.values() if not ws.closed)

    def _auth_ok(self, request: web.Request) -> bool:
        auth = request.headers.get("Authorization", "")
        qtoken = request.rel_url.query.get("access_token", "")
        supplied = ""
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
        elif qtoken:
            supplied = qtoken
        return bool(self.token) and supplied == self.token

    async def handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        if not self._auth_ok(request):
            log.warning("ws auth failed from %s", request.remote)
            return web.Response(status=401, text="unauthorized")

        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        conn_id = f"{request.remote}:{id(ws)}"
        self._connections[conn_id] = ws
        log.info("ws connected %s (total=%d)", conn_id, self.connection_count())

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    # 接收循环不得阻塞在业务 handler 上，否则 echo 永远读不到
                    try:
                        frame = json.loads(msg.data)
                    except json.JSONDecodeError:
                        log.warning("bad json frame: %.200s", msg.data)
                        continue
                    echo = frame.get("echo")
                    if echo and echo in self._pending:
                        fut = self._pending.get(echo)
                        if fut and not fut.done():
                            fut.set_result(frame)
                        continue
                    try:
                        asyncio.create_task(self._dispatch_frame(frame))
                    except RuntimeError:
                        await self._dispatch_frame(frame)
                elif msg.type == WSMsgType.ERROR:
                    log.error("ws error: %s", ws.exception())
        finally:
            self._connections.pop(conn_id, None)
            log.info("ws disconnected %s (total=%d)", conn_id, self.connection_count())
        return ws

    async def _dispatch_frame(self, frame: dict) -> None:
        post_type = frame.get("post_type", "")
        if post_type == "meta_event":
            return
        if post_type == "message":
            await self._handle_message(frame)
            return
        if post_type in ("notice", "request"):
            log.info("%s: %s", post_type, frame.get("notice_type") or frame.get("request_type"))
            return

    async def _on_frame(self, ws: web.WebSocketResponse, raw: str) -> None:
        try:
            frame = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("bad json frame: %.200s", raw)
            return
        await self._dispatch_frame(frame)

    async def _handle_message(self, event: dict) -> None:
        # self_id 校验
        if self.self_id and event.get("self_id") and int(event["self_id"]) != self.self_id:
            log.warning("self_id mismatch: %s", event.get("self_id"))
            return
        message_id = str(event.get("message_id") or "")
        if message_id:
            now = time.time()
            self._recent_msgs = {
                k: v for k, v in self._recent_msgs.items() if now - v < RECENT_TTL
            }
            if message_id in self._recent_msgs:
                log.debug("duplicate message %s", message_id)
                return
            self._recent_msgs[message_id] = now

        if self._on_message:
            try:
                await self._on_message(event)
            except Exception:
                log.exception("message handler failed")

    def _pick_ws(self) -> web.WebSocketResponse | None:
        for ws in self._connections.values():
            if not ws.closed:
                return ws
        return None

    async def call_action(
        self, action: str, params: dict, timeout: float = 10.0
    ) -> dict[str, Any] | None:
        ws = self._pick_ws()
        if not ws:
            return None
        self._echo_counter += 1
        echo = f"e{self._echo_counter}"
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[echo] = fut
        payload = {"action": action, "params": params, "echo": echo}
        try:
            await ws.send_str(json.dumps(payload, ensure_ascii=False))
            return await asyncio.wait_for(fut, timeout=timeout)
        except Exception as e:
            log.warning("action %s failed: %s", action, e)
            return None
        finally:
            self._pending.pop(echo, None)

    async def send_private(self, user_id: int | str, text: str) -> bool:
        res = await self.call_action(
            "send_private_msg",
            {
                "user_id": int(user_id),
                "message": [{"type": "text", "data": {"text": text}}],
            },
        )
        return bool(res and res.get("retcode") == 0)

    async def send_group(self, group_id: int | str, text: str) -> bool:
        res = await self.call_action(
            "send_group_msg",
            {
                "group_id": int(group_id),
                "message": [{"type": "text", "data": {"text": text}}],
            },
        )
        return bool(res and res.get("retcode") == 0)

    async def send_to_target(self, target: str, text: str) -> bool:
        """target: 'user:123' 或 'group:456' 或纯数字（私聊）。"""
        if target.startswith("group:"):
            return await self.send_group(target.split(":", 1)[1], text)
        if target.startswith("user:"):
            return await self.send_private(target.split(":", 1)[1], text)
        return await self.send_private(target, text)


def extract_text(event: dict) -> str:
    msg = event.get("message")
    if isinstance(msg, str):
        return msg.strip()
    if isinstance(msg, list):
        parts = []
        for seg in msg:
            if isinstance(seg, dict) and seg.get("type") == "text":
                parts.append(seg.get("data", {}).get("text", ""))
        return "".join(parts).strip()
    raw = event.get("raw_message", "")
    return raw.strip() if isinstance(raw, str) else ""
