"""Ayana v0.1.0 — 最小 QQ 收发实验。

脱离 AstrBot，直接以 OneBot v11 反向 WS 服务端接管 NapCat。
本版只做：/ping、/health、日志、独立配置。
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time
from pathlib import Path

from aiohttp import web, WSMsgType

log = logging.getLogger("ayana")

VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------


def load_config(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        log.error("config not found: %s", p)
        sys.exit(1)
    cfg = json.loads(p.read_text(encoding="utf-8"))
    required = ("ws_port", "token")
    for k in required:
        if k not in cfg:
            log.error("config missing key: %s", k)
            sys.exit(1)
    cfg.setdefault("ws_host", "0.0.0.0")
    cfg.setdefault("ws_path", "/ws")
    cfg.setdefault("http_host", "0.0.0.0")
    cfg.setdefault("http_port", 6200)
    cfg.setdefault("log_level", "INFO")
    cfg.setdefault("self_id", 0)
    return cfg


def setup_logging(level: str, log_file: str | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
    )


# ---------------------------------------------------------------------------
# OneBot v11 反向 WS 服务端
# ---------------------------------------------------------------------------


class OneBotReverseWS:
    """接受 NapCat 的 WS 客户端连接，收事件、发动作。"""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.token = cfg["token"]
        self.self_id = int(cfg.get("self_id") or 0)
        self._connections: set[web.WebSocketResponse] = set()
        self._echo_counter = 0

    # -- 连接管理 --

    @property
    def connected(self) -> bool:
        return bool(self._connections)

    async def handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        # token 校验：Authorization: Bearer <token>  或  ?access_token=
        auth = request.headers.get("Authorization", "")
        qtoken = request.rel_url.query.get("access_token", "")
        supplied = ""
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
        elif qtoken:
            supplied = qtoken
        if supplied != self.token:
            log.warning("ws auth failed from %s", request.remote)
            return web.Response(status=401, text="unauthorized")

        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        self._connections.add(ws)
        log.info("ws connected from %s (total=%d)", request.remote, len(self._connections))

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    await self._on_event(ws, msg.data)
                elif msg.type == WSMsgType.ERROR:
                    log.error("ws error: %s", ws.exception())
        finally:
            self._connections.discard(ws)
            log.info("ws disconnected (total=%d)", len(self._connections))
        return ws

    # -- 事件处理 --

    async def _on_event(self, ws: web.WebSocketResponse, raw: str) -> None:
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("bad json event: %.200s", raw)
            return

        post_type = event.get("post_type", "")
        if post_type == "meta_event":
            # 心跳，仅 debug
            log.debug("heartbeat ok")
            return
        if post_type == "message":
            await self._on_message(ws, event)
            return
        if post_type == "notice":
            log.info("notice: %s", event.get("notice_type"))
            return
        if post_type == "request":
            log.info("request: %s", event.get("request_type"))
            return
        log.debug("unhandled post_type=%s", post_type)

    async def _on_message(self, ws: web.WebSocketResponse, event: dict) -> None:
        message_type = event.get("message_type", "")
        user_id = event.get("user_id", 0)
        group_id = event.get("group_id", 0)
        raw_text = self._extract_text(event)
        log.info(
            "msg type=%s user=%s group=%s text=%.100s",
            message_type, user_id, group_id, raw_text,
        )

        reply = self._dispatch(raw_text)
        if not reply:
            return

        if message_type == "private":
            await self.send_private_msg(ws, user_id, reply)
        elif message_type == "group":
            await self.send_group_msg(ws, group_id, reply)
        else:
            log.warning("unknown message_type=%s", message_type)

    @staticmethod
    def _extract_text(event: dict) -> str:
        """从 array / string 两种 message 格式提取纯文本。"""
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

    # -- 命令分发 --

    def _dispatch(self, text: str) -> str | None:
        if not text:
            return None
        if text in ("/ping", "/Ping", "/PING"):
            return f"Ayana v{VERSION}\npong"
        if text in ("/health", "/Health", "/HEALTH"):
            return self._health_text()
        if text in ("/help", "/Help"):
            return (
                f"Ayana v{VERSION}\n"
                "/ping   响应测试\n"
                "/health 服务状态\n"
                "/help   本帮助"
            )
        return None

    def _health_text(self) -> str:
        status = "connected" if self.connected else "disconnected"
        return (
            f"Ayana v{VERSION}\n"
            f"status: ok\n"
            f"napcat: {status}\n"
            f"connections: {len(self._connections)}\n"
            f"uptime: {int(time.time() - _START_TIME)}s"
        )

    # -- 发送 --

    async def _send_action(self, ws: web.WebSocketResponse, action: str, params: dict) -> dict | None:
        self._echo_counter += 1
        payload = {"action": action, "params": params, "echo": str(self._echo_counter)}
        try:
            await ws.send_str(json.dumps(payload, ensure_ascii=False))
        except Exception as e:
            log.error("send action failed: %s", e)
            return None
        return payload

    async def send_private_msg(self, ws: web.WebSocketResponse, user_id: int, text: str) -> None:
        await self._send_action(ws, "send_private_msg", {
            "user_id": user_id,
            "message": [{"type": "text", "data": {"text": text}}],
        })

    async def send_group_msg(self, ws: web.WebSocketResponse, group_id: int, text: str) -> None:
        await self._send_action(ws, "send_group_msg", {
            "group_id": group_id,
            "message": [{"type": "text", "data": {"text": text}}],
        })

    async def send_private_to_napcat(self, user_id: int, text: str) -> bool:
        """向 NapCat 连接推送私聊消息；返回是否至少发出一次。"""
        ok = False
        for ws in list(self._connections):
            if ws.closed:
                continue
            payload = await self._send_action(ws, "send_private_msg", {
                "user_id": user_id,
                "message": [{"type": "text", "data": {"text": text}}],
            })
            if payload:
                ok = True
        return ok


# ---------------------------------------------------------------------------
# HTTP health
# ---------------------------------------------------------------------------

_START_TIME = time.time()


def make_http_app(agent: OneBotReverseWS) -> web.Application:
    app = web.Application()

    async def health(_req: web.Request) -> web.Response:
        return web.json_response({
            "ok": True,
            "service": "ayana",
            "version": VERSION,
            "napcat_connected": agent.connected,
            "connections": len(agent._connections),
            "uptime_sec": int(time.time() - _START_TIME),
        })

    app.router.add_get("/health", health)

    async def index(_req: web.Request) -> web.Response:
        html = Path(__file__).resolve().parent.parent / "index.html"
        if html.exists():
            return web.FileResponse(html)
        return web.Response(text="Ayana v0.1.0", content_type="text/plain")

    async def static_file(req: web.Request) -> web.Response:
        name = req.match_info.get("name", "")
        base = Path(__file__).resolve().parent.parent
        target = (base / name).resolve()
        if not str(target).startswith(str(base)) or not target.is_file():
            return web.Response(status=404, text="Not Found")
        return web.FileResponse(target)

    app.router.add_get("/", index)
    app.router.add_get("/{name}", static_file)

    async def send(req: web.Request) -> web.Response:
        try:
            body = await req.json()
        except Exception:
            return web.json_response({"ok": False, "error": "invalid json"}, status=400)
        user_id = body.get("user_id")
        message = body.get("message", "")
        if not user_id or not message:
            return web.json_response({"ok": False, "error": "user_id and message required"}, status=400)
        sent = await agent.send_private_to_napcat(int(user_id), str(message))
        return web.json_response({"ok": sent, "sent": sent})

    app.router.add_post("/send", send)
    return app


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


async def main(config_path: str) -> None:
    cfg = load_config(config_path)
    setup_logging(cfg["log_level"], cfg.get("log_file"))
    log.info("Ayana v%s starting", VERSION)

    agent = OneBotReverseWS(cfg)

    # WS 路由
    ws_app = web.Application()
    ws_app.router.add_get(cfg["ws_path"], agent.handle_ws)

    # HTTP health
    http_app = make_http_app(agent)

    ws_runner = web.AppRunner(ws_app)
    http_runner = web.AppRunner(http_app)
    await ws_runner.setup()
    await http_runner.setup()

    ws_site = web.TCPSite(ws_runner, cfg["ws_host"], cfg["ws_port"])
    http_site = web.TCPSite(http_runner, cfg["http_host"], cfg["http_port"])
    await ws_site.start()
    await http_site.start()

    log.info("ws  server listening on ws://%s:%s%s", cfg["ws_host"], cfg["ws_port"], cfg["ws_path"])
    log.info("http health on http://%s:%s/health", cfg["http_host"], cfg["http_port"])

    # 等待退出
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    log.info("shutting down …")
    await ws_runner.cleanup()
    await http_runner.cleanup()


def cli() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    try:
        asyncio.run(main(path))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    cli()
