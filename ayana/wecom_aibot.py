"""企业微信智能机器人 · WebSocket 长连接薄客户端（协议适配层）。

协议对齐官方文档 / aibot SDK，仅实现 Ayana 所需子集：
  认证 aibot_subscribe · 心跳 ping · 主动推送 aibot_send_msg · 收消息 aibot_msg_callback

设计约束：
- 只用 aiohttp WS，不引入 websockets / pyee
- 发送与回执用 req_id 关联；未回执视为「结果未知」，调用方不得盲目重发
- 一机器人一条连接；断线指数退避重连（服务期默认无限）
- 对外仅 send_text / status / on_message / start / stop；可整体替换为官方 SDK
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Awaitable, Callable

log = logging.getLogger("ayana.wecom_aibot")

DEFAULT_WS_URL = "wss://openws.work.weixin.qq.com"
HEARTBEAT_SEC = 30.0
ACK_TIMEOUT_SEC = 8.0
RECONNECT_BASE_SEC = 1.0
RECONNECT_MAX_SEC = 30.0
MAX_MISSED_PONG = 2

# 主动推送：markdown 正文上限（官方）
MARKDOWN_MAX_BYTES = 20480


def _req_id(cmd: str) -> str:
    return f"{cmd}_{uuid.uuid4().hex[:16]}"


class WeComAibotError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class WeComAibotClient:
    """单机器人长连接。线程不安全，只在事件循环里用。"""

    def __init__(
        self,
        *,
        bot_id: str,
        secret: str,
        ws_url: str = "",
        on_message: Callable[[dict], Awaitable[None] | None] | None = None,
        on_status: Callable[[dict], None] | None = None,
    ):
        self.bot_id = bot_id
        self._secret = secret
        self.ws_url = (ws_url or DEFAULT_WS_URL).strip() or DEFAULT_WS_URL
        self._on_message = on_message
        self._on_status = on_status

        self._ws: Any = None
        self._session: Any = None
        self._recv_task: asyncio.Task | None = None
        self._hb_task: asyncio.Task | None = None
        self._run_task: asyncio.Task | None = None
        self._pending: dict[str, asyncio.Future] = {}
        self._stopped = False
        self._authenticated = False
        self._missed_pong = 0
        self._reconnect_try = 0
        self._connected_at: float | None = None
        self._last_error = ""
        self._last_status = "init"

    # ---- status ----

    def status(self) -> dict[str, Any]:
        return {
            "bot_id": self.bot_id,
            "ws_url": self.ws_url,
            "connected": bool(self._ws and not self._ws.closed),
            "authenticated": self._authenticated,
            "state": self._last_status,
            "error": self._last_error,
            "connected_at": self._connected_at,
            "reconnect_try": self._reconnect_try,
            "pending_acks": len(self._pending),
        }

    def _set_status(self, state: str, error: str = "") -> None:
        self._last_status = state
        self._last_error = error[:200]
        self._notify_status()

    def _notify_status(self) -> None:
        if not self._on_status:
            return
        try:
            self._on_status(self.status())
        except Exception:
            pass

    # ---- lifecycle ----

    def start(self) -> None:
        """启动后台连接（幂等）。"""
        self._stopped = False
        if self._run_task and not self._run_task.done():
            return
        self._run_task = asyncio.create_task(self._run(), name=f"wecom-aibot-{self.bot_id}")

    async def stop(self) -> None:
        self._stopped = True
        self._authenticated = False
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(WeComAibotError("closed", "connection stopping"))
        self._pending.clear()
        for t in (self._hb_task, self._recv_task, self._run_task):
            if t and not t.done():
                t.cancel()
        self._hb_task = self._recv_task = self._run_task = None
        await self._close_ws()
        self._set_status("stopped")

    async def _close_ws(self) -> None:
        ws, self._ws = self._ws, None
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass
        sess, self._session = self._session, None
        if sess is not None:
            try:
                await sess.close()
            except Exception:
                pass

    async def _run(self) -> None:
        while not self._stopped:
            try:
                await self._connect_once()
                self._reconnect_try = 0
                self._set_status("connected")
                # 等到连接结束
                if self._recv_task:
                    await self._recv_task
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self._last_error = str(e)[:200]
                log.warning("wecom aibot connect error: %s", e)
            finally:
                self._authenticated = False
                self._fail_pending(WeComAibotError("disconnected", "connection lost"))
                await self._close_ws()
            if self._stopped:
                break
            self._reconnect_try += 1
            delay = min(RECONNECT_MAX_SEC, RECONNECT_BASE_SEC * (2 ** min(self._reconnect_try - 1, 5)))
            self._set_status("reconnecting", self._last_error)
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                raise

    def _fail_pending(self, exc: Exception) -> None:
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(exc)
        self._pending.clear()

    async def _connect_once(self) -> None:
        import aiohttp

        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=15)
        )
        self._set_status("connecting")
        self._ws = await self._session.ws_connect(self.ws_url, heartbeat=None, autoping=True)
        self._connected_at = time.time()
        self._missed_pong = 0
        # 认证
        auth_id = _req_id("aibot_subscribe")
        await self._send_frame(
            {
                "cmd": "aibot_subscribe",
                "headers": {"req_id": auth_id},
                "body": {"bot_id": self.bot_id, "secret": self._secret},
            }
        )
        self._recv_task = asyncio.create_task(self._recv_loop(), name="wecom-aibot-recv")
        self._hb_task = asyncio.create_task(self._heartbeat_loop(), name="wecom-aibot-hb")
        # 等认证回执（短等）
        try:
            await asyncio.wait_for(self._wait_auth(auth_id), timeout=ACK_TIMEOUT_SEC)
            self._authenticated = True
            self._set_status("authenticated")
        except asyncio.TimeoutError:
            raise WeComAibotError("auth_timeout", "no subscribe ack")
        except WeComAibotError:
            raise
        except Exception as e:
            raise WeComAibotError("auth_failed", str(e)) from e

    async def _wait_auth(self, auth_id: str) -> None:
        # 认证回执由 _recv_loop 根据 req_id 前缀 aibot_subscribe 处理并置位
        deadline = time.time() + ACK_TIMEOUT_SEC
        while time.time() < deadline:
            if self._authenticated:
                return
            if self._ws is None or self._ws.closed:
                raise WeComAibotError("closed", "socket closed during auth")
            await asyncio.sleep(0.05)
        raise WeComAibotError("auth_timeout")

    async def _send_frame(self, frame: dict) -> None:
        ws = self._ws
        if ws is None or ws.closed:
            raise WeComAibotError("not_connected")
        await ws.send_str(json.dumps(frame, ensure_ascii=False))

    async def _heartbeat_loop(self) -> None:
        try:
            while not self._stopped:
                await asyncio.sleep(HEARTBEAT_SEC)
                if self._ws is None or self._ws.closed:
                    return
                if self._missed_pong >= MAX_MISSED_PONG:
                    log.warning("wecom aibot heartbeat dead, closing")
                    try:
                        await self._ws.close()
                    except Exception:
                        pass
                    return
                rid = _req_id("ping")
                try:
                    await self._send_frame(
                        {"cmd": "ping", "headers": {"req_id": rid}, "body": {}}
                    )
                    self._missed_pong += 1
                except Exception:
                    return
        except asyncio.CancelledError:
            pass

    async def _recv_loop(self) -> None:
        ws = self._ws
        if ws is None:
            return
        try:
            async for msg in ws:
                if msg.type.name in ("TEXT", "text") or hasattr(msg, "data") and isinstance(msg.data, str):
                    raw = msg.data if isinstance(msg.data, str) else ""
                    if not raw:
                        continue
                    try:
                        frame = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    await self._handle_frame(frame)
                elif msg.type.name in ("ERROR", "error"):
                    break
                elif msg.type.name in ("CLOSE", "close", "CLOSED", "closed"):
                    break
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.debug("wecom aibot recv end: %s", e)

    async def _handle_frame(self, frame: dict) -> None:
        req_id = str((frame.get("headers") or {}).get("req_id") or "")
        cmd = str(frame.get("cmd") or "")
        errcode = frame.get("errcode")

        # 认证回执
        if req_id.startswith("aibot_subscribe") or cmd == "aibot_subscribe":
            if errcode in (0, None):
                self._authenticated = True
            else:
                self._last_error = f"auth_{errcode}:{frame.get('errmsg')}"
                try:
                    if self._ws:
                        await self._ws.close()
                except Exception:
                    pass
            return

        # 心跳
        if req_id.startswith("ping") or cmd == "ping":
            self._missed_pong = 0
            return

        # 主动推送回执：与 pending future 关联
        if req_id and req_id in self._pending:
            fut = self._pending.pop(req_id, None)
            if fut and not fut.done():
                if errcode in (0, None):
                    fut.set_result(frame)
                else:
                    fut.set_exception(
                        WeComAibotError(
                            f"send_{errcode}", str(frame.get("errmsg") or "")[:120]
                        )
                    )
            return

        # 消息 / 事件推送
        if cmd in ("aibot_msg_callback", "aibot_event_callback"):
            if self._on_message:
                try:
                    res = self._on_message(frame)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    log.exception("wecom aibot on_message failed")

    # ---- send ----

    async def send_text(self, chatid: str, content: str) -> tuple[bool, str]:
        """主动推送到会话。返回 (ok, err)。

        ok=True  → 已收到 errcode=0 回执
        ok=False → 明确失败（可重试）或结果未知（err 以 unknown: 开头，调用方勿盲目重发）
        """
        if not chatid:
            return False, "missing_target"
        text = content or ""
        raw = text.encode("utf-8")
        if len(raw) > MARKDOWN_MAX_BYTES:
            text = text.encode("utf-8")[: MARKDOWN_MAX_BYTES - 12].decode("utf-8", "ignore") + "\n…"
        if self._ws is None or self._ws.closed or not self._authenticated:
            return False, "unknown:not_authenticated"
        rid = _req_id("aibot_send_msg")
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[rid] = fut
        try:
            await self._send_frame(
                {
                    "cmd": "aibot_send_msg",
                    "headers": {"req_id": rid},
                    "body": {
                        "chatid": chatid,
                        "msgtype": "markdown",
                        "markdown": {"content": text},
                    },
                }
            )
        except Exception as e:
            self._pending.pop(rid, None)
            return False, f"unknown:send_error:{str(e)[:80]}"
        try:
            await asyncio.wait_for(fut, timeout=ACK_TIMEOUT_SEC)
            return True, ""
        except asyncio.TimeoutError:
            self._pending.pop(rid, None)
            return False, "unknown:ack_timeout"
        except WeComAibotError as e:
            return False, str(e)[:160]
        except Exception as e:
            self._pending.pop(rid, None)
            return False, f"unknown:{str(e)[:80]}"


class WeComAibotManager:
    """按渠道维护长连接（一机器人一条）。"""

    def __init__(
        self,
        on_message: Callable[[str, dict], Awaitable[None] | None] | None = None,
    ):
        self._clients: dict[str, WeComAibotClient] = {}
        self._on_message = on_message
        self._status: dict[str, dict] = {}

    def status_all(self) -> dict[str, dict]:
        out = dict(self._status)
        for cid, c in self._clients.items():
            out[cid] = c.status()
        return out

    def status(self, channel_id: str) -> dict[str, Any]:
        c = self._clients.get(channel_id)
        return c.status() if c else self._status.get(channel_id, {"state": "down", "connected": False})

    async def ensure(self, channel_id: str, *, bot_id: str, secret: str, ws_url: str = "") -> None:
        cur = self._clients.get(channel_id)
        if cur and cur.bot_id == bot_id and cur._secret == secret and cur.status().get("connected"):
            return
        if cur:
            await cur.stop()
            self._clients.pop(channel_id, None)

        async def _msg(frame: dict, _cid: str = channel_id) -> None:
            if self._on_message:
                res = self._on_message(_cid, frame)
                if asyncio.iscoroutine(res):
                    await res

        client = WeComAibotClient(
            bot_id=bot_id,
            secret=secret,
            ws_url=ws_url,
            on_message=_msg,
            on_status=lambda st, _cid=channel_id: self._status.__setitem__(_cid, st),
        )
        self._clients[channel_id] = client
        client.start()

    async def stop(self, channel_id: str) -> None:
        c = self._clients.pop(channel_id, None)
        if c:
            await c.stop()
        self._status[channel_id] = {"state": "stopped", "connected": False}

    async def stop_all(self) -> None:
        for cid in list(self._clients):
            await self.stop(cid)

    async def send_text(self, channel_id: str, chatid: str, content: str) -> tuple[bool, str]:
        c = self._clients.get(channel_id)
        if not c:
            return False, "unknown:client_not_running"
        try:
            return await c.send_text(chatid, content)
        except Exception as e:
            return False, f"unknown:{str(e)[:80]}"
