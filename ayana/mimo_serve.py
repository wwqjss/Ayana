"""MiMoCode serve 客户端（实时 Agent 交互）。

复用 MiMoCode 开源 HTTP API（@mimo-ai/sdk 同协议）：
- POST /session                 建会话
- POST /session/{id}/prompt_async  非阻塞发消息（204）
- POST /session/{id}/abort      停止
- GET  /session/{id}/message    历史
- GET  /event                   SSE 事件流（session.status / message.part.delta / ...）

本模块负责：托管 mimo serve 子进程、HTTP 调用、SSE 事件泵落库。
不做：Agent 决策、审批语义（由 Ayana 侧策略负责）。
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import signal
import time
from typing import Any, Callable

log = __import__("logging").getLogger("ayana.mimo_serve")


class MimoServeError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.message = message or code
        super().__init__(f"{code}: {message}" if message else code)


class MimoServeClient:
    """对 mimo serve 的轻量 HTTP 客户端（aiohttp）。"""

    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:6290",
        username: str = "mimocode",
        password: str = "",
        timeout: float = 15.0,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.username = username or "mimocode"
        self.password = password or ""
        self.timeout = timeout

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        h = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        if extra:
            h.update(extra)
        return h

    async def _request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        timeout: float | None = None,
        expect_json: bool = True,
    ) -> Any:
        import aiohttp

        url = self.base_url + path
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    json=body if body is not None else None,
                    headers=self._headers(
                        {"Content-Type": "application/json"} if body is not None else None
                    ),
                    timeout=aiohttp.ClientTimeout(total=timeout or self.timeout),
                ) as resp:
                    if resp.status >= 400:
                        text = (await resp.text())[:300]
                        raise MimoServeError(f"http_{resp.status}", text)
                    if resp.status == 204 or not expect_json:
                        return {"ok": True, "status": resp.status}
                    raw = await resp.text()
                    if not raw:
                        return {"ok": True, "status": resp.status}
                    try:
                        return json.loads(raw)
                    except Exception:
                        return {"ok": True, "raw": raw[:2000]}
        except MimoServeError:
            raise
        except Exception as e:  # noqa: BLE001
            raise MimoServeError("unreachable", str(e)[:200]) from e

    async def health(self) -> dict[str, Any]:
        try:
            data = await self._request("GET", "/session/status", timeout=5)
            return {"ok": True, "status": data}
        except MimoServeError as e:
            return {"ok": False, "error": e.code, "message": e.message}

    async def create_session(self, *, title: str = "", directory: str = "") -> dict[str, Any]:
        body: dict[str, Any] = {}
        if title:
            body["title"] = title[:120]
        if directory:
            body["directory"] = directory
        data = await self._request("POST", "/session", body=body)
        sid = ""
        if isinstance(data, dict):
            sid = str(data.get("id") or (data.get("data") or {}).get("id") or "")
        if not sid:
            raise MimoServeError("create_failed", str(data)[:200])
        return {"ok": True, "session_id": sid, "info": data}

    async def prompt_async(self, session_id: str, text: str, *, agent: str = "") -> dict[str, Any]:
        if not session_id:
            raise MimoServeError("session_id_required")
        parts = [{"type": "text", "text": (text or "")[:20000]}]
        body: dict[str, Any] = {"parts": parts}
        if agent:
            body["agent"] = agent
        await self._request("POST", f"/session/{session_id}/prompt_async", body=body, expect_json=False)
        return {"ok": True, "session_id": session_id}

    async def abort(self, session_id: str) -> dict[str, Any]:
        await self._request("POST", f"/session/{session_id}/abort", expect_json=False)
        return {"ok": True, "session_id": session_id}

    async def messages(self, session_id: str) -> list[dict[str, Any]]:
        data = await self._request("GET", f"/session/{session_id}/message")
        return data if isinstance(data, list) else []

    async def session_info(self, session_id: str) -> dict[str, Any]:
        data = await self._request("GET", f"/session/{session_id}")
        return data if isinstance(data, dict) else {}

    def open_event_stream(self, timeout: float = 300.0):
        """返回 aiohttp SSE 上下文（调用方在 async for 中读）。"""
        import aiohttp

        return aiohttp.ClientSession(
            headers=self._headers({"Accept": "text/event-stream"}),
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=10),
        ), self.base_url + "/event"


class MimoServeManager:
    """托管 mimo serve 子进程（127.0.0.1 + 密码）。"""

    def __init__(
        self,
        *,
        mimo_bin: str = "mimo",
        workdir: str = "",
        host: str = "127.0.0.1",
        port: int = 6290,
        username: str = "mimocode",
        password: str = "",
    ):
        self.mimo_bin = mimo_bin or "mimo"
        self.workdir = workdir or ""
        self.host = host
        self.port = int(port)
        self.username = username or "mimocode"
        self.password = password or ""
        self._proc: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def client(self) -> MimoServeClient:
        return MimoServeClient(
            base_url=self.base_url,
            username=self.username,
            password=self.password,
        )

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["MIMOCODE_SERVER_PASSWORD"] = self.password
        env["MIMOCODE_SERVER_USERNAME"] = self.username
        if self.workdir:
            env.setdefault("HOME", self.workdir)
        return env

    async def ensure_running(self) -> dict[str, Any]:
        c = self.client()
        h = await c.health()
        if h.get("ok"):
            return {"ok": True, "action": "already_running", "base_url": self.base_url}
        return await self.start()

    async def start(self) -> dict[str, Any]:
        if self._proc and self._proc.returncode is None:
            return {"ok": True, "action": "already_started", "base_url": self.base_url}
        argv = [
            self.mimo_bin,
            "serve",
            "--port",
            str(self.port),
            "--hostname",
            self.host,
        ]
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=self.workdir or None,
                env=self._env(),
            )
        except Exception as e:  # noqa: BLE001
            raise MimoServeError("spawn_failed", str(e)[:200]) from e
        # 等待就绪
        c = self.client()
        for _ in range(30):
            await asyncio.sleep(0.5)
            h = await c.health()
            if h.get("ok"):
                return {"ok": True, "action": "started", "base_url": self.base_url, "pid": self._proc.pid}
            if self._proc.returncode is not None:
                raise MimoServeError("exited", f"rc={self._proc.returncode}")
        raise MimoServeError("start_timeout", "mimo serve did not become ready")

    async def stop(self) -> dict[str, Any]:
        proc = self._proc
        self._proc = None
        if not proc or proc.returncode is not None:
            return {"ok": True, "action": "not_running"}
        try:
            proc.send_signal(signal.SIGTERM)
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return {"ok": True, "action": "stopped"}


class MimoEventPump:
    """订阅 mimo serve /event SSE，转成结构化回调（落库/转发）。"""

    def __init__(self, client: MimoServeClient, on_event: Callable[[dict[str, Any]], None] | None = None):
        self.client = client
        self.on_event = on_event
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self.recent: list[dict[str, Any]] = []

    def _emit(self, ev: dict[str, Any]) -> None:
        self.recent.append(ev)
        if len(self.recent) > 500:
            self.recent = self.recent[-300:]
        if self.on_event:
            try:
                self.on_event(ev)
            except Exception as e:  # noqa: BLE001
                log.warning("on_event failed: %s", e)

    async def run_forever(self) -> None:
        import aiohttp

        self._stop.clear()
        while not self._stop.is_set():
            try:
                async with aiohttp.ClientSession(
                    headers=self.client._headers({"Accept": "text/event-stream"}),
                    timeout=aiohttp.ClientTimeout(total=None, sock_connect=10),
                ) as session:
                    async with session.get(self.client.base_url + "/event") as resp:
                        if resp.status >= 400:
                            log.warning("mimo event stream http %s", resp.status)
                            await asyncio.sleep(3)
                            continue
                        buf = ""
                        async for chunk in resp.content.iter_any():
                            if self._stop.is_set():
                                break
                            buf += chunk.decode("utf-8", "replace")
                            while "\n\n" in buf:
                                raw, buf = buf.split("\n\n", 1)
                                data_lines = []
                                for line in raw.splitlines():
                                    if line.startswith("data:"):
                                        data_lines.append(line[5:].strip())
                                if not data_lines:
                                    continue
                                payload = "\n".join(data_lines)
                                try:
                                    ev = json.loads(payload)
                                except Exception:
                                    continue
                                if isinstance(ev, dict):
                                    self._emit(ev)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.warning("mimo event pump error: %s", e)
                await asyncio.sleep(3)

    def stop(self) -> None:
        self._stop.set()
        if self._task and not self._task.done():
            self._task.cancel()

    def start(self) -> asyncio.Task:
        self._task = asyncio.create_task(self.run_forever())
        return self._task


def translate_event(ev: dict[str, Any]) -> dict[str, Any] | None:
    """把 mimo 事件压成工作台可展示的紧凑结构。"""
    et = str(ev.get("type") or "")
    props = ev.get("properties") or {}
    sid = str(props.get("sessionID") or "")
    if et == "session.status":
        st = (props.get("status") or {}).get("type") or ""
        return {"kind": "status", "session_id": sid, "status": st}
    if et == "session.updated":
        info = props.get("info") or {}
        return {
            "kind": "session_updated",
            "session_id": sid,
            "title": info.get("title") or "",
            "updated_at": (info.get("time") or {}).get("updated") or 0,
        }
    if et == "message.updated":
        info = props.get("info") or {}
        return {
            "kind": "message",
            "session_id": sid,
            "message_id": info.get("id") or "",
            "role": info.get("role") or "",
        }
    if et == "message.part.updated":
        part = props.get("part") or {}
        ptype = str(part.get("type") or "")
        return {
            "kind": "part",
            "session_id": sid,
            "part_id": part.get("id") or "",
            "message_id": part.get("messageID") or "",
            "part_type": ptype,
            "text": (part.get("text") or "")[:4000],
            "tool": part.get("tool") or part.get("name") or "",
            "state": (part.get("state") or {}).get("status") if isinstance(part.get("state"), dict) else part.get("state"),
        }
    if et == "message.part.delta":
        return {
            "kind": "delta",
            "session_id": sid,
            "part_id": props.get("partID") or "",
            "message_id": props.get("messageID") or "",
            "field": props.get("field") or "text",
            "delta": (props.get("delta") or "")[:2000],
        }
    return {"kind": "raw", "type": et, "session_id": sid}
