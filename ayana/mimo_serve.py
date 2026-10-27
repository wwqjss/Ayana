"""One native MiMo server owns execution; HTTP/TUI clients only attach.

A 202 response is admission, not completion. Credentials stay in private runtime
configuration/environment, never URL arguments or returned provider errors.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import tempfile
import time
from typing import Any, Callable
from urllib.parse import quote, urlsplit

log = __import__("logging").getLogger("ayana.mimo_serve")
SERVICE_HOME = "/var/lib/ayana"
AGENT_WORKSPACE = "/var/lib/ayana/agent-workspace"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class MimoServeError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.message = message or code
        super().__init__(f"{code}: {self.message}")


def local_serve_url(value: str) -> str:
    """Native server credentials must never be sent to arbitrary endpoints."""
    try:
        parts = urlsplit(str(value or "").rstrip("/"))
        if (parts.scheme != "http" or parts.hostname not in ("127.0.0.1", "localhost", "::1")
                or parts.username is not None or parts.password is not None
                or parts.path not in ("", "/") or parts.query or parts.fragment
                or not parts.port or not 1 <= parts.port <= 65535):
            raise ValueError()
        return parts.geturl().rstrip("/")
    except (TypeError, ValueError):
        raise MimoServeError("invalid_serve_url", "MiMo server must use a fixed local endpoint") from None


def native_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", value):
        raise MimoServeError("invalid_native_id", "Invalid native session or receipt identifier")
    return quote(value, safe="")


def normalize_receipt_status(data: dict[str, Any]) -> str:
    """Normalize native receipt state and outcome without assuming success.

    MiMo 0.1.16 settles both successful and failed turns. ``settled`` alone
    cannot release a task lease or count as successful business completion.
    """
    if not isinstance(data, dict):
        return "unknown"
    value: Any = data.get("state") or data.get("status") or data.get("phase") or ""
    if isinstance(value, dict):
        value = value.get("type") or value.get("status") or value.get("state") or value.get("_tag") or value.get("tag") or ""
    value = str(value).lower().replace("-", "_")
    if value == "settled":
        outcome = data.get("outcome")
        if outcome == "success" and data.get("consumed") is True:
            return "completed"
        if outcome == "assistant_error":
            return "failed"
        if outcome in ("interrupted", "never_ran"):
            return "cancelled"
        return "unknown"
    if value in ("accepted", "queued", "admitted", "pending"):
        return "pending"
    if value in ("claimed", "running", "active", "in_progress"):
        return "running"
    if value in ("completed", "succeeded", "success", "done"):
        return "completed"
    if value in ("failed", "error", "rejected"):
        return "failed"
    if value in ("cancelled", "canceled", "aborted"):
        return "cancelled"
    return "unknown"


class MimoServeClient:
    def __init__(self, *, base_url: str = "http://127.0.0.1:6290", username: str = "mimocode",
                 password: str = "", timeout: float = 15.0, directory: str = "",
                 runtime_resolver: Callable[[], Any] | None = None):
        self.base_url = local_serve_url(base_url)
        self.username = username or "mimocode"
        self.password = password or ""
        self.timeout = timeout
        self.directory = str(directory or "")
        self.runtime_resolver = runtime_resolver

    def _admit(self) -> None:
        if self.runtime_resolver is not None:
            try:
                self.runtime_resolver()
            except MimoServeError:
                raise
            except Exception:
                raise MimoServeError("provider_not_verified", "Current model configuration is not verified") from None

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        if self.directory:
            headers["x-mimocode-directory"] = quote(self.directory, safe="")
        if extra:
            headers.update(extra)
        return headers

    async def _request(self, method: str, path: str, *, body: Any = None,
                       timeout: float | None = None, expect_json: bool = True,
                       include_status: bool = False, query: dict | None = None) -> Any:
        import aiohttp
        if not path.startswith("/") or path.startswith("//") or any(ord(c) < 32 for c in path):
            raise MimoServeError("invalid_path", "Invalid native server path")
        params = dict(query or {})
        if self.directory and method.upper() in ("GET", "HEAD"):
            params["directory"] = self.directory
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout or self.timeout)) as session:
                async with session.request(method, self.base_url + path, json=body,
                        params=params or None, headers=self._headers({"Content-Type": "application/json"} if body is not None else None),
                        allow_redirects=False) as response:
                    if 300 <= response.status < 400:
                        raise MimoServeError("redirect_rejected", "MiMo server redirect was rejected")
                    if response.status >= 400:
                        raise MimoServeError(f"http_{response.status}", "MiMo server rejected the request")
                    if response.status == 204:
                        data: Any = None
                    elif expect_json:
                        try:
                            raw = await response.content.readexactly(MAX_RESPONSE_BYTES + 1)
                        except asyncio.IncompleteReadError as error:
                            raw = error.partial
                        if len(raw) > MAX_RESPONSE_BYTES:
                            raise MimoServeError("response_too_large", "MiMo server response exceeds the allowed size")
                        try:
                            data = json.loads(raw)
                        except (ValueError, UnicodeError):
                            raise MimoServeError("invalid_response", "MiMo server did not return valid JSON") from None
                    else:
                        data = None
                    if include_status:
                        return {"status": response.status, "data": data}
                    return data if data is not None else {"ok": True, "status": response.status}
        except MimoServeError:
            raise
        except asyncio.TimeoutError:
            raise MimoServeError("timeout", "MiMo server request timed out") from None
        except Exception:
            raise MimoServeError("unreachable", "MiMo server connection failed") from None

    async def health(self) -> dict[str, Any]:
        try:
            data = await self._request("GET", "/session/status", timeout=5)
            if not isinstance(data, dict):
                raise MimoServeError("invalid_response", "MiMo status must be an object")
            return {"ok": True, "status": data}
        except MimoServeError as error:
            return {"ok": False, "error": error.code, "message": error.message}

    async def create_session(self, *, title: str = "", directory: str = "") -> dict[str, Any]:
        self._admit()
        if directory and directory != self.directory:
            raise MimoServeError("directory_mismatch", "Native session directory must match the runtime")
        data = await self._request("POST", "/session", body={"title": title[:120]} if title else {})
        inner = data.get("data") if isinstance(data, dict) else None
        sid = data.get("id") or (inner.get("id") if isinstance(inner, dict) else "") if isinstance(data, dict) else ""
        if not isinstance(sid, str) or not sid:
            raise MimoServeError("create_failed", "MiMo server did not return a session identifier")
        native_id(sid)
        return {"ok": True, "session_id": sid, "info": data}

    async def prompt_async(self, session_id: str, text: str, *, agent: str = "",
                           message_id: str = "", model: str = "") -> dict[str, Any]:
        self._admit()
        if not isinstance(text, str) or not text.strip() or len(text) > 20000:
            raise MimoServeError("invalid_prompt", "A nonempty prompt of at most 20000 characters is required")
        body: dict[str, Any] = {"parts": [{"type": "text", "text": text}]}
        if agent:
            body["agent"] = agent
        if message_id:
            native_id(message_id); body["messageID"] = message_id
        if model:
            provider, separator, selected = model.partition("/")
            if not separator or not provider or not selected:
                raise MimoServeError("invalid_model", "A provider/model identifier is required")
            body["model"] = {"providerID": provider, "modelID": selected}
        response = await self._request("POST", f"/session/{native_id(session_id)}/prompt_async", body=body, include_status=True)
        status, data = response["status"], response["data"]
        if status == 204:
            return {"ok": True, "accepted": False, "status": 204, "session_id": session_id, "message_id": message_id, "receipt_id": ""}
        receipt = data.get("receiptId") if isinstance(data, dict) else None
        if status != 202 or not isinstance(receipt, str) or not receipt:
            raise MimoServeError("invalid_receipt", "MiMo did not acknowledge a durable turn receipt")
        native_id(receipt)
        return {"ok": True, "accepted": True, "status": 202, "session_id": session_id, "message_id": message_id, "receipt_id": receipt}

    async def receipt(self, session_id: str, receipt_id: str) -> dict[str, Any]:
        data = await self._request("GET", f"/session/{native_id(session_id)}/receipt/{native_id(receipt_id)}")
        if not isinstance(data, dict):
            raise MimoServeError("invalid_receipt", "MiMo receipt must be an object")
        if data.get("id") not in (None, receipt_id):
            raise MimoServeError("receipt_binding_mismatch", "Native receipt identity does not match this turn")
        lane = data.get("lane")
        if lane is not None and (not isinstance(lane, dict) or lane.get("sessionID") != session_id):
            raise MimoServeError("receipt_binding_mismatch", "Native receipt belongs to another session")
        return data

    @staticmethod
    def receipt_state(data: dict) -> str:
        return normalize_receipt_status(data)

    async def wait_receipt(self, session_id: str, receipt_id: str, *, timeout: float = 120,
                           poll_interval: float = 0.3) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data = await self.receipt(session_id, receipt_id)
            state = self.receipt_state(data)
            if state in ("completed", "succeeded", "done"):
                return data
            if state in ("failed", "cancelled", "canceled", "aborted", "rejected"):
                raise MimoServeError("receipt_failed", "The native turn did not complete successfully")
            await asyncio.sleep(max(0.01, min(poll_interval, deadline - time.monotonic())))
        raise MimoServeError("receipt_pending", "The native turn remains pending; it was not replayed or aborted")

    async def abort(self, session_id: str) -> dict[str, Any]:
        await self._request("POST", f"/session/{native_id(session_id)}/abort", expect_json=False)
        return {"ok": True, "session_id": session_id}

    async def messages(self, session_id: str, *, limit: int = 100, before: str = "") -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise MimoServeError("invalid_limit", "History page size must be between 1 and 1000")
        query: dict[str, Any] = {"limit": limit}
        if before:
            native_id(before); query["before"] = before
        data = await self._request("GET", f"/session/{native_id(session_id)}/message", query=query)
        if not isinstance(data, list):
            raise MimoServeError("invalid_response", "MiMo history must be a list")
        return data

    async def session_info(self, session_id: str) -> dict[str, Any]:
        data = await self._request("GET", f"/session/{native_id(session_id)}")
        if not isinstance(data, dict):
            raise MimoServeError("invalid_response", "MiMo session information must be an object")
        return data

    async def session_status(self, session_id: str = "") -> dict[str, Any]:
        data = await self._request("GET", "/session/status")
        if not isinstance(data, dict):
            raise MimoServeError("invalid_response", "MiMo status must be an object")
        if not session_id:
            return data
        # Native /session/status omits idle lanes. An explicitly malformed or
        # unknown state must never be silently converted to idle.
        value = data.get(session_id, {"type": "idle"})
        if not isinstance(value, dict) or value.get("type") not in ("idle", "busy", "retry"):
            raise MimoServeError("session_state_unknown", "Native task state cannot be verified")
        return value

    async def require_session_idle(self, session_id: str) -> None:
        native_id(session_id)
        status = await self.session_status(session_id)
        if status.get("type") != "idle":
            raise MimoServeError("session_busy", "This native session already owns an active task")

    async def archive_session(self, session_id: str, *, archived: bool = True) -> dict[str, Any]:
        self._admit()
        if type(archived) is not bool:
            raise MimoServeError("invalid_archive", "Archive state must be a boolean")
        data = await self._request("PATCH", f"/session/{native_id(session_id)}",
                                   body={"time": {"archived": int(time.time() * 1000) if archived else 0}})
        return {"ok": True, "session_id": session_id, "info": data}

    def open_event_stream(self, timeout: float = 300.0):
        import aiohttp
        return aiohttp.ClientSession(headers=self._headers({"Accept": "text/event-stream"}),
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=10)), self.base_url + "/event"


class MimoServeManager:
    def __init__(self, *, mimo_bin: str = "mimo", workdir: str = "", host: str = "127.0.0.1", port: int = 6290,
                 username: str = "mimocode", password: str = "", home: str = SERVICE_HOME,
                 runtime_resolver: Callable[[], dict[str, Any]] | None = None,
                 managed_externally: bool = False, runtime_attestation_path: str = ""):
        self.mimo_bin = mimo_bin or "mimo"
        self.workdir = str(workdir or AGENT_WORKSPACE)
        self.home = str(home or SERVICE_HOME)
        self.host, self.port = host, int(port)
        self.username, self.password = username or "mimocode", password or ""
        local_serve_url(self.base_url)
        self.runtime_resolver = runtime_resolver
        self.managed_externally = bool(managed_externally)
        self.runtime_attestation_path = str(runtime_attestation_path or "")
        self._applied_digest = ""
        self._proc: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    @property
    def base_url(self) -> str:
        hostname = "[::1]" if self.host == "::1" else self.host
        return f"http://{hostname}:{self.port}"

    def _runtime(self) -> dict[str, Any]:
        if self.runtime_resolver is None:
            return {}
        try:
            runtime = self.runtime_resolver()
            if not isinstance(runtime, dict): raise ValueError()
            return runtime
        except Exception:
            raise MimoServeError("provider_not_verified", "Current model configuration is not verified") from None

    def _env(self, runtime: dict[str, Any] | None = None) -> dict[str, str]:
        from .mimo_session import READONLY_AGENT, DECISION_AGENT, MANAGED_AGENT, READONLY_TOOLS, DECISION_TOOLS
        runtime = self._runtime() if runtime is None else runtime
        try:
            config = json.loads(json.dumps(runtime.get("config") or {}))
            if not isinstance(config, dict): raise ValueError()
            agents = config.setdefault("agent", {})
            if not isinstance(agents, dict): raise ValueError()
            tools = tuple(dict.fromkeys(DECISION_TOOLS + READONLY_TOOLS))
            managed = runtime.get("managed_context") is True
            if managed:
                from .mcp_tools import TOOL_SPECS
                tools = tuple("ayana_" + spec["name"].replace(".", "_") for spec in TOOL_SPECS)
            policy = {"*": "deny", **dict.fromkeys(tools, "allow"), "mcp_tool_search": "allow"}
            for name, allowed in ((READONLY_AGENT, READONLY_TOOLS), (DECISION_AGENT, DECISION_TOOLS)):
                if name in agents and not isinstance(agents[name], dict): raise ValueError()
                agents.setdefault(name, {}).update({"mode": "primary", "disable": False,
                    "tool_allowlist": list(allowed), "permission": {"*": "deny", **dict.fromkeys(allowed, "allow"), "mcp_tool_search": "allow"}})
            if managed:
                # Schemas stay stable throughout a turn. Each actual MCP call
                # is authorized from native metadata and live session state.
                agents[MANAGED_AGENT] = {"mode":"primary", "disable":False, "tool_allowlist":list(tools), "permission":policy}
            config["default_agent"] = MANAGED_AGENT if managed else READONLY_AGENT
            config["permission"] = policy
            mcp = config.setdefault("mcp", {})
            if not isinstance(mcp, dict): raise ValueError()
            if "ayana" in mcp:
                if not isinstance(mcp["ayana"], dict): raise ValueError()
                environment = mcp["ayana"].setdefault("environment", {})
                if not isinstance(environment, dict): raise ValueError()
                environment["AYANA_MCP_READONLY"] = "0" if managed else "1"
                if managed: environment["AYANA_MCP_MANAGED_CONTEXT"] = "1"
            env = {**os.environ, **{str(k): str(v) for k, v in (runtime.get("environment") or {}).items()}}
            env.update({"HOME": self.home, "XDG_CONFIG_HOME": str(Path(self.home) / ".config"),
                        "XDG_DATA_HOME": str(Path(self.home) / ".local" / "share"),
                        "XDG_CACHE_HOME": str(Path(self.home) / ".cache"),
                        "XDG_STATE_HOME": str(Path(self.home) / ".local" / "state"),
                        "MIMOCODE_SERVER_PASSWORD": self.password, "MIMOCODE_SERVER_USERNAME": self.username,
                        "MIMOCODE_CONFIG_CONTENT": json.dumps(config, ensure_ascii=False),
                        "MIMOCODE_PERMISSION": json.dumps(policy), "AYANA_MCP_READONLY": "0" if managed else "1"})
            if managed: env["AYANA_MCP_MANAGED_CONTEXT"] = "1"
            env.pop("MIMOCODE_HOME", None)
            if runtime.get("config_path"): env["MIMOCODE_CONFIG"] = str(runtime["config_path"])
            binary = str(runtime.get("mimo_bin") or self.mimo_bin)
            extra = ([str(Path(binary).parent)] if os.path.isabs(binary) else [])
            extra += [str(Path(self.home) / ".mimocode" / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]
            env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
            return env
        except (TypeError, ValueError):
            raise MimoServeError("runtime_config_invalid", "Native runtime configuration must contain valid objects") from None

    def _digest(self, runtime: dict[str, Any]) -> str:
        env = self._env(runtime)
        material = {"home": self.home, "workdir": self.workdir,
                    "binary": str(runtime.get("mimo_bin") or self.mimo_bin),
                    "config": env["MIMOCODE_CONFIG_CONTENT"], "config_path": env.get("MIMOCODE_CONFIG", ""),
                    "permission": env["MIMOCODE_PERMISSION"], "environment": runtime.get("environment") or {}}
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def _process_start(pid: int) -> str:
        if os.name != "posix" or not Path("/proc").is_dir(): return ""
        try: return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        except (OSError, IndexError): return ""

    def _write_attestation(self, digest: str) -> None:
        if not self.runtime_attestation_path or self._proc is None: return
        path = Path(self.runtime_attestation_path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        data = {"version": 1, "config_digest": digest, "home": self.home, "workdir": self.workdir,
                "owner_pid": self._proc.pid, "owner_start": self._process_start(self._proc.pid)}
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".serve-", delete=False, mode="w", encoding="utf-8") as stream:
                temporary = Path(stream.name); os.chmod(temporary, 0o600)
                json.dump(data, stream); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path); temporary = None
        finally:
            if temporary is not None: temporary.unlink(missing_ok=True)

    def _verify_attestation(self, digest: str) -> None:
        try:
            path = Path(self.runtime_attestation_path)
            if not self.runtime_attestation_path or path.is_symlink(): raise ValueError()
            data = json.loads(path.read_text())
            if (data.get("config_digest") != digest or data.get("home") != self.home or data.get("workdir") != self.workdir):
                raise MimoServeError("runtime_changed", "Native runtime must be reconciled before accepting a new turn")
            pid = data.get("owner_pid")
            if type(pid) is not int or pid <= 0: raise ValueError()
            if os.name == "posix" and Path("/proc").is_dir():
                actual = self._process_start(pid)
                if not actual or actual != data.get("owner_start"): raise ValueError()
        except MimoServeError: raise
        except Exception:
            raise MimoServeError("runtime_attestation_missing", "Native runtime identity could not be verified") from None

    def validate_runtime(self) -> dict[str, Any]:
        runtime = self._runtime()
        if self.runtime_resolver is None: return runtime
        digest = self._digest(runtime)
        if self.managed_externally: self._verify_attestation(digest)
        elif not self._applied_digest or self._applied_digest != digest:
            raise MimoServeError("runtime_changed", "Native runtime must be reconciled before accepting a new turn")
        return runtime

    def client(self) -> MimoServeClient:
        return MimoServeClient(base_url=self.base_url, username=self.username, password=self.password,
            directory=self.workdir, runtime_resolver=self.validate_runtime if self.runtime_resolver else None)

    async def ensure_running(self) -> dict[str, Any]:
        runtime = self._runtime()
        digest = self._digest(runtime)
        if self.managed_externally:
            self._verify_attestation(digest)
            if not (await self.client().health()).get("ok"):
                raise MimoServeError("serve_unavailable", "The external native runtime is unavailable")
            return {"ok": True, "action": "external_running", "base_url": self.base_url}
        health = await self.client().health()
        if health.get("ok"):
            if self.runtime_resolver and self._applied_digest != digest:
                raise MimoServeError("runtime_changed", "Refusing an unverified or stale native server")
            return {"ok": True, "action": "already_running", "base_url": self.base_url}
        return await self.start(runtime=runtime)

    async def start(self, *, runtime: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.managed_externally:
            raise MimoServeError("external_runtime", "Native runtime is managed independently of the Web process")
        runtime = self._runtime() if runtime is None else runtime
        digest = self._digest(runtime)
        if self._proc and self._proc.returncode is None:
            if self._applied_digest != digest:
                raise MimoServeError("runtime_changed", "A running native task will not be interrupted for reconfiguration")
            if not (await self.client().health()).get("ok"):
                raise MimoServeError("serve_unavailable", "The owned native process is not ready")
            return {"ok": True, "action": "already_started", "base_url": self.base_url}
        try:
            self._proc = await asyncio.create_subprocess_exec(str(runtime.get("mimo_bin") or self.mimo_bin),
                "serve", "--port", str(self.port), "--hostname", self.host,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                cwd=self.workdir, env=self._env(runtime))
        except Exception:
            raise MimoServeError("spawn_failed", "Native MiMo process could not be started") from None
        self._applied_digest = digest
        for _ in range(30):
            if self._proc.returncode is not None:
                raise MimoServeError("exited", "Native MiMo process exited before readiness")
            if (await self.client().health()).get("ok"):
                self._write_attestation(digest)
                return {"ok": True, "action": "started", "base_url": self.base_url, "pid": self._proc.pid}
            await asyncio.sleep(0.5)
        raise MimoServeError("start_timeout", "Native MiMo server did not become ready")

    async def stop(self) -> dict[str, Any]:
        if self.managed_externally:
            return {"ok": True, "action": "external_runtime_preserved"}
        proc, self._proc = self._proc, None
        self._applied_digest = ""
        if not proc or proc.returncode is not None: return {"ok": True, "action": "not_running"}
        try:
            proc.send_signal(signal.SIGTERM); await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            try: proc.kill(); await proc.wait()
            except Exception: pass
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
