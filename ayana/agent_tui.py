"""Persistent native MiMo terminals and a session-scoped loopback proxy.

The browser owns an attach client, never the tmux pane or model task. The
native TUI does not receive the serve administrator credential. POSIX imports
are lazy so ordinary Windows unit tests can still import this module.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from typing import Any, Callable
from urllib.parse import quote

log = __import__("logging").getLogger("ayana.agent_tui")

LOCAL_ID = re.compile(r"sess_[A-Za-z0-9_-]{1,80}\Z")
REMOTE_ID = re.compile(r"ses_[A-Za-z0-9_-]{1,160}\Z")
MAX_INPUT = 16384
MAX_BODY = 131072
MAX_UPSTREAM_BYTES = 8 * 1024 * 1024
CONTROL_SECONDS = 60.0
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS agent_runtime_bindings (
 session_id TEXT PRIMARY KEY, remote_session_id TEXT NOT NULL DEFAULT '',
 runtime_id TEXT NOT NULL DEFAULT '', engine_pid INTEGER NOT NULL DEFAULT 0,
 engine_started_at TEXT NOT NULL DEFAULT '', tmux_name TEXT UNIQUE,
 pane_id TEXT NOT NULL DEFAULT '', pane_pid INTEGER NOT NULL DEFAULT 0,
 pane_started_at TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'idle',
 receipt_id TEXT NOT NULL DEFAULT '', receipt_status TEXT NOT NULL DEFAULT '',
 controller TEXT NOT NULL DEFAULT '', controller_connection_id TEXT NOT NULL DEFAULT '',
 control_token_hash TEXT NOT NULL DEFAULT '', control_expires_at REAL NOT NULL DEFAULT 0,
 created_at REAL NOT NULL, updated_at REAL NOT NULL
);
"""


class AgentTuiError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _local_id(value: str) -> str:
    if not isinstance(value, str) or not LOCAL_ID.fullmatch(value):
        raise AgentTuiError("invalid_session")
    return value


def _remote_id(value: str) -> str:
    if not isinstance(value, str) or not REMOTE_ID.fullmatch(value):
        raise AgentTuiError("invalid_remote_session")
    return value


def _identity(pid: int) -> str:
    try:
        raw = Path(f"/proc/{int(pid)}/stat").read_text()
        return raw[raw.rfind(")") + 2:].split()[19]
    except (OSError, ValueError, IndexError):
        return ""


def _read_private(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise AgentTuiError("unsafe_runtime_file")
    st = path.stat()
    if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o077):
        raise AgentTuiError("unsafe_runtime_file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        raise AgentTuiError("invalid_runtime_file") from None
    if not isinstance(value, dict):
        raise AgentTuiError("invalid_runtime_file")
    return value


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise AgentTuiError("unsafe_runtime_directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        if path.stat().st_uid != os.geteuid():
            raise AgentTuiError("unsafe_runtime_directory")
        path.chmod(0o700)


def _atomic_private(path: Path, value: dict) -> None:
    import tempfile
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".runtime-", delete=False, mode="w", encoding="utf-8") as stream:
            temporary = Path(stream.name)
            if os.name == "posix":
                os.chmod(temporary, 0o600)
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class AgentTuiManager:
    def __init__(self, db: Any, serve_client_factory: Callable[[], Any], *,
                 mimo_bin: str = "/var/lib/ayana/.mimocode/bin/mimo",
                 workdir: str = "/var/lib/ayana/agent-workspace", home: str = "/var/lib/ayana",
                 state_dir: str = "/var/lib/ayana/tui", tmux_bin: str = "tmux",
                 proxy_host: str = "127.0.0.1", proxy_port: int = 6291,
                 runtime_resolver: Callable[[], dict] | None = None,
                 redactor: Callable[[str], str] | None = None):
        if proxy_host not in ("127.0.0.1", "::1"):
            raise AgentTuiError("proxy_must_be_loopback")
        self.db = db
        self.serve_client_factory = serve_client_factory
        self.mimo_bin = str(mimo_bin)
        self.workdir = str(Path(workdir).resolve())
        self.home = str(Path(home).resolve())
        self.state_dir = Path(state_dir).resolve()
        self.tmux_bin = tmux_bin
        self.socket = self.state_dir / "tmux.sock"
        self.proxy_host = proxy_host
        self.proxy_port = int(proxy_port)
        self.runtime_resolver = runtime_resolver
        self.redactor = redactor
        self._runner = None
        self._http = None
        self._tokens: dict[str, str] = {}
        self._ensure_lock = asyncio.Lock()
        self._connections: dict[str, dict] = {}

    @property
    def proxy_url(self) -> str:
        host = "[::1]" if self.proxy_host == "::1" else self.proxy_host
        return f"http://{host}:{self.proxy_port}"

    def ensure_schema(self) -> None:
        # The production migration owns the version. This also supports isolated
        # module fixtures without replacing any existing history or binding.
        with self.db.tx() as conn:
            conn.execute(SCHEMA_SQL.strip().rstrip(";"))

    def _file(self, session_id: str) -> Path:
        name = hashlib.sha256(_local_id(session_id).encode()).hexdigest()
        return self.state_dir / "secrets" / (name + ".json")

    def _binding(self, session_id: str) -> dict | None:
        row = self.db.query_one("SELECT * FROM agent_runtime_bindings WHERE session_id=?", (_local_id(session_id),))
        return dict(row) if row else None

    def _session(self, session_id: str) -> dict:
        row = self.db.query_one("SELECT * FROM duty_sessions WHERE id=?", (_local_id(session_id),))
        if not row:
            raise AgentTuiError("session_not_found")
        return dict(row)

    def _runtime(self) -> dict:
        if self.runtime_resolver is None:
            raise AgentTuiError("provider_not_verified")
        try:
            value = self.runtime_resolver()
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except Exception:
            raise AgentTuiError("provider_not_verified") from None

    def _token(self, session_id: str, remote_id: str) -> str:
        _private_directory(self.state_dir)
        _private_directory(self.state_dir / "secrets")
        path = self._file(session_id)
        if path.exists():
            config = _read_private(path)
            if config.get("session_id") != session_id or config.get("remote_id") != remote_id:
                raise AgentTuiError("runtime_binding_changed")
            token = config.get("token")
            if not isinstance(token, str) or len(token) < 32:
                raise AgentTuiError("invalid_runtime_file")
        else:
            token = secrets.token_urlsafe(40)
        _atomic_private(path, {"session_id": session_id, "remote_id": remote_id, "token": token,
                              "mimo_bin": self.mimo_bin, "directory": self.workdir, "home": self.home,
                              "proxy_url": self.proxy_url})
        self._tokens[hashlib.sha256(token.encode()).hexdigest()] = session_id
        return token

    async def start(self) -> None:
        from aiohttp import ClientSession, ClientTimeout, web
        if self._runner is not None:
            return
        self.ensure_schema()
        _private_directory(self.state_dir)
        _private_directory(self.state_dir / "secrets")
        if os.name == "posix":
            # Web owns the loopback proxy; it also keeps the hardened tmux
            # server available so the first attach does not race a cold start.
            try:
                await self.bootstrap_tmux()
            except AgentTuiError as error:
                log.warning("agent_tui tmux bootstrap deferred: %s", error.code)
        for path in (self.state_dir / "secrets").glob("*.json"):
            try:
                config = _read_private(path)
                sid = _local_id(config.get("session_id"))
                token = config.get("token", "")
                if isinstance(token, str) and len(token) >= 32:
                    self._tokens[hashlib.sha256(token.encode()).hexdigest()] = sid
            except AgentTuiError:
                continue
        self._http = ClientSession(timeout=ClientTimeout(total=None, sock_connect=5, sock_read=None), trust_env=False)
        app = web.Application(client_max_size=MAX_BODY)
        app.router.add_route("*", "/{path:.*}", self.proxy_request)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.proxy_host, self.proxy_port)
        try:
            await site.start()
            if self.proxy_port == 0:
                self.proxy_port = site._server.sockets[0].getsockname()[1]
        except Exception:
            await self.stop()
            raise

    async def stop(self) -> None:
        # The proxy may restart with Ayana; tmux and model ownership belong to
        # the independent runtime unit and are deliberately not stopped here.
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
        if self._http is not None:
            await self._http.close()
            self._http = None

    def _tmux(self, *arguments: str, timeout: float = 8.0) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([self.tmux_bin, "-S", str(self.socket), *map(str, arguments)],
                                  capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        except FileNotFoundError:
            raise AgentTuiError("tmux_not_installed") from None
        except (OSError, subprocess.TimeoutExpired):
            raise AgentTuiError("tmux_unavailable") from None

    async def bootstrap_tmux(self) -> None:
        """Only the independent runtime daemon calls this, never a WS route."""
        if os.name != "posix":
            raise AgentTuiError("posix_required")
        _private_directory(self.state_dir)
        result = await asyncio.to_thread(self._tmux, "list-sessions")
        if result.returncode:
            result = await asyncio.to_thread(self._tmux, "-f", "/dev/null", "new-session", "-d",
                                            "-s", "ayana-runtime-anchor", "-x", "120", "-y", "36", "/bin/sleep", "infinity")
            if result.returncode:
                raise AgentTuiError("tmux_start_failed")
        for command in (
            ("set-option", "-g", "prefix", "None"), ("set-option", "-g", "prefix2", "None"),
            ("unbind-key", "-a"), ("unbind-key", "-a", "-T", "root"),
            ("set-option", "-g", "status", "off"), ("set-option", "-g", "mouse", "off"),
            ("set-option", "-g", "destroy-unattached", "off"), ("set-option", "-g", "exit-empty", "off"),
            ("set-option", "-g", "remain-on-exit", "on"), ("set-option", "-g", "allow-rename", "off"),
            ("set-option", "-g", "update-environment", ""),
            # tmux 3.3a segfaults on new-session after `window-size manual`;
            # attach-time TIOCSWINSZ still resizes the pane.
        ):
            configured = await asyncio.to_thread(self._tmux, *command)
            # Hardening is idempotent: unbind on an already-clean server and
            # repeat set-option must not block the first operator attach.
            if configured.returncode and command[0] == "set-option" and command[2] in ("status", "mouse", "remain-on-exit", "exit-empty"):
                raise AgentTuiError("tmux_hardening_failed")
        if self.socket.exists() and not self.socket.is_symlink():
            self.socket.chmod(0o600)

    async def _pane(self, name: str) -> dict | None:
        result = await asyncio.to_thread(self._tmux, "display-message", "-p", "-t", name,
                                        "#{pane_id}\t#{pane_pid}\t#{pane_dead}")
        if result.returncode:
            return None
        try:
            pane, pid, dead = result.stdout.strip().split("\t")
            if not re.fullmatch(r"%\d+", pane):
                return None
            return {"pane_id": pane, "pane_pid": int(pid), "pane_dead": dead == "1", "pane_started_at": _identity(int(pid))}
        except (ValueError, IndexError):
            return None

    async def ensure(self, session_id: str, remote_id: str) -> dict:
        session_id = _local_id(session_id)
        remote_id = _remote_id(remote_id)
        if os.name != "posix":
            raise AgentTuiError("posix_required")
        async with self._ensure_lock:
            sess = self._session(session_id)
            if sess.get("remote_session_id") != remote_id:
                raise AgentTuiError("runtime_binding_changed")
            server = await asyncio.to_thread(self._tmux, "list-sessions")
            if server.returncode:
                # First attach after a cold start: bring the hardened server up
                # rather than failing the operator out of the same running task.
                await self.bootstrap_tmux()
                server = await asyncio.to_thread(self._tmux, "list-sessions")
                if server.returncode:
                    raise AgentTuiError("tmux_runtime_not_started")
            name = "ayana-" + hashlib.sha256(session_id.encode()).hexdigest()[:24]
            existing = self._binding(session_id)
            if existing and existing.get("remote_session_id") not in ("", remote_id):
                raise AgentTuiError("runtime_binding_changed")
            self._token(session_id, remote_id)
            pane = await self._pane(name)
            if pane and pane["pane_dead"]:
                # A dead attach client is not a dead model task: serve still
                # owns the remote session. Drop the viewport and reattach.
                await asyncio.to_thread(self._tmux, "kill-session", "-t", name)
                pane = None
            if pane and existing and existing.get("pane_started_at") and (
                int(existing.get("pane_pid") or 0) != pane["pane_pid"] or str(existing["pane_started_at"]) != pane["pane_started_at"]
            ):
                await asyncio.to_thread(self._tmux, "kill-session", "-t", name)
                pane = None
            if not pane:
                package_root = str(Path(__file__).resolve().parents[1])
                env_prefix = "PYTHONPATH=" + package_root + (os.pathsep + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else "")
                created = await asyncio.to_thread(self._tmux, "new-session", "-d", "-s", name, "-x", "120", "-y", "36", "-c", package_root,
                                        "/usr/bin/env", env_prefix, sys.executable, "-m", "ayana.agent_tui", "launch",
                                        "--state-dir", str(self.state_dir), "--session", session_id)
                await asyncio.sleep(0.35)
                pane = await self._pane(name)
                if not pane or pane["pane_dead"]:
                    capture = await asyncio.to_thread(self._tmux, "capture-pane", "-p", "-t", name)
                    detail = ((created.stderr or created.stdout or "") + " " + (capture.stdout or capture.stderr or "")).strip().replace("\n", " ")[:200]
                    log.warning("agent_tui pane start failed sid=%s rc=%s detail=%s", session_id, created.returncode, detail)
                    raise AgentTuiError("tui_start_failed")
            runtime_id = hashlib.sha256((str(self.socket) + ":" + pane["pane_started_at"]).encode()).hexdigest()[:24]
            t = time.time()
            with self.db.tx() as conn:
                conn.execute(
                    "INSERT INTO agent_runtime_bindings(session_id,remote_session_id,runtime_id,tmux_name,pane_id,pane_pid,pane_started_at,created_at,updated_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET remote_session_id=excluded.remote_session_id,"
                    "runtime_id=excluded.runtime_id,tmux_name=excluded.tmux_name,pane_id=excluded.pane_id,pane_pid=excluded.pane_pid,"
                    "pane_started_at=excluded.pane_started_at,updated_at=excluded.updated_at",
                    (session_id, remote_id, runtime_id, name, pane["pane_id"], pane["pane_pid"], pane["pane_started_at"], t, t))
            return self.public_binding(self._binding(session_id) or {})

    @staticmethod
    def public_binding(binding: dict) -> dict:
        allowed = ("session_id", "remote_session_id", "runtime_id", "engine_pid", "engine_started_at", "tmux_name", "pane_id",
                   "pane_pid", "pane_started_at", "state", "receipt_id", "receipt_status", "controller", "control_expires_at")
        return {key: binding.get(key) for key in allowed}

    async def status(self, session_id: str) -> dict:
        binding = self._binding(session_id)
        if not binding:
            return {"ok": True, "attached": False, "binding": None}
        pane = await self._pane(binding.get("tmux_name") or "__absent__")
        alive = bool(pane and not pane["pane_dead"] and pane["pane_pid"] == int(binding.get("pane_pid") or 0)
                     and pane["pane_started_at"] == str(binding.get("pane_started_at") or ""))
        return {"ok": True, "attached": alive, "binding": self.public_binding(binding)}

    def acquire_control(self, session_id: str, username: str, connection_id: str) -> dict:
        session_id = _local_id(session_id)
        connection = self._connections.get(connection_id)
        if not connection or connection["session_id"] != session_id or connection["username"] != username:
            raise AgentTuiError("connection_not_found")
        t = time.time()
        with self.db.tx() as conn:
            if not conn.execute("SELECT 1 FROM agent_runtime_bindings WHERE session_id=?", (session_id,)).fetchone():
                raise AgentTuiError("binding_missing")
            cursor = conn.execute(
                "UPDATE agent_runtime_bindings SET controller=?,controller_connection_id=?,control_expires_at=?,updated_at=?"
                " WHERE session_id=? AND (control_expires_at<=? OR controller_connection_id=?)",
                (username, connection_id, t + CONTROL_SECONDS, t, session_id, t, connection_id))
            if cursor.rowcount != 1:
                raise AgentTuiError("control_in_use")
        self.db.audit("web_user", username, "agent_tui_control_acquired",
                      detail={"session_id": session_id, "connection_id": connection_id}, channel="web")
        return {"ok": True, "connection_id": connection_id, "expires_at": t + CONTROL_SECONDS}

    def release_control(self, session_id: str, username: str, connection_id: str = "") -> dict:
        session_id = _local_id(session_id)
        with self.db.tx() as conn:
            cursor = conn.execute(
                "UPDATE agent_runtime_bindings SET controller='',controller_connection_id='',control_expires_at=0,updated_at=?"
                " WHERE session_id=? AND controller=? AND controller_connection_id=?",
                (time.time(), session_id, username, connection_id))
        return {"ok": True, "released": cursor.rowcount == 1}

    def _has_control(self, session_id: str, username: str, connection_id: str, *, renew: bool = False) -> bool:
        t = time.time()
        binding = self._binding(session_id)
        allowed = bool(binding and binding.get("controller") == username and binding.get("controller_connection_id") == connection_id
                       and float(binding.get("control_expires_at") or 0) > t)
        if allowed and renew:
            self.db.execute("UPDATE agent_runtime_bindings SET control_expires_at=?,updated_at=? WHERE session_id=? AND controller_connection_id=?",
                            (t + CONTROL_SECONDS, t, session_id, connection_id))
        return allowed

    def _proxy_scope(self, request) -> tuple[str, dict]:
        try:
            scheme, encoded = request.headers.get("Authorization", "").split(" ", 1)
            if scheme.lower() != "basic":
                raise ValueError()
            decoded = base64.b64decode(encoded, validate=True).decode()
            _, token = decoded.split(":", 1)
        except (ValueError, UnicodeError):
            raise AgentTuiError("unauthorized") from None
        sid = self._tokens.get(hashlib.sha256(token.encode()).hexdigest())
        if not sid:
            raise AgentTuiError("unauthorized")
        config = _read_private(self._file(sid))
        if not hmac.compare_digest(str(config.get("token") or ""), token):
            raise AgentTuiError("unauthorized")
        session = self._session(sid)
        binding = self._binding(sid)
        if not binding or session.get("remote_session_id") != binding.get("remote_session_id") or config.get("remote_id") != binding.get("remote_session_id"):
            raise AgentTuiError("runtime_binding_changed")
        return sid, binding

    def _sanitize(self, value):
        if isinstance(value, str):
            if self.redactor:
                try:
                    return self.redactor(value)
                except Exception:
                    return "[unavailable]"
            return re.sub(r"(?i)(Bearer\s+)\S+", r"\1[redacted]", value)
        if isinstance(value, list):
            return [self._sanitize(item) for item in value]
        if isinstance(value, dict):
            return {key: ("[redacted]" if re.search(r"(?i)(apikey|api_key|password|authorization|secret|token)$", str(key))
                          else self._sanitize(item)) for key, item in value.items()}
        return value

    async def proxy_request(self, request):
        from aiohttp import web
        try:
            sid, binding = self._proxy_scope(request)
            remote = _remote_id(binding["remote_session_id"])
            path = "/" + request.match_info.get("path", "").strip("/")
            method = request.method.upper()
            relative = path[len("/session/" + remote):] if path.startswith("/session/" + remote + "/") or path == "/session/" + remote else None
            if method in ("GET", "HEAD"):
                if path == "/event":
                    return await self._proxy_events(request, remote)
                if path in ("/permission", "/question", "/command", "/file/status", "/lsp", "/formatter", "/project"):
                    return web.json_response([])
                if path == "/path":
                    return web.json_response({"home": self.home, "directory": self.workdir, "worktree": self.workdir})
                if path == "/config":
                    return web.json_response({"permission": {"*": "deny"}, "agent": {},
                                              "keybinds": {"editor_open": "none", "suspend": "none"}})
                if path == "/agent":
                    return web.json_response([
                        {"name": "ayana-readonly", "mode": "primary", "description": "Ayana 受限调查", "permission": {"*": "deny"}},
                        {"name": "ayana-decision", "mode": "primary", "description": "Ayana 处置计划", "permission": {"*": "deny"}}])
                if path == "/session":
                    info = await self._upstream("GET", "/session/" + remote)
                    return web.json_response([self._sanitize(info)] if isinstance(info, dict) else [])
                if path == "/session/status":
                    info = await self._upstream("GET", path)
                    return web.json_response({remote: self._sanitize(info[remote])} if isinstance(info, dict) and remote in info else {})
                if path in ("/provider", "/config/providers", "/mcp", "/vcs", "/project/current", "/global/health"):
                    return web.json_response(self._sanitize(await self._upstream(method, path)))
                if relative is not None and (relative == "" or re.fullmatch(r"/(?:message(?:/[A-Za-z0-9_-]+)?|receipt/[A-Za-z0-9_-]+|children|todo|diff)", relative)):
                    query = dict(request.query)
                    if relative.startswith("/message") and "limit" not in query:
                        query["limit"] = "200"
                    return web.json_response(self._sanitize(await self._upstream(method, path, query=query)))
                raise AgentTuiError("tui_route_forbidden")
            if method == "POST" and relative in ("/message", "/prompt_async", "/abort"):
                session = self._session(sid)
                if session.get("status") != "open":
                    raise AgentTuiError("session_archived")
                if not binding.get("controller_connection_id") or float(binding.get("control_expires_at") or 0) <= time.time():
                    raise AgentTuiError("control_required")
                self._runtime()
                body = {} if relative == "/abort" else await request.json()
                if not isinstance(body, dict):
                    raise AgentTuiError("invalid_prompt")
                if relative != "/abort":
                    parts = body.get("parts")
                    if not isinstance(parts, list) or not parts or len(parts) > 20:
                        raise AgentTuiError("invalid_prompt")
                    if any(not isinstance(part, dict) or part.get("type") != "text" or not isinstance(part.get("text"), str) for part in parts):
                        raise AgentTuiError("text_only_prompt")
                    if sum(len(part["text"]) for part in parts) > 20000:
                        raise AgentTuiError("prompt_too_large")
                    body = {"parts": [{"type": "text", "text": part["text"]} for part in parts], "agent": "ayana-readonly"}
                status, payload = await self._upstream(method, path, body=body, with_status=True)
                self.db.audit("web_user", binding.get("controller") or "", "agent_tui_prompt" if relative != "/abort" else "agent_tui_abort",
                              detail={"session_id": sid}, channel="web")
                return web.Response(status=204) if status == 204 else web.json_response(self._sanitize(payload), status=status)
            raise AgentTuiError("tui_route_forbidden")
        except AgentTuiError as error:
            status = 401 if error.code == "unauthorized" else 409 if error.code in ("control_required", "runtime_binding_changed") else 403
            return web.json_response({"name": "AyanaTuiRestricted", "data": {"message": error.code}}, status=status)
        except Exception:
            return web.json_response({"name": "AyanaTuiUnavailable", "data": {"message": "native_backend_unavailable"}}, status=502)

    async def _upstream(self, method, path, *, body=None, query=None, with_status=False):
        from aiohttp import ClientTimeout
        if self._http is None:
            raise AgentTuiError("proxy_not_started")
        client = self.serve_client_factory()
        headers = client._headers({"x-mimocode-directory": quote(self.workdir, safe="")})
        params = dict(query or {})
        params["directory"] = self.workdir
        async with self._http.request(method, client.base_url + path, json=body, params=params, headers=headers,
                                      allow_redirects=False, timeout=ClientTimeout(total=20)) as response:
            if response.status >= 300:
                raise AgentTuiError("native_backend_unavailable")
            if response.status == 204:
                return (204, {}) if with_status else {}
            try:
                raw = await response.content.readexactly(MAX_UPSTREAM_BYTES + 1)
            except asyncio.IncompleteReadError as error:
                raw = error.partial
            if len(raw) > MAX_UPSTREAM_BYTES:
                raise AgentTuiError("native_response_too_large")
            payload = json.loads(raw) if raw else {}
            return (response.status, payload) if with_status else payload

    @staticmethod
    def _event_matches(value: dict, remote: str) -> bool:
        found = []
        def visit(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    if key in ("sessionID", "sessionId", "session_id") and isinstance(child, str):
                        found.append(child)
                    elif isinstance(child, (dict, list)):
                        visit(child)
            elif isinstance(item, list):
                for child in item:
                    visit(child)
        visit(value)
        if not found:
            # Server-level frames and some part deltas omit session IDs.
            return value.get("type") in (
                "server.connected", "server.heartbeat",
                "message.part.delta", "message.part.updated", "message.updated",
                "session.status", "session.updated",
            )
        return remote in found

    async def _proxy_events(self, request, remote):
        from aiohttp import web, ClientTimeout
        client = self.serve_client_factory()
        headers = client._headers({"Accept": "text/event-stream", "x-mimocode-directory": quote(self.workdir, safe="")})
        async with self._http.get(client.base_url + "/event", params={"directory": self.workdir}, headers=headers,
                                  allow_redirects=False, timeout=ClientTimeout(total=None, sock_connect=5)) as response:
            if response.status != 200:
                raise AgentTuiError("native_backend_unavailable")
            output = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"})
            await output.prepare(request)
            buffer = b""
            try:
                async for chunk in response.content.iter_any():
                    buffer += chunk
                    if len(buffer) > 1_000_000:
                        break
                    while b"\n\n" in buffer:
                        frame, buffer = buffer.split(b"\n\n", 1)
                        data = b"\n".join(line[5:].strip() for line in frame.splitlines() if line.startswith(b"data:"))
                        try:
                            payload = json.loads(data)
                        except (ValueError, UnicodeError):
                            continue
                        if isinstance(payload, dict) and self._event_matches(payload, remote):
                            packet = "data: " + json.dumps(self._sanitize(payload), ensure_ascii=False) + "\n\n"
                            await asyncio.wait_for(output.write(packet.encode()), timeout=10)
            except (ConnectionError, asyncio.TimeoutError):
                pass
            return output

    async def websocket(self, request, session_id: str, *, username: str, authorize: Callable[[], Any]):
        from aiohttp import web, WSMsgType
        async def permitted():
            result = authorize()
            return bool(await result if inspect.isawaitable(result) else result)
        if not await permitted():
            raise web.HTTPForbidden()
        session = self._session(session_id)
        remote = _remote_id(session.get("remote_session_id") or "")
        binding = await self.ensure(session_id, remote)
        if os.name != "posix":
            raise web.HTTPServiceUnavailable(text="posix_required")
        import pty, fcntl, termios, struct
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 120, 0, 0))
        def child_setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        try:
            process = subprocess.Popen(
                [self.tmux_bin, "-S", str(self.socket), "attach-session", "-t", binding["tmux_name"]],
                stdin=slave, stdout=slave, stderr=slave, close_fds=True, preexec_fn=child_setup,
                env={**os.environ, "TERM": "xterm-256color"})
        except Exception:
            os.close(master)
            os.close(slave)
            raise AgentTuiError("attach_failed") from None
        os.close(slave)
        os.set_blocking(master, False)
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=MAX_INPUT + 1024)
        connection_id = secrets.token_hex(16)
        queue: asyncio.Queue = asyncio.Queue(maxsize=64)
        self._connections[connection_id] = {"session_id": session_id, "username": username}
        loop = asyncio.get_running_loop()
        overflow = asyncio.Event()
        def readable():
            try:
                data = os.read(master, 65536)
                if not data:
                    overflow.set()
                    return
                try:
                    queue.put_nowait(data)
                except asyncio.QueueFull:
                    overflow.set()
            except BlockingIOError:
                pass
            except OSError:
                overflow.set()
        loop.add_reader(master, readable)
        bytes_in = bytes_out = 0
        async def output_pump():
            nonlocal bytes_out
            while not ws.closed:
                if not await permitted():
                    await ws.close(code=4403, message=b"permission revoked")
                    break
                if overflow.is_set() or process.poll() is not None:
                    await ws.close(code=1013, message=b"reattach required")
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=1)
                except asyncio.TimeoutError:
                    continue
                bytes_out += len(data)
                try:
                    await asyncio.wait_for(ws.send_bytes(data), timeout=10)
                except asyncio.TimeoutError:
                    await ws.close(code=1013)
                    break
        pump = None
        try:
            await ws.prepare(request)
            await ws.send_json({"type": "ready", "connection_id": connection_id, "binding": binding, "control": False})
            pump = asyncio.create_task(output_pump())
            self.db.audit("web_user", username, "agent_tui_attached", detail={"session_id": session_id, "connection_id": connection_id}, channel="web")
            async for message in ws:
                if not await permitted():
                    await ws.close(code=4403)
                    break
                payload = None
                if message.type == WSMsgType.BINARY:
                    data = message.data
                elif message.type == WSMsgType.TEXT:
                    try:
                        payload = json.loads(message.data)
                    except ValueError:
                        continue
                    if not isinstance(payload, dict):
                        continue
                    kind = payload.get("type")
                    if kind == "ping":
                        control = self._has_control(session_id, username, connection_id, renew=True)
                        await ws.send_json({"type": "control", "control": control})
                        continue
                    if kind == "resize":
                        # Viewport size is not an Agent instruction; observers
                        # may resize so the native TUI fills the browser pane.
                        try:
                            cols = max(20, min(400, int(payload.get("cols", 120))))
                            rows = max(5, min(200, int(payload.get("rows", 36))))
                        except (TypeError, ValueError):
                            continue
                        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                        await asyncio.to_thread(self._tmux, "resize-window", "-t", binding["tmux_name"], "-x", str(cols), "-y", str(rows))
                        continue
                    if kind == "release":
                        self.release_control(session_id, username, connection_id)
                        continue
                    if kind != "input" or not isinstance(payload.get("data"), str):
                        continue
                    data = payload["data"].encode()
                else:
                    continue
                if not self._has_control(session_id, username, connection_id, renew=True):
                    continue
                if len(data) > MAX_INPUT:
                    await ws.close(code=1009)
                    break
                # Suspension is not an Agent instruction. Model/shell permissions
                # are also independently constrained by the scoped proxy.
                data = data.replace(b"\x1a", b"")
                if data:
                    try:
                        bytes_in += os.write(master, data)
                    except (BlockingIOError, OSError):
                        await ws.close(code=1013)
                        break
        finally:
            loop.remove_reader(master)
            if pump:
                pump.cancel()
                await asyncio.gather(pump, return_exceptions=True)
            self.release_control(session_id, username, connection_id)
            self._connections.pop(connection_id, None)
            os.close(master)
            if process.poll() is None:
                process.terminate()
                try:
                    await asyncio.to_thread(process.wait, 2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    await asyncio.to_thread(process.wait, 2)
            self.db.audit("web_user", username, "agent_tui_detached",
                          detail={"session_id": session_id, "bytes_in": bytes_in, "bytes_out": bytes_out}, channel="web")
        return ws


def launch_native_attach(state_dir: str, session_id: str) -> None:
    """Trusted tmux entry point; scope credentials never enter argv."""
    session_id = _local_id(session_id)
    path = Path(state_dir).resolve() / "secrets" / (hashlib.sha256(session_id.encode()).hexdigest() + ".json")
    config = _read_private(path)
    if config.get("session_id") != session_id:
        raise AgentTuiError("runtime_binding_changed")
    remote = _remote_id(config.get("remote_id"))
    token = config.get("token")
    if not isinstance(token, str) or len(token) < 32:
        raise AgentTuiError("invalid_runtime_file")
    url = str(config.get("proxy_url") or "")
    if not re.fullmatch(r"http://(?:127\.0\.0\.1|\[::1\]):\d{1,5}", url):
        raise AgentTuiError("invalid_proxy_url")
    binary = str(config.get("mimo_bin") or "")
    workdir = str(config.get("directory") or "")
    home = str(config.get("home") or "")
    if not os.path.isabs(binary) or not os.path.isabs(workdir) or not os.path.isabs(home):
        raise AgentTuiError("invalid_runtime_file")
    env = {key: value for key, value in os.environ.items() if key in ("LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM", "TMPDIR")}
    env.update(HOME=home, XDG_CONFIG_HOME=str(Path(home) / ".config"), XDG_DATA_HOME=str(Path(home) / ".local/share"),
               XDG_CACHE_HOME=str(Path(home) / ".cache"),
               PATH=os.pathsep.join([str(Path(binary).parent), "/usr/local/bin", "/usr/bin", "/bin"]), TERM="xterm-256color",
               MIMOCODE_SERVER_USERNAME="ayana-tui", MIMOCODE_SERVER_PASSWORD=token,
               EDITOR="/bin/false", VISUAL="/bin/false", BROWSER="/bin/false", AYANA_MCP_READONLY="1")
    os.chdir(workdir)
    os.execvpe(binary, [binary, "attach", url, "--session", remote, "--dir", workdir], env)


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["launch"])
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--session", required=True)
    args = parser.parse_args(argv)
    launch_native_attach(args.state_dir, args.session)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
