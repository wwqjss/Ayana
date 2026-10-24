"""人工 Web SSH 终端（MVP）。

- 仅服务 Web 已认证管理员（shell.interactive）
- 与 Agent 执行入口隔离：不提供 Agent API，不进 runbook/tools
- 复用 ssh_endpoints / 凭据库 / host_key 信任
- 审计会话起止，不记录按键
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from typing import Any

from .db import Database, new_id, now

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None  # type: ignore


class TerminalError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.detail = message
        super().__init__(f"{code}: {message}" if message else code)


MAX_SESSIONS_PER_USER = 3
MAX_SESSIONS_GLOBAL = 10
SESSION_IDLE_TIMEOUT = 900.0
SESSION_MAX_LIFE = 3600.0


class TerminalSession:
    """一条人工交互 SSH 会话（paramiko shell）。"""

    def __init__(
        self,
        *,
        session_id: str,
        asset_id: str,
        role: str,
        host: str,
        port: int,
        username: str,
        cred_kind: str,
        secret: str,
        host_key_line: str,
        cols: int = 80,
        rows: int = 24,
    ):
        self.session_id = session_id
        self.asset_id = asset_id
        self.role = role
        self.host = host
        self.port = port
        self.username = username
        self.cred_kind = cred_kind
        self._secret = secret
        self.host_key_line = host_key_line
        self.cols = max(20, min(400, int(cols or 80)))
        self.rows = max(5, min(200, int(rows or 24)))
        self.created_at = time.time()
        self.last_activity = time.time()
        self.closed = False
        self.close_reason = ""
        # P4.2 会话审计：统计字节，不做逐键审批
        self.bytes_in = 0
        self.bytes_out = 0
        self._client: Any = None
        self._chan: Any = None
        self._lock = threading.Lock()

    def touch(self) -> None:
        self.last_activity = time.time()

    def alive(self) -> bool:
        if self.closed:
            return False
        if time.time() - self.created_at > SESSION_MAX_LIFE:
            return False
        if time.time() - self.last_activity > SESSION_IDLE_TIMEOUT:
            return False
        return bool(self._chan and not self._chan.closed)

    def _host_key(self):
        """从已信任 key_line 构造 host key（与 known_hosts 同语义）。"""
        line = (self.host_key_line or "").strip()
        if not line:
            raise TerminalError("host_key_line_missing")
        parts = line.split()
        # [host]:port type blob  |  host type blob
        if len(parts) < 3:
            raise TerminalError("bad_host_key_line")
        key_type, key_b64 = parts[-2], parts[-1]
        try:
            key = paramiko.ECDSAKey(data=__import__("base64").b64decode(key_b64)) if key_type.startswith("ecdsa") else None
            if key is None and key_type == "ssh-ed25519":
                key = paramiko.Ed25519Key(data=__import__("base64").b64decode(key_b64))
            elif key is None and key_type.startswith("ssh-rsa"):
                key = paramiko.RSAKey(data=__import__("base64").b64decode(key_b64))
            elif key is None:
                # 最后尝试
                try:
                    key = paramiko.Ed25519Key(data=__import__("base64").b64decode(key_b64))
                except Exception:
                    key = paramiko.RSAKey(data=__import__("base64").b64decode(key_b64))
        except Exception as e:
            raise TerminalError("host_key_parse_failed", str(e)) from e
        return key

    def connect(self) -> None:
        if paramiko is None:
            raise TerminalError("paramiko_unavailable")
        client = paramiko.SSHClient()
        host_key = self._host_key()

        class _OnlyExpected(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                if key.get_name() == host_key.get_name() and key.asbytes() == host_key.asbytes():
                    try:
                        client.get_host_keys().add(hostname, key.get_name(), key)
                    except Exception:
                        pass
                    return
                raise TerminalError("host_key_mismatch", hostname)

        client.set_missing_host_key_policy(_OnlyExpected())
        kwargs: dict[str, Any] = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": 15,
            "banner_timeout": 15,
            "auth_timeout": 15,
            "allow_agent": False,
            "look_for_keys": False,
        }
        try:
            if self.cred_kind == "private_key":
                import io

                pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(self._secret))
                kwargs["pkey"] = pkey
            else:
                kwargs["password"] = self._secret
            # 预置已信任 host key，避免 UnknownHostKey 被拒
            host_label = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
            client.get_host_keys().add(host_label, host_key.get_name(), host_key)
            client.connect(**kwargs)
            remote_key = client.get_transport().get_remote_server_key()
            if remote_key.get_name() != host_key.get_name() or remote_key.asbytes() != host_key.asbytes():
                client.close()
                raise TerminalError("host_key_mismatch")
        except TerminalError:
            raise
        except Exception as e:
            try:
                client.close()
            except Exception:
                pass
            raise TerminalError("ssh_connect_failed", str(e)[:300]) from e

        chan = client.invoke_shell(term="xterm-256color", width=self.cols, height=self.rows)
        chan.settimeout(0.0)
        self._client = client
        self._chan = chan

    def resize(self, cols: int, rows: int) -> None:
        self.cols = max(20, min(400, int(cols)))
        self.rows = max(5, min(200, int(rows)))
        if self._chan and not self._chan.closed:
            try:
                self._chan.resize_pty(width=self.cols, height=self.rows)
            except Exception:
                pass

    def write(self, data: bytes) -> None:
        # S03: 仅在真实用户输入时刷新 idle；写入前复核存活（超时/撤销即拒绝）
        if not self.alive():
            self.close("timeout_or_revoked")
            raise TerminalError("session_closed", "timeout or revoked")
        self.touch()
        if not self._chan or self._chan.closed:
            raise TerminalError("session_closed")
        self._chan.sendall(data)
        self.bytes_in = getattr(self, "bytes_in", 0) + len(data)

    def read(self, bufsize: int = 8192) -> bytes:
        # S03: 轮询读不刷新 idle，避免空闲会话永不超时
        if not self._chan or self.closed:
            return b""
        try:
            if self._chan.recv_ready():
                data = self._chan.recv(bufsize)
                self.bytes_out = getattr(self, "bytes_out", 0) + len(data or b"")
                return data
        except Exception:
            pass
        return b""

    def close(self, reason: str = "closed") -> None:
        self.closed = True
        self.close_reason = reason
        try:
            if self._chan:
                self._chan.close()
        except Exception:
            pass
        try:
            if self._client:
                self._client.close()
        except Exception:
            pass
        self._secret = ""


class TerminalService:
    """人工终端会话管理（与 Agent 隔离）。"""

    def __init__(self, db: Database, ssh_store: Any, cred_store: Any):
        self.db = db
        self.ssh_store = ssh_store
        self.cred_store = cred_store
        self._sessions: dict[str, TerminalSession] = {}
        self._lock = asyncio.Lock()

    def _count_for(self, username: str) -> int:
        n = 0
        for s in self._sessions.values():
            if s.alive() and getattr(s, "username_label", "") == username:
                n += 1
        return n

    async def create(
        self,
        *,
        asset_id: str,
        role: str = "write",
        username: str,
        cols: int = 80,
        rows: int = 24,
    ) -> tuple[TerminalSession, dict[str, Any]]:
        """建立会话。返回 (session, info)。host key 未信任/变更时抛 TerminalError 并带 host_key_info。"""
        async with self._lock:
            self._reap_locked()
            live = [s for s in self._sessions.values() if s.alive()]
            if len(live) >= MAX_SESSIONS_GLOBAL:
                raise TerminalError("too_many_sessions", "global")
            mine = [s for s in live if getattr(s, "username_label", "") == username]
            if len(mine) >= MAX_SESSIONS_PER_USER:
                raise TerminalError("too_many_sessions", "user")

            eps = self.ssh_store.list_endpoints(asset_id) if self.ssh_store else []
            ep = next((e for e in eps if e.get("role") == role and e.get("enabled")), None)
            if not ep:
                ep = next((e for e in eps if e.get("enabled")), None)
            if not ep:
                raise TerminalError("no_ssh_endpoint", "请先配置 SSH 连接")
            if not ep.get("credential_id"):
                raise TerminalError("no_credential", "未配置密码或密钥")

            # host key：未信任 / 变更 → 阻止，附指纹信息
            from .transport import fetch_host_key

            scanned = await fetch_host_key(ep.get("host") or "", int(ep.get("port") or 22))
            stored_fp = ep.get("host_key_sha256") or ""
            stored_line = ep.get("host_key_line") or ""
            if stored_fp and scanned.get("ok") and scanned.get("fingerprint") and scanned["fingerprint"] != stored_fp:
                raise TerminalError(
                    "host_key_changed",
                    json.dumps(
                        {
                            "host": ep.get("host"),
                            "port": ep.get("port"),
                            "stored_fingerprint": stored_fp,
                            "current_fingerprint": scanned.get("fingerprint"),
                        },
                        ensure_ascii=False,
                    ),
                )
            if not stored_fp or not ep.get("host_key_trusted_at"):
                raise TerminalError(
                    "host_key_untrusted",
                    json.dumps(
                        {
                            "host": ep.get("host"),
                            "port": ep.get("port"),
                            "fingerprint": scanned.get("fingerprint") if scanned.get("ok") else "",
                            "key_type": scanned.get("key_type") if scanned.get("ok") else "",
                            "key_line": scanned.get("key_line") if scanned.get("ok") else "",
                        },
                        ensure_ascii=False,
                    ),
                )
            if not stored_line:
                raise TerminalError("host_key_line_missing", "请重新信任 host key 以保存公钥")

            meta = self.cred_store.get_meta(ep["credential_id"]) if self.cred_store else None
            cred_kind = (meta or {}).get("kind") or "password"
            secret = self.cred_store.reveal_secret(ep["credential_id"]) if self.cred_store else ""

            sid = new_id("term")
            sess = TerminalSession(
                session_id=sid,
                asset_id=asset_id,
                role=ep.get("role") or role,
                host=ep.get("host") or "",
                port=int(ep.get("port") or 22),
                username=ep.get("username") or "",
                cred_kind=cred_kind,
                secret=secret,
                host_key_line=stored_line,
                cols=cols,
                rows=rows,
            )
            sess.username_label = username  # type: ignore[attr-defined]
            try:
                await asyncio.to_thread(sess.connect)
            except TerminalError as e:
                sess.close(e.code)
                raise
            except Exception as e:
                sess.close("error")
                raise TerminalError("ssh_connect_failed", str(e)[:300]) from e

            self._sessions[sid] = sess
            self.db.audit(
                "web_user",
                username,
                "terminal_opened",
                asset_id=asset_id,
                detail={
                    "session_id": sid,
                    "host": sess.host,
                    "port": sess.port,
                    "remote_user": sess.username,
                    "role": sess.role,
                    "auth": cred_kind,
                },
                channel="web",
            )
            info = {
                "session_id": sid,
                "asset_id": asset_id,
                "host": sess.host,
                "port": sess.port,
                "remote_user": sess.username,
                "auth_method": cred_kind,
                "cols": sess.cols,
                "rows": sess.rows,
            }
            return sess, info

    def get(self, session_id: str) -> TerminalSession:
        sess = self._sessions.get(session_id)
        if not sess:
            raise TerminalError("session_not_found")
        return sess

    def close(self, session_id: str, username: str = "", reason: str = "user") -> None:
        sess = self._sessions.pop(session_id, None)
        if not sess:
            return
        sess.close(reason)
        self.db.audit(
            "web_user",
            username or getattr(sess, "username_label", ""),
            "terminal_closed",
            asset_id=sess.asset_id,
            detail={
                "session_id": session_id,
                "host": sess.host,
                "reason": reason,
                "duration_sec": int(time.time() - sess.created_at),
                "bytes_in": getattr(sess, "bytes_in", 0),
                "bytes_out": getattr(sess, "bytes_out", 0),
            },
            channel="web",
        )

    def _reap_locked(self) -> None:
        dead = [sid for sid, s in self._sessions.items() if not s.alive()]
        for sid in dead:
            s = self._sessions.pop(sid, None)
            if s:
                s.close("timeout_or_dead")

    async def reap(self) -> int:
        async with self._lock:
            n = len(self._sessions)
            self._reap_locked()
            return n - len(self._sessions)

    def stats(self) -> dict[str, Any]:
        live = [s for s in self._sessions.values() if s.alive()]
        return {
            "live": len(live),
            "max_global": MAX_SESSIONS_GLOBAL,
            "max_per_user": MAX_SESSIONS_PER_USER,
            "idle_timeout_sec": SESSION_IDLE_TIMEOUT,
            "max_life_sec": SESSION_MAX_LIFE,
        }


async def run_cmd_probe(host: str, port: int, username: str, cred_kind: str, secret: str,
                        host_key_line: str, cmds: list[str], timeout: float = 12.0) -> dict[str, Any]:
    """连接测试：真实执行 hostname/whoami/uname 等，返回逐条结果。"""
    if paramiko is None:
        return {"ok": False, "error": "paramiko_unavailable", "results": []}

    def _work() -> dict[str, Any]:
        import base64
        import io as _io

        client = paramiko.SSHClient()
        try:
            parts = (host_key_line or "").split()
            if len(parts) >= 3:
                key_type, key_b64 = parts[-2], parts[-1]
                raw = base64.b64decode(key_b64)
                if key_type == "ssh-ed25519":
                    expect = paramiko.Ed25519Key(data=raw)
                elif key_type.startswith("ssh-rsa"):
                    expect = paramiko.RSAKey(data=raw)
                else:
                    expect = paramiko.ECDSAKey(data=raw)
            else:
                return {"ok": False, "error": "host_key_line_missing", "results": []}

            class _OnlyExpected(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, client, hostname, key):
                    if key.get_name() == expect.get_name() and key.asbytes() == expect.asbytes():
                        try:
                            client.get_host_keys().add(hostname, key.get_name(), key)
                        except Exception:
                            pass
                        return
                    raise RuntimeError(f"host_key_mismatch:{hostname}")

            client.set_missing_host_key_policy(_OnlyExpected())
            kwargs: dict[str, Any] = {
                "hostname": host,
                "port": port,
                "username": username,
                "timeout": timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }
            if cred_kind == "private_key":
                kwargs["pkey"] = paramiko.Ed25519Key.from_private_key(_io.StringIO(secret))
            else:
                kwargs["password"] = secret
            host_label = host if int(port or 22) == 22 else f"[{host}]:{int(port or 22)}"
            client.get_host_keys().add(host_label, expect.get_name(), expect)
            client.connect(**kwargs)
            remote = client.get_transport().get_remote_server_key()
            if remote.get_name() != expect.get_name() or remote.asbytes() != expect.asbytes():
                return {"ok": False, "error": "host_key_mismatch", "results": []}
            results = []
            all_ok = True
            for c in cmds:
                stdin, stdout, stderr = client.exec_command(c, timeout=timeout)
                rc = stdout.channel.recv_exit_status()
                out = (stdout.read() or b"").decode("utf-8", "replace").strip()
                err = (stderr.read() or b"").decode("utf-8", "replace").strip()
                results.append({"cmd": c, "ok": rc == 0, "returncode": rc, "stdout": out, "stderr": err})
                if rc != 0:
                    all_ok = False
            return {"ok": all_ok, "results": results}
        except Exception as e:
            return {"ok": False, "error": str(e)[:300], "results": []}
        finally:
            try:
                client.close()
            except Exception:
                pass

    return await asyncio.to_thread(_work)
