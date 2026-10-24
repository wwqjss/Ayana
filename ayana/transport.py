"""轻量 Transport：只保留 NT 与原生 SSH 两种实现。

迁移完成后删除 NT 实现。不为 Node/K8s 预留插件框架。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .db import Database, new_id, now
from .ntsafe import NTError, NTResult

# S01: 严格校验 SSH username/host，拒绝选项形态与元字符注入
_USERNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:\-_]{0,252}$")

# B5: SSRF / 元数据 / 本机探测黑名单（host 名或 IP 字面量）
_SSRF_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "instance-data",
    }
)


def _normalize_host_ip(host: str) -> str | None:
    """规范化主机为 IP 字符串；无法解析为 IP 则返回 None。"""
    h = (host or "").strip().lower().strip("[]")
    if not h:
        return None
    try:
        import ipaddress

        addr = ipaddress.ip_address(h)
        # IPv4-mapped IPv6 → IPv4
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return None


def is_blocked_ssrf_host(host: str, *, allow_loopback: bool = False, purpose: str = "webhook") -> bool:
    """环回 / 链路本地（含 169.254.169.254）/ 元数据主机名拒绝。

    allow_loopback=True：允许 127.0.0.1/::1（SSH 本机主机密钥等运维场景）。
    purpose=webhook：额外拒绝 .local 等 mDNS 名。
    """
    raw = (host or "").strip().lower().strip("[]")
    if not raw:
        return True
    if raw in _SSRF_BLOCKED_HOSTNAMES:
        return True
    if raw.endswith(".localhost"):
        return not allow_loopback
    if purpose == "webhook" and raw.endswith(".local"):
        return True
    ip = _normalize_host_ip(raw)
    if ip is not None:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return not allow_loopback
        if addr.is_unspecified or addr.is_multicast or addr.is_reserved:
            return True
        # link-local (含 169.254.x.x 与 fe80::/10)
        if addr.is_link_local:
            return True
        # 云元数据
        if ip in {"169.254.169.254", "fd00:ec2::254"}:
            return True
        return False
    # 非 IP：语法校验
    if not _HOST_RE.match(host.strip()) and not raw.endswith(".local"):
        return True
    return False


def validate_ssh_identity(username: str, host: str) -> None:
    """拒绝可被 OpenSSH 解析为选项或带 shell 元字符的 username/host。"""
    if not username or not _USERNAME_RE.match(username) or username.startswith("-"):
        raise TransportError("bad_username", "invalid username syntax")
    if not host or not _HOST_RE.match(host) or host.startswith("-"):
        raise TransportError("bad_host", "invalid host syntax")
    if "@" in username or "@" in host:
        raise TransportError("bad_identity", "unexpected @ in identity")
    if ":" in username:
        raise TransportError("bad_username", "unexpected : in username")


class TransportError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def compute_host_key_fingerprint(key_line: str) -> tuple[str, str]:
    """从 ssh-keyscan 行算出 SHA256 指纹（与 ssh-keygen -lf 一致）。"""
    parts = (key_line or "").strip().split()
    if len(parts) < 2:
        raise TransportError("bad_host_key_line")
    key_type = parts[-2] if len(parts) >= 3 else parts[0]
    # 形式: [host] type base64 | type base64
    b64 = parts[-1]
    try:
        blob = base64.b64decode(b64)
    except Exception as e:
        raise TransportError("bad_host_key_b64", str(e)) from e
    digest = hashlib.sha256(blob).digest()
    fp = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
    return fp, key_type


async def fetch_host_key(host: str, port: int = 22, *, timeout: float = 8.0) -> dict[str, Any]:
    """用 ssh-keyscan 获取主机公钥（不登录）。失败返回 ok=False。"""
    if not host:
        raise TransportError("host_required")
    # S01: host 也须合法，防止 ssh-keyscan 参数注入
    if not _HOST_RE.match(host) or host.startswith("-"):
        raise TransportError("bad_host", "invalid host syntax")
    # B5: 禁止 keyscan 链路本地/元数据（本机 127.0.0.1 仍允许，SSH 运维常见）
    if is_blocked_ssrf_host(host, allow_loopback=True, purpose="ssh"):
        raise TransportError("ssrf_blocked", "host not allowed")
    proc = await asyncio.create_subprocess_exec(
        "ssh-keyscan",
        "-T", str(max(2, int(timeout))),
        "-p", str(int(port or 22)),
        "-t", "ed25519,rsa,ecdsa",
        host,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {"ok": False, "error": "keyscan_timeout"}
    out = (out_b or b"").decode("utf-8", errors="replace")
    lines = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.startswith("#")]
    if not lines:
        return {
            "ok": False,
            "error": "keyscan_empty",
            "stderr": (err_b or b"").decode("utf-8", errors="replace")[:300],
        }
    # 优先 ed25519
    chosen = None
    for ln in lines:
        if "ssh-ed25519" in ln:
            chosen = ln
            break
    if not chosen:
        chosen = lines[0]
    try:
        fp, key_type = compute_host_key_fingerprint(chosen)
    except TransportError as e:
        return {"ok": False, "error": e.code, "detail": e.detail}
    # known_hosts 需要 [host]:port 或 host 前缀
    host_field = host
    if int(port or 22) != 22:
        host_field = f"[{host}]:{int(port)}"
    key_body = chosen.split(None, 1)[1] if len(chosen.split(None, 1)) > 1 else chosen
    # 若 keyscan 行已含 host 前缀则只取 type+key
    parts = chosen.split()
    if len(parts) >= 3:
        key_type = parts[-2]
        key_body = f"{parts[-2]} {parts[-1]}"
    else:
        key_body = chosen
    known_line = f"{host_field} {key_body}"
    return {
        "ok": True,
        "host": host,
        "port": int(port or 22),
        "fingerprint": fp,
        "key_type": key_type,
        "key_line": known_line,
        "raw_line": chosen,
    }


class Transport(Protocol):
    async def probe(self, asset_id: str, cmd_tokens: list[str], timeout: float | None = None) -> NTResult: ...

    async def exec(self, asset_id: str, cmd_tokens: list[str], timeout: float | None = None) -> NTResult: ...

    async def exec_shell(
        self,
        asset_id: str,
        command: str,
        timeout: float | None = None,
        *,
        channel: str = "write",
    ) -> NTResult: ...


@dataclass
class SSHEndpoint:
    id: str
    asset_id: str
    role: str  # read|write
    host: str
    port: int
    username: str
    credential_id: str
    host_key_sha256: str
    host_key_trusted_at: float | None
    host_key_line: str = ""
    enabled: bool = True


class SSHAssetStore:
    """SSH 端点登记与 host key 信任。角色可自定义，kind 决定读/写通道。"""

    DEFAULT_ROLES = [
        {"name": "write", "kind": "write", "label": "可执行"},
        {"name": "read", "kind": "read", "label": "只读"},
    ]

    def __init__(self, db: Database):
        self.db = db

    def list_roles(self) -> list[dict[str, Any]]:
        row = self.db.query_one("SELECT value FROM meta WHERE key='ssh_roles'")
        if not row:
            return list(self.DEFAULT_ROLES)
        try:
            data = json.loads(row["value"])
            return data if isinstance(data, list) else list(self.DEFAULT_ROLES)
        except Exception:
            return list(self.DEFAULT_ROLES)

    def add_role(self, *, name: str, kind: str, label: str = "", actor: str = "web") -> dict[str, Any]:
        name = (name or "").strip()
        if not name or not name.replace("_", "-").replace(".", "").isalnum() or len(name) > 32:
            raise TransportError("bad_role_name", name)
        if kind not in ("read", "write"):
            raise TransportError("bad_role_kind", kind)
        roles = self.list_roles()
        if any(r.get("name") == name for r in roles):
            raise TransportError("role_exists", name)
        item = {"name": name, "kind": kind, "label": label or name}
        roles.append(item)
        with self.db.tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('ssh_roles', ?)",
                (json.dumps(roles, ensure_ascii=False),),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json, channel)"
                " VALUES(?,?,?,?,?,?)",
                (
                    now(),
                    "web_user",
                    actor,
                    "ssh_role_added",
                    json.dumps(item, ensure_ascii=False),
                    "web",
                ),
            )
        return item

    def role_kind(self, role: str) -> str:
        """角色名 → 读/写通道。未知角色按 write 收紧前先拒绝。"""
        for r in self.list_roles():
            if r.get("name") == role:
                return r.get("kind") or "read"
        if role in ("read", "write"):
            return role
        raise TransportError("unknown_role", role)

    def upsert_endpoint(
        self,
        *,
        asset_id: str,
        role: str,
        host: str,
        port: int = 22,
        username: str,
        credential_id: str = "",
        actor: str = "web",
    ) -> dict[str, Any]:
        if not host or not username:
            raise TransportError("bad_endpoint", "host/username required")
        # S01: 严格校验 username/host，防止 SSH 参数注入
        validate_ssh_identity(username, host)
        if not (1 <= int(port) <= 65535):
            raise TransportError("bad_port", "port out of range")
        # 允许自定义角色名；校验 kind
        self.role_kind(role)
        t = now()
        eid = new_id("ssh")
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO ssh_endpoints(id, asset_id, role, host, port, username,"
                " credential_id, enabled, created_at, updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(asset_id, role) DO UPDATE SET"
                " host=excluded.host, port=excluded.port, username=excluded.username,"
                " credential_id=excluded.credential_id, updated_at=excluded.updated_at",
                (eid, asset_id, role, host, int(port), username, credential_id or "", 1, t, t),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, detail_json, channel)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor,
                    "ssh_endpoint_upsert",
                    asset_id,
                    json.dumps(
                        {
                            "role": role,
                            "host": host,
                            "port": int(port),
                            "username": username,
                            "credential_id": credential_id or "",
                        },
                        ensure_ascii=False,
                    ),
                    "web",
                ),
            )
        return self.get_endpoint(asset_id, role) or {}

    def get_endpoint(self, asset_id: str, role: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT * FROM ssh_endpoints WHERE asset_id=? AND role=?",
            (asset_id, role),
        )
        return dict(row) if row else None

    def list_endpoints(self, asset_id: str = "") -> list[dict[str, Any]]:
        if asset_id:
            rows = self.db.query(
                "SELECT * FROM ssh_endpoints WHERE asset_id=? ORDER BY role", (asset_id,)
            )
        else:
            rows = self.db.query("SELECT * FROM ssh_endpoints ORDER BY asset_id, role")
        return [dict(r) for r in rows]

    def trust_host_key(
        self, asset_id: str, role: str, sha256_fp: str, actor: str = "web", *,
        key_line: str = "",
    ) -> dict[str, Any]:
        """管理员核实后登记 host key。指纹变更需再次确认，不自动覆盖。"""
        if not sha256_fp:
            raise TransportError("bad_fingerprint")
        t = now()
        row = self.get_endpoint(asset_id, role)
        if not row:
            raise TransportError("endpoint_missing", f"{asset_id}/{role}")
        prev = row.get("host_key_sha256") or ""
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE ssh_endpoints SET host_key_sha256=?, host_key_line=?, host_key_trusted_at=?, updated_at=?"
                " WHERE asset_id=? AND role=?",
                (sha256_fp, key_line or (row.get("host_key_line") or ""), t, t, asset_id, role),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, detail_json, channel)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor,
                    "ssh_host_key_trusted" if not prev else "ssh_host_key_changed",
                    asset_id,
                    __import__("json").dumps(
                        {
                            "role": role,
                            "previous": prev,
                            "current": sha256_fp,
                            "changed": bool(prev and prev != sha256_fp),
                        },
                        ensure_ascii=False,
                    ),
                    "web",
                ),
            )
        return self.get_endpoint(asset_id, role) or {}

    def delete_endpoint(self, asset_id: str, role: str, actor: str = "web") -> None:
        with self.db.tx() as conn:
            conn.execute(
                "DELETE FROM ssh_endpoints WHERE asset_id=? AND role=?", (asset_id, role)
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, detail_json, channel)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    now(),
                    "web_user",
                    actor,
                    "ssh_endpoint_deleted",
                    asset_id,
                    __import__("json").dumps({"role": role}, ensure_ascii=False),
                    "web",
                ),
            )


class SSHTransport:
    """原生 SSH：Ayana → ssh → 目标服务器。命令 tokens 由 capabilities 约束。"""

    def __init__(
        self,
        store: SSHAssetStore,
        cred_store: Any,
        *,
        ssh_binary: str = "ssh",
        default_timeout: float = 12.0,
    ):
        self.store = store
        self.cred_store = cred_store
        self.ssh_binary = ssh_binary
        self.default_timeout = default_timeout

    def _endpoint(self, asset_id: str, role: str) -> SSHEndpoint:
        row = self.store.get_endpoint(asset_id, role)
        if not row or not row.get("enabled"):
            raise TransportError("endpoint_missing", f"{asset_id}/{role}")
        return SSHEndpoint(
            id=row["id"],
            asset_id=row["asset_id"],
            role=row["role"],
            host=row["host"],
            port=int(row["port"] or 22),
            username=row["username"],
            credential_id=row["credential_id"] or "",
            host_key_sha256=row["host_key_sha256"] or "",
            host_key_trusted_at=row["host_key_trusted_at"],
            host_key_line=(row["host_key_line"] or "") if "host_key_line" in row.keys() else "",
            enabled=bool(row["enabled"]),
        )

    def _endpoint_for_channel(self, asset_id: str, kind: str) -> SSHEndpoint:
        """按读/写通道找端点：优先精确角色名，再按角色 kind 匹配。

        只读探测在缺少 read 端点时，回落到同资产 write 端点（只读命令仍走 probe）。
        """
        if kind == "write":
            row = self.store.get_endpoint(asset_id, "write")
            if row and row.get("enabled"):
                return self._endpoint(asset_id, "write")
            for r in self.store.list_roles():
                if r.get("kind") == "write":
                    row = self.store.get_endpoint(asset_id, r["name"])
                    if row and row.get("enabled"):
                        return self._endpoint(asset_id, r["name"])
            raise TransportError("endpoint_missing", f"{asset_id}/write")
        row = self.store.get_endpoint(asset_id, "read")
        if row and row.get("enabled"):
            return self._endpoint(asset_id, "read")
        for r in self.store.list_roles():
            if r.get("kind") == "read":
                row = self.store.get_endpoint(asset_id, r["name"])
                if row and row.get("enabled"):
                    return self._endpoint(asset_id, r["name"])
        # 同资产 write 端点可做只读探测（避免「只有 write 就完全不能查状态」）
        wrow = self.store.get_endpoint(asset_id, "write")
        if wrow and wrow.get("enabled"):
            return self._endpoint(asset_id, "write")
        raise TransportError("endpoint_missing", f"{asset_id}/read")

    async def probe(self, asset_id: str, cmd_tokens: list[str], timeout: float | None = None) -> NTResult:
        return await self._run(asset_id, "read", cmd_tokens, timeout)

    async def exec(self, asset_id: str, cmd_tokens: list[str], timeout: float | None = None) -> NTResult:
        return await self._run(asset_id, "write", cmd_tokens, timeout)

    async def exec_shell(
        self,
        asset_id: str,
        command: str,
        timeout: float | None = None,
        *,
        channel: str = "write",
    ) -> NTResult:
        """通用 shell 入口：绕过 cmd_tokens 元字符检查，其余校验照旧。

        权限半径 = 目标机 SSH 账户。host key / 用户校验 / 超时 / 输出截断与 probe/exec 一致。
        channel: write（默认）| read，决定走写/读端点。
        """
        if not isinstance(command, str) or not command.strip():
            raise TransportError("bad_command")
        if "\x00" in command:
            raise TransportError("unsafe_command", "null byte")
        kind = "read" if channel == "read" else "write"
        return await self._run_command(asset_id, kind, command, timeout)

    async def _run(
        self, asset_id: str, kind: str, cmd_tokens: list[str], timeout: float | None = None
    ) -> NTResult:
        if not cmd_tokens or not all(isinstance(t, str) and t for t in cmd_tokens):
            raise TransportError("bad_tokens")
        for t in cmd_tokens:
            if any(ch in t for ch in " \t\n;|&$`"):
                raise TransportError("unsafe_token", t)
        remote = shlex.join(cmd_tokens)
        return await self._run_command(asset_id, kind, remote, timeout)

    async def _run_command(
        self, asset_id: str, kind: str, remote: str, timeout: float | None = None
    ) -> NTResult:
        ep = self._endpoint_for_channel(asset_id, "write" if kind == "write" else "read")
        # 首次未信任：不要求用户手工粘贴；由上层 fetch_host_key + 信任后再连
        if not ep.host_key_sha256 or not ep.host_key_trusted_at:
            raise TransportError("host_key_untrusted", f"{asset_id}/{ep.role}")
        # 已信任：核对当前指纹，变更则阻断，不自动覆盖
        current = await fetch_host_key(ep.host, ep.port, timeout=5.0)
        if current.get("ok"):
            if current.get("fingerprint") != ep.host_key_sha256:
                raise TransportError(
                    "host_key_changed",
                    json.dumps(
                        {
                            "stored": ep.host_key_sha256,
                            "current": current.get("fingerprint"),
                            "host": ep.host,
                            "port": ep.port,
                        },
                        ensure_ascii=False,
                    ),
                )
        known_line = ep.host_key_line or ""

        t = max(3.0, float(timeout or self.default_timeout))
        workdir = tempfile.mkdtemp(prefix="ayana-ssh-")
        try:
            env = os.environ.copy()
            askpass = None
            identity = None
            secret = ""
            auth_mode = "none"
            cred_kind = ""
            if ep.credential_id and self.cred_store is not None:
                meta = self.cred_store.get_meta(ep.credential_id)
                cred_kind = (meta or {}).get("kind") or ""
                secret = self.cred_store.reveal_secret(ep.credential_id)
                if cred_kind == "private_key":
                    auth_mode = "key"
                    identity = Path(workdir) / "id_key"
                    identity.write_text(secret, encoding="utf-8")
                    os.chmod(identity, 0o600)
                else:
                    auth_mode = "password"
                    askpass = Path(workdir) / "askpass.sh"
                    # 不把密码写入 argv；经 askpass 脚本供 ssh 读取
                    askpass.write_text(
                        "#!/bin/sh\nprintf '%s' \"$AYANA_SSH_PASSWORD\"\n",
                        encoding="utf-8",
                    )
                    os.chmod(askpass, 0o700)
                    env["AYANA_SSH_PASSWORD"] = secret
                    env["SSH_ASKPASS"] = str(askpass)
                    # 无 TTY 时也强制走 ASKPASS，否则 BatchMode/无终端会跳过密码
                    env["SSH_ASKPASS_REQUIRE"] = "force"
                    env["DISPLAY"] = env.get("DISPLAY") or "ayana:0"

            # host key：strict + 已信任的公钥写入临时 known_hosts
            known_hosts = Path(workdir) / "known_hosts"
            if known_line:
                known_hosts.write_text(known_line + "\n", encoding="utf-8")
            else:
                # 兼容旧数据：无 key_line 时无法 strict 通过，明确报错
                raise TransportError("host_key_line_missing", f"{asset_id}/{ep.role}")

            # 密码认证不能开 BatchMode（会跳过 password）；密钥认证用 BatchMode
            argv = [
                self.ssh_binary,
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={known_hosts}",
                "-o", f"ConnectTimeout={max(2, int(t) - 1)}",
                "-o", "NumberOfPasswordPrompts=1",
                "-p", str(ep.port),
            ]
            if auth_mode == "password":
                argv += [
                    "-o", "PreferredAuthentications=password,keyboard-interactive",
                    "-o", "PubkeyAuthentication=no",
                    "-o", "PasswordAuthentication=yes",
                ]
            elif auth_mode == "key":
                argv += [
                    "-o", "BatchMode=yes",
                    "-o", "PreferredAuthentications=publickey",
                    "-o", "IdentitiesOnly=yes",
                    "-o", "PasswordAuthentication=no",
                ]
            else:
                argv += ["-o", "BatchMode=yes"]
            if identity:
                argv += ["-i", str(identity)]
            # S01: 用 -l 分隔用户与目的地，拒绝选项形态注入
            validate_ssh_identity(ep.username, ep.host)
            argv += ["-l", ep.username, "--", ep.host, remote]

            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=t)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=2)
                except Exception:
                    pass
                return NTResult(ok=False, output="timeout", timed_out=True, returncode=-1)
            out = (out_b or b"").decode("utf-8", errors="replace")
            err = (err_b or b"").decode("utf-8", errors="replace")
            text = out if proc.returncode == 0 else (err or out or f"exit={proc.returncode}")
            return NTResult(
                ok=proc.returncode == 0,
                output=text,
                returncode=proc.returncode,
                mode="exec" if kind == "write" else "probe",
                account=ep.username,
            )
        finally:
            # 凭据与临时文件立即清理
            try:
                import shutil

                shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass
            secret = ""

    async def send_file(
        self, asset_id: str, local_path: str, remote_path: str, *, timeout: float = 90.0
    ) -> NTResult:
        """把本地文件推到远端固定路径：ssh + cat > path（不依赖 scp/sftp）。"""
        if not remote_path.startswith("/") or any(c in remote_path for c in " \t\n;|&$`"):
            raise TransportError("bad_remote_path", remote_path[:80])
        lp = Path(local_path)
        if not lp.is_file():
            raise TransportError("local_file_missing", str(local_path)[:80])
        ep = self._endpoint_for_channel(asset_id, "write")
        if not ep.host_key_sha256 or not ep.host_key_trusted_at:
            raise TransportError("host_key_untrusted", f"{asset_id}/{ep.role}")
        known_line = ep.host_key_line or ""
        if not known_line:
            raise TransportError("host_key_line_missing", f"{asset_id}/{ep.role}")
        workdir = tempfile.mkdtemp(prefix="ayana-send-")
        try:
            env = os.environ.copy()
            identity = None
            secret = ""
            auth_mode = "none"
            if ep.credential_id and self.cred_store is not None:
                meta = self.cred_store.get_meta(ep.credential_id)
                cred_kind = (meta or {}).get("kind") or ""
                secret = self.cred_store.reveal_secret(ep.credential_id)
                if cred_kind == "private_key":
                    auth_mode = "key"
                    identity = Path(workdir) / "id_key"
                    identity.write_text(secret, encoding="utf-8")
                    os.chmod(identity, 0o600)
                else:
                    auth_mode = "password"
                    askpass = Path(workdir) / "askpass.sh"
                    askpass.write_text("#!/bin/sh\nprintf '%s' \"$AYANA_SSH_PASSWORD\"\n", encoding="utf-8")
                    os.chmod(askpass, 0o700)
                    env["AYANA_SSH_PASSWORD"] = secret
                    env["SSH_ASKPASS"] = str(askpass)
                    env["SSH_ASKPASS_REQUIRE"] = "force"
                    env["DISPLAY"] = env.get("DISPLAY") or "ayana:0"
            known_hosts = Path(workdir) / "known_hosts"
            known_hosts.write_text(known_line + "\n", encoding="utf-8")
            validate_ssh_identity(ep.username, ep.host)
            remote_cmd = f"cat > {remote_path}"
            argv = [
                self.ssh_binary,
                "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={known_hosts}",
                "-o", f"ConnectTimeout={max(2, int(timeout) - 1)}",
                "-p", str(ep.port),
            ]
            if auth_mode == "key" and identity:
                argv += ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", str(identity)]
            elif auth_mode == "password":
                argv += ["-o", "PreferredAuthentications=password,keyboard-interactive"]
            argv += ["-l", ep.username, "--", ep.host, remote_cmd]

            async def _run_cat(cmd_line: str, data: bytes) -> NTResult:
                proc = await asyncio.create_subprocess_exec(
                    *argv[:-1],
                    cmd_line,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
                try:
                    out_b, err_b = await asyncio.wait_for(proc.communicate(input=data), timeout=timeout)
                except asyncio.TimeoutError:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    return NTResult(ok=False, output="timeout", returncode=-1)
                text = ((out_b or b"") + (err_b or b"")).decode("utf-8", "replace")
                return NTResult(ok=proc.returncode == 0, output=text[:500], returncode=proc.returncode)

            # 大文件分块写入，避免单次 stdin 过大被 sshd 重置
            size = lp.stat().st_size
            chunk = 1024 * 1024
            if size <= chunk * 2:
                with open(lp, "rb") as f:
                    return await _run_cat(f"cat > {remote_path}", f.read())
            tmp_r = remote_path + ".part"
            with open(lp, "rb") as f:
                first = f.read(chunk)
            r = await _run_cat(f"cat > {tmp_r}", first)
            if not r.ok:
                return r
            with open(lp, "rb") as f:
                f.read(chunk)
                while True:
                    part = f.read(chunk)
                    if not part:
                        break
                    r = await _run_cat(f"cat >> {tmp_r}", part)
                    if not r.ok:
                        return r
            return await self._run(
                asset_id, "write", ["mv", tmp_r, remote_path], timeout=max(20.0, timeout)
            )
        finally:
            try:
                import shutil

                shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass
            secret = ""

    async def test_connection(self, asset_id: str, role: str = "read") -> dict[str, Any]:
        kind = "write" if role == "write" else "read"
        try:
            self.store.role_kind(role) if role not in ("read", "write") else None
            kind = self.store.role_kind(role) if role not in ("read", "write") else role
        except Exception:
            pass
        res = await self._run(asset_id, "write" if kind == "write" else "read", ["true"], timeout=8.0)
        return {
            "ok": res.ok,
            "output": res.output[:500],
            "returncode": res.returncode,
            "timed_out": res.timed_out,
        }


# NT 实现已移除。仅保留原生 SSH（Transport）。
# LocalExecTransport 保留在 promconfig.py（node_exporter 本机安装/控制用），
# 通道解析统一走 resolve_exec_channel，避免第三份实现。


class ChannelUnavailable(Exception):
    """资产既无 SSH 端点也不在 local_assets 集合。"""


def resolve_exec_channel(
    asset_id: str,
    ssh_transport: Any | None,
    *,
    local_assets: set[str] | None = None,
    role: str = "read",
) -> Any:
    """统一执行通道解析：有 SSH 端点用 SSH；仅本机登记资产才允许 LocalExec。

    合并自 main._checks_transport 与 web._ne_transport 两处重复回落逻辑。
    SSH 失败不得静默跨主机回退；找不到通道抛 ChannelUnavailable。
    """
    local_assets = local_assets or set()
    store = getattr(ssh_transport, "store", None) if ssh_transport is not None else None
    if store is not None:
        try:
            ep = store.get_endpoint(asset_id, role) or store.get_endpoint(
                asset_id, "write" if role == "read" else "read"
            )
        except Exception:
            ep = None
        if ep and ep.get("enabled") and ssh_transport is not None:
            return ssh_transport
    if asset_id in local_assets:
        from .promconfig import LocalExecTransport

        return LocalExecTransport()
    raise ChannelUnavailable(f"asset_channel_unavailable:{asset_id}")
