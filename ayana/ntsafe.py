"""NT 受限 SSH 通道与资产身份绑定校验。

只允许 restricted_dispatcher 模式；写通道必须走 write_alias。
host_id：管理员核实登记 + 启动/执行前别名绑定校验；
运行时可通过 astrbot-identity 核验账号模式。
"""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import time
from dataclasses import dataclass
from typing import Any

DISPATCHER = "/usr/local/sbin/astrbot-nt-command"
ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
MAX_OUT = 32768


class NTError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def is_safe_alias(name: str) -> bool:
    return bool(name) and bool(ASSET_RE.fullmatch(name)) and not name.startswith("-")


@dataclass
class NTResult:
    ok: bool
    output: str
    returncode: int = -1
    timed_out: bool = False
    mode: str = ""
    account: str = ""

    def clipped(self, limit: int = 4000) -> str:
        t = self.output or ""
        return t if len(t) <= limit else t[:limit] + "\n…[truncated]"


class NTClient:
    """经本地 ssh + Host 别名执行固定受限入口。"""

    def __init__(
        self,
        *,
        privilege_mode: str = "restricted_dispatcher",
        ssh_timeout: float = 12.0,
        ssh_binary: str = "ssh",
    ):
        if privilege_mode != "restricted_dispatcher":
            raise NTError("blocked-ssh-privilege-mode", privilege_mode)
        self.ssh_timeout = ssh_timeout
        self.ssh_binary = ssh_binary

    async def identity(self, alias: str) -> NTResult:
        """调用 astrbot-identity，返回账号与模式。"""
        return await self._run(alias, "astrbot-identity")

    async def describe(self, alias: str) -> NTResult:
        """受限只读 describe：host_id / account / mode / protocol_version。"""
        return await self._run(alias, "astrbot-describe")

    async def probe(self, alias: str, cmd_tokens: list[str], timeout: float | None = None) -> NTResult:
        if not is_safe_alias(alias):
            raise NTError("blocked-alias", alias)
        remote = shlex.join(["sudo", "-n", "--", DISPATCHER, "probe", *cmd_tokens])
        return await self._run(alias, remote, timeout=timeout)

    async def exec(self, write_alias: str, cmd_tokens: list[str], timeout: float | None = None) -> NTResult:
        if not is_safe_alias(write_alias):
            raise NTError("blocked-alias", write_alias)
        remote = shlex.join(["sudo", "-n", "--", DISPATCHER, "exec", *cmd_tokens])
        return await self._run(write_alias, remote, timeout=timeout)

    async def _run(self, alias: str, remote_cmd: str, timeout: float | None = None) -> NTResult:
        if not is_safe_alias(alias):
            raise NTError("blocked-alias", alias)
        # 远端仍经 shell；astrbot-nt-ssh 会再解析。禁元字符由入口负责。
        t = max(3.0, float(timeout or self.ssh_timeout))
        argv = [
            self.ssh_binary,
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={max(2, int(t) - 1)}",
            alias,
            remote_cmd,
        ]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
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
        text = (out if proc.returncode == 0 else (err or out or f"exit={proc.returncode}"))
        if len(text.encode("utf-8", "replace")) > MAX_OUT:
            text = text.encode("utf-8", "replace")[:MAX_OUT].decode("utf-8", "replace") + "\n…[truncated]"
        return NTResult(ok=proc.returncode == 0, output=text, returncode=proc.returncode)


@dataclass
class AssetBinding:
    asset_id: str
    read_alias: str
    write_alias: str
    expected_host_id: str = ""
    host_id_verified_at: float | None = None


class IdentityGate:
    """别名绑定 + host_id 登记状态校验。"""

    def __init__(self, nt: NTClient, bindings: list[AssetBinding]):
        self.nt = nt
        self._by_asset = {b.asset_id: b for b in bindings}
        self._by_read = {b.read_alias: b for b in bindings}
        self._by_write = {b.write_alias: b for b in bindings}
        self._check()

    def _check(self) -> None:
        for b in self._by_asset.values():
            if not is_safe_alias(b.read_alias) or not is_safe_alias(b.write_alias):
                raise NTError("bad-alias", b.asset_id)
            if b.read_alias == b.write_alias:
                raise NTError("read-write-alias-collision", b.asset_id)

    def get(self, asset_id: str) -> AssetBinding:
        b = self._by_asset.get(asset_id)
        if not b:
            raise NTError("unknown-asset", asset_id)
        return b

    def binding_status(self, asset_id: str) -> dict[str, Any]:
        b = self.get(asset_id)
        return {
            "asset_id": b.asset_id,
            "read_alias": b.read_alias,
            "write_alias": b.write_alias,
            "expected_host_id": b.expected_host_id,
            "host_id_verified_at": b.host_id_verified_at,
            "identity_source": "admin_registered" if b.host_id_verified_at else "unverified",
        }

    async def verify_account(self, asset_id: str, *, write: bool = False) -> dict[str, Any]:
        b = self.get(asset_id)
        alias = b.write_alias if write else b.read_alias
        info: dict[str, Any] = {"ok": False}
        # 优先 describe；旧 identity 不得视为 host_id 已验收
        res = await self.nt.describe(alias) if hasattr(self.nt, "describe") else NTResult(ok=False, output="")
        source = "describe"
        if not res.ok:
            res = await self.nt.identity(alias)
            source = "identity_legacy"
        info["raw"] = res.clipped(500)
        info["identity_source"] = source
        if not res.ok:
            info["error"] = "identity_call_failed"
            return info
        try:
            data = json.loads(res.output.strip())
        except json.JSONDecodeError:
            info["error"] = "identity_parse_failed"
            return info
        mode = data.get("mode") or ""
        remote_host_id = data.get("host_id") or data.get("hostid") or ""
        info.update(
            account=data.get("user", "") or "",
            mode=mode,
            uid=data.get("uid"),
            remote_host_id=remote_host_id,
            protocol_version=str(data.get("protocol_version") or data.get("proto") or ""),
        )
        want = "exec" if write else "probe"
        if mode != want:
            info["error"] = f"mode mismatch: {mode or 'missing'} != {want}"
            return info
        if write:
            if not b.expected_host_id or not b.host_id_verified_at:
                info["error"] = "host_id not registered/verified"
                return info
            if not remote_host_id:
                info["error"] = "remote_host_id_missing"
                return info
            if remote_host_id != b.expected_host_id:
                info["error"] = (
                    f"host_id mismatch: remote={remote_host_id} expected={b.expected_host_id}"
                )
                return info
        elif remote_host_id and b.expected_host_id and remote_host_id != b.expected_host_id:
            info["error"] = (
                f"host_id mismatch: remote={remote_host_id} expected={b.expected_host_id}"
            )
            return info
        info["ok"] = True
        return info


def record_host_id(db, asset_id: str, host_id: str, actor: str) -> None:
    """管理员核实后登记 host_id。"""
    from .db import now

    db.execute(
        "UPDATE assets SET expected_host_id=?, host_id_verified_at=?, updated_at=? WHERE id=?",
        (host_id, now(), now(), asset_id),
    )
    db.audit(
        "system",
        actor,
        "host_id_registered",
        asset_id=asset_id,
        detail={"host_id": host_id},
    )
