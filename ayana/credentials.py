"""SSH 凭据加密存取。明文只在建连瞬间进内存，不进日志/事件/LLM。"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .db import Database, new_id, now

try:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    serialization = None  # type: ignore
    AESGCM = None  # type: ignore


class CredentialError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.detail = message
        super().__init__(f"{code}: {message}" if message else code)


def _derive_key(master: str) -> bytes:
    if not master:
        raise CredentialError("missing_key", "ssh_credential_key not configured")
    if AESGCM is None:
        raise CredentialError("crypto_unavailable", "cryptography not installed")
    # 固定 salt 派生 32 字节；主密钥本身来自 secrets/环境变量
    return hashlib.sha256(master.encode("utf-8")).digest()


def _encrypt(master: str, plaintext: bytes) -> bytes:
    key = _derive_key(master)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _decrypt(master: str, blob: bytes) -> bytes:
    key = _derive_key(master)
    if not blob or len(blob) < 13:
        raise CredentialError("bad_blob", "ciphertext too short")
    nonce, ct = blob[:12], blob[12:]
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise CredentialError("decrypt_failed", str(e)) from e


def generate_keypair() -> tuple[str, str]:
    """生成 ed25519 密钥对，返回 (private_pem, public_line)。不落盘。"""
    with tempfile.TemporaryDirectory() as td:
        key_path = Path(td) / "id_ed25519"
        proc = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "ayana", "-f", str(key_path)],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode != 0:
            raise CredentialError("keygen_failed", (proc.stderr or "")[:300])
        priv = key_path.read_text(encoding="utf-8")
        pub = (Path(str(key_path) + ".pub")).read_text(encoding="utf-8").strip()
        return priv, pub


def public_key_from_private(secret: str, supplied_public_key: str = "") -> str:
    """验证无密码私钥并推导 OpenSSH 公钥；可选公钥必须属于同一把私钥。"""
    if serialization is None:
        raise CredentialError("crypto_unavailable", "cryptography not installed")
    try:
        raw = secret.encode("utf-8")
        loader = (serialization.load_ssh_private_key if "BEGIN OPENSSH PRIVATE KEY" in secret
                  else serialization.load_pem_private_key)
        private = loader(raw, password=None)
        derived = private.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        ).decode("ascii")
    except (ValueError, TypeError, AttributeError, UnicodeError, UnsupportedAlgorithm) as e:
        raise CredentialError("bad_private_key", "需要有效的无密码 PEM/OpenSSH 私钥") from e
    if supplied_public_key:
        supplied = supplied_public_key.strip()
        if "\n" in supplied or "\r" in supplied or supplied.split()[:2] != derived.split():
            raise CredentialError("public_key_mismatch", "公钥与提交的私钥不匹配")
        return supplied
    return derived


def generate_and_store_keypair(
    store: "CredentialStore", *, name: str, actor: str = "web"
) -> dict[str, Any]:
    """生成密钥对：私钥加密入库，公钥返回给用户/部署。"""
    priv, pub = generate_keypair()
    meta = store.create(
        name=name, kind="private_key", secret=priv, public_key=pub, actor=actor
    )
    # 私钥不进返回值
    return {"id": meta["id"], "name": meta["name"], "kind": meta["kind"], "public_key": meta["public_key"]}


async def deploy_public_key(
    *,
    host: str,
    port: int,
    username: str,
    public_key: str,
    credential_id: str,
    store: "CredentialStore",
    ssh_binary: str = "ssh",
    host_key_line: str = "",
) -> dict[str, Any]:
    """用现有授权方式向服务器安装公钥（追加 authorized_keys）。不自动提权。"""
    if not public_key.strip():
        raise CredentialError("empty_public_key")
    secret = store.reveal_secret(credential_id)
    meta = store.get_meta(credential_id)
    kind = (meta or {}).get("kind") or ""
    workdir = Path(tempfile.mkdtemp(prefix="ayana-deploy-"))
    try:
        env = os.environ.copy()
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = env.get("DISPLAY") or ":0"
        identity = None
        if kind == "private_key":
            identity = workdir / "id_key"
            identity.write_text(secret, encoding="utf-8")
            os.chmod(identity, 0o600)
        else:
            askpass = workdir / "askpass.sh"
            askpass.write_text(
                "#!/bin/sh\nprintf '%s' \"$AYANA_SSH_PASSWORD\"\n", encoding="utf-8"
            )
            os.chmod(askpass, 0o700)
            env["AYANA_SSH_PASSWORD"] = secret
            env["SSH_ASKPASS"] = str(askpass)

        remote = (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
            f"grep -qF {shlex.quote(public_key.strip())} ~/.ssh/authorized_keys 2>/dev/null || "
            f"echo {shlex.quote(public_key.strip())} >> ~/.ssh/authorized_keys"
        )
        known_hosts = workdir / "known_hosts"
        known_hosts.write_text((host_key_line + "\n") if host_key_line else "", encoding="utf-8")
        argv = [
            ssh_binary,
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "NumberOfPasswordPrompts=1",
            "-p", str(port),
        ]
        if kind == "private_key":
            argv += [
                "-o", "BatchMode=yes",
                "-o", "PreferredAuthentications=publickey",
                "-o", "IdentitiesOnly=yes",
                "-o", "PasswordAuthentication=no",
            ]
            argv += ["-i", str(identity)]
        else:
            # 密码认证：不能 BatchMode，否则跳过 password
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = env.get("DISPLAY") or "ayana:0"
            argv += [
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                "-o", "PubkeyAuthentication=no",
                "-o", "PasswordAuthentication=yes",
            ]
        argv += [f"{username}@{host}", remote]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=20)
        text = ((out_b or b"") + (err_b or b"")).decode("utf-8", errors="replace")
        ok = proc.returncode == 0
        return {"ok": ok, "output": text[:500], "returncode": proc.returncode}
    finally:
        import shutil

        shutil.rmtree(workdir, ignore_errors=True)
        secret = ""


class CredentialStore:
    def __init__(self, db: Database, master_key: str = ""):
        self.db = db
        self.master_key = master_key or os.environ.get("AYANA_SSH_CREDENTIAL_KEY", "")

    def _require_key(self) -> str:
        if not self.master_key:
            raise CredentialError("missing_key", "ssh_credential_key required")
        return self.master_key

    def create(
        self,
        *,
        name: str,
        kind: str,
        secret: str,
        public_key: str = "",
        actor: str = "web",
    ) -> dict[str, Any]:
        if kind not in ("password", "private_key"):
            raise CredentialError("bad_kind", kind)
        if not secret:
            raise CredentialError("empty_secret")
        if kind == "private_key":
            public_key = public_key_from_private(secret, public_key)
        key = self._require_key()
        cid = new_id("cred")
        t = now()
        enc = _encrypt(key, secret.encode("utf-8"))
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO ssh_credentials(id, name, kind, secret_enc, public_key,"
                " created_at, updated_at) VALUES(?,?,?,?,?,?,?)",
                (cid, name, kind, enc, public_key, t, t),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json, channel)"
                " VALUES(?,?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor,
                    "ssh_credential_created",
                    json.dumps({"id": cid, "name": name, "kind": kind}, ensure_ascii=False),
                    "web",
                ),
            )
        return {"id": cid, "name": name, "kind": kind, "public_key": public_key}

    def rotate(
        self,
        credential_id: str,
        *,
        secret: str,
        public_key: str = "",
        actor: str = "web",
    ) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM ssh_credentials WHERE id=?", (credential_id,))
        if not row:
            raise CredentialError("not_found", credential_id)
        key = self._require_key()
        if not secret:
            raise CredentialError("empty_secret")
        if row["kind"] == "private_key":
            public_key = public_key_from_private(secret, public_key)
        else:
            public_key = public_key or row["public_key"]
        t = now()
        enc = _encrypt(key, secret.encode("utf-8"))
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE ssh_credentials SET secret_enc=?, public_key=?, updated_at=?, rotated_at=?"
                " WHERE id=?",
                (enc, public_key, t, t, credential_id),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json, channel)"
                " VALUES(?,?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor,
                    "ssh_credential_rotated",
                    json.dumps({"id": credential_id, "kind": row["kind"]}, ensure_ascii=False),
                    "web",
                ),
            )
        return {"id": credential_id, "kind": row["kind"], "public_key": public_key, "rotated_at": t}

    def delete(self, credential_id: str, actor: str = "web") -> None:
        row = self.db.query_one("SELECT * FROM ssh_credentials WHERE id=?", (credential_id,))
        if not row:
            raise CredentialError("not_found", credential_id)
        with self.db.tx() as conn:
            conn.execute("DELETE FROM ssh_credentials WHERE id=?", (credential_id,))
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json, channel)"
                " VALUES(?,?,?,?,?,?)",
                (
                    now(),
                    "web_user",
                    actor,
                    "ssh_credential_deleted",
                    json.dumps({"id": credential_id, "kind": row["kind"]}, ensure_ascii=False),
                    "web",
                ),
            )

    def get_meta(self, credential_id: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT id, name, kind, public_key, created_at, updated_at, rotated_at"
            " FROM ssh_credentials WHERE id=?",
            (credential_id,),
        )
        return dict(row) if row else None

    def list_meta(self) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT id, name, kind, public_key, created_at, updated_at, rotated_at"
            " FROM ssh_credentials ORDER BY created_at DESC"
        )
        return [dict(r) for r in rows]

    def reveal_secret(self, credential_id: str) -> str:
        """仅建连路径调用。调用方不得写入日志/事件/LLM。"""
        row = self.db.query_one(
            "SELECT secret_enc FROM ssh_credentials WHERE id=?", (credential_id,)
        )
        if not row:
            raise CredentialError("not_found", credential_id)
        return _decrypt(self._require_key(), bytes(row["secret_enc"])).decode("utf-8")
