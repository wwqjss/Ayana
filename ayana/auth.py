"""本地认证：密码（PBKDF2）+ TOTP 2FA + 恢复码 + Web 会话。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets as pysecrets
import struct
import time
from typing import Any

from .db import Database, now, new_id

PBKDF2_ITERATIONS = 200_000
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_WINDOW = 1  # 允许前后 1 个时间步


def hash_password(password: str, pepper: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", (password + pepper).encode("utf-8"), salt, iterations
    )
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str, pepper: str) -> bool:
    try:
        algo, iter_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False
    dk = hashlib.pbkdf2_hmac(
        "sha256", (password + pepper).encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(dk, expected)


def hash_recovery_code(code: str, pepper: str) -> str:
    return hashlib.sha256((code + pepper).encode("utf-8")).hexdigest()


# ---- TOTP (RFC 6238) ----


def _hotp(key: bytes, counter: int, digits: int = TOTP_DIGITS) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_now(secret_b32: str, *, at: float | None = None) -> str:
    key = base64.b32decode(secret_b32, casefold=True)
    counter = int((at if at is not None else time.time()) // TOTP_PERIOD)
    return _hotp(key, counter)


def totp_verify(secret_b32: str, code: str, *, at: float | None = None) -> bool:
    if not secret_b32 or not code or not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    try:
        key = base64.b32decode(secret_b32, casefold=True)
    except Exception:
        return False
    counter = int((at if at is not None else time.time()) // TOTP_PERIOD)
    for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        if hmac.compare_digest(_hotp(key, counter + delta), code):
            return True
    return False


def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def otpauth_uri(username: str, secret_b32: str, issuer: str = "Ayana") -> str:
    return (
        f"otpauth://totp/{issuer}:{username}"
        f"?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )


def generate_recovery_codes(count: int = 8) -> list[str]:
    # 8 组 4 位，便于抄写：XXXX-XXXX-XXXX
    codes = []
    for _ in range(count):
        raw = pysecrets.token_hex(6).upper()
        codes.append(f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}")
    return codes


# ---- 服务 ----


class AuthError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        super().__init__(message or code)


class AuthService:
    def __init__(self, db: Database, pepper: str, session_ttl: int, max_failed: int, lockout: int):
        self.db = db
        self.pepper = pepper
        self.session_ttl = session_ttl
        self.max_failed = max_failed
        self.lockout = lockout

    def ensure_bootstrap_admin(self, username: str) -> str | None:
        """若无用户则创建管理员，返回临时密码；否则 None。"""
        row = self.db.query_one("SELECT COUNT(*) AS n FROM users")
        if row and row["n"] > 0:
            return None
        password = pysecrets.token_urlsafe(12)
        self.create_user(username, password, is_admin=True)
        return password

    def create_user(self, username: str, password: str, *, is_admin: bool = True) -> int:
        t = now()
        cur = self.db.execute(
            "INSERT INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?)",
            (username, hash_password(password, self.pepper), 0, 1 if is_admin else 0, t, t),
        )
        return int(cur.lastrowid or 0)

    def _recent_failures(self, username: str) -> int:
        since = now() - self.lockout
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM login_attempts"
            " WHERE username=? AND ok=0 AND at>?",
            (username, since),
        )
        return int(row["n"] if row else 0)

    def login(
        self,
        username: str,
        password: str,
        totp_code: str = "",
        recovery_code: str = "",
        *,
        ip: str = "",
    ) -> dict[str, Any]:
        if self._recent_failures(username) >= self.max_failed:
            raise AuthError("locked", "尝试过多，请稍后再试")

        row = self.db.query_one("SELECT * FROM users WHERE username=?", (username,))
        ok = False
        user_id = 0
        if row and verify_password(password, row["password_hash"], self.pepper):
            user_id = int(row["id"])
            if not row["totp_enabled"]:
                ok = True
            elif recovery_code:
                ok = self._use_recovery_code(user_id, recovery_code)
            elif totp_code and totp_verify(row["totp_secret"], totp_code):
                ok = True

        self.db.execute(
            "INSERT INTO login_attempts(username, at, ok, ip) VALUES(?,?,?,?)",
            (username, now(), 1 if ok else 0, ip),
        )
        if not ok:
            raise AuthError("invalid", "用户名、密码或验证码错误")

        assert row is not None
        return self._issue_session(user_id, ip)

    def _use_recovery_code(self, user_id: int, code: str) -> bool:
        needle = hash_recovery_code(code.strip(), self.pepper)
        rows = self.db.query(
            "SELECT id FROM recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL",
            (user_id, needle),
        )
        if not rows:
            return False
        self.db.execute(
            "UPDATE recovery_codes SET used_at=? WHERE id=?", (now(), rows[0]["id"])
        )
        return True

    def _issue_session(self, user_id: int, ip: str = "", ua: str = "") -> dict[str, Any]:
        sid = new_id("sess")
        csrf = pysecrets.token_urlsafe(24)
        t = now()
        self.db.execute(
            "INSERT INTO web_sessions(id, user_id, csrf_token, created_at, expires_at, ip, ua)"
            " VALUES(?,?,?,?,?,?,?)",
            (sid, user_id, csrf, t, t + self.session_ttl, ip, ua),
        )
        return {"session_id": sid, "csrf_token": csrf, "expires_at": t + self.session_ttl}

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        if not session_id:
            return None
        row = self.db.query_one(
            "SELECT s.id AS session_id, s.csrf_token, s.expires_at, s.user_id,"
            " u.username, u.is_admin FROM web_sessions s JOIN users u ON u.id=s.user_id"
            " WHERE s.id=?",
            (session_id,),
        )
        if not row:
            return None
        if row["expires_at"] < now():
            self.db.execute("DELETE FROM web_sessions WHERE id=?", (session_id,))
            return None
        return dict(row)

    def logout(self, session_id: str) -> None:
        self.db.execute("DELETE FROM web_sessions WHERE id=?", (session_id,))

    def change_password(self, user_id: int, old_password: str, new_password: str) -> None:
        if not old_password or not new_password or len(new_password) < 10:
            raise AuthError("weak_password", "新密码至少 10 位")
        row = self.db.query_one("SELECT password_hash FROM users WHERE id=?", (user_id,))
        if not row or not verify_password(old_password, row["password_hash"], self.pepper):
            raise AuthError("invalid", "原密码错误")
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                (hash_password(new_password, self.pepper), now(), user_id),
            )
            # 改密撤销旧会话
            conn.execute("DELETE FROM web_sessions WHERE user_id=?", (user_id,))

    def setup_totp(self, user_id: int, password: str = "", totp_code: str = "") -> dict[str, str]:
        """生成待确认 secret，不打断现有 2FA。

        若已启用 TOTP，必须提供密码 + 当前 OTP 才能进入更换流程。
        """
        row = self.db.query_one("SELECT * FROM users WHERE id=?", (user_id,))
        if not row:
            raise AuthError("no_user")
        if row["totp_enabled"]:
            if not password or not verify_password(password, row["password_hash"], self.pepper):
                raise AuthError("reauth_required", "更换 2FA 需要当前密码")
            if not totp_code or not totp_verify(row["totp_secret"], totp_code):
                raise AuthError("reauth_required", "更换 2FA 需要当前动态码")
        secret = generate_totp_secret()
        # 待确认 secret 与正式 secret 分离：不覆盖、不禁用
        self.db.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"totp_pending:{user_id}", secret),
        )
        username = row["username"]
        return {"secret": secret, "otpauth": otpauth_uri(username, secret)}

    def cancel_totp_setup(self, user_id: int) -> None:
        self.db.execute("DELETE FROM meta WHERE key=?", (f"totp_pending:{user_id}",))

    def confirm_totp(self, user_id: int, code: str, password: str = "") -> list[str]:
        """用待确认 secret 验证后才启用；之前保留原认证。"""
        row = self.db.query_one("SELECT * FROM users WHERE id=?", (user_id,))
        if not row:
            raise AuthError("no_user")
        pending = self.db.query_one(
            "SELECT value FROM meta WHERE key=?", (f"totp_pending:{user_id}",)
        )
        if not pending or not pending["value"]:
            raise AuthError("no_secret", "尚未初始化 TOTP")
        if not totp_verify(pending["value"], code):
            raise AuthError("invalid_code", "动态验证码错误")
        if row["totp_enabled"] and password:
            # 更换流程需再次确认密码（setup 已验过，这里做一次最终确认）
            if not verify_password(password, row["password_hash"], self.pepper):
                raise AuthError("reauth_required", "原密码错误")

        codes = generate_recovery_codes()
        with self.db.tx() as conn:
            conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
            for c in codes:
                conn.execute(
                    "INSERT INTO recovery_codes(user_id, code_hash) VALUES(?,?)",
                    (user_id, hash_recovery_code(c, self.pepper)),
                )
            conn.execute(
                "UPDATE users SET totp_secret=?, totp_enabled=1, updated_at=? WHERE id=?",
                (pending["value"], now(), user_id),
            )
            conn.execute("DELETE FROM meta WHERE key=?", (f"totp_pending:{user_id}",))
            # 更换认证因素：撤销该用户其它会话（保留当前由调用方决定）
            conn.execute("DELETE FROM web_sessions WHERE user_id=?", (user_id,))
        return codes

    def disable_totp(self, user_id: int, password: str = "", totp_code: str = "") -> None:
        row = self.db.query_one("SELECT * FROM users WHERE id=?", (user_id,))
        if not row:
            raise AuthError("no_user")
        if not password or not verify_password(password, row["password_hash"], self.pepper):
            raise AuthError("reauth_required", "需要当前密码")
        if row["totp_enabled"]:
            if not totp_code or not totp_verify(row["totp_secret"], totp_code):
                raise AuthError("reauth_required", "需要当前动态码")
        self.db.execute(
            "UPDATE users SET totp_enabled=0, totp_secret='', updated_at=? WHERE id=?",
            (now(), user_id),
        )
        self.db.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        self.db.execute("DELETE FROM meta WHERE key=?", (f"totp_pending:{user_id}",))
        self.db.execute("DELETE FROM web_sessions WHERE user_id=?", (user_id,))

    def cleanup(self) -> None:
        self.db.execute("DELETE FROM web_sessions WHERE expires_at<?", (now(),))
