"""本地认证：密码（PBKDF2）+ TOTP 2FA + 恢复码 + Web 会话。

S11: TOTP 秘密使用 AES-GCM 加密存储（totp_encrypt_key），明文只在验证瞬间进内存。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets as pysecrets
import struct
import time
from typing import Any

from .db import Database, now, new_id

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    AESGCM = None  # type: ignore

PBKDF2_ITERATIONS = 200_000
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_WINDOW = 1  # 允许前后 1 个时间步

# S11: 版本化前缀，区分加密/明文存量
_TOTP_ENC_PREFIX = "enc:v1:"


def _totp_derive_key(master: str) -> bytes:
    if not master:
        return b""
    return hashlib.sha256(master.encode("utf-8")).digest()


def encrypt_totp_secret(master: str, plaintext: str) -> str:
    """S11: 加密 TOTP secret。无密钥时降级明文（兼容旧数据），但标 prefix 不加。"""
    if not master or AESGCM is None or not plaintext:
        return plaintext
    key = _totp_derive_key(master)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _TOTP_ENC_PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt_totp_secret(master: str, stored: str) -> str:
    """S11: 解密 TOTP secret。兼容旧明文（无 prefix 直接返回）。"""
    if not stored:
        return ""
    if not stored.startswith(_TOTP_ENC_PREFIX):
        return stored  # 旧明文数据
    if not master or AESGCM is None:
        return ""
    try:
        raw = base64.b64decode(stored[len(_TOTP_ENC_PREFIX):])
        nonce, ct = raw[:12], raw[12:]
        key = _totp_derive_key(master)
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except Exception:
        return ""


def _as_str(value: Any, default: str = "") -> str:
    """登录/验证边界只接受字符串；非字符串统一成 default，避免 TypeError 造成 500/枚举。"""
    return value if isinstance(value, str) else default


def hash_password(password: str, pepper: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    password = _as_str(password)
    pepper = _as_str(pepper)
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", (password + pepper).encode("utf-8"), salt, iterations
    )
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str, pepper: str) -> bool:
    if not isinstance(password, str) or not isinstance(stored, str) or not isinstance(pepper, str):
        return False
    try:
        # P1-10: 畸形 Unicode（如 lone surrogate）编码失败不得形成 500/枚举
        (password + pepper).encode("utf-8")
    except UnicodeEncodeError:
        return False
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
    code = _as_str(code)
    pepper = _as_str(pepper)
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
    code = _as_str(code)
    if not isinstance(secret_b32, str) or not secret_b32:
        return False
    # P1-10: 仅 ASCII 6 位数字，拒绝全角数字等 isdigit 通过项
    if not code or not re.fullmatch(r"[0-9]{6}", code):
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
    def __init__(
        self,
        db: Database,
        pepper: str,
        session_ttl: int,
        max_failed: int,
        lockout: int,
        totp_key: str = "",
        legacy_peppers: list[str] | None = None,
    ):
        self.db = db
        self.pepper = pepper
        self.legacy_peppers = [p for p in (legacy_peppers or []) if p and p != pepper]
        self.session_ttl = session_ttl
        self.max_failed = max_failed
        self.lockout = lockout
        self._totp_key = totp_key  # S11: TOTP 加密密钥
        self._pending_logins: dict[str, dict[str, Any]] = {}

    def ensure_bootstrap_admin(self, username: str) -> str | None:
        """若无用户则创建管理员，返回临时密码；否则 None。"""
        row = self.db.query_one("SELECT COUNT(*) AS n FROM users")
        if row and row["n"] > 0:
            return None
        password = pysecrets.token_urlsafe(12)
        self.create_user(username, password, is_admin=True, must_change_password=True)
        return password

    # ---- 一次性 Setup Token 注册管理员 ----

    def user_count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS n FROM users")
        return int(row["n"] if row else 0)

    def setup_state(self) -> str:
        """服务端初始化状态：pending / completed / unknown。

        不得仅凭用户数为 0 开放注册；必须有显式 setup_state。
        """
        row = self.db.query_one("SELECT value FROM meta WHERE key='setup_state'")
        return str(row["value"]) if row and row["value"] else "unknown"

    def _set_setup_state(self, state: str) -> None:
        self.db.execute(
            "INSERT INTO meta(key, value) VALUES('setup_state', ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (state,),
        )

    def ensure_setup_initialized(self) -> dict[str, Any]:
        """启动时判定注册门闩。返回 {state, token, token_hint}。

        规则（防 DB 异常/迁移失败误开注册）：
        - 已有用户 → 一律 completed，即使 meta 丢失
        - meta=completed → 永不重开
        - 无用户且无 setup_state（真正首次安装）→ pending + 生成一次性 token
        - pending 但已有用户（异常）→ 收敛为 completed 并作废 token
        """
        n = self.user_count()
        state = self.setup_state()
        if n > 0:
            if state != "completed":
                self._set_setup_state("completed")
                self.db.execute("DELETE FROM meta WHERE key='setup_token_hash'")
            return {"state": "completed", "token": "", "token_hint": ""}
        if state == "completed":
            # 空库但标记完成：视为异常，不开放注册
            return {"state": "completed", "token": "", "token_hint": ""}
        if state == "pending":
            row = self.db.query_one("SELECT value FROM meta WHERE key='setup_token_hash'")
            if row and row["value"]:
                return {"state": "pending", "token": "", "token_hint": ""}
            # pending 却无 token hash：重新发一枚（仅限仍无用户）
            token = self._issue_setup_token()
            return {"state": "pending", "token": token, "token_hint": ""}
        # unknown + 无用户：首次安装
        token = self._issue_setup_token()
        self._set_setup_state("pending")
        return {"state": "pending", "token": token, "token_hint": ""}

    def _issue_setup_token(self) -> str:
        token = pysecrets.token_urlsafe(24)
        self.db.execute(
            "INSERT INTO meta(key, value) VALUES('setup_token_hash', ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (hash_recovery_code(token, self.pepper),),
        )
        return token

    def verify_setup_token(self, token: str) -> bool:
        """校验一次性 Token；不匹配不区分原因。"""
        token = _as_str(token).strip()
        if not token or self.setup_state() != "pending" or self.user_count() > 0:
            return False
        row = self.db.query_one("SELECT value FROM meta WHERE key='setup_token_hash'")
        if not row or not row["value"]:
            return False
        return hmac.compare_digest(hash_recovery_code(token, self.pepper), str(row["value"]))

    def register_admin(
        self,
        token: str,
        username: str,
        password: str,
        *,
        ip: str = "",
        ua: str = "",
    ) -> dict[str, Any]:
        """Token 一次性注册管理员。成功后关闭注册并撤销 token。"""
        username = _as_str(username).strip()
        password = _as_str(password)
        if self.setup_state() != "pending":
            raise AuthError("setup_closed", "注册已关闭，无法再次开放")
        if self.user_count() > 0:
            # 空库条件已不满足：立即收敛，禁止误开
            self._set_setup_state("completed")
            self.db.execute("DELETE FROM meta WHERE key='setup_token_hash'")
            raise AuthError("setup_closed", "系统已初始化，注册已关闭")
        if not username or not re.fullmatch(r"[A-Za-z0-9._-]{2,32}", username):
            raise AuthError("bad_username", "用户名需 2–32 位字母/数字/._-")
        if not password or len(password) < 10:
            raise AuthError("weak_password", "密码至少 10 位")
        if not self.verify_setup_token(token):
            raise AuthError("bad_token", "初始化 Token 无效或已使用")

        uid = self.create_user(
            username, password, is_admin=True, must_change_password=False
        )
        # 一次性：关闭注册、作废 token
        self._set_setup_state("completed")
        self.db.execute("DELETE FROM meta WHERE key='setup_token_hash'")
        self.db.execute(
            "INSERT INTO login_attempts(username, at, ok, ip) VALUES(?,?,?,?)",
            (username, now(), 1, _as_str(ip)),
        )
        return self._issue_session(uid, _as_str(ip), _as_str(ua))

    def create_user(
        self,
        username: str,
        password: str,
        *,
        is_admin: bool = True,
        must_change_password: bool = False,
    ) -> int:
        t = now()
        cur = self.db.execute(
            "INSERT INTO users(username, password_hash, totp_enabled, is_admin,"
            " must_change_password, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                username,
                hash_password(password, self.pepper),
                0,
                1 if is_admin else 0,
                1 if must_change_password else 0,
                t,
                t,
            ),
        )
        return int(cur.lastrowid or 0)

    def _verify_password_any(self, password: str, stored: str) -> tuple[bool, str]:
        """返回 (ok, pepper_used)。legacy pepper 成功时便于登录后重哈希。"""
        if verify_password(password, stored, self.pepper):
            return True, self.pepper
        for p in self.legacy_peppers:
            if verify_password(password, stored, p):
                return True, p
        return False, ""

    def rehash_password(self, user_id: int, password: str) -> None:
        """登录成功后把口令哈希迁到当前 pepper。"""
        self.db.execute(
            "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
            (hash_password(password, self.pepper), now(), user_id),
        )

    def must_change_password(self, user_id: int) -> bool:
        row = self.db.query_one(
            "SELECT must_change_password FROM users WHERE id=?", (user_id,)
        )
        return bool(row and row["must_change_password"])

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
        ua: str = "",
    ) -> dict[str, Any]:
        """完整登录（兼容旧接口）：密码 + 可选 TOTP 一步完成。"""
        res = self.begin_login(username, password, ip=ip, ua=ua)
        if res.get("complete"):
            return res["session"]
        return self.complete_login(
            res["pending_id"], totp_code=totp_code, recovery_code=recovery_code, ip=ip, ua=ua
        )

    def begin_login(self, username: str, password: str, *, ip: str = "", ua: str = "") -> dict[str, Any]:
        """两阶段登录第一步：只验账号密码。

        - 密码错误 → 抛 AuthError，不进入第二阶段
        - 未启用 2FA → 直接发会话 {complete: True, session}
        - 已启用 2FA → {complete: False, need_totp: True, pending_id}
        """
        # A1: 非字符串入参不得区分用户是否存在，统一走失败路径
        username = _as_str(username)
        password = _as_str(password)
        ip = _as_str(ip)
        ua = _as_str(ua)
        if self._recent_failures(username) >= self.max_failed:
            raise AuthError("locked", "尝试过多，请稍后再试")

        row = self.db.query_one("SELECT * FROM users WHERE username=?", (username,))
        ok, used_pepper = (False, "")
        if row:
            ok, used_pepper = self._verify_password_any(password, row["password_hash"])
        if not row or not ok:
            self.db.execute(
                "INSERT INTO login_attempts(username, at, ok, ip) VALUES(?,?,?,?)",
                (username, now(), 0, ip),
            )
            raise AuthError("invalid", "用户名或密码错误")

        user_id = int(row["id"])
        # pepper 迁移：legacy 命中则登录后重哈希到当前 pepper
        if used_pepper and used_pepper != self.pepper:
            try:
                self.rehash_password(user_id, password)
            except Exception:
                pass
        if not row["totp_enabled"]:
            self.db.execute(
                "INSERT INTO login_attempts(username, at, ok, ip) VALUES(?,?,?,?)",
                (username, now(), 1, ip),
            )
            return {"complete": True, "session": self._issue_session(user_id, ip, ua)}

        # 2FA 账号：先发 pending，不建完整会话
        pending_id = "pend_" + pysecrets.token_urlsafe(24)
        self._pending_logins[pending_id] = {
            "user_id": user_id,
            "username": username,
            "password_hash": row["password_hash"],
            "ip": ip,
            "ua": ua,
            "at": now(),
            "failures": 0,
        }
        self._gc_pending()
        return {
            "complete": False,
            "need_totp": True,
            "pending_id": pending_id,
            "username": username,
        }

    def complete_login(
        self,
        pending_id: str,
        *,
        totp_code: str = "",
        recovery_code: str = "",
        ip: str = "",
        ua: str = "",
    ) -> dict[str, Any]:
        """两阶段登录第二步：TOTP / 恢复码通过后才建会话。"""
        self._gc_pending()
        pending_id = _as_str(pending_id)
        totp_code = _as_str(totp_code)
        recovery_code = _as_str(recovery_code)
        ip = _as_str(ip)
        ua = _as_str(ua)
        item = self._pending_logins.get(pending_id)
        if not item:
            raise AuthError("pending_expired", "登录已过期，请重新输入密码")
        if item.get("failures", 0) >= self.max_failed or self._recent_failures(item["username"]) >= self.max_failed:
            self._revoke_pending(int(item["user_id"]))
            raise AuthError("locked", "尝试过多，请稍后再试")
        row = self.db.query_one("SELECT * FROM users WHERE id=?", (item["user_id"],))
        if not row or not row["totp_enabled"] or row["password_hash"] != item.get("password_hash"):
            del self._pending_logins[pending_id]
            raise AuthError("invalid", "账号状态已变化，请重新登录")

        ok = False
        if recovery_code:
            ok = self._use_recovery_code(int(row["id"]), recovery_code)
        elif totp_code and totp_verify(
            decrypt_totp_secret(self._totp_key, row["totp_secret"]), totp_code
        ):
            ok = True

        self.db.execute(
            "INSERT INTO login_attempts(username, at, ok, ip) VALUES(?,?,?,?)",
            (item["username"], now(), 1 if ok else 0, ip or item.get("ip") or ""),
        )
        if not ok:
            item["failures"] = int(item.get("failures", 0)) + 1
            if item["failures"] >= self.max_failed or self._recent_failures(item["username"]) >= self.max_failed:
                self._revoke_pending(int(item["user_id"]))
                raise AuthError("locked", "尝试过多，请稍后再试")
            raise AuthError("totp_invalid", "动态码或恢复码错误")
        del self._pending_logins[pending_id]
        return self._issue_session(int(row["id"]), ip or item.get("ip") or "", ua or item.get("ua") or "")

    def _gc_pending(self) -> None:
        cutoff = now() - 300  # 5 分钟
        dead = [k for k, v in self._pending_logins.items() if v.get("at", 0) < cutoff]
        for k in dead:
            self._pending_logins.pop(k, None)

    def _revoke_pending(self, user_id: int) -> None:
        for pending_id, item in list(self._pending_logins.items()):
            if item.get("user_id") == user_id:
                self._pending_logins.pop(pending_id, None)

    def _use_recovery_code(self, user_id: int, code: str) -> bool:
        code = _as_str(code)
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
        # S23: 会话 token 使用高熵随机值（≥128bit），不用短 UUID
        sid = "sess_" + pysecrets.token_urlsafe(32)
        csrf = pysecrets.token_urlsafe(24)
        t = now()
        self.db.execute(
            "INSERT INTO web_sessions(id, user_id, csrf_token, created_at, expires_at, ip, ua)"
            " VALUES(?,?,?,?,?,?,?)",
            (sid, user_id, csrf, t, t + self.session_ttl, ip, ua),
        )
        return {"session_id": sid, "csrf_token": csrf, "expires_at": t + self.session_ttl}

    def get_session(self, session_id: str, *, ip: str = "", ua: str = "") -> dict[str, Any] | None:
        session_id = _as_str(session_id)
        if not session_id:
            return None
        row = self.db.query_one(
            "SELECT s.id AS session_id, s.csrf_token, s.expires_at, s.user_id, s.ip, s.ua,"
            " u.username, u.is_admin, u.must_change_password"
            " FROM web_sessions s JOIN users u ON u.id=s.user_id"
            " WHERE s.id=?",
            (session_id,),
        )
        if not row:
            return None
        if row["expires_at"] < now():
            self.db.execute("DELETE FROM web_sessions WHERE id=?", (session_id,))
            return None
        # A3/P2-12: 双因素同时变化才拒绝；仅 IP 变化（移动切网）允许
        sess_ip = (row["ip"] or "").strip()
        sess_ua = (row["ua"] or "").strip()
        ip = _as_str(ip).strip()
        ua = _as_str(ua).strip()
        ip_mismatch = bool(sess_ip and ip and sess_ip != ip)
        ua_mismatch = bool(sess_ua and ua and sess_ua != ua)
        if ip_mismatch and ua_mismatch:
            return None
        data = dict(row)
        data.pop("ip", None)
        data.pop("ua", None)
        return data

    def logout(self, session_id: str) -> None:
        self.db.execute("DELETE FROM web_sessions WHERE id=?", (session_id,))

    def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str,
        *,
        require_old: bool | None = None,
        keep_session_id: str | None = None,
    ) -> None:
        """修改密码。

        - 首次/强制改密（must_change_password=1）：不要求旧密码，仅校验新密码。
        - 普通主动改密：必须验证旧密码。
        - keep_session_id 非空时保留该会话（首登改密后继续使用），其余会话一律撤销。
        - 错误码与失败原因一一对应，禁止把「缺旧密/弱新密」混成同一条提示。
        """
        old_password = _as_str(old_password)
        new_password = _as_str(new_password)
        if not new_password:
            raise AuthError("weak_password", "请输入新密码")
        if len(new_password) < 10:
            raise AuthError(
                "weak_password", f"新密码至少 10 位（当前 {len(new_password)} 位）"
            )
        if old_password and new_password == old_password:
            raise AuthError("weak_password", "新密码不能与当前密码相同")

        row = self.db.query_one(
            "SELECT password_hash, must_change_password FROM users WHERE id=?",
            (user_id,),
        )
        if not row:
            raise AuthError("no_user", "用户不存在")

        must = bool(row["must_change_password"])
        # 首登/强制改密默认不验旧密；普通改密必须验。require_old 可显式覆盖。
        need_old = (not must) if require_old is None else bool(require_old)
        if need_old:
            if not old_password:
                raise AuthError("invalid", "请输入当前密码")
            ok, _ = self._verify_password_any(old_password, row["password_hash"])
            if not ok:
                raise AuthError("invalid", "当前密码错误")

        with self.db.tx() as conn:
            conn.execute(
                "UPDATE users SET password_hash=?, must_change_password=0, updated_at=? WHERE id=?",
                (hash_password(new_password, self.pepper), now(), user_id),
            )
            # 改密撤销旧会话；首登改密可保留当前会话以便继续使用
            if keep_session_id:
                conn.execute(
                    "DELETE FROM web_sessions WHERE user_id=? AND id<>?",
                    (user_id, keep_session_id),
                )
            else:
                conn.execute("DELETE FROM web_sessions WHERE user_id=?", (user_id,))
        self._revoke_pending(user_id)

    def reset_user_password(self, username: str = "admin") -> str:
        """服务器本地管理员恢复：重置口令并强制下次登录改密。

        仅限本机运维 CLI 使用，不暴露任何网络 API。返回一次性新口令。
        """
        username = _as_str(username)
        row = self.db.query_one("SELECT id FROM users WHERE username=?", (username,))
        if not row:
            raise AuthError("no_user", f"用户不存在: {username}")
        password = pysecrets.token_urlsafe(12)
        uid = int(row["id"])
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE users SET password_hash=?, must_change_password=1, updated_at=? WHERE id=?",
                (hash_password(password, self.pepper), now(), uid),
            )
            conn.execute("DELETE FROM web_sessions WHERE user_id=?", (uid,))
        self._revoke_pending(uid)
        return password

    def setup_totp(self, user_id: int, password: str = "", totp_code: str = "") -> dict[str, str]:
        """生成待确认 secret，不打断现有 2FA。

        若已启用 TOTP，必须提供密码 + 当前 OTP 才能进入更换流程。
        """
        row = self.db.query_one("SELECT * FROM users WHERE id=?", (user_id,))
        if not row:
            raise AuthError("no_user")
        password = _as_str(password)
        totp_code = _as_str(totp_code)
        if row["totp_enabled"]:
            if not password or not self._verify_password_any(password, row["password_hash"])[0]:
                raise AuthError("reauth_required", "更换 2FA 需要当前密码")
            if not totp_code or not totp_verify(decrypt_totp_secret(self._totp_key, row["totp_secret"]), totp_code):
                raise AuthError("reauth_required", "更换 2FA 需要当前动态码")
        secret = generate_totp_secret()
        # S11: 待确认 secret 加密存储
        enc_secret = encrypt_totp_secret(self._totp_key, secret)
        self.db.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"totp_pending:{user_id}", enc_secret),
        )
        username = row["username"]
        return {"secret": secret, "otpauth": otpauth_uri(username, secret)}

    def cancel_totp_setup(self, user_id: int) -> None:
        self.db.execute("DELETE FROM meta WHERE key=?", (f"totp_pending:{user_id}",))

    def confirm_totp(self, user_id: int, code: str, password: str = "") -> list[str]:
        """用待确认 secret 验证后才启用；之前保留原认证。"""
        code = _as_str(code)
        password = _as_str(password)
        row = self.db.query_one("SELECT * FROM users WHERE id=?", (user_id,))
        if not row:
            raise AuthError("no_user")
        pending = self.db.query_one(
            "SELECT value FROM meta WHERE key=?", (f"totp_pending:{user_id}",)
        )
        if not pending or not pending["value"]:
            raise AuthError("no_secret", "尚未初始化 TOTP")
        # S11: 解密 pending secret 再验证
        pending_secret = decrypt_totp_secret(self._totp_key, pending["value"])
        if not pending_secret:
            raise AuthError("no_secret", "TOTP secret 解密失败")
        if not totp_verify(pending_secret, code):
            raise AuthError("invalid_code", "动态验证码错误")
        if row["totp_enabled"] and password:
            # 更换流程需再次确认密码（setup 已验过，这里做一次最终确认）
            if not self._verify_password_any(password, row["password_hash"])[0]:
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
                (encrypt_totp_secret(self._totp_key, pending_secret), now(), user_id),
            )
            conn.execute("DELETE FROM meta WHERE key=?", (f"totp_pending:{user_id}",))
            # 更换认证因素：撤销该用户其它会话（保留当前由调用方决定）
            conn.execute("DELETE FROM web_sessions WHERE user_id=?", (user_id,))
        self._revoke_pending(user_id)
        return codes

    def disable_totp(self, user_id: int, password: str = "", totp_code: str = "") -> None:
        password = _as_str(password)
        totp_code = _as_str(totp_code)
        row = self.db.query_one("SELECT * FROM users WHERE id=?", (user_id,))
        if not row:
            raise AuthError("no_user")
        if not password or not self._verify_password_any(password, row["password_hash"])[0]:
            raise AuthError("reauth_required", "需要当前密码")
        if row["totp_enabled"]:
            if not totp_code or not totp_verify(decrypt_totp_secret(self._totp_key, row["totp_secret"]), totp_code):
                raise AuthError("reauth_required", "需要当前动态码")
        self.db.execute(
            "UPDATE users SET totp_enabled=0, totp_secret='', updated_at=? WHERE id=?",
            (now(), user_id),
        )
        self.db.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        self.db.execute("DELETE FROM meta WHERE key=?", (f"totp_pending:{user_id}",))
        self.db.execute("DELETE FROM web_sessions WHERE user_id=?", (user_id,))
        self._revoke_pending(user_id)

    def totp_enabled(self, username: str) -> bool:
        row = self.db.query_one(
            "SELECT totp_enabled, totp_secret FROM users WHERE username=?", (username,)
        )
        return bool(row and row["totp_enabled"] and row["totp_secret"])

    def verify_totp(self, username: str, code: str) -> bool:
        """验证某用户的 TOTP。调用方不得把 code 传给 LLM/日志。

        P1-06: 敏感操作 TOTP 与登录共用失败限额，并记录单码重放窗口。
        """
        username = _as_str(username)
        code = _as_str(code)
        if self._recent_failures(username) >= self.max_failed:
            raise AuthError("locked", "尝试过多，请稍后再试")
        row = self.db.query_one(
            "SELECT totp_enabled, totp_secret FROM users WHERE username=?", (username,)
        )
        if not row or not row["totp_enabled"] or not row["totp_secret"]:
            self._record_totp_attempt(username, ok=False)
            return False
        # S11: 解密后验证
        secret = decrypt_totp_secret(self._totp_key, row["totp_secret"])
        if not secret:
            self._record_totp_attempt(username, ok=False)
            return False
        # 防重放：同一用户 30s 内不得重复使用同一动态码
        code_key = f"totp_used:{username}:{code}"
        recent = self.db.query_one("SELECT value FROM meta WHERE key=?", (code_key,))
        if recent and recent["value"]:
            self._record_totp_attempt(username, ok=False)
            return False
        ok = totp_verify(secret, code)
        self._record_totp_attempt(username, ok=ok)
        if ok:
            try:
                self.db.execute(
                    "INSERT INTO meta(key, value) VALUES(?, ?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (code_key, str(int(now()))),
                )
            except Exception:
                pass
        return ok

    def _record_totp_attempt(self, username: str, *, ok: bool) -> None:
        try:
            self.db.execute(
                "INSERT INTO login_attempts(username, at, ok, ip) VALUES(?,?,?,?)",
                (username, now(), 1 if ok else 0, "totp-sensitive"),
            )
        except Exception:
            pass

    def cleanup(self) -> None:
        self.db.execute("DELETE FROM web_sessions WHERE expires_at<?", (now(),))
