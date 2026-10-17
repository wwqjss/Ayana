"""通知渠道注册与发送。

- 渠道：qq（NapCat）、wecom（群机器人 Webhook）、wecom_aibot（智能机器人·长连接）、webhook
- 凭据 AES-GCM 加密入库，API 不回显明文
- 发送失败不拖垮其他渠道（flush 按 outbox 行独立重试）
- **每个渠道必须有 CHANNEL_GUIDES 专属接入说明**（Web 配置页直接展示）
- 配置流：平台 → 接入方式 → 字段/说明
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any

from .db import Database, new_id, now
from .messagelog import platform_of_kind
from .transport import is_blocked_ssrf_host

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    AESGCM = None  # type: ignore


def _assert_safe_webhook_url(url: str) -> str:
    """B5: Webhook 目标禁止环回/链路本地/元数据等 SSRF 面。"""
    from urllib.parse import urlsplit

    u = (url or "").strip()
    try:
        parts = urlsplit(u)
    except ValueError as e:
        raise ChannelError("bad_url", "invalid url") from e
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ChannelError("bad_url", "webhook url must be http(s)")
    if parts.username or parts.password:
        raise ChannelError("bad_url", "webhook url must not contain userinfo")
    if is_blocked_ssrf_host(parts.hostname, allow_loopback=False, purpose="webhook"):
        raise ChannelError("bad_url", "webhook target host is not allowed")
    return u


def _assert_safe_ws_url(url: str) -> str:
    """B5: WebSocket 目标与 webhook 同级限制。"""
    from urllib.parse import urlsplit

    u = (url or "").strip()
    try:
        parts = urlsplit(u)
    except ValueError as e:
        raise ChannelError("bad_ws_url", "invalid url") from e
    if parts.scheme.lower() not in ("ws", "wss") or not parts.hostname:
        raise ChannelError("bad_ws_url", "ws_url must be ws(s)://")
    if parts.username or parts.password:
        raise ChannelError("bad_ws_url", "ws_url must not contain userinfo")
    if is_blocked_ssrf_host(parts.hostname, allow_loopback=False, purpose="webhook"):
        raise ChannelError("bad_ws_url", "ws target host is not allowed")
    return u

CHANNEL_KINDS = ("qq", "wecom", "wecom_aibot", "webhook")

_KIND_LABEL = {
    "qq": "QQ (NapCat)",
    "wecom": "企业微信 · 群机器人 Webhook",
    "wecom_aibot": "企业微信 · 智能机器人长连接",
    "webhook": "Webhook",
}

# 平台 → 可选接入方式（kind）
PLATFORMS: list[dict[str, Any]] = [
    {
        "id": "qq",
        "label": "QQ",
        "methods": [{"kind": "qq", "label": "NapCat / OneBot 反向 WS"}],
    },
    {
        "id": "wecom",
        "label": "企业微信",
        "methods": [
            {"kind": "wecom", "label": "群机器人 Webhook 推送"},
            {"kind": "wecom_aibot", "label": "智能机器人 · 长连接"},
        ],
    },
    {
        "id": "webhook",
        "label": "通用 Webhook",
        "methods": [{"kind": "webhook", "label": "HTTP POST"}],
    },
]

# Web 配置页展示的渠道专属接入说明。
# 新增渠道时：必须在此登记，否则 create() 拒绝。
CHANNEL_GUIDES: dict[str, dict[str, Any]] = {
    "qq": {
        "title": "QQ（NapCat）接入说明",
        "summary": "通过 NapCat 的 OneBot v11 反向 WebSocket 把告警发到 QQ 好友或群。",
        "steps": [
            "在服务器上安装并启动 NapCat（QQ 机器人客户端），登录接收告警的 QQ 号。",
            "在 NapCat 中开启 OneBot v11 反向 WebSocket，指向 Ayana 的 WS 地址（默认 ws://主机:6199/ws）。",
            "在 NapCat 的鉴权里填入 Ayana 的 onewbot_token（见 secrets.json，两端必须一致）。",
            "确认 Ayana 日志出现「ws connected」，表示 NapCat 已连上。",
            "在下方填写目标：私聊用 user:QQ号，群聊用 group:群号，然后保存渠道。",
            "点击「发送测试消息」，在对应 QQ 会话中确认收到。",
        ],
        "notes": [
            "目标格式必须是 user:123456 或 group:123456；填纯数字会被当作私聊。",
            "该渠道依赖 NapCat 在线；NapCat 断线时消息会进 outbox 重试，恢复后自动补发。",
            "不要把 onewbot_token 写进聊天记录或截图；泄露后任何人可冒充机器人发消息。",
            "QQ 对机器人有频率限制，短时间大量发送可能被限制或掉线。",
        ],
        "docs": [
            {"title": "NapCat 文档", "url": "https://napneko.github.io/"},
            {"title": "OneBot v11 标准", "url": "https://github.com/botuniverse/onebot-11"},
        ],
    },
    "wecom": {
        "title": "企业微信 · 群机器人 Webhook 接入说明",
        "summary": "通过企业微信群机器人 Webhook，把告警推送到指定群。适合「只发不收」的告警通知。",
        "steps": [
            "打开企业微信，进入需要接收告警的群聊。",
            "在群聊管理中添加群机器人。",
            "创建机器人并复制 Webhook 地址。",
            "将 Webhook 地址填入 Ayana，保存渠道。",
            "点击「发送测试消息」，确认群内收到通知。",
        ],
        "notes": [
            "该渠道只能向对应的企业微信群发送消息，无法私聊个人或其他群。",
            "Webhook 地址属于敏感凭据，不要泄露；泄露后任何人都能向该群发消息。Ayana 会加密保存，界面不回显明文。",
            "机器人发送存在频率限制（通常每机器人每分钟约 20 条），超限会被拒绝；失败会进 outbox 按退避重试。",
            "删除群机器人后 Webhook 立即失效，需在 Ayana 更新地址或停用该渠道。",
            "与「智能机器人 · 长连接」不是同一种接入方式，不可混用同一套参数。",
        ],
        "docs": [
            {
                "title": "企业微信群机器人配置说明（官方）",
                "url": "https://developer.work.weixin.qq.com/document/path/91770",
            },
        ],
    },
    "wecom_aibot": {
        "title": "企业微信 · 智能机器人长连接接入说明",
        "summary": (
            "通过企业微信「智能机器人」WebSocket 长连接推送告警，并可接收用户命令。"
            "无需公网域名；一个机器人只保持一条连接，可配置多个推送目标。"
        ),
        "steps": [
            "登录企业微信管理后台 → 安全与管理 → 管理工具 → 智能机器人，创建机器人。",
            "进入机器人详情 → 编辑 → 选择「API 模式」→「使用长连接」。",
            "复制生成的 Bot ID 和 Secret（Secret 仅本模式有效，勿与 URL 回调的 Token/AESKey 混淆）。",
            "在 Ayana 填写名称、Bot ID、Secret 后保存（推送目标可先留空，连接成功后再选）。",
            "等待连接状态变为「已认证」；在需要告警的群里 @机器人 发一条消息，该群会出现在「已发现的推送目标」。",
            "在「已发现的推送目标」勾选要推送的会话并保存，或手动填写 chatid/userid；然后点「发送测试消息」。",
        ],
        "notes": [
            "一个机器人同一时间只能保持一条有效长连接；切换到「URL 回调」会使长连接失效。",
            "主动推送目标：单聊填成员 userid，群聊填群 chatid；机器人须在该会话中。",
            "连接成功后，在企业微信群内 @机器人 发送任意消息，即可发现该群的 chatid，无需手动查找。",
            "推送目标可以为空保存；没有目标时事件通知不会发到企微，但不影响其他渠道。",
            "markdown 正文官方上限约 20480 字节，超长会被截断。",
            "Bot ID / Secret 属敏感凭据，加密保存且不明文回显；Secret 可在企微后台刷新，旧值立即失效。",
            "发送回执超时或断线时结果可能不确定，Ayana 不会盲目重发，避免重复推送；可在 outbox 手动重试。",
            "「URL 回调」方式需公网 HTTPS，与主动告警能力不同，当前版本不提供。",
            "用户命令权限走 Ayana Policy（主体 wecom_user），默认拒绝，需在「权限」页授权后才能调查/批准。",
        ],
        "docs": [
            {
                "title": "智能机器人长连接（官方）",
                "url": "https://developer.work.weixin.qq.com/document/path/101463",
            },
            {
                "title": "接收消息（官方）",
                "url": "https://developer.work.weixin.qq.com/document/path/100719",
            },
            {
                "title": "官方 Node.js SDK（协议参照）",
                "url": "https://github.com/WecomTeam/aibot-node-sdk",
            },
        ],
    },
    "webhook": {
        "title": "通用 Webhook 接入说明",
        "summary": "向任意 HTTP(S) 端点 POST 告警文本，适合自建系统、其它 IM、工单等。",
        "steps": [
            "在接收方准备一个 HTTP(S) 接口，能够接收 POST 请求。",
            "在 Ayana 填入该接口的完整 URL，选择 POST 或 PUT。",
            "如接收方需要鉴权，填入 Token（将作为 Bearer 发送）或自定义请求头 JSON。",
            "保存渠道后点击「发送测试消息」，在接收方确认收到。",
        ],
        "notes": [
            "默认 JSON 体为 {\"text\": \"消息内容\"}；可用模板自定义，占位符 {body} 为消息文本。",
            "URL、Token、含 Authorization 的请求头均属敏感凭据，加密保存且不在界面回显。",
            "目标可达性取决于 Ayana 所在主机的出网策略与对端防火墙。",
            "对方接口超时或返回非 2xx 会记为失败并独立重试，不影响其他渠道。",
        ],
        "docs": [],
    },
}


class ChannelError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.detail = message
        super().__init__(f"{code}: {message}" if message else code)


def _derive_key(master: str) -> bytes:
    if not master:
        raise ChannelError("missing_key", "notify_channel_key required")
    if AESGCM is None:
        raise ChannelError("crypto_unavailable", "cryptography not installed")
    import hashlib

    return hashlib.sha256(master.encode("utf-8")).digest()


def encrypt_secret(master: str, plaintext: str) -> bytes:
    key = _derive_key(master)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)


def decrypt_secret(master: str, blob: bytes) -> str:
    key = _derive_key(master)
    if not blob or len(blob) < 13:
        raise ChannelError("bad_blob", "ciphertext too short")
    nonce, ct = bytes(blob[:12]), bytes(blob[12:])
    try:
        return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
    except Exception as e:
        raise ChannelError("decrypt_failed", str(e)) from e


def _mask_webhook_url(url: str) -> str:
    """展示用：保留主机路径，遮蔽 key=... 等敏感段。"""
    u = (url or "").strip()
    if not u:
        return ""
    u = re.sub(r"(key=)[^&\s]+", r"\1****", u, flags=re.I)
    u = re.sub(r"(token=)[^&\s]+", r"\1****", u, flags=re.I)
    if len(u) > 80:
        u = u[:77] + "..."
    return u


def _public_config(kind: str, config: dict) -> dict:
    """配置里允许回显的字段（非敏感）。"""
    out: dict[str, Any] = {}
    if kind == "qq":
        out["target"] = str(config.get("target") or "")
    elif kind == "wecom":
        # 企业微信 URL 含 key，只回显脱敏地址
        out["webhook_masked"] = _mask_webhook_url(str(config.get("webhook_masked") or config.get("url") or ""))
    elif kind == "wecom_aibot":
        out["bot_id_masked"] = _mask_bot_id(str(config.get("bot_id_masked") or config.get("bot_id") or ""))
        out["targets"] = [str(t) for t in (config.get("targets") or []) if str(t).strip()]
        out["ws_url"] = str(config.get("ws_url") or "")
    elif kind == "webhook":
        out["url"] = str(config.get("url") or "")
        out["method"] = str(config.get("method") or "POST").upper()
        out["content_type"] = str(config.get("content_type") or "application/json")
        out["template"] = str(config.get("template") or "")  # {body} 占位
        headers = config.get("headers") or {}
        if isinstance(headers, dict):
            # 只保留非敏感头名；值不含密钥类字段
            safe = {}
            for k, v in headers.items():
                lk = str(k).lower()
                if lk in ("authorization", "x-api-key", "token", "secret", "password"):
                    continue
                safe[str(k)] = str(v)
            out["headers"] = safe
    return out


def _mask_bot_id(bot_id: str) -> str:
    b = (bot_id or "").strip()
    if not b:
        return ""
    if len(b) <= 6:
        return b[:2] + "****"
    return b[:4] + "****" + b[-2:]


def _normalize_targets(raw: Any) -> list[str]:
    if isinstance(raw, str):
        raw = [x.strip() for x in re.split(r"[\s,;，；]+", raw) if x.strip()]
    if not isinstance(raw, (list, tuple)):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for t in raw:
        s = str(t or "").strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _channel_health(kind: str, cfg: dict, meta: dict) -> dict[str, Any]:
    """连接/配置健康，与 enabled 开关无关。"""
    cfg = cfg or {}
    label, level = "未检测", "unknown"
    if kind == "qq":
        target = str(cfg.get("target") or "").strip()
        if not target:
            label, level = "未配置目标", "bad"
        elif meta.get("last_test_at"):
            label = "测试通过" if meta.get("last_test_ok") else "测试失败"
            level = "ok" if meta.get("last_test_ok") else "bad"
        else:
            label, level = "需 NapCat 在线", "warn"
    elif kind in ("wecom", "webhook"):
        if meta.get("last_test_at"):
            label = "测试通过" if meta.get("last_test_ok") else "测试失败"
            level = "ok" if meta.get("last_test_ok") else "bad"
        else:
            label, level = "未测试", "warn"
    elif kind == "wecom_aibot":
        tgts = cfg.get("targets") or []
        if meta.get("last_test_at"):
            label = "测试通过" if meta.get("last_test_ok") else "测试失败"
            level = "ok" if meta.get("last_test_ok") else "bad"
        elif not tgts:
            label, level = "推送目标未配置", "warn"
        else:
            label, level = "未测试", "warn"
    return {"label": label, "level": level}


def _normalize(kind: str, config: dict) -> dict:
    if kind == "qq":
        target = str((config or {}).get("target") or "").strip()
        return {"target": target}
    if kind == "wecom":
        # 企业微信群机器人：URL 含 key，归入 secret；config 只存脱敏预览
        url = str((config or {}).get("url") or (config or {}).get("webhook_url") or "").strip()
        if url and not url.startswith(("http://", "https://")):
            raise ChannelError("bad_url", "wecom webhook must be http(s)")
        if url:
            url = _assert_safe_webhook_url(url)
        return {"webhook_masked": _mask_webhook_url(url)}
    if kind == "wecom_aibot":
        bot_id = str((config or {}).get("bot_id") or (config or {}).get("bot_id_masked") or "").strip()
        targets = _normalize_targets((config or {}).get("targets") or (config or {}).get("target"))
        ws_url = str((config or {}).get("ws_url") or "").strip()
        if ws_url and not ws_url.startswith(("ws://", "wss://")):
            raise ChannelError("bad_ws_url", "ws_url must be ws(s)://")
        if ws_url:
            ws_url = _assert_safe_ws_url(ws_url)
        return {
            "bot_id_masked": _mask_bot_id(bot_id),
            "targets": targets,
            "ws_url": ws_url,
        }
    if kind == "webhook":
        url = str((config or {}).get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            raise ChannelError("bad_url", "webhook url must be http(s)")
        url = _assert_safe_webhook_url(url)
        method = str((config or {}).get("method") or "POST").upper()
        if method not in ("POST", "PUT"):
            raise ChannelError("bad_method", method)
        headers = {}
        raw_h = (config or {}).get("headers") or {}
        if isinstance(raw_h, dict):
            for k, v in raw_h.items():
                headers[str(k)] = str(v)
        return {
            "url": url,
            "method": method,
            "content_type": str((config or {}).get("content_type") or "application/json"),
            "template": str((config or {}).get("template") or ""),
            "headers": headers,
        }
    raise ChannelError("bad_kind", kind)


def _normalize_secret(kind: str, secret: dict | None, config: dict | None = None) -> dict:
    secret = secret or {}
    out: dict[str, Any] = {}
    if kind == "wecom_aibot":
        bot_id = str(secret.get("bot_id") or "").strip()
        if not bot_id and config:
            bot_id = str(config.get("bot_id") or "").strip()
        sec = str(secret.get("secret") or secret.get("bot_secret") or "").strip()
        if bot_id:
            out["bot_id"] = bot_id
        if sec:
            out["secret"] = sec
    elif kind == "wecom":
        url = str(secret.get("webhook_url") or secret.get("url") or "").strip()
        if not url and config:
            # 兼容：只在创建时把完整 URL 从 config 提到 secret
            url = str(config.get("url") or config.get("webhook_url") or "").strip()
        if url:
            if not url.startswith(("http://", "https://")):
                raise ChannelError("bad_url", "wecom webhook must be http(s)")
            url = _assert_safe_webhook_url(url)
            out["webhook_url"] = url
    elif kind == "webhook":
        # 敏感头 / token 整段加密
        sens_headers = {}
        raw_h = secret.get("headers") or {}
        if isinstance(raw_h, dict):
            for k, v in raw_h.items():
                if str(v):
                    sens_headers[str(k)] = str(v)
        if sens_headers:
            out["headers"] = sens_headers
        tok = str(secret.get("token") or "").strip()
        if tok:
            out["token"] = tok
    elif kind == "qq":
        # QQ 无本地密钥；保留扩展位
        pass
    return out


def list_channel_kinds() -> list[dict[str, Any]]:
    """渠道类型 + Web 接入说明（配置页必须展示；新渠道缺指南则不可用）。"""
    out = []
    for kind in CHANNEL_KINDS:
        guide = CHANNEL_GUIDES.get(kind)
        if not guide:
            continue
        platform = ""
        for p in PLATFORMS:
            if any(m["kind"] == kind for m in p.get("methods") or []):
                platform = p["id"]
                break
        out.append(
            {
                "kind": kind,
                "platform": platform,
                "label": _KIND_LABEL.get(kind, kind),
                "title": guide.get("title") or _KIND_LABEL.get(kind, kind),
                "summary": guide.get("summary") or "",
                "steps": list(guide.get("steps") or []),
                "notes": list(guide.get("notes") or []),
                "docs": list(guide.get("docs") or []),
            }
        )
    return out


def list_platforms() -> list[dict[str, Any]]:
    """配置流第一步：消息平台；每平台含接入方式列表。"""
    return json.loads(json.dumps(PLATFORMS, ensure_ascii=False))


class ChannelStore:
    def __init__(self, db: Database, master_key: str = "", qq_sender=None):
        self.db = db
        self.master_key = master_key or os.environ.get("AYANA_NOTIFY_CHANNEL_KEY", "")
        self._qq_sender = qq_sender  # async (target, body) -> bool
        self._aibot_manager = None  # WeComAibotManager | None
        self._mlog = None  # MessageLog | None

    def set_qq_sender(self, sender) -> None:
        self._qq_sender = sender

    def set_aibot_manager(self, manager) -> None:
        self._aibot_manager = manager

    def set_mlog(self, mlog) -> None:
        self._mlog = mlog

    # ---- 已发现推送目标（群 chatid / 单聊 userid）----

    def record_seen_target(
        self,
        channel_id: str,
        *,
        target_id: str,
        chattype: str = "",
        userid: str = "",
        msgtype: str = "",
    ) -> None:
        """收消息时登记会话目标，供 Web 勾选作为推送目标。幂等更新 last_seen。"""
        tid = str(target_id or "").strip()
        if not tid or not channel_id:
            return
        t = now()
        try:
            self.db.execute(
                "INSERT INTO aibot_seen_targets(channel_id, target_id, chattype, userid,"
                " first_seen_at, last_seen_at, last_msgtype)"
                " VALUES(?,?,?,?,?,?,?)"
                " ON CONFLICT(channel_id, target_id) DO UPDATE SET"
                " last_seen_at=excluded.last_seen_at,"
                " last_msgtype=excluded.last_msgtype,"
                " userid=CASE WHEN excluded.userid!='' THEN excluded.userid ELSE userid END,"
                " chattype=CASE WHEN excluded.chattype!='' THEN excluded.chattype ELSE chattype END",
                (
                    channel_id,
                    tid,
                    str(chattype or ""),
                    str(userid or ""),
                    t,
                    t,
                    str(msgtype or ""),
                ),
            )
        except Exception:
            pass

    def list_seen_targets(self, channel_id: str) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT target_id, chattype, userid, first_seen_at, last_seen_at, last_msgtype"
            " FROM aibot_seen_targets WHERE channel_id=?"
            " ORDER BY last_seen_at DESC LIMIT 100",
            (channel_id,),
        )
        out = []
        for r in rows:
            d = dict(r)
            d["kind_label"] = "群聊" if d.get("chattype") == "group" else (
                "单聊" if d.get("chattype") == "single" else (d.get("chattype") or "会话")
            )
            out.append(d)
        return out

    def set_targets(self, channel_id: str, targets: list[str], actor: str = "web") -> dict[str, Any]:
        """保存/更新推送目标列表（手动填写 + 从发现列表勾选共用）。"""
        row = self.get_raw(channel_id)
        if not row:
            raise ChannelError("not_found", channel_id)
        kind = row["kind"]
        if kind != "wecom_aibot":
            raise ChannelError("bad_kind", f"{kind} has no multi-target config")
        try:
            cfg = json.loads(row["config_json"] or "{}")
        except Exception:
            cfg = {}
        cfg["targets"] = _normalize_targets(targets)
        with self.db.tx() as conn:
            conn.execute(
                "UPDATE notify_channels SET config_json=?, updated_at=? WHERE id=?",
                (json.dumps(cfg, ensure_ascii=False), now(), channel_id),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json, channel)"
                " VALUES(?,?,?,?,?,?)",
                (
                    now(),
                    "web_user",
                    actor,
                    "notify_channel_targets_updated",
                    json.dumps(
                        {"id": channel_id, "targets": cfg["targets"]}, ensure_ascii=False
                    ),
                    "web",
                ),
            )
        return self.get_meta(channel_id) or {"id": channel_id}

    def _require_key(self) -> str:
        if not self.master_key:
            raise ChannelError("missing_key", "notify_channel_key required")
        return self.master_key

    def ensure_default_qq(self, admin_target: str = "") -> None:
        """已废弃：全新安装不再自动创建 QQ 渠道。

        保留方法以免外部调用报错；始终不写入。老实例已有渠道不受影响。
        """
        return

    def list_meta(self) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT id, name, kind, enabled, config_json, created_at, updated_at,"
            " last_test_at, last_test_ok, last_test_error"
            " FROM notify_channels ORDER BY created_at ASC"
        )
        out = []
        for r in rows:
            d = dict(r)
            try:
                cfg = json.loads(d.pop("config_json") or "{}")
            except Exception:
                cfg = {}
            kind = d.get("kind") or ""
            d["config"] = _public_config(kind, cfg)
            d["kind_label"] = _KIND_LABEL.get(kind, kind)
            d["has_secret"] = self._has_secret(d["id"])
            # 启用状态与连接/配置健康分离：health 仅描述能否真正送出
            d["health"] = _channel_health(kind, cfg, d)
            out.append(d)
        return out

    def _has_secret(self, channel_id: str) -> bool:
        row = self.db.query_one(
            "SELECT secret_enc FROM notify_channels WHERE id=?", (channel_id,)
        )
        if not row:
            return False
        blob = bytes(row["secret_enc"] or b"")
        return len(blob) > 13

    def get_meta(self, channel_id: str) -> dict[str, Any] | None:
        for m in self.list_meta():
            if m["id"] == channel_id:
                return m
        return None

    def get_raw(self, channel_id: str) -> dict[str, Any] | None:
        row = self.db.query_one("SELECT * FROM notify_channels WHERE id=?", (channel_id,))
        return dict(row) if row else None

    def list_enabled(self) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT id, name, kind, config_json, created_at, updated_at FROM notify_channels WHERE enabled=1"
            " ORDER BY created_at ASC"
        )
        out = []
        for r in rows:
            try:
                cfg = json.loads(r["config_json"] or "{}")
            except Exception:
                cfg = {}
            kind = r["kind"] or ""
            targets = _normalize_targets(cfg.get("targets") or cfg.get("target"))
            if not targets:
                one = cfg.get("target") or cfg.get("url") or cfg.get("webhook_masked") or ""
                if one:
                    targets = [str(one)]
            out.append(
                {
                    "id": r["id"],
                    "name": r["name"],
                    "kind": kind,
                    "config": cfg,
                    "target": targets[0] if targets else "",
                    "targets": targets,
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
            )
        return out

    def create(
        self,
        *,
        name: str,
        kind: str,
        config: dict | None = None,
        secret: dict | None = None,
        enabled: bool = True,
        actor: str = "web",
    ) -> dict[str, Any]:
        if kind not in CHANNEL_KINDS:
            raise ChannelError("bad_kind", kind)
        if kind not in CHANNEL_GUIDES:
            raise ChannelError("missing_guide", f"channel kind {kind} has no Web setup guide")
        if not str(name or "").strip():
            raise ChannelError("empty_name")
        cfg = _normalize(kind, config or {})
        sec = _normalize_secret(kind, secret, config or {})
        if kind == "wecom" and not sec.get("webhook_url"):
            raise ChannelError("missing_webhook_url", "企业微信 Webhook 地址必填")
        if kind == "wecom" and sec.get("webhook_url"):
            cfg["webhook_masked"] = _mask_webhook_url(sec["webhook_url"])
        if kind == "wecom_aibot":
            if not sec.get("bot_id") or not sec.get("secret"):
                raise ChannelError("missing_aibot_creds", "智能机器人 Bot ID 与 Secret 必填")
            # 推送目标可为空：连接后可从群消息自动发现 chatid/userid
            cfg["bot_id_masked"] = _mask_bot_id(sec["bot_id"])
        cid = new_id("nch")
        t = now()
        enc = b""
        if sec:
            enc = encrypt_secret(self._require_key(), json.dumps(sec, ensure_ascii=False))
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO notify_channels(id, name, kind, enabled, config_json, secret_enc,"
                " created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    cid,
                    str(name).strip(),
                    kind,
                    1 if enabled else 0,
                    json.dumps(cfg, ensure_ascii=False),
                    enc,
                    t,
                    t,
                ),
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json, channel)"
                " VALUES(?,?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor,
                    "notify_channel_created",
                    json.dumps({"id": cid, "name": name, "kind": kind}, ensure_ascii=False),
                    "web",
                ),
            )
        return self.get_meta(cid) or {"id": cid}

    def update(
        self,
        channel_id: str,
        *,
        name: str | None = None,
        config: dict | None = None,
        secret: dict | None = None,
        clear_secret: bool = False,
        enabled: bool | None = None,
        actor: str = "web",
    ) -> dict[str, Any]:
        row = self.get_raw(channel_id)
        if not row:
            raise ChannelError("not_found", channel_id)
        kind = row["kind"]
        try:
            old_cfg = json.loads(row["config_json"] or "{}")
        except Exception:
            old_cfg = {}
        cfg = _normalize(kind, config) if config is not None else old_cfg
        t = now()
        sets = ["updated_at=?"]
        params: list[Any] = [t]
        if name is not None and str(name).strip():
            sets.append("name=?")
            params.append(str(name).strip())
        if enabled is not None:
            sets.append("enabled=?")
            params.append(1 if enabled else 0)
        touch_secret = secret is not None or (
            kind == "wecom" and config and (config.get("url") or config.get("webhook_url"))
        )
        if clear_secret:
            sets.append("secret_enc=?")
            params.append(b"")
            if kind == "wecom":
                cfg["webhook_masked"] = ""
        elif touch_secret:
            sec = _normalize_secret(kind, secret or {}, config or {})
            if kind == "wecom" and sec.get("webhook_url"):
                cfg["webhook_masked"] = _mask_webhook_url(sec["webhook_url"])
            enc = (
                encrypt_secret(self._require_key(), json.dumps(sec, ensure_ascii=False))
                if sec
                else b""
            )
            sets.append("secret_enc=?")
            params.append(enc)
        sets.append("config_json=?")
        params.append(json.dumps(cfg, ensure_ascii=False))
        params.append(channel_id)
        with self.db.tx() as conn:
            conn.execute(
                f"UPDATE notify_channels SET {', '.join(sets)} WHERE id=?", tuple(params)
            )
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json, channel)"
                " VALUES(?,?,?,?,?,?)",
                (
                    t,
                    "web_user",
                    actor,
                    "notify_channel_updated",
                    json.dumps(
                        {
                            "id": channel_id,
                            "name": name,
                            "enabled": enabled,
                            "secret_touched": bool(secret is not None or clear_secret),
                        },
                        ensure_ascii=False,
                    ),
                    "web",
                ),
            )
        return self.get_meta(channel_id) or {"id": channel_id}

    def set_enabled(self, channel_id: str, enabled: bool, actor: str = "web") -> dict[str, Any]:
        return self.update(channel_id, enabled=enabled, actor=actor)

    def delete(self, channel_id: str, actor: str = "web") -> None:
        row = self.get_raw(channel_id)
        if not row:
            raise ChannelError("not_found", channel_id)
        with self.db.tx() as conn:
            conn.execute("DELETE FROM notify_channels WHERE id=?", (channel_id,))
            conn.execute(
                "INSERT INTO audit_log(at, actor_type, actor_id, entry, detail_json, channel)"
                " VALUES(?,?,?,?,?,?)",
                (
                    now(),
                    "web_user",
                    actor,
                    "notify_channel_deleted",
                    json.dumps({"id": channel_id, "kind": row["kind"]}, ensure_ascii=False),
                    "web",
                ),
            )

    def reveal_for_send(self, channel_id: str) -> dict[str, Any]:
        """仅发送路径。调用方不得写入日志/浏览器/LLM。"""
        row = self.get_raw(channel_id)
        if not row:
            raise ChannelError("not_found", channel_id)
        try:
            cfg = json.loads(row["config_json"] or "{}")
        except Exception:
            cfg = {}
        sec: dict[str, Any] = {}
        blob = bytes(row["secret_enc"] or b"")
        if len(blob) > 13:
            try:
                sec = json.loads(decrypt_secret(self._require_key(), blob))
            except ChannelError:
                raise
            except Exception as e:
                raise ChannelError("decrypt_failed", str(e)) from e
        return {
            "id": row["id"],
            "name": row["name"],
            "kind": row["kind"],
            "enabled": bool(row["enabled"]),
            "config": cfg,
            "secret": sec,
        }

    async def send(self, channel_id: str, body: str, target: str = "") -> tuple[bool, str]:
        try:
            ch = self.reveal_for_send(channel_id)
        except ChannelError as e:
            return False, str(e)
        if not ch.get("enabled"):
            return False, "channel_disabled"
        kind = ch["kind"]
        cfg = ch["config"]
        sec = ch["secret"]
        try:
            if kind == "qq":
                tgt = target or str(cfg.get("target") or "")
                return await self._send_qq({"target": tgt}, body)
            if kind == "wecom":
                return await self._send_wecom(sec, body)
            if kind == "wecom_aibot":
                return await self._send_wecom_aibot(channel_id, sec, body, target)
            if kind == "webhook":
                return await self._send_webhook(cfg, sec, body)
            return False, f"unknown_kind:{kind}"
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return False, str(e)[:200]
        finally:
            # 明文不驻留
            if isinstance(sec, dict):
                sec.clear()

    async def _send_qq(self, cfg: dict, body: str) -> tuple[bool, str]:
        if not self._qq_sender:
            return False, "qq_sender_unavailable"
        target = str(cfg.get("target") or "").strip()
        if not target:
            return False, "missing_target"
        ok = await self._qq_sender(target, body)
        return (True, "") if ok else (False, "qq_send_failed")

    async def _send_wecom_aibot(
        self, channel_id: str, sec: dict, body: str, target: str
    ) -> tuple[bool, str]:
        """智能机器人长连接主动推送。target 为 userid 或群 chatid。"""
        if not self._aibot_manager:
            return False, "unknown:aibot_manager_unavailable"
        chatid = str(target or "").strip()
        if not chatid:
            return False, "missing_target"
        bot_id = str(sec.get("bot_id") or "")
        secret = str(sec.get("secret") or "")
        if not bot_id or not secret:
            return False, "missing_aibot_creds"
        ws_url = ""
        try:
            raw = self.get_raw(channel_id) or {}
            cfg = json.loads(raw.get("config_json") or "{}")
            ws_url = str(cfg.get("ws_url") or "")
        except Exception:
            ws_url = ""
        try:
            await self._aibot_manager.ensure(
                channel_id, bot_id=bot_id, secret=secret, ws_url=ws_url
            )
        except Exception as e:
            return False, f"unknown:ensure_failed:{str(e)[:80]}"
        return await self._aibot_manager.send_text(channel_id, chatid, body)

    async def _send_wecom(self, sec: dict, body: str) -> tuple[bool, str]:
        """企业微信群机器人：POST {"msgtype":"text","text":{"content":"..."}}。"""
        import aiohttp

        url = str(sec.get("webhook_url") or "").strip()
        if not url:
            return False, "missing_webhook_url"
        try:
            url = _assert_safe_webhook_url(url)
        except ChannelError as e:
            return False, f"bad_url:{e}"
        payload = json.dumps(
            {"msgtype": "text", "text": {"content": body}}, ensure_ascii=False
        ).encode("utf-8")
        timeout = aiohttp.ClientTimeout(total=12)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url, data=payload, headers={"Content-Type": "application/json"},
                allow_redirects=False,
            ) as resp:
                txt = await resp.text()
                if resp.status != 200:
                    return False, f"http_{resp.status}:{txt[:120]}"
                try:
                    data = json.loads(txt)
                except Exception:
                    return False, f"bad_response:{txt[:80]}"
                # 企业微信固定 200 + errcode
                errcode = int(data.get("errcode") or 0)
                if errcode != 0:
                    return False, f"wecom_{errcode}:{str(data.get('errmsg') or '')[:80]}"
                return True, ""

    async def _send_webhook(self, cfg: dict, sec: dict, body: str) -> tuple[bool, str]:
        import aiohttp

        url = str(cfg.get("url") or "").strip()
        if not url:
            return False, "missing_url"
        try:
            url = _assert_safe_webhook_url(url)
        except ChannelError as e:
            return False, f"bad_url:{e}"
        headers: dict[str, str] = {}
        for k, v in (cfg.get("headers") or {}).items():
            headers[str(k)] = str(v)
        for k, v in (sec.get("headers") or {}).items():
            headers[str(k)] = str(v)
        token = str(sec.get("token") or "")
        if token and "Authorization" not in {k.title(): k for k in headers}:
            headers["Authorization"] = f"Bearer {token}"
        content_type = str(cfg.get("content_type") or "application/json")
        template = str(cfg.get("template") or "")
        method = str(cfg.get("method") or "POST").upper()
        if content_type == "application/json":
            headers.setdefault("Content-Type", "application/json")
            if template:
                # 模板中 {body} 替换为 JSON 字符串
                payload_txt = template.replace("{body}", json.dumps(body, ensure_ascii=False))
                try:
                    data: Any = json.loads(payload_txt)
                except Exception:
                    data = {"text": body}
            else:
                data = {"text": body}
            body_arg: Any = json.dumps(data, ensure_ascii=False).encode("utf-8")
        else:
            headers.setdefault("Content-Type", content_type)
            text = template.replace("{body}", body) if template else body
            body_arg = text.encode("utf-8")
        timeout = aiohttp.ClientTimeout(total=12)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(method, url, data=body_arg, headers=headers, allow_redirects=False) as resp:
                txt = await resp.text()
                if 200 <= resp.status < 300:
                    return True, ""
                return False, f"http_{resp.status}:{txt[:120]}"

    async def test(self, channel_id: str, actor: str = "web", target: str = "") -> dict[str, Any]:
        meta = self.get_meta(channel_id)
        name = (meta or {}).get("name") or channel_id
        body = f"[Ayana] 通道测试：{name}"
        kind = (meta or {}).get("kind") or ""
        cfg = (meta or {}).get("config") or {}
        targets = _normalize_targets(cfg.get("targets") or cfg.get("target"))
        if target:
            targets = [target]
        # 长连接：无目标时给出可操作提示，不发空 target
        if kind == "wecom_aibot" and not targets:
            seen = self.list_seen_targets(channel_id)
            hint = "未配置推送目标"
            if seen:
                hint += f"；可点「推送目标」从已发现的 {len(seen)} 个会话中勾选"
            else:
                hint += "；请先在企业微信群 @机器人 发消息以发现会话，或手动填写 chatid/userid"
            self.db.execute(
                "UPDATE notify_channels SET last_test_at=?, last_test_ok=?, last_test_error=?"
                " WHERE id=?",
                (now(), 0, hint[:200], channel_id),
            )
            self.db.audit(
                "web_user",
                actor,
                "notify_channel_test",
                detail={"id": channel_id, "ok": False, "error": "no_targets"},
            )
            return {
                "ok": False,
                "error": hint,
                "id": channel_id,
                "results": [],
                "need_targets": True,
                "seen_count": len(seen),
            }
        if not targets:
            targets = [""]
        results: list[dict[str, Any]] = []
        all_ok = True
        for tgt in targets:
            ok, err = await self.send(channel_id, body, target=tgt)
            results.append({"target": tgt, "ok": ok, "error": err[:160]})
            all_ok = all_ok and ok
            if self._mlog:
                try:
                    self._mlog.record(
                        direction="out",
                        platform=platform_of_kind(kind),
                        channel_kind=kind,
                        channel_id=channel_id,
                        channel_name=name,
                        sender="ayana",
                        target=tgt,
                        body=body,
                        state="sent" if ok else (
                            "unknown" if (err or "").startswith("unknown:") else "failed"
                        ),
                        error="" if ok else err,
                        detail={"kind": "channel_test"},
                    )
                except Exception:
                    pass
        # 错误展示：去掉前导冒号，unknown 转人话
        def _fmt_err(e: str) -> str:
            e = (e or "").strip()
            if e.startswith(":"):
                e = e.lstrip(":")
            if e == "missing_target":
                return "缺少推送目标"
            if e.startswith("unknown:"):
                return "结果不确定(" + e.split(":", 1)[1] + ")"
            return e

        err_summary = (
            "; ".join(
                f"{r['target'] or '默认'}:{_fmt_err(r['error'])}" for r in results if not r["ok"]
            )
            or ""
        )[:200]
        self.db.execute(
            "UPDATE notify_channels SET last_test_at=?, last_test_ok=?, last_test_error=?"
            " WHERE id=?",
            (now(), 1 if all_ok else 0, err_summary, channel_id),
        )
        self.db.audit(
            "web_user",
            actor,
            "notify_channel_test",
            detail={"id": channel_id, "ok": all_ok, "results": results},
        )
        for r in results:
            if not r.get("ok"):
                r["error"] = _fmt_err(r.get("error") or "")
        return {"ok": all_ok, "error": "" if all_ok else (err_summary or "some_targets_failed"), "id": channel_id, "results": results}
