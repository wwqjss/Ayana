"""企微智能机器人命令入口：复用 QQBot 业务分发，权限由本渠道管理员身份控制。

统一消息入口（与 QQ 一致）：
- `@Ayana /cmd` → 斜杠命令
- `@Ayana -c <host> <cmd>` → 受控命令
- `@Ayana <自然语言>` → Agent 监控查询

同时从收消息帧里提取并登记可推送目标（群 chatid / 单聊 userid），供 Web 勾选。
入站/回复写入消息记录（可观测）。
"""

from __future__ import annotations

import logging
import socket
import time
import uuid
from typing import Any

from .msgentry import error_reply, parse_entry
from .qqbot import QQBot

log = logging.getLogger("ayana.wecom")


class WeComBot:
    """把 aibot 消息接到 Ayana 业务层，并发现推送目标。

    - 身份：from.userid → subject wecom_user
    - 权限：仅本渠道配置的管理员可调查和批准，写操作逐次审批
    - 发现：群聊记 chatid，单聊记 userid；可在 Web「已发现的推送目标」勾选保存
    """

    def __init__(self, qqbot: QQBot, aibot_manager: Any, channel_store: Any = None, mlog: Any = None,
                 node_name: str = ""):
        self.qqbot = qqbot
        self.aibot = aibot_manager
        self.channel_store = channel_store
        self.mlog = mlog
        self.node_name = node_name or socket.gethostname()

    def _discover(self, channel_id: str, body: dict) -> None:
        if not self.channel_store:
            return
        chatid = str(body.get("chatid") or "").strip()
        chattype = str(body.get("chattype") or "").strip()
        from_ = body.get("from") or {}
        user_id = str(from_.get("userid") or "").strip()
        msgtype = str(body.get("msgtype") or "")
        try:
            if chattype == "group" and chatid:
                self.channel_store.record_seen_target(
                    channel_id,
                    target_id=chatid,
                    chattype="group",
                    userid=user_id,
                    msgtype=msgtype,
                )
            elif chattype == "single" and user_id:
                self.channel_store.record_seen_target(
                    channel_id,
                    target_id=user_id,
                    chattype="single",
                    userid=user_id,
                    msgtype=msgtype,
                )
            elif chatid:
                self.channel_store.record_seen_target(
                    channel_id,
                    target_id=chatid,
                    chattype=chattype or "",
                    userid=user_id,
                    msgtype=msgtype,
                )
            elif user_id:
                self.channel_store.record_seen_target(
                    channel_id,
                    target_id=user_id,
                    chattype=chattype or "single",
                    userid=user_id,
                    msgtype=msgtype,
                )
        except Exception:
            log.exception("record_seen_target failed")

    def _channel_name(self, channel_id: str) -> str:
        try:
            meta = self.channel_store.get_meta(channel_id) if self.channel_store else None
            return (meta or {}).get("name") or ""
        except Exception:
            return ""

    async def on_channel_frame(self, channel_id: str, frame: dict) -> None:
        cmd = str(frame.get("cmd") or "")
        log.info("wecom frame cmd=%s channel=%s", cmd, channel_id)
        if cmd not in ("aibot_msg_callback", "aibot_event_callback"):
            return
        body = frame.get("body") or {}
        self._discover(channel_id, body)

        if cmd != "aibot_msg_callback":
            return
        msgtype = str(body.get("msgtype") or "")
        content = ""
        if msgtype == "text":
            content = str((body.get("text") or {}).get("content") or "").strip()
        from_ = body.get("from") or {}
        user_id = str(from_.get("userid") or "")
        chatid = str(body.get("chatid") or "")
        chattype = str(body.get("chattype") or "")
        target = chatid or user_id

        log_id = ""
        if self.mlog:
            try:
                log_id = self.mlog.record(
                    direction="in",
                    platform="wecom",
                    channel_kind="wecom_aibot",
                    channel_id=channel_id,
                    channel_name=self._channel_name(channel_id),
                    sender=user_id,
                    target=target,
                    body=content or f"[{msgtype or 'event'}]",
                    state="received",
                    detail={"msgtype": msgtype, "chattype": chattype, "cmd": cmd},
                )
            except Exception:
                log.exception("message_log inbound failed")

        if not content:
            log.info("wecom msg empty content, msgtype=%s", msgtype)
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="ignored", detail={"reason": "not_text"})
            return

        log.info("wecom msg content=%r", content[:80])
        # 统一入口解析
        entry = parse_entry(content)
        log.info("wecom msg entry kind=%s", entry.kind)
        if entry.kind == "empty":
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="ignored", detail={"reason": "empty"})
            return

        group_id = chatid if chattype == "group" else ""
        if not user_id:
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="failed", error="missing_userid")
            return

        if entry.kind == "unknown":
            reply = error_reply(entry.error, entry.error_hint)
            if log_id and self.mlog:
                self.mlog.update_state(
                    log_id, state="processed", detail={"kind": "error_hint", "reason": entry.error}
                )
            await self._send_reply(channel_id, target, reply, log_id)
            return

        try:
            if entry.kind == "watch_ping":
                reply = (
                    f"AYANA-WATCH-PONG {entry.request_id} "
                    f"ts={int(time.time())} node={self.node_name}"
                )
            elif entry.kind == "urgent":
                rid = uuid.uuid4().hex[:12]
                extra = entry.nl_text or "（无补充说明）"
                reply = (
                    f"[紧急呼叫] 已收到\n"
                    f"请求ID: {rid}\n"
                    f"内容: {extra}\n"
                    f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
            elif entry.kind == "settings":
                reply = (
                    "可用触发词（不必 @）：\n"
                    "· 紧急呼叫 [说明]\n"
                    "· 设置\n"
                    "· AYANA-WATCH-PING <request_id>\n"
                    "可使用 @Ayana /help 查看当前命令；主机操作请使用 Web 中的 MiMoCode 会话。"
                )
            elif entry.kind == "slash":
                reply = await self.qqbot.dispatch(
                    entry.text,
                    user_id=user_id,
                    group_id=group_id,
                    actor_type="wecom_user",
                    channel="wecom_aibot",
                    channel_id=channel_id,
                )
            elif entry.kind == "controlled":
                reply = await self.qqbot._handle_controlled(
                    entry, user_id=user_id, group_id=group_id, log_id=log_id,
                    actor_type="wecom_user", channel="wecom_aibot", channel_id=channel_id,
                )
            elif entry.kind == "nl":
                reply = await self.qqbot._handle_nl(
                    entry, user_id=user_id, group_id=group_id, log_id=log_id,
                    actor_type="wecom_user", channel_id=channel_id,
                )
            else:
                reply = ""
        except Exception as e:
            log.exception("wecom command failed")
            reply = "错误: 内部异常"
            if log_id and self.mlog:
                self.mlog.update_state(
                    log_id,
                    state="failed",
                    error=str(e)[:200],
                    detail={"reason": "processing_failed", "error": str(e)[:200]},
                )
        else:
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="processed")

        if not reply:
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="ignored", detail={"reason": "no_reply"})
            return
        await self._send_reply(channel_id, target, reply, log_id)

    async def _send_reply(
        self, channel_id: str, target: str, reply: str, log_id: str
    ) -> None:
        if not target:
            if log_id and self.mlog:
                try:
                    self.mlog.update_state(
                        log_id, detail={"reason": "no_target"}
                    )
                except Exception:
                    pass
            return
        ok = False
        err = ""
        try:
            ok, err = await self.aibot.send_text(channel_id, target, reply)
        except Exception as e:
            err = str(e)[:120]
            log.exception("wecom reply failed")
        if self.mlog:
            try:
                self.mlog.record(
                    direction="out",
                    platform="wecom",
                    channel_kind="wecom_aibot",
                    channel_id=channel_id,
                    channel_name=self._channel_name(channel_id),
                    sender="ayana",
                    target=target,
                    body=reply,
                    state="sent" if ok else ("unknown" if (err or "").startswith("unknown:") else "failed"),
                    error="" if ok else err,
                    reply_to=log_id or "",
                    detail={"kind": "command_reply"},
                )
            except Exception:
                log.exception("message_log reply failed")
        if log_id and self.mlog:
            try:
                reason = "" if ok else ("send_failed" if err else "send_unknown")
                self.mlog.update_state(
                    log_id,
                    replied=ok,
                    detail={
                        "send_ok": ok,
                        "send_err": err[:100] if err else "",
                        **({} if ok else {"reason": reason}),
                    },
                )
            except Exception:
                pass
