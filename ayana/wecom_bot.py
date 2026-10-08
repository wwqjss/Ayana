"""企微智能机器人命令入口：复用 QQBot 业务分发，权限走 Policy（wecom_user）。

同时从收消息帧里提取并登记可推送目标（群 chatid / 单聊 userid），供 Web 勾选。
入站/回复写入消息记录（可观测，不新增 NL 能力）。
"""

from __future__ import annotations

import logging
from typing import Any

from .qqbot import QQBot

log = logging.getLogger("ayana.wecom")


class WeComBot:
    """把 aibot 消息接到 Ayana 业务层，并发现推送目标。

    - 身份：from.userid → subject wecom_user
    - 权限：Policy 默认拒绝，需在 Web「权限」页授权
    - 发现：群聊记 chatid，单聊记 userid；可在 Web「已发现的推送目标」勾选保存
    """

    def __init__(self, qqbot: QQBot, aibot_manager: Any, channel_store: Any = None, mlog: Any = None):
        self.qqbot = qqbot
        self.aibot = aibot_manager
        self.channel_store = channel_store
        self.mlog = mlog

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
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="ignored", detail={"reason": "not_text"})
            return

        text = content
        if text.startswith("@"):
            parts = text.split(None, 1)
            text = (parts[1] if len(parts) > 1 else "").strip()
        if not text.startswith("/"):
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="ignored", detail={"reason": "not_command"})
            return

        group_id = chatid if chattype == "group" else ""
        if not user_id:
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="failed", error="missing_userid")
            return
        try:
            reply = await self.qqbot.dispatch(
                text,
                user_id=user_id,
                group_id=group_id,
                actor_type="wecom_user",
                channel="wecom_aibot",
            )
        except Exception as e:
            log.exception("wecom command failed")
            reply = "错误: 内部异常"
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="failed", error=str(e)[:200])
        else:
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="processed")
        if not reply:
            return
        if not target:
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
        if log_id and self.mlog and ok:
            try:
                self.mlog.update_state(log_id, replied=True)
            except Exception:
                pass
