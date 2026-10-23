"""QQ 命令分发：与 Web 共用业务服务层。

统一消息入口：
- `@Ayana /cmd` → 斜杠命令
- `@Ayana -c <host> <cmd>` → 受控命令（跳过 Agent）
- `@Ayana <自然语言>` → Agent 监控查询
"""

from __future__ import annotations

import logging
from typing import Any

from .actions import ActionError, ActionService
from .approval import ApprovalService
from .alertmanager import AlertIngest
from .agent_query import AgentQueryService
from .controlled import ControlledExecutor
from .db import Database
from .incidents import IncidentService
from .investigation import InvestigationService
from .msgentry import ERR_TARGET_UNAVAILABLE, error_reply, parse_entry, usage_hint_for_controlled
from .notify import Notifier
from .onewbot import OneBotServer, extract_text
from .policy import Policy

log = logging.getLogger("ayana.qq")

HELP = """Ayana 命令
@Ayana /ping 存活
@Ayana /health 自身状态
@Ayana /help 本帮助
@Ayana /status 总览
@Ayana -c <host> <cmd> 受控命令
@Ayana 查询 <host> 状态 自然语言查询
@Ayana /incident [id] 事件
@Ayana /investigate <asset> [object] 发起只读调查
@Ayana /actions 待批准操作
@Ayana /approve <action_id> 批准并执行
@Ayana /reject <action_id> [原因] 拒绝操作
@Ayana /cancel <action_id> 取消操作
"""

# 词表唯一来源：fmt.py（P2-3）
from .fmt import ZH_STAGE, ZH_STATE, ZH_STATUS


def _zstatus(s: str) -> str:
    return ZH_STATUS.get(s, s)


def _zstage(s: str) -> str:
    return ZH_STAGE.get(s, s)


def _zstate(s: str) -> str:
    return ZH_STATE.get(s, s)


class QQBot:
    def __init__(
        self,
        db: Database,
        ob: OneBotServer,
        incidents: IncidentService,
        investigation: InvestigationService,
        actions: ActionService,
        policy: Policy,
        notifier: Notifier,
        *,
        admin_qq: str = "",
        admin_wecom_users: list[str] | tuple[str, ...] = (),
        channel_store=None,
        version: str = "0.2.0",
    ):
        self.db = db
        self.ob = ob
        self.incidents = incidents
        self.investigation = investigation
        self.actions = actions
        self.policy = policy
        self.notifier = notifier
        self.admin_qq = admin_qq
        self.channel_store = channel_store
        self.admin_wecom_users = frozenset(
            u.strip() for u in admin_wecom_users if isinstance(u, str) and u.strip()
        ) if isinstance(admin_wecom_users, (list, tuple)) else frozenset()
        self.version = version
        self.mlog = None  # MessageLog | None
        self.agent_query: AgentQueryService | None = None
        self.controlled: ControlledExecutor | None = None
        self.ob.set_message_handler(self.on_event)

    async def on_event(self, event: dict) -> None:
        text = extract_text(event)
        message_type = event.get("message_type", "")
        user_id = str(event.get("user_id") or "")
        group_id = str(event.get("group_id") or "")
        # 消息记录：入站（可观测，不改变命令行为）
        log_id = ""
        if text and self.mlog:
            try:
                log_id = self.mlog.record(
                    direction="in",
                    platform="qq",
                    channel_kind="qq",
                    channel_id="napcat",
                    channel_name="NapCat",
                    sender=user_id,
                    target=group_id or user_id,
                    body=text,
                    state="received",
                    detail={"message_type": message_type},
                )
            except Exception:
                log.exception("message_log inbound failed")

        # 统一入口解析
        entry = parse_entry(text)
        if entry.kind == "empty":
            if log_id and self.mlog:
                try:
                    self.mlog.update_state(log_id, state="ignored", detail={"reason": "empty"})
                except Exception:
                    pass
            return

        if entry.kind == "unknown":
            reply = error_reply(entry.error, entry.error_hint)
            if log_id and self.mlog:
                self.mlog.update_state(
                    log_id, state="processed", detail={"kind": "error_hint", "reason": entry.error}
                )
            await self._send_reply(message_type, user_id, group_id, reply, log_id)
            return

        try:
            if entry.kind == "approval":
                reply = await self._handle_approval(entry, user_id=user_id)
            elif entry.kind == "slash":
                reply = await self.dispatch(
                    entry.text, user_id=user_id, group_id=group_id
                )
            elif entry.kind == "controlled":
                reply = await self._handle_controlled(
                    entry, user_id=user_id, group_id=group_id, log_id=log_id
                )
            elif entry.kind == "nl":
                reply = await self._handle_nl(
                    entry, user_id=user_id, group_id=group_id, log_id=log_id
                )
            else:
                reply = ""
            if log_id and self.mlog:
                self.mlog.update_state(log_id, state="processed")
        except Exception as e:
            if log_id and self.mlog:
                self.mlog.update_state(
                    log_id,
                    state="failed",
                    error=str(e)[:200],
                    detail={"reason": "processing_failed", "error": str(e)[:200]},
                )
            raise
        if not reply:
            if log_id and self.mlog:
                self.mlog.update_state(
                    log_id, state="ignored", detail={"reason": "no_reply"}
                )
            return
        await self._send_reply(message_type, user_id, group_id, reply, log_id)

    async def _send_reply(
        self, message_type: str, user_id: str, group_id: str, reply: str, log_id: str
    ) -> None:
        if not reply:
            return
        send_ok = False
        send_err = ""
        try:
            if message_type == "private":
                # S19: 使用真实回执，不忽略返回值
                send_ok = await self.ob.send_private(user_id, reply)
                if not send_ok:
                    send_err = "send_rejected"
            elif message_type == "group":
                send_ok = await self.ob.send_group(group_id, reply)
                if not send_ok:
                    send_err = "send_rejected"
            else:
                send_err = "unknown_message_type"
        except Exception as e:
            send_err = str(e)[:120]
            log.exception("qq send reply failed")
        if self.mlog:
            try:
                self.mlog.record(
                    direction="out",
                    platform="qq",
                    channel_kind="qq",
                    channel_id="napcat",
                    channel_name="NapCat",
                    sender="ayana",
                    target=group_id or user_id,
                    body=reply,
                    state="sent" if send_ok else "failed",
                    error=send_err,
                    reply_to=log_id or "",
                    detail={"kind": "command_reply"},
                )
            except Exception:
                log.exception("message_log reply failed")
            if log_id:
                try:
                    reason = "" if send_ok else ("send_failed" if send_err else "send_unknown")
                    self.mlog.update_state(
                        log_id,
                        replied=send_ok,
                        detail={
                            "send_ok": send_ok,
                            "send_err": send_err,
                            **({} if send_ok else {"reason": reason}),
                        },
                    )
                except Exception:
                    pass

    async def _handle_controlled(
        self, entry, *, user_id: str, group_id: str, log_id: str = "",
        actor_type: str = "qq_user", channel: str = "qq",
    ) -> str:
        """-c 受控命令：跳过 Agent，保留只读/写判定、Policy、审批、审计。"""
        if not self.controlled:
            return "受控命令服务未就绪"
        res = await self.controlled.execute(
            host=entry.host,
            cmd_tokens=entry.cmd_tokens,
            is_write=entry.is_write,
            actor_type=actor_type,
            actor_id=user_id,
            channel=channel,
        )
        # 消息记录：关联执行状态
        if log_id and self.mlog:
            try:
                self.mlog.update_state(
                    log_id,
                    detail={
                        "kind": "controlled",
                        "host": entry.host,
                        "is_write": entry.is_write,
                        "exec_ok": res.get("ok", False),
                        "need_approval": res.get("need_approval", False),
                        "action_id": res.get("action_id", ""),
                    },
                )
            except Exception:
                pass
        return res.get("reply") or ""

    async def _handle_approval(
        self, entry, *, user_id: str, actor_type: str = "qq_user", channel: str = "qq", channel_id: str = "",
    ) -> str:
        """三句授权共用服务层；管理身份只能来自已配置的通道用户。"""
        from .fmt import approval_error
        try:
            result = await ApprovalService(self.actions).decide(
                entry.approval_decision,
                actor_type=actor_type, actor_id=user_id, channel=channel,
                is_admin=self._is_channel_admin(actor_type, user_id, channel_id),
            )
        except ActionError as e:
            return approval_error(e.code)
        if result.get("decision") == "reject":
            return "已选择不执行，本次处置已跳过。"
        prefix = "已允许以后自动执行。" if result.get("permanent_granted") else ""
        if result.get("already"):
            return prefix + "这条操作已经处理，没有重复执行。"
        if result.get("executed"):
            state = ZH_STATE.get(result.get("state"), "已提交")
            return prefix + f"已批准本次处置，执行结果：{state}。"
        return prefix + "已批准本次处置，执行尚未完成，请在事件详情查看。"

    def _is_channel_admin(self, actor_type: str, actor_id: str, channel_id: str = "") -> bool:
        if not actor_id:
            return False
        if actor_type == "qq_user":
            return bool(self.admin_qq) and actor_id == str(self.admin_qq)
        if actor_type != "wecom_user":
            return False
        if actor_id in self.admin_wecom_users:
            return True
        store = getattr(self, "channel_store", None)
        return bool(store and channel_id and store.is_aibot_admin(channel_id, actor_id))

    async def _handle_nl(
        self, entry, *, user_id: str, group_id: str, log_id: str = "",
        actor_type: str = "qq_user",
    ) -> str:
        """自然语言：交给 Agent 查询（只读监控数据）。"""
        log.info("_handle_nl actor=%s/%s text=%r", actor_type, user_id, entry.nl_text[:60])
        if not self.agent_query:
            log.warning("agent_query not configured")
            return "查询服务未就绪"
        reply = await self.agent_query.handle(
            entry.nl_text,
            actor_type=actor_type,
            actor_id=user_id,
            policy=self.policy,
        )
        log.info("_handle_nl reply=%r", reply[:80])
        # 消息记录：关联 Agent 处理结果
        if log_id and self.mlog:
            try:
                self.mlog.update_state(
                    log_id,
                    detail={"kind": "nl_query", "query": entry.nl_text[:200], "has_reply": bool(reply)},
                )
            except Exception:
                pass
        return reply

    def _subject(self, user_id: str, group_id: str) -> tuple[str, str]:
        if group_id:
            return "qq_user", user_id
        return "qq_user", user_id

    def _visible_assets(self, actor_type: str, actor_id: str) -> list[dict[str, Any]]:
        """S04: 按主体×资产×asset.summary 过滤可见资产，不泄露无权资产。"""
        rows = self.db.query("SELECT id, display_name, enabled FROM assets ORDER BY id")
        out = []
        for r in rows:
            decision = self.policy.check(
                subject_type=actor_type,
                subject_id=actor_id,
                capability="asset.summary",
                asset_id=r["id"],
                object_id="*",
            )
            if decision.get("allowed"):
                out.append(dict(r))
        return out

    async def dispatch(
        self,
        text: str,
        *,
        user_id: str,
        group_id: str = "",
        actor_type: str = "qq_user",
        channel: str = "qq",
        channel_id: str = "",
    ) -> str:
        parts = text.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        actor_type, actor_id = actor_type, user_id

        try:
            if cmd == "/ping":
                return f"Ayana v{self.version}\npong"
            if cmd == "/health":
                return (
                    f"Ayana v{self.version}\n"
                    f"napcat: {'connected' if self.ob.connected else 'disconnected'}\n"
                    f"connections: {self.ob.connection_count()}"
                )
            if cmd == "/help":
                return HELP
            if cmd == "/status":
                return self._status_text(actor_type, actor_id)
            if cmd == "/asset":
                return self._asset_text(args[0] if args else "", actor_type, actor_id)
            if cmd in ("/incident", "/incidents"):
                return self._incident_text(args[0] if args else "", actor_type, actor_id)
            if cmd == "/investigate":
                return await self._investigate(args, actor_type, actor_id)
            if cmd == "/actions":
                return self._actions_text(actor_type, actor_id)
            if cmd == "/approve":
                return await self._approve(args, actor_type, actor_id, channel=channel, channel_id=channel_id)
            if cmd == "/reject":
                return await self._reject(args, actor_type, actor_id, channel=channel)
            if cmd == "/cancel":
                return self._cancel(args, actor_type, actor_id, channel=channel)
        except Exception as e:
            log.exception("command failed")
            return f"错误: {e}"
        return ""

    def _status_text(self, actor_type: str = "qq_user", actor_id: str = "") -> str:
        # S04: 仅显示调用者有权看到的资产
        assets = self._visible_assets(actor_type, actor_id) if actor_id else []
        visible_ids = {asset["id"] for asset in assets}
        incs = [inc for inc in self.incidents.list_incidents(status="open")
                if inc.get("asset_id") in visible_ids][:5] if assets else []
        lines = ["Ayana 状态"]
        if not assets:
            lines.append("目标不可用或无访问权限")
            return "\n".join(lines)
        for a in assets:
            lines.append(f"- {a['id']}: {'启用' if a['enabled'] else '停用'} {a['display_name']}")
        if incs:
            lines.append("活动事件:")
            for i in incs:
                flag = "需人工 " if i.get("need_human") else ""
                lines.append(
                    f"{flag}{i['id']} {i['title'][:40]} [{_zstage(i['stage'])}]"
                )
        else:
            lines.append("没有需要你处理的事情")
        return "\n".join(lines)

    def _asset_text(self, asset_id: str, actor_type: str = "qq_user", actor_id: str = "") -> str:
        # S04: 资产详情也按权限过滤
        if not asset_id:
            rows = self._visible_assets(actor_type, actor_id) if actor_id else []
            if not rows:
                return ERR_TARGET_UNAVAILABLE
            return "资产: " + ", ".join(r["id"] for r in rows)
        decision = self.policy.check(
            subject_type=actor_type, subject_id=actor_id,
            capability="asset.summary", asset_id=asset_id, object_id="*",
        ) if actor_id else {"allowed": False}
        if not decision.get("allowed"):
            return ERR_TARGET_UNAVAILABLE
        row = self.db.query_one("SELECT * FROM assets WHERE id=?", (asset_id,))
        if not row:
            return ERR_TARGET_UNAVAILABLE
        objs = self.db.query("SELECT kind, name FROM objects WHERE asset_id=?", (asset_id,))
        return (
            f"{row['id']} / {row['display_name']}\n"
            f"read={row['read_alias']} write={row['write_alias']}\n"
            f"host_id={row['expected_host_id'] or '未登记'}\n"
            f"objects: " + ", ".join(f"{o['kind']}:{o['name']}" for o in objs)
        )

    def _incident_text(self, inc_id: str, actor_type: str = "qq_user", actor_id: str = "") -> str:
        # Resolve every incident against the caller's visible assets.
        visible = self._visible_assets(actor_type, actor_id) if actor_id else []
        if not visible:
            return ERR_TARGET_UNAVAILABLE
        visible_ids = {asset["id"] for asset in visible}
        if not inc_id:
            rows = [inc for inc in self.incidents.list_incidents()
                    if inc.get("asset_id") in visible_ids][:5]
            if not rows:
                return "无 Incident"
            return "\n".join(
                f"{r['id']} [{_zstage(r['stage'])}/{_zstatus(r['status'])}] {r['title'][:50]}"
                for r in rows
            )
        inc = self.incidents.get_incident(inc_id)
        if not inc or inc.get("asset_id") not in visible_ids:
            return ERR_TARGET_UNAVAILABLE
        return self.incidents.summary_text(inc_id, for_qq=True)

    async def _investigate(self, args: list[str], actor_type: str, actor_id: str) -> str:
        if not args:
            return "用法: /investigate <asset> [object]"
        asset_id = args[0]
        object_id = args[1] if len(args) > 1 else ""
        res = await self.investigation.run(
            asset_id=asset_id,
            object_id=object_id,
            capability="asset.summary",
            actor_type=actor_type,
            actor_id=actor_id,
        )
        if not res.get("ok"):
            return f"调查失败: {res.get('error')}"
        ev = res.get("evidence") or []
        lines = [f"调查 {res['id']} ({len(ev)} 条证据)"]
        for e in ev[:4]:
            if e.get("source") in ("ssh_probe", "nt_probe"):
                lines.append(f"$ {' '.join(e.get('cmd') or [])}")
                out = (e.get("output") or "")[:200]
                lines.append(out)
            else:
                lines.append(str(e.get("summary") or e.get("source")))
        return "\n".join(lines)[:1500]

    def _actions_text(self, actor_type: str = "qq_user", actor_id: str = "") -> str:
        # S04: 操作列表也按资产可见范围过滤
        visible = self._visible_assets(actor_type, actor_id) if actor_id else []
        if not visible:
            return ERR_TARGET_UNAVAILABLE
        visible_ids = {a["id"] for a in visible}
        rows = self.actions.list_actions(limit=10)
        if not rows:
            return "无操作记录"
        lines = []
        for r in rows:
            if r.get("asset_id") not in visible_ids:
                continue
            lines.append(
                f"{r['id']} [{_zstate(r['state'])}] {r['capability']} {r['asset_id']}/{r['object_id']}"
            )
        return "\n".join(lines) if lines else "无操作记录"

    async def _approve(self, args: list[str], actor_type: str, actor_id: str, channel: str = "qq", channel_id: str = "") -> str:
        if not args:
            return "用法: /approve <action_id>"
        try:
            res = await ApprovalService(self.actions).decide(
                "execute_once", action_id=args[0],
                actor_type=actor_type,
                actor_id=actor_id,
                channel=channel,
                reason=f"{channel}_approve",
                is_admin=self._is_channel_admin(actor_type, actor_id, channel_id),
            )
            if res.get("already"):
                return f"{args[0]} 已是 {res.get('state')}，未重复派发"
            if res.get("executed"):
                return f"已批准并执行 {res['id']} → {res.get('state')}"
            return (
                f"已批准 {res.get('id')}，但执行未完成: "
                f"{res.get('error') or res.get('state')}"
            )
        except ActionError as e:
            return f"批准失败: {e}"

    async def _reject(self, args: list[str], actor_type: str, actor_id: str, channel: str = "qq") -> str:
        if not args:
            return "用法: /reject <action_id> [原因]"
        reason = " ".join(args[1:]) if len(args) > 1 else ""
        try:
            res = await ApprovalService(self.actions).decide(
                "reject", action_id=args[0],
                actor_type=actor_type,
                actor_id=actor_id,
                channel=channel,
                reason=reason,
            )
            return f"已拒绝 {res['id']}" + (f"（{reason}）" if reason else "")
        except ActionError as e:
            return f"拒绝失败: {e}"

    def _cancel(self, args: list[str], actor_type: str, actor_id: str, channel: str = "qq") -> str:
        if not args:
            return "用法: /cancel <action_id>"
        try:
            self.actions.cancel(
                args[0], actor_type=actor_type, actor_id=actor_id, channel=channel
            )
            return f"已取消 {args[0]}"
        except ActionError as e:
            return f"取消失败: {e}"

    async def notify_incident(self, incident_id: str, typ: str, body: str, target: str = "") -> None:
        target = target or (f"user:{self.admin_qq}" if self.admin_qq else "")
        if not target:
            return
        self.notifier.enqueue(
            dedup_key=self.notifier.incident_key(incident_id, typ),
            target=target,
            body=body,
        )
