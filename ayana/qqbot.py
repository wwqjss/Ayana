"""QQ 命令分发：与 Web 共用业务服务层。"""

from __future__ import annotations

import logging
from typing import Any

from .actions import ActionError, ActionService
from .alertmanager import AlertIngest
from .db import Database
from .incidents import IncidentService
from .investigation import InvestigationService
from .notify import Notifier
from .onewbot import OneBotServer, extract_text
from .policy import Policy

log = logging.getLogger("ayana.qq")

HELP = """Ayana 命令
/ping 存活
/health 自身状态
/help 本帮助
/status 总览
/asset <id> 资产状态
/incident [id] 事件
/investigate <asset> [object] 发起只读调查
/actions 待批准操作
/approve <action_id> 批准操作
/cancel <action_id> 取消操作
"""

ZH_STATUS = {"open": "处理中", "resolved": "已解决", "closed": "已关闭"}
ZH_STAGE = {
    "pending": "待调查", "investigating": "调查中", "awaiting_approval": "待批准",
    "executing": "执行中", "verifying": "验证中", "watching": "观察中",
    "done": "完成", "need_human": "需人工",
}
ZH_STATE = {
    "proposed": "已提案", "approved": "已批准", "dispatched": "已派发",
    "success": "成功", "failure": "失败", "unknown": "结果未知",
    "cancelled": "已取消", "expired": "已过期",
}


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
        self.version = version
        self.ob.set_message_handler(self.on_event)

    async def on_event(self, event: dict) -> None:
        text = extract_text(event)
        if not text.startswith("/"):
            return
        message_type = event.get("message_type", "")
        user_id = str(event.get("user_id") or "")
        group_id = str(event.get("group_id") or "")
        reply = await self.dispatch(text, user_id=user_id, group_id=group_id)
        if not reply:
            return
        if message_type == "private":
            await self.ob.send_private(user_id, reply)
        elif message_type == "group":
            await self.ob.send_group(group_id, reply)

    def _subject(self, user_id: str, group_id: str) -> tuple[str, str]:
        if group_id:
            return "qq_user", user_id
        return "qq_user", user_id

    async def dispatch(self, text: str, *, user_id: str, group_id: str = "") -> str:
        parts = text.strip().split()
        cmd = parts[0].lower()
        args = parts[1:]
        actor_type, actor_id = self._subject(user_id, group_id)

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
                return self._status_text()
            if cmd == "/asset":
                return self._asset_text(args[0] if args else "")
            if cmd in ("/incident", "/incidents"):
                return self._incident_text(args[0] if args else "")
            if cmd == "/investigate":
                return await self._investigate(args, actor_type, actor_id)
            if cmd == "/actions":
                return self._actions_text()
            if cmd == "/approve":
                return self._approve(args, actor_type, actor_id)
            if cmd == "/cancel":
                return self._cancel(args, actor_type, actor_id)
        except Exception as e:
            log.exception("qq command failed")
            return f"错误: {e}"
        return ""

    def _status_text(self) -> str:
        assets = self.db.query("SELECT id, display_name, enabled FROM assets ORDER BY id")
        incs = self.incidents.list_incidents(status="open", limit=5)
        lines = ["Ayana 状态"]
        for a in assets:
            lines.append(f"- {a['id']}: {'启用' if a['enabled'] else '停用'} {a['display_name']}")
        if incs:
            lines.append("活动事件:")
            for i in incs:
                flag = "⚠ " if i.get("need_human") else ""
                lines.append(
                    f"{flag}{i['id']} {i['title'][:40]} [{_zstage(i['stage'])}]"
                )
        else:
            lines.append("没有需要你处理的事情")
        return "\n".join(lines)

    def _asset_text(self, asset_id: str) -> str:
        if not asset_id:
            rows = self.db.query("SELECT id, display_name FROM assets ORDER BY id")
            return "资产: " + ", ".join(r["id"] for r in rows)
        row = self.db.query_one("SELECT * FROM assets WHERE id=?", (asset_id,))
        if not row:
            return f"未知资产 {asset_id}"
        objs = self.db.query("SELECT kind, name FROM objects WHERE asset_id=?", (asset_id,))
        return (
            f"{row['id']} / {row['display_name']}\n"
            f"read={row['read_alias']} write={row['write_alias']}\n"
            f"host_id={row['expected_host_id'] or '未登记'}\n"
            f"objects: " + ", ".join(f"{o['kind']}:{o['name']}" for o in objs)
        )

    def _incident_text(self, inc_id: str) -> str:
        if not inc_id:
            rows = self.incidents.list_incidents(limit=5)
            if not rows:
                return "无 Incident"
            return "\n".join(
                f"{r['id']} [{_zstage(r['stage'])}/{_zstatus(r['status'])}] {r['title'][:50]}"
                for r in rows
            )
        return self.incidents.summary_text(inc_id)

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
            if e.get("source") == "nt_probe":
                lines.append(f"$ {' '.join(e.get('cmd') or [])}")
                out = (e.get("output") or "")[:200]
                lines.append(out)
            else:
                lines.append(str(e.get("summary") or e.get("source")))
        return "\n".join(lines)[:1500]

    def _actions_text(self) -> str:
        rows = self.actions.list_actions(limit=10)
        if not rows:
            return "无操作记录"
        lines = []
        for r in rows:
            lines.append(
                f"{r['id']} [{_zstate(r['state'])}] {r['capability']} {r['asset_id']}/{r['object_id']}"
            )
        return "\n".join(lines)

    def _approve(self, args: list[str], actor_type: str, actor_id: str) -> str:
        if not args:
            return "用法: /approve <action_id>"
        try:
            res = self.actions.approve(args[0], approver_type=actor_type, approver_id=actor_id)
            return f"已批准 {res['id']}，可执行"
        except ActionError as e:
            return f"批准失败: {e}"

    def _cancel(self, args: list[str], actor_type: str, actor_id: str) -> str:
        if not args:
            return "用法: /cancel <action_id>"
        try:
            self.actions.cancel(args[0], actor_type=actor_type, actor_id=actor_id)
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
