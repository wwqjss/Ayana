"""受控命令执行（-c 模式）：跳过 Agent，直接进入现有执行层。

- 只读/写入静态判定，不依赖 Agent 改写
- Policy 校验 + 审批 + 审计
- 错误引导不泄露资产名/别名/数量/内部配置
- 目标不存在与无权限统一「目标不可用或无访问权限」
"""

from __future__ import annotations

import logging
import shlex
import time
from typing import Any

from .msgentry import ERR_TARGET_UNAVAILABLE, classify_command, error_reply

log = logging.getLogger("ayana.controlled")


class ControlledExecutor:
    """-c 模式执行器。复用 transport / policy / actions。"""

    def __init__(
        self,
        db: Any,
        transport: Any,
        policy: Any,
        actions: Any | None = None,
    ):
        self.db = db
        self.transport = transport
        self.policy = policy
        self.actions = actions

    def _asset_ok(self, asset_id: str) -> bool:
        row = self.db.query_one(
            "SELECT id, enabled, read_alias, write_alias FROM assets WHERE id=?",
            (asset_id,),
        )
        return bool(row and row["enabled"])

    def _resolve_host(self, host: str) -> str | None:
        """主机名 → 资产 id。失败返回 None（不泄露是否存在）。"""
        row = self.db.query_one(
            "SELECT id, enabled FROM assets WHERE id=? OR display_name=?",
            (host, host),
        )
        if not row or not row["enabled"]:
            return None
        return str(row["id"])

    async def execute(
        self,
        *,
        host: str,
        cmd_tokens: list[str],
        actor_type: str,
        actor_id: str,
        channel: str = "msg",
        is_write: bool | None = None,  # 兼容旧签名；实际由 classify_command 决定
    ) -> dict[str, Any]:
        """执行受控命令。返回 {ok, reply, need_approval, action_id}。"""
        if not cmd_tokens:
            return {
                "ok": False,
                "reply": error_reply("missing_args"),
                "need_approval": False,
            }

        # S07: 未知命令默认拒绝，不放行任意 argv
        cmd_class = classify_command(cmd_tokens)
        if cmd_class == "unknown":
            self._audit(actor_type, actor_id, "cmd_unknown_rejected", "", cmd_tokens, channel=channel)
            return {
                "ok": False,
                "reply": error_reply("unsafe_token", "仅支持受控目录中的命令。"),
                "need_approval": False,
            }

        asset_id = self._resolve_host(host)
        if not asset_id:
            return {
                "ok": False,
                "reply": ERR_TARGET_UNAVAILABLE,
                "need_approval": False,
            }

        is_write = cmd_class == "write"
        if is_write:
            return await self._exec_write(
                asset_id=asset_id,
                cmd_tokens=cmd_tokens,
                actor_type=actor_type,
                actor_id=actor_id,
                channel=channel,
            )
        return await self._exec_read(
            asset_id=asset_id,
            cmd_tokens=cmd_tokens,
            actor_type=actor_type,
            actor_id=actor_id,
        )

    async def _exec_read(
        self,
        *,
        asset_id: str,
        cmd_tokens: list[str],
        actor_type: str,
        actor_id: str,
    ) -> dict[str, Any]:
        decision = self.policy.check(
            subject_type=actor_type,
            subject_id=actor_id,
            capability="asset.summary",
            asset_id=asset_id,
            object_id="*",
        )
        if not decision.get("allowed"):
            self._audit(actor_type, actor_id, "cmd_denied", asset_id, cmd_tokens, channel="msg")
            return {
                "ok": False,
                "reply": ERR_TARGET_UNAVAILABLE,
                "need_approval": False,
            }

        try:
            res = await self.transport.probe(asset_id, cmd_tokens)
        except Exception as e:
            log.exception("controlled probe failed")
            self._audit(actor_type, actor_id, "cmd_failed", asset_id, cmd_tokens, channel="msg")
            return {
                "ok": False,
                "reply": f"执行失败: {str(e)[:120]}",
                "need_approval": False,
            }

        out = (res.output or "")[:4000]
        self._audit(
            actor_type,
            actor_id,
            "cmd_read_ok" if res.ok else "cmd_read_fail",
            asset_id,
            cmd_tokens,
            channel="msg",
        )
        return {
            "ok": res.ok,
            "reply": out if out else "(无输出)",
            "need_approval": False,
            "returncode": res.returncode,
        }

    async def _exec_write(
        self,
        *,
        asset_id: str,
        cmd_tokens: list[str],
        actor_type: str,
        actor_id: str,
        channel: str,
    ) -> dict[str, Any]:
        """写操作：映射到登记对象 + 能力，走 Action 审批流。"""
        mapped = self._map_write_capability(asset_id, cmd_tokens)
        if not mapped:
            self._audit(
                actor_type, actor_id, "cmd_write_unmapped", asset_id, cmd_tokens, channel=channel
            )
            return {
                "ok": False,
                "reply": ERR_TARGET_UNAVAILABLE,
                "need_approval": False,
            }

        capability, object_id = mapped
        decision = self.policy.check(
            subject_type=actor_type,
            subject_id=actor_id,
            capability=capability,
            asset_id=asset_id,
            object_id=object_id,
        )
        if not decision.get("allowed"):
            self._audit(actor_type, actor_id, "cmd_denied", asset_id, cmd_tokens, channel=channel)
            return {
                "ok": False,
                "reply": ERR_TARGET_UNAVAILABLE,
                "need_approval": False,
            }

        if not self.actions:
            return {
                "ok": False,
                "reply": "写操作需审批，但审批服务未就绪。",
                "need_approval": True,
            }

        try:
            action = self.actions.propose(
                asset_id=asset_id,
                object_id=object_id,
                capability=capability,
                reason=f"controlled_cmd:{shlex.join(cmd_tokens)[:80]}",
                proposer_type=actor_type,
                proposer_id=actor_id,
                mode="manual",
                template_id="",  # 由 propose 内部解析
            )
        except Exception as e:
            log.exception("controlled write propose failed")
            self._audit(actor_type, actor_id, "cmd_write_propose_fail", asset_id, cmd_tokens, channel=channel)
            return {
                "ok": False,
                "reply": ERR_TARGET_UNAVAILABLE,
                "need_approval": False,
            }

        self._audit(actor_type, actor_id, "cmd_write_proposed", asset_id, cmd_tokens, channel=channel)
        return {
            "ok": True,
            "reply": f"写操作需审批。\nAction: {action['id']}\n能力: {capability}\n批准后执行。",
            "need_approval": True,
            "action_id": action["id"],
        }

    def _map_write_capability(
        self, asset_id: str, cmd_tokens: list[str]
    ) -> tuple[str, str] | None:
        """把写命令映射到 (capability, object_id)。仅接受已登记对象。

        S21: 只接受目录确实支持的精确语法，不悄悄改命令语义。
        """
        if len(cmd_tokens) < 3:
            return None
        prog = cmd_tokens[0].lower()
        verb = cmd_tokens[1].lower()
        name = cmd_tokens[2]

        if prog == "systemctl":
            cap_map = {"start": "service.start", "stop": "service.stop", "restart": "service.restart"}
        elif prog in ("docker", "podman"):
            # S21: 仅 restart 有对应能力；start/stop 不悄悄映射成 restart
            if verb != "restart":
                return None
            cap_map = {"restart": "container.restart"}
        else:
            return None

        capability = cap_map.get(verb)
        if not capability:
            return None

        obj = self.db.query_one(
            "SELECT id FROM objects WHERE asset_id=? AND (name=? OR unit=? OR container=?)",
            (asset_id, name, name, name),
        )
        if not obj:
            return None
        return capability, str(obj["id"])

    def _audit(
        self,
        actor_type: str,
        actor_id: str,
        entry: str,
        asset_id: str,
        cmd_tokens: list[str],
        channel: str = "msg",
    ) -> None:
        try:
            self.db.audit(
                actor_type,
                actor_id,
                entry,
                asset_id=asset_id,
                detail={"cmd": " ".join(cmd_tokens)[:200], "mode": "controlled"},
                channel=channel,
            )
        except Exception:
            log.exception("audit failed")
