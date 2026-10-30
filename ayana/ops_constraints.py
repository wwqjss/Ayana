"""软约束提示词：可编辑、可版本化、可生效确认。

硬保护不在此层。约束只约束 MiMoCode 行为习惯：
- 无进展 3 轮停止
- 同方案失败 2 次停止
- 证据不足转人工
"""

from __future__ import annotations

import json
from typing import Any

from .db import Database, new_id, now

DEFAULT_CONSTRAINTS = """# MiMoCode 运维软约束（生效版本）

你是值班运维 Agent。目标：恢复服务并留下可核对证据。

## 行为约束（必须遵守）
1. **无进展 3 轮停止**：连续 3 轮调查/处置未产生新证据或状态未改善 → 停止自动循环，整理证据并转人工。
2. **同方案执行失败 2 次停止**：同一修复方案（相同命令意图）连续【实际执行后】失败 2 次 → 停止重试，换策略或转人工。对象或目标缺失等未执行的拦截不算执行失败；先补齐条件，不得无限重复同一拦截。上述轮次由你根据执行证据记录并遵守。
3. **证据不足转人工**：根因不明、关键探测无样本、或写结果为 unknown → 不得假装恢复；标记需人工并通知。
4. **SSH 成功 ≠ 恢复**：必须用指标/探针/服务状态验证。
5. **同一会话完成处置**：由 MiMoCode 在当前会话内自行调查、修复与验证；通过 Ayana MCP 的 host.exec 读写目标，使用当前会话账号组（未覆盖时继承全局默认）。处理未关闭工单时明确真实 incident_id，写入该工单当前代次的写台账和审计，不等待第二套决策或派发。手动会话没有未关闭的关联候选时，后续独立任务省略 incident_id，使用当前会话台账并保留历史关联；不得对已关闭工单反复 session.claim，也不解除已有 unknown 或防重复保护。
6. **不接触明文凭据**；不把密钥写入日志/知识库。

## 输出
用简短中文公开说明进度：开始先说目标和首个核对步骤；关键阶段、遇到失败或改变方案时说明已知事实、失败原因与下一步；结束给出结果、依据、未完成项和下一步。不要展示内部思考或推理过程。工具调用错误不等于目标业务故障；没有执行或验证证据时，不得声称已配置、已执行或已恢复。完整痕迹留在审计与事件时间线。
"""


MANAGED_EXECUTION_PROMPT = """# Ayana 当前执行契约（2026-10-29）

你是当前受管的 MiMoCode 值班 Agent，在同一原生会话内自行完成调查、修复、验证与报告。

- 每次开始、继续或恢复任务，先调用 ayana_ops_constraints 读取当前生效的运维软约束及版本；按当前工具目录和服务端返回判断能力。历史消息、旧工具返回和旧提示词不代表当前配置，不能据此判断自动写入已关闭。
- 每个任务开始先用一两句简短中文说明目标和首个核对步骤；只在关键阶段、工具失败或改变方案时补充已知事实、实际失败原因及下一步，无需逐次复述工具日志。不要连续静默试探或只输出 Thought，也不要展示内部思考或推理过程。把参数校验、工具拒绝、执行失败和业务故障区分说明；同类错误先读取结构化错误并修正，不要只改名称反复重试。结束时说明结果、验证依据、未完成项和下一步；无法确认时如实说明待核对。
- ActionService、Council 和旧 OpsLoop 的二次决策/派发链已经退役。ayana_action_execute 不再使用；不要等待它恢复，也不要把历史 ops_loop_state 的 need_human、轮次或停止原因当作当前执行权限或原生任务状态。
- 调查和修复可自主使用 ayana_host_exec。channel=read 标注调查用途，channel=write 标注变更用途；两者使用当前会话所选账号组，未覆盖时继承全局默认。实际主机权限由该 SSH 账号及 sudo 决定；缺少所选组的目标连接时应补齐配置，不得借用其他组回退。
- 针对工单执行变更时携带真实 incident_id，将执行事实记入该工单当前故障代次的台账。尚未关联当前会话时先调用 ayana_session_claim；可能对应多个工单时先查询并确认，不能猜测工单、使用虚构 ID 或将工单处置记入无关会话台账。
- 手动会话仅有同一主机已关闭的历史工单时，后续独立任务可在 host.exec 中省略 incident_id，使用当前会话台账；历史关联继续保留。显式指定已关闭工单会返回 incident_not_open；服务端提示 can_run_standalone=true 时，按 omit_incident_id 提示继续，不要对已关闭工单反复 session.claim。仍有未关闭关联时必须遵守其工单选择和代次检查；自动会话不能因工单关闭降级为独立写。已有 done 不重复派发，unknown 保护不解除。
- 服从当前会话暂停、删除、目标占用、主机指纹和未知写结果等执行检查，不绕过拒绝。unknown 不能当作失败后盲目重试或重放；先核对台账和目标状态，未澄清时整理证据转人工。
- 命令成功不等于故障恢复。修复后以当前目标的服务状态、指标或探针取得恢复证据，核对工单和故障代次后如实报告；没有充分证据不得宣称 recovered。保留审计，不接触或输出明文凭据。
"""


class OpsConstraints:
    """提示词版本库：编辑 → 新版本 → 确认生效。"""

    KIND = "ops_constraints"

    def __init__(self, db: Database):
        self.db = db

    def current(self) -> dict[str, Any]:
        rows = self.db.query(
            "SELECT payload_json, created_at, created_by, id FROM config_versions"
            " WHERE kind=? ORDER BY id DESC",
            (self.KIND,),
        )
        active = None
        latest = None
        for r in rows:
            try:
                p = json.loads(r["payload_json"] or "{}")
            except Exception:
                p = {}
            item = {
                "text": p.get("text") or DEFAULT_CONSTRAINTS,
                "version": int(p.get("version") or r["id"]),
                "active": bool(p.get("active", False)),
                "created_at": r["created_at"],
                "created_by": r["created_by"] or "",
                "is_default": False,
                "change_note": p.get("change_note") or "",
            }
            if latest is None:
                latest = item
            if item["active"] and active is None:
                active = item
        if active:
            return active
        return {
            "text": DEFAULT_CONSTRAINTS,
            "version": 0,
            "active": True,
            "created_at": 0,
            "created_by": "system",
            "is_default": True,
        }

    def list_versions(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT id, payload_json, created_at, created_by FROM config_versions"
            " WHERE kind=? ORDER BY id DESC LIMIT ?",
            (self.KIND, int(limit)),
        )
        out = []
        for r in rows:
            p = json.loads(r["payload_json"] or "{}")
            out.append(
                {
                    "id": r["id"],
                    "version": int(p.get("version") or r["id"]),
                    "active": bool(p.get("active", False)),
                    "created_at": r["created_at"],
                    "created_by": r["created_by"] or "",
                    "change_note": p.get("change_note") or "",
                    "preview": (p.get("text") or "")[:160],
                }
            )
        return out

    def save(
        self,
        text: str,
        *,
        actor: str = "web_user",
        change_note: str = "",
        activate: bool = True,
    ) -> dict[str, Any]:
        if not isinstance(text, str) or not text.strip():
            raise ValueError("empty_constraints")
        if len(text) > 20000:
            raise ValueError("constraints_too_long")
        with self.db.tx() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            cur = self.db.execute(
                "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
                " VALUES(?,?,?,?)",
                (
                    self.KIND,
                    json.dumps(
                        {
                            "text": text,
                            "active": bool(activate),
                            "change_note": change_note or "",
                            "version": 0,
                        },
                        ensure_ascii=False,
                    ),
                    now(),
                    actor,
                ),
            )
            vid = int(cur.lastrowid or 0)
            payload = {
                "text": text,
                "active": bool(activate),
                "change_note": change_note or "",
                "version": vid,
            }
            self.db.execute(
                "UPDATE config_versions SET payload_json=? WHERE id=?",
                (json.dumps(payload, ensure_ascii=False), vid),
            )
            if activate:
                for r in self.db.query(
                    "SELECT id, payload_json FROM config_versions WHERE kind=? AND id!=?",
                    (self.KIND, vid),
                ):
                    try:
                        p = json.loads(r["payload_json"] or "{}")
                    except Exception:
                        p = {}
                    p["active"] = False
                    self.db.execute(
                        "UPDATE config_versions SET payload_json=? WHERE id=?",
                        (json.dumps(p, ensure_ascii=False), int(r["id"])),
                    )
            self.db.audit(
                "web_user",
                actor,
                "ops_constraints_saved",
                detail={"version": vid, "activate": bool(activate), "change_note": change_note or ""},
                channel="web",
            )
            return self.current()

    def activate(self, version_id: int, *, actor: str = "web_user") -> dict[str, Any]:
        with self.db.tx() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            row = self.db.query_one(
                "SELECT id, payload_json FROM config_versions WHERE id=? AND kind=?",
                (int(version_id), self.KIND),
            )
            if not row:
                raise ValueError("version_not_found")
            # 唯一生效：先关闭其它 active，再激活目标
            for r in self.db.query(
                "SELECT id, payload_json FROM config_versions WHERE kind=?", (self.KIND,)
            ):
                try:
                    p = json.loads(r["payload_json"] or "{}")
                except Exception:
                    p = {}
                p["active"] = int(r["id"]) == int(row["id"])
                p["version"] = int(r["id"])
                self.db.execute(
                    "UPDATE config_versions SET payload_json=? WHERE id=?",
                    (json.dumps(p, ensure_ascii=False), int(r["id"])),
                )
            self.db.audit(
                "web_user",
                actor,
                "ops_constraints_activated",
                detail={"version": int(row["id"])},
                channel="web",
            )
            return self.current()
