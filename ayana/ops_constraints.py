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
2. **同方案失败 2 次停止**：同一修复方案（相同 capability/命令意图）连续失败 2 次 → 停止重试，换策略或转人工。
3. **证据不足转人工**：根因不明、关键探测无样本、或写结果为 unknown → 不得假装恢复；标记需人工并通知。
4. **SSH 成功 ≠ 恢复**：必须用指标/探针/服务状态验证。
5. **写操作可自主执行**，但必须走 Ayana 工具链（host.exec / action），禁止绕过审计。
6. **不接触明文凭据**；不把密钥写入日志/知识库。

## 输出
结论 + 依据 + 下一步；完整痕迹留在审计与事件时间线。
"""


class OpsConstraints:
    """提示词版本库：编辑 → 新版本 → 确认生效。"""

    KIND = "ops_constraints"

    def __init__(self, db: Database):
        self.db = db

    def current(self) -> dict[str, Any]:
        rows = self.db.query(
            "SELECT payload_json, created_at, created_by, id FROM config_versions"
            " WHERE kind=? ORDER BY id DESC LIMIT 20",
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
        if latest:
            return latest
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
