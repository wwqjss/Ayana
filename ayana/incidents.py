"""Incident 归并与生命周期（确定性规则，不做跨资产智能聚类）。"""

from __future__ import annotations

import json
import time
from typing import Any

from .db import Database, new_id, now

# 短期复发窗口（秒）
RECURRENCE_WINDOW = 30 * 60


class IncidentService:
    def __init__(self, db: Database):
        self.db = db

    def upsert_from_episode(self, episode_id: str) -> str:
        ep = self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (episode_id,))
        if not ep:
            return ""
        if ep["incident_id"]:
            return ep["incident_id"]

        asset_id = ep["asset_id"] or ""
        object_id = ep["object_id"] or ""
        alertname = ep["alertname"] or ""

        # 找活动或短期复发 Incident
        rows = self.db.query(
            "SELECT * FROM incidents WHERE asset_id=? AND status='open'"
            " ORDER BY updated_at DESC LIMIT 20",
            (asset_id,),
        )
        chosen = None
        for r in rows:
            same_obj = (r["object_id"] or "") == object_id
            recent = (now() - (r["updated_at"] or 0)) < RECURRENCE_WINDOW
            if same_obj and (recent or r["status"] == "open"):
                chosen = r
                break
        if not chosen:
            # 短期复发：最近 resolved
            r2 = self.db.query_one(
                "SELECT * FROM incidents WHERE asset_id=? AND status='resolved'"
                " AND updated_at>? ORDER BY updated_at DESC LIMIT 1",
                (asset_id, now() - RECURRENCE_WINDOW),
            )
            if r2 and (r2["object_id"] or "") == object_id:
                chosen = r2

        if chosen and chosen["status"] == "open":
            inc_id = chosen["id"]
            self.db.execute(
                "UPDATE alert_episodes SET incident_id=? WHERE id=?", (inc_id, episode_id)
            )
            self.db.event(
                "episode_attached",
                f"{alertname} → incident",
                incident_id=inc_id,
                payload={"episode_id": episode_id, "alertname": alertname},
            )
            return inc_id

        # 短期复发：重开旧 Incident，不再新建第二个 open
        if chosen and chosen["status"] == "resolved":
            inc_id = chosen["id"]
            with self.db.tx() as conn:
                conn.execute(
                    "UPDATE alert_episodes SET incident_id=? WHERE id=?", (inc_id, episode_id)
                )
                conn.execute(
                    "UPDATE incidents SET status='open', resolved_at=NULL, updated_at=?,"
                    " stage='pending' WHERE id=?",
                    (now(), inc_id),
                )
                conn.execute(
                    "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                    (
                        inc_id,
                        now(),
                        "incident_reopened",
                        f"reopened from {alertname}",
                        json.dumps({"episode_id": episode_id}, ensure_ascii=False),
                    ),
                )
            return inc_id

        inc_id = new_id("inc")
        title = f"{asset_id or 'unknown'} / {object_id or alertname}: {alertname}"
        severity = "critical" if "critical" in json.dumps(ep["labels_json"] or "") else "warning"
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
                " need_human, summary, created_at, updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    inc_id,
                    title,
                    asset_id,
                    object_id,
                    severity,
                    "open",
                    "pending",
                    0,
                    "",
                    now(),
                    now(),
                ),
            )
            conn.execute(
                "UPDATE alert_episodes SET incident_id=? WHERE id=?", (inc_id, episode_id)
            )
            conn.execute(
                "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                (
                    inc_id,
                    now(),
                    "incident_opened",
                    title,
                    json.dumps(
                        {
                            "episode_id": episode_id,
                            "alertname": alertname,
                            "labels": ep["labels_json"],
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        return inc_id

    def on_episode_resolved(self, episode_id: str) -> None:
        ep = self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (episode_id,))
        if not ep or not ep["incident_id"]:
            return
        inc_id = ep["incident_id"]
        firing = self.db.query_one(
            "SELECT COUNT(*) AS n FROM alert_episodes WHERE incident_id=? AND status='firing'",
            (inc_id,),
        )
        if firing and firing["n"] > 0:
            return
        # 监控恢复不能解除尚未核清的执行义务
        blocked = self.db.query_one(
            "SELECT COUNT(*) AS n FROM actions WHERE incident_id=?"
            " AND (state IN ('unknown','dispatched')"
            "  OR (state='success' AND id IN (SELECT action_id FROM verifications"
            "      WHERE status='pending')))",
            (inc_id,),
        )
        need = self.db.query_one(
            "SELECT need_human FROM incidents WHERE id=?", (inc_id,)
        )
        if (blocked and blocked["n"] > 0) or (need and need["need_human"]):
            # 只推进到 watching，并持久记录本次恢复已处理，避免后台重复
            with self.db.tx() as conn:
                conn.execute(
                    "UPDATE incidents SET stage='watching', updated_at=? WHERE id=? AND status='open'",
                    (now(), inc_id),
                )
                # 幂等标记：同一 episode 的恢复转换只记一次 hold
                exists = conn.execute(
                    "SELECT 1 FROM events WHERE incident_id=? AND type='alert_resolved_hold'"
                    " AND payload_json LIKE ?",
                    (inc_id, f"%{episode_id}%"),
                ).fetchone()
                if not exists:
                    conn.execute(
                        "INSERT INTO events(incident_id, at, type, title, payload_json)"
                        " VALUES(?,?,?,?,?)",
                        (
                            inc_id,
                            now(),
                            "alert_resolved_hold",
                            "alerts resolved but human/exec obligations remain",
                            json.dumps(
                                {"episode_id": episode_id, "hold": True}, ensure_ascii=False
                            ),
                        ),
                    )
            return
        # 仅在实际 open→resolved 时写恢复事件
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE incidents SET status='resolved', resolved_at=?, stage='done', updated_at=?"
                " WHERE id=? AND status='open'",
                (now(), now(), inc_id),
            )
            if cur.rowcount == 1:
                conn.execute(
                    "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                    (
                        inc_id,
                        now(),
                        "incident_resolved",
                        "alerts resolved",
                        json.dumps({"episode_id": episode_id}, ensure_ascii=False),
                    ),
                )

    def set_stage(self, inc_id: str, stage: str, note: str = "") -> None:
        self.db.execute(
            "UPDATE incidents SET stage=?, updated_at=? WHERE id=?", (stage, now(), inc_id)
        )
        self.db.event("stage_changed", note or stage, incident_id=inc_id, payload={"stage": stage})

    def need_human(self, inc_id: str, reason: str) -> None:
        self.db.execute(
            "UPDATE incidents SET need_human=1, need_human_reason=?, updated_at=? WHERE id=?",
            (reason, now(), inc_id),
        )
        self.db.event("need_human", reason, incident_id=inc_id)

    def list_incidents(self, status: str = "", limit: int = 50) -> list[dict[str, Any]]:
        if status:
            rows = self.db.query(
                "SELECT * FROM incidents WHERE status=? ORDER BY updated_at DESC LIMIT ?",
                (status, limit),
            )
        else:
            rows = self.db.query(
                "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in rows]

    def get_incident(self, inc_id: str) -> dict[str, Any] | None:
        row = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not row:
            return None
        data = dict(row)
        data["events"] = [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM events WHERE incident_id=? ORDER BY at ASC LIMIT 200", (inc_id,)
            )
        ]
        data["episodes"] = [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM alert_episodes WHERE incident_id=? ORDER BY first_seen ASC", (inc_id,)
            )
        ]
        data["actions"] = [
            dict(r)
            for r in self.db.query(
                "SELECT * FROM actions WHERE incident_id=? ORDER BY created_at ASC", (inc_id,)
            )
        ]
        return data

    def summary_text(self, inc_id: str) -> str:
        inc = self.get_incident(inc_id)
        if not inc:
            return "未找到 Incident"
        lines = [
            f"Incident {inc['id']}",
            inc.get("title") or "",
            f"状态: {inc['status']} / 阶段: {inc['stage']}"
            + (" / 需人工" if inc.get("need_human") else ""),
        ]
        if inc.get("need_human_reason"):
            lines.append(f"原因: {inc['need_human_reason']}")
        for e in (inc.get("events") or [])[-5:]:
            lines.append(f"- {e.get('title') or e.get('type')}")
        return "\n".join(lines)

    def reevaluate_after_action(self, inc_id: str) -> None:
        """Action 终态或人工义务解除后重新评估 hold。"""
        if not inc_id:
            return
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not inc or inc["status"] != "open":
            return
        firing = self.db.query_one(
            "SELECT COUNT(*) AS n FROM alert_episodes WHERE incident_id=? AND status='firing'",
            (inc_id,),
        )
        blocked = self.db.query_one(
            "SELECT COUNT(*) AS n FROM actions WHERE incident_id=?"
            " AND (state IN ('unknown','dispatched')"
            "  OR (state='success' AND id IN (SELECT action_id FROM verifications"
            "      WHERE status='pending')))",
            (inc_id,),
        )
        need = self.db.query_one(
            "SELECT need_human FROM incidents WHERE id=?", (inc_id,)
        )
        if firing and firing["n"] > 0:
            return
        if (blocked and blocked["n"] > 0) or (need and need["need_human"]):
            return
        # 无阻塞且无 firing：收敛
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE incidents SET status='resolved', resolved_at=?, stage='done',"
                " updated_at=? WHERE id=? AND status='open'",
                (now(), now(), inc_id),
            )
            if cur.rowcount == 1:
                conn.execute(
                    "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                    (
                        inc_id,
                        now(),
                        "incident_resolved",
                        "obligations cleared",
                        json.dumps({"reason": "reevaluate"}, ensure_ascii=False),
                    ),
                )
