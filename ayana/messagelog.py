"""消息记录：入站 / 出站可观测性。

- 入站（用户消息）与机器人主动回复写入 message_log
- 通知出站复用 notification_outbox，列表时 UNION，**不重复写入**
- 不记录敏感凭据；正文可截断，完整内容在 detail 不放密钥
"""

from __future__ import annotations

import json
import time
from typing import Any

from .db import Database, new_id, now

# 入站状态
IN_STATES = ("received", "processed", "ignored", "failed")
# 出站状态（含 outbox 映射）
OUT_STATES = ("pending", "sent", "failed", "unknown")

MAX_BODY_STORE = 8000


def platform_of_kind(kind: str) -> str:
    if kind in ("qq",):
        return "qq"
    if kind in ("wecom", "wecom_aibot"):
        return "wecom"
    if kind in ("webhook",):
        return "webhook"
    return kind or ""


class MessageLog:
    def __init__(self, db: Database):
        self.db = db

    def record(
        self,
        *,
        direction: str,
        platform: str = "",
        channel_kind: str = "",
        channel_id: str = "",
        channel_name: str = "",
        sender: str = "",
        target: str = "",
        body: str = "",
        state: str = "",
        error: str = "",
        replied: bool = False,
        reply_to: str = "",
        reply_log_id: str = "",
        detail: dict | None = None,
        outbox_id: str = "",
    ) -> str:
        mid = new_id("msg")
        text = (body or "")[:MAX_BODY_STORE]
        self.db.execute(
            "INSERT INTO message_log(id, at, direction, platform, channel_kind, channel_id,"
            " channel_name, sender, target, body, state, error, replied, reply_to, reply_log_id,"
            " detail_json, outbox_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                mid,
                now(),
                direction,
                platform or platform_of_kind(channel_kind),
                channel_kind,
                channel_id,
                channel_name,
                sender,
                target,
                text,
                state,
                (error or "")[:300],
                1 if replied else 0,
                reply_to,
                reply_log_id,
                json.dumps(detail or {}, ensure_ascii=False),
                outbox_id,
            ),
        )
        return mid

    def update_state(self, log_id: str, *, state: str = "", error: str = "", **extra: Any) -> None:
        sets = []
        params: list[Any] = []
        if state:
            sets.append("state=?")
            params.append(state)
        if error:
            sets.append("error=?")
            params.append((error or "")[:300])
        if "replied" in extra:
            sets.append("replied=?")
            params.append(1 if extra["replied"] else 0)
        if "reply_log_id" in extra:
            sets.append("reply_log_id=?")
            params.append(str(extra["reply_log_id"] or ""))
        if "detail" in extra:
            sets.append("detail_json=?")
            params.append(json.dumps(extra["detail"] or {}, ensure_ascii=False))
        if not sets:
            return
        params.append(log_id)
        self.db.execute(f"UPDATE message_log SET {', '.join(sets)} WHERE id=?", tuple(params))

    def get(self, log_id: str) -> dict[str, Any] | None:
        rows = self._query_unified(where="m.id=?", params=[log_id], limit=1)
        return rows[0] if rows else None

    def _query_unified(
        self,
        *,
        where: str = "",
        params: list[Any] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        params = list(params or [])
        # outbox → 统一字段（不复制写入）
        outbox_sql = """
            SELECT
              o.id AS id,
              o.created_at AS at,
              'out' AS direction,
              CASE
                WHEN o.channel='qq' THEN 'qq'
                WHEN o.channel IN ('wecom','wecom_aibot') THEN 'wecom'
                WHEN o.channel='webhook' THEN 'webhook'
                ELSE o.channel
              END AS platform,
              o.channel AS channel_kind,
              o.channel_id AS channel_id,
              COALESCE(c.name, '') AS channel_name,
              'ayana' AS sender,
              o.target AS target,
              o.body AS body,
              CASE
                WHEN o.state='sent' THEN 'sent'
                WHEN o.state='pending' THEN 'pending'
                WHEN o.last_error LIKE 'unknown:%' THEN 'unknown'
                WHEN o.state='failed' THEN 'failed'
                ELSE o.state
              END AS state,
              o.last_error AS error,
              0 AS replied,
              '' AS reply_to,
              '' AS reply_log_id,
              '{"src":"outbox"}' AS detail_json,
              o.id AS outbox_id
            FROM notification_outbox o
            LEFT JOIN notify_channels c ON c.id = o.channel_id
        """
        log_sql = """
            SELECT
              id, at, direction,
              platform, channel_kind, channel_id, channel_name,
              sender, target, body, state, error,
              replied, reply_to, reply_log_id, detail_json, outbox_id
            FROM message_log
        """
        union = f"SELECT * FROM ({outbox_sql} UNION ALL {log_sql}) AS m"
        sql = union
        if where:
            sql += f" WHERE {where}"
        sql += " ORDER BY m.at DESC LIMIT ? OFFSET ?"
        qparams = params + [int(limit), int(offset)]
        rows = self.db.query(sql, tuple(qparams))
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = json.loads(d.pop("detail_json") or "{}")
            except Exception:
                d["detail"] = {}
            out.append(d)
        return out

    def _count_unified(self, where: str = "", params: list[Any] | None = None) -> int:
        params = list(params or [])
        outbox_sql = """
            SELECT o.id AS id, o.created_at AS at, 'out' AS direction,
              CASE
                WHEN o.channel='qq' THEN 'qq'
                WHEN o.channel IN ('wecom','wecom_aibot') THEN 'wecom'
                WHEN o.channel='webhook' THEN 'webhook'
                ELSE o.channel
              END AS platform,
              o.channel AS channel_kind,
              o.channel_id AS channel_id,
              COALESCE(c.name, '') AS channel_name,
              'ayana' AS sender,
              o.target AS target,
              o.body AS body,
              CASE
                WHEN o.state='sent' THEN 'sent'
                WHEN o.state='pending' THEN 'pending'
                WHEN o.last_error LIKE 'unknown:%' THEN 'unknown'
                WHEN o.state='failed' THEN 'failed'
                ELSE o.state
              END AS state,
              o.last_error AS error
            FROM notification_outbox o
            LEFT JOIN notify_channels c ON c.id = o.channel_id
        """
        log_sql = """
            SELECT id, at, direction, platform, channel_kind, channel_id, channel_name,
                   sender, target, body, state, error
            FROM message_log
        """
        sql = f"SELECT COUNT(*) AS n FROM ({outbox_sql} UNION ALL {log_sql}) AS m"
        if where:
            sql += f" WHERE {where}"
        row = self.db.query_one(sql, tuple(params))
        if not row:
            return 0
        try:
            return int(row["n"])
        except Exception:
            return int(dict(row).get("n") or 0)

    def list_messages(
        self,
        *,
        platform: str = "",
        channel_kind: str = "",
        channel_id: str = "",
        direction: str = "",
        state: str = "",
        q: str = "",
        start: float | None = None,
        end: float | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        where: list[str] = []
        params: list[Any] = []
        if platform:
            where.append("m.platform=?")
            params.append(platform)
        if channel_kind:
            where.append("m.channel_kind=?")
            params.append(channel_kind)
        if channel_id:
            where.append("m.channel_id=?")
            params.append(channel_id)
        if direction:
            where.append("m.direction=?")
            params.append(direction)
        if state:
            where.append("m.state=?")
            params.append(state)
        if q:
            where.append("(m.body LIKE ? OR m.sender LIKE ? OR m.target LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like, like])
        if start is not None:
            where.append("m.at>=?")
            params.append(float(start))
        if end is not None:
            where.append("m.at<=?")
            params.append(float(end))
        w = " AND ".join(where) if where else ""
        limit = max(1, min(200, int(limit)))
        offset = max(0, int(offset))
        total = self._count_unified(w, params)
        items = self._query_unified(where=w, params=params, limit=limit, offset=offset)
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": items,
            "states": {
                "in": list(IN_STATES),
                "out": list(OUT_STATES),
            },
        }
