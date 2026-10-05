"""通知 outbox：退避基于最后尝试时间，连接不可用不迅速耗尽预算。"""

from __future__ import annotations

import time
from typing import Any, Awaitable, Callable

from .db import Database, new_id, now

MAX_TRIES = 15
BASE_BACKOFF = 15.0
MAX_BACKOFF = 600.0


class Notifier:
    def __init__(self, db: Database, default_target: str = ""):
        self.db = db
        self.default_target = default_target
        self._sender: Callable[[str, str], Awaitable[bool]] | None = None

    def set_sender(self, sender: Callable[[str, str], Awaitable[bool]]) -> None:
        self._sender = sender

    def set_default_target(self, target: str) -> None:
        self.default_target = target

    def enqueue(self, *, dedup_key: str, target: str, body: str, channel: str = "qq") -> bool:
        target = target or self.default_target
        if not target:
            return False
        try:
            self.db.execute(
                "INSERT INTO notification_outbox(id, dedup_key, channel, target, body, state,"
                " created_at, last_try_at) VALUES(?,?,?,?,?,?,?,0)",
                (new_id("ntf"), dedup_key, channel, target, body, "pending", now()),
            )
            return True
        except Exception:
            return False

    def compensate_missing(self) -> int:
        """Event→缺失 outbox 补偿：为 notify_* 事件补回通知义务。"""
        rows = self.db.query(
            "SELECT e.id AS ev_id, e.payload_json FROM events e"
            " WHERE e.type LIKE 'notify_%'"
            " AND NOT EXISTS (SELECT 1 FROM notification_outbox o WHERE o.dedup_key = 'ev:' || e.id)"
            " ORDER BY e.id ASC LIMIT 50"
        )
        n = 0
        for r in rows:
            try:
                import json as _json

                payload = _json.loads(r["payload_json"] or "{}")
                body = payload.get("body") or ""
                target = self.default_target
                self.db.execute(
                    "INSERT INTO notification_outbox(id, dedup_key, channel, target, body,"
                    " state, created_at, last_try_at) VALUES(?,?,?,?,?,?,?,0)",
                    (
                        new_id("ntf"),
                        f"ev:{r['ev_id']}",
                        "qq",
                        target or "",
                        body,
                        "pending" if target else "failed",
                        now(),
                    ),
                )
                n += 1
            except Exception:
                pass
        return n

    def retry_failed(self, outbox_id: str = "") -> int:
        """把 failed 通知重新置为 pending，便于审计重试。"""
        if outbox_id:
            cur = self.db.execute(
                "UPDATE notification_outbox SET state='pending', tries=0, last_error='retry'"
                " WHERE id=? AND state='failed'",
                (outbox_id,),
            )
        else:
            cur = self.db.execute(
                "UPDATE notification_outbox SET state='pending', tries=0, last_error='retry'"
                " WHERE state='failed'"
            )
        return int(cur.rowcount or 0)

    def failed_summary(self, limit: int = 20) -> list[dict]:
        return [
            dict(r)
            for r in self.db.query(
                "SELECT id, dedup_key, target, last_error, tries, created_at"
                " FROM notification_outbox WHERE state='failed'"
                " ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        ]

    def incident_key(self, incident_id: str, typ: str, rev: int = 0) -> str:
        """每次转换唯一：rev 用事件序号/时间戳，避免复发永久去重。"""
        return f"{incident_id}:{typ}:{rev}"

    def enqueue_transition(
        self,
        *,
        incident_id: str,
        typ: str,
        target: str,
        body: str,
        at: float | None = None,
    ) -> bool:
        rev = int((at or now()) * 1000)
        # 同毫秒内可能多次转换：加随机后缀保证唯一
        import uuid

        key = f"{incident_id}:{typ}:{rev}:{uuid.uuid4().hex[:8]}"
        return self.enqueue(dedup_key=key, target=target, body=body)

    def _due(self, row: dict) -> bool:
        tries = int(row.get("tries") or 0)
        if tries >= MAX_TRIES:
            return False
        if tries == 0:
            return True
        delay = min(MAX_BACKOFF, BASE_BACKOFF * (2 ** (tries - 1)))
        last_try = float(row.get("last_try_at") or 0)
        return (now() - last_try) >= delay

    async def flush(self, limit: int = 20) -> int:
        if not self._sender:
            return 0
        self.mark_failed_exhausted()
        # 分页寻找到期项，避免未到期旧通知挡住新通知
        sent = 0
        offset = 0
        batch = 50
        scanned = 0
        while sent < limit and scanned < 500:
            rows = self.db.query(
                "SELECT * FROM notification_outbox WHERE state='pending' AND tries<?"
                " ORDER BY created_at ASC LIMIT ? OFFSET ?",
                (MAX_TRIES, batch, offset),
            )
            if not rows:
                break
            for r in rows:
                d = dict(r)
                scanned += 1
                if not self._due(d):
                    continue
                rid = d["id"]
                try:
                    ok = await self._sender(d["target"], d["body"])
                except Exception as e:
                    self.db.execute(
                        "UPDATE notification_outbox SET tries=tries+1, last_try_at=?, last_error=?"
                        " WHERE id=?",
                        (now(), str(e)[:200], rid),
                    )
                    continue
                if ok:
                    self.db.execute(
                        "UPDATE notification_outbox SET state='sent', sent_at=?, tries=tries+1,"
                        " last_try_at=? WHERE id=?",
                        (now(), now(), rid),
                    )
                    sent += 1
                    if sent >= limit:
                        break
                else:
                    self.db.execute(
                        "UPDATE notification_outbox SET tries=tries+1, last_try_at=?,"
                        " last_error='send_failed' WHERE id=?",
                        (now(), rid),
                    )
            offset += batch
        return sent

    def mark_failed_exhausted(self) -> int:
        return int(
            self.db.execute(
                "UPDATE notification_outbox SET state='failed'"
                " WHERE state='pending' AND tries>=?",
                (MAX_TRIES,),
            ).rowcount
            or 0
        )
