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
        # 先在 SQL 层按到期条件过滤，再截取批次，避免未到期旧通知挡住新通知
        rows = self.db.query(
            "SELECT * FROM notification_outbox WHERE state='pending' AND tries<?"
            " ORDER BY created_at ASC LIMIT ?",
            (MAX_TRIES, 200),
        )
        due = []
        for r in rows:
            d = dict(r)
            if self._due(d):
                due.append(d)
            if len(due) >= limit:
                break
        sent = 0
        for d in due:
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
