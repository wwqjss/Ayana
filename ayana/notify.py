"""通知 outbox。

- 到期用 `next_try_at` 在 SQL 层筛选，无固定扫描预算
- 补偿以真实生命周期事件为源（incident_opened/reopened/resolved、verified_recovered）
- 空目标重试时补填当前默认目标并审计
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from .db import Database, new_id, now

MAX_TRIES = 15
BASE_BACKOFF = 15.0
MAX_BACKOFF = 600.0

# 通知义务来源：真实生命周期事件
LIFECYCLE_TYPES = (
    "incident_opened",
    "incident_reopened",
    "incident_resolved",
    "verified_recovered",
)


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
        t = now()
        if not target:
            try:
                self.db.execute(
                    "INSERT INTO notification_outbox(id, dedup_key, channel, target, body,"
                    " state, created_at, last_try_at, next_try_at, last_error)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        new_id("ntf"), dedup_key, channel, "", body,
                        "failed", t, 0, 0, "missing_target",
                    ),
                )
            except Exception:
                pass
            return False
        try:
            self.db.execute(
                "INSERT INTO notification_outbox(id, dedup_key, channel, target, body, state,"
                " created_at, last_try_at, next_try_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (new_id("ntf"), dedup_key, channel, target, body, "pending", t, 0, 0),
            )
            return True
        except Exception:
            return False

    def enqueue_for_event(self, event_id: int | str, *, body: str, typ: str = "") -> bool:
        """按生命周期 Event 建立通知义务（幂等：dedup_key=ev:<id>）。"""
        return self.enqueue(
            dedup_key=f"ev:{event_id}", target="", body=body, channel="qq"
        )

    def compensate_missing(self, limit: int = 100) -> int:
        """扫生命周期事件，为缺失 outbox 的补回义务。"""
        placeholders = ",".join("?" for _ in LIFECYCLE_TYPES)
        rows = self.db.query(
            f"SELECT e.id AS ev_id, e.type, e.payload_json, e.incident_id"
            f" FROM events e WHERE e.type IN ({placeholders})"
            f" AND NOT EXISTS (SELECT 1 FROM notification_outbox o"
            f"               WHERE o.dedup_key = 'ev:' || e.id)"
            f" ORDER BY e.id ASC LIMIT ?",
            (*LIFECYCLE_TYPES, limit),
        )
        n = 0
        for r in rows:
            body = f"[Ayana] {r['type']} {r['incident_id'] or ''}".strip()
            try:
                payload = json.loads(r["payload_json"] or "{}")
                if payload.get("body"):
                    body = payload["body"]
            except Exception:
                pass
            if self.enqueue(dedup_key=f"ev:{r['ev_id']}", target="", body=body):
                n += 1
            else:
                # 目标缺失也记一条，便于后续补填重试
                n += 1
        return n

    def _next_try_delay(self, tries: int) -> float:
        if tries <= 0:
            return 0.0
        return min(MAX_BACKOFF, BASE_BACKOFF * (2 ** (tries - 1)))

    def _due(self, row: dict) -> bool:
        tries = int(row.get("tries") or 0)
        if tries >= MAX_TRIES:
            return False
        return float(row.get("next_try_at") or 0) <= now()

    async def flush(self, limit: int = 20) -> int:
        if not self._sender:
            return 0
        self.mark_failed_exhausted()
        # SQL 层筛到期；无固定前缀预算
        rows = self.db.query(
            "SELECT * FROM notification_outbox"
            " WHERE state='pending' AND tries<? AND next_try_at<=?"
            " ORDER BY created_at ASC LIMIT ?",
            (MAX_TRIES, now(), limit),
        )
        sent = 0
        for r in rows:
            d = dict(r)
            rid = d["id"]
            target = d.get("target") or self.default_target
            if not target:
                self.db.execute(
                    "UPDATE notification_outbox SET tries=tries+1, last_try_at=?, next_try_at=?,"
                    " last_error='missing_target' WHERE id=?",
                    (now(), now() + self._next_try_delay(int(d.get("tries") or 0) + 1), rid),
                )
                continue
            try:
                ok = await self._sender(target, d["body"])
            except Exception as e:
                tries = int(d.get("tries") or 0) + 1
                self.db.execute(
                    "UPDATE notification_outbox SET tries=?, last_try_at=?, next_try_at=?, last_error=?"
                    " WHERE id=?",
                    (tries, now(), now() + self._next_try_delay(tries), str(e)[:200], rid),
                )
                continue
            if ok:
                self.db.execute(
                    "UPDATE notification_outbox SET state='sent', sent_at=?, tries=tries+1,"
                    " last_try_at=?, next_try_at=?, target=? WHERE id=?",
                    (now(), now(), 0, target, rid),
                )
                sent += 1
            else:
                tries = int(d.get("tries") or 0) + 1
                self.db.execute(
                    "UPDATE notification_outbox SET tries=?, last_try_at=?, next_try_at=?,"
                    " last_error='send_failed', target=? WHERE id=?",
                    (tries, now(), now() + self._next_try_delay(tries), target, rid),
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

    def retry_failed(self, outbox_id: str = "") -> int:
        """失败重试：空目标补填当前默认目标；记审计。"""
        if outbox_id:
            rows = self.db.query(
                "SELECT * FROM notification_outbox WHERE id=? AND state='failed'", (outbox_id,)
            )
        else:
            rows = self.db.query(
                "SELECT * FROM notification_outbox WHERE state='failed' LIMIT 50"
            )
        n = 0
        for r in rows:
            d = dict(r)
            target = d.get("target") or ""
            if not target and self.default_target:
                target = self.default_target
            if not target:
                self.db.execute(
                    "UPDATE notification_outbox SET last_error='missing_target_no_default'"
                    " WHERE id=?",
                    (d["id"],),
                )
                continue
            self.db.execute(
                "UPDATE notification_outbox SET state='pending', tries=0, last_error='retry',"
                " target=?, next_try_at=0 WHERE id=?",
                (target, d["id"]),
            )
            self.db.audit(
                "web_user",
                "admin",
                "notification_retry",
                detail={
                    "outbox_id": d["id"],
                    "dedup_key": d.get("dedup_key"),
                    "target_filled": bool(not d.get("target") and target),
                },
            )
            n += 1
        return n

    def failed_summary(self, limit: int = 20) -> list[dict[str, Any]]:
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
        return f"{incident_id}:{typ}:{rev}"
