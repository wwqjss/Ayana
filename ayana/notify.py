"""通知 outbox。

- 到期用 `next_try_at` 在 SQL 层筛选，无固定扫描预算
- 补偿以真实生命周期事件为源（incident_opened/reopened/resolved、verified_recovered）
- 多渠道：同一事件对每个启用渠道各建一条 outbox，状态/重试独立
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
        self._channels: Any = None  # ChannelStore | None

    def set_sender(self, sender: Callable[[str, str], Awaitable[bool]]) -> None:
        self._sender = sender

    def set_channel_store(self, store: Any) -> None:
        self._channels = store

    def set_default_target(self, target: str) -> None:
        self.default_target = target

    def _insert_outbox(
        self,
        *,
        dedup_key: str,
        target: str,
        body: str,
        channel: str,
        channel_id: str = "",
    ) -> bool:
        t = now()
        if not target:
            try:
                self.db.execute(
                    "INSERT INTO notification_outbox(id, dedup_key, channel, target, body,"
                    " state, created_at, last_try_at, next_try_at, last_error, channel_id)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        new_id("ntf"), dedup_key, channel, "", body,
                        "failed", t, 0, 0, "missing_target", channel_id,
                    ),
                )
            except Exception:
                pass
            return False
        try:
            self.db.execute(
                "INSERT INTO notification_outbox(id, dedup_key, channel, target, body, state,"
                " created_at, last_try_at, next_try_at, channel_id)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (new_id("ntf"), dedup_key, channel, target, body, "pending", t, 0, 0, channel_id),
            )
            return True
        except Exception:
            return False

    def enqueue(
        self,
        *,
        dedup_key: str,
        target: str,
        body: str,
        channel: str = "qq",
        channel_id: str = "",
    ) -> bool:
        target = target or (self.default_target if channel == "qq" else "")
        return self._insert_outbox(
            dedup_key=dedup_key,
            target=target,
            body=body,
            channel=channel,
            channel_id=channel_id,
        )

    def _enabled_channels(self) -> list[dict[str, Any]]:
        if not self._channels:
            return []
        try:
            return list(self._channels.list_enabled())
        except Exception:
            return []

    def enqueue_for_event(self, event_id: int | str, *, body: str, typ: str = "") -> bool:
        """按生命周期 Event 建立通知义务。

        幂等键：ev:<id>:<channel_id> 或 ev:<id>:<channel_id>:<target>（多目标时每目标一行）。
        """
        channels = self._enabled_channels()
        if not channels:
            return self.enqueue(
                dedup_key=f"ev:{event_id}", target="", body=body, channel="qq"
            )
        any_ok = False
        for ch in channels:
            targets = list(ch.get("targets") or [])
            if not targets:
                t0 = str(ch.get("target") or "")
                if t0:
                    targets = [t0]
            if not targets and ch.get("kind") == "qq":
                targets = [self.default_target] if self.default_target else [""]
            if not targets:
                targets = [""]
            multi = len(targets) > 1 or ch.get("kind") == "wecom_aibot"
            for tgt in targets:
                if multi:
                    key = f"ev:{event_id}:{ch['id']}:{tgt}"
                else:
                    key = f"ev:{event_id}:{ch['id']}"
                ok = self._insert_outbox(
                    dedup_key=key,
                    target=tgt,
                    body=body,
                    channel=str(ch.get("kind") or "qq"),
                    channel_id=str(ch.get("id") or ""),
                )
                any_ok = any_ok or ok
        return any_ok

    def compensate_missing(self, limit: int = 100) -> int:
        """扫生命周期事件，为缺失 outbox 的补回义务。"""
        placeholders = ",".join("?" for _ in LIFECYCLE_TYPES)
        rows = self.db.query(
            f"SELECT e.id AS ev_id, e.type, e.payload_json, e.incident_id"
            f" FROM events e WHERE e.type IN ({placeholders})"
            f" AND NOT EXISTS (SELECT 1 FROM notification_outbox o"
            f"               WHERE o.dedup_key = 'ev:' || e.id"
            f"                  OR o.dedup_key LIKE 'ev:' || e.id || ':%')"
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
            if self.enqueue_for_event(r["ev_id"], body=body):
                n += 1
            else:
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

    async def _deliver(self, row: dict) -> tuple[bool, str]:
        """按 channel_id + target 路由。

        返回 (ok, err)。err 以 unknown: 开头表示结果不确定，调用方不得盲目重试。
        """
        channel_id = str(row.get("channel_id") or "")
        body = row.get("body") or ""
        target = row.get("target") or ""
        if channel_id and self._channels:
            try:
                return await self._channels.send(channel_id, body, target=target)
            except Exception as e:
                return False, f"unknown:{str(e)[:160]}"
        # 遗留单通道：QQ sender
        if not self._sender:
            return False, "no_sender"
        if not target:
            return False, "missing_target"
        try:
            ok = await self._sender(target, body)
        except Exception as e:
            return False, str(e)[:200]
        return (True, "") if ok else (False, "send_failed")

    async def flush(self, limit: int = 20) -> int:
        if not self._sender and not self._channels:
            return 0
        self.mark_failed_exhausted()
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
            channel_id = str(d.get("channel_id") or "")
            # 渠道自身有 target/url 时可为空 target；仅遗留 QQ 需要补默认
            if not target and not channel_id:
                self.db.execute(
                    "UPDATE notification_outbox SET tries=tries+1, last_try_at=?, next_try_at=?,"
                    " last_error='missing_target' WHERE id=?",
                    (now(), now() + self._next_try_delay(int(d.get("tries") or 0) + 1), rid),
                )
                continue
            if not target:
                target = d.get("target") or ""
            ok, err = await self._deliver(d)
            if ok:
                self.db.execute(
                    "UPDATE notification_outbox SET state='sent', sent_at=?, tries=tries+1,"
                    " last_try_at=?, next_try_at=?, target=?, last_error='' WHERE id=?",
                    (now(), now(), 0, target, rid),
                )
                sent += 1
            else:
                tries = int(d.get("tries") or 0) + 1
                # 结果不确定（可能已送达）：直接 failed，禁止自动重试，避免重复推送
                if (err or "").startswith("unknown:"):
                    self.db.execute(
                        "UPDATE notification_outbox SET state='failed', tries=?, last_try_at=?,"
                        " next_try_at=?, last_error=?, target=? WHERE id=?",
                        (tries, now(), 0, (err or "unknown")[:200], target, rid),
                    )
                    self.db.audit(
                        "system",
                        "outbox",
                        "notify_result_unknown",
                        detail={"outbox_id": rid, "channel_id": channel_id, "target": target, "error": err[:120]},
                    )
                    continue
                self.db.execute(
                    "UPDATE notification_outbox SET tries=?, last_try_at=?, next_try_at=?,"
                    " last_error=?, target=? WHERE id=?",
                    (tries, now(), now() + self._next_try_delay(tries), err or "send_failed", target, rid),
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
            channel_id = str(d.get("channel_id") or "")
            if not target and not channel_id:
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
                    "channel_id": channel_id,
                    "target_filled": bool(not d.get("target") and target),
                },
            )
            n += 1
        return n

    def failed_summary(self, limit: int = 20) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self.db.query(
                "SELECT id, dedup_key, channel, channel_id, target, last_error, tries, created_at"
                " FROM notification_outbox WHERE state='failed'"
                " ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        ]

    def outbox_summary(self, limit: int = 50, state: str = "") -> list[dict[str, Any]]:
        sql = (
            "SELECT id, dedup_key, channel, channel_id, target, body, state, tries,"
            " last_error, created_at, last_try_at, sent_at FROM notification_outbox"
        )
        params: list[Any] = []
        if state:
            sql += " WHERE state=?"
            params.append(state)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.db.query(sql, tuple(params))]

    def incident_key(self, incident_id: str, typ: str, rev: int = 0) -> str:
        return f"{incident_id}:{typ}:{rev}"
