"""通知 outbox。

- 到期用 `next_try_at` 在 SQL 层筛选，无固定扫描预算
- 补偿以真实生命周期事件为源（incident_opened/reopened/resolved、verified_recovered）
- 多渠道：同一事件对每个启用渠道各建一条 outbox，状态/重试独立
- 空目标重试时补填当前默认目标并审计
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Awaitable, Callable

from .db import Database, new_id, now

MAX_TRIES = 15
BASE_BACKOFF = 15.0
MAX_BACKOFF = 600.0

# 通知义务来源：真实生命周期事件
LIFECYCLE_TYPES = (
    "incident_opened",
    "incident_reopened",
    "incident_refired",
    "incident_resolved",
    "verified_recovered",
    "proposal_waiting",
    "agent_waiting",
    "agent_auto_exec",
    "agent_escalated",
    "autonomy_notice",
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
        strict: bool = False,
    ) -> bool:
        t = now()
        if not target:
            try:
                self.db.execute(
                    "INSERT OR IGNORE INTO notification_outbox(id, dedup_key, channel, target, body,"
                    " state, created_at, last_try_at, next_try_at, last_error, channel_id)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        new_id("ntf"), dedup_key, channel, "", body,
                        "failed", t, 0, 0, "missing_target", channel_id,
                    ),
                )
            except Exception:
                if strict:
                    raise
            return False
        try:
            self.db.execute(
                "INSERT OR IGNORE INTO notification_outbox(id, dedup_key, channel, target, body, state,"
                " created_at, last_try_at, next_try_at, channel_id)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (new_id("ntf"), dedup_key, channel, target, body, "pending", t, 0, 0, channel_id),
            )
            return True
        except Exception:
            if strict:
                raise
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
        # 显式指定渠道：单路插入（nodewatch / 测试）
        if channel_id:
            target = target or (self.default_target if channel == "qq" else "")
            return self._insert_outbox(
                dedup_key=dedup_key,
                target=target,
                body=body,
                channel=channel,
                channel_id=channel_id,
            )
        # 未指定渠道：只扇出到启用渠道；没有就留在 Ayana（不回落 QQ）
        routes = self._event_routes()
        if not routes:
            return False
        any_ok = False
        for route in routes:
            tgt = route["target"] or target or (
                self.default_target if route["channel"] == "qq" else ""
            )
            ok = self._insert_outbox(
                dedup_key=f"{dedup_key}{route['suffix']}",
                target=tgt,
                body=body,
                channel=route["channel"],
                channel_id=route["channel_id"],
            )
            any_ok = any_ok or ok
        return any_ok

    def _enabled_channels(self) -> list[dict[str, Any]]:
        if not self._channels:
            return []
        # A failed lookup is not an empty configuration; let the obligation retry.
        return list(self._channels.list_enabled())

    def _event_routes(self) -> list[dict[str, Any]]:
        """Expected channel/target obligations, shared by enqueue and compensation."""
        channels = self._enabled_channels()
        if not channels:
            return []
        routes = []
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
            for tgt in targets:
                suffix = f":{ch['id']}:{tgt}"
                routes.append({"suffix": suffix, "target": str(tgt),
                               "channel": str(ch.get("kind") or "qq"),
                               "channel_id": str(ch.get("id") or ""),
                               "created_at": ch.get("created_at", 0),
                               "updated_at": ch.get("updated_at", 0)})
        return routes

    def _event_is_actionable(self, event: Any, payload: dict) -> bool:
        """授权/等待/升级消息只描述当前义务，不能在恢复后补发过期请求。"""
        # 旧版 Agent 使用独立直接发送键，不能将其历史事件猜成新的通知义务。
        if event and event["type"] in ("proposal_waiting", "agent_waiting", "agent_escalated", "agent_auto_exec", "autonomy_notice"):
            if not isinstance(payload.get("body"), str) or not payload["body"]:
                return False
        if event and event["type"] == "autonomy_notice":
            return self._autonomy_notice_actionable(event, payload)
        if not event or event["type"] not in ("proposal_waiting", "agent_waiting", "agent_escalated"):
            return True
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (event["incident_id"],))
        if not inc or inc["status"] != "open":
            return False
        if int(payload.get("generation") or inc["generation"] or 1) != int(inc["generation"] or 1):
            return False
        generation_event = self.db.query_one(
            "SELECT id FROM events WHERE incident_id=? AND type IN"
            " ('incident_opened','incident_reopened','generation_bumped') ORDER BY id DESC LIMIT 1",
            (event["incident_id"],),
        )
        if generation_event and event["id"] < generation_event["id"]:
            return False
        if event["type"] == "proposal_waiting":
            from .actions import action_incident_block
            action = self.db.query_one("SELECT * FROM actions WHERE id=?", (payload.get("action_id") or "",))
            if not action or action["state"] != "proposed" or action_incident_block(self.db, action):
                return False
            deadline = float(action["approval_deadline"] or 0)
            return not deadline or now() <= deadline
        if event["type"] == "agent_waiting":
            from .actions import action_incident_block
            latest = self.db.query_one("SELECT id FROM events WHERE incident_id=? AND type='agent_waiting'"
                                       " ORDER BY id DESC LIMIT 1", (event["incident_id"],))
            if not (latest and latest["id"] == event["id"] and inc["stage"] == "watching" and not inc["need_human"]):
                return False
            return not any(not action_incident_block(self.db, action) for action in self.db.query(
                "SELECT * FROM actions WHERE incident_id=? AND state IN"
                " ('proposed','approved','dispatched','success','unknown')", (event["incident_id"],),
            ))
        reason = payload.get("reason") or ""
        return bool(inc["need_human"] and reason and any(
            obligation == reason or obligation.startswith(reason + " | llm:")
            for obligation in (inc["need_human_reason"] or "").splitlines()
        ))

    def _autonomy_notice_actionable(self, event: Any, payload: dict) -> bool:
        """Recheck durable AI notices at enqueue, compensation and delivery.

        The notice is an obligation of this active generation and condition,
        rather than a historical message that should be replayed after recovery.
        Parts of one adjudication bundle stay independent delivery obligations.
        """
        inc = self.db.query_one("SELECT status,generation FROM incidents WHERE id=?", (event["incident_id"],))
        generation = payload.get("generation")
        if not inc or inc["status"] != "open" or type(generation) is not int or generation != int(inc["generation"] or 1):
            return False
        kind = payload.get("notice_kind")
        if not isinstance(kind, str) or kind not in {"manual", "budget", "provider"}:
            return False
        boundary = self.db.query_one("SELECT id FROM events WHERE incident_id=? AND type IN"
                                     " ('incident_opened','incident_reopened','generation_bumped') ORDER BY id DESC LIMIT 1",
                                     (event["incident_id"],))
        if boundary and event["id"] < boundary["id"]:
            return False
        try:
            state = self.db.query_one("SELECT phase FROM autonomy_state WHERE incident_id=? AND generation=?", (event["incident_id"], generation))
            phase = state["phase"] if state else ""
            if kind == "manual":
                goal = self.db.query_one("SELECT id FROM council_goals WHERE incident_id=? AND generation=? AND manual_required=1 LIMIT 1", (event["incident_id"], generation))
                active = bool(goal or phase == "manual")
            else:
                active = phase == {"budget": "budget_blocked", "provider": "provider_unavailable"}[kind]
        except sqlite3.OperationalError:
            return False  # Optional AI storage is not initialized.
        if not active:
            return False
        for later in self.db.query("SELECT payload_json FROM events WHERE incident_id=? AND type='autonomy_notice' AND id>? ORDER BY id", (event["incident_id"], event["id"])):
            try:
                other = json.loads(later["payload_json"] or "{}")
            except (TypeError, ValueError):
                continue
            if isinstance(other, dict) and other.get("generation") == generation and other.get("notice_kind") == kind and other.get("part", 1) == 1:
                return False  # Replaced by a newer bundle of the same condition.
        return True

    def _event_plan(self, event_id: int | str, *, establish: bool = False) -> list[dict[str, str]]:
        """Persist the original recipients so later configuration changes do not replay history."""
        with self.db.tx() as conn:
            event = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            try:
                payload = json.loads(event["payload_json"] or "{}") if event else {}
            except (TypeError, ValueError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            if not self._event_is_actionable(event, payload):
                return []
            # 通知意图同事件持久化：实时发送和补偿都遵守同一静默窗口。
            if payload.get("_notification_suppressed"):
                return []
            if isinstance(payload.get("_notification_routes"), list):
                return payload["_notification_routes"]
            if event and event["type"] in ("incident_reopened", "incident_refired"):
                episode_id = event["episode_id"] or payload.get("episode_id") or ""
                prior = conn.execute(
                    "SELECT MAX(at) AS at FROM events WHERE incident_id=? AND id<?"
                    " AND type IN ('incident_opened','incident_reopened','incident_resolved',"
                    " 'alert_fired','episode_attached','incident_refired')"
                    " AND (?='' OR COALESCE(episode_id,'')!=?)",
                    (event["incident_id"], event["id"], episode_id, episode_id),
                ).fetchone()
                if prior and prior["at"] is not None and float(event["at"]) - float(prior["at"]) < 3600:
                    payload["_notification_suppressed"] = "quiet_window"
                    conn.execute("UPDATE events SET payload_json=? WHERE id=?",
                                 (json.dumps(payload, ensure_ascii=False), event_id))
                    return []
            routes = self._event_routes()
            if event:
                # Legacy events have no snapshot. Only channels that existed at the
                # event time are candidates. A legacy short key proves that channel
                # originally had one target; preserve that recipient when it expands.
                legacy = conn.execute("SELECT dedup_key,channel_id,target FROM notification_outbox"
                                      " WHERE dedup_key=? OR dedup_key LIKE ?",
                                      (f"ev:{event_id}", f"ev:{event_id}:%")).fetchall()
                old_targets = {}
                single_target_channels = set()
                for row in legacy:
                    old_targets.setdefault(row["channel_id"], set()).add(row["target"])
                    if row["dedup_key"] == f"ev:{event_id}:{row['channel_id']}":
                        single_target_channels.add(row["channel_id"])
                routes = [route for route in routes
                          if (payload.get("_notification_deferred_no_channels")
                              or float(route.get("created_at") or 0) <= float(event["at"]))
                          and (route["channel_id"] not in single_target_channels
                               or route["target"] in old_targets[route["channel_id"]])]
                legacy_default = [row for row in legacy if not row["channel_id"]]
                if not any(route["channel_id"] for route in routes) and legacy_default:
                    routes = [{"suffix": "", "target": legacy_default[0]["target"], "channel": "qq", "channel_id": ""}]
            plan = [{key: route[key] for key in ("suffix", "target", "channel", "channel_id")}
                    for route in routes]
            # 无启用渠道时不落快照：事件留在 Ayana，待配置渠道后由补偿再派发
            if event and plan:
                payload["_notification_routes"] = plan
                conn.execute("UPDATE events SET payload_json=? WHERE id=?",
                             (json.dumps(payload, ensure_ascii=False), event_id))
            elif establish and event and not routes and not self._enabled_channels():
                payload["_notification_deferred_no_channels"] = True
                conn.execute("UPDATE events SET payload_json=? WHERE id=?",
                             (json.dumps(payload, ensure_ascii=False), event_id))
            return plan

    def _route_exists(self, event_id: int | str, route: dict[str, str]) -> bool:
        # Include legacy short keys: target count changes must never duplicate delivery.
        return bool(self.db.query_one(
            "SELECT 1 FROM notification_outbox WHERE target=? AND ("
            " (dedup_key LIKE ? AND channel_id=?)"
            " OR (dedup_key=? AND channel_id='' AND channel=?)) LIMIT 1",
            (route["target"], f"ev:{event_id}:%", route["channel_id"],
             f"ev:{event_id}", route["channel"]),
        ))

    def _enqueue_plan(self, event_id: int | str, body: str, routes: list[dict[str, str]]) -> bool:
        any_ok = False
        with self.db.tx():
            for route in routes:
                if self._route_exists(event_id, route):
                    any_ok = any_ok or bool(route["target"])
                    continue
                ok = self._insert_outbox(
                    dedup_key=f"ev:{event_id}{route['suffix']}",
                    target=route["target"], body=body, channel=route["channel"],
                    channel_id=route["channel_id"], strict=True,
                )
                any_ok = any_ok or ok
        return any_ok

    def enqueue_for_event(self, event_id: int | str, *, body: str, typ: str = "") -> bool:
        """Atomically establish all channel/target obligations with idempotent keys."""
        try:
            event = self.db.query_one("SELECT payload_json FROM events WHERE id=?", (event_id,))
            payload = json.loads(event["payload_json"] or "{}") if event else {}
            if isinstance(payload, dict) and isinstance(payload.get("body"), str) and payload["body"]:
                body = payload["body"]
            return self._enqueue_plan(event_id, body, self._event_plan(event_id, establish=True))
        except Exception:
            return False

    def _fallback_body(self, r: dict) -> str:
        """事件没带 body 时的人类可读兜底（禁止再吐 event_type + 内部 ID）。"""
        row = dict(r) if not isinstance(r, dict) else r
        typ = str(row.get("type") or "")
        inc_id = str(row.get("incident_id") or "")
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,)) if inc_id else None
        if inc:
            d = dict(inc)
            try:
                from .fmt import fmt_incident_open, fmt_incident_resolved

                if typ == "incident_resolved":
                    return fmt_incident_resolved(d)
                return fmt_incident_open(
                    d,
                    at=float(row.get("at") or 0) or None,
                    refire=typ in ("incident_reopened", "incident_refired"),
                )
            except Exception:
                pass
        zh = {"incident_opened": "发现异常", "incident_reopened": "告警复发",
              "incident_resolved": "已恢复", "verified_recovered": "验证通过"}
        title = (dict(inc).get("title") if inc else "") or ""
        return f"{zh.get(typ, '事件更新')}\n{title}".strip()

    def compensate_missing(self, limit: int = 100) -> int:
        """Repair missing obligations per channel/target, including partial fanout."""
        placeholders = ",".join("?" for _ in LIFECYCLE_TYPES)
        n = 0
        cursor = 0
        while n < limit:
            rows = self.db.query(
                f"SELECT id AS ev_id,type,payload_json,incident_id,at FROM events"
                f" WHERE type IN ({placeholders}) AND id>? ORDER BY id LIMIT 100",
                (*LIFECYCLE_TYPES, cursor),
            )
            if not rows:
                break
            for r in rows:
                cursor = r["ev_id"]
                try:
                    plan = self._event_plan(cursor)
                    if all(self._route_exists(cursor, route) for route in plan):
                        continue
                    try:
                        payload = json.loads(r["payload_json"] or "{}")
                    except (TypeError, ValueError):
                        payload = {}
                    if not isinstance(payload, dict):
                        payload = {}
                    body = payload.get("body") or self._fallback_body(r)
                    self._enqueue_plan(cursor, body, plan)
                    if all(self._route_exists(cursor, route) for route in plan):
                        n += 1
                except Exception:
                    return n
                if n >= limit:
                    break
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
            if (d.get("dedup_key") or "").startswith("ev:"):
                event_id = d["dedup_key"].split(":", 2)[1]
                event = self.db.query_one("SELECT * FROM events WHERE id=?", (event_id,))
                try:
                    payload = json.loads(event["payload_json"] or "{}") if event else {}
                except (TypeError, ValueError):
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}
                if payload.get("_notification_suppressed") or not self._event_is_actionable(event, payload):
                    self.db.execute("UPDATE notification_outbox SET state='cancelled',last_error='obsolete_request'"
                                    " WHERE id=? AND state='pending'", (rid,))
                    continue
                if event and event["type"] == "agent_waiting" and payload.get("body"):
                    d["body"] = payload["body"]
                    self.db.execute("UPDATE notification_outbox SET body=? WHERE id=? AND state='pending'",
                                    (d["body"], rid))
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
