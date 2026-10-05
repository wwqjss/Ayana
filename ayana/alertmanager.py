"""Alertmanager webhook 接收与状态对账。"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from .db import Database, new_id, now

MAX_ALERTS_PER_HOOK = 200


def fingerprint_of(labels: dict) -> str:
    raw = json.dumps(labels, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def normalize_starts_at(starts_at: str) -> str:
    return (starts_at or "").strip() or "unknown"


class AlertIngest:
    def __init__(self, db: Database, source_id: str = "alertmanager", incidents=None, notifier=None):
        self.db = db
        self.source_id = source_id
        self._incidents = incidents
        self._notifier = notifier

    def set_incidents(self, incidents) -> None:
        self._incidents = incidents

    def set_notifier(self, notifier) -> None:
        self._notifier = notifier

    def _row_dict(self, row) -> dict:
        return dict(row) if row is not None else {}

    def _sync_incident(self, episode_id: str) -> None:
        """把 episode 同步到 Incident；转换与通知义务尽量同事务。

        opened 仅在真正新建/重开 Incident 时发出，不随 episode 附加重复发。
        """
        if not self._incidents:
            return
        try:
            ep = self._row_dict(
                self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (episode_id,))
            )
            if not ep:
                return
            if not ep.get("incident_id"):
                before_open = self.db.query_one(
                    "SELECT COUNT(*) AS n FROM incidents WHERE status='open'"
                    " AND asset_id=? AND object_id=?",
                    (ep.get("asset_id") or "", ep.get("object_id") or ""),
                )
                inc_id = self._incidents.upsert_from_episode(episode_id)
                ep = self._row_dict(
                    self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (episode_id,))
                )
                after_open = self.db.query_one(
                    "SELECT COUNT(*) AS n FROM incidents WHERE status='open'"
                    " AND asset_id=? AND object_id=?",
                    (ep.get("asset_id") or "", ep.get("object_id") or ""),
                )
                # 仅当确实新打开了 Incident 才通知
                if inc_id and (not before_open or after_open["n"] > before_open["n"]):
                    self._notify_incident(inc_id, "opened", episode_id=episode_id)
            if ep.get("status") == "resolved" and ep.get("incident_id"):
                before = self._row_dict(
                    self.db.query_one(
                        "SELECT status FROM incidents WHERE id=?", (ep["incident_id"],)
                    )
                )
                self._incidents.on_episode_resolved(episode_id)
                after = self._row_dict(
                    self.db.query_one(
                        "SELECT status FROM incidents WHERE id=?", (ep["incident_id"],)
                    )
                )
                if before.get("status") == "open" and after.get("status") == "resolved":
                    self._notify_incident(ep["incident_id"], "resolved", episode_id=episode_id)
        except Exception:
            pass

    def _notify_incident(self, inc_id: str, typ: str, *, episode_id: str = "") -> None:
        """以生命周期 Event 为源建立通知义务（幂等 ev:<id>）。"""
        if not self._notifier:
            return
        try:
            event_type = {
                "opened": "incident_opened",
                "reopened": "incident_reopened",
                "resolved": "incident_resolved",
            }.get(typ, f"incident_{typ}")
            ev = self.db.query_one(
                "SELECT id FROM events WHERE incident_id=? AND type=?"
                " ORDER BY id DESC LIMIT 1",
                (inc_id, event_type),
            )
            if not ev:
                return
            inc = self._row_dict(
                self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
            )
            body = f"[Ayana] {inc.get('title','')}\n{inc_id} {typ}"
            self._notifier.enqueue_for_event(ev["id"], body=body, typ=typ)
        except Exception:
            pass

    def ingest_webhook(self, payload: dict, *, received_at: float | None = None) -> dict[str, Any]:
        alerts = payload.get("alerts") or []
        if not isinstance(alerts, list):
            raise ValueError("alerts must be list")
        if len(alerts) > MAX_ALERTS_PER_HOOK:
            raise ValueError(f"too many alerts: {len(alerts)}")
        t = received_at or now()
        created = 0
        updated = 0
        episodes: list[str] = []
        with self.db.tx() as conn:
            for a in alerts:
                if not isinstance(a, dict):
                    continue
                labels = a.get("labels") or {}
                annotations = a.get("annotations") or {}
                status = (a.get("status") or "firing").lower()
                if status not in ("firing", "resolved"):
                    status = "firing"
                fp = labels.get("fingerprint") or fingerprint_of(labels)
                starts = normalize_starts_at(a.get("startsAt"))
                alertname = labels.get("alertname") or "unknown"
                asset_id = labels.get("asset") or ""
                obj_name = labels.get("service") or ""

                row = conn.execute(
                    "SELECT * FROM alert_episodes WHERE source_id=? AND fingerprint=?"
                    " AND starts_at_norm=?",
                    (self.source_id, fp, starts),
                ).fetchone()
                if row:
                    row_d = dict(row)
                    new_status = status
                    if row_d["status"] == "resolved" and status == "firing":
                        new_status = "resolved"
                    conn.execute(
                        "UPDATE alert_episodes SET last_seen=?, receive_count=receive_count+1,"
                        " status=?, annotations_json=?, labels_json=? WHERE id=?",
                        (
                            t,
                            new_status,
                            json.dumps(annotations, ensure_ascii=False),
                            json.dumps(labels, ensure_ascii=False),
                            row_d["id"],
                        ),
                    )
                    updated += 1
                    episodes.append(row_d["id"])
                    if new_status == "resolved" and row_d["status"] != "resolved":
                        conn.execute(
                            "INSERT INTO events(incident_id, at, type, title, payload_json)"
                            " VALUES(?,?,?,?,?)",
                            (
                                "",
                                now(),
                                "alert_resolved",
                                f"{alertname} resolved",
                                json.dumps(
                                    {"alertname": alertname, "asset": asset_id, "episode_id": row_d["id"]},
                                    ensure_ascii=False,
                                ),
                            ),
                        )
                else:
                    eid = new_id("ep")
                    conn.execute(
                        "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm,"
                        " alertname, status, asset_id, object_id, first_seen, last_seen,"
                        " receive_count, labels_json, annotations_json)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            eid,
                            self.source_id,
                            fp,
                            starts,
                            alertname,
                            status,
                            asset_id,
                            obj_name,
                            t,
                            t,
                            1,
                            json.dumps(labels, ensure_ascii=False),
                            json.dumps(annotations, ensure_ascii=False),
                        ),
                    )
                    created += 1
                    episodes.append(eid)
                    conn.execute(
                        "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
                        (
                            "",
                            now(),
                            "alert_fired",
                            f"{alertname} firing",
                            json.dumps(
                                {
                                    "alertname": alertname,
                                    "asset": asset_id,
                                    "labels": labels,
                                    "episode_id": eid,
                                },
                                ensure_ascii=False,
                            ),
                        ),
                    )
        for eid in episodes:
            self._sync_incident(eid)
        return {"created": created, "updated": updated, "episodes": episodes}

    def reconcile(self, alerts: list[dict]) -> dict[str, Any]:
        """对账：补入仍 active 且本地缺失的告警；不把「没看到」当恢复。"""
        seen = 0
        imported = 0
        t = now()
        for a in alerts:
            labels = a.get("labels") or {}
            fp = labels.get("fingerprint") or fingerprint_of(labels)
            starts = normalize_starts_at(a.get("startsAt"))
            status_obj = a.get("status") if isinstance(a.get("status"), dict) else {}
            am_state = status_obj.get("state") or a.get("status") or "active"
            am_firing = am_state in ("active", "unprocessed", "suppressed")
            row = self.db.query_one(
                "SELECT id, status FROM alert_episodes WHERE source_id=? AND fingerprint=?"
                " AND starts_at_norm=?",
                (self.source_id, fp, starts),
            )
            if row:
                seen += 1
                continue
            if not am_firing:
                continue
            alertname = labels.get("alertname") or "unknown"
            eid = new_id("ep")
            self.db.execute(
                "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm,"
                " alertname, status, asset_id, object_id, first_seen, last_seen,"
                " receive_count, labels_json, annotations_json)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    eid,
                    self.source_id,
                    fp,
                    starts,
                    alertname,
                    "firing",
                    labels.get("asset") or "",
                    labels.get("service") or "",
                    t,
                    t,
                    1,
                    json.dumps(labels, ensure_ascii=False),
                    json.dumps(a.get("annotations") or {}, ensure_ascii=False),
                ),
            )
            imported += 1
            self._sync_incident(eid)
        return {"seen": seen, "imported": imported, "at": t}

    async def fetch_am_alerts(self, am_url: str, timeout: float = 8.0) -> list[dict]:
        import aiohttp

        url = am_url.rstrip("/") + "/api/v2/alerts"
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.get(url) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"AM http {resp.status}: {text[:200]}")
                return await resp.json()
