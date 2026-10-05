"""SQLite 持久化：schema、迁移、短事务写入通道。"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA_VERSION = 1

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL DEFAULT '',
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  is_admin INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at REAL
);

CREATE TABLE IF NOT EXISTS web_sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  ua TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  at REAL NOT NULL,
  ok INTEGER NOT NULL,
  ip TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  read_alias TEXT NOT NULL UNIQUE,
  write_alias TEXT NOT NULL UNIQUE,
  expected_host_id TEXT NOT NULL DEFAULT '',
  host_id_verified_at REAL,
  prom_asset TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  notes TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS objects (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, -- service|container|port|probe|filesystem
  name TEXT NOT NULL,
  unit TEXT NOT NULL DEFAULT '',
  container TEXT NOT NULL DEFAULT '',
  port INTEGER,
  protocol TEXT NOT NULL DEFAULT '',
  external_probe TEXT NOT NULL DEFAULT '',
  auto_recover INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  UNIQUE(asset_id, kind, name)
);

CREATE TABLE IF NOT EXISTS permissions (
  id INTEGER PRIMARY KEY,
  subject_type TEXT NOT NULL, -- web_user|qq_user|qq_group|auto_rule|llm
  subject_id TEXT NOT NULL,
  asset_id TEXT NOT NULL DEFAULT '*',
  capability TEXT NOT NULL,
  object_id TEXT NOT NULL DEFAULT '*',
  allow INTEGER NOT NULL DEFAULT 0,
  require_approval INTEGER NOT NULL DEFAULT 1,
  auto_allowed INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  UNIQUE(subject_type, subject_id, asset_id, capability, object_id)
);

CREATE TABLE IF NOT EXISTS config_versions (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at REAL NOT NULL,
  created_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY,
  at REAL NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  entry TEXT NOT NULL,
  asset_id TEXT NOT NULL DEFAULT '',
  object_id TEXT NOT NULL DEFAULT '',
  action_id TEXT NOT NULL DEFAULT '',
  detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS alert_episodes (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  starts_at_norm TEXT NOT NULL,
  alertname TEXT NOT NULL,
  status TEXT NOT NULL, -- firing|resolved
  asset_id TEXT NOT NULL DEFAULT '',
  object_id TEXT NOT NULL DEFAULT '',
  incident_id TEXT NOT NULL DEFAULT '',
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  receive_count INTEGER NOT NULL DEFAULT 1,
  labels_json TEXT NOT NULL DEFAULT '{}',
  annotations_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(source_id, fingerprint, starts_at_norm)
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  asset_id TEXT NOT NULL DEFAULT '',
  object_id TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'warning',
  status TEXT NOT NULL DEFAULT 'open', -- open|resolved|closed
  stage TEXT NOT NULL DEFAULT 'pending', -- pending|investigating|awaiting_approval|executing|verifying|watching|done
  need_human INTEGER NOT NULL DEFAULT 0,
  need_human_reason TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  resolved_at REAL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  incident_id TEXT NOT NULL DEFAULT '',
  at REAL NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS investigations (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL DEFAULT '',
  asset_id TEXT NOT NULL,
  object_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  conclusion TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  finished_at REAL
);

CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL DEFAULT '',
  asset_id TEXT NOT NULL,
  object_id TEXT NOT NULL DEFAULT '',
  capability TEXT NOT NULL,
  params_json TEXT NOT NULL DEFAULT '{}',
  reason TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'proposed',
  -- proposed|approved|dispatched|success|failure|unknown|cancelled|expired
  proposer_type TEXT NOT NULL DEFAULT '',
  proposer_id TEXT NOT NULL DEFAULT '',
  approver_type TEXT NOT NULL DEFAULT '',
  approver_id TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  approved_at REAL,
  dispatched_at REAL,
  finished_at REAL,
  exec_account TEXT NOT NULL DEFAULT '',
  policy_snapshot_json TEXT NOT NULL DEFAULT '{}',
  result_detail TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS verifications (
  id TEXT PRIMARY KEY,
  action_id TEXT NOT NULL DEFAULT '',
  incident_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', -- pending|passed|failed|inconclusive
  criteria_json TEXT NOT NULL DEFAULT '{}',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  note TEXT NOT NULL DEFAULT '',
  started_at REAL NOT NULL,
  finished_at REAL
);

CREATE TABLE IF NOT EXISTS notification_outbox (
  id TEXT PRIMARY KEY,
  dedup_key TEXT NOT NULL UNIQUE,
  channel TEXT NOT NULL,
  target TEXT NOT NULL,
  body TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  tries INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  last_try_at REAL NOT NULL DEFAULT 0,
  next_try_at REAL NOT NULL DEFAULT 0,
  sent_at REAL
);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL DEFAULT 'pending',
  due_at REAL NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_episodes_incident ON alert_episodes(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id, at);
CREATE INDEX IF NOT EXISTS idx_actions_state ON actions(state, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
CREATE INDEX IF NOT EXISTS idx_outbox_state ON notification_outbox(state, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state, due_at);
"""


def now() -> float:
    return time.time()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Database:
    """单写者短事务；事务内不做网络 IO。"""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=5.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            finally:
                self._local.conn = None

    def _init_schema(self) -> None:
        conn = self._connect()
        with self._write_lock:
            conn.executescript(SCHEMA)
            # 轻量迁移：补齐缺失列
            cols = [r[1] for r in conn.execute("PRAGMA table_info(notification_outbox)")]
            if cols and "last_try_at" not in cols:
                conn.execute(
                    "ALTER TABLE notification_outbox ADD COLUMN last_try_at REAL NOT NULL DEFAULT 0"
                )
            if cols and "next_try_at" not in cols:
                conn.execute(
                    "ALTER TABLE notification_outbox ADD COLUMN next_try_at REAL NOT NULL DEFAULT 0"
                )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            conn.commit()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        with self._write_lock:
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        conn = self._connect()
        with self._write_lock:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur

    def query(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        conn = self._connect()
        return list(conn.execute(sql, params))

    def query_one(self, sql: str, params: tuple | dict = ()) -> sqlite3.Row | None:
        conn = self._connect()
        return conn.execute(sql, params).fetchone()

    # -- 便捷 --

    def audit(
        self,
        actor_type: str,
        actor_id: str,
        entry: str,
        *,
        asset_id: str = "",
        object_id: str = "",
        action_id: str = "",
        detail: dict | None = None,
    ) -> None:
        self.execute(
            "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
            " action_id, detail_json) VALUES(?,?,?,?,?,?,?,?)",
            (
                now(),
                actor_type,
                actor_id,
                entry,
                asset_id,
                object_id,
                action_id,
                json.dumps(detail or {}, ensure_ascii=False),
            ),
        )

    def event(
        self,
        type_: str,
        title: str = "",
        incident_id: str = "",
        payload: dict | None = None,
    ) -> None:
        self.execute(
            "INSERT INTO events(incident_id, at, type, title, payload_json) VALUES(?,?,?,?,?)",
            (incident_id, now(), type_, title, json.dumps(payload or {}, ensure_ascii=False)),
        )

    def snapshot_config(self, kind: str, payload: dict, created_by: str = "") -> None:
        self.execute(
            "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
            " VALUES(?,?,?,?)",
            (kind, json.dumps(payload, ensure_ascii=False), now(), created_by),
        )
