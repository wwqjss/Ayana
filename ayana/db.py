"""SQLite 持久化：schema、顺序迁移、短事务写入通道。

迁移语义（P1-06）：
- meta.schema_version 记录当前版本
- schema_migrations 记录已应用迁移（可审计）
- 迁移按版本顺序执行，中途失败不得标记完成
- 版本高于本程序支持 → 拒绝启动
- 新库直接初始化到当前版本；旧库按序升级
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

SCHEMA_VERSION = 3


class MigrationError(RuntimeError):
    """schema 迁移失败：不得以不确定状态继续启动。"""

    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.detail = message
        super().__init__(f"{code}: {message}" if message else code)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at REAL NOT NULL,
  checksum TEXT NOT NULL DEFAULT ''
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
  detail_json TEXT NOT NULL DEFAULT '{}',
  decision_id TEXT NOT NULL DEFAULT '',
  incident_id TEXT NOT NULL DEFAULT '',
  channel TEXT NOT NULL DEFAULT ''
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
  source_state TEXT NOT NULL DEFAULT 'firing',
  last_reconciled_at REAL,
  silenced INTEGER NOT NULL DEFAULT 0,
  inhibited INTEGER NOT NULL DEFAULT 0,
  source_health TEXT NOT NULL DEFAULT 'ok',
  problem_family TEXT NOT NULL DEFAULT '',
  quarantine_reason TEXT NOT NULL DEFAULT '',
  canonical_object TEXT NOT NULL DEFAULT '',
  UNIQUE(source_id, fingerprint, starts_at_norm)
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  asset_id TEXT NOT NULL DEFAULT '',
  object_id TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'warning',
  status TEXT NOT NULL DEFAULT 'open', -- open|resolved|closed
  stage TEXT NOT NULL DEFAULT 'pending', -- pending|investigating|awaiting_approval|executing|verifying|watching|done|need_human
  need_human INTEGER NOT NULL DEFAULT 0,
  need_human_reason TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  generation INTEGER NOT NULL DEFAULT 1,
  outcome TEXT NOT NULL DEFAULT '', -- recovered|unrecovered|unknown|closed_unverified|''
  resolution_basis TEXT NOT NULL DEFAULT '',
  closed_at REAL,
  close_reason TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  resolved_at REAL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  incident_id TEXT NOT NULL DEFAULT '',
  episode_id TEXT NOT NULL DEFAULT '',
  at REAL NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  source_state TEXT NOT NULL DEFAULT ''
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
  finished_at REAL,
  stop_reason TEXT NOT NULL DEFAULT '',
  facts_json TEXT NOT NULL DEFAULT '[]',
  hypotheses_json TEXT NOT NULL DEFAULT '[]',
  missing_json TEXT NOT NULL DEFAULT '[]',
  knowledge_refs_json TEXT NOT NULL DEFAULT '[]',
  knowledge_revision TEXT NOT NULL DEFAULT '',
  rounds INTEGER NOT NULL DEFAULT 0,
  tool_calls INTEGER NOT NULL DEFAULT 0,
  status_detail TEXT NOT NULL DEFAULT ''
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
  result_detail TEXT NOT NULL DEFAULT '',
  decision_channel TEXT NOT NULL DEFAULT '',
  decision_reason TEXT NOT NULL DEFAULT '',
  decided_at REAL,
  decision_snapshot_json TEXT NOT NULL DEFAULT '{}',
  adjudication TEXT NOT NULL DEFAULT '',
  adjudicated_at REAL,
  adjudication_reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS verifications (
  id TEXT PRIMARY KEY,
  action_id TEXT NOT NULL DEFAULT '',
  incident_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', -- pending|passed|failed|inconclusive|unknown
  criteria_json TEXT NOT NULL DEFAULT '{}',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  note TEXT NOT NULL DEFAULT '',
  profile_id TEXT NOT NULL DEFAULT '',
  generation INTEGER NOT NULL DEFAULT 1,
  deadline_at REAL,
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

CREATE TABLE IF NOT EXISTS work_items (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  identity TEXT NOT NULL,
  incident_id TEXT NOT NULL DEFAULT '',
  action_id TEXT NOT NULL DEFAULT '',
  generation INTEGER NOT NULL DEFAULT 1,
  state TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  due_at REAL,
  deadline_at REAL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(kind, identity)
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

CREATE TABLE IF NOT EXISTS object_knowledge (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL,
  object_name TEXT NOT NULL,
  object_kind TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL DEFAULT '',
  purpose TEXT NOT NULL DEFAULT '',
  related_objects TEXT NOT NULL DEFAULT '[]',
  dependencies TEXT NOT NULL DEFAULT '[]',
  expected_state TEXT NOT NULL DEFAULT '',
  failure_meaning TEXT NOT NULL DEFAULT '',
  investigation_hints TEXT NOT NULL DEFAULT '[]',
  remediation_hints TEXT NOT NULL DEFAULT '[]',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(asset_id, object_name)
);

CREATE TABLE IF NOT EXISTS global_stops (
  key TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT '',
  updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_episodes_incident ON alert_episodes(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id, at);
CREATE INDEX IF NOT EXISTS idx_actions_state ON actions(state, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
CREATE INDEX IF NOT EXISTS idx_outbox_state ON notification_outbox(state, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state, due_at);
CREATE INDEX IF NOT EXISTS idx_knowledge_asset ON object_knowledge(asset_id, object_name);
"""


def now() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# 顺序迁移（幂等；失败不标记完成）
# ---------------------------------------------------------------------------

def _add_columns(conn: sqlite3.Connection, table: str, columns: list[tuple[str, str]]) -> None:
    existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    for name, ddl in columns:
        if name not in existing:
            conn.execute(ddl)


def _migrate_v1_baseline(conn: sqlite3.Connection) -> None:
    """v1：基础列补齐（0.1/0.2 → 0.3 旧库）。"""
    _add_columns(conn, "notification_outbox", [
        ("last_try_at", "ALTER TABLE notification_outbox ADD COLUMN last_try_at REAL NOT NULL DEFAULT 0"),
        ("next_try_at", "ALTER TABLE notification_outbox ADD COLUMN next_try_at REAL NOT NULL DEFAULT 0"),
    ])
    _add_columns(conn, "actions", [
        ("mode", "ALTER TABLE actions ADD COLUMN mode TEXT NOT NULL DEFAULT 'manual'"),
        ("runbook_id", "ALTER TABLE actions ADD COLUMN runbook_id TEXT NOT NULL DEFAULT ''"),
        ("runbook_rev", "ALTER TABLE actions ADD COLUMN runbook_rev TEXT NOT NULL DEFAULT ''"),
        ("template_id", "ALTER TABLE actions ADD COLUMN template_id TEXT NOT NULL DEFAULT ''"),
        ("object_ref", "ALTER TABLE actions ADD COLUMN object_ref TEXT NOT NULL DEFAULT ''"),
        ("params_digest", "ALTER TABLE actions ADD COLUMN params_digest TEXT NOT NULL DEFAULT ''"),
        ("approval_deadline", "ALTER TABLE actions ADD COLUMN approval_deadline REAL"),
        ("budget_claimed_at", "ALTER TABLE actions ADD COLUMN budget_claimed_at REAL"),
        ("precondition_json", "ALTER TABLE actions ADD COLUMN precondition_json TEXT NOT NULL DEFAULT '{}'"),
    ])
    _add_columns(conn, "incidents", [
        ("generation", "ALTER TABLE incidents ADD COLUMN generation INTEGER NOT NULL DEFAULT 1"),
        ("outcome", "ALTER TABLE incidents ADD COLUMN outcome TEXT NOT NULL DEFAULT ''"),
        ("resolution_basis", "ALTER TABLE incidents ADD COLUMN resolution_basis TEXT NOT NULL DEFAULT ''"),
        ("closed_at", "ALTER TABLE incidents ADD COLUMN closed_at REAL"),
        ("close_reason", "ALTER TABLE incidents ADD COLUMN close_reason TEXT NOT NULL DEFAULT ''"),
    ])
    _add_columns(conn, "verifications", [
        ("profile_id", "ALTER TABLE verifications ADD COLUMN profile_id TEXT NOT NULL DEFAULT ''"),
        ("generation", "ALTER TABLE verifications ADD COLUMN generation INTEGER NOT NULL DEFAULT 1"),
        ("deadline_at", "ALTER TABLE verifications ADD COLUMN deadline_at REAL"),
    ])


def _migrate_v2_p0_p1_columns(conn: sqlite3.Connection) -> None:
    """v2：Phase D/E 列（审批记录、episode source、investigation 有限循环）。"""
    _add_columns(conn, "actions", [
        ("decision_channel", "ALTER TABLE actions ADD COLUMN decision_channel TEXT NOT NULL DEFAULT ''"),
        ("decision_reason", "ALTER TABLE actions ADD COLUMN decision_reason TEXT NOT NULL DEFAULT ''"),
        ("decided_at", "ALTER TABLE actions ADD COLUMN decided_at REAL"),
        ("decision_snapshot_json", "ALTER TABLE actions ADD COLUMN decision_snapshot_json TEXT NOT NULL DEFAULT '{}'"),
        ("adjudication", "ALTER TABLE actions ADD COLUMN adjudication TEXT NOT NULL DEFAULT ''"),
        ("adjudicated_at", "ALTER TABLE actions ADD COLUMN adjudicated_at REAL"),
        ("adjudication_reason", "ALTER TABLE actions ADD COLUMN adjudication_reason TEXT NOT NULL DEFAULT ''"),
    ])
    _add_columns(conn, "alert_episodes", [
        ("source_state", "ALTER TABLE alert_episodes ADD COLUMN source_state TEXT NOT NULL DEFAULT 'firing'"),
        ("last_reconciled_at", "ALTER TABLE alert_episodes ADD COLUMN last_reconciled_at REAL"),
        ("silenced", "ALTER TABLE alert_episodes ADD COLUMN silenced INTEGER NOT NULL DEFAULT 0"),
        ("inhibited", "ALTER TABLE alert_episodes ADD COLUMN inhibited INTEGER NOT NULL DEFAULT 0"),
        ("source_health", "ALTER TABLE alert_episodes ADD COLUMN source_health TEXT NOT NULL DEFAULT 'ok'"),
        ("problem_family", "ALTER TABLE alert_episodes ADD COLUMN problem_family TEXT NOT NULL DEFAULT ''"),
        ("quarantine_reason", "ALTER TABLE alert_episodes ADD COLUMN quarantine_reason TEXT NOT NULL DEFAULT ''"),
        ("canonical_object", "ALTER TABLE alert_episodes ADD COLUMN canonical_object TEXT NOT NULL DEFAULT ''"),
    ])
    _add_columns(conn, "events", [
        ("episode_id", "ALTER TABLE events ADD COLUMN episode_id TEXT NOT NULL DEFAULT ''"),
        ("source_state", "ALTER TABLE events ADD COLUMN source_state TEXT NOT NULL DEFAULT ''"),
    ])
    _add_columns(conn, "investigations", [
        ("stop_reason", "ALTER TABLE investigations ADD COLUMN stop_reason TEXT NOT NULL DEFAULT ''"),
        ("facts_json", "ALTER TABLE investigations ADD COLUMN facts_json TEXT NOT NULL DEFAULT '[]'"),
        ("hypotheses_json", "ALTER TABLE investigations ADD COLUMN hypotheses_json TEXT NOT NULL DEFAULT '[]'"),
        ("missing_json", "ALTER TABLE investigations ADD COLUMN missing_json TEXT NOT NULL DEFAULT '[]'"),
        ("knowledge_refs_json", "ALTER TABLE investigations ADD COLUMN knowledge_refs_json TEXT NOT NULL DEFAULT '[]'"),
        ("knowledge_revision", "ALTER TABLE investigations ADD COLUMN knowledge_revision TEXT NOT NULL DEFAULT ''"),
        ("rounds", "ALTER TABLE investigations ADD COLUMN rounds INTEGER NOT NULL DEFAULT 0"),
        ("tool_calls", "ALTER TABLE investigations ADD COLUMN tool_calls INTEGER NOT NULL DEFAULT 0"),
        ("status_detail", "ALTER TABLE investigations ADD COLUMN status_detail TEXT NOT NULL DEFAULT ''"),
    ])


def _migrate_v3_recovery_columns(conn: sqlite3.Connection) -> None:
    """v3：Phase F 中断恢复 / adjudication / durable work。"""
    _add_columns(conn, "actions", [
        ("adjudication", "ALTER TABLE actions ADD COLUMN adjudication TEXT NOT NULL DEFAULT ''"),
        ("adjudicated_at", "ALTER TABLE actions ADD COLUMN adjudicated_at REAL"),
        ("adjudication_reason", "ALTER TABLE actions ADD COLUMN adjudication_reason TEXT NOT NULL DEFAULT ''"),
    ])
    _add_columns(conn, "investigations", [
        ("status_detail", "ALTER TABLE investigations ADD COLUMN status_detail TEXT NOT NULL DEFAULT ''"),
    ])
    # durable work 义务表（最小，非通用 scheduler）
    conn.execute(
        "CREATE TABLE IF NOT EXISTS work_items ("
        " id TEXT PRIMARY KEY,"
        " kind TEXT NOT NULL,"
        " identity TEXT NOT NULL,"
        " incident_id TEXT NOT NULL DEFAULT '',"
        " action_id TEXT NOT NULL DEFAULT '',"
        " generation INTEGER NOT NULL DEFAULT 1,"
        " state TEXT NOT NULL DEFAULT 'pending',"
        " attempts INTEGER NOT NULL DEFAULT 0,"
        " due_at REAL,"
        " deadline_at REAL,"
        " last_error TEXT NOT NULL DEFAULT '',"
        " created_at REAL NOT NULL,"
        " updated_at REAL NOT NULL,"
        " UNIQUE(kind, identity)"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_work_state ON work_items(state, due_at)"
    )
    # 审计补强列（decision_id 等）
    _add_columns(conn, "audit_log", [
        ("decision_id", "ALTER TABLE audit_log ADD COLUMN decision_id TEXT NOT NULL DEFAULT ''"),
        ("incident_id", "ALTER TABLE audit_log ADD COLUMN incident_id TEXT NOT NULL DEFAULT ''"),
        ("channel", "ALTER TABLE audit_log ADD COLUMN channel TEXT NOT NULL DEFAULT ''"),
    ])


_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    1: _migrate_v1_baseline,
    2: _migrate_v2_p0_p1_columns,
    3: _migrate_v3_recovery_columns,
}

_MIGRATION_NAMES = {
    1: "baseline_columns",
    2: "p0_p1_columns",
    3: "recovery_and_work_items",
}


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Database:
    """单写者短事务；事务内不做网络 IO。"""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        try:
            self._init_schema()
        except Exception:
            # 迁移失败：释放连接，避免文件锁残留
            try:
                self.close()
            except Exception:
                pass
            raise

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
            conn.commit()
            self._run_migrations(conn)
            conn.execute(
                "INSERT OR IGNORE INTO global_stops(key, enabled, reason, actor, updated_at)"
                " VALUES('auto_dispatch', 0, '', 'system', 0)"
            )
            conn.commit()

    # ---- 顺序迁移 ----

    def _current_version(self, conn: sqlite3.Connection) -> int:
        row = conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()
        if row:
            try:
                return int(row["value"])
            except Exception:
                return 0
        return 0

    def _run_migrations(self, conn: sqlite3.Connection) -> None:
        cur = self._current_version(conn)
        if cur > SCHEMA_VERSION:
            raise MigrationError(
                "future_schema",
                f"db schema_version={cur} > supported={SCHEMA_VERSION}; refuse to start",
            )
        if cur == SCHEMA_VERSION:
            return
        for version in range(cur + 1, SCHEMA_VERSION + 1):
            fn = _MIGRATIONS.get(version)
            if fn is None:
                raise MigrationError("missing_migration", f"no migration for v{version}")
            try:
                fn(conn)
            except MigrationError:
                raise
            except Exception as e:
                # 中途失败：不标记完成、不静默继续
                raise MigrationError(
                    "migration_failed", f"v{version} {_MIGRATION_NAMES.get(version, '')}: {e}"
                ) from e
            conn.execute(
                "INSERT OR REPLACE INTO schema_migrations(version, name, applied_at, checksum)"
                " VALUES(?,?,?,?)",
                (
                    version,
                    _MIGRATION_NAMES.get(version, f"v{version}"),
                    now(),
                    "",
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(version),),
            )
            conn.commit()

    def schema_version(self) -> int:
        return self._current_version(self._connect())

    def migration_status(self) -> dict[str, Any]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT version, name, applied_at FROM schema_migrations ORDER BY version"
        ).fetchall()
        return {
            "current": self._current_version(conn),
            "supported": SCHEMA_VERSION,
            "applied": [dict(r) for r in rows],
        }

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
        *,
        episode_id: str = "",
        source_state: str = "",
    ) -> None:
        self.execute(
            "INSERT INTO events(incident_id, episode_id, at, type, title, payload_json,"
            " source_state) VALUES(?,?,?,?,?,?,?)",
            (
                incident_id,
                episode_id,
                now(),
                type_,
                title,
                json.dumps(payload or {}, ensure_ascii=False),
                source_state,
            ),
        )

    def snapshot_config(self, kind: str, payload: dict, created_by: str = "") -> None:
        self.execute(
            "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
            " VALUES(?,?,?,?)",
            (kind, json.dumps(payload, ensure_ascii=False), now(), created_by),
        )
