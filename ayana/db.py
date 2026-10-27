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

SCHEMA_VERSION = 25


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
  must_change_password INTEGER NOT NULL DEFAULT 0,
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

-- SSH 凭据：密文入库；主密钥在 secrets（ssh_credential_key），与 DB 分离
CREATE TABLE IF NOT EXISTS ssh_credentials (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL, -- password|private_key
  secret_enc BLOB NOT NULL,
  public_key TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  rotated_at REAL
);

-- SSH 连接端点：读/写账户分离；host_key_sha256 信任链
CREATE TABLE IF NOT EXISTS ssh_endpoints (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  role TEXT NOT NULL, -- read|write
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  username TEXT NOT NULL,
  credential_id TEXT NOT NULL DEFAULT '',
  host_key_sha256 TEXT NOT NULL DEFAULT '',
  host_key_line TEXT NOT NULL DEFAULT '',
  host_key_trusted_at REAL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(asset_id, role)
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
  decision_id TEXT NOT NULL DEFAULT '',
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

-- work_items: 无写入点，仅 web.py 一处 COUNT 读取；保留兼容旧库，勿写入
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

-- Agent 权限上限（用户可配）：强制 ⊆ capabilities 源码目录；后端在 Policy 判定时执行
CREATE TABLE IF NOT EXISTS agent_ceiling (
  capability TEXT PRIMARY KEY,
  allowed INTEGER NOT NULL DEFAULT 1,
  allow_auto INTEGER NOT NULL DEFAULT 0,
  updated_at REAL NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS permission_changes (
  id TEXT PRIMARY KEY,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  asset_id TEXT NOT NULL DEFAULT '*',
  object_id TEXT NOT NULL DEFAULT '*',
  to_allow INTEGER NOT NULL DEFAULT 0,
  to_require_approval INTEGER NOT NULL DEFAULT 1,
  to_auto_allowed INTEGER NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT '',
  incident_id TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'proposed',
  created_by TEXT NOT NULL DEFAULT '',
  created_channel TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  decided_by TEXT NOT NULL DEFAULT '',
  decided_channel TEXT NOT NULL DEFAULT '',
  decided_at REAL,
  totp_verified_at REAL,
  applied_at REAL,
  from_snapshot_json TEXT NOT NULL DEFAULT '{}',
  result_json TEXT NOT NULL DEFAULT '{}'
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


def _migrate_v4_agent_ceiling(conn: sqlite3.Connection) -> None:
    """v4：Agent 权限上限（用户可配，强制 ⊆ 源码能力目录）。"""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS agent_ceiling ("
        " capability TEXT PRIMARY KEY,"
        " allowed INTEGER NOT NULL DEFAULT 1,"
        " allow_auto INTEGER NOT NULL DEFAULT 0,"
        " updated_at REAL NOT NULL,"
        " updated_by TEXT NOT NULL DEFAULT ''"
        ")"
    )


def _migrate_v5_action_decision_id(conn: sqlite3.Connection) -> None:
    """v5：审批关联 —— actions.decision_id，与审计/PermissionChange 同语义。"""
    _add_columns(conn, "actions", [
        ("decision_id", "ALTER TABLE actions ADD COLUMN decision_id TEXT NOT NULL DEFAULT ''"),
    ])


def _migrate_v6_ssh_endpoints_credentials(conn: sqlite3.Connection) -> None:
    """v6：原生 SSH 资产端点与加密凭据。"""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ssh_credentials ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL DEFAULT '',"
        " kind TEXT NOT NULL,"
        " secret_enc BLOB NOT NULL,"
        " public_key TEXT NOT NULL DEFAULT '',"
        " created_at REAL NOT NULL,"
        " updated_at REAL NOT NULL,"
        " rotated_at REAL"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ssh_endpoints ("
        " id TEXT PRIMARY KEY,"
        " asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,"
        " role TEXT NOT NULL,"
        " host TEXT NOT NULL,"
        " port INTEGER NOT NULL DEFAULT 22,"
        " username TEXT NOT NULL,"
        " credential_id TEXT NOT NULL DEFAULT '',"
        " host_key_sha256 TEXT NOT NULL DEFAULT '',"
        " host_key_trusted_at REAL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " created_at REAL NOT NULL,"
        " updated_at REAL NOT NULL,"
        " UNIQUE(asset_id, role)"
        ")"
    )


def _migrate_v7_host_key_line(conn: sqlite3.Connection) -> None:
    """v7：保存 host 公钥原文，连接时写入 known_hosts。"""
    _add_columns(conn, "ssh_endpoints", [
        ("host_key_line", "ALTER TABLE ssh_endpoints ADD COLUMN host_key_line TEXT NOT NULL DEFAULT ''"),
    ])


def _migrate_v8_notify_channels(conn: sqlite3.Connection) -> None:
    """v8：多消息渠道 + outbox 按渠道独立状态。"""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notify_channels ("
        " id TEXT PRIMARY KEY,"
        " name TEXT NOT NULL,"
        " kind TEXT NOT NULL,"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " config_json TEXT NOT NULL DEFAULT '{}',"
        " secret_enc BLOB NOT NULL DEFAULT X'',"
        " created_at REAL NOT NULL,"
        " updated_at REAL NOT NULL,"
        " last_test_at REAL,"
        " last_test_ok INTEGER,"
        " last_test_error TEXT NOT NULL DEFAULT ''"
        ")"
    )
    _add_columns(conn, "notification_outbox", [
        ("channel_id", "ALTER TABLE notification_outbox ADD COLUMN channel_id TEXT NOT NULL DEFAULT ''"),
    ])


def _migrate_v9_aibot_seen_targets(conn: sqlite3.Connection) -> None:
    """v9：企微智能机器人已发现推送目标（群 chatid / 单聊 userid）。"""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS aibot_seen_targets ("
        " channel_id TEXT NOT NULL,"
        " target_id TEXT NOT NULL,"
        " chattype TEXT NOT NULL DEFAULT '',"
        " userid TEXT NOT NULL DEFAULT '',"
        " first_seen_at REAL NOT NULL,"
        " last_seen_at REAL NOT NULL,"
        " last_msgtype TEXT NOT NULL DEFAULT '',"
        " PRIMARY KEY (channel_id, target_id)"
        ")"
    )


def _migrate_v10_message_log(conn: sqlite3.Connection) -> None:
    """v10：消息记录（入站 + 机器人回复等非 outbox 出站）。

    通知 outbox 不复制，列表查询时与本表 UNION，避免重复写入。
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS message_log ("
        " id TEXT PRIMARY KEY,"
        " at REAL NOT NULL,"
        " direction TEXT NOT NULL,"
        " platform TEXT NOT NULL DEFAULT '',"
        " channel_kind TEXT NOT NULL DEFAULT '',"
        " channel_id TEXT NOT NULL DEFAULT '',"
        " channel_name TEXT NOT NULL DEFAULT '',"
        " sender TEXT NOT NULL DEFAULT '',"
        " target TEXT NOT NULL DEFAULT '',"
        " body TEXT NOT NULL DEFAULT '',"
        " state TEXT NOT NULL DEFAULT '',"
        " error TEXT NOT NULL DEFAULT '',"
        " replied INTEGER NOT NULL DEFAULT 0,"
        " reply_to TEXT NOT NULL DEFAULT '',"
        " reply_log_id TEXT NOT NULL DEFAULT '',"
        " detail_json TEXT NOT NULL DEFAULT '{}',"
        " outbox_id TEXT NOT NULL DEFAULT ''"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_msglog_at ON message_log(at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_msglog_dir ON message_log(direction, at)"
    )


def _migrate_v11_checks(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS checks ("
        " id TEXT PRIMARY KEY,"
        " asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,"
        " name TEXT NOT NULL DEFAULT '',"
        " kind TEXT NOT NULL,"
        " params_json TEXT NOT NULL DEFAULT '{}',"
        " expect_json TEXT NOT NULL DEFAULT '{}',"
        " interval_sec INTEGER NOT NULL DEFAULT 60,"
        " fail_threshold INTEGER NOT NULL DEFAULT 2,"
        " severity TEXT NOT NULL DEFAULT 'warning',"
        " enabled INTEGER NOT NULL DEFAULT 1,"
        " last_state TEXT NOT NULL DEFAULT 'unknown',"
        " last_ok INTEGER NOT NULL DEFAULT 0,"
        " last_at REAL NOT NULL DEFAULT 0,"
        " last_detail TEXT NOT NULL DEFAULT '',"
        " fail_streak INTEGER NOT NULL DEFAULT 0,"
        " created_at REAL NOT NULL,"
        " updated_at REAL NOT NULL,"
        " UNIQUE(asset_id, kind, name)"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS check_results ("
        " id INTEGER PRIMARY KEY,"
        " check_id TEXT NOT NULL,"
        " at REAL NOT NULL,"
        " ok INTEGER NOT NULL,"
        " state TEXT NOT NULL,"
        " detail TEXT NOT NULL DEFAULT ''"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_check_results ON check_results(check_id, at)"
    )


def _migrate_v12_asset_host(conn: sqlite3.Connection) -> None:
    """资产主 IP/主机名：用于自动填监控地址。"""
    try:
        conn.execute("ALTER TABLE assets ADD COLUMN host TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    # 从 SSH 端点回填（无端点则保持空串）
    conn.execute(
        "UPDATE assets SET host=COALESCE("
        " (SELECT host FROM ssh_endpoints"
        "  WHERE ssh_endpoints.asset_id=assets.id AND ssh_endpoints.enabled=1"
        "  ORDER BY CASE role WHEN 'write' THEN 0 ELSE 1 END LIMIT 1), '')"
        " WHERE host='' OR host IS NULL"
    )


def _migrate_v13_users_must_change_password(conn: sqlite3.Connection) -> None:
    """首登强制改密标记。"""
    _add_columns(conn, "users", [
        ("must_change_password", "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"),
    ])


def _migrate_v14_node_watch(conn: sqlite3.Connection) -> None:
    """节点守望：心跳对端状态 + 防重放 nonce。"""
    conn.executescript(
        """
CREATE TABLE IF NOT EXISTS node_watch_peers (
  node_id TEXT PRIMARY KEY,
  last_seq INTEGER NOT NULL DEFAULT 0,
  last_ts REAL NOT NULL DEFAULT 0,
  last_seen_at REAL,
  last_payload TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'unknown',
  incident_open INTEGER NOT NULL DEFAULT 0,
  last_alert_at REAL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS node_watch_nonces (
  nonce TEXT PRIMARY KEY,
  seen_at REAL NOT NULL
);
"""
    )


def _migrate_v15_ext_tasks(conn: sqlite3.Connection) -> None:
    """v15：外部事务（接入配置 / Token / 执行记录 / 失联标记）。"""
    conn.executescript(
        """
CREATE TABLE IF NOT EXISTS ext_transactions (
  id TEXT PRIMARY KEY,
  event_key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  source_label TEXT NOT NULL DEFAULT '',
  asset_id TEXT NOT NULL DEFAULT '',
  object_id TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  watch_mode TEXT NOT NULL DEFAULT 'off',
  grace_sec INTEGER NOT NULL DEFAULT 300,
  expect_interval_sec INTEGER NOT NULL DEFAULT 0,
  timeout_sec INTEGER NOT NULL DEFAULT 0,
  schedule_json TEXT NOT NULL DEFAULT '{}',
  alert_on_failure INTEGER NOT NULL DEFAULT 1,
  alert_on_recovery INTEGER NOT NULL DEFAULT 1,
  alert_on_timeout INTEGER NOT NULL DEFAULT 1,
  alert_on_missing INTEGER NOT NULL DEFAULT 1,
  alert_on_collector INTEGER NOT NULL DEFAULT 1,
  resolve_delay_sec INTEGER NOT NULL DEFAULT 0,
  pending_resolve_at REAL NOT NULL DEFAULT 0,
  last_status TEXT NOT NULL DEFAULT 'unknown',
  last_run_id TEXT NOT NULL DEFAULT '',
  last_report_at REAL NOT NULL DEFAULT 0,
  last_success_at REAL NOT NULL DEFAULT 0,
  last_failure_at REAL NOT NULL DEFAULT 0,
  open_incident_id TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS ext_tokens (
  id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_hint TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  revoked_at REAL,
  last_used_at REAL,
  rotated_from TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ext_runs (
  id TEXT PRIMARY KEY,
  transaction_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'warning',
  message TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  report_kind TEXT NOT NULL DEFAULT 'run',
  client_ts REAL,
  reported_at REAL NOT NULL,
  content_hash TEXT NOT NULL DEFAULT '',
  episode_id TEXT NOT NULL DEFAULT '',
  incident_id TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(transaction_id, run_id)
);

CREATE TABLE IF NOT EXISTS ext_watch_marks (
  transaction_id TEXT NOT NULL,
  mark_key TEXT NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY (transaction_id, mark_key)
);

CREATE INDEX IF NOT EXISTS idx_ext_runs_tx ON ext_runs(transaction_id, reported_at);
CREATE INDEX IF NOT EXISTS idx_ext_tokens_hash ON ext_tokens(token_hash);
"""
    )
    # 兼容已建库：补齐防抖列
    _add_columns(conn, "ext_transactions", [
        ("resolve_delay_sec", "ALTER TABLE ext_transactions ADD COLUMN resolve_delay_sec INTEGER NOT NULL DEFAULT 0"),
        ("pending_resolve_at", "ALTER TABLE ext_transactions ADD COLUMN pending_resolve_at REAL NOT NULL DEFAULT 0"),
    ])


def _migrate_v16_council(conn: sqlite3.Connection) -> None:
    """Persist immutable plans, independent review receipts and single-use grants."""
    conn.executescript("""
CREATE TABLE IF NOT EXISTS council_goals (
 id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), generation INTEGER NOT NULL,
 asset_id TEXT NOT NULL, object_id TEXT NOT NULL, repair_goal TEXT NOT NULL,
 consecutive_vetoes INTEGER NOT NULL DEFAULT 0, manual_required INTEGER NOT NULL DEFAULT 0,
 manual_reason TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, updated_at REAL NOT NULL,
 UNIQUE(incident_id,generation,asset_id,object_id,repair_goal)
);
CREATE TABLE IF NOT EXISTS council_plans (
 id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), generation INTEGER NOT NULL,
 goal_id TEXT NOT NULL REFERENCES council_goals(id), version INTEGER NOT NULL, digest TEXT NOT NULL,
 asset_id TEXT NOT NULL, object_id TEXT NOT NULL, canonical_object TEXT NOT NULL,
 plan_json TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'drafted',
 created_at REAL NOT NULL, expires_at REAL NOT NULL,
 UNIQUE(goal_id,version)
);
CREATE INDEX IF NOT EXISTS idx_council_plans_incident ON council_plans(incident_id,created_at);
CREATE TABLE IF NOT EXISTS council_reviews (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES council_plans(id), plan_digest TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('reviewer_kimi','reviewer_deepseek')),
 provider TEXT NOT NULL, model TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
 approve INTEGER, reason TEXT NOT NULL DEFAULT '', missing_json TEXT NOT NULL DEFAULT '[]',
 suggested_revision TEXT NOT NULL DEFAULT '', requested_at REAL NOT NULL,
 deadline_at REAL NOT NULL, finished_at REAL, UNIQUE(plan_id,role)
);
CREATE TABLE IF NOT EXISTS council_ballots (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE REFERENCES council_plans(id),
 decision TEXT NOT NULL, reason TEXT NOT NULL, grant_id TEXT NOT NULL DEFAULT '', at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS council_grants (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE REFERENCES council_plans(id),
 plan_digest TEXT NOT NULL, incident_id TEXT NOT NULL, generation INTEGER NOT NULL,
 goal_id TEXT NOT NULL, asset_id TEXT NOT NULL, object_id TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'granted', created_at REAL NOT NULL, expires_at REAL NOT NULL,
 claimed_at REAL, finished_at REAL, result_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS council_steps (
 grant_id TEXT NOT NULL REFERENCES council_grants(id), ordinal INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending', action_id TEXT NOT NULL DEFAULT '',
 result_json TEXT NOT NULL DEFAULT '{}', claimed_at REAL, finished_at REAL,
 PRIMARY KEY(grant_id,ordinal)
);
CREATE TRIGGER IF NOT EXISTS council_plan_immutable BEFORE UPDATE OF
 incident_id,generation,goal_id,version,digest,asset_id,object_id,canonical_object,plan_json,created_at,expires_at
 ON council_plans BEGIN SELECT RAISE(ABORT,'immutable council plan'); END;
CREATE TRIGGER IF NOT EXISTS council_review_identity_immutable BEFORE UPDATE OF
 plan_id,plan_digest,role,provider,model,requested_at,deadline_at ON council_reviews
 BEGIN SELECT RAISE(ABORT,'immutable council review identity'); END;
CREATE TRIGGER IF NOT EXISTS council_review_final_immutable BEFORE UPDATE ON council_reviews
 WHEN OLD.state != 'pending' BEGIN SELECT RAISE(ABORT,'immutable council review result'); END;
CREATE TRIGGER IF NOT EXISTS council_ballot_immutable BEFORE UPDATE ON council_ballots
 BEGIN SELECT RAISE(ABORT,'immutable council ballot'); END;
CREATE TRIGGER IF NOT EXISTS council_grant_binding_immutable BEFORE UPDATE OF
 plan_id,plan_digest,incident_id,generation,goal_id,asset_id,object_id,created_at,expires_at ON council_grants
 BEGIN SELECT RAISE(ABORT,'immutable council grant binding'); END;
""")
    _add_columns(conn, "actions", [
        ("council_grant_id", "ALTER TABLE actions ADD COLUMN council_grant_id TEXT NOT NULL DEFAULT ''"),
        ("council_step", "ALTER TABLE actions ADD COLUMN council_step INTEGER NOT NULL DEFAULT -1"),
    ])
    # Empty action IDs cannot share the UNIQUE index while a multi-step grant waits.
    conn.execute("DROP INDEX IF EXISTS idx_council_step_action")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_council_step_action ON council_steps(action_id) WHERE action_id!=''")


def _migrate_v17_incident_session(conn: sqlite3.Connection) -> None:
    """Incident→Session 薄桥：映射 + 写操作幂等台账（SpeedSupreme P2）。"""
    conn.executescript("""
CREATE TABLE IF NOT EXISTS incident_session (
  incident_id TEXT PRIMARY KEY,
  generation INTEGER NOT NULL DEFAULT 1,
  session_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  prompt TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_session_sid ON incident_session(session_id);
CREATE TABLE IF NOT EXISTS session_write_ops (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  session_id TEXT NOT NULL DEFAULT '',
  action_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'claimed',
  result TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(incident_id, action_key)
);
""")


def _migrate_v18_mimo_remote_session(conn: sqlite3.Connection) -> None:
    """MiMo 远端 Session 映射元数据（P3）。不存 token/密钥。"""
    for ddl in (
        "ALTER TABLE incident_session ADD COLUMN remote_session_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE incident_session ADD COLUMN remote_status TEXT NOT NULL DEFAULT 'none'",
        "ALTER TABLE incident_session ADD COLUMN remote_model TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE incident_session ADD COLUMN remote_last_error TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE incident_session ADD COLUMN remote_history TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE incident_session ADD COLUMN remote_updated_at REAL NOT NULL DEFAULT 0",
    ):
        try:
            conn.execute(ddl)
        except Exception:
            pass  # 列已存在（幂等重放）


def _migrate_v19_write_ops_unknown_lease(conn: sqlite3.Connection) -> None:
    """写操作台账：unknown 态 + 租约 + 幂等键上下文（P4.1）。"""
    for ddl in (
        "ALTER TABLE session_write_ops ADD COLUMN lease_expires_at REAL NOT NULL DEFAULT 0",
        "ALTER TABLE session_write_ops ADD COLUMN target TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE session_write_ops ADD COLUMN params_hash TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE session_write_ops ADD COLUMN claimed_by TEXT NOT NULL DEFAULT ''",
    ):
        try:
            conn.execute(ddl)
        except Exception:
            pass


def _migrate_v20_investigation_jobs(conn: sqlite3.Connection) -> None:
    """P4.3 无人值守只读调查任务台账（重启恢复/防重复）。"""
    conn.executescript("""
CREATE TABLE IF NOT EXISTS investigation_jobs (
  incident_id TEXT PRIMARY KEY,
  generation INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'queued',
  rounds INTEGER NOT NULL DEFAULT 0,
  lease_expires_at REAL NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  last_result_status TEXT NOT NULL DEFAULT '',
  last_conclusion_json TEXT NOT NULL DEFAULT '',
  updated_at REAL NOT NULL DEFAULT 0,
  created_at REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_investigation_jobs_status ON investigation_jobs(status);
""")


def _migrate_v21_ops_loop(conn: sqlite3.Connection) -> None:
    """最终架构：工单闭环软约束状态（无进展/同方案失败/停止原因）。"""
    conn.executescript("""
CREATE TABLE IF NOT EXISTS ops_loop_state (
  incident_id TEXT PRIMARY KEY,
  generation INTEGER NOT NULL DEFAULT 1,
  rounds INTEGER NOT NULL DEFAULT 0,
  no_progress_rounds INTEGER NOT NULL DEFAULT 0,
  same_plan_failures INTEGER NOT NULL DEFAULT 0,
  last_plan_sig TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'idle',
  stop_reason TEXT NOT NULL DEFAULT '',
  last_result TEXT NOT NULL DEFAULT '',
  updated_at REAL NOT NULL DEFAULT 0
);
""")


def _migrate_v22_duty_sessions(conn: sqlite3.Connection) -> None:
    """值班/手动会话：一会话多 Incident + 归档倒计时 + Agent 设置。"""
    conn.executescript("""
CREATE TABLE IF NOT EXISTS duty_sessions (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL DEFAULT '',
  origin TEXT NOT NULL DEFAULT 'auto',
  status TEXT NOT NULL DEFAULT 'open',
  remote_session_id TEXT NOT NULL DEFAULT '',
  remote_status TEXT NOT NULL DEFAULT 'none',
  remote_model TEXT NOT NULL DEFAULT '',
  remote_last_error TEXT NOT NULL DEFAULT '',
  remote_history TEXT NOT NULL DEFAULT '[]',
  remote_updated_at REAL NOT NULL DEFAULT 0,
  prompt TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  last_activity_at REAL NOT NULL DEFAULT 0,
  archive_due_at REAL NOT NULL DEFAULT 0,
  archived_at REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_duty_sessions_status ON duty_sessions(status, origin);

CREATE TABLE IF NOT EXISTS session_incidents (
  session_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  joined_at REAL NOT NULL,
  PRIMARY KEY (session_id, incident_id)
);
CREATE INDEX IF NOT EXISTS idx_session_incidents_inc ON session_incidents(incident_id);

CREATE TABLE IF NOT EXISTS agent_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '',
  updated_at REAL NOT NULL DEFAULT 0,
  updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS session_messages (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'assistant',
  kind TEXT NOT NULL DEFAULT 'text',
  title TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  incident_id TEXT NOT NULL DEFAULT '',
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_messages_sid ON session_messages(session_id, created_at);

CREATE TABLE IF NOT EXISTS session_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  incident_id TEXT NOT NULL DEFAULT '',
  type TEXT NOT NULL DEFAULT 'info',
  title TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_events_sid ON session_events(session_id, id);
""")
    rows = conn.execute(
        "SELECT incident_id, generation, session_id, status, prompt, created_at, updated_at,"
        " remote_session_id, remote_status, remote_model, remote_last_error, remote_history,"
        " remote_updated_at FROM incident_session"
    ).fetchall()
    for row in rows:
        row = dict(row)
        sid = row.get("session_id") or ""
        if not sid:
            continue
        status = "open" if (row.get("status") or "open") == "open" else "archived"
        conn.execute(
            "INSERT OR IGNORE INTO duty_sessions("
            " id, title, origin, status, remote_session_id, remote_status, remote_model,"
            " remote_last_error, remote_history, remote_updated_at, prompt, created_by,"
            " created_at, updated_at, last_activity_at, archive_due_at, archived_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sid,
                f"inc:{row.get('incident_id') or ''}",
                "auto",
                status,
                row.get("remote_session_id") or "",
                row.get("remote_status") or "none",
                row.get("remote_model") or "",
                row.get("remote_last_error") or "",
                row.get("remote_history") or "[]",
                float(row.get("remote_updated_at") or 0),
                row.get("prompt") or "",
                "system",
                float(row.get("created_at") or 0),
                float(row.get("updated_at") or 0),
                float(row.get("updated_at") or 0),
                0,
                float(row.get("updated_at") or 0) if status == "archived" else 0,
            ),
        )
        conn.execute(
            "INSERT OR IGNORE INTO session_incidents(session_id, incident_id, generation, joined_at)"
            " VALUES(?,?,?,?)",
            (sid, row.get("incident_id") or "", int(row.get("generation") or 1), float(row.get("created_at") or 0)),
        )
    conn.execute(
        "INSERT OR IGNORE INTO agent_settings(key, value, updated_at, updated_by)"
        " VALUES('require_human_approval','1',?, 'system')",
        (now(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO agent_settings(key, value, updated_at, updated_by)"
        " VALUES('archive_delay_sec','300',?, 'system')",
        (now(),),
    )


def _migrate_v23_native_runtime(conn: sqlite3.Connection) -> None:
    """Persistent native bindings and one automatic duty slot; retain old history."""
    # Older builds could leave several open automatic sessions. Preserve every
    # row, native ID and Incident link, but only one is the current duty slot.
    rows = conn.execute("SELECT id FROM duty_sessions WHERE origin='auto' AND status='open' ORDER BY created_at DESC,id DESC").fetchall()
    for row in rows[1:]:
        sid = row["id"]
        conn.execute("UPDATE duty_sessions SET origin='legacy_auto' WHERE id=?", (sid,))
        conn.execute("INSERT INTO session_events(session_id,type,title,payload_json,created_at) VALUES(?,?,?,?,?)",
                     (sid,"migration_preserved","旧值班会话保留为历史上下文",'{"migration":23}',now()))
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_auto_session ON duty_sessions(origin) WHERE origin='auto' AND status='open'")
    conn.executescript("""
CREATE TABLE IF NOT EXISTS agent_runtime_bindings (
  session_id TEXT PRIMARY KEY,
  remote_session_id TEXT NOT NULL DEFAULT '',
  runtime_id TEXT NOT NULL DEFAULT '',
  engine_pid INTEGER NOT NULL DEFAULT 0,
  engine_started_at TEXT NOT NULL DEFAULT '',
  tmux_name TEXT UNIQUE,
  pane_id TEXT NOT NULL DEFAULT '',
  pane_pid INTEGER NOT NULL DEFAULT 0,
  pane_started_at TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'idle',
  receipt_id TEXT NOT NULL DEFAULT '',
  receipt_status TEXT NOT NULL DEFAULT '',
  controller TEXT NOT NULL DEFAULT '',
  controller_connection_id TEXT NOT NULL DEFAULT '',
  control_token_hash TEXT NOT NULL DEFAULT '',
  control_expires_at REAL NOT NULL DEFAULT 0,
  created_at REAL NOT NULL DEFAULT 0,
  updated_at REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agent_session_turns (
  session_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  expires_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_runtime_receipts (
  receipt_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  remote_session_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'accepted',
  origin TEXT NOT NULL DEFAULT 'auto',
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runtime_receipts_session_status ON agent_runtime_receipts(session_id,status);
""")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(investigation_jobs)")}
    if "phase" not in columns:
        conn.execute("ALTER TABLE investigation_jobs ADD COLUMN phase TEXT NOT NULL DEFAULT 'queued'")


def _migrate_v24_agent_authority(conn: sqlite3.Connection) -> None:
    """Preserve historical effective modes; new manual defaults are independent."""
    added_approval = False
    for table, columns in {
        "duty_sessions": (("access_mode", "TEXT NOT NULL DEFAULT 'readonly'"), ("approval_mode", "TEXT NOT NULL DEFAULT 'manual'"), ("authority_revision", "INTEGER NOT NULL DEFAULT 0")),
        "agent_runtime_bindings": (("override_access_mode", "TEXT NOT NULL DEFAULT ''"), ("override_approval_mode", "TEXT NOT NULL DEFAULT ''")),
    }.items():
        existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for column, definition in columns:
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                added_approval |= table == "duty_sessions" and column == "approval_mode"
    old = conn.execute("SELECT value FROM agent_settings WHERE key='require_human_approval'").fetchone()
    approval = "automatic" if old and str(old[0]) in ("0", "false", "False", "") else "manual"
    if added_approval:
        conn.execute("UPDATE duty_sessions SET approval_mode=?", (approval,))
    for key, value in (("auto_access_mode", "readwrite"), ("auto_approval_mode", approval), ("manual_approval_default", approval)):
        conn.execute("INSERT OR IGNORE INTO agent_settings(key,value,updated_at,updated_by) VALUES(?,?,?,'migration24')", (key,value,now()))
    conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('agent_authority_revision','0')")


def _migrate_v25_session_lifecycle(conn: sqlite3.Connection) -> None:
    """Durable pause/deletion requests and native admission; retain all history."""
    existing = {r[1] for r in conn.execute("PRAGMA table_info(duty_sessions)")}
    for column, definition in (
        ("paused_at", "REAL NOT NULL DEFAULT 0"), ("pause_reason", "TEXT NOT NULL DEFAULT ''"),
        ("delete_requested_at", "REAL NOT NULL DEFAULT 0"), ("deleted_at", "REAL NOT NULL DEFAULT 0"),
        ("deleted_by", "TEXT NOT NULL DEFAULT ''"), ("delete_error", "TEXT NOT NULL DEFAULT ''"),
        ("human_message_revision", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if column not in existing:
            conn.execute(f"ALTER TABLE duty_sessions ADD COLUMN {column} {definition}")
    conn.execute("CREATE TABLE IF NOT EXISTS agent_native_submissions (session_id TEXT NOT NULL, submission_id TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL, remote_session_id TEXT NOT NULL DEFAULT '',payload_json TEXT NOT NULL DEFAULT '{}',receipt_id TEXT NOT NULL DEFAULT '',PRIMARY KEY(session_id,submission_id))")
    submission_columns={r[1] for r in conn.execute("PRAGMA table_info(agent_native_submissions)")}
    for column,definition in (("remote_session_id","TEXT NOT NULL DEFAULT ''"),("payload_json","TEXT NOT NULL DEFAULT '{}'"),("receipt_id","TEXT NOT NULL DEFAULT ''")):
        if column not in submission_columns:conn.execute(f"ALTER TABLE agent_native_submissions ADD COLUMN {column} {definition}")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_native_submitting ON agent_native_submissions(session_id) WHERE state='submitting'")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_native_recovering ON agent_native_submissions(session_id) WHERE kind='recovery' AND state IN ('submitting','recovering','unknown')")
    conn.execute("CREATE TABLE IF NOT EXISTS agent_work_targets (asset_id TEXT NOT NULL, object_id TEXT NOT NULL, session_id TEXT NOT NULL, updated_at REAL NOT NULL, PRIMARY KEY(asset_id,object_id))")


_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    1: _migrate_v1_baseline,
    2: _migrate_v2_p0_p1_columns,
    3: _migrate_v3_recovery_columns,
    4: _migrate_v4_agent_ceiling,
    5: _migrate_v5_action_decision_id,
    6: _migrate_v6_ssh_endpoints_credentials,
    7: _migrate_v7_host_key_line,
    8: _migrate_v8_notify_channels,
    9: _migrate_v9_aibot_seen_targets,
    10: _migrate_v10_message_log,
    11: _migrate_v11_checks,
    12: _migrate_v12_asset_host,
    13: _migrate_v13_users_must_change_password,
    14: _migrate_v14_node_watch,
    15: _migrate_v15_ext_tasks,
    16: _migrate_v16_council,
    17: _migrate_v17_incident_session,
    18: _migrate_v18_mimo_remote_session,
    19: _migrate_v19_write_ops_unknown_lease,
    20: _migrate_v20_investigation_jobs,
    21: _migrate_v21_ops_loop,
    22: _migrate_v22_duty_sessions,
    23: _migrate_v23_native_runtime,
    24: _migrate_v24_agent_authority,
    25: _migrate_v25_session_lifecycle,
}

_MIGRATION_NAMES = {
    1: "baseline_columns",
    2: "p0_p1_columns",
    3: "recovery_and_work_items",
    4: "agent_ceiling",
    5: "action_decision_id",
    6: "ssh_endpoints_credentials",
    7: "host_key_line",
    8: "notify_channels",
    9: "aibot_seen_targets",
    10: "message_log",
    11: "checks",
    12: "asset_host",
    13: "users_must_change_password",
    14: "node_watch",
    15: "ext_tasks",
    16: "council_plans_reviews_grants",
    17: "incident_session_bridge",
    18: "mimo_remote_session",
    19: "write_ops_unknown_lease",
    20: "investigation_jobs",
    21: "ops_loop_state",
    22: "duty_sessions",
    23: "native_runtime_bindings",
    24: "live_session_authority",
    25: "native_guidance_and_session_lifecycle",
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
        """短事务。S16: 嵌套 tx 只在最外层提交/回滚，内层共享同一事务。"""
        conn = self._connect()
        with self._write_lock:
            # 事务深度：用线程局部变量追踪（sqlite3.Connection 不允许自定义属性）
            depth = getattr(self._local, "tx_depth", 0)
            self._local.tx_depth = depth + 1
            try:
                yield conn
                if depth == 0:
                    conn.commit()
            except Exception:
                if depth == 0:
                    conn.rollback()
                raise
            finally:
                self._local.tx_depth = depth

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        conn = self._connect()
        with self._write_lock:
            cur = conn.execute(sql, params)
            if getattr(self._local, "tx_depth", 0) == 0:
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
        decision_id: str = "",
        incident_id: str = "",
        channel: str = "",
    ) -> None:
        self.execute(
            "INSERT INTO audit_log(at, actor_type, actor_id, entry, asset_id, object_id,"
            " action_id, detail_json, decision_id, incident_id, channel) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                now(),
                actor_type,
                actor_id,
                entry,
                asset_id,
                object_id,
                action_id,
                json.dumps(detail or {}, ensure_ascii=False),
                decision_id,
                incident_id,
                channel,
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
    ) -> int | None:
        """写入事件并返回事件 id（enqueue_for_event 需要）。"""
        cur = self.execute(
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
        return cur.lastrowid

    def snapshot_config(self, kind: str, payload: dict, created_by: str = "") -> None:
        self.execute(
            "INSERT INTO config_versions(kind, payload_json, created_at, created_by)"
            " VALUES(?,?,?,?)",
            (kind, json.dumps(payload, ensure_ascii=False), now(), created_by),
        )
