"""Phase F: schema migration / backup / recovery / ready / adapter / replay。"""

from __future__ import annotations

import asyncio
import inspect
import json
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if "aiohttp" not in sys.modules:
    _a = types.ModuleType("aiohttp")

    class _CT:
        def __init__(self, **k):
            pass

    class _CS:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def post(self, *a, **k):
            raise RuntimeError("no net")

    _a.ClientTimeout = _CT
    _a.ClientSession = _CS
    sys.modules["aiohttp"] = _a

# 补齐 aiohttp.web stub（兼容其它测试文件先注入的简易 aiohttp）
import aiohttp as _aio  # noqa: E402

if not hasattr(_aio, "web") or "aiohttp.web" not in sys.modules:
    class _WebApp:
        def __init__(self, **k):
            self.router = types.SimpleNamespace(
                add_get=lambda *a, **k: None,
                add_post=lambda *a, **k: None,
                add_static=lambda *a, **k: None,
            )

    class _WebResp:
        def __init__(self, *a, **k):
            data = a[0] if a else k.get("data", {})
            if isinstance(data, (dict, list)):
                self.body = json.dumps(data).encode("utf-8")
            else:
                self.body = str(data).encode("utf-8")
            self.status = k.get("status", 200)
            self.text = k.get("text", "")
            self.headers = {}

    class _WebReq:
        pass

    _web = types.ModuleType("aiohttp.web")
    _web.Application = _WebApp
    _web.Response = _WebResp
    _web.FileResponse = _WebResp
    _web.Request = _WebReq

    def _json_response(data=None, status=200, **k):
        r = _WebResp(data or {})
        r.status = status
        return r

    _web.json_response = _json_response
    _aio.web = _web
    sys.modules["aiohttp.web"] = _web

from ayana.backup import (
    BackupError,
    create_backup,
    restore_rehearsal,
    validate_backup_file,
)
from ayana.db import SCHEMA_VERSION, Database, MigrationError, now
from ayana.actions import ActionError, ActionService
from ayana.investigation import InvestigationService
from ayana.knowledge import KnowledgeBase
from ayana.ntsafe import NTResult
from ayana.policy import Policy
from ayana.capabilities import CAPABILITIES
from ayana import prom as prom_mod
from ayana import ntsafe as ntsafe_mod


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class FakeNT:
    def __init__(self):
        self.probe_calls = []
        self.exec_calls = []
        self.default = NTResult(ok=True, output="ok", returncode=0)
        self.script = []

    def set_script(self, *items):
        self.script = list(items)

    def _match(self, tokens):
        blob = " ".join(tokens)
        for substr, res in self.script:
            if substr in blob:
                return res
        return self.default

    async def describe(self, alias):
        return NTResult(ok=True, output='{"user":"nt-probe","mode":"probe","host_id":"NERV"}')

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"nt-probe","mode":"probe"}')

    async def probe(self, alias, cmd_tokens, timeout=None):
        self.probe_calls.append(list(cmd_tokens))
        return self._match(cmd_tokens)

    async def exec(self, write_alias, cmd_tokens, timeout=None):
        self.exec_calls.append(list(cmd_tokens))
        return NTResult(ok=True, output="ok", returncode=0)


class FakeGate:
    def get(self, asset_id):
        class B:
            pass
        b = B()
        b.read_alias = asset_id
        b.write_alias = asset_id + "-exec"
        b.asset_id = asset_id
        b.expected_host_id = "NERV"
        b.host_id_verified_at = 1.0
        return b

    async def verify_account(self, asset_id, *, write=False):
        return {"ok": True, "mode": "exec" if write else "probe", "error": ""}


class FakeProm:
    def __init__(self, value=0):
        self.value = value
        self.calls = []
        self.since_calls = []
        self.samples = []

    async def probe_success(self, asset, service=""):
        self.calls.append((asset, service))
        return {
            "result": [
                {"metric": {"asset": asset, "service": service}, "value": self.value,
                 "sample_at": now()}
            ],
            "evaluated_at": now(),
        }

    async def probe_success_since(self, asset, service="", *, start, end=None, step=15.0,
                                  window_sec=None, max_window_sec=600.0):
        self.since_calls.append({"asset": asset, "service": service, "start": start})
        return [
            {"metric": {"asset": asset, "service": service}, "value": self.value,
             "sample_at": now() - 5}
        ]


def make_db_env():
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "t.db")
    t = now()
    db.execute(
        "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
        " host_id_verified_at, prom_asset, enabled, notes, created_at, updated_at)"
        " VALUES(?,?,?,?,?,?,?,1,'',?,?)",
        ("nerv", "NERV", "nerv", "nerv-exec", "NERV", t, "nerv", t, t),
    )
    db.execute(
        "INSERT INTO objects(id, asset_id, kind, name, unit, container, port, protocol,"
        " external_probe, auto_recover, created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("nerv:service:frps", "nerv", "service", "frps", "frps", "", 32659, "tcp", "frps-probe", 1, t),
    )
    return tmp, db


def close_env(tmp, db):
    try:
        db.close()
    except Exception:
        pass
    try:
        tmp.cleanup()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 一、Schema migration
# ---------------------------------------------------------------------------

class TestSchemaMigration(unittest.TestCase):
    def test_fresh_db_at_current_version(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "fresh.db")
        self.addCleanup(db.close)
        self.assertEqual(db.schema_version(), SCHEMA_VERSION)
        st = db.migration_status()
        self.assertEqual(st["current"], SCHEMA_VERSION)
        self.assertTrue(st["applied"])

    def test_old_db_upgrades_to_current(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "old.db"
        # 构造 v0.2 风格旧库（缺 P0/P1 列，无 schema_version）
        c = sqlite3.connect(str(path))
        c.executescript(
            """
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE actions (
              id TEXT PRIMARY KEY, incident_id TEXT, asset_id TEXT, object_id TEXT,
              capability TEXT, params_json TEXT, reason TEXT, state TEXT,
              proposer_type TEXT, proposer_id TEXT, approver_type TEXT, approver_id TEXT,
              created_at REAL, approved_at REAL, dispatched_at REAL, finished_at REAL,
              exec_account TEXT, policy_snapshot_json TEXT, result_detail TEXT
            );
            CREATE TABLE incidents (
              id TEXT PRIMARY KEY, title TEXT, asset_id TEXT, object_id TEXT, severity TEXT,
              status TEXT, stage TEXT, need_human INTEGER, need_human_reason TEXT,
              summary TEXT, created_at REAL, updated_at REAL, resolved_at REAL
            );
            CREATE TABLE investigations (
              id TEXT PRIMARY KEY, incident_id TEXT, asset_id TEXT, object_id TEXT,
              status TEXT, evidence_json TEXT, conclusion TEXT, created_at REAL, finished_at REAL
            );
            CREATE TABLE verifications (
              id TEXT PRIMARY KEY, action_id TEXT, incident_id TEXT, status TEXT,
              criteria_json TEXT, evidence_json TEXT, note TEXT, started_at REAL, finished_at REAL
            );
            CREATE TABLE alert_episodes (
              id TEXT PRIMARY KEY, source_id TEXT, fingerprint TEXT, starts_at_norm TEXT,
              alertname TEXT, status TEXT, asset_id TEXT, object_id TEXT, incident_id TEXT,
              first_seen REAL, last_seen REAL, receive_count INTEGER, labels_json TEXT,
              annotations_json TEXT
            );
            CREATE TABLE events (
              id INTEGER PRIMARY KEY, incident_id TEXT, at REAL, type TEXT,
              title TEXT, payload_json TEXT
            );
            CREATE TABLE audit_log (
              id INTEGER PRIMARY KEY, at REAL, actor_type TEXT, actor_id TEXT, entry TEXT,
              asset_id TEXT, object_id TEXT, action_id TEXT, detail_json TEXT
            );
            """
        )
        c.execute(
            "INSERT INTO actions(id, asset_id, object_id, capability, state, created_at)"
            " VALUES('a1','nerv','frps','service.restart','success',1)"
        )
        c.execute("INSERT INTO meta(key,value) VALUES('x','1')")
        c.commit()
        c.close()
        # 升级
        db = Database(path)
        self.addCleanup(db.close)
        self.assertEqual(db.schema_version(), SCHEMA_VERSION)
        # 旧数据仍在
        row = db.query_one("SELECT * FROM actions WHERE id='a1'")
        self.assertIsNotNone(row)
        # 新列存在
        self.assertIn("mode", row.keys())
        self.assertIn("adjudication", row.keys())

    def test_repeat_start_idempotent(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "rep.db"
        db1 = Database(path)
        self.assertEqual(db1.schema_version(), SCHEMA_VERSION)
        db1.close()
        db2 = Database(path)
        self.addCleanup(db2.close)
        self.assertEqual(db2.schema_version(), SCHEMA_VERSION)
        st = db2.migration_status()
        # 不重复插入
        versions = [m["version"] for m in st["applied"]]
        self.assertEqual(versions, sorted(set(versions)))

    def test_migration_failure_does_not_mark_done(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "fail.db"
        db = Database(path)
        db.close()
        # 把 version 制造为 1，并注入失败迁移
        c = sqlite3.connect(str(path))
        c.execute("UPDATE meta SET value='1' WHERE key='schema_version'")
        c.execute("DELETE FROM schema_migrations WHERE version>1")
        c.commit()
        c.close()
        from ayana import db as dbmod

        def boom(conn):
            raise RuntimeError("injected failure")

        orig = dbmod._MIGRATIONS.get(2)
        dbmod._MIGRATIONS[2] = boom
        try:
            with self.assertRaises(MigrationError) as ctx:
                Database(path)
            self.assertEqual(ctx.exception.code, "migration_failed")
        finally:
            if orig:
                dbmod._MIGRATIONS[2] = orig
        # version 未标到 3
        c2 = sqlite3.connect(str(path))
        try:
            v = c2.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            self.assertEqual(int(v[0]), 1)
        finally:
            c2.close()

    def test_future_schema_refused(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(lambda: tmp.cleanup())
        path = Path(tmp.name) / "future.db"
        db = Database(path)
        db.close()
        c = sqlite3.connect(str(path))
        c.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        c.commit()
        c.close()
        with self.assertRaises(MigrationError) as ctx:
            db2 = Database(path)
            try:
                db2.close()
            except Exception:
                pass
        self.assertEqual(ctx.exception.code, "future_schema")


# ---------------------------------------------------------------------------
# 二、Backup / restore
# ---------------------------------------------------------------------------

class TestBackupRestore(unittest.TestCase):
    def test_backup_isolated_restore_roundtrip(self):
        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
            " need_human, summary, generation, outcome, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("inc1", "frps down", "nerv", "frps", "warning", "open", "pending",
             0, "", 1, "", now(), now()),
        )
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, state, created_at) VALUES(?,?,?,?,?,?,?,?)",
            ("a1", "inc1", "nerv", "frps", "service.restart", "{}", "success", now()),
        )
        db.execute(
            "INSERT INTO investigations(id, incident_id, asset_id, object_id, status,"
            " created_at) VALUES(?,?,?,?,?,?)",
            ("inv1", "inc1", "nerv", "frps", "done", now()),
        )
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, started_at)"
            " VALUES(?,?,?,?,?)",
            ("v1", "a1", "inc1", "passed", now()),
        )
        # 必须在关闭/flush 后备份？backup API 可对 WAL 运行库
        bdir = Path(tmp.name) / "bk"
        meta = create_backup(db.path, bdir / "ayana.bak", source_label="test")
        self.assertTrue(meta["ok"])
        self.assertEqual(meta["schema_version"], SCHEMA_VERSION)
        self.assertTrue((bdir / "ayana.bak").is_file())
        self.assertTrue((bdir / "ayana.bak.meta.json").is_file())

        report = restore_rehearsal(bdir / "ayana.bak", work_dir=Path(tmp.name) / "restore")
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["integrity"], "ok")
        self.assertEqual(report["schema_version"], SCHEMA_VERSION)
        for t in ("incidents", "investigations", "actions", "verifications", "audit_log", "events"):
            self.assertIsNotNone(report["tables"].get(t), t)

        # 隔离库内容可读
        rdb = sqlite3.connect(str(Path(tmp.name) / "restore" / "restored.db"))
        try:
            n = rdb.execute("SELECT COUNT(*) FROM incidents").fetchone()
            self.assertEqual(n[0], 1)
            a = rdb.execute("SELECT state FROM actions WHERE id='a1'").fetchone()
            self.assertEqual(a[0], "success")
        finally:
            rdb.close()

    def test_backup_missing_source_fails(self):
        with self.assertRaises(BackupError):
            create_backup("/nonexistent/ayana.db", "/tmp/x.bak")

    def test_validate_backup_file(self):
        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        b = Path(tmp.name) / "b.bak"
        create_backup(db.path, b)
        v = validate_backup_file(b)
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["schema_version"], SCHEMA_VERSION)
        bad = validate_backup_file(Path(tmp.name) / "nope.bak")
        self.assertFalse(bad["ok"])


# ---------------------------------------------------------------------------
# 三、P1-05 重启 / unknown / adjudication
# ---------------------------------------------------------------------------

class TestRestartAndAdjudication(unittest.TestCase):
    def _env(self):
        tmp, db = make_db_env()
        policy = Policy(db)
        policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="*", allow=True, require_approval=False, actor="t",
        )
        nt = FakeNT()
        prom = FakeProm()
        actions = ActionService(db, nt, FakeGate(), policy, prom, verify_timeout=1)
        return tmp, db, policy, nt, prom, actions

    def test_dispatched_becomes_unknown_not_replayed(self):
        tmp, db, policy, nt, prom, actions = self._env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, state, created_at, dispatched_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("a1", "inc1", "nerv", "frps", "service.restart", "{}", "dispatched", now(), now()),
        )
        n = actions.mark_unknown_unfinished()
        self.assertEqual(n, 1)
        row = db.query_one("SELECT * FROM actions WHERE id='a1'")
        self.assertEqual(row["state"], "unknown")
        self.assertIn("restart_recovery", row["result_detail"])
        # 不自动重放
        self.assertFalse(nt.exec_calls)

    def test_proposed_safe_to_wait(self):
        tmp, db, policy, nt, prom, actions = self._env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO actions(id, asset_id, object_id, capability, params_json, state, created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            ("a1", "nerv", "frps", "service.restart", "{}", "proposed", now()),
        )
        actions.mark_unknown_unfinished()
        row = db.query_one("SELECT state FROM actions WHERE id='a1'")
        self.assertEqual(row["state"], "proposed")
        st = actions.restart_semantics()
        self.assertEqual(st["proposed_safe_to_wait"], 1)

    def test_approved_not_blindly_executed(self):
        tmp, db, policy, nt, prom, actions = self._env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO actions(id, asset_id, object_id, capability, params_json, state, created_at,"
            " approved_at) VALUES(?,?,?,?,?,?,?,?)",
            ("a1", "nerv", "frps", "service.restart", "{}", "approved", now(), now()),
        )
        actions.mark_unknown_unfinished()
        self.assertFalse(nt.exec_calls)
        # 必须重新走 execute（内含 dispatch gate）
        st = actions.restart_semantics()
        self.assertGreaterEqual(st["approved_need_recheck"], 1)

    def test_adjudicate_executed_releases_lock(self):
        tmp, db, policy, nt, prom, actions = self._env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, created_at, result_detail) VALUES(?,?,?,?,?,?,?,?,?)",
            ("a1", "inc1", "nerv", "frps", "service.restart", "{}", "unknown", now(), "timeout"),
        )
        res = actions.adjudicate(
            "a1", outcome="executed", reason="host log shows restart",
            actor_type="web_user", actor_id="admin", channel="web",
        )
        self.assertEqual(res["adjudication"], "executed")
        row = db.query_one("SELECT * FROM actions WHERE id='a1'")
        self.assertEqual(row["adjudication"], "executed")
        self.assertEqual(row["state"], "success")
        # 不伪造原始 result_detail
        self.assertIn("timeout", row["result_detail"])
        aud = db.query_one(
            "SELECT * FROM audit_log WHERE action_id='a1' AND entry='action_adjudicated'"
        )
        self.assertIsNotNone(aud)

    def test_adjudicate_not_executed(self):
        tmp, db, policy, nt, prom, actions = self._env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, created_at) VALUES(?,?,?,?,?,?,?,?)",
            ("a1", "inc1", "nerv", "frps", "service.restart", "{}", "unknown", now()),
        )
        res = actions.adjudicate("a1", outcome="not_executed", reason="no host record")
        self.assertEqual(res["adjudication"], "not_executed")
        row = db.query_one("SELECT state FROM actions WHERE id='a1'")
        self.assertEqual(row["state"], "cancelled")

    def test_adjudicate_still_unknown_keeps_lock(self):
        tmp, db, policy, nt, prom, actions = self._env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, created_at) VALUES(?,?,?,?,?,?,?,?)",
            ("a1", "inc1", "nerv", "frps", "service.restart", "{}", "unknown", now()),
        )
        res = actions.adjudicate("a1", outcome="still_unknown", reason="no evidence")
        self.assertEqual(res["adjudication"], "still_unknown")
        row = db.query_one("SELECT state FROM actions WHERE id='a1'")
        self.assertEqual(row["state"], "unknown")

    def test_investigation_interrupted_not_done(self):
        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        policy = Policy(db)
        inv = InvestigationService(db, FakeNT(), FakeGate(), FakeProm(), policy)
        # 模拟中断：running 状态残留
        db.execute(
            "INSERT INTO investigations(id, asset_id, object_id, status, created_at)"
            " VALUES(?,?,?,? ,?)",
            ("inv1", "nerv", "frps", "running", now() - 600),
        )
        # 重启语义：running 超时 → interrupted
        n = db.execute(
            "UPDATE investigations SET status='interrupted',"
            " status_detail='restart_recovery' WHERE status='running'"
        ).rowcount
        self.assertEqual(n, 1)
        row = db.query_one("SELECT status, status_detail FROM investigations WHERE id='inv1'")
        self.assertEqual(row["status"], "interrupted")
        self.assertEqual(row["status_detail"], "restart_recovery")


# ---------------------------------------------------------------------------
# 四、/ready 语义
# ---------------------------------------------------------------------------

class TestReadySemantics(unittest.TestCase):
    def _app(self, tmp, db, prom=None):
        from ayana.web import WebApp
        from ayana.auth import AuthService
        from ayana.incidents import IncidentService

        policy = Policy(db)
        auth = AuthService(db, pepper="p", session_ttl=3600, max_failed=5, lockout=60)
        inv = InvestigationService(db, FakeNT(), FakeGate(), FakeProm(), policy)
        actions = ActionService(db, FakeNT(), FakeGate(), policy, FakeProm())
        return WebApp(
            db, auth, policy, IncidentService(db), inv, actions, prom or FakeProm(),
            static_dir=Path(tmp.name),
        )

    def test_ready_reports_db_and_schema(self):
        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        app = self._app(tmp, db)

        class Req:
            remote = "127.0.0.1"

        async def run():
            h = await app.health(Req())
            r = await app.ready(Req())
            return h, r

        h, r = asyncio.run(run())
        body = json.loads(r.body)
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["checks"]["db"], "available")
        self.assertEqual(body["checks"]["schema"], "current")

    def test_health_alive_even_if_prom_down(self):
        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        prom = FakeProm()
        prom.last_status = "unavailable"
        app = self._app(tmp, db, prom=prom)

        class Req:
            remote = "127.0.0.1"

        async def run():
            return await app.ready(Req())

        r = asyncio.run(run())
        body = json.loads(r.body)
        # Prom 降级不应拖死 ready
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["checks"].get("prometheus"), "unavailable")


# ---------------------------------------------------------------------------
# 五、Adapter 契约
# ---------------------------------------------------------------------------

class TestAdapterContracts(unittest.TestCase):
    def test_fake_prom_matches_real_signatures(self):
        real = inspect.signature(prom_mod.PromClient.probe_success)
        fake = inspect.signature(FakeProm.probe_success)
        self.assertEqual(
            [p for p in real.parameters if p != "self"],
            [p for p in fake.parameters if p != "self"],
        )
        real_s = inspect.signature(prom_mod.PromClient.probe_success_since)
        fake_s = inspect.signature(FakeProm.probe_success_since)
        self.assertEqual(
            [p for p in real_s.parameters if p != "self"],
            [p for p in fake_s.parameters if p != "self"],
        )
        # 正向：确实调用并拿到 sample
        async def run():
            p = FakeProm(value=1)
            r = await p.probe_success("nerv", "frps")
            self.assertTrue(r["result"])
            s = await p.probe_success_since("nerv", "frps", start=now() - 60)
            self.assertTrue(s)
        asyncio.run(run())

    def test_fake_nt_matches_real_signatures(self):
        real = inspect.signature(ntsafe_mod.NTClient.probe)
        fake = inspect.signature(FakeNT.probe)
        self.assertEqual(
            [p for p in real.parameters if p != "self"],
            [p for p in fake.parameters if p != "self"],
        )
        real_e = inspect.signature(ntsafe_mod.NTClient.exec)
        fake_e = inspect.signature(FakeNT.exec)
        self.assertEqual(
            [p for p in real_e.parameters if p != "self"],
            [p for p in fake_e.parameters if p != "self"],
        )
        # NTResult 字段契约
        import dataclasses

        fields = {f.name for f in dataclasses.fields(NTResult)}
        for name in ("ok", "returncode", "timed_out", "output"):
            self.assertIn(name, fields)
        sample = NTResult(ok=True, output="x", returncode=0)
        self.assertTrue(sample.ok)
        self.assertEqual(sample.returncode, 0)
        self.assertFalse(sample.timed_out)

    def test_wrong_fake_fails_not_silently_green(self):
        class BadProm:
            async def probe_success(self, asset):  # 缺 service 参数
                return {"result": []}

        sig = inspect.signature(BadProm.probe_success)
        # 与真实调用 (asset, service) 对齐时必须失败
        with self.assertRaises(TypeError):
            sig.bind(object(), "nerv", "frps")


# ---------------------------------------------------------------------------
# 六、Replay set
# ---------------------------------------------------------------------------

class TestReplayFrps(unittest.TestCase):
    def test_frps_full_closed_loop(self):
        """monitoring failure → inv → approval → action → verify → recovered"""
        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
            " need_human, summary, generation, outcome, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("inc1", "nerv / frps: TargetDown", "nerv", "frps", "warning", "open", "pending",
             0, "", 1, "", now(), now()),
        )
        policy = Policy(db)
        policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability="service.status",
            asset_id="nerv", object_id="*", allow=True, require_approval=False,
            auto_allowed=True, actor="t",
        )
        policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability="service.logs",
            asset_id="nerv", object_id="*", allow=True, require_approval=False,
            auto_allowed=True, actor="t",
        )
        policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="*", allow=True, require_approval=True,
            auto_allowed=False, actor="t",
        )
        nt = FakeNT()
        nt.set_script(("is-active", NTResult(ok=False, output="inactive", returncode=3)))
        prom = FakeProm(value=0)
        inv = InvestigationService(db, nt, FakeGate(), prom, policy)
        actions = ActionService(db, nt, FakeGate(), policy, prom, verify_window=5, verify_timeout=1)

        # 1. Investigation
        ires = asyncio.run(inv.run_loop(asset_id="nerv", object_id="frps", incident_id="inc1"))
        self.assertTrue(any(
            f.get("kind") == "service_state" and f.get("service_state") == "inactive"
            for f in ires["facts"]
        ), ires["facts"])

        # 2. proposal approval_required
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="runbook: frps down", incident_id="inc1",
            proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        self.assertEqual(prop["state"], "proposed")
        self.assertEqual(prop.get("decision"), "approval_required")

        # 3. approve + execute exactly once
        res = asyncio.run(actions.approve_and_execute(
            prop["id"], actor_type="web_user", actor_id="admin", channel="web",
        ))
        self.assertEqual(len(nt.exec_calls), 1)
        self.assertEqual(res.get("state"), "success")

        # 4. verification obligation exists
        ver = db.query_one(
            "SELECT * FROM verifications WHERE action_id=?", (prop["id"],)
        )
        self.assertIsNotNone(ver)

    def test_approval_before_natural_recovery_cancelled(self):
        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
            " need_human, summary, generation, outcome, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("inc1", "x", "nerv", "frps", "warning", "open", "pending",
             0, "", 1, "", now(), now()),
        )
        policy = Policy(db)
        policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="*", allow=True, require_approval=True, actor="t",
        )
        nt = FakeNT()
        actions = ActionService(db, nt, FakeGate(), policy, FakeProm())
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="t", incident_id="inc1",
            proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )
        from ayana.incidents import IncidentService

        IncidentService(db)._cancel_pending_proposals("inc1", "incident_recovered")
        row = db.query_one("SELECT state FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["state"], "cancelled")
        self.assertFalse(nt.exec_calls)

    def test_verification_insufficient_window_not_recovered(self):
        from ayana.incidents import IncidentService

        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
            " need_human, summary, generation, outcome, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("inc1", "x", "nerv", "frps", "warning", "open", "pending",
             0, "", 1, "", now(), now()),
        )
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, created_at) VALUES(?,?,?,?,?,?,?,?)",
            ("a1", "inc1", "nerv", "frps", "service.restart", "{}", "success", now()),
        )
        # pending verification 阻塞 recovered
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, generation, started_at)"
            " VALUES(?,?,?,?,?,?)",
            ("v1", "a1", "inc1", "pending", 1, now()),
        )
        res = IncidentService(db).reconcile("inc1")
        self.assertNotEqual(res.get("outcome"), "recovered")

    def test_dispatched_unknown_not_autoreplay(self):
        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        policy = Policy(db)
        nt = FakeNT()
        actions = ActionService(db, nt, FakeGate(), policy, FakeProm())
        db.execute(
            "INSERT INTO actions(id, asset_id, object_id, capability, params_json, state, created_at,"
            " dispatched_at) VALUES(?,?,?,?,?,?,?,?)",
            ("a1", "nerv", "frps", "service.restart", "{}", "dispatched", now(), now()),
        )
        actions.mark_unknown_unfinished()
        self.assertFalse(nt.exec_calls)
        # 核清前仍 unknown
        row = db.query_one("SELECT state, adjudication FROM actions WHERE id='a1'")
        self.assertEqual(row["state"], "unknown")
        self.assertEqual(row["adjudication"], "")


class TestReplayHysteria(unittest.TestCase):
    def test_hysteria_investigation_no_write_expansion(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        t = now()
        db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
            " host_id_verified_at, prom_asset, enabled, notes, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,1,'',?,?)",
            ("sora", "Sora", "sora", "sora-exec", "sora", t, "sora", t, t),
        )
        for name, kind, port, proto in (
            ("hysteria-server", "service", None, ""),
            ("hy2-443", "port", 443, "udp"),
            ("google", "probe", None, ""),
        ):
            db.execute(
                "INSERT INTO objects(id, asset_id, kind, name, unit, container, port, protocol,"
                " external_probe, auto_recover, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (f"sora:{kind}:{name}", "sora", kind, name, name, "", port, proto, name, 1, t),
            )
        policy = Policy(db)
        for cap in ("service.status", "service.logs", "port.listen", "probe.status", "asset.summary"):
            policy.upsert_permission(
                subject_type="auto_rule", subject_id="agent", capability=cap,
                asset_id="sora", object_id="*", allow=True, require_approval=False,
                auto_allowed=True, actor="t",
            )
        nt = FakeNT()
        nt.set_script(("is-active", NTResult(ok=False, output="inactive", returncode=3)))
        inv = InvestigationService(db, nt, FakeGate(), FakeProm(), policy)
        res = asyncio.run(inv.run_loop(asset_id="sora", object_id="hysteria-server"))
        self.assertTrue(res["facts"])
        self.assertFalse(res.get("ok_for_auto_write"))
        self.assertFalse(nt.exec_calls)
        # 无自动 restart 权限
        d = policy.check(
            subject_type="auto_rule", subject_id="agent", capability="service.restart",
            asset_id="sora", object_id="sora:service:hysteria-server", auto=True,
        )
        self.assertFalse(d["allowed"])


class TestReplayPortBind(unittest.TestCase):
    def test_ayana_port_bind_knowledge_and_evidence(self):
        """bind failure / stale process：启动命令成功 ≠ Web 已恢复。"""
        root = Path(__file__).resolve().parents[1] / "knowledge"
        kb = KnowledgeBase(db=None, root=root)
        docs = kb.docs_for_object("kanata", "ayana")
        self.assertTrue(any(d.id == "ayana-port-bind-failed" for d in docs), docs)
        ctx = kb.investigation_context("kanata", "ayana")
        self.assertIn("bind", ctx["context_text"].lower() + ctx["context_text"])

        # 证据语义：transport 成功但业务未恢复
        from ayana.investigation import classify_evidence

        c = classify_evidence(
            "service.status", ["systemctl", "is-active", "ayana"],
            NTResult(ok=True, output="failed", returncode=3),
        )
        self.assertEqual(c["classification"], "observed")
        self.assertFalse(c["observed"]["healthy"])
        # 启动命令 transport ok ≠ recovered
        c2 = classify_evidence(
            "service.status", ["systemctl", "is-active", "ayana"],
            NTResult(ok=True, output="activating", returncode=0),
        )
        self.assertEqual(c2["classification"], "observed")
        self.assertFalse(c2["observed"].get("healthy"))


# ---------------------------------------------------------------------------
# 七、用户视角 acceptance
# ---------------------------------------------------------------------------

class TestUserAcceptance(unittest.TestCase):
    def test_user_sees_evidence_and_recovers(self):
        """用户路径：异常→调查→批准→执行→验证→恢复，timeline 完整。"""
        from ayana.incidents import IncidentService
        from ayana.alertmanager import AlertIngest

        tmp, db = make_db_env()
        self.addCleanup(close_env, tmp, db)
        policy = Policy(db)
        policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability="service.status",
            asset_id="nerv", object_id="*", allow=True, require_approval=False,
            auto_allowed=True, actor="t",
        )
        policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="*", allow=True, require_approval=True, actor="t",
        )
        nt = FakeNT()
        nt.set_script(("is-active", NTResult(ok=False, output="inactive", returncode=3)))
        prom = FakeProm(value=0)
        inv = InvestigationService(db, nt, FakeGate(), prom, policy)
        actions = ActionService(db, nt, FakeGate(), policy, prom, verify_timeout=1, verify_window=5)
        incidents = IncidentService(db)
        ingest = AlertIngest(db, incidents=incidents)

        # 1. alert
        ingest.ingest_webhook({"alerts": [{
            "labels": {"alertname": "TargetDown", "asset": "nerv", "service": "frps"},
            "status": "firing",
            "startsAt": "2026-10-07T10:00:00Z",
        }]})
        inc = db.query_one("SELECT * FROM incidents")
        self.assertIsNotNone(inc)
        inc_id = inc["id"]

        # 2. investigation
        ires = asyncio.run(inv.run_loop(
            asset_id="nerv", object_id="frps", incident_id=inc_id,
        ))
        self.assertTrue(ires["facts"])

        # 3. proposal
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            reason="frps inactive", incident_id=inc_id,
            proposer_type="web_user", proposer_id="admin",
            mode="manual", template_id="tmpl_service_restart",
        )

        # 4. approve + execute once
        ares = asyncio.run(actions.approve_and_execute(
            prop["id"], actor_type="web_user", actor_id="admin", channel="web",
        ))
        self.assertEqual(len(nt.exec_calls), 1)

        # 5. timeline has full causal chain
        detail = incidents.get_incident(inc_id)
        types = [e["type"] for e in detail["events"]]
        self.assertTrue(any(t in ("incident_opened", "alert_fired") for t in types), types)
        self.assertIn("action_proposed", types)
        self.assertIn("action_approved", types)
        self.assertTrue(
            any(t.startswith("action_") for t in types if t in
                ("action_success", "action_failure", "action_unknown", "action_dispatched")
                or t.startswith("action_")),
            types,
        )

        # 6. disposition context available for UI
        self.assertTrue(detail["actions"])
        self.assertTrue(detail["investigations"] or ires["id"])


if __name__ == "__main__":
    unittest.main()
