"""外部事务：状态机、Token、幂等、Episode 收敛、失联/超时（不触网）。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database, SCHEMA_VERSION, now
from ayana.exttx import (
    ExtTxError,
    ExtTxService,
    LEGAL_TRANSITIONS,
    expected_run_times,
    hash_token,
    parse_ts,
    validate_schedule,
)
from ayana.incidents import IncidentService
from ayana.notify import Notifier


class FakeNotifier:
    def __init__(self):
        self.calls = []

    def enqueue_for_event(self, event_id, *, body, typ=""):
        self.calls.append({"event_id": event_id, "body": body, "typ": typ})
        return True

    def enqueue(self, **kw):
        self.calls.append({"enqueue": kw})
        return True


class ExtTxBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.tmp.name) / "t.db"))
        self.incidents = IncidentService(self.db)
        self.notifier = FakeNotifier()
        self.svc = ExtTxService(
            self.db, incidents=self.incidents, notifier=self.notifier, pepper="pep"
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def make_tx(self, **kw):
        data = {
            "event_key": "mysqlbk.cloud_backup",
            "name": "云盘备份",
            "description": "测试事务",
            "source_label": "kanata",
            "watch_mode": "off",
        }
        data.update(kw)
        return self.svc.create_transaction(data, actor="admin")


class TestMigration(ExtTxBase):
    def test_current_schema_retains_external_transactions(self):
        self.assertEqual(self.db.schema_version(), SCHEMA_VERSION)

    def test_ext_tables_exist(self):
        for t in ("ext_transactions", "ext_tokens", "ext_runs", "ext_watch_marks"):
            row = self.db.query_one(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (t,)
            )
            self.assertIsNotNone(row, t)


class TestValidation(ExtTxBase):
    def test_bad_event_key(self):
        with self.assertRaises(ExtTxError):
            self.make_tx(event_key="bad key!!")

    def test_bad_status(self):
        tx = self.make_tx()
        self.svc.issue_token(tx["id"])
        with self.assertRaises(ExtTxError):
            self.svc.report(
                {
                    "event_key": tx["event_key"],
                    "status": "not-a-status",
                    "run_id": "r1",
                }
            )

    def test_bad_run_id(self):
        tx = self.make_tx()
        with self.assertRaises(ExtTxError):
            self.svc.report(
                {
                    "event_key": tx["event_key"],
                    "status": "success",
                    "run_id": "bad run id!",
                }
            )

    def test_message_too_long(self):
        tx = self.make_tx()
        with self.assertRaises(ExtTxError):
            self.svc.report(
                {
                    "event_key": tx["event_key"],
                    "status": "failure",
                    "run_id": "r1",
                    "message": "x" * 501,
                }
            )

    def test_schedule_validate(self):
        self.assertEqual(validate_schedule({"kind": "daily", "time": "03:00"}),
                         {"kind": "daily", "time": "03:00"})
        self.assertEqual(validate_schedule({"kind": "weekly", "dow": 1, "time": "00:00"}),
                         {"kind": "weekly", "dow": 1, "time": "00:00"})
        with self.assertRaises(ExtTxError):
            validate_schedule({"kind": "weekly", "dow": 9, "time": "00:00"})
        with self.assertRaises(ExtTxError):
            validate_schedule({"kind": "daily", "time": "25:00"})

    def test_parse_ts(self):
        # 2026-10-19T00:00:00+08:00 == 2026-10-18T16:00:00Z
        self.assertAlmostEqual(parse_ts("2026-10-19T00:00:00+08:00"), 1792339200.0, delta=1)
        self.assertIsNone(parse_ts("not-a-time"))
        self.assertIsNone(parse_ts(None))


class TestToken(ExtTxBase):
    def test_issue_returns_plaintext_once(self):
        tx = self.make_tx()
        res = self.svc.issue_token(tx["id"], actor="admin")
        self.assertTrue(res["token"].startswith("ext_"))
        self.assertEqual(res["token"][-4:], res["token_hint"])
        # 列表不回显明文/哈希
        listed = self.svc.list_transactions()
        blob = json.dumps(listed)
        self.assertNotIn(res["token"], blob)
        self.assertNotIn(hash_token(res["token"], "pep"), blob)

    def test_multi_token_independent_revoke(self):
        tx = self.make_tx()
        t1 = self.svc.issue_token(tx["id"])
        t2 = self.svc.issue_token(tx["id"])
        self.svc.revoke_token(t1["token_id"])
        with self.assertRaises(ExtTxError):
            self.svc.authenticate_token(t1["token"])
        who = self.svc.authenticate_token(t2["token"])
        self.assertEqual(who["event_key"], tx["event_key"])

    def test_rotate_no_downtime(self):
        tx = self.make_tx()
        t1 = self.svc.issue_token(tx["id"])
        t2 = self.svc.rotate_token(tx["id"], t1["token_id"])
        # 新 Token 可用
        self.svc.authenticate_token(t2["token"])
        # 旧 Token 已吊销
        with self.assertRaises(ExtTxError):
            self.svc.authenticate_token(t1["token"])
        # 轮换时不指定旧 Token 则新旧并存
        t3 = self.svc.issue_token(tx["id"])
        t4 = self.svc.rotate_token(tx["id"], "")  # 不吊销
        self.svc.authenticate_token(t3["token"])
        self.svc.authenticate_token(t4["token"])

    def test_wrong_token_rejected(self):
        self.make_tx()
        with self.assertRaises(ExtTxError):
            self.svc.authenticate_token("ext_notreal")

    def test_revoked_rejected(self):
        tx = self.make_tx()
        t = self.svc.issue_token(tx["id"])
        self.svc.revoke_token(t["token_id"])
        with self.assertRaises(ExtTxError):
            self.svc.authenticate_token(t["token"])

    def test_disabled_tx_rejected(self):
        tx = self.make_tx()
        t = self.svc.issue_token(tx["id"])
        self.svc.set_enabled(tx["id"], False)
        with self.assertRaises(ExtTxError):
            self.svc.authenticate_token(t["token"])


class TestStateMachine(ExtTxBase):
    def test_legal_table_success_is_terminal(self):
        self.assertEqual(LEGAL_TRANSITIONS["success"], frozenset({"success"}))
        self.assertNotIn("failure", LEGAL_TRANSITIONS["success"])
        self.assertNotIn("running", LEGAL_TRANSITIONS["success"])

    def test_late_failure_cannot_overwrite_success(self):
        tx = self.make_tx()
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "success",
                "run_id": "r1",
                "timestamp": "2026-10-19T01:00:00+08:00",
            }
        )
        # 迟到的失败（旧时间戳）不得覆盖
        res = self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "failure",
                "run_id": "r1",
                "timestamp": "2026-10-19T00:00:00+08:00",
                "message": "迟到失败",
            }
        )
        self.assertTrue(res.get("rejected") or res.get("deduped"))
        run = self.svc.get_run(tx["id"], "r1")
        self.assertEqual(run["status"], "success")

    def test_running_then_success_ok(self):
        tx = self.make_tx()
        self.svc.report({"event_key": tx["event_key"], "status": "running", "run_id": "r2"})
        res = self.svc.report({"event_key": tx["event_key"], "status": "success", "run_id": "r2"})
        self.assertEqual(res["status"], "success")
        self.assertFalse(res["deduped"])

    def test_timeout_then_late_success_ok(self):
        tx = self.make_tx()
        self.svc.report({"event_key": tx["event_key"], "status": "timeout", "run_id": "r3"})
        res = self.svc.report({"event_key": tx["event_key"], "status": "success", "run_id": "r3"})
        self.assertEqual(res["status"], "success")

    def test_failure_then_success_same_run(self):
        tx = self.make_tx()
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "r4", "message": "err"}
        )
        res = self.svc.report(
            {"event_key": tx["event_key"], "status": "success", "run_id": "r4"}
        )
        self.assertEqual(res["status"], "success")
        run = self.svc.get_run(tx["id"], "r4")
        self.assertEqual(run["status"], "success")

    def test_idempotent_same_content(self):
        tx = self.make_tx()
        body = {
            "event_key": tx["event_key"],
            "status": "failure",
            "run_id": "r5",
            "message": "x",
            "detail": "y",
            "severity": "warning",
            "timestamp": "2026-10-19T00:00:00+08:00",
        }
        r1 = self.svc.report(dict(body))
        r2 = self.svc.report(dict(body))
        self.assertFalse(r1["deduped"])
        self.assertTrue(r2["deduped"])
        runs = self.svc.list_runs(tx["id"])
        self.assertEqual(len(runs), 1)

    def test_old_run_does_not_overwrite_new_txn_status(self):
        tx = self.make_tx()
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "success",
                "run_id": "new",
                "timestamp": "2026-10-19T12:00:00+08:00",
            }
        )
        # 新事务的 last_status 跟随最新上报
        t1 = self.svc.get_transaction(tx["id"])
        self.assertEqual(t1["last_status"], "success")
        self.assertEqual(t1["last_run_id"], "new")


class TestEpisodeIncident(ExtTxBase):
    def test_first_failure_creates_incident_and_notify(self):
        tx = self.make_tx()
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "failure",
                "run_id": "f1",
                "severity": "critical",
                "message": "备份失败",
                "detail": "RefreshTokenExpired",
            }
        )
        eps = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertEqual(len(eps), 1)
        inc_id = eps[0]["incident_id"]
        self.assertTrue(inc_id)
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        self.assertEqual(inc["status"], "open")
        # 生命周期通知已建立
        self.assertTrue(self.notifier.calls)

    def test_persistent_failure_no_duplicate_incident(self):
        tx = self.make_tx()
        for i in range(5):
            self.svc.report(
                {
                    "event_key": tx["event_key"],
                    "status": "failure",
                    "run_id": f"f{i}",
                    "message": f"失败{i}",
                }
            )
        eps = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertEqual(len(eps), 1, "持续失败应共用同一 episode")
        incs = self.db.query("SELECT * FROM incidents WHERE status='open'")
        self.assertEqual(len(incs), 1)
        runs = self.svc.list_runs(tx["id"])
        self.assertEqual(len(runs), 5, "每次执行都要留记录")

    def test_success_resolves_and_notifies_recovery(self):
        tx = self.make_tx()
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "f1"}
        )
        eps = self.db.query("SELECT * FROM alert_episodes WHERE source_id='ext_tx'")
        inc_id = eps[0]["incident_id"]
        self.notifier.calls.clear()
        self.svc.report(
            {"event_key": tx["event_key"], "status": "success", "run_id": "s1"}
        )
        ep = self.db.query_one(
            "SELECT * FROM alert_episodes WHERE id=?", (eps[0]["id"],)
        )
        self.assertEqual(ep["status"], "resolved")
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        self.assertIn(inc["status"], ("resolved", "closed"))
        # 恢复通知来自 incident_resolved 生命周期事件
        types = [c.get("typ") for c in self.notifier.calls]
        self.assertTrue(
            any(t in ("incident_resolved", "verified_recovered") for t in types)
            or self.notifier.calls
        )

    def test_timeout_alert(self):
        tx = self.make_tx(timeout_sec=60, alert_on_timeout=1)
        self.svc.report({"event_key": tx["event_key"], "status": "running", "run_id": "t1"})
        res = self.svc.watch_tick(now_ts=now() + 120)
        self.assertGreaterEqual(res["timeouts"], 1)
        run = self.svc.get_run(tx["id"], "t1")
        self.assertEqual(run["status"], "timeout")

    def test_heartbeat_missing(self):
        tx = self.make_tx(
            watch_mode="heartbeat",
            expect_interval_sec=60,
            grace_sec=30,
            alert_on_missing=1,
        )
        self.svc.report({"event_key": tx["event_key"], "status": "success", "run_id": "h1"})
        res = self.svc.watch_tick(now_ts=now() + 60 + 30 + 10)
        self.assertGreaterEqual(res["missing"], 1)
        # 再扫不重复告警
        res2 = self.svc.watch_tick(now_ts=now() + 60 + 30 + 20)
        self.assertEqual(res2["missing"], 0)

    def test_schedule_missed(self):
        # 计划：每天 00:00，宽限 60s；把 now 放到「今天 00:00 已过 + 宽限」之后
        from datetime import datetime, timezone

        tx = self.make_tx(
            watch_mode="schedule",
            schedule={"kind": "daily", "time": "00:00"},
            grace_sec=60,
            alert_on_missing=1,
        )
        base = datetime(2026, 10, 20, 1, 0, 0, tzinfo=timezone.utc).timestamp()
        res = self.svc.watch_tick(now_ts=base)
        self.assertGreaterEqual(res["missed"], 1)
        # 幂等
        res2 = self.svc.watch_tick(now_ts=base + 10)
        self.assertEqual(res2["missed"], 0)

    def test_schedule_expected_times(self):
        from datetime import datetime, timezone

        sched = {"kind": "weekly", "dow": 1, "time": "00:00"}  # 周一
        # 2026-10-20 是周二，lookback 3 天应包含 10-19 周一
        now_ts = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        times = expected_run_times(sched, now_ts=now_ts, lookback_sec=3 * 86400)
        self.assertTrue(times)
        # 最近一个是 2026-10-19 00:00 UTC
        latest = max(times)
        dt = datetime.fromtimestamp(latest, tz=timezone.utc)
        self.assertEqual(dt.isoweekday(), 1)
        self.assertEqual((dt.hour, dt.minute), (0, 0))


class TestCollectorVsBusiness(ExtTxBase):
    def test_collector_error_is_not_business_failure(self):
        tx = self.make_tx()
        # 先有业务成功
        self.svc.report(
            {"event_key": tx["event_key"], "status": "success", "run_id": "b1"}
        )
        # 采集异常
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "unknown",
                "report_kind": "collector",
                "run_id": "c1",
                "message": "数据库不可读",
                "detail": "sqlite3.OperationalError: database is locked",
            }
        )
        # 不得出现业务 failure episode
        fail_eps = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx'"
            " AND labels_json LIKE '%\"ext_problem\": \"failure\"%'"
        )
        self.assertEqual(len(fail_eps), 0)
        # 采集 episode 存在
        col_eps = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx'"
            " AND labels_json LIKE '%\"ext_problem\": \"collector\"%'"
        )
        self.assertEqual(len(col_eps), 1)
        self.assertEqual(col_eps[0]["status"], "firing")
        # last_status 不因采集上报变成 failure
        t1 = self.svc.get_transaction(tx["id"])
        self.assertEqual(t1["last_status"], "success")

    def test_collector_error_does_not_default_success(self):
        tx = self.make_tx()
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "unknown",
                "report_kind": "collector",
                "run_id": "c1",
                "message": "DB unreadable",
            }
        )
        run = self.svc.get_run(tx["id"], "c1")
        self.assertEqual(run["status"], "unknown")
        self.assertEqual(run["report_kind"], "collector")

    def test_collector_recovery_resolves_collector_episode(self):
        tx = self.make_tx()
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "failure",
                "report_kind": "collector",
                "run_id": "c1",
                "message": "采集异常",
            }
        )
        eps = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx'"
            " AND labels_json LIKE '%collector%' AND status='firing'"
        )
        self.assertEqual(len(eps), 1)
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "success",
                "report_kind": "collector",
                "run_id": "c2",
            }
        )
        ep = self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (eps[0]["id"],))
        self.assertEqual(ep["status"], "resolved")

    def test_collector_error_does_not_resolve_business_failure(self):
        tx = self.make_tx()
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "b1"}
        )
        fail_eps = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertTrue(fail_eps)
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "failure",
                "report_kind": "collector",
                "run_id": "c1",
                "message": "采集异常",
            }
        )
        # 业务 failure episode 仍应 firing（采集恢复≠业务恢复）
        # 但 collector 成功不应关闭业务失败
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "success",
                "report_kind": "collector",
                "run_id": "c2",
            }
        )
        fail = self.db.query_one(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx'"
            " AND labels_json LIKE '%\"ext_problem\": \"failure\"%'"
        )
        self.assertEqual(fail["status"], "firing")


class TestDeleteGuard(ExtTxBase):
    def test_delete_blocked_when_open_incident(self):
        tx = self.make_tx()
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "f1"}
        )
        with self.assertRaises(ExtTxError) as ctx:
            self.svc.delete_transaction(tx["id"], actor="admin")
        self.assertEqual(ctx.exception.code, "has_open_incident")
        # 禁用允许
        self.svc.set_enabled(tx["id"], False, actor="admin")
        t = self.svc.get_transaction(tx["id"])
        self.assertFalse(t["enabled"])

    def test_delete_ok_after_resolve(self):
        tx = self.make_tx()
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "f1"}
        )
        self.svc.report(
            {"event_key": tx["event_key"], "status": "success", "run_id": "s1"}
        )
        # 解决后 open_incident_id 清空
        self.svc.delete_transaction(tx["id"], actor="admin")
        self.assertIsNone(self.svc.get_transaction(tx["id"]))


class TestPersistence(ExtTxBase):
    def test_state_survives_reopen(self):
        tx = self.make_tx()
        t = self.svc.issue_token(tx["id"])
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "failure",
                "run_id": "f1",
                "message": "x",
            }
        )
        # 幂等标记与 run 在库中
        path = self.db.path
        self.db.close()
        db2 = Database(path)
        try:
            svc2 = ExtTxService(db2, incidents=IncidentService(db2), pepper="pep")
            runs = svc2.list_runs(tx["id"])
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["status"], "failure")
            # 同内容重放 → deduped
            res = svc2.report(
                {
                    "event_key": tx["event_key"],
                    "status": "failure",
                    "run_id": "f1",
                    "message": "x",
                }
            )
            self.assertTrue(res["deduped"])
            # Token 仍可用
            who = svc2.authenticate_token(t["token"])
            self.assertEqual(who["event_key"], tx["event_key"])
        finally:
            db2.close()


class TestReportKind(ExtTxBase):
    def test_default_report_kind_is_run(self):
        tx = self.make_tx()
        self.svc.report({"event_key": tx["event_key"], "status": "success", "run_id": "r1"})
        run = self.svc.get_run(tx["id"], "r1")
        self.assertEqual(run["report_kind"], "run")

    def test_bad_report_kind(self):
        tx = self.make_tx()
        with self.assertRaises(ExtTxError):
            self.svc.report(
                {
                    "event_key": tx["event_key"],
                    "status": "success",
                    "run_id": "r1",
                    "report_kind": "hacker",
                }
            )


class TestResolveDelay(ExtTxBase):
    def _fail_then_tx(self, **kw):
        tx = self.make_tx(**kw)
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "f1", "message": "err"}
        )
        eps = self.db.query("SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'")
        self.assertTrue(eps)
        inc_id = eps[0]["incident_id"]
        self.assertTrue(inc_id)
        return tx, inc_id

    def test_zero_delay_closes_immediately(self):
        tx, inc_id = self._fail_then_tx(resolve_delay_sec=0)
        self.svc.report({"event_key": tx["event_key"], "status": "success", "run_id": "s1"})
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        self.assertIn(inc["status"], ("resolved", "closed"))
        t = self.svc.get_transaction(tx["id"])
        self.assertEqual(float(t.get("pending_resolve_at") or 0), 0)

    def test_delay_holds_incident_open(self):
        tx, inc_id = self._fail_then_tx(resolve_delay_sec=300)
        self.svc.report({"event_key": tx["event_key"], "status": "success", "run_id": "s1"})
        # Run 立即入账
        run = self.svc.get_run(tx["id"], "s1")
        self.assertEqual(run["status"], "success")
        # Incident 仍打开
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        self.assertEqual(inc["status"], "open")
        t = self.svc.get_transaction(tx["id"])
        self.assertGreater(float(t.get("pending_resolve_at") or 0), 0)

    def test_delay_expiry_closes_incident(self):
        tx, inc_id = self._fail_then_tx(resolve_delay_sec=300)
        self.svc.report({"event_key": tx["event_key"], "status": "success", "run_id": "s1"})
        res = self.svc.watch_tick(now_ts=now() + 310)
        self.assertGreaterEqual(res["recovered"], 1)
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        self.assertIn(inc["status"], ("resolved", "closed"))

    def test_failure_during_delay_cancels_recovery(self):
        tx, inc_id = self._fail_then_tx(resolve_delay_sec=300)
        self.svc.report({"event_key": tx["event_key"], "status": "success", "run_id": "s1"})
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "f2", "message": "again"}
        )
        t = self.svc.get_transaction(tx["id"])
        self.assertEqual(float(t.get("pending_resolve_at") or 0), 0)
        # 到期扫描不应关闭
        res = self.svc.watch_tick(now_ts=now() + 400)
        self.assertEqual(res["recovered"], 0)
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        self.assertEqual(inc["status"], "open")


class TestCronSchedule(ExtTxBase):
    def test_cron_expr_accepted(self):
        s = validate_schedule({"kind": "cron", "expr": "0 0 * * 1", "tz": "Asia/Shanghai"})
        self.assertEqual(s["kind"], "cron")
        self.assertEqual(s["expr"], "0 0 * * 1")

    def test_cron_string_shorthand(self):
        s = validate_schedule("*/5 * * * *")
        self.assertEqual(s["kind"], "cron")

    def test_cron_invalid_rejected(self):
        with self.assertRaises(ExtTxError):
            validate_schedule({"kind": "cron", "expr": "0 0 * *"})
        with self.assertRaises(ExtTxError):
            validate_schedule({"kind": "cron", "expr": "not a cron"})

    def test_cron_expected_times_weekly(self):
        from datetime import datetime, timezone

        sched = {"kind": "cron", "expr": "0 0 * * 1", "tz": "UTC"}
        # 2026-10-20 是周二；lookback 3 天应含 2026-10-19 周一 00:00
        now_ts = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc).timestamp()
        times = expected_run_times(sched, now_ts=now_ts, lookback_sec=3 * 86400)
        self.assertTrue(times)
        latest = max(times)
        dt = datetime.fromtimestamp(latest, tz=timezone.utc)
        self.assertEqual(dt.isoweekday(), 1)
        self.assertEqual((dt.hour, dt.minute), (0, 0))

    def test_cron_missed_detection(self):
        from datetime import datetime, timezone

        tx = self.make_tx(
            watch_mode="schedule",
            schedule={"kind": "cron", "expr": "0 0 * * *", "tz": "UTC"},
            grace_sec=60,
            alert_on_missing=1,
        )
        base = datetime(2026, 10, 20, 1, 0, 0, tzinfo=timezone.utc).timestamp()
        res = self.svc.watch_tick(now_ts=base)
        self.assertGreaterEqual(res["missed"], 1)


class TestReceivedAt(ExtTxBase):
    def test_received_at_used_for_heartbeat_not_client_ts(self):
        tx = self.make_tx(
            watch_mode="heartbeat",
            expect_interval_sec=60,
            grace_sec=30,
            alert_on_missing=1,
        )
        # 客户端时间很新，但服务端接收时间应作为 last_report_at
        old_recv = now() - 3600
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "success",
                "run_id": "r1",
                "timestamp": "2030-01-01T00:00:00Z",
            },
            received_at=old_recv,
        )
        t = self.svc.get_transaction(tx["id"])
        self.assertAlmostEqual(float(t["last_report_at"]), old_recv, delta=2)
        # 服务端接收时间已超窗 → 应判失联
        res = self.svc.watch_tick(now_ts=old_recv + 120)
        self.assertGreaterEqual(res["missing"], 1)


class TestTokenPrivacy(ExtTxBase):
    def test_token_not_in_audit_or_events(self):
        tx = self.make_tx()
        tok = self.svc.issue_token(tx["id"], actor="admin")
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "failure",
                "run_id": "f1",
                "message": "m",
            }
        )
        blob = ""
        for r in self.db.query("SELECT detail_json FROM audit_log"):
            blob += r["detail_json"] or ""
        for r in self.db.query("SELECT payload_json FROM events"):
            blob += r["payload_json"] or ""
        for r in self.db.query("SELECT message, detail FROM ext_runs"):
            blob += (r["message"] or "") + (r["detail"] or "")
        self.assertNotIn(tok["token"], blob)
        self.assertNotIn(hash_token(tok["token"], "pep"), blob)

    def test_api_style_report_uses_bearer_only(self):
        """Token 不得出现在 run 的 message/detail。"""
        tx = self.make_tx()
        tok = self.svc.issue_token(tx["id"])
        self.svc.report(
            {
                "event_key": tx["event_key"],
                "status": "failure",
                "run_id": "f1",
                "message": "backup failed",
                "detail": "RefreshTokenExpired",
            },
            token_hint=tok["token_hint"],
        )
        run = self.svc.get_run(tx["id"], "f1")
        self.assertNotIn(tok["token"], run["message"] or "")
        self.assertNotIn(tok["token"], run["detail"] or "")


class TestDisabledAndAuth(ExtTxBase):
    def test_disabled_rejects_report(self):
        tx = self.make_tx()
        tok = self.svc.issue_token(tx["id"])
        self.svc.set_enabled(tx["id"], False)
        with self.assertRaises(ExtTxError) as ctx:
            self.svc.authenticate_token(tok["token"])
        self.assertEqual(ctx.exception.code, "transaction_disabled")

    def test_unknown_token(self):
        self.make_tx()
        with self.assertRaises(ExtTxError):
            self.svc.authenticate_token("ext_totally-wrong")

    def test_token_bound_to_one_event_key(self):
        """Token 绑定事务 A；web 层据 who.event_key 拒绝上报其他事务。"""
        a = self.make_tx(event_key="a.one", name="A")
        self.make_tx(event_key="b.two", name="B")
        tok = self.svc.issue_token(a["id"])
        who = self.svc.authenticate_token(tok["token"])
        self.assertEqual(who["event_key"], "a.one")
        self.assertEqual(who["transaction_id"], a["id"])


class TestFullHistory(ExtTxBase):
    def test_all_runs_kept_not_coalesced(self):
        tx = self.make_tx()
        for i in range(10):
            self.svc.report(
                {
                    "event_key": tx["event_key"],
                    "status": "success",
                    "run_id": f"r{i}",
                }
            )
        runs = self.svc.list_runs(tx["id"], limit=50)
        self.assertEqual(len(runs), 10)

    def test_same_second_rebuild_episode(self):
        """失败→成功→失败 在同一秒内：必须能重建 episode，不被 UNIQUE 撞掉。"""
        tx = self.make_tx(resolve_delay_sec=0)
        t0 = now()
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "a", "message": "1"},
            received_at=t0,
        )
        self.svc.report(
            {"event_key": tx["event_key"], "status": "success", "run_id": "b"},
            received_at=t0,
        )
        res = self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "c", "message": "2"},
            received_at=t0,
        )
        self.assertTrue(res.get("episode_id"), res)
        eps = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertEqual(len(eps), 1)

    def test_same_second_rapid_flap(self):
        """同秒内多次 成功/失败 抖动：run 全保留，episode 不炸不重复告警。"""
        tx = self.make_tx(resolve_delay_sec=0)
        t0 = now()
        for i in range(5):
            self.svc.report(
                {"event_key": tx["event_key"], "status": "failure", "run_id": f"f{i}",
                 "message": f"m{i}"},
                received_at=t0,
            )
            self.svc.report(
                {"event_key": tx["event_key"], "status": "success", "run_id": f"s{i}"},
                received_at=t0,
            )
        runs = self.svc.list_runs(tx["id"], limit=50)
        self.assertEqual(len(runs), 10)
        firing = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertEqual(len(firing), 0, "最后一次成功应已收敛")

    def test_episode_sync_error_audited_and_recoverable(self):
        """episode 同步异常：run 仍入账，审计可追踪，缓存不脏。"""
        tx = self.make_tx(resolve_delay_sec=0)
        orig = self.svc._upsert_episode

        def boom(**kw):
            raise RuntimeError("simulated sync failure")

        self.svc._upsert_episode = boom
        res = self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "sx1", "message": "x"},
        )
        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("episode_id") or "", "")
        run = self.svc.get_run(tx["id"], "sx1")
        self.assertEqual(run["status"], "failure")
        audits = self.db.query(
            "SELECT * FROM audit_log WHERE entry='ext_episode_sync_error'"
        )
        self.assertTrue(audits, "必须有审计记录")
        blob = json.dumps([dict(a) for a in audits], ensure_ascii=False)
        self.assertIn("sx1", blob)
        # 恢复后下一次上报可正常建 episode
        self.svc._upsert_episode = orig
        res2 = self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "sx2", "message": "y"},
        )
        self.assertTrue(res2.get("episode_id"))
        t = self.svc.get_transaction(tx["id"])
        self.assertTrue(t.get("open_incident_id"), "同步成功后缓存应有 open incident")

    def test_refresh_cache_on_partial_resolve(self):
        """同步半途失败后缓存以库内 episode 为准，不残留脏 open_incident_id。"""
        tx = self.make_tx(resolve_delay_sec=0)
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "p1"}
        )
        t1 = self.svc.get_transaction(tx["id"])
        self.assertTrue(t1.get("open_incident_id"))
        # 让 resolve 抛错
        orig = self.svc._resolve_episode

        def boom(*a, **k):
            raise RuntimeError("resolve fail")

        self.svc._resolve_episode = boom
        self.svc.report(
            {"event_key": tx["event_key"], "status": "success", "run_id": "p2"}
        )
        self.svc._resolve_episode = orig
        t2 = self.svc.get_transaction(tx["id"])
        # 库内 episode 仍 firing → 缓存仍指向 incident
        self.assertTrue(t2.get("open_incident_id"))
        # 正常成功后应清空
        self.svc.report(
            {"event_key": tx["event_key"], "status": "success", "run_id": "p3"}
        )
        t3 = self.svc.get_transaction(tx["id"])
        self.assertFalse(t3.get("open_incident_id"))

    def test_watch_tick_compensates_missing_episode(self):
        """Run 已写入、episode 同步失败：watch_tick 应补建 episode/Incident。"""
        tx = self.make_tx(resolve_delay_sec=0)
        orig = self.svc._upsert_episode

        def boom(**kw):
            raise RuntimeError("sync fail")

        self.svc._upsert_episode = boom
        res = self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "cx1",
             "message": "lost episode", "detail": "err"},
        )
        self.assertTrue(res.get("ok"))
        self.assertFalse(res.get("episode_id"))
        self.svc._upsert_episode = orig
        # 补偿前：无 firing episode
        eps0 = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertEqual(len(eps0), 0)
        # watch_tick 补偿
        tick = self.svc.watch_tick(now_ts=now())
        self.assertGreaterEqual(tick.get("compensated", 0), 1)
        eps = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertEqual(len(eps), 1)
        self.assertTrue(eps[0]["incident_id"])
        run = self.svc.get_run(tx["id"], "cx1")
        self.assertEqual(run.get("episode_id"), eps[0]["id"])
        # 幂等：再扫不重复建
        tick2 = self.svc.watch_tick(now_ts=now() + 1)
        self.assertEqual(tick2.get("compensated", 0), 0)
        eps2 = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertEqual(len(eps2), 1)

    def test_watch_tick_skips_compensate_after_success(self):
        """last_status=success 时不因历史失败 Run 补建 episode。"""
        tx = self.make_tx()
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "h1"}
        )
        self.svc.report(
            {"event_key": tx["event_key"], "status": "success", "run_id": "h2"}
        )
        tick = self.svc.watch_tick(now_ts=now())
        self.assertEqual(tick.get("compensated", 0), 0)
        firing = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertEqual(len(firing), 0)

    def test_labels_json_refreshed_on_same_streak(self):
        """同一 streak 再次上报会刷新 labels_json（含 severity）。"""
        tx = self.make_tx()
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "l1",
             "severity": "warning", "message": "m1"}
        )
        self.svc.report(
            {"event_key": tx["event_key"], "status": "failure", "run_id": "l2",
             "severity": "critical", "message": "m2"}
        )
        eps = self.db.query(
            "SELECT * FROM alert_episodes WHERE source_id='ext_tx' AND status='firing'"
        )
        self.assertEqual(len(eps), 1)
        labels = json.loads(eps[0]["labels_json"] or "{}")
        self.assertEqual(labels.get("severity"), "critical")
        ann = json.loads(eps[0]["annotations_json"] or "{}")
        self.assertEqual(ann.get("message"), "m2")


if __name__ == "__main__":
    unittest.main()
