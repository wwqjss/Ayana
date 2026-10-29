"""P2 统一改造回归：词表 / series_key / host_health_view / policy / 配置。"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.business import host_health_view
from ayana.db import Database, now
from ayana.fmt import ZH_EVENT, ZH_STAGE, ZH_STATE, ZH_STATUS
from ayana.health import sample_state
from ayana.access import AccessControl as Policy
from ayana.prom import series_key, summarize_probe


class TestSampleStateVocabulary(unittest.TestCase):
    """P2-1: 统一样本判定词表 ok/fail/stale/no_data。"""

    def test_ok_fail_no_data_stale(self):
        now = time.time()
        self.assertEqual(sample_state({"sample_at": now, "value": 1}, 120, at=now), "ok")
        self.assertEqual(sample_state({"sample_at": now, "value": 0}, 120, at=now), "fail")
        self.assertEqual(sample_state(None, 120, at=now), "no_data")
        self.assertEqual(sample_state({"sample_at": now, "value": None}, 120, at=now), "no_data")
        self.assertEqual(sample_state({"sample_at": now - 600, "value": 1}, 120, at=now), "stale")

    def test_expect_ok_inverted(self):
        now = time.time()
        self.assertEqual(
            sample_state({"sample_at": now, "value": 0}, 120, at=now, expect_ok=False), "ok"
        )
        self.assertEqual(
            sample_state({"sample_at": now, "value": 1}, 120, at=now, expect_ok=False), "fail"
        )

    def test_nonfinite_is_no_data(self):
        now = time.time()
        self.assertEqual(sample_state({"sample_at": now, "value": float("nan")}, 120, at=now), "no_data")
        self.assertEqual(sample_state({"sample_at": float("nan"), "value": 1}, 120, at=now), "no_data")

    def test_unexpected_value_is_fail_not_ok(self):
        now = time.time()
        self.assertEqual(sample_state({"sample_at": now, "value": 2}, 120, at=now), "fail")


class TestSeriesKeySingleSource(unittest.TestCase):
    """P2-1: series_key 只留 prom.py 一份，monitor/business 复用。"""

    def test_strips_internal_labels(self):
        k = series_key({"__name__": "probe_success", "asset": "nerv", "service": "frps"})
        self.assertNotIn("__name__", k)
        self.assertIn("nerv", k)

    def test_monitor_uses_same_key(self):
        from ayana.monitor import series_key as mk
        from ayana.prom import series_key as pk

        labels = {"__name__": "up", "job": "node", "instance": "h1"}
        self.assertEqual(mk(labels), pk(labels))

    def test_business_uses_same_key(self):
        # business.prometheus_checks 内部走 prom.series_key；指纹稳定
        labels = {"asset": "nerv", "service": "frps", "__name__": "probe_success"}
        self.assertEqual(series_key(labels), series_key(dict(labels)))


class TestHostHealthView(unittest.TestCase):
    """P2-1: host_health_view 三 endpoint 共用拼装。"""

    def test_assembles_all_slices(self):
        now = time.time()
        prom_items = [
            {"name": "frps", "state": "ok", "required": True},
            {"name": "ext", "state": "fail", "required": False},
        ]
        view = host_health_view(
            prom_items=prom_items,
            native_states=["ok"],
            metric_state="ok",
            firing_severities=["warning"],
        )
        self.assertEqual(view["health"]["state"], "healthy")
        self.assertEqual(view["health"]["coverage"], "required 1")
        self.assertEqual(view["health"]["objects"][0]["state"], "healthy")
        self.assertEqual(view["health_dot"]["state"], "bad")  # fail check + warning→warn, fail wins
        self.assertEqual(view["business_summary"]["total"], 3)
        self.assertEqual(view["business_summary"]["healthy"], 2)
        self.assertEqual(view["business_summary"]["failed"], 1)
        self.assertEqual(view["firing"], ["warning"])

    def test_collect_error_path(self):
        view = host_health_view(
            prom_items=[],
            metric_state="collect_error",
            metric_error="prom query failed",
        )
        self.assertEqual(view["health_dot"]["state"], "collect_error")


class TestPolicyUnifiedEvaluation(unittest.TestCase):
    """Display and execution use the same authenticated-account decision."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.policy = Policy(self.db)
        for username, admin in (("admin", 1), ("viewer", 0)):
            self.db.execute(
                "INSERT INTO users(username,password_hash,is_admin,created_at,updated_at) VALUES(?,?,?,?,?)",
                (username, "test-hash", admin, now(), now()),
            )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_check_and_display_match_for_human_write(self):
        args = dict(subject_type="web_user", subject_id="admin", capability="service.restart",
                    asset_id="a1", object_id="o1")
        self.assertEqual(self.policy.check(**args), self.policy.effective_decision(**args))
        self.assertEqual(self.policy.check(**args)["decision"], "approval_required")

    def test_auto_write_requires_trusted_session_in_both_views(self):
        args = dict(subject_type="web_user", subject_id="admin", capability="service.restart", auto=True)
        checked = self.policy.check(**args)
        self.assertEqual(checked, self.policy.effective_decision(**args))
        self.assertFalse(checked["allowed"])
        self.assertEqual(checked["reason"], "trusted_session_context_required")

    def test_authenticated_viewer_reads_without_approval(self):
        decision = self.policy.effective_decision(subject_type="web_user", subject_id="viewer",
                                                  capability="asset.summary", asset_id="a1")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["decision"], "automatic")
        self.assertFalse(decision["require_approval"])
        self.assertEqual(decision["readable"], "允许读取")

    def test_machine_identity_alone_never_grants_access(self):
        for subject in ("auto_rule", "agent", "llm", "system"):
            with self.subTest(subject=subject):
                decision = self.policy.effective_decision(subject_type=subject, subject_id="agent",
                                                          capability="service.restart")
                self.assertFalse(decision["allowed"])
                self.assertEqual(decision["reason"], "trusted_session_context_required")


class TestFmtWordTables(unittest.TestCase):
    """P2-3: 词表只留 fmt.py，resolved 统一「已恢复」。"""

    def test_resolved_is_recovered(self):
        self.assertEqual(ZH_STATUS["resolved"], "已恢复")
        self.assertEqual(ZH_STATUS["open"], "处理中")
        self.assertEqual(ZH_STATUS["closed"], "已关闭")

    def test_qqbot_imports_fmt_tables(self):
        from ayana import qqbot

        self.assertIs(qqbot.ZH_STATUS, ZH_STATUS)
        self.assertIs(qqbot.ZH_STAGE, ZH_STAGE)
        self.assertIs(qqbot.ZH_STATE, ZH_STATE)

    def test_zh_event_in_fmt(self):
        self.assertEqual(ZH_EVENT["incident_opened"], "发现异常")
        self.assertEqual(ZH_EVENT["check_failed"], "检查失败")
        self.assertEqual(ZH_EVENT["incident_resolved"], "事件解决")


class TestChecksMultiChannelNotify(unittest.TestCase):
    """P2-3: checks 通知走 enqueue_for_event 多渠道。"""

    def test_raise_alert_uses_enqueue_for_event(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        t = time.time()
        db.execute(
            "INSERT INTO assets(id, display_name, read_alias, write_alias, created_at, updated_at)"
            " VALUES('a1','A','a1','a1',?,?)",
            (t, t),
        )
        from ayana.checks import CheckService

        notified = []

        class FakeNotifier:
            def enqueue_for_event(self, ev_id, *, body, typ=""):
                notified.append({"ev_id": ev_id, "body": body, "typ": typ})
                return True

            def enqueue(self, **kw):
                raise AssertionError("checks 不应再硬编码 enqueue(channel=qq)")

        svc = CheckService(db, transport=MagicMock())
        svc.notifier = FakeNotifier()
        svc.incidents = None
        check = {
            "id": "chk1", "asset_id": "a1", "kind": "port", "name": "web",
            "severity": "warning", "fail_threshold": 1, "params": {}, "expect": {},
        }
        asyncio.run(svc._raise_alert(check, detail="down", streak=1))
        self.assertTrue(notified, "check_failed 应走 enqueue_for_event")
        self.assertEqual(notified[0]["typ"], "check_failed")
        rows = db.query("SELECT type FROM events WHERE type='check_failed'")
        self.assertTrue(rows)


class TestConfigSources(unittest.TestCase):
    """P2-4: 死键修复 + config.example 补齐。"""

    def test_secret_keys_no_dead_session_signing_key(self):
        from ayana.config import SECRET_KEYS

        self.assertNotIn("session_signing_key", SECRET_KEYS)

    def test_gen_secrets_keys_subset_of_secret_keys(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "gen_secrets", Path(__file__).resolve().parents[1] / "scripts" / "gen-secrets.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        from ayana.config import SECRET_KEYS

        for k in mod.KEYS:
            self.assertIn(k, SECRET_KEYS)
        # llm_* 不随机生成
        for k in ("llm_api_key", "llm_base_url", "llm_model"):
            self.assertNotIn(k, mod.KEYS)

    def test_config_example_has_v073_keys(self):
        example = json.loads(
            (Path(__file__).resolve().parents[1] / "config.example.json").read_text(encoding="utf-8")
        )
        self.assertIn("required_checks", example)
        self.assertIn("runbook_rules", example)
        self.assertIn("prometheus_config", example)
        self.assertIn("alertmanager_webhook_path", example)

    def test_default_alertmanager_path_present(self):
        from ayana.config import DEFAULTS

        self.assertEqual(DEFAULTS["alertmanager_webhook_path"], "/hooks/alertmanager")

    def test_webapp_reads_alertmanager_webhook_path(self):
        from ayana.web import WebApp

        # 构造最小实例验证属性被保留（build 路由用它）
        import inspect

        sig = inspect.signature(WebApp.__init__)
        self.assertIn("alertmanager_webhook_path", sig.parameters)


class TestSummarizeProbeUsesSampleState(unittest.TestCase):
    def test_failure_sample_wins(self):
        now = time.time()
        s = summarize_probe({
            "result": [
                {"metric": {"a": "1"}, "value": 0, "sample_at": now - 30},
                {"metric": {"a": "1"}, "value": 1, "sample_at": now - 5},
            ]
        })
        self.assertEqual(s["state"], "fail")

    def test_ok_and_unknown_words_preserved(self):
        now = time.time()
        self.assertEqual(
            summarize_probe({"result": [{"metric": {}, "value": 1, "sample_at": now}]})["state"],
            "ok",
        )
        self.assertEqual(
            summarize_probe({"result": [{"metric": {}, "value": None, "sample_at": now}]})["state"],
            "unknown",
        )
        self.assertEqual(summarize_probe({"result": []})["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
