"""Composition, worker isolation and restart ordering use only local mocks."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from ayana.main import App


class AutonomyIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = {
            "db_path": str(Path(self.tmp.name) / "app.db"), "base_dir": self.tmp.name,
            "onewbot_token": "test", "webhook_token": "test", "ssh_credential_key": "test",
            "web_auth_pepper": "test", "prometheus_config": {"local_dir": str(Path(self.tmp.name) / "prom")},
        }
        self.apps = []

    def tearDown(self):
        for app in self.apps:
            app.db.close()
        self.tmp.cleanup()

    def app(self, **config):
        # P4.0：旧自治默认关闭；本文件测的是 legacy 路径，显式打开
        instance = App({**self.cfg, "legacy_agent_loop": True, **config})
        self.apps.append(instance)
        return instance

    async def start_without_network(self, app):
        scheduled = []
        def schedule(coro):
            scheduled.append(coro.cr_code.co_name)
            coro.close()
            return Mock()
        runner = SimpleNamespace(setup=AsyncMock(), cleanup=AsyncMock())
        app.nodewatch = None
        app._stop.set()
        with patch("ayana.main.web.AppRunner", return_value=runner), \
             patch("ayana.main.web.TCPSite", return_value=SimpleNamespace(start=AsyncMock())), \
             patch.object(app.auth, "ensure_setup_initialized", return_value={"state": "closed"}), \
             patch("ayana.main.asyncio.create_task", side_effect=schedule):
            await app.start()
        return scheduled

    async def test_composition_reuses_action_service_and_existing_llm_without_unconfigured_api_calls(self):
        app = self.app()
        self.assertIs(app.council.actions, app.actions)
        self.assertIs(app.autonomy.actions, app.actions)
        self.assertIs(app.autonomy.investigation, app.investigation)
        self.assertIs(app.webapp.autonomy, app.autonomy)
        self.assertIs(app.webapp.providers, app.providers)
        self.assertIs(app.webapp.llm, app.llm)
        self.assertIs(app.investigation.llm, app.llm)
        self.assertFalse(app.providers.public_config()["enabled"])
        self.assertEqual(app.db.query_one("SELECT COUNT(*) n FROM ai_calls")["n"], 0)

    async def test_global_automatic_switch_is_a_live_callback_not_a_captured_value(self):
        app = self.app(auto_remediation_enabled=False)
        self.assertTrue(callable(app.autonomy.runbook_auto_enabled))
        self.assertFalse(app.autonomy.runbook_auto_enabled())
        app.agent.auto_enabled = True
        self.assertTrue(app.autonomy.runbook_auto_enabled())
        app.agent.auto_enabled = False
        self.assertFalse(app.autonomy.runbook_auto_enabled())

    async def test_bad_optional_provider_config_does_not_disable_core_services(self):
        app = self.app(autonomous_agent={"roles": {"planner": {"model": None}}})
        self.assertIsNone(app.providers)
        self.assertIsNone(app.autonomy)
        self.assertIsNone(app.webapp.autonomy)
        self.assertIsNotNone(app.actions)
        self.assertIsNotNone(app.agent)
        self.assertIsNotNone(app.alert_ingest)
        scheduled = await self.start_without_network(app)
        for worker in ("_bg_agent", "_bg_outbox", "_bg_checks", "_bg_reconcile"):
            self.assertIn(worker, scheduled)
        self.assertNotIn("_bg_autonomy", scheduled)

    async def test_restart_marks_uncertain_writes_and_restores_verification_before_autonomy_recovery(self):
        app = self.app()
        order = []
        for name in ("mark_unknown_unfinished", "backfill_missing_verifications", "resume_pending_verifications"):
            setattr(app.actions, name, Mock(side_effect=lambda step=name: order.append(step) or 0))
        app.autonomy.recover_inflight = Mock(side_effect=lambda: order.append("autonomy_recovery"))
        scheduled = await self.start_without_network(app)
        self.assertEqual(order, ["mark_unknown_unfinished", "backfill_missing_verifications", "resume_pending_verifications", "autonomy_recovery"])
        self.assertEqual(scheduled.count("_bg_autonomy"), 1)
        self.assertEqual(scheduled.count("_bg_agent"), 1)

    async def test_autonomy_recovery_failure_prevents_new_ai_work_but_core_workers_start(self):
        app = self.app()
        app.autonomy.recover_inflight = Mock(side_effect=RuntimeError("simulated recovery failure"))
        scheduled = await self.start_without_network(app)
        self.assertIsNone(app.autonomy)
        self.assertIsNone(app.webapp.autonomy)
        self.assertNotIn("_bg_autonomy", scheduled)
        self.assertIn("_bg_agent", scheduled)
        self.assertIn("_bg_checks", scheduled)

    async def test_worker_bounds_concurrency_isolates_incidents_and_polls_verifications_during_slow_models(self):
        app = App.__new__(App)
        app.db = Mock()
        app._stop = asyncio.Event()
        calls, completed, cancelled = [], [], []
        active = set()
        high_water = 0
        async def tick(inc_id):
            nonlocal high_water
            calls.append(inc_id)
            active.add(inc_id)
            high_water = max(high_water, len(active))
            try:
                if inc_id == "bad":
                    raise RuntimeError("one incident failed")
                if inc_id == "slow":
                    await asyncio.Event().wait()
                completed.append(inc_id)
            except asyncio.CancelledError:
                cancelled.append(inc_id)
                raise
            finally:
                active.discard(inc_id)
        def ready(limit):
            return [name for name in ("bad", "slow", "good", "next") if name not in calls][:limit]
        app.autonomy = SimpleNamespace(tick=tick, poll_verifications=Mock(), ready_incident_ids=ready)
        passes = 0
        async def advance(waiter, timeout):
            nonlocal passes
            waiter.close()
            await asyncio.sleep(0)
            passes += 1
            if passes >= 5:
                app._stop.set()
                return True
            raise asyncio.TimeoutError
        with patch("ayana.main.asyncio.wait_for", side_effect=advance):
            await app._bg_autonomy()
        self.assertLessEqual(high_water, 3)
        self.assertEqual(calls.count("slow"), 1)
        self.assertIn("good", completed)
        self.assertIn("next", completed)
        self.assertIn("slow", cancelled)
        self.assertFalse(active)
        self.assertEqual(app.autonomy.poll_verifications.call_count, 5)

    async def test_model_failure_task_does_not_raise_into_core_agent_worker(self):
        app = App.__new__(App)
        app.autonomy = SimpleNamespace(tick=AsyncMock(side_effect=RuntimeError("offline")))
        await app._run_autonomy_incident("inc1")
        app.autonomy.tick.assert_awaited_once_with("inc1")


class LegacyDefaultOffTests(unittest.IsolatedAsyncioTestCase):
    """P4.0：默认 legacy_agent_loop=false 时旧自治不得启动。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.cfg = {
            "db_path": str(Path(self.tmp.name) / "app.db"),
            "base_dir": self.tmp.name,
            "onewbot_token": "test",
            "webhook_token": "test",
            "ssh_credential_key": "test",
            "web_auth_pepper": "test",
            "prometheus_config": {"local_dir": str(Path(self.tmp.name) / "prom")},
        }
        self.apps = []

    def tearDown(self):
        for app in self.apps:
            app.db.close()
        self.tmp.cleanup()

    async def test_default_no_legacy_workers_or_autonomy(self):
        app = App(self.cfg)
        self.apps.append(app)
        self.assertFalse(app.legacy_agent_loop)
        self.assertIsNone(app.autonomy)
        self.assertIsNone(app.council)
        self.assertTrue(app.agent.legacy_locked)
        self.assertFalse(app.agent.auto_enabled)
        scheduled = []
        def schedule(coro):
            scheduled.append(coro.cr_code.co_name)
            coro.close()
            return Mock()
        runner = SimpleNamespace(setup=AsyncMock(), cleanup=AsyncMock())
        app.nodewatch = None
        app._stop.set()
        with patch("ayana.main.web.AppRunner", return_value=runner), \
             patch("ayana.main.web.TCPSite", return_value=SimpleNamespace(start=AsyncMock())), \
             patch.object(app.auth, "ensure_setup_initialized", return_value={"state": "closed"}), \
             patch("ayana.main.asyncio.create_task", side_effect=schedule):
            await app.start()
        self.assertNotIn("_bg_agent", scheduled)
        self.assertNotIn("_bg_autonomy", scheduled)
        self.assertIn("_bg_reconcile", scheduled, "告警对账必须仍启动")

    async def test_toggle_cannot_enable_when_legacy_off(self):
        app = App(self.cfg)
        self.apps.append(app)
        app.agent.set_auto_enabled(True)
        self.assertFalse(app.agent.auto_enabled)


if __name__ == "__main__":
    unittest.main()
