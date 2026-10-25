"""P4.4: no old runtime composition; core recovery/maintenance stay independent."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from ayana.main import App
from ayana.config import DEFAULTS, RETIRED_AUTONOMY_KEYS, SECRET_KEYS, load_config


class _AppIntegrationCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
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
        instance = App({**self.cfg, "legacy_agent_loop": True, "auto_remediation_enabled": True,
                        "autonomous_agent": {"enabled": True}, **config})
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

    def assert_no_legacy(self, app):
        for name in ("agent", "autonomy", "council", "providers"):
            self.assertIsNone(getattr(app, name), name)
        self.assertFalse(app.legacy_agent_loop)
        for name in ("_bg_agent", "_bg_autonomy", "_run_autonomy_incident"):
            self.assertFalse(hasattr(App, name), name + " must be removed")

    def assert_core_scheduled(self, scheduled):
        for name in ("_bg_outbox", "_bg_checks", "_bg_reconcile", "_bg_correlate", "_bg_maintenance"):
            self.assertEqual(scheduled.count(name), 1, name)
        self.assertNotIn("_bg_agent", scheduled)
        self.assertNotIn("_bg_autonomy", scheduled)



class AutonomyIntegrationTests(_AppIntegrationCase):
    async def test_composition_reuses_action_service_and_existing_llm_without_unconfigured_api_calls(self):
        app = self.app()
        self.assert_no_legacy(app)
        self.assertIs(app.webapp.actions, app.actions)
        self.assertIs(app.qq.actions, app.actions)
        self.assertIs(app.investigation.llm, app.llm)
        self.assertIs(app.webapp.llm, app.llm)
        self.assertIs(app.actions.write_ops, app.session_bridge)
        self.assertEqual(app.db.query_one("SELECT COUNT(*) n FROM sqlite_master WHERE type='table' AND name='ai_calls'")["n"], 0)

    async def test_global_automatic_switch_is_a_live_callback_not_a_captured_value(self):
        """P4.4: no callback or mutable flag can recreate the removed service."""
        app = self.app(auto_remediation_enabled=True)
        app.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('agent_auto_enabled','1')")
        app.cfg.update(legacy_agent_loop=True, auto_remediation_enabled=True, autonomous_agent={"enabled": True})
        self.assert_no_legacy(app)
        self.assert_core_scheduled(await self.start_without_network(app))

    async def test_bad_optional_provider_config_does_not_disable_core_services(self):
        app = self.app(autonomous_agent={"enabled": True, "roles": {"planner": {"model": None}}})
        self.assert_no_legacy(app)
        self.assertIsNotNone(app.actions)
        self.assertIsNotNone(app.investigation)
        self.assertIsNotNone(app.alert_ingest)
        self.assert_core_scheduled(await self.start_without_network(app))

    async def test_restart_marks_uncertain_writes_and_restores_verification_before_autonomy_recovery(self):
        app = self.app()
        order = []
        for name in ("mark_unknown_unfinished", "backfill_missing_verifications", "resume_pending_verifications"):
            setattr(app.actions, name, Mock(side_effect=lambda step=name: order.append(step) or 0))
        # Injected old objects cannot be recovered or scheduled after retirement.
        old = Mock()
        app.autonomy = old
        self.assert_core_scheduled(await self.start_without_network(app))
        self.assertEqual(order, ["mark_unknown_unfinished", "backfill_missing_verifications", "resume_pending_verifications"])
        self.assertEqual(old.mock_calls, [])

    async def test_autonomy_recovery_failure_prevents_new_ai_work_but_core_workers_start(self):
        app = self.app()
        old = Mock()
        old.recover_inflight.side_effect = RuntimeError("must never be invoked")
        app.autonomy = old
        self.assert_core_scheduled(await self.start_without_network(app))
        old.recover_inflight.assert_not_called()
        self.assertEqual(old.mock_calls, [])

    async def test_worker_bounds_concurrency_isolates_incidents_and_polls_verifications_during_slow_models(self):
        """P4.4: even a supplied slow old engine receives no scheduling capacity."""
        app = self.app()
        old = Mock()
        old.tick = AsyncMock(side_effect=RuntimeError("slow provider is unreachable"))
        old.ready_incident_ids.return_value = ["slow", "good", "next"]
        app.autonomy = old
        self.assert_core_scheduled(await self.start_without_network(app))
        self.assertEqual(old.mock_calls, [])

    async def test_model_failure_task_does_not_raise_into_core_agent_worker(self):
        app = self.app()
        app.providers = Mock()
        app.providers.call_json = AsyncMock(side_effect=RuntimeError("must never call a model"))
        self.assert_core_scheduled(await self.start_without_network(app))
        self.assertEqual(app.providers.mock_calls, [])

    async def test_readonly_investigation_worker_remains_independent_and_makes_no_startup_model_call(self):
        with patch("ayana.mimo_session.subprocess.run") as process:
            app = self.app(auto_investigate={"enabled": True, "mimo_bin": "must-not-run-during-startup"})
            self.assert_no_legacy(app)
            self.assertIsNotNone(app.auto_investigator)
            self.assertIs(app.incidents.auto_investigator, app.auto_investigator)
            self.assertTrue(app.auto_investigator.mimo.readonly_env)
            scheduled = await self.start_without_network(app)
            self.assert_core_scheduled(scheduled)
            self.assertEqual(scheduled.count("run_forever"), 1)
            process.assert_not_called()

    async def test_maintenance_runs_both_expiry_paths_without_a_model_or_agent(self):
        app = self.app()
        app.actions.expire_stale_proposals = Mock()
        app.permission_changes.expire_stale = Mock(side_effect=app._stop.set)
        await app._bg_maintenance()
        app.actions.expire_stale_proposals.assert_called_once_with()
        app.permission_changes.expire_stale.assert_called_once_with()
        self.assertIsNotNone(app.db.query_one("SELECT value FROM meta WHERE key='worker_maintenance_last_ok'"))
        self.assert_no_legacy(app)

    async def test_maintenance_failure_does_not_skip_other_expiry_path(self):
        app = self.app()
        app.actions.expire_stale_proposals = Mock(side_effect=RuntimeError("injected expiry error"))
        app.permission_changes.expire_stale = Mock(side_effect=app._stop.set)
        with self.assertLogs("ayana", level="ERROR"):
            await app._bg_maintenance()
        app.actions.expire_stale_proposals.assert_called_once_with()
        app.permission_changes.expire_stale.assert_called_once_with()
        self.assert_no_legacy(app)


class LegacyDefaultOffTests(_AppIntegrationCase):
    async def test_default_no_legacy_workers_or_autonomy(self):
        app = self.app(legacy_agent_loop=False)
        self.assert_no_legacy(app)
        self.assert_core_scheduled(await self.start_without_network(app))

    async def test_toggle_cannot_enable_when_legacy_off(self):
        """Explicit old config/environment/meta cannot reconstruct retired classes."""
        env = {
            "AYANA_LEGACY_AGENT_LOOP": "1", "AYANA_AUTO_REMEDIATION_ENABLED": "1",
            "AYANA_AI_PLANNER_API_KEY": "retired-test-key", "AYANA_AI_CREDENTIAL_KEY": "retired-test-secret",
        }
        with patch.dict(os.environ, env), \
             patch("ayana.agent.AgentLoop", side_effect=AssertionError("retired constructor must not be called")) as agent, \
             patch("ayana.autonomy.AutonomyEngine", side_effect=AssertionError("retired constructor must not be called")) as engine, \
             patch("ayana.ai_providers.ProviderRegistry", side_effect=AssertionError("retired constructor must not be called")) as provider:
            app = self.app()
            app.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('agent_auto_enabled','1')")
            self.assert_no_legacy(app)
            self.assert_core_scheduled(await self.start_without_network(app))
        agent.assert_not_called()
        engine.assert_not_called()
        provider.assert_not_called()


class RetiredConfigurationTests(unittest.TestCase):
    def test_retired_config_secrets_and_environment_are_ignored_without_affecting_shared_llm_ssh(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            base = Path(temp)
            (base / "config.json").write_text(json.dumps({
                "legacy_agent_loop": True, "auto_remediation_enabled": True,
                "autonomous_agent": {"enabled": True, "roles": "malformed"},
                "ai_planner_api_key": "retired-config-key",
            }), encoding="utf-8")
            (base / "secrets.json").write_text(json.dumps({
                "onewbot_token": "test", "webhook_token": "test",
                "ai_credential_key": "retired-secret", "ai_planner_api_key": "retired-secret-key",
                "ai_reviewer_kimi_api_key": "retired-kimi", "ai_reviewer_deepseek_api_key": "retired-deepseek",
            }), encoding="utf-8")
            env = {"AYANA_AI_PLANNER_API_KEY": "retired-env-key", "AYANA_AI_CREDENTIAL_KEY": "retired-env-secret",
                   "AYANA_LLM_API_KEY": "shared-llm-test", "AYANA_SSH_CREDENTIAL_KEY": "shared-ssh-test"}
            with patch.dict(os.environ, env):
                cfg = load_config(base)
            for key in RETIRED_AUTONOMY_KEYS:
                self.assertNotIn(key, cfg)
                self.assertNotIn(key, SECRET_KEYS)
                self.assertNotIn(key, DEFAULTS)
            self.assertEqual(cfg["llm_api_key"], "shared-llm-test")
            self.assertEqual(cfg["ssh_credential_key"], "shared-ssh-test")


if __name__ == "__main__":
    unittest.main()
