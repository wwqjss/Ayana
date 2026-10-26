"""P4.4 retirement acceptance: simulated model flow, no paid/production calls.

This file deliberately labels FakeMimo evidence as simulated. Real P4.3 model
acceptance is documented separately; these tests only prove preserved wiring.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
import importlib
import inspect
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from ayana.alertmanager import AlertIngest
from ayana.auto_investigate import AutoInvestigator, InvestConfig
from ayana.config import DEFAULTS, load_config
from ayana.db import Database, SCHEMA_VERSION, now
from ayana.incidents import IncidentService
from ayana.knowledge import KnowledgeBase
from ayana.legacy_history import LegacyHistory, RetiredAutonomyError
from ayana.main import App
from ayana.mimo_session import RemoteSession
from ayana.session_bridge import SessionBridge

ROOT = Path(__file__).resolve().parents[1]
OLD_CLASSES = (
    ("ayana.agent", "AgentLoop"), ("ayana.autonomy", "AutonomyEngine"),
    ("ayana.ai_providers", "ProviderRegistry"), ("ayana.council", "CouncilService"),
)


class FakeMimo:
    """Deterministic local response; contains no real tool/model assertion."""
    model = "fake-mimo-for-retirement-regression"

    def __init__(self):
        self.calls = []

    def create(self, *, title, prompt, timeout=None):
        self.calls.append({"title": title, "prompt": prompt, "timeout": timeout})
        return RemoteSession(
            remote_session_id="ses_p44_simulated", status="active", model=self.model,
            text=json.dumps({
                "status": "completed", "symptoms": "simulated P4.4 alert",
                "facts": [{"claim": "local regression fixture", "evidence": "SIMULATED FakeMimo response"}],
                "hypotheses": [], "unconfirmed": ["no real host or MCP was contacted"],
                "next_steps": [], "root_cause": "unknown",
            }),
        )

    def exists(self, remote_session_id, *, timeout=20):
        return remote_session_id == "ses_p44_simulated"

    def resume(self, *args, **kwargs):
        raise AssertionError("duplicate firing must not resume or create another model request")


def forbid_old_constructors(stack):
    return [stack.enter_context(patch(module + "." + name, side_effect=AssertionError("retired constructor invoked")))
            for module, name in OLD_CLASSES]


class RetirementFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_simulated_alert_reaches_new_session_queue_worker_and_persisted_conclusion(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp, ExitStack() as stack:
            old = forbid_old_constructors(stack)
            process = stack.enter_context(patch("ayana.mimo_session.subprocess.run", side_effect=AssertionError("no real CLI allowed")))
            db = Database(Path(temp) / "flow.db")
            try:
                knowledge_root = Path(temp) / "kb"
                knowledge_root.mkdir()
                kb = KnowledgeBase(db, root=knowledge_root)
                kb.reload()
                mimo = FakeMimo()
                bridge = SessionBridge(db, knowledge=kb, mimo=mimo)
                worker = AutoInvestigator(db, knowledge=kb, mimo=mimo, bridge=bridge,
                                          config=InvestConfig(enabled=True, timeout_sec=2))
                incidents = IncidentService(db)
                incidents.session_bridge = bridge
                incidents.auto_investigator = worker
                ingest = AlertIngest(db, incidents=incidents)
                payload = {"alerts": [{
                    "status": "firing", "fingerprint": "p44-simulated-alert",
                    "startsAt": "2026-10-25T00:00:00Z",
                    "labels": {"alertname": "P44SimulatedTargetDown", "asset": "test-host", "service": "test-service", "severity": "warning"},
                    "annotations": {"summary": "P4.4 simulated regression only"},
                }]}
                first = ingest.ingest_webhook(payload)
                self.assertEqual((first["created"], first["quarantined"]), (1, 0))
                episode = db.query_one("SELECT * FROM alert_episodes")
                incident_id = episode["incident_id"]
                self.assertTrue(incident_id)
                # 新模型：session_incidents + duty_sessions
                link = db.query_one("SELECT * FROM session_incidents WHERE incident_id=?", (incident_id,))
                self.assertIsNotNone(link)
                session = db.query_one("SELECT * FROM duty_sessions WHERE id=?", (link["session_id"],))
                self.assertIsNotNone(session)
                self.assertTrue(session["id"].startswith("sess_"))
                job = db.query_one("SELECT * FROM investigation_jobs WHERE incident_id=?", (incident_id,))
                self.assertEqual((job["status"], job["generation"], job["rounds"]), ("queued", 1, 0))
                ingest.ingest_webhook(payload)
                self.assertEqual(db.query_one("SELECT COUNT(*) n FROM investigation_jobs")["n"], 1)
                self.assertEqual(await worker.tick_once(), 1)
                await __import__("asyncio").gather(*worker._running.values())
                worker._running.clear()
                job = db.query_one("SELECT * FROM investigation_jobs WHERE incident_id=?", (incident_id,))
                self.assertEqual((job["status"], job["rounds"], job["lease_expires_at"]), ("done", 1, 0))
                conclusion = json.loads(job["last_conclusion_json"])
                self.assertEqual(conclusion["remote_session_id"], "ses_p44_simulated")
                self.assertEqual(conclusion["root_cause"], "unknown")
                self.assertEqual(conclusion["facts"][0]["evidence"], "SIMULATED FakeMimo response")
                timeline = [dict(row) for row in db.query("SELECT * FROM events WHERE incident_id=? ORDER BY id", (incident_id,))]
                kinds = [event["type"] for event in timeline]
                for kind in ("alert_fired", "incident_opened", "session_opened", "auto_investigation"):
                    self.assertEqual(kinds.count(kind), 1, kind)
                self.assertLess(kinds.index("incident_opened"), kinds.index("auto_investigation"))
                self.assertEqual(db.query_one("SELECT status FROM incidents WHERE id=?", (incident_id,))["status"], "open")
                ingest.ingest_webhook(payload)
                self.assertEqual(await worker.tick_once(), 0)
                self.assertEqual(len(mimo.calls), 1)
                self.assertIn(incident_id, mimo.calls[0]["prompt"])
                self.assertEqual(db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)
                self.assertEqual(db.query_one("SELECT COUNT(*) n FROM session_write_ops")["n"], 0)
                process.assert_not_called()
                for constructor in old:
                    constructor.assert_not_called()
            finally:
                db.close()

    async def test_default_auto_stays_off_and_old_config_meta_env_cannot_start_a_legacy_worker(self):
        # P6.1: 新闭环 auto_investigate 默认开；legacy worker 仍不得被拉起
        self.assertTrue(DEFAULTS["auto_investigate"]["enabled"])
        self.assertTrue(DEFAULTS["auto_investigate"].get("closed_loop", False))
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp, ExitStack() as stack:
            base = Path(temp)
            (base / "config.json").write_text(json.dumps({
                "db_path": str(base / "app.db"), "legacy_agent_loop": True,
                "auto_remediation_enabled": True, "autonomous_agent": {"enabled": True},
                "web_auth_pepper": "regression-test", "ssh_credential_key": "regression-test",
                "prometheus_config": {"local_dir": str(base / "prom")},
            }), encoding="utf-8")
            (base / "secrets.json").write_text(json.dumps({"onewbot_token": "regression-test", "webhook_token": "regression-test"}), encoding="utf-8")
            stack.enter_context(patch.dict(os.environ, {
                "AYANA_LEGACY_AGENT_LOOP": "1", "AYANA_AUTO_REMEDIATION_ENABLED": "1",
                "AYANA_AI_PLANNER_API_KEY": "old-test-key", "AYANA_AI_REVIEWER_KIMI_API_KEY": "old-test-key",
            }))
            old = forbid_old_constructors(stack)
            cfg = load_config(base)
            db = Database(cfg["db_path"])
            db.execute("INSERT INTO meta(key,value) VALUES('agent_auto_enabled','1')")
            db.close()
            # Also bypass the loader with direct old config to prove App is inert.
            cfg.update(legacy_agent_loop=True, auto_remediation_enabled=True, autonomous_agent={"enabled": True})
            app = App(cfg)
            try:
                # P6.1: auto_investigator 是新闭环入口（默认开），不是旧 AgentLoop
                self.assertIsNotNone(app.auto_investigator)
                self.assertTrue(getattr(app.auto_investigator.config, "closed_loop", False))
                for attr in ("agent", "providers", "council", "autonomy"):
                    self.assertIsNone(getattr(app, attr))
                scheduled = []
                def schedule(coro):
                    scheduled.append(coro.cr_code.co_name)
                    coro.close()
                    return Mock()
                runner = SimpleNamespace(setup=AsyncMock(), cleanup=AsyncMock())
                stack.enter_context(patch("ayana.main.web.AppRunner", return_value=runner))
                stack.enter_context(patch("ayana.main.web.TCPSite", return_value=SimpleNamespace(start=AsyncMock())))
                stack.enter_context(patch.object(app.auth, "ensure_setup_initialized", return_value={"state": "closed"}))
                stack.enter_context(patch("ayana.main.asyncio.create_task", side_effect=schedule))
                app.nodewatch = None
                app._stop.set()
                await app.start()
                # 旧自治 worker 不得调度；新闭环 AutoInvestigator.run_forever 允许且仅一次
                for name in ("_bg_agent", "_bg_autonomy"):
                    self.assertNotIn(name, scheduled)
                self.assertLessEqual(scheduled.count("run_forever"), 1)
                for name in ("_bg_maintenance", "_bg_outbox", "_bg_reconcile", "_bg_checks"):
                    self.assertEqual(scheduled.count(name), 1)
                self.assertEqual(app.db.query_one("SELECT COUNT(*) n FROM investigation_jobs")["n"], 0)
                self.assertEqual(app.db.query_one("SELECT value FROM meta WHERE key='agent_auto_enabled'")["value"], "1")
                for constructor in old:
                    constructor.assert_not_called()
            finally:
                app.db.close()


class RetirementHistoryTests(unittest.TestCase):
    def test_existing_v20_database_reopen_preserves_council_action_incident_and_audit_history(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            path = Path(temp) / "history.db"
            db = Database(path)
            t = now()
            db.execute("INSERT INTO incidents(id,title,asset_id,object_id,status,stage,created_at,updated_at) VALUES('history-inc','historical incident','host','service','open','watching',?,?)", (t,t))
            db.execute("INSERT INTO council_goals(id,incident_id,generation,asset_id,object_id,repair_goal,created_at,updated_at) VALUES('history-goal','history-inc',1,'host','service','historical_goal',?,?)", (t,t))
            db.execute("INSERT INTO council_plans(id,incident_id,generation,goal_id,version,digest,asset_id,object_id,canonical_object,plan_json,state,created_at,expires_at) VALUES('history-plan','history-inc',1,'history-goal',1,'history-digest','host','service','service','{}','reviewed',?,?)", (t,t+300))
            db.execute("INSERT INTO council_reviews(id,plan_id,plan_digest,role,provider,model,state,approve,reason,requested_at,deadline_at,finished_at) VALUES('history-review','history-plan','history-digest','reviewer_kimi','kimi','historical-model','completed',1,'historical opinion',?,?,?)", (t,t+300,t))
            db.execute("INSERT INTO council_grants(id,plan_id,plan_digest,incident_id,generation,goal_id,asset_id,object_id,state,created_at,expires_at) VALUES('history-grant','history-plan','history-digest','history-inc',1,'history-goal','host','service','granted',?,?)", (t,t+300))
            db.execute("INSERT INTO actions(id,incident_id,asset_id,object_id,capability,mode,state,council_grant_id,created_at) VALUES('history-action','history-inc','host','service','service.restart','reviewed','unknown','history-grant',?)", (t,))
            db.audit("system", "retirement-regression", "historical_audit", incident_id="history-inc", detail={"historical": True})
            tables = ("incidents", "actions", "audit_log", "council_goals", "council_plans", "council_reviews", "council_grants", "schema_migrations")
            def rows(database):
                return {table: [dict(row) for row in database.query("SELECT * FROM " + table + " ORDER BY rowid")] for table in tables}
            before = rows(db)
            ddl = [tuple(row) for row in db.query("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
            self.assertEqual(int(db.query_one("SELECT value FROM meta WHERE key='schema_version'")["value"]), SCHEMA_VERSION)
            db.close()
            reopened = Database(path)
            try:
                self.assertGreaterEqual(SCHEMA_VERSION, 22)
                self.assertEqual(int(reopened.query_one("SELECT value FROM meta WHERE key='schema_version'")["value"]), SCHEMA_VERSION)
                self.assertEqual(rows(reopened), before)
                self.assertEqual([tuple(row) for row in reopened.query("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")], ddl)
                snapshot = LegacyHistory(reopened).snapshot("history-inc")
                self.assertTrue(snapshot["retired"])
                self.assertEqual(snapshot["plans"][0]["id"], "history-plan")
                self.assertEqual(rows(reopened), before)
                self.assertEqual(reopened.query_one("SELECT state FROM actions WHERE id='history-action'")["state"], "unknown")
            finally:
                reopened.close()


class RetirementSourceGuards(unittest.IsolatedAsyncioTestCase):
    def test_main_has_no_old_import_construction_or_worker_definition(self):
        tree = ast.parse((ROOT / "ayana/main.py").read_text(encoding="utf-8"))
        banned_classes = {name for _, name in OLD_CLASSES}
        banned_modules = {module.rsplit(".",1)[1] for module, _ in OLD_CLASSES}
        banned_workers = {"_bg_agent", "_bg_autonomy", "_run_autonomy_incident"}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module, banned_modules)
                for alias in node.names:
                    self.assertNotIn(alias.name, banned_classes)
            elif isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
                self.assertNotIn(name, banned_classes | banned_workers)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.assertNotIn(node.name, banned_workers)

    def test_all_four_compatibility_constructors_permanently_reject_before_using_dependencies(self):
        for module_name, class_name in OLD_CLASSES:
            cls = getattr(importlib.import_module(module_name), class_name)
            dependencies = [Mock() for _ in range(8)]
            with self.subTest(class_name=class_name), self.assertRaises(RetiredAutonomyError) as cm:
                cls(*dependencies, enabled=True, auto_enabled=True, legacy_locked=False)
            self.assertEqual(cm.exception.code, "legacy_autonomy_retired")
            for dependency in dependencies:
                self.assertEqual(dependency.mock_calls, [])

    async def test_all_compatibility_entry_methods_reject_even_when_construction_and_locks_are_bypassed(self):
        for module_name, class_name in OLD_CLASSES:
            cls = getattr(importlib.import_module(module_name), class_name)
            instance = object.__new__(cls)
            dependencies = {name: Mock() for name in ("db", "actions", "providers", "transport", "council", "investigation", "notifier")}
            instance.__dict__.update(dependencies)
            instance.__dict__.update(enabled=True, auto_enabled=True, writes_enabled=True, legacy_locked=False,
                                     runbook_auto_enabled=lambda: True)
            entries = [(name, value) for name, value in vars(cls).items() if inspect.isfunction(value)
                       and (not name.startswith("_") or name == "_auto_dispatch")]
            self.assertTrue(entries)
            for name, method in entries:
                with self.subTest(class_name=class_name, entry=name), self.assertRaises(RetiredAutonomyError):
                    if inspect.iscoroutinefunction(method):
                        await method(instance, "forged-old-id", enabled=True)
                    else:
                        method(instance, "forged-old-id", enabled=True)
            for name, dependency in dependencies.items():
                self.assertEqual(dependency.mock_calls, [], class_name + "." + name)


if __name__ == "__main__":
    unittest.main()
