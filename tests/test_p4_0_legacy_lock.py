"""P4.0 lock scenarios migrated to P4.4 permanent retirement, never unlockable."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from ayana.agent import AgentLoop
from ayana.config import DEFAULTS
from ayana.db import Database
from ayana.legacy_history import RetiredAutonomyError


class TestLegacyLockDefaults(unittest.TestCase):
    def assert_toggle_rejected(self, requested, *, locked):
        agent = object.__new__(AgentLoop)
        db, actions, model, transport = (Mock() for _ in range(4))
        agent.__dict__.update(db=db, actions=actions, llm=model, transport=transport,
                              auto_enabled=False, legacy_locked=locked)
        with self.assertRaises(RetiredAutonomyError) as cm:
            agent.set_auto_enabled(requested)
        self.assertEqual(cm.exception.code, "legacy_autonomy_retired")
        self.assertFalse(agent.auto_enabled)
        for dependency in (db, actions, model, transport):
            self.assertEqual(dependency.mock_calls, [])

    def test_config_defaults_safe(self):
        for key in ("auto_remediation_enabled", "legacy_agent_loop", "autonomous_agent"):
            self.assertNotIn(key, DEFAULTS)
        # P6.1: auto_investigate 是新闭环入口，默认开启；legacy agent auto 仍锁死
        self.assertTrue(DEFAULTS["auto_investigate"]["enabled"])
        self.assertTrue(DEFAULTS["auto_investigate"].get("closed_loop", False))

    def test_agent_loop_starts_locked(self):
        """Construction itself is rejected before any legacy service is used."""
        for enabled in (False, True):
            dependencies = [Mock() for _ in range(6)]
            with self.subTest(enabled=enabled), self.assertRaises(RetiredAutonomyError):
                AgentLoop(*dependencies, auto_enabled=enabled)
            for dependency in dependencies:
                self.assertEqual(dependency.mock_calls, [])

    def test_set_auto_enabled_blocked_when_locked(self):
        self.assert_toggle_rejected(True, locked=True)

    def test_set_auto_enabled_allows_disable_even_if_locked(self):
        """Retirement rejects the old control API even for a disable request."""
        self.assert_toggle_rejected(False, locked=True)

    def test_unlock_allows_enable(self):
        """Historical test name retained: fake unlock must now still reject."""
        self.assert_toggle_rejected(True, locked=False)

    def test_meta_1_does_not_override_lock(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp:
            db = Database(Path(temp) / "test.db")
            try:
                db.execute("INSERT INTO meta(key,value) VALUES('agent_auto_enabled','1')")
                dependencies = [Mock() for _ in range(5)]
                with self.assertRaises(RetiredAutonomyError):
                    AgentLoop(db, *dependencies, auto_enabled=True)
                agent = object.__new__(AgentLoop)
                agent.__dict__.update(db=db, auto_enabled=False, legacy_locked=False)
                with self.assertRaises(RetiredAutonomyError):
                    agent.set_auto_enabled(True)
                self.assertFalse(agent.auto_enabled)
                self.assertEqual(db.query_one("SELECT value FROM meta WHERE key='agent_auto_enabled'")["value"], "1")
                self.assertEqual(db.query_one("SELECT COUNT(*) n FROM actions")["n"], 0)
                for dependency in dependencies:
                    self.assertEqual(dependency.mock_calls, [])
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
