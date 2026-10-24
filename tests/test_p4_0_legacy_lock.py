"""P4.0：旧自治安全收口。"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.agent import AgentLoop  # noqa: E402
from ayana.config import DEFAULTS  # noqa: E402
from ayana.db import Database  # noqa: E402


def make_db():
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db = Database(Path(tmp.name) / "t.db")
    return tmp, db


class TestLegacyLockDefaults(unittest.TestCase):
    def test_config_defaults_safe(self):
        self.assertFalse(DEFAULTS.get("auto_remediation_enabled"))
        self.assertFalse(DEFAULTS.get("legacy_agent_loop"))
        aa = DEFAULTS.get("autonomous_agent") or {}
        self.assertFalse(aa.get("enabled"))

    def test_agent_loop_starts_locked(self):
        tmp, db = make_db()
        self.addCleanup(db.close)
        self.addCleanup(tmp.cleanup)
        agent = AgentLoop(
            db, MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock()
        )
        self.assertTrue(agent.legacy_locked)
        self.assertFalse(agent.auto_enabled)

    def test_set_auto_enabled_blocked_when_locked(self):
        tmp, db = make_db()
        self.addCleanup(db.close)
        self.addCleanup(tmp.cleanup)
        agent = AgentLoop(
            db, MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            auto_enabled=False,
        )
        agent.legacy_locked = True
        agent.set_auto_enabled(True)
        self.assertFalse(agent.auto_enabled, "locked 时不得打开")
        row = db.query_one("SELECT value FROM meta WHERE key='agent_auto_enabled'")
        self.assertEqual(row["value"], "0", "meta 不得被写成 1")

    def test_set_auto_enabled_allows_disable_even_if_locked(self):
        tmp, db = make_db()
        self.addCleanup(db.close)
        self.addCleanup(tmp.cleanup)
        agent = AgentLoop(
            db, MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            auto_enabled=True,
        )
        agent.legacy_locked = True
        agent.set_auto_enabled(False)
        self.assertFalse(agent.auto_enabled)

    def test_unlock_allows_enable(self):
        tmp, db = make_db()
        self.addCleanup(db.close)
        self.addCleanup(tmp.cleanup)
        agent = AgentLoop(
            db, MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            auto_enabled=False,
        )
        agent.legacy_locked = False
        agent.set_auto_enabled(True)
        self.assertTrue(agent.auto_enabled)
        row = db.query_one("SELECT value FROM meta WHERE key='agent_auto_enabled'")
        self.assertEqual(row["value"], "1")

    def test_meta_1_does_not_override_lock(self):
        """即使 meta 被写成 1，legacy 锁定仍禁止自动执行。"""
        tmp, db = make_db()
        self.addCleanup(db.close)
        self.addCleanup(tmp.cleanup)
        db.execute(
            "INSERT INTO meta(key,value) VALUES('agent_auto_enabled','1')"
        )
        agent = AgentLoop(
            db, MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            auto_enabled=False,
        )
        agent.legacy_locked = True
        agent.set_auto_enabled(True)
        self.assertFalse(agent.auto_enabled)


if __name__ == "__main__":
    unittest.main()
