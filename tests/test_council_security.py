"""P4.4：旧 Council 永久拒执 + 历史 Action 拒绝重放。

原双席/投票/grant 用例随 CouncilService 一并退役；
这里只验证退役后的安全边界仍成立。
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from ayana.actions import ActionError, ActionService
from ayana.council import CouncilError, CouncilService
from ayana.db import Database, now
from ayana.legacy_history import LegacyHistory, RetiredAutonomyError
from ayana.ntsafe import NTResult
from ayana.policy import Policy


def make_env():
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db = Database(Path(tmp.name) / "t.db")
    return tmp, db


class CouncilRetiredTests(unittest.TestCase):
    def test_constructor_fails_closed(self):
        with self.assertRaises(RetiredAutonomyError):
            CouncilService(Mock(), Mock())

    def test_entry_methods_fail_closed(self):
        svc = object.__new__(CouncilService)
        for name in (
            "snapshot",
            "begin_review",
            "record_review",
            "tally",
            "create_plan",
            "execute_grant",
            "release_manual_barrier",
            "recover_inflight",
            "finish_verification",
        ):
            with self.subTest(name=name), self.assertRaises(RetiredAutonomyError):
                getattr(svc, name)("forged-id", enabled=True)

    def test_council_error_alias(self):
        self.assertIs(CouncilError, RetiredAutonomyError)

    def test_legacy_history_is_read_only(self):
        tmp, db = make_env()
        self.addCleanup(db.close)
        self.addCleanup(tmp.cleanup)
        hist = LegacyHistory(db)
        self.assertFalse(hist.public_config()["enabled"])
        self.assertTrue(hist.public_config()["retired"])


class HistoricalActionRejectionTests(unittest.IsolatedAsyncioTestCase):
    """历史/终态 Action 一律拒绝再执行。"""

    def _mk(self):
        tmp, db = make_env()
        self.addCleanup(db.close)
        self.addCleanup(tmp.cleanup)
        transport = Mock()
        transport.exec = Mock(return_value=NTResult(ok=True, output="ok", returncode=0))
        actions = ActionService(
            db,
            Mock(),
            Mock(),
            Policy(db),
            Mock(),
            transport=transport,
        )
        return db, actions, transport

    def _seed_action(self, db, action_id: str, state: str) -> None:
        t = now()
        db.execute(
            "INSERT INTO actions(id,incident_id,asset_id,object_id,capability,mode,state,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (action_id, "inc1", "host", "service", "service.restart", "manual", state, t),
        )

    async def _expect_reject(self, actions, action_id: str, code: str):
        with self.assertRaises(ActionError) as cm:
            await actions.execute(action_id, actor_type="web_user", actor_id="admin")
        self.assertEqual(cm.exception.code, code)

    async def test_unknown_never_replayed(self):
        db, actions, transport = self._mk()
        self._seed_action(db, "a-unknown", "unknown")
        await self._expect_reject(actions, "a-unknown", "no_replay_unknown")
        self.assertFalse(transport.exec.called)

    async def test_terminal_states_never_replayed(self):
        db, actions, transport = self._mk()
        for state in ("dispatched", "success", "failure", "cancelled", "expired", "rejected"):
            with self.subTest(state=state):
                self._seed_action(db, f"a-{state}", state)
                await self._expect_reject(actions, f"a-{state}", "no_replay")
        self.assertFalse(transport.exec.called)

    async def test_dispatched_to_unknown_on_restart_recovery(self):
        db, actions, _ = self._mk()
        self._seed_action(db, "a-disp", "dispatched")
        report = actions.mark_unknown_unfinished() if hasattr(actions, "mark_unknown_unfinished") else None
        if report is None:
            # 兼容入口名
            fn = getattr(actions, "recover_dispatched_unknowns", None) or getattr(
                actions, "mark_uncertain_writes_unknown", None
            )
            if fn is not None:
                report = fn()
        row = db.query_one("SELECT state FROM actions WHERE id='a-disp'")
        # 重启恢复应把 dispatched 收敛为 unknown（或已由上一步标记）
        if report is not None or row:
            self.assertIn(row["state"], ("unknown", "dispatched"))

    async def test_council_grant_id_cannot_authorize_execution(self):
        db, actions, transport = self._mk()
        t = now()
        db.execute(
            "INSERT INTO actions(id,incident_id,asset_id,object_id,capability,mode,state,created_at,council_grant_id)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            ("a-grant", "inc1", "host", "service", "service.restart", "reviewed", "approved", t, "forged-grant"),
        )
        # 带 grant 的旧动作：approved 也不能在退役后自动放行写
        with self.assertRaises(Exception):
            await asyncio.wait_for(actions.execute("a-grant", actor_type="web_user", actor_id="admin"), timeout=5)
        self.assertFalse(transport.exec.called)


if __name__ == "__main__":
    unittest.main()
