"""权限展示必须与实际授权判定一致，展示不能改写配置。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ayana.db import Database
from ayana.policy import Policy


class TestTruthfulPolicyViews(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.policy = Policy(self.db)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def grant(self, capability, *, asset_id="*", object_id="*", **flags):
        return self.policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability=capability,
            asset_id=asset_id, object_id=object_id, allow=True,
            require_approval=True, auto_allowed=False, **flags,
        )

    def assert_matches_authority(self, capability, asset_id="romi", object_id="obj-web"):
        decision = self.policy.effective_decision(subject_type="auto_rule", subject_id="agent",
            capability=capability, asset_id=asset_id, object_id=object_id)
        view = self.policy.effective_for(capability=capability, asset_id=asset_id, object_id=object_id)
        self.assertEqual(view["decision"], decision["decision"])
        self.assertEqual(view["allow"], decision["allowed"])
        self.assertEqual(view["require_approval"], decision["require_approval"])
        self.assertEqual(view["auto_allowed"], decision["auto_allowed"])
        self.assertEqual(view["reason"], decision["reason"])
        return view

    def test_read_approval_bit_is_not_displayed_as_real_approval(self):
        self.grant("service.logs")
        before = [dict(row) for row in self.db.query("SELECT * FROM permissions")]
        row = self.policy.default_policy()["service.logs"]
        self.assertEqual(row["state"], "auto")
        self.assertEqual(row["readable"], "允许读取")
        self.assertFalse(row["require_approval"])
        self.assertTrue(row["auto_allowed"])
        view = self.assert_matches_authority("service.logs")
        self.assertEqual(view["state"], "auto")
        self.assertEqual(view["source"], "default")
        self.assertEqual(self.policy.model_view()["defaults"]["service.logs"]["state"], "auto")
        self.assertEqual([dict(row) for row in self.db.query("SELECT * FROM permissions")], before)

    def test_read_exception_deny_and_matching_source_remain_effective(self):
        self.grant("service.logs")
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent",
            capability="service.logs", asset_id="romi", object_id="obj-web", allow=False)
        view = self.assert_matches_authority("service.logs")
        self.assertEqual(view["state"], "deny")
        self.assertEqual(view["source"], "exception")
        self.assertEqual(view["matched_rule"]["object_id"], "obj-web")
        self.assertEqual(self.policy.asset_exceptions()[0]["state"], "deny")

    def test_nonautomatic_write_capability_is_not_presented_as_automatic(self):
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent",
            capability="checks.write", allow=True, require_approval=False, auto_allowed=True)
        row = self.policy.default_policy()["checks.write"]
        self.assertEqual(row["state"], "confirm")
        self.assertEqual(self.assert_matches_authority("checks.write")["decision"], "approval_required")

    def test_agent_ceiling_block_is_reflected_without_changing_stored_rule(self):
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent",
            capability="service.restart", allow=True, require_approval=False, auto_allowed=True)
        self.policy.agent_ceiling.set("service.restart", allowed=False, allow_auto=False)
        before = [dict(row) for row in self.db.query("SELECT * FROM permissions")]
        view = self.assert_matches_authority("service.restart")
        self.assertEqual(view["state"], "deny")
        self.assertEqual(view["reason"], "denied_by_agent_ceiling")
        self.assertEqual(self.policy.default_policy()["service.restart"]["state"], "deny")
        self.assertEqual([dict(row) for row in self.db.query("SELECT * FROM permissions")], before)

    def test_auto_ceiling_requires_confirmation_in_display(self):
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent",
            capability="service.restart", allow=True, require_approval=False, auto_allowed=True)
        self.policy.agent_ceiling.set("service.restart", allowed=True, allow_auto=False)
        self.assertEqual(self.assert_matches_authority("service.restart")["state"], "confirm")
        self.assertEqual(self.policy.default_policy()["service.restart"]["state"], "confirm")

    def test_agent_terminal_block_is_not_displayed_as_granted(self):
        self.policy.upsert_permission(subject_type="auto_rule", subject_id="agent",
            capability="shell.interactive", allow=True, require_approval=False, auto_allowed=False)
        self.assertEqual(self.assert_matches_authority("shell.interactive")["state"], "deny")
        self.assertEqual(self.policy.default_policy()["shell.interactive"]["state"], "deny")

    def test_implicit_deny_remains_without_a_matching_rule(self):
        view = self.assert_matches_authority("service.logs")
        self.assertEqual(view["state"], "deny")
        self.assertEqual(view["source"], "implicit_deny")
        self.assertEqual(self.policy.model_view()["defaults"]["service.logs"]["state"], "deny")


if __name__ == "__main__":
    unittest.main()
