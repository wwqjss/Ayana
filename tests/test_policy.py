"""Legacy policy views are retired; the console decides by account role only."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ayana.db import Database, now
from ayana.policy import Policy, PolicyDeny


class TestTruthfulPolicyViews(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.policy = Policy(self.db)
        self.db.execute(
            "INSERT INTO users(username,password_hash,is_admin,created_at,updated_at)"
            " VALUES('admin','x',1,?,?)",
            (now(), now()),
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_stored_grant_views_are_retired(self):
        for call in (
            lambda: self.policy.default_policy(),
            lambda: self.policy.asset_exceptions(),
            lambda: self.policy.model_view(),
            lambda: self.policy.effective_for(capability="service.logs", asset_id="a", object_id="o"),
            lambda: self.policy.effective_summary(),
            lambda: self.policy.list_permissions(),
            lambda: self.policy.list_config_history(),
        ):
            with self.assertRaises(PolicyDeny):
                call()

    def test_grant_writes_are_retired(self):
        with self.assertRaises(PolicyDeny):
            self.policy.upsert_permission(
                subject_type="web_user", subject_id="admin", capability="service.logs",
                asset_id="a", object_id="o", allow=True,
            )
        with self.assertRaises(PolicyDeny):
            self.policy.delete_permission(1)
        with self.assertRaises(PolicyDeny):
            self.policy.preview(subject_type="web_user", subject_id="admin", capability="service.logs")

    def test_view_never_displays_more_than_the_decision(self):
        """Display (decision dict) matches authority: reads automatic, writes approval."""
        read = self.policy.check(subject_type="web_user", subject_id="admin",
            capability="service.logs", asset_id="a", object_id="o")
        self.assertEqual(read["decision"], "automatic")
        self.assertFalse(read["require_approval"])
        write = self.policy.check(subject_type="web_user", subject_id="admin",
            capability="service.restart", asset_id="a", object_id="o")
        self.assertEqual(write["decision"], "approval_required")
        self.assertTrue(write["require_approval"])
        self.assertEqual(self.policy.effective_decision(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="a", object_id="o")["decision"], write["decision"])


if __name__ == "__main__":
    unittest.main()
