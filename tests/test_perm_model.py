"""Retired permission model: stored defaults/exceptions are never evaluated."""
from __future__ import annotations

import os
import tempfile
import unittest

from ayana.db import Database
from ayana.access import AccessControl as Policy, PolicyDeny


class PermModelTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.db = Database(self.path)
        self.db._init_schema()
        self.policy = Policy(self.db)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        try:
            os.unlink(self.path)
        except Exception:
            pass

    def test_default_vs_exception(self):
        """Default/exception storage no longer exists as an authorization model."""
        with self.assertRaises(PolicyDeny):
            self.policy.default_policy()
        with self.assertRaises(PolicyDeny):
            self.policy.asset_exceptions()

    def test_effective_source_labels(self):
        """Effective results carry only account-role provenance, never rule labels."""
        self.db.execute(
            "INSERT INTO users(username,password_hash,is_admin,created_at,updated_at)"
            " VALUES('admin','x',1,1,1)",
        )
        d = self.policy.check(subject_type="web_user", subject_id="admin",
            capability="service.restart", asset_id="nerv", object_id="o")
        self.assertEqual(d["source"], "account_role")
        self.assertIsNone(d["rule"])
        self.assertIsNone(d["matched_rule"])

    def test_implicit_deny_not_expand(self):
        """No stored grant can widen access: unauthenticated stays denied."""
        self.db.execute(
            "INSERT INTO permissions(subject_type,subject_id,asset_id,capability,object_id,"
            "allow,require_approval,auto_allowed,created_at,updated_at,created_by)"
            " VALUES('web_user','ghost','nerv','service.restart','*',1,0,1,1,1,'legacy')",
        )
        d = self.policy.check(subject_type="web_user", subject_id="ghost",
            capability="service.restart", asset_id="nerv", object_id="o")
        self.assertFalse(d["allowed"])


if __name__ == "__main__":
    unittest.main()
