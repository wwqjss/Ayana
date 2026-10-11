"""权限模型：默认策略 / 资产例外 / 不扩大既有授权。"""
from __future__ import annotations

import os
import tempfile
import unittest

from ayana.db import Database
from ayana.policy import Policy


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
        self.policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent",
            capability="asset.summary", asset_id="*", object_id="*",
            allow=True, require_approval=False, auto_allowed=False, actor="t",
        )
        self.policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            allow=True, require_approval=True, auto_allowed=False, actor="t",
        )
        defaults = self.policy.default_policy()
        self.assertIn("asset.summary", defaults)
        self.assertEqual(defaults["asset.summary"]["state"], "auto")
        self.assertNotIn("service.restart", defaults)

        ex = self.policy.asset_exceptions()
        self.assertTrue(any(x["capability"] == "service.restart" and x["asset_id"] == "nerv" for x in ex))
        self.assertTrue(all(x["source"] == "exception" for x in ex))

    def test_effective_source_labels(self):
        self.policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent",
            capability="asset.summary", asset_id="*", object_id="*",
            allow=True, require_approval=False, auto_allowed=False, actor="t",
        )
        eff = self.policy.effective_for(capability="asset.summary", asset_id="kanata")
        self.assertEqual(eff["source"], "default")
        self.assertEqual(eff["state"], "auto")

        self.policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent",
            capability="asset.summary", asset_id="kanata", object_id="*",
            allow=False, require_approval=True, auto_allowed=False, actor="t",
        )
        eff2 = self.policy.effective_for(capability="asset.summary", asset_id="kanata")
        self.assertEqual(eff2["source"], "exception")
        self.assertEqual(eff2["state"], "deny")

    def test_implicit_deny_not_expand(self):
        mv = self.policy.model_view()
        self.assertTrue(any(v["state"] == "deny" for v in mv["defaults"].values()))

    def test_unknown_capability_rejected(self):
        from ayana.policy import PolicyDeny

        with self.assertRaises(PolicyDeny):
            self.policy.upsert_permission(
                subject_type="auto_rule", subject_id="agent",
                capability="totally.fake.cap", asset_id="*", object_id="*",
                allow=True, require_approval=False, auto_allowed=True, actor="t",
            )


if __name__ == "__main__":
    unittest.main()
