"""Runbook / 验证 profile 权限边界：通用化不得扩大自动执行范围。"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionError, ActionService
from ayana.db import Database, now
from ayana.ntsafe import NTResult
from ayana.policy import Policy
from ayana.runbook import RUNBOOK, RunbookRule, apply_runbook_rules, match_runbook
from ayana.verify_profiles import profile_for_action, PROFILES


class ProfileBoundaryTests(unittest.TestCase):
    def test_generic_recover_profile_has_no_asset_binding(self):
        p = profile_for_action(capability="service.restart", asset_id="any", object_id="svc")
        self.assertIsNotNone(p)
        self.assertEqual(p.id, "svc.recover")
        blob = str(p.checks).lower()
        self.assertNotIn("nerv", blob)
        self.assertNotIn("frps", blob)

    def test_profile_existence_does_not_grant_execute(self):
        """profile 只服务验证；调用方不得把它当授权。"""
        # 文档化断言：capabilities/policy 不读 PROFILES
        from ayana import capabilities, policy

        for mod in (capabilities, policy):
            src = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn("verify_profiles", src)
            self.assertNotIn("profile_for_action", src)

    def test_empty_runbook_matches_nothing(self):
        apply_runbook_rules([])
        self.assertIsNone(
            match_runbook(asset_id="x", object_name="y", alertname="TargetDown")
        )

    def test_runbook_match_still_specific(self):
        apply_runbook_rules(
            [
                {
                    "id": "rb_only_a",
                    "name": "only A",
                    "asset_id": "host-a",
                    "object_name": "svc-a",
                    "capability": "service.restart",
                }
            ]
        )
        self.addCleanup(lambda: apply_runbook_rules([]))
        self.assertIsNotNone(
            match_runbook(asset_id="host-a", object_name="svc-a", alertname="TargetDown")
        )
        self.assertIsNone(
            match_runbook(asset_id="host-b", object_name="svc-a", alertname="TargetDown")
        )
        self.assertIsNone(
            match_runbook(asset_id="host-a", object_name="svc-b", alertname="TargetDown")
        )

    def test_control_plane_never_matches_auto_runbook(self):
        apply_runbook_rules(
            [
                {
                    "id": "rb_ayana",
                    "name": "bad",
                    "asset_id": "*",
                    "object_name": "*",
                    "capability": "service.restart",
                }
            ]
        )
        self.addCleanup(lambda: apply_runbook_rules([]))
        self.assertIsNone(
            match_runbook(asset_id="h", object_name="ayana", alertname="TargetDown")
        )


class FakeNT:
    async def probe(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="ok", returncode=0)

    async def exec(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="ok", returncode=0)

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"x","mode":"exec","uid":1}')


class FakeGate:
    class B:
        asset_id = "host-a"
        read_alias = "host-a"
        write_alias = "host-a-exec"
        expected_host_id = "HOST-A"
        host_id_verified_at = 1.0

    def get(self, asset_id):
        return self.B()

    async def verify_account(self, asset_id, *, write=False):
        return {"ok": True, "mode": "exec" if write else "probe", "error": ""}


class AutoExecuteBoundaryTests(unittest.TestCase):
    """自动执行仍受 runbook × policy × 审批链约束。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.addCleanup(self.db.close)
        t = now()
        self.db.execute(
            "INSERT INTO assets(id,display_name,read_alias,write_alias,expected_host_id,host_id_verified_at,created_at,updated_at)"
            " VALUES('host-a','A','host-a','host-a-exec','HOST-A',?,?,?)",
            (t, t, t),
        )
        self.db.execute(
            "INSERT INTO objects(id,asset_id,kind,name,unit,created_at)"
            " VALUES('host-a:service:svc-a','host-a','service','svc-a','svc-a',?)",
            (t,),
        )
        self.db.execute(
            "INSERT OR IGNORE INTO users(username,password_hash,totp_enabled,is_admin,created_at,updated_at)"
            " VALUES('admin','x',0,1,?,?)",
            (t, t),
        )
        self.policy = Policy(self.db)
        self.actions = ActionService(
            self.db,
            nt=FakeNT(),
            gate=FakeGate(),
            policy=self.policy,
            prom=type("P", (), {})(),
            action_ttl=1800,
            verify_window=30,
            verify_timeout=5,
        )
        apply_runbook_rules([])

    def tearDown(self):
        apply_runbook_rules([])

    def test_auto_without_runbook_rejected(self):
        # 即便有通用 svc.recover，无 runbook 仍不得自动执行
        self.policy.upsert_permission(
            subject_type="auto_rule",
            subject_id="agent",
            capability="service.restart",
            asset_id="host-a",
            object_id="*",
            allow=True,
            require_approval=False,
            auto_allowed=True,
            actor="test",
        )
        with self.assertRaises(ActionError) as ctx:
            self.actions.propose(
                asset_id="host-a",
                object_id="host-a:service:svc-a",
                capability="service.restart",
                reason="probe fail",
                proposer_type="auto_rule",
                proposer_id="agent",
                mode="auto",
            )
        self.assertIn(ctx.exception.code, ("runbook_required", "denied", "template_required"))

    def test_manual_without_template_or_runbook_rejected(self):
        """无 template/runbook 的能力不得提案；有通用模板的仍走 Policy（默认拒绝）。"""
        # service.restart 有通用人工模板 → 可提案但 Policy 默认拒绝
        with self.assertRaises(ActionError) as ctx:
            self.actions.propose(
                asset_id="host-a",
                object_id="host-a:service:svc-a",
                capability="service.restart",
                reason="manual",
                proposer_type="web_user",
                proposer_id="admin",
                mode="manual",
            )
        self.assertIn(ctx.exception.code, ("denied", "template_required", "auto_not_allowed"))
        # 不存在的写能力类路径：无模板不得放行
        with self.assertRaises(ActionError) as ctx2:
            self.actions.propose(
                asset_id="host-a",
                object_id="host-a:service:svc-a",
                capability="service.restart",
                reason="manual",
                proposer_type="web_user",
                proposer_id="admin",
                mode="manual",
                template_id="",
                runbook_id="",
            )
        # 若 CAPABILITY_TEMPLATE 兜底成功，必须带 template_id 且仍被 Policy 拒
        self.assertTrue(ctx2.exception.code)

    def test_profile_not_used_as_policy(self):
        """即便 profile 存在，无 Policy 仍拒绝。"""
        apply_runbook_rules(
            [
                {
                    "id": "rb_a",
                    "name": "rb",
                    "asset_id": "host-a",
                    "object_name": "svc-a",
                    "capability": "service.restart",
                }
            ]
        )
        self.addCleanup(lambda: apply_runbook_rules([]))
        with self.assertRaises(ActionError) as ctx:
            self.actions.propose(
                asset_id="host-a",
                object_id="host-a:service:svc-a",
                capability="service.restart",
                reason="probe fail",
                proposer_type="auto_rule",
                proposer_id="agent",
                mode="auto",
                runbook_id="rb_a",
            )
        self.assertIn(ctx.exception.code, ("denied", "auto_not_allowed", "forbidden"))


if __name__ == "__main__":
    unittest.main()
