"""v0.4.0 剩余：Policy 管理、审批关联 decision_id、审计补强。"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionError, ActionService
from ayana.db import Database, now
from ayana.ntsafe import NTResult
from ayana.policy import Policy, PolicyDeny


class FakeNT:
    def __init__(self):
        self.calls = []
        self.next = NTResult(ok=True, output="ok", returncode=0)

    async def probe(self, alias, tokens, timeout=None):
        return self.next

    async def exec(self, alias, tokens, timeout=None):
        self.calls.append(("exec", alias, tokens))
        return self.next

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"nt-exec","mode":"exec","uid":1}')


class FakeGate:
    class B:
        asset_id = "nerv"
        read_alias = "nerv"
        write_alias = "nerv-exec"
        expected_host_id = "NERV"
        host_id_verified_at = 1.0

    def get(self, asset_id):
        return self.B()

    async def verify_account(self, asset_id, *, write=False):
        return {"ok": True, "mode": "exec" if write else "probe", "error": ""}


class FakeProm:
    async def probe_success_since(self, *a, **k):
        return []


def make_env():
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "t.db")
    t = now()
    db.execute(
        "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
        " host_id_verified_at, prom_asset, enabled, notes, created_at, updated_at)"
        " VALUES(?,?,?,?,?,?,?,1,'',?,?)",
        ("nerv", "NERV", "nerv", "nerv-exec", "NERV", t, "nerv", t, t),
    )
    db.execute(
        "INSERT INTO objects(id, asset_id, kind, name, unit, container, port, protocol,"
        " external_probe, auto_recover, created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("nerv:service:nginx", "nerv", "service", "nginx", "nginx", "", 80, "tcp", "", 1, t),
    )
    policy = Policy(db)
    return tmp, db, policy


class TestPolicyManagement(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.policy = make_env()

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_upsert_records_before_after(self):
        res = self.policy.upsert_permission(
            subject_type="web_user",
            subject_id="admin",
            capability="service.restart",
            allow=True,
            asset_id="nerv",
            object_id="nerv:service:nginx",
            require_approval=True,
            actor="admin",
        )
        self.assertIsNone(res["before"])
        self.assertTrue(res["after"]["allow"])
        res2 = self.policy.upsert_permission(
            subject_type="web_user",
            subject_id="admin",
            capability="service.restart",
            allow=True,
            asset_id="nerv",
            object_id="nerv:service:nginx",
            require_approval=False,
            auto_allowed=True,
            actor="admin",
        )
        self.assertIsNotNone(res2["before"])
        self.assertTrue(res2["before"]["require_approval"])
        self.assertFalse(res2["after"]["require_approval"])
        # auto_allowed 被目录截断（service.restart 目录允许 auto）
        hist = self.policy.list_config_history(limit=10)
        self.assertGreaterEqual(len(hist), 2)
        self.assertIn("before", hist[0]["payload"])
        self.assertIn("after", hist[0]["payload"])

    def test_upsert_cannot_raise_auto_above_catalog(self):
        # asset.summary 目录 auto_allowed=False
        res = self.policy.upsert_permission(
            subject_type="auto_rule",
            subject_id="agent",
            capability="asset.summary",
            allow=True,
            require_approval=False,
            auto_allowed=True,
            actor="admin",
        )
        self.assertFalse(res["after"]["auto_allowed"])

    def test_upsert_validates_inputs(self):
        with self.assertRaises(PolicyDeny):
            self.policy.upsert_permission(
                subject_type="nope",
                subject_id="x",
                capability="service.restart",
                allow=True,
            )
        with self.assertRaises(PolicyDeny):
            self.policy.upsert_permission(
                subject_type="web_user",
                subject_id="",
                capability="service.restart",
                allow=True,
            )
        with self.assertRaises(PolicyDeny):
            self.policy.upsert_permission(
                subject_type="web_user",
                subject_id="a",
                capability="shell.root",
                allow=True,
            )

    def test_preview_dry_run_no_write(self):
        d = self.policy.preview(
            subject_type="web_user",
            subject_id="admin",
            capability="service.restart",
            asset_id="nerv",
            object_id="nerv:service:nginx",
        )
        self.assertEqual(d["decision"], "forbidden")
        self.assertEqual(self.policy.list_permissions(), [])

    def test_delete_records_before(self):
        self.policy.upsert_permission(
            subject_type="web_user",
            subject_id="admin",
            capability="service.restart",
            allow=True,
            asset_id="nerv",
            object_id="x",
            actor="admin",
        )
        perms = self.policy.list_permissions()
        self.policy.delete_permission(perms[0]["id"], actor="admin")
        hist = self.policy.list_config_history(limit=5)
        kinds = {h["kind"] for h in hist}
        self.assertIn("permission_delete", kinds)


class TestApprovalAudit(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.policy = make_env()
        self.db.execute(
            "INSERT INTO permissions(subject_type, subject_id, asset_id, capability, object_id,"
            " allow, require_approval, auto_allowed, created_at, updated_at, created_by)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("web_user", "admin", "*", "service.restart", "*", 1, 1, 0, now(), now(), "seed"),
        )
        self.actions = ActionService(
            self.db, FakeNT(), FakeGate(), self.policy, FakeProm(),
            action_ttl=1800, approval_ttl=900,
        )

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_approve_links_decision_id_and_audit(self):
        prop = self.actions.propose(
            asset_id="nerv",
            object_id="nerv:service:nginx",
            capability="service.restart",
            reason="test",
            proposer_type="web_user",
            proposer_id="admin",
            mode="manual",
            template_id="tmpl_service_restart",
        )
        res = self.actions.approve(
            prop["id"],
            approver_type="web_user",
            approver_id="admin",
            channel="web",
            reason="ok",
        )
        self.assertFalse(res["idempotent"])
        self.assertTrue(res.get("decision_id"))
        row = self.db.query_one("SELECT * FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["decision_id"], res["decision_id"])
        audits = self.db.query(
            "SELECT * FROM audit_log WHERE entry='action_approved' AND action_id=?",
            (prop["id"],),
        )
        self.assertEqual(len(audits), 1)
        a = audits[0]
        self.assertEqual(a["decision_id"], res["decision_id"])
        self.assertEqual(a["channel"], "web")
        detail = json.loads(a["detail_json"])
        self.assertEqual(detail["capability"], "service.restart")
        self.assertTrue(detail["tokens"])

    def test_exec_audit_has_tokens_and_decision(self):
        nt = FakeNT()
        self.actions.nt = nt
        prop = self.actions.propose(
            asset_id="nerv",
            object_id="nerv:service:nginx",
            capability="service.restart",
            reason="test",
            proposer_type="web_user",
            proposer_id="admin",
            mode="manual",
            template_id="tmpl_service_restart",
        )
        self.actions.approve(
            prop["id"], approver_type="web_user", approver_id="admin", channel="web"
        )
        res = asyncio.run(
            self.actions.execute(prop["id"], actor_type="web_user", actor_id="admin", is_admin=True)
        )
        self.assertEqual(res["state"], "success")
        audits = self.db.query(
            "SELECT * FROM audit_log WHERE entry='action_success' AND action_id=?",
            (prop["id"],),
        )
        self.assertEqual(len(audits), 1)
        detail = json.loads(audits[0]["detail_json"])
        self.assertTrue(detail["tokens"])
        self.assertEqual(detail["capability"], "service.restart")
        row = self.db.query_one("SELECT decision_id FROM actions WHERE id=?", (prop["id"],))
        self.assertTrue(row["decision_id"])
        self.assertEqual(audits[0]["decision_id"], row["decision_id"])

    def test_reject_links_decision_id(self):
        prop = self.actions.propose(
            asset_id="nerv",
            object_id="nerv:service:nginx",
            capability="service.restart",
            reason="test",
            proposer_type="web_user",
            proposer_id="admin",
            mode="manual",
            template_id="tmpl_service_restart",
        )
        res = self.actions.reject(
            prop["id"], actor_type="web_user", actor_id="admin", channel="web", reason="no"
        )
        self.assertTrue(res.get("decision_id"))
        row = self.db.query_one("SELECT decision_id FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["decision_id"], res["decision_id"])


if __name__ == "__main__":
    unittest.main()
