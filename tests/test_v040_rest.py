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
    db.execute(
        "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
        " VALUES('admin','x',0,1,?,?)",
        (now(), now()),
    )

    policy = Policy(db)
    return tmp, db, policy


class TestRetiredPolicyManagement(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.policy = make_env()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_mutations_fail_without_writing_history_or_rules(self):
        before = self.db.query_one("SELECT COUNT(*) n FROM config_versions")["n"]
        for method, args in (("upsert_permission", {"capability": "service.restart", "allow": True}),
                             ("delete_permission", {"permission_id": 1})):
            with self.subTest(method=method), self.assertRaises(PolicyDeny) as caught:
                getattr(self.policy, method)(**args)
            self.assertIn("permission_model_retired", caught.exception.reason)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM config_versions")["n"], before)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) n FROM permissions")["n"], 0)

    def test_legacy_preview_is_explicitly_retired(self):
        with self.assertRaises(PolicyDeny) as caught:
            self.policy.preview(subject_type="web_user", subject_id="admin", capability="service.restart")
        self.assertIn("permission_model_retired", caught.exception.reason)

    def test_role_decision_does_not_require_seed_grants(self):
        decision = self.policy.effective_decision(subject_type="web_user", subject_id="admin",
                                                  capability="service.restart", asset_id="nerv")
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["source"], "account_role")
        self.assertIsNone(decision["matched_rule"])


class TestApprovalAudit(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.policy = make_env()
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
