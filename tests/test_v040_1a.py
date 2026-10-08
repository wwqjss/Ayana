"""v0.4.0 1a：Agent ceiling 后端强制、敏感 TOTP 钩子、unknown 禁止重放。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import (
    WRITE_NO_REPLAY_STATES,
    ActionError,
    ActionService,
    write_may_dispatch,
)
from ayana.auth import AuthService, generate_totp_secret, totp_now
from ayana.capabilities import CAPABILITIES, ObjectBindingError, assert_within_ceiling
from ayana.db import Database, now
from ayana.ntsafe import NTResult
from ayana.policy import AGENT_SUBJECT_TYPES, AgentCeiling, Policy


class FakeNT:
    def __init__(self):
        self.calls = []
        self.next = NTResult(ok=True, output="ok", returncode=0)

    async def probe(self, alias, tokens, timeout=None):
        self.calls.append(("probe", alias, tokens))
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


def make_db_env():
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
    return tmp, db


class TestAgentCeiling(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db_env()
        self.policy = Policy(self.db)
        self.ceil = self.policy.agent_ceiling

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_default_follows_catalog(self):
        eff = self.ceil.effective("service.restart")
        self.assertTrue(eff["allowed"])
        self.assertTrue(eff["allow_auto"])
        self.assertEqual(eff["source"], "catalog")

    def test_user_cannot_invent_capability(self):
        with self.assertRaises(ObjectBindingError):
            self.ceil.set("shell.root", allowed=True, allow_auto=True, actor="admin")
        with self.assertRaises(ObjectBindingError):
            self.ceil.effective("not_a_capability")

    def test_user_ceiling_cannot_exceed_catalog_auto(self):
        # asset.summary 在目录中 auto_allowed=False，用户不得抬高
        eff = self.ceil.set("asset.summary", allowed=True, allow_auto=True, actor="admin")
        self.assertTrue(eff["allowed"])
        self.assertFalse(eff["allow_auto"])

    def test_backend_denies_agent_when_tightened(self):
        self.db.execute(
            "INSERT INTO permissions(subject_type, subject_id, asset_id, capability, object_id,"
            " allow, require_approval, auto_allowed, created_at, updated_at, created_by)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("auto_rule", "agent", "*", "service.restart", "*", 1, 0, 1, now(), now(), "seed"),
        )
        before = self.policy.check(
            subject_type="auto_rule",
            subject_id="agent",
            capability="service.restart",
            asset_id="nerv",
            object_id="nerv:service:nginx",
        )
        self.assertTrue(before["allowed"])
        self.ceil.set("service.restart", allowed=False, allow_auto=False, actor="admin")
        after = self.policy.check(
            subject_type="auto_rule",
            subject_id="agent",
            capability="service.restart",
            asset_id="nerv",
            object_id="nerv:service:nginx",
        )
        self.assertFalse(after["allowed"])
        self.assertEqual(after["reason"], "denied_by_agent_ceiling")
        dec = self.policy.effective_decision(
            subject_type="auto_rule",
            subject_id="agent",
            capability="service.restart",
            asset_id="nerv",
            object_id="nerv:service:nginx",
        )
        self.assertEqual(dec["decision"], "forbidden")
        self.assertEqual(dec["reason"], "denied_by_agent_ceiling")

    def test_auto_flag_tightened_by_ceiling(self):
        self.db.execute(
            "INSERT INTO permissions(subject_type, subject_id, asset_id, capability, object_id,"
            " allow, require_approval, auto_allowed, created_at, updated_at, created_by)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("auto_rule", "agent", "*", "service.restart", "*", 1, 0, 1, now(), now(), "seed"),
        )
        self.ceil.set("service.restart", allowed=True, allow_auto=False, actor="admin")
        d = self.policy.check(
            subject_type="auto_rule",
            subject_id="agent",
            capability="service.restart",
            asset_id="nerv",
            object_id="nerv:service:nginx",
            auto=True,
        )
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], "auto_not_allowed")
        # 人工路径仍允许（allowed=True 且非 auto）
        d2 = self.policy.check(
            subject_type="auto_rule",
            subject_id="agent",
            capability="service.restart",
            asset_id="nerv",
            object_id="nerv:service:nginx",
            auto=False,
        )
        self.assertTrue(d2["allowed"])
        self.assertFalse(d2["auto_allowed"])

    def test_non_agent_subject_unaffected(self):
        self.ceil.set("service.restart", allowed=False, allow_auto=False, actor="admin")
        self.db.execute(
            "INSERT INTO permissions(subject_type, subject_id, asset_id, capability, object_id,"
            " allow, require_approval, auto_allowed, created_at, updated_at, created_by)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("web_user", "admin", "*", "service.restart", "*", 1, 1, 0, now(), now(), "seed"),
        )
        d = self.policy.check(
            subject_type="web_user",
            subject_id="admin",
            capability="service.restart",
            asset_id="nerv",
            object_id="nerv:service:nginx",
        )
        self.assertTrue(d["allowed"])

    def test_list_covers_catalog(self):
        rows = self.ceil.list()
        self.assertEqual({r["capability"] for r in rows}, set(CAPABILITIES.keys()))
        self.assertTrue(all("allowed" in r for r in rows))

    def test_agent_subject_types(self):
        self.assertEqual(set(AGENT_SUBJECT_TYPES), {"auto_rule", "llm"})


class TestSensitiveTotp(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db_env()
        self.auth = AuthService(self.db, pepper="pep", session_ttl=3600, max_failed=8, lockout=60)
        self.auth.create_user("admin", "pw", is_admin=True)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def test_totp_disabled_skips(self):
        self.assertFalse(self.auth.totp_enabled("admin"))

    def test_totp_enabled_and_verify(self):
        secret = generate_totp_secret()
        t = now()
        self.db.execute(
            "UPDATE users SET totp_secret=?, totp_enabled=1, updated_at=? WHERE username=?",
            (secret, t, "admin"),
        )
        self.assertTrue(self.auth.totp_enabled("admin"))
        code = totp_now(secret)
        self.assertTrue(self.auth.verify_totp("admin", code))
        self.assertFalse(self.auth.verify_totp("admin", "000000"))
        # code 不得在任何返回值中出现
        self.assertFalse(self.auth.verify_totp("admin", ""))

    def test_sensitive_helper_contract(self):
        """与 web._sensitive_totp 同契约：未启用放行；启用后缺码/错码拒绝。"""
        secret = generate_totp_secret()
        self.db.execute(
            "UPDATE users SET totp_secret=?, totp_enabled=1 WHERE username=?",
            (secret, "admin"),
        )
        # 模拟 web 层判定逻辑
        def decide(body):
            if not self.auth.totp_enabled("admin"):
                return None
            code = str(body.get("totp") or "").strip()
            if not code:
                return "totp_required"
            if not self.auth.verify_totp("admin", code):
                return "totp_invalid"
            return None

        self.assertEqual(decide({"totp": totp_now(secret)}), None)
        self.assertEqual(decide({}), "totp_required")
        self.assertEqual(decide({"totp": "000000"}), "totp_invalid")


class TestUnknownNoReplay(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db_env()
        self.policy = Policy(self.db)
        self.db.execute(
            "INSERT INTO permissions(subject_type, subject_id, asset_id, capability, object_id,"
            " allow, require_approval, auto_allowed, created_at, updated_at, created_by)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("web_user", "admin", "*", "*", "*", 1, 1, 0, now(), now(), "seed"),
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

    def test_dispatch_predicate(self):
        self.assertTrue(write_may_dispatch("approved"))
        self.assertFalse(write_may_dispatch("unknown"))
        self.assertFalse(write_may_dispatch("dispatched"))
        self.assertFalse(write_may_dispatch("success"))
        self.assertIn("unknown", WRITE_NO_REPLAY_STATES)

    def test_execute_refuses_unknown(self):
        t = now()
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, reason, state, proposer_type, proposer_id, created_at,"
            " policy_snapshot_json, mode, runbook_id, runbook_rev, template_id,"
            " object_ref, params_digest, approval_deadline)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "act_unknown", "", "nerv", "nerv:service:nginx", "service.restart",
                "{}", "", "unknown", "web_user", "admin", t, "{}",
                "manual", "", "", "manual-template:svc-restart",
                "nerv:service:nginx", "x", t + 1800,
            ),
        )
        with self.assertRaises(ActionError) as ctx:
            asyncio.run(self.actions.execute("act_unknown", actor_id="admin"))
        self.assertEqual(ctx.exception.code, "no_replay_unknown")

    def test_execute_refuses_dispatched(self):
        t = now()
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, reason, state, proposer_type, proposer_id, created_at,"
            " policy_snapshot_json, mode, runbook_id, runbook_rev, template_id,"
            " object_ref, params_digest, approval_deadline)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "act_disp", "", "nerv", "nerv:service:nginx", "service.restart",
                "{}", "", "dispatched", "web_user", "admin", t, "{}",
                "manual", "", "", "manual-template:svc-restart",
                "nerv:service:nginx", "x", t + 1800,
            ),
        )
        with self.assertRaises(ActionError) as ctx:
            asyncio.run(self.actions.execute("act_disp", actor_id="admin"))
        self.assertEqual(ctx.exception.code, "no_replay")

    def test_propose_blocked_while_unknown_locks_object(self):
        t = now()
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, reason, state, proposer_type, proposer_id, created_at,"
            " policy_snapshot_json, mode, runbook_id, runbook_rev, template_id,"
            " object_ref, params_digest, approval_deadline)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "act_u2", "", "nerv", "nerv:service:nginx", "service.restart",
                "{}", "", "unknown", "web_user", "admin", t, "{}",
                "manual", "", "", "manual-template:svc-restart",
                "nerv:service:nginx", "x", t + 1800,
            ),
        )
        with self.assertRaises(ActionError) as ctx:
            self.actions.propose(
                asset_id="nerv",
                object_id="nerv:service:nginx",
                capability="service.restart",
                reason="retry",
                proposer_type="web_user",
                proposer_id="admin",
                mode="manual",
                template_id="manual-template:svc-restart",
            )
        self.assertEqual(ctx.exception.code, "object_locked")


if __name__ == "__main__":
    unittest.main()
