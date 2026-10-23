"""0.4：Permission Change + TOTP 专签一笔 + capability ceiling。"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import aiohttp.web  # noqa: F401
except Exception:
    import types

    _a = types.ModuleType("aiohttp")

    class _CT:
        def __init__(self, **k):
            pass

    class _CS:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def post(self, *a, **k):
            raise RuntimeError("no net")

    _a.ClientTimeout = _CT
    _a.ClientSession = _CS
    _a.web = types.SimpleNamespace(
        Application=type("Application", (), {"__init__": lambda self, **k: None}),
        Response=type("Response", (), {"__init__": lambda self, *a, **k: None}),
        json_response=lambda *a, **k: None,
    )
    sys.modules["aiohttp"] = _a
    sys.modules["aiohttp.web"] = _a.web

from ayana.capabilities import CAPABILITIES, assert_within_ceiling, ceiling
from ayana.db import Database, now
from ayana.permission_change import PermissionChangeError, PermissionChangeService
from ayana.policy import Policy, PolicyDeny


def make_env(totp_ok: dict | None = None):
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

    def verifier(username: str, code: str) -> bool:
        if totp_ok is None:
            return code == "123456" and username == "admin"
        return totp_ok.get(username) == code

    svc = PermissionChangeService(db, policy, totp_verifier=verifier, ttl_sec=3600)
    return tmp, db, policy, svc


def close_env(tmp, db):
    try:
        db.close()
    except Exception:
        pass
    try:
        tmp.cleanup()
    except Exception:
        pass


class TestCeiling(unittest.TestCase):
    def test_ceiling_contains_registered_only(self):
        names = ceiling()
        self.assertIn("service.restart", names)
        self.assertNotIn("shell.root", names)

    def test_assert_rejects_unknown(self):
        with self.assertRaises(Exception):
            assert_within_ceiling("shell.root")
        self.assertTrue(assert_within_ceiling("service.restart"))

    def test_policy_cannot_grant_outside_ceiling(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        with self.assertRaises(PolicyDeny):
            policy.upsert_permission(
                subject_type="auto_rule", subject_id="agent",
                capability="shell.root", asset_id="nerv", object_id="*",
                allow=True, actor="t",
            )

    def test_permission_change_cannot_invent_capability(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        with self.assertRaises(PermissionChangeError) as ctx:
            svc.propose(
                subject_type="auto_rule", subject_id="agent",
                capability="shell.root", asset_id="nerv", object_id="*",
                reason="give me root", created_by="agent", created_channel="system",
            )
        self.assertEqual(ctx.exception.code, "not_in_ceiling")
        n = db.query_one("SELECT COUNT(*) AS n FROM permission_changes")
        self.assertEqual(int(n["n"]), 0)


class TestPermissionChange(unittest.TestCase):
    def test_propose_does_not_apply(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        res = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            to_allow=True, to_require_approval=True, to_auto_allowed=False,
            reason="Incident #xxx needs nginx restart",
            created_by="agent", created_channel="system",
        )
        self.assertEqual(res["state"], "proposed")
        d = policy.check(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="nerv:service:nginx",
        )
        self.assertFalse(d["allowed"])

    def test_present_shows_diff(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        res = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            reason="need restart", created_by="agent", created_channel="system",
        )
        p = svc.present(res["id"])
        self.assertEqual(p["capability"], "service.restart")
        self.assertIn("from", p)
        self.assertIn("to", p)
        self.assertIn("change_id", p["note"])

    def test_authorize_applies_only_this_change(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        a = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            to_allow=True, to_require_approval=True, to_auto_allowed=False,
            reason="P-A", created_by="agent", created_channel="system",
        )
        b = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.stop", asset_id="nerv", object_id="*",
            to_allow=True, to_require_approval=False, to_auto_allowed=True,
            reason="P-B", created_by="agent", created_channel="system",
        )
        res = svc.authorize(
            a["id"], actor_id="admin", totp_code="123456",
            channel="web", is_admin=True,
        )
        self.assertEqual(res["state"], "applied")
        self.assertEqual(res["scope"], "this_change_only")
        # A 已生效
        d_a = policy.check(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="x",
        )
        self.assertTrue(d_a["allowed"])
        self.assertEqual(d_a["decision"], "approval_required")
        # B 未生效
        d_b = policy.check(
            subject_type="auto_rule", subject_id="agent",
            capability="service.stop", asset_id="nerv", object_id="x",
        )
        self.assertFalse(d_b["allowed"])
        b_row = db.query_one("SELECT state FROM permission_changes WHERE id=?", (b["id"],))
        self.assertEqual(b_row["state"], "proposed")

    def test_totp_invalid_no_apply(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        res = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            created_by="agent", created_channel="system",
        )
        with self.assertRaises(PermissionChangeError) as ctx:
            svc.authorize(
                res["id"], actor_id="admin", totp_code="000000",
                channel="web", is_admin=True,
            )
        self.assertEqual(ctx.exception.code, "totp_invalid")
        d = policy.check(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="x",
        )
        self.assertFalse(d["allowed"])
        row = db.query_one("SELECT state, totp_verified_at FROM permission_changes WHERE id=?", (res["id"],))
        self.assertEqual(row["state"], "proposed")
        self.assertIsNone(row["totp_verified_at"])

    def test_totp_code_not_persisted(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        res = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            created_by="agent", created_channel="system",
        )
        svc.authorize(res["id"], actor_id="admin", totp_code="123456", is_admin=True)
        blob = ""
        for r in db.query("SELECT detail_json FROM audit_log"):
            blob += r["detail_json"] or ""
        for r in db.query("SELECT payload_json FROM events"):
            blob += r["payload_json"] or ""
        for r in db.query("SELECT result_json, from_snapshot_json FROM permission_changes"):
            blob += (r["result_json"] or "") + (r["from_snapshot_json"] or "")
        self.assertNotIn("123456", blob)

    def test_reject_zero_apply(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        res = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            created_by="agent", created_channel="system",
        )
        r = svc.reject(res["id"], actor_id="admin", reason="not now")
        self.assertEqual(r["state"], "rejected")
        d = policy.check(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="x",
        )
        self.assertFalse(d["allowed"])

    def test_double_authorize_idempotent_no_reapply(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        res = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            created_by="agent", created_channel="system",
        )
        svc.authorize(res["id"], actor_id="admin", totp_code="123456", is_admin=True)
        with self.assertRaises(PermissionChangeError) as ctx:
            svc.authorize(res["id"], actor_id="admin", totp_code="123456", is_admin=True)
        self.assertEqual(ctx.exception.code, "bad_state")

    def test_non_admin_cannot_authorize(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        res = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            created_by="agent", created_channel="system",
        )
        with self.assertRaises(PermissionChangeError) as ctx:
            svc.authorize(
                res["id"], actor_id="bob", totp_code="123456",
                is_admin=False,
            )
        self.assertEqual(ctx.exception.code, "admin_required")

    def test_agent_can_propose_not_approve(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        # Agent 提出加权（这是合法的「拉一根申请杆」）
        res = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            reason="Incident #1 recovery needs service.restart",
            created_by="agent", created_channel="system",
        )
        self.assertEqual(res["state"], "proposed")
        # Agent 不能 approve（没有 is_admin + TOTP）
        with self.assertRaises(PermissionChangeError):
            svc.authorize(
                res["id"], actor_id="agent", totp_code="123456",
                is_admin=False,
            )

    def test_expired_not_applied(self):
        tmp, db, policy, svc = make_env()
        self.addCleanup(close_env, tmp, db)
        res = svc.propose(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="*",
            created_by="agent", created_channel="system",
        )
        db.execute(
            "UPDATE permission_changes SET created_at=? WHERE id=?",
            (now() - 99999, res["id"]),
        )
        with self.assertRaises(PermissionChangeError) as ctx:
            svc.authorize(res["id"], actor_id="admin", totp_code="123456", is_admin=True)
        self.assertEqual(ctx.exception.code, "expired")
        d = policy.check(
            subject_type="auto_rule", subject_id="agent",
            capability="service.restart", asset_id="nerv", object_id="x",
        )
        self.assertFalse(d["allowed"])


if __name__ == "__main__":
    unittest.main()
