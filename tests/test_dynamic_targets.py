"""动态目标：免预登记可执行，执行前存在性确认，名称注入仍拒绝。"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from ayana.actions import ActionError, ActionService, dynamic_object
from ayana.db import Database, now
from ayana.ntsafe import NTError, NTResult


class FakeNT:
    def __init__(self):
        self.calls = []
        self.exec_calls = []
        self.probe_result = NTResult(ok=True, output="loaded", returncode=0)

    async def probe(self, alias, tokens, timeout=None):
        self.calls.append(("probe", alias, tokens))
        return self.probe_result

    async def exec(self, alias, tokens, timeout=None):
        self.exec_calls.append(("exec", alias, tokens))
        return NTResult(ok=True, output="ok", returncode=0)

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"nt-probe","mode":"probe","uid":1}')


class FakeGate:
    class B:
        asset_id = "nerv"
        read_alias = "nerv"
        write_alias = "nerv-exec"
        expected_host_id = "NERV"
        host_id_verified_at = 1.0

    def get(self, asset_id):
        if asset_id != "nerv":
            raise NTError("unknown-asset", asset_id)
        return self.B()

    async def verify_account(self, asset_id, *, write=False):
        return {"ok": True, "mode": "exec" if write else "probe",
                "account": "nt-exec" if write else "nt-probe", "error": ""}


class FakeProm:
    async def probe_success(self, asset, service=""):
        return {"result": [{"metric": {}, "value": [0, "1"]}]}


def make_env():
    tmp = tempfile.TemporaryDirectory()
    db = Database(Path(tmp.name) / "t.db")
    t = now()
    db.execute(
        "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
        " host_id_verified_at, created_at, updated_at)"
        " VALUES('nerv','N','nerv','nerv-exec','NERV',?,?,?)",
        (t, t, t),
    )
    db.execute(
        "INSERT INTO objects(id, asset_id, kind, name, unit, created_at)"
        " VALUES('nerv:service:frps','nerv','service','frps','frps',?)",
        (t,),
    )
    db.execute(
        "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
        " VALUES('admin','x',0,1,?,?)",
        (t, t),
    )
    from ayana.policy import Policy

    nt = FakeNT()
    actions = ActionService(
        db, nt, FakeGate(), Policy(db), FakeProm(),
        action_ttl=1800, verify_window=5, verify_timeout=1,
    )
    return tmp, db, nt, actions


def close_env(tmp, db):
    try:
        db.close()
    except Exception:
        pass
    try:
        tmp.cleanup()
    except Exception:
        pass


class DynamicTargetTests(unittest.TestCase):
    def test_dynamic_object_binds_kind_and_validates_name(self):
        obj = dynamic_object("service.restart", "nerv", "nginx")
        self.assertIsNotNone(obj)
        self.assertEqual(obj["kind"], "service")
        self.assertEqual(obj["name"], "nginx")
        self.assertTrue(obj["_dynamic"])
        self.assertIsNone(dynamic_object("service.restart", "nerv", "ng inx"))
        self.assertIsNone(dynamic_object("service.restart", "nerv", "--all"))
        self.assertIsNone(dynamic_object("service.restart", "nerv", "x;rm -rf /"))

    def test_remediation_capabilities_have_verification_profiles(self):
        from ayana.verify_profiles import profile_for_action
        for capability in ("service.start", "service.restart", "service.stop",
                           "service.reload", "service.reset_failed", "container.restart"):
            self.assertIsNotNone(profile_for_action(capability=capability), capability)

    def test_propose_allows_unregistered_target(self):
        tmp, db, nt, actions = make_env()
        self.addCleanup(close_env, tmp, db)
        prop = actions.propose(
            asset_id="nerv", object_id="nginx", capability="service.start",
            reason="dynamic", proposer_type="web_user", proposer_id="admin",
            template_id="tmpl_service_restart",
        )
        self.assertEqual(prop["tokens"], ["systemctl", "start", "nginx"])
        row = db.query_one("SELECT params_json FROM actions WHERE id=?", (prop["id"],))
        self.assertTrue(json.loads(row["params_json"])["dynamic_target"])

    def test_execute_discovers_and_runs_dynamic_target(self):
        tmp, db, nt, actions = make_env()
        self.addCleanup(close_env, tmp, db)
        nt.probe_result = NTResult(ok=True, output="loaded", returncode=0)
        prop = actions.propose(
            asset_id="nerv", object_id="nginx", capability="service.start",
            reason="dynamic", proposer_type="web_user", proposer_id="admin",
            template_id="tmpl_service_restart",
        )
        actions.approve(prop["id"], approver_type="web_user", approver_id="admin")
        res = asyncio.run(actions.execute(prop["id"], actor_type="web_user", actor_id="admin"))
        self.assertEqual(res["state"], "success", res)
        self.assertEqual(nt.exec_calls[0][2], ["systemctl", "start", "nginx"])
        probes = [c for c in nt.calls if c[0] == "probe"]
        self.assertTrue(any("systemctl" in c[2] for c in probes), nt.calls)

    def test_execute_blocks_when_target_definitively_missing(self):
        tmp, db, nt, actions = make_env()
        self.addCleanup(close_env, tmp, db)
        nt.probe_result = NTResult(ok=True, output="not-found", returncode=0)
        prop = actions.propose(
            asset_id="nerv", object_id="ghost", capability="service.start",
            reason="dynamic", proposer_type="web_user", proposer_id="admin",
            template_id="tmpl_service_restart",
        )
        actions.approve(prop["id"], approver_type="web_user", approver_id="admin")
        with self.assertRaises(ActionError) as ctx:
            asyncio.run(actions.execute(prop["id"], actor_type="web_user", actor_id="admin"))
        self.assertEqual(ctx.exception.code, "target_not_found")
        self.assertFalse(nt.exec_calls)

    def test_execute_proceeds_when_probe_fails(self):
        tmp, db, nt, actions = make_env()
        self.addCleanup(close_env, tmp, db)

        async def broken_probe(alias, tokens, timeout=None):
            raise NTError("probe_unavailable", "net")

        nt.probe = broken_probe
        prop = actions.propose(
            asset_id="nerv", object_id="nginx", capability="service.start",
            reason="dynamic", proposer_type="web_user", proposer_id="admin",
            template_id="tmpl_service_restart",
        )
        actions.approve(prop["id"], approver_type="web_user", approver_id="admin")
        res = asyncio.run(actions.execute(prop["id"], actor_type="web_user", actor_id="admin"))
        self.assertEqual(res["state"], "success", res)
        self.assertTrue(nt.exec_calls)


if __name__ == "__main__":
    unittest.main()
