"""终审 P1 失败路径回归：对象绑定、批准/取消、验证前置、断链 unknown。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.actions import ActionError, ActionService, classify_exec_result
from ayana.capabilities import ObjectBindingError, build_write_tokens
from ayana.db import Database, now
from ayana.ntsafe import NTError, NTResult
from ayana.policy import Policy
from ayana.prom import match_series


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

    def __init__(self, verified=True):
        self.verified = verified

    def get(self, asset_id):
        if asset_id != "nerv":
            raise NTError("unknown-asset", asset_id)
        b = self.B()
        if not self.verified:
            b.host_id_verified_at = None
            b.expected_host_id = ""
        return b

    async def verify_account(self, asset_id, *, write=False):
        if not self.verified:
            return {"ok": False, "error": "host_id not registered/verified"}
        return {"ok": True, "mode": "exec" if write else "probe", "error": ""}


class FakeProm:
    """契约对齐 prom.PromClient：验证器调用 probe_success_since。"""

    def __init__(self):
        self.samples = []
        self.since_calls = []

    async def probe_success_since(
        self,
        asset,
        service="",
        *,
        start,
        end=None,
        step=15.0,
        window_sec=None,
        max_window_sec=600.0,
    ):
        self.since_calls.append({"asset": asset, "service": service, "start": start})
        out = []
        for s in self.samples:
            ts = s.get("sample_at")
            if ts is None or float(ts) <= float(start):
                continue
            labels = s.get("metric") or {}
            if labels.get("asset") != asset:
                continue
            if service and labels.get("service") != service:
                continue
            out.append(s)
        return out

    async def probe_success(self, asset, service=""):
        return {
            "result": match_series(self.samples, asset=asset, service=service),
            "evaluated_at": now(),
        }


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
        "INSERT INTO objects(id, asset_id, kind, name, unit, created_at)"
        " VALUES('nerv:service:nginx','nerv','service','nginx','nginx',?)",
        (t,),
    )
    policy = Policy(db)
    return tmp, db, policy


class TestObjectBinding(unittest.TestCase):
    def test_params_cannot_override_target(self):
        obj = {"kind": "service", "name": "frps", "unit": "frps"}
        tokens = build_write_tokens("service.restart", obj)
        self.assertEqual(tokens, ["systemctl", "restart", "frps"])

    def test_wrong_kind_rejected(self):
        obj = {"kind": "port", "name": "p", "port": 1, "protocol": "tcp"}
        with self.assertRaises((ObjectBindingError, ValueError)):
            build_write_tokens("service.restart", obj)


class TestClassifyExec(unittest.TestCase):
    def test_ssh_255_is_unknown(self):
        r = NTResult(ok=False, output="Connection reset", returncode=255)
        state, _ = classify_exec_result(r)
        self.assertEqual(state, "unknown")

    def test_denied_is_failure(self):
        r = NTResult(ok=False, output="Denied: not-allowlisted", returncode=126)
        state, _ = classify_exec_result(r)
        self.assertEqual(state, "failure")

    def test_timeout_is_unknown(self):
        r = NTResult(ok=False, output="timeout", returncode=-1, timed_out=True)
        state, _ = classify_exec_result(r)
        self.assertEqual(state, "unknown")


class TestActionSecurity(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.policy = make_env()
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=True,
        )
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:nginx", allow=True,
        )
        self.nt = FakeNT()
        self.prom = FakeProm()
        self.gate = FakeGate(verified=True)
        self.actions = ActionService(
            self.db, self.nt, self.gate, self.policy, self.prom,
            action_ttl=1800, approval_ttl=900, verify_window=5, verify_timeout=1,
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_approver_without_permission_does_not_cancel(self):
        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )
        with self.assertRaises(ActionError) as ctx:
            self.actions.approve(
                prop["id"], approver_type="web_user", approver_id="stranger"
            )
        self.assertEqual(ctx.exception.code, "approve_denied")
        row = self.db.query_one("SELECT state FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["state"], "proposed")

    def test_cancel_requires_owner(self):
        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )
        with self.assertRaises(ActionError) as ctx:
            self.actions.cancel(prop["id"], actor_type="web_user", actor_id="stranger")
        self.assertEqual(ctx.exception.code, "cancel_denied")
        row = self.db.query_one("SELECT state FROM actions WHERE id=?", (prop["id"],))
        self.assertEqual(row["state"], "proposed")

    def test_execute_rechecks_policy(self):
        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )
        self.actions.approve(prop["id"], approver_type="web_user", approver_id="admin")
        # 撤权
        self.policy.upsert_permission(
            subject_type="web_user", subject_id="admin", capability="service.restart",
            asset_id="nerv", object_id="nerv:service:frps", allow=False,
        )

        async def run():
            return await self.actions.execute(prop["id"])

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "policy_revoked")

    def test_execute_requires_verified_host_id(self):
        self.gate = FakeGate(verified=False)
        self.actions.gate = self.gate
        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )
        self.actions.approve(prop["id"], approver_type="web_user", approver_id="admin")

        async def run():
            return await self.actions.execute(prop["id"])

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "identity_gate")

    def test_unknown_blocks_same_object(self):
        self.db.execute(
            "INSERT INTO actions(id, asset_id, object_id, capability, params_json, state,"
            " created_at) VALUES('a1','nerv','nerv:service:frps','service.restart','{}','unknown',?)",
            (now(),),
        )
        with self.assertRaises(ActionError) as ctx:
            self.actions.propose(
                asset_id="nerv", object_id="frps", capability="service.restart",
                proposer_type="web_user", proposer_id="admin",
            )
        self.assertEqual(ctx.exception.code, "object_locked")

    def test_verify_requires_success_state(self):
        prop = self.actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )

        async def run():
            return await self.actions.verify(prop["id"])

        with self.assertRaises(ActionError) as ctx:
            asyncio.run(run())
        self.assertEqual(ctx.exception.code, "verify_requires_success")

    def test_verify_does_not_resolve_unrelated_service(self):
        # Action 是 frps，样本是 nginx —— 不得把 incident 关掉
        aid = "act_nginx"
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                aid,
                "inc1",
                "nerv",
                "nerv:service:frps",
                "service.restart",
                '{"tokens":["systemctl","restart","frps"],"object_name":"frps"}',
                "success",
                "web_user",
                "admin",
                now(),
                now(),
            ),
        )
        self.db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES('inc1','t','nerv','frps','open','pending',?,?)",
            (now(), now()),
        )
        # 只有 nginx 的成功样本
        self.prom.samples = [
            {
                "metric": {"asset": "nerv", "service": "nginx"},
                "value": 1,
                "sample_at": now() + 10,
            },
            {
                "metric": {"asset": "nerv", "service": "nginx"},
                "value": 1,
                "sample_at": now() + 25,
            },
        ]

        async def run():
            return await self.actions.verify(aid)

        res = asyncio.run(run())
        self.assertNotEqual(res["status"], "passed")
        inc = self.db.query_one("SELECT status FROM incidents WHERE id='inc1'")
        self.assertEqual(inc["status"], "open")
        # 正向：样本必须进入 probe_success_since（避免“没取到样本所以绿”）
        self.assertTrue(self.prom.since_calls, "verifier never sampled via probe_success_since")

    def test_positive_matching_samples_can_pass(self):
        """正向契约：匹配 service 的双样本可 passed（证明路径真实可恢复）。"""
        aid = "act_frps_ok"
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                aid, "inc2", "nerv", "nerv:service:frps", "service.restart",
                '{"tokens":["systemctl","restart","frps"],"object_name":"frps"}',
                "success", "web_user", "admin", now() - 30, now() - 30,
            ),
        )
        self.db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, created_at,"
            " updated_at) VALUES('inc2','t','nerv','frps','open','pending',?,?)",
            (now(), now()),
        )
        base = now() - 5
        self.prom.samples = [
            {"metric": {"asset": "nerv", "service": "frps"}, "value": 1, "sample_at": base + i * 15.0}
            for i in range(16)
        ]

        async def run():
            return await self.actions.verify(aid)

        res = asyncio.run(run())
        self.assertTrue(self.prom.since_calls)
        self.assertEqual(res["status"], "passed", res)
        v = self.db.query_one(
            "SELECT evidence_json FROM verifications WHERE action_id=?", (aid,)
        )
        self.assertIn("frps", v["evidence_json"] or "")


class TestMatchSeries(unittest.TestCase):
    def test_exact_service(self):
        samples = [
            {"metric": {"asset": "nerv", "service": "frps"}, "value": 1},
            {"metric": {"asset": "nerv", "service": "nginx"}, "value": 1},
        ]
        got = match_series(samples, asset="nerv", service="frps")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["metric"]["service"], "frps")


if __name__ == "__main__":
    unittest.main()
