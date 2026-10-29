"""终审 P1 失败路径回归：对象绑定、批准/取消、验证前置、断链 unknown。"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.exec_facts import ActionError, classify_exec_result
from ayana.capabilities import ObjectBindingError, build_write_tokens
from ayana.db import Database, now
from ayana.ntsafe import NTError, NTResult
from ayana.access import AccessControl as Policy
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
    # B2: 自批限制依赖 users.is_admin
    db.execute(
        "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
        " VALUES('admin','x',0,1,?,?)",
        (t, t),
    )
    db.execute(
        "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
        " VALUES('op','x',0,0,?,?)",
        (t, t),
    )
    policy = Policy(db)
    return tmp, db, policy


def _install_test_recover_profile(asset_id: str = "nerv", service: str = "frps"):
    """测试专用：发行版不再内置特定资产 profile，这里临时注册一个。"""
    from ayana import verify_profiles as vp

    pid = f"test.{asset_id}.recover"
    vp.PROFILES[pid] = vp.VerificationProfile(
        id=pid,
        name="test recover",
        capability="service.restart",
        object_kind="service",
        checks=(
            {
                "kind": "prom_range",
                "metric": "probe_success",
                "selector": {"asset": asset_id, "service": service},
                "success_value": 1,
            },
        ),
        warmup_sec=5.0,
        continuous_success_sec=30.0,
        max_sample_gap_sec=20.0,
        deadline_sec=120.0,
        expect="up",
    )
    orig = vp.profile_for_action

    def _pfa(*, capability, asset_id="", object_id=""):
        if capability == "service.restart":
            return vp.PROFILES[pid]
        return orig(capability=capability, asset_id=asset_id, object_id=object_id)

    vp.profile_for_action = _pfa
    return lambda: setattr(vp, "profile_for_action", orig)


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
