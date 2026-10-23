"""Phase C: P0-04/05/06 positive and negative tests."""

from __future__ import annotations

import asyncio
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import aiohttp.web  # noqa: F401
except Exception:
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

from ayana.actions import ActionService
from ayana.db import Database, now
from ayana.health import object_health
from ayana.incidents import IncidentService
from ayana.ntsafe import NTResult
from ayana.policy import Policy
from ayana.prom import summarize_probe
from ayana.verify_profiles import get_profile, profile_for_action


class FakeNT:
    async def describe(self, alias):
        return NTResult(ok=True, output='{"user":"nt-exec","mode":"exec","host_id":"NERV"}')

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"nt-exec","mode":"exec"}')

    async def probe(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="ok", returncode=0)

    async def exec(self, alias, tokens, timeout=None):
        return NTResult(ok=True, output="ok", returncode=0)


class FakeGate:
    def get(self, asset_id):
        class B:
            asset_id = "nerv"
            read_alias = "nerv"
            write_alias = "nerv-exec"
            expected_host_id = "NERV"
            host_id_verified_at = 1.0
        return B()

    async def verify_account(self, asset_id, *, write=False):
        return {"ok": True, "mode": "exec" if write else "probe", "error": ""}


class FakeProm:
    def __init__(self):
        self.samples = []

    async def probe_success_since(self, asset, service="", *, start, end=None, step=15.0,
                                  window_sec=None, max_window_sec=600.0):
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
        return {"result": list(self.samples), "evaluated_at": now()}


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
        "INSERT INTO objects(id, asset_id, kind, name, unit, created_at)"
        " VALUES(?,?,?,?,?,?)",
        ("nerv:service:frps", "nerv", "service", "frps", "frps", t),
    )
    db.execute(
        "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
        " VALUES('admin','x',0,1,?,?)",
        (now(), now()),
    )

    policy = Policy(db)
    policy.upsert_permission(
        subject_type="web_user", subject_id="admin", capability="service.restart",
        asset_id="nerv", object_id="*", allow=True, require_approval=False, actor="t",
    )
    prom = FakeProm()
    actions = ActionService(db, FakeNT(), FakeGate(), policy, prom, verify_window=90, verify_timeout=2)
    inc = IncidentService(db)
    return tmp, db, policy, prom, actions, inc


def close(tmp, db):
    try:
        db.close()
    except Exception:
        pass
    try:
        tmp.cleanup()
    except Exception:
        pass


def seed_incident(db, inc_id="inc1", gen=1, need_human=0, firing=True):
    t = now()
    db.execute(
        "INSERT INTO incidents(id, title, asset_id, object_id, status, stage, need_human,"
        " generation, outcome, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (inc_id, "nerv/frps", "nerv", "frps", "open", "verifying", need_human,
         gen, "", t, t),
    )
    if firing:
        db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm, alertname,"
            " status, asset_id, object_id, incident_id, first_seen, last_seen, receive_count,"
            " labels_json, annotations_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"ep_{inc_id}", "am", "fp", "x", "TargetDown", "firing", "nerv", "frps",
             inc_id, t, t, 1, "{}", "{}"),
        )


def seed_success_action(db, action_id="act1", inc_id="inc1"):
    t = now()
    db.execute(
        "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
        " state, mode, template_id, runbook_id, proposer_type, proposer_id, created_at,"
        " finished_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (action_id, inc_id, "nerv", "nerv:service:frps", "service.restart",
         '{"tokens":["systemctl","restart","frps"]}', "success", "manual",
         "tmpl_service_restart", "", "web_user", "admin", t, t),
    )


class TestP004Reconcile(unittest.TestCase):
    def test_passed_with_firing_not_recovered(self):
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        seed_incident(db, firing=True, need_human=1)
        seed_success_action(db)
        t = now()
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, generation,"
            " started_at) VALUES(?,?,?,?,?,?)",
            ("v1", "act1", "inc1", "passed", 1, t),
        )
        res = incs.reconcile("inc1")
        row = db.query_one("SELECT status, outcome FROM incidents WHERE id='inc1'")
        self.assertNotEqual(row["status"], "resolved")
        self.assertNotEqual(row["outcome"], "recovered")

    def test_unknown_action_blocks_recovered(self):
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        seed_incident(db, firing=False, need_human=0)
        seed_success_action(db)
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, created_at) VALUES(?,?,?,?,?,?,?,?)",
            ("act_u", "inc1", "nerv", "nerv:service:frps", "service.restart", "{}",
             "unknown", now()),
        )
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, generation, started_at)"
            " VALUES(?,?,?,?,?,?)",
            ("v1", "act1", "inc1", "passed", 1, now()),
        )
        incs.reconcile("inc1")
        row = db.query_one("SELECT status FROM incidents WHERE id='inc1'")
        self.assertNotEqual(row["status"], "resolved")

    def test_need_human_blocks_recovered(self):
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        seed_incident(db, firing=False, need_human=1)
        seed_success_action(db)
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, generation, started_at)"
            " VALUES(?,?,?,?,?,?)",
            ("v1", "act1", "inc1", "passed", 1, now()),
        )
        incs.reconcile("inc1")
        row = db.query_one("SELECT status FROM incidents WHERE id='inc1'")
        self.assertNotEqual(row["status"], "resolved")

    def test_manual_closed_not_recovered(self):
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        seed_incident(db, firing=False)
        incs.close_manual("inc1", "wontfix")
        row = db.query_one(
            "SELECT status, outcome, resolved_at, close_reason FROM incidents WHERE id='inc1'"
        )
        self.assertEqual(row["status"], "closed")
        self.assertEqual(row["outcome"], "closed_unverified")
        self.assertIsNone(row["resolved_at"])
        self.assertTrue(row["close_reason"])

    def test_stale_generation_cannot_recover_current(self):
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        seed_incident(db, firing=False, gen=2)
        seed_success_action(db, action_id="act_old", inc_id="inc1")
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, generation, started_at)"
            " VALUES(?,?,?,?,?,?)",
            ("v_old", "act_old", "inc1", "passed", 1, now()),
        )
        res = incs.reconcile("inc1")
        row = db.query_one("SELECT status, outcome, generation FROM incidents WHERE id='inc1'")
        self.assertNotEqual(row["status"], "resolved")
        self.assertEqual(row["generation"], 2)

    def test_clean_pass_can_recover(self):
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        seed_incident(db, firing=False, need_human=0)
        seed_success_action(db)
        db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, generation, started_at)"
            " VALUES(?,?,?,?,?,?)",
            ("v1", "act1", "inc1", "passed", 1, now()),
        )
        res = incs.reconcile("inc1", resolution_basis="test")
        row = db.query_one("SELECT status, outcome FROM incidents WHERE id='inc1'")
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["outcome"], "recovered")


class TestP005Profile(unittest.TestCase):
    def test_profile_for_service_restart(self):
        """v0.7.3+ 去个人化：service.restart 解析到通用 svc.recover。"""
        p = profile_for_action(
            capability="service.restart", asset_id="demo", object_id="demo:service:svc-x"
        )
        self.assertIsNotNone(p)
        self.assertEqual(p.id, "svc.recover")
        self.assertEqual(p.continuous_success_sec, 90.0)

    def test_unsupported_profile(self):
        """不在 CAP_PROFILE 中的 capability 无 profile。"""
        p = profile_for_action(
            capability="container.restart", asset_id="demo", object_id="demo:x"
        )
        self.assertIsNone(p)

    def test_15s_span_not_enough_for_90s(self):
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        t = now() - 5
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, mode, template_id, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("act1", "", "nerv", "nerv:service:frps", "service.restart",
             '{"tokens":["systemctl","restart","frps"]}', "success", "manual",
             "tmpl_service_restart", "web_user", "admin", t, t),
        )
        # two samples 15s apart after warmup
        base = t + 25
        prom.samples = [
            {"metric": {"asset": "nerv", "service": "frps"}, "value": 1, "sample_at": base},
            {"metric": {"asset": "nerv", "service": "frps"}, "value": 1, "sample_at": base + 15},
        ]
        res = asyncio.run(actions.verify("act1"))
        self.assertNotEqual(res["status"], "passed", res)

    def test_empty_samples_unknown(self):
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        t = now() - 5
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, mode, template_id, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("act1", "", "nerv", "nerv:service:frps", "service.restart",
             '{"tokens":["systemctl","restart","frps"]}', "success", "manual",
             "tmpl_service_restart", "web_user", "admin", t, t),
        )
        res = asyncio.run(actions.verify("act1"))
        self.assertIn(res["status"], ("unknown", "inconclusive"))

    def test_unsupported_profile_blocks_verify(self):
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        t = now()
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, mode, template_id, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("act1", "", "demo", "demo:x", "container.restart",
             '{"tokens":["docker","restart","x"]}', "success", "auto",
             "", "web_user", "admin", t, t),
        )
        res = asyncio.run(actions.verify("act1"))
        self.assertEqual(res.get("note"), "unsupported_verification_profile")

    def test_long_stable_window_can_pass(self):
        """90s 连续成功（>90s span）应 passed。"""
        tmp, db, policy, prom, actions, incs = make_env()
        self.addCleanup(close, tmp, db)
        t = now() - 120
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability, params_json,"
            " state, mode, template_id, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("act1", "", "nerv", "nerv:service:frps", "service.restart",
             '{"tokens":["systemctl","restart","frps"]}', "success", "manual",
             "tmpl_service_restart", "web_user", "admin", t, t),
        )
        # warmup 20s then 95s continuous samples every 15s
        base = t + 25
        prom.samples = [
            {"metric": {"asset": "nerv", "service": "frps"}, "value": 1,
             "sample_at": base + i * 15.0}
            for i in range(8)  # span 105s
        ]
        res = asyncio.run(actions.verify("act1"))
        self.assertEqual(res["status"], "passed", res)


class TestP006Health(unittest.TestCase):
    def test_no_samples_unknown(self):
        h = object_health(asset_id="yomi", object_name="x", samples=[], required=None)
        self.assertEqual(h["state"], "unknown")

    def test_stale_not_healthy(self):
        s = [{"metric": {"asset": "nerv", "service": "frps"}, "value": 1,
              "sample_at": now() - 600}]
        h = object_health(
            asset_id="nerv", object_name="frps", samples=s,
            required=[{"object": "frps", "metric": "probe_success",
                       "selector": {"asset": "nerv", "service": "frps"},
                       "freshness_sec": 120}],
        )
        self.assertEqual(h["state"], "stale")

    def test_partial_required_not_healthy(self):
        # frps ok, nginx missing
        now_t = now()
        samples = [
            {"metric": {"asset": "nerv", "service": "frps"}, "value": 1, "sample_at": now_t},
            {"metric": {"asset": "nerv", "service": "nginx"}, "value": 0, "sample_at": now_t},
        ]
        h = object_health(
            asset_id="nerv", object_name="nginx", samples=samples,
            required=[{"object": "nginx", "metric": "probe_success",
                       "selector": {"asset": "nerv", "service": "nginx"},
                       "freshness_sec": 120}],
        )
        self.assertEqual(h["state"], "unhealthy")

    def test_all_fresh_ok_healthy(self):
        now_t = now()
        samples = [
            {"metric": {"asset": "nerv", "service": "frps"}, "value": 1, "sample_at": now_t},
        ]
        h = object_health(
            asset_id="nerv", object_name="frps", samples=samples,
            required=[{"object": "frps", "metric": "probe_success",
                       "selector": {"asset": "nerv", "service": "frps"},
                       "freshness_sec": 120}],
        )
        self.assertEqual(h["state"], "healthy")

    def test_summarize_mixed_not_ok(self):
        t = now()
        s = summarize_probe({
            "result": [
                {"metric": {"asset": "nerv", "service": "frps"}, "value": 0, "sample_at": t - 30},
                {"metric": {"asset": "nerv", "service": "frps"}, "value": 1, "sample_at": t - 5},
            ]
        })
        self.assertNotEqual(s["state"], "ok")


if __name__ == "__main__":
    unittest.main()
