"""Phase A: P0-01..06 defect reproduction baseline (Astra 0.3.0 review).

These cases assert CORRECT behavior. They are expected to FAIL while the
defect remains, proving the issue is still present.

Tags:
- expected_fail_*: expected failure (documents a P0 defect)
- contract_*: fake contract / positive path (must pass; samples really run)
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# llm.py imports aiohttp at module level; stub when offline
try:
    import aiohttp.web  # noqa: F401
except Exception:
    _aiohttp = types.ModuleType("aiohttp")

    class _ClientTimeout:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class _ClientSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            raise RuntimeError("network disabled in tests")

    _aiohttp.ClientTimeout = _ClientTimeout
    _aiohttp.ClientSession = _ClientSession
    _aiohttp.web = types.SimpleNamespace(
        Application=type("Application", (), {"__init__": lambda self, **k: None}),
        Response=type("Response", (), {"__init__": lambda self, *a, **k: None}),
        json_response=lambda *a, **k: None,
    )
    sys.modules["aiohttp"] = _aiohttp
    sys.modules["aiohttp.web"] = _aiohttp.web

from ayana.actions import ActionError, ActionService
from ayana.agent import AgentLoop
from ayana.db import Database, now
from ayana.investigation import InvestigationService
from ayana.knowledge import KnowledgeBase
from ayana.ntsafe import AssetBinding, IdentityGate, NTResult
from ayana.policy import Policy
from ayana.prom import match_series, summarize_probe
from ayana.runbook import RunbookRule, match_runbook


class FakeNT:
    """Contract-aligned with ntsafe.NTClient: probe/exec/identity."""

    def __init__(self, identity_json: str | None = None, exec_ok: bool = True):
        self.calls = []
        self.identity_json = identity_json or '{"user":"nt-exec","mode":"exec","uid":1}'
        self.exec_ok = exec_ok

    async def probe(self, alias, tokens, timeout=None):
        self.calls.append(("probe", alias, list(tokens)))
        return NTResult(ok=True, output="ok", returncode=0)

    async def exec(self, alias, tokens, timeout=None):
        self.calls.append(("exec", alias, list(tokens)))
        return NTResult(ok=self.exec_ok, output="ok", returncode=0 if self.exec_ok else 1)

    async def identity(self, alias):
        self.calls.append(("identity", alias, []))
        return NTResult(ok=True, output=self.identity_json)


class RealContractProm:
    """Contract-aligned with prom.PromClient: probe_success_since + probe_success."""

    def __init__(self):
        self.samples: list[dict] = []
        self.since_calls: list[dict] = []

    async def probe_success_since(
        self,
        asset: str,
        service: str = "",
        *,
        start: float,
        end: float | None = None,
        step: float = 15.0,
        window_sec: float | None = None,
        max_window_sec: float = 600.0,
    ) -> list[dict]:
        self.since_calls.append(
            {"asset": asset, "service": service, "start": start, "end": end}
        )
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

    async def probe_success(self, asset: str, service: str = "") -> dict:
        end = now()
        samples = await self.probe_success_since(
            asset, service, start=end - 120, end=end, window_sec=120
        )
        return {"result": samples, "evaluated_at": end}


class FakeGate:
    class B:
        def __init__(self, verified=True):
            self.asset_id = "nerv"
            self.read_alias = "nerv"
            self.write_alias = "nerv-exec"
            self.expected_host_id = "NERV"
            self.host_id_verified_at = 1.0 if verified else None
            if not verified:
                self.expected_host_id = ""

    def __init__(self, verified=True):
        self.verified = verified

    def get(self, asset_id):
        return FakeGate.B(self.verified)

    async def verify_account(self, asset_id, *, write=False):
        if not self.verified:
            return {"ok": False, "error": "host_id not registered/verified"}
        return {"ok": True, "mode": "exec" if write else "probe", "error": ""}


class DenyNT:
    """All probes fail with rc255."""

    def __init__(self):
        self.exec_calls = []

    async def probe(self, alias, tokens, timeout=None):
        return NTResult(ok=False, output="", returncode=255)

    async def exec(self, alias, tokens, timeout=None):
        self.exec_calls.append((alias, list(tokens)))
        return NTResult(ok=True, output="ok", returncode=0)

    async def identity(self, alias):
        return NTResult(ok=True, output='{"user":"nt-probe","mode":"probe"}')


class DenyGate:
    def get(self, asset_id):
        class B:
            read_alias = "nerv"
            write_alias = "nerv-exec"
        return B()

    async def verify_account(self, asset_id, *, write=False):
        return {"ok": True, "mode": "probe", "error": ""}


def _seed_nerv(db: Database) -> None:
    t = now()
    db.execute(
        "INSERT INTO assets(id, display_name, read_alias, write_alias, expected_host_id,"
        " host_id_verified_at, prom_asset, enabled, notes, created_at, updated_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("nerv", "NERV", "nerv", "nerv-exec", "NERV", t, "nerv", 1, "", t, t),
    )
    db.execute(
        "INSERT INTO objects(id, asset_id, kind, name, unit, container, port, protocol,"
        " external_probe, auto_recover, created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("nerv:service:frps", "nerv", "service", "frps", "frps", "", None, "", "", 1, t),
    )


def _allow(policy: Policy, **kw) -> None:
    kw.setdefault("subject_type", "web_user")
    kw.setdefault("subject_id", "admin")
    kw.setdefault("capability", "service.restart")
    kw.setdefault("asset_id", "nerv")
    kw.setdefault("object_id", "*")
    kw.setdefault("allow", True)
    kw.setdefault("require_approval", False)
    kw.setdefault("auto_allowed", False)
    kw.setdefault("actor", "test")
    policy.upsert_permission(**kw)


def _make_actions(tmp: tempfile.TemporaryDirectory):
    db = Database(Path(tmp.name) / "t.db")
    _seed_nerv(db)
    db.execute(
        "INSERT OR IGNORE INTO users(username, password_hash, totp_enabled, is_admin, created_at, updated_at)"
        " VALUES('admin','x',0,1,?,?)",
        (now(), now()),
    )

    policy = Policy(db)
    _allow(policy)
    prom = RealContractProm()
    actions = ActionService(
        db,
        FakeNT(),
        FakeGate(),
        policy,
        prom,
        action_ttl=1800,
        verify_window=90,
        verify_timeout=5,
    )
    return db, policy, prom, actions


def _close_tmp(db: Database, tmp: tempfile.TemporaryDirectory) -> None:
    try:
        db.close()
    except Exception:
        pass
    try:
        tmp.cleanup()
    except Exception:
        pass


def _ok_samples(asset="nerv", service="frps", base=None, n=2, gap=15.0, value=1):
    base = base if base is not None else now()
    out = []
    for i in range(n):
        out.append(
            {
                "metric": {"asset": asset, "service": service},
                "value": value,
                "sample_at": base + i * gap,
            }
        )
    return out


class TestFakeContract(unittest.TestCase):
    def test_fake_has_probe_success_since(self):
        prom = RealContractProm()
        self.assertTrue(callable(getattr(prom, "probe_success_since", None)))
        self.assertTrue(callable(getattr(prom, "probe_success", None)))

    def test_positive_samples_reach_verifier(self):
        """Positive: samples enter probe_success_since and can pass."""
        tmp = tempfile.TemporaryDirectory()
        db, policy, prom, actions = _make_actions(tmp)
        self.addCleanup(_close_tmp, db, tmp)
        prom.samples = _ok_samples(n=12, gap=15.0, base=now() - 5)
        aid = "act_pos"
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, state, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                aid, "", "nerv", "nerv:service:frps", "service.restart",
                '{"tokens":["systemctl","restart","frps"]}',
                "success", "web_user", "admin", now() - 30, now() - 30,
            ),
        )
        res = asyncio.run(actions.verify(aid))
        self.assertTrue(prom.since_calls, "verifier never called probe_success_since")
        self.assertEqual(res["status"], "passed")
        v = db.query_one("SELECT evidence_json FROM verifications WHERE action_id=?", (aid,))
        self.assertIn("samples", (v["evidence_json"] or ""))


class TestP002IdentityAndAuthz(unittest.TestCase):
    def test_expected_fail_wrong_remote_host_id_must_not_ok(self):
        """P0-02: identity without remote host_id must not be ok."""
        binding = AssetBinding(
            asset_id="nerv",
            read_alias="nerv",
            write_alias="nerv-exec",
            expected_host_id="NERV",
            host_id_verified_at=1.0,
        )
        nt = FakeNT(identity_json='{"user":"nt-exec","mode":"exec","uid":1}')
        gate = IdentityGate(nt, [binding])
        res = asyncio.run(gate.verify_account("nerv", write=True))
        self.assertFalse(res.get("ok"), f"P0-02: missing remote host_id still ok=True ({res})")

    def test_expected_fail_wrong_host_id_value(self):
        binding = AssetBinding(
            asset_id="nerv",
            read_alias="nerv",
            write_alias="nerv-exec",
            expected_host_id="NERV",
            host_id_verified_at=1.0,
        )
        nt = FakeNT(
            identity_json='{"user":"nt-exec","mode":"exec","uid":1,"host_id":"WRONG-HOST"}'
        )
        gate = IdentityGate(nt, [binding])
        res = asyncio.run(gate.verify_account("nerv", write=True))
        self.assertFalse(res.get("ok"), f"P0-02: WRONG-HOST still accepted ({res})")

    def test_expected_fail_execute_skips_auto_flag(self):
        """P0-02: auto dispatch must recheck auto_allowed."""
        tmp = tempfile.TemporaryDirectory()
        db, policy, prom, actions = _make_actions(tmp)
        self.addCleanup(_close_tmp, db, tmp)
        policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability="service.restart",
            asset_id="nerv", object_id="*", allow=True, require_approval=True,
            auto_allowed=False, actor="test",
        )
        try:
            actions.propose(
                asset_id="nerv", object_id="frps", capability="service.restart",
                proposer_type="auto_rule", proposer_id="agent",
                reason="p0-02", mode="auto",
                runbook_id="rb_frps_down_restart", runbook_rev="x",
            )
            proposed = True
        except ActionError as e:
            proposed = False
            self.assertEqual(e.code, "auto_not_allowed")
        self.assertFalse(proposed, "P0-02: auto propose allowed without auto_allowed")

        policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability="service.restart",
            asset_id="nerv", object_id="*", allow=True, require_approval=False,
            auto_allowed=True, actor="test",
        )
        from ayana.runbook import apply_runbook_rules, get_runbook_rule as _grr

        apply_runbook_rules([{
            "id": "rb_frps_down_restart", "name": "frps down restart",
            "asset_id": "nerv", "object_name": "frps", "alertname": "TargetDown",
            "capability": "service.restart", "reason": "restart frps",
            "require_probe_fail": True,
        }])
        self.addCleanup(lambda: apply_runbook_rules([]))

        rule_rev = _grr("rb_frps_down_restart").rev
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="auto_rule", proposer_id="agent",
            reason="p0-02b", mode="auto",
            runbook_id="rb_frps_down_restart", runbook_rev=rule_rev,
        )
        actions.approve(prop["id"], approver_type="auto_rule", approver_id="agent")
        policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability="service.restart",
            asset_id="nerv", object_id="*", allow=True, require_approval=True,
            auto_allowed=False, actor="test",
        )

        async def run():
            return await actions.execute(
                prop["id"], actor_type="auto_rule", actor_id="agent"
            )

        try:
            res = asyncio.run(run())
            dispatched = res.get("state") in ("dispatched", "success", "failure", "unknown")
        except ActionError as e:
            dispatched = False
            res = {"error": e.code}
        self.assertFalse(
            dispatched,
            f"P0-02: auto dispatched after auto revoked (state={res})",
        )

    def test_expected_fail_manual_propose_without_runbook(self):
        """P0-02: propose does not persist runbook/template contract."""
        tmp = tempfile.TemporaryDirectory()
        db, policy, prom, actions = _make_actions(tmp)
        self.addCleanup(_close_tmp, db, tmp)
        prop = actions.propose(
            asset_id="nerv", object_id="frps", capability="service.restart",
            proposer_type="web_user", proposer_id="admin",
        )
        row = db.query_one("SELECT params_json, reason FROM actions WHERE id=?", (prop["id"],))
        blob = (row["params_json"] or "") + (row["reason"] or "")
        self.assertTrue(
            ("runbook" in blob.lower()) or ("template" in blob.lower()),
            "P0-02: propose does not persist runbook/template contract",
        )


class TestP003Preconditions(unittest.TestCase):
    def test_require_probe_fail_field_unused_in_runbook(self):
        """P0-03: require_probe_fail has no consumer API."""
        rule = RunbookRule(
            id="rb_x", name="x", asset_id="nerv", object_name="frps",
            alertname="TargetDown", capability="service.restart",
            require_probe_fail=True,
        )
        matched = match_runbook(
            asset_id="nerv", object_name="frps", alertname="TargetDown", runbook=[rule]
        )
        self.assertIsNotNone(matched)
        self.assertTrue(
            hasattr(matched, "check_preconditions"),
            "P0-03: RunbookRule.require_probe_fail has no consumer API",
        )

    def test_expected_fail_agent_executes_after_failed_investigation(self):
        """P0-03: agent still executes after failed investigation."""
        tmp = tempfile.TemporaryDirectory()
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(_close_tmp, db, tmp)
        _seed_nerv(db)
        t = now()
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage,"
            " created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
            ("inc_fail", "nerv/frps: TargetDown", "nerv", "frps", "open", "pending", t, t),
        )
        db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm,"
            " alertname, status, asset_id, object_id, incident_id, first_seen, last_seen,"
            " receive_count, labels_json, annotations_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("ep1", "am", "fp", "x", "TargetDown", "firing", "nerv", "frps", "inc_fail",
             t, t, 1, "{}", "{}"),
        )
        policy = Policy(db)
        policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability="asset.summary",
            asset_id="*", object_id="*", allow=True, require_approval=False,
            auto_allowed=False, actor="test",
        )
        policy.upsert_permission(
            subject_type="auto_rule", subject_id="agent", capability="service.restart",
            asset_id="*", object_id="*", allow=True, require_approval=False,
            auto_allowed=True, actor="test",
        )
        nt = DenyNT()
        inv = InvestigationService(db, nt, DenyGate(), RealContractProm(), policy)
        actions = ActionService(
            db, nt, FakeGate(), policy, RealContractProm(), verify_timeout=3
        )

        class NoLLM:
            enabled = False

            async def analyze_incident(self, **kw):
                return None

        class QuietNotify:
            def enqueue(self, **kw):
                pass

        agent = AgentLoop(
            db, inv, actions, policy, NoLLM(), QuietNotify(), auto_enabled=True,
            knowledge=KnowledgeBase(db),
        )
        res = asyncio.run(agent.handle_incident("inc_fail"))
        executed = bool(nt.exec_calls) or any(
            (s.get("step") == "execute" and s.get("ok")) for s in res.get("steps", [])
        )
        self.assertFalse(
            executed,
            f"P0-03: agent executed despite failed investigation; steps={res.get('steps')}",
        )


class TestP004IncidentConvergence(unittest.TestCase):
    def test_expected_fail_passed_resolves_despite_firing_and_need_human(self):
        """P0-04: verification must not resolve while firing/unknown/need_human."""
        tmp = tempfile.TemporaryDirectory()
        db, policy, prom, actions = _make_actions(tmp)
        self.addCleanup(_close_tmp, db, tmp)
        t = now()
        db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage,"
            " need_human, need_human_reason, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("inc_c", "nerv/frps", "nerv", "frps", "open", "verifying",
             1, "exec_unknown", t, t),
        )
        db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm,"
            " alertname, status, asset_id, object_id, incident_id, first_seen, last_seen,"
            " receive_count, labels_json, annotations_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("ep_f", "am", "fp", "x", "TargetDown", "firing", "nerv", "frps", "inc_c",
             t, t, 1, "{}", "{}"),
        )
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, state, proposer_type, proposer_id, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("act_unknown", "inc_c", "nerv", "nerv:service:frps", "service.restart",
             "{}", "unknown", "web_user", "admin", t),
        )
        aid = "act_ok"
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, state, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (aid, "inc_c", "nerv", "nerv:service:frps", "service.restart",
             '{"tokens":["systemctl","restart","frps"]}',
             "success", "web_user", "admin", t, t),
        )
        prom.samples = _ok_samples(n=12, gap=15.0, base=now() - 5)
        asyncio.run(actions.verify(aid))
        inc = db.query_one(
            "SELECT status, need_human, stage FROM incidents WHERE id='inc_c'"
        )
        self.assertNotEqual(
            inc["status"],
            "resolved",
            f"P0-04: resolved despite firing/unknown/need_human row={dict(inc)}",
        )


class TestP005VerificationSemantics(unittest.TestCase):
    def test_expected_fail_15s_span_passes_90s_window(self):
        """P0-05: 15s span must not pass a 90s stability window."""
        tmp = tempfile.TemporaryDirectory()
        db, policy, prom, actions = _make_actions(tmp)
        self.addCleanup(_close_tmp, db, tmp)
        aid = "act_span"
        finished = now() - 5.0
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, state, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (aid, "", "nerv", "nerv:service:frps", "service.restart",
             '{"tokens":["systemctl","restart","frps"]}',
             "success", "web_user", "admin", finished, finished),
        )
        # two samples 15s apart AFTER action finish; 90s window should require ~90s
        prom.samples = _ok_samples(n=2, gap=15.0, base=finished + 2.0)
        res = asyncio.run(actions.verify(aid))
        self.assertTrue(prom.since_calls, "samples never queried")
        self.assertNotEqual(
            res["status"], "passed", f"P0-05: 15s span passed 90s window ({res})"
        )

    def test_expected_fail_criteria_hardcodes_probe_success(self):
        """P0-05: criteria has no metric/profile contract."""
        tmp = tempfile.TemporaryDirectory()
        db, policy, prom, actions = _make_actions(tmp)
        self.addCleanup(_close_tmp, db, tmp)
        aid = "act_crit"
        db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " params_json, state, proposer_type, proposer_id, created_at, finished_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (aid, "", "nerv", "nerv:service:frps", "service.restart",
             '{"tokens":["systemctl","restart","frps"]}',
             "success", "web_user", "admin", now(), now()),
        )
        asyncio.run(actions.verify(aid))
        v = db.query_one("SELECT criteria_json FROM verifications WHERE action_id=?", (aid,))
        crit = v["criteria_json"] or ""
        self.assertTrue(
            ("profile_id" in crit) or ("profile" in crit) or ("verify_capability" in crit) or ("metric" in crit),
            f"P0-05: criteria has no metric/profile contract: {crit[:200]}",
        )


class TestP006Observability(unittest.TestCase):
    def test_summarize_mixed_broken_and_healthy_not_ok(self):
        """P0-06: newest healthy=1 must not mask an older failure sample."""
        t = now()
        data = {
            "result": [
                {"metric": {"asset": "nerv", "service": "frps"}, "value": 0, "sample_at": t - 30},
                {"metric": {"asset": "nerv", "service": "frps"}, "value": 1, "sample_at": t - 5},
            ]
        }
        s = summarize_probe(data)
        self.assertNotEqual(
            s["state"], "ok", f"P0-06: summarize_probe ok despite failure sample: {s}"
        )

    def test_expected_fail_no_incident_means_healthy(self):
        """P0-06: object without probe must not render as healthy."""
        # Mirror app.js computeObjectStatus: no incident hit => healthy
        inc_by_obj: dict = {}
        hit = inc_by_obj.get("yomi/yomi:x")
        from ayana.health import object_health as _oh
        h = _oh(asset_id="yomi", object_name="x", samples=[])
        current = h["state"]
        self.assertNotEqual(current, "healthy")  # current buggy semantics
        # Correct semantics: unobserved object is unknown / unobserved
        self.assertIn(
            current,
            ("unknown", "unobserved", "stale", "incomplete", "未观测", "观测不全"),
            "P0-06: object without probe should not be labeled healthy",
        )


if __name__ == "__main__":
    unittest.main()

