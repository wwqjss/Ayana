"""恢复证据门槛、Loop 代次收尾、preflight 独立预算。"""
from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.prom import PromClient
from ayana.ops_loop import (
    MAX_PREFLIGHT_BLOCKS,
    PREFLIGHT_COOLDOWN_SEC,
    OpsLoop,
    close_recovered,
)
from ayana.verify_profiles import PROFILES, recovery_evidence_contract


def recorded_recovery(db, *, profile_id="svc.recover", generation=1, age=0, service="nginx"):
    t = now() - age
    db.execute(
        "INSERT INTO actions(id,incident_id,asset_id,object_id,capability,params_json,state,created_at,finished_at)"
        " VALUES('act1','inc1','romi','romi:service:nginx','service.start','{}','success',?,?)", (t - 150, t - 120),
    )
    evidence = {"profile_id": profile_id, "generation": generation, "asset": "romi",
                "service": service, "action_id": "act1", "baseline": t - 150,
                "samples": [{"metric": {"asset": "romi", "service": service},
                             "sample_at": t - 90 + 15 * i, "value": 1} for i in range(7)]}
    db.execute(
        "INSERT INTO verifications(id,action_id,incident_id,status,generation,profile_id,started_at,finished_at,evidence_json)"
        " VALUES('ver1','act1','inc1','passed',?,?,?,?,?)", (generation, profile_id, t - 150, t, json.dumps(evidence)),
    )


class FakeProm:
    def __init__(self, verdict="green"):
        self.verdict = verdict
        self.calls = []

    def evaluate_recovery_evidence_sync(self, profile, *, asset_id, service):
        self.calls.append((getattr(profile, "id", ""), asset_id, service))
        return {"verdict": self.verdict, "contract": getattr(profile, "id", ""), "checks": []}


def make_env(prom_verdict="green"):
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db = Database(Path(tmp.name) / "t.db")
    t = now()
    db.execute(
        "INSERT INTO incidents(id,title,asset_id,object_id,status,stage,need_human,"
        " generation,outcome,created_at,updated_at)"
        " VALUES('inc1','t','romi','nginx','open','pending',0,1,'',?,?)",
        (t, t),
    )
    db.execute(
        "INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,alertname,status,"
        " asset_id,object_id,incident_id,first_seen,last_seen,problem_family,source_state)"
        " VALUES('ep1','am','fp','x','TargetDown','resolved','romi','nginx','inc1',?,?, 'availability','resolved')",
        (t, t),
    )
    incidents = IncidentService(db)
    prom = FakeProm(prom_verdict)
    incidents.prom = prom
    loop = OpsLoop(db, incidents=incidents)
    return tmp, db, incidents, prom, loop


def close_env(tmp, db):
    try:
        db.close()
    except Exception:
        pass
    try:
        tmp.cleanup()
    except Exception:
        pass


class ContractTests(unittest.TestCase):
    def test_contract_matches_failure_type(self):
        self.assertEqual(
            recovery_evidence_contract(alertname="TargetDown", problem_family="availability").id,
            "svc.recover",
        )
        self.assertEqual(
            recovery_evidence_contract(alertname="MySQLReplicationIORunning",
                                       problem_family="availability").id,
            "mysql.replica.recover",
        )
        self.assertIsNone(
            recovery_evidence_contract(alertname="DiskUsageHigh", problem_family="capacity")
        )
        self.assertIsNone(
            recovery_evidence_contract(alertname="MySQLReplicationLag", problem_family="capacity")
        )

    def test_service_probe_contract_is_not_inferred_from_broad_availability_family(self):
        for alertname in ("PrometheusJobMissing", "MySQLMetricsMissing", "instance_down",
                          "MySQLDown", "UnknownWarning"):
            with self.subTest(alertname=alertname):
                self.assertIsNone(recovery_evidence_contract(alertname=alertname, problem_family="availability"))
        for alertname in ("TargetDown", "ServiceDown", "Probe_Failed"):
            with self.subTest(alertname=alertname):
                self.assertEqual(recovery_evidence_contract(alertname=alertname, problem_family="availability").id,
                                 "svc.recover")


class EvidenceGateTests(unittest.TestCase):
    def _claim(self, incidents):
        incidents.on_episode_resolved("ep1")

    def test_green_evidence_recovers_with_recorded_evidence(self):
        tmp, db, incidents, prom, loop = make_env("green")
        self.addCleanup(close_env, tmp, db)
        self._claim(incidents)
        inc = db.query_one("SELECT status,outcome,resolution_basis FROM incidents WHERE id='inc1'")
        self.assertEqual((inc["status"], inc["outcome"]), ("resolved", "recovered"))
        ev = db.query_one(
            "SELECT payload_json FROM events WHERE incident_id='inc1' AND type='incident_resolved'"
        )
        self.assertIn("evidence", ev["payload_json"])
        self.assertEqual(prom.calls[0][1:], ("romi", "nginx"))
        st = db.query_one("SELECT status FROM ops_loop_state WHERE incident_id='inc1'")
        self.assertIsNone(st)

    def test_red_evidence_rejects_recovery_claim(self):
        tmp, db, incidents, prom, loop = make_env("red")
        self.addCleanup(close_env, tmp, db)
        self._claim(incidents)
        inc = db.query_one("SELECT status,outcome FROM incidents WHERE id='inc1'")
        self.assertEqual(inc["status"], "open")
        self.assertIsNotNone(db.query_one(
            "SELECT 1 FROM events WHERE incident_id='inc1' AND type='recovery_claim_rejected'"))

    def test_missing_evidence_never_claims_recovered(self):
        tmp, db, incidents, prom, loop = make_env("none")
        self.addCleanup(close_env, tmp, db)
        self._claim(incidents)
        inc = db.query_one("SELECT status,outcome FROM incidents WHERE id='inc1'")
        self.assertEqual(inc["status"], "open")
        self.assertNotEqual(inc["outcome"], "recovered")
        self.assertIsNotNone(db.query_one(
            "SELECT 1 FROM events WHERE incident_id='inc1' AND type='recovery_claim_awaiting_evidence'"))

    def test_no_contract_closes_unverified_never_recovered(self):
        tmp, db, incidents, prom, loop = make_env("green")
        self.addCleanup(close_env, tmp, db)
        db.execute(
            "UPDATE alert_episodes SET alertname='DiskUsageHigh', problem_family='capacity'"
            " WHERE id='ep1'")
        self._claim(incidents)
        inc = db.query_one("SELECT status,outcome FROM incidents WHERE id='inc1'")
        self.assertEqual((inc["status"], inc["outcome"]), ("closed", "closed_unverified"))
        self.assertFalse(prom.calls)

    def test_loop_close_is_generation_bound(self):
        tmp, db, incidents, prom, loop = make_env("green")
        self.addCleanup(close_env, tmp, db)
        t = now()
        db.execute(
            "INSERT INTO ops_loop_state(incident_id,generation,rounds,no_progress_rounds,"
            " same_plan_failures,last_plan_sig,status,stop_reason,last_result,updated_at)"
            " VALUES('inc1',9,2,1,2,'sig','need_human','stale','x',?)",
            (t,),
        )
        self.assertFalse(close_recovered(db, "inc1", generation=1))
        st = db.query_one("SELECT status,generation FROM ops_loop_state WHERE incident_id='inc1'")
        self.assertEqual((st["status"], st["generation"]), ("need_human", 9))
        db.execute("UPDATE incidents SET generation=9 WHERE id='inc1'")
        self.assertTrue(close_recovered(db, "inc1", generation=9))
        st = db.query_one("SELECT status,stop_reason FROM ops_loop_state WHERE incident_id='inc1'")
        self.assertEqual((st["status"], st["stop_reason"]), ("done", ""))

    def test_recorded_matching_fresh_verification_recovers_and_closes_loop(self):
        tmp, db, incidents, prom, loop = make_env("none")
        self.addCleanup(close_env, tmp, db)
        recorded_recovery(db)
        loop._state("inc1")
        res = incidents.reconcile("inc1")
        self.assertEqual(res["outcome"], "recovered")
        self.assertEqual(db.query_one("SELECT status FROM ops_loop_state")["status"], "done")
        event = db.query_one("SELECT payload_json FROM events WHERE type='incident_resolved'")
        self.assertIn("ver1", event["payload_json"])

    def test_bare_passed_verification_does_not_bypass_gate(self):
        tmp, db, incidents, prom, loop = make_env("none")
        self.addCleanup(close_env, tmp, db)
        recorded_recovery(db)
        db.execute("UPDATE verifications SET profile_id='', evidence_json='{}'")
        self._claim(incidents)
        self.assertEqual(incidents.reconcile("inc1")["status"], "open")

    def test_recorded_verification_must_match_profile_generation_freshness_and_target(self):
        for changes in ({"profile_id": "svc.stop"}, {"generation": 2}, {"age": 180}, {"service": "other"}):
            with self.subTest(changes=changes):
                tmp, db, incidents, prom, loop = make_env("none")
                try:
                    recorded_recovery(db, **changes)
                    self._claim(incidents)
                    self.assertEqual(incidents.reconcile("inc1")["status"], "open")
                finally:
                    close_env(tmp, db)

    def test_fresh_red_evidence_overrides_passed_verification(self):
        tmp, db, incidents, prom, loop = make_env("red")
        self.addCleanup(close_env, tmp, db)
        recorded_recovery(db)
        self._claim(incidents)
        self.assertEqual(incidents.reconcile("inc1")["status"], "open")

    def test_each_current_failure_contract_requires_evidence(self):
        tmp, db, incidents, prom, loop = make_env("green")
        self.addCleanup(close_env, tmp, db)
        db.execute("INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,alertname,status,asset_id,object_id,incident_id,first_seen,last_seen,problem_family,source_state)"
                   " SELECT 'ep2',source_id,'fp2',starts_at_norm,'MySQLReplicationIORunning',status,asset_id,object_id,incident_id,first_seen,last_seen,problem_family,source_state"
                   " FROM alert_episodes WHERE id='ep1'")
        original = prom.evaluate_recovery_evidence_sync
        prom.evaluate_recovery_evidence_sync = lambda profile, **kwargs: (
            {"verdict": "red", "contract": profile.id} if profile.id == "mysql.replica.recover"
            else original(profile, **kwargs))
        self._claim(incidents)
        self.assertEqual(db.query_one("SELECT status FROM incidents")["status"], "open")

    def test_evidence_evaluation_cannot_close_a_new_generation(self):
        tmp, db, incidents, prom, loop = make_env("green")
        self.addCleanup(close_env, tmp, db)
        original = prom.evaluate_recovery_evidence_sync
        def bump(profile, **kwargs):
            db.execute("UPDATE incidents SET generation=2 WHERE id='inc1'")
            return original(profile, **kwargs)
        prom.evaluate_recovery_evidence_sync = bump
        self._claim(incidents)
        self.assertEqual(db.query_one("SELECT status FROM incidents")["status"], "open")

    def test_loop_close_error_rolls_back_incident_and_recovery_event(self):
        tmp, db, incidents, prom, loop = make_env("green")
        self.addCleanup(close_env, tmp, db)
        loop._state("inc1")
        with patch("ayana.ops_loop.close_recovered", side_effect=RuntimeError("loop write failed")):
            with self.assertRaisesRegex(RuntimeError, "loop write failed"):
                self._claim(incidents)
        self.assertEqual(db.query_one("SELECT status FROM incidents")["status"], "open")
        self.assertEqual(db.query_one("SELECT status FROM ops_loop_state")["status"], "idle")
        self.assertIsNone(db.query_one("SELECT 1 FROM events WHERE type='incident_resolved'"))


class RawEvidenceTests(unittest.TestCase):
    def _evaluate(self, samples):
        client = PromClient("http://unused")
        client._range_sync = lambda *args, **kwargs: samples
        with patch("ayana.prom.time.time", return_value=1000):
            return client.evaluate_recovery_evidence_sync(PROFILES["svc.recover"], asset_id="romi", service="nginx")

    def _samples(self, *, end=1000, step=15, count=7, value=1, instance="one"):
        return [{"metric": {"asset": "romi", "service": "nginx", "instance": instance},
                 "sample_at": end - (count - i - 1) * step, "value": value} for i in range(count)]

    def test_fresh_sustained_exact_series_is_green(self):
        self.assertEqual(self._evaluate(self._samples())["verdict"], "green")

    def test_stale_single_gapped_or_ambiguous_samples_are_not_green(self):
        cases = [self._samples(end=900), self._samples(count=1), self._samples(step=45, count=3),
                 self._samples() + self._samples(instance="two"),
                 [{**s, "metric": {"asset": "other", "service": "nginx"}} for s in self._samples()]]
        for samples in cases:
            with self.subTest(samples=samples):
                self.assertEqual(self._evaluate(samples)["verdict"], "none")

    def test_fresh_failure_is_red(self):
        samples = self._samples()
        samples[-1]["value"] = 0
        self.assertEqual(self._evaluate(samples)["verdict"], "red")

    def test_sync_query_requests_raw_range_vector(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self): return b'{"status":"success","data":{"resultType":"matrix","result":[]}}'
        with patch("urllib.request.urlopen", return_value=Response()) as request:
            PromClient("http://prom")._range_sync('probe_success{asset="romi",service="nginx"}', window_sec=120)
        from urllib.parse import parse_qs, urlsplit
        url = urlsplit(request.call_args.args[0])
        self.assertEqual(url.path, "/api/v1/query")
        self.assertTrue(parse_qs(url.query)["query"][0].endswith("[120s]"))


class PreflightBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, self.incidents, self.prom, self.loop = make_env("none")

    def tearDown(self):
        close_env(self.tmp, self.db)

    def test_preflight_does_not_consume_execution_budget(self):
        self.loop.note_preflight_block("inc1", plan_sig="p", code="object_not_registered")
        st = self.loop._state("inc1")
        self.assertEqual(st["preflight_blocks"], 1)
        self.assertEqual(st["same_plan_failures"], 0)
        self.assertEqual(st["no_progress_rounds"], 0)
        self.assertEqual(st["last_result"], "preflight_blocked:object_not_registered")

    def test_preflight_limit_escalates_with_accurate_reason(self):
        for i in range(MAX_PREFLIGHT_BLOCKS - 1):
            out = self.loop.note_preflight_block("inc1", plan_sig="p", code="target_not_found")
            self.assertFalse(out["blocked"])
        out = self.loop.note_preflight_block("inc1", plan_sig="p", code="target_not_found")
        self.assertTrue(out["blocked"])
        inc = self.db.query_one("SELECT need_human, need_human_reason FROM incidents WHERE id='inc1'")
        self.assertEqual(inc["need_human"], 1)
        self.assertIn("preflight_blocked:target_not_found", inc["need_human_reason"])

    def test_preflight_cooldown_defers_next_attempt(self):
        self.loop.note_preflight_block("inc1", plan_sig="p", code="object_not_registered")
        # 旧 ActionService 派发已退役；冷却状态仍约束后续尝试
        st = self.loop._state("inc1")
        self.assertEqual(st["preflight_blocks"], 1)
        self.assertGreater(float(st["preflight_at"] or 0), time.time() - 5)
        self.db.execute("UPDATE ops_loop_state SET preflight_at=0 WHERE incident_id='inc1'")
        st = self.loop._state("inc1")
        self.assertEqual(st["preflight_blocks"], 1)

    def test_action_success_progress_is_not_recovery_and_gen_guarded(self):
        self.loop.note_preflight_block("inc1", plan_sig="p", code="object_not_registered")
        self.loop.note_round("inc1", progressed=False, plan_sig="p", write_ok=False, result="fail")
        self.loop.record_action_progress("inc1", plan_sig="p")
        st = self.loop._state("inc1")
        self.assertNotEqual(st["status"], "done")  # 动作成功不等于恢复，不结案
        self.assertEqual(st["same_plan_failures"], 0)
        self.assertEqual(st["no_progress_rounds"], 0)
        # 收尾绑定代次：旧代迟到回写丢弃
        db_gen = self.db.query_one("SELECT generation FROM incidents WHERE id='inc1'")["generation"]
        self.assertFalse(close_recovered(self.db, "inc1", generation=int(db_gen) + 5))
        st = self.loop._state("inc1")
        self.assertNotEqual(st["status"], "done")


if __name__ == "__main__":
    unittest.main()
