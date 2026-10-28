"""need_human 恢复入口：换代重置预算、重新入队、历史审计保留。"""
from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path

from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.ops_loop import OpsLoop


class ResumeAutonomyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.incidents = IncidentService(self.db)
        self.loop = OpsLoop(self.db, incidents=self.incidents)
        t = now()
        self.db.execute(
            "INSERT INTO incidents(id,title,asset_id,object_id,status,stage,need_human,"
            " need_human_reason,generation,outcome,created_at,updated_at)"
            " VALUES('inc1','t','romi','nginx','open','need_human',1,'remediation_failed_or_unverified',1,'unrecovered',?,?)",
            (t, t),
        )
        self.db.execute(
            "INSERT INTO ops_loop_state(incident_id,generation,rounds,no_progress_rounds,"
            " same_plan_failures,last_plan_sig,status,stop_reason,last_result,updated_at)"
            " VALUES('inc1',1,3,2,2,'start-nginx-romi','need_human','remediation_failed_or_unverified','object_not_registered: nginx',?)",
            (t,),
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _inc(self):
        return self.db.query_one("SELECT * FROM incidents WHERE id='inc1'")

    def test_resume_clears_need_human_and_bumps_generation(self):
        res = self.incidents.resume_autonomy("inc1", actor="admin")
        self.assertTrue(res["ok"], res)
        inc = self._inc()
        self.assertEqual(inc["need_human"], 0)
        self.assertEqual(inc["need_human_reason"], "")
        self.assertEqual(inc["stage"], "pending")
        self.assertEqual(inc["generation"], 2)

    def test_resume_resets_loop_counters_but_keeps_history(self):
        events_before = self.db.query("SELECT COUNT(*) n FROM events")[0]["n"]
        self.incidents.resume_autonomy("inc1", actor="admin")
        st = self.loop._state("inc1")
        self.assertEqual(st["generation"], 2)
        self.assertEqual(st["rounds"], 0)
        self.assertEqual(st["no_progress_rounds"], 0)
        self.assertEqual(st["same_plan_failures"], 0)
        self.assertEqual(st["last_plan_sig"], "")
        self.assertNotEqual(st["status"], "need_human")
        events_after = self.db.query("SELECT COUNT(*) n FROM events")[0]["n"]
        self.assertGreater(events_after, events_before)
        blob = "\n".join(
            (r["title"] or "") + (r["payload_json"] or "")
            for r in self.db.query("SELECT title, payload_json FROM events")
        )
        self.assertIn("remediation_failed_or_unverified", blob)
        aud = self.db.query_one(
            "SELECT * FROM audit_log WHERE entry='incident_resume_autonomy'"
        )
        self.assertIsNotNone(aud)

    def test_resume_requeues_investigation_with_fresh_budget(self):
        self.db.execute(
            "INSERT INTO investigation_jobs(incident_id,generation,status,rounds,last_error,"
            " lease_expires_at,updated_at,created_at)"
            " VALUES('inc1',1,'failed',3,'boom',0,?,?)",
            (now(), now()),
        )
        offered = {}

        class FakeInvestigator:
            def offer(self, incident_id, *, generation=None):
                offered["incident_id"] = incident_id
                offered["generation"] = generation
                return {"ok": True, "action": "requeued", "generation": generation}

        self.incidents.auto_investigator = FakeInvestigator()
        res = self.incidents.resume_autonomy("inc1", actor="admin")
        self.assertTrue(res["ok"])
        self.assertEqual(offered.get("incident_id"), "inc1")
        self.assertEqual(offered.get("generation"), 2)

    def test_loop_gate_reopens_after_resume(self):
        self.incidents.resume_autonomy("inc1", actor="admin")

        class FakeActions:
            async def autonomous_execute(self, **kw):
                return {"ok": True, "state": "success"}

        self.loop.actions = FakeActions()
        res = asyncio.run(self.loop.run_action_and_verify(
            incident_id="inc1", asset_id="romi", object_id="nginx",
            capability="service.start", plan_sig="new-plan",
        ))
        self.assertNotEqual(res.get("error"), "loop_stopped", res)

    def test_resume_rejects_missing_or_closed_incident(self):
        self.assertFalse(self.incidents.resume_autonomy("nope")["ok"])
        self.db.execute("UPDATE incidents SET status='closed' WHERE id='inc1'")
        res = self.incidents.resume_autonomy("inc1")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "incident_not_open")


if __name__ == "__main__":
    unittest.main()
