"""Write-result adjudication: unknown ledger needs a human decision, never deletion."""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.session_bridge import SessionBridge


class AdjudicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "t.db")
        self.duty = DutySessionManager(self.db)
        self.bridge = SessionBridge(self.db, duty=self.duty)
        self.sid = self.duty.create(origin="auto")["session_id"]
        self.duty.set_runtime_state(self.sid, "idle")
        self.db.execute(
            "INSERT INTO incidents(id,title,asset_id,object_id,status,created_at,updated_at)"
            " VALUES('inc1','inc1','host','service','open',?,?)",
            (time.time(), time.time()),
        )
        self.duty.join_incident(self.sid, "inc1")
        self.duty.set_setting("auto_approval_mode", "automatic")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _claim_unknown(self, key="key"):
        self.bridge.claim_write("inc1", key, authority_session_id=self.sid)
        self.bridge.mark_unknown("inc1", key, reason="probe_error")

    def _row(self, key="key"):
        return self.db.query_one(
            "SELECT * FROM session_write_ops WHERE action_key=?", (key,)
        )

    def test_deletion_alone_never_releases_unknown(self):
        self._claim_unknown()
        result = self.duty.request_delete(self.sid, actor="admin", stop=True)
        self.assertTrue(result["pending"])
        self.assertEqual(self._row()["status"], "unknown")

    def test_adjudicate_not_executed_releases_and_unblocks_deletion(self):
        self._claim_unknown()
        res = self.bridge.adjudicate_write(
            "inc1", "key", outcome="not_executed", reason="verified absent",
            actor_id="admin",
        )
        self.assertTrue(res["ok"])
        row = self._row()
        self.assertEqual(row["status"], "released")
        self.assertEqual(row["adjudication"], "not_executed")
        self.assertIn("unknown:", row["result"])
        result = self.duty.request_delete(self.sid, actor="admin", stop=True)
        self.assertTrue(result.get("deleted"), result)

    def test_adjudicate_executed_marks_done_and_unblocks_deletion(self):
        self._claim_unknown()
        res = self.bridge.adjudicate_write(
            "inc1", "key", outcome="executed", reason="verified on host",
            actor_id="admin",
        )
        self.assertTrue(res["ok"])
        row = self._row()
        self.assertEqual(row["status"], "done")
        self.assertEqual(row["adjudication"], "executed")
        self.assertIn("unknown:", row["result"])
        result = self.duty.request_delete(self.sid, actor="admin", stop=True)
        self.assertTrue(result.get("deleted"), result)

    def test_still_unknown_keeps_block_and_original_result(self):
        self._claim_unknown()
        before = self._row()["result"]
        res = self.bridge.adjudicate_write(
            "inc1", "key", outcome="still_unknown", reason="no evidence",
            actor_id="admin",
        )
        self.assertTrue(res["ok"])
        row = self._row()
        self.assertEqual(row["status"], "unknown")
        self.assertEqual(row["adjudication"], "still_unknown")
        self.assertEqual(row["result"], before)
        result = self.duty.request_delete(self.sid, actor="admin", stop=True)
        self.assertTrue(result["pending"])
        self.assertIn("write_result_pending", result.get("deletion_blockers", []))

    def test_adjudicate_rejects_bad_outcome_and_non_unknown_state(self):
        self._claim_unknown()
        bad = self.bridge.adjudicate_write("inc1", "key", outcome="whatever", actor_id="admin")
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["error"], "bad_adjudication")
        self.bridge.adjudicate_write("inc1", "key", outcome="executed", actor_id="admin")
        again = self.bridge.adjudicate_write("inc1", "key", outcome="not_executed", actor_id="admin")
        self.assertFalse(again["ok"])
        self.assertEqual(again["error"], "bad_state")

    def test_adjudication_is_audited(self):
        self._claim_unknown()
        self.bridge.adjudicate_write("inc1", "key", outcome="not_executed", reason="absent", actor_id="admin")
        aud = self.db.query_one(
            "SELECT * FROM audit_log WHERE entry='write_result_adjudicated'"
        )
        self.assertIsNotNone(aud)
        self.assertIn("not_executed", aud["detail_json"])


if __name__ == "__main__":
    unittest.main()
