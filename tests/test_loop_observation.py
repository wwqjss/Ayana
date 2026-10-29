"""Legacy scheduler reads must never invent or mutate present execution state."""
import tempfile
import unittest
from pathlib import Path
from ayana.db import Database
from ayana.ops_loop import OpsLoop


class LoopObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name)/'test.db')
        self.db.execute("INSERT INTO incidents(id,title,asset_id,status,generation,created_at,updated_at) "
                        "VALUES('inc','incident','host','open',4,1,1)")
        self.loop = OpsLoop(self.db)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def legacy(self, generation=4):
        self.db.execute("INSERT INTO ops_loop_state(incident_id,generation,status,stop_reason,updated_at) "
                        "VALUES('inc',?,'need_human','old_action_failed',123)", (generation,))

    def test_reads_never_create_scheduler_rows(self):
        self.assertFalse(self.loop.status('inc')['recorded'])
        current = self.loop.observed_status('inc')
        self.assertEqual(current['status'], 'retired')
        self.assertIsNone(current['legacy_loop']['snapshot'])
        self.assertEqual(current['incident']['status'], 'open')
        self.assertEqual(self.db.query_one('SELECT count(*) AS n FROM ops_loop_state')['n'], 0)

    def test_old_generation_read_preserves_raw_history(self):
        self.legacy(1)
        before = dict(self.db.query_one("SELECT * FROM ops_loop_state WHERE incident_id='inc'"))
        self.assertEqual(self.loop.status('inc'), before)
        current = self.loop.observed_status('inc')
        self.assertFalse(current['legacy_loop']['same_generation'])
        self.assertEqual(current['legacy_loop']['snapshot'], before)
        self.assertEqual(dict(self.db.query_one("SELECT * FROM ops_loop_state WHERE incident_id='inc'")), before)

    def test_recovered_incident_does_not_rewrite_historical_stop_as_completion(self):
        self.legacy()
        self.db.execute("UPDATE incidents SET status='resolved',outcome='recovered',need_human=0 WHERE id='inc'")
        current = self.loop.observed_status('inc')
        self.assertEqual(current['execution_mode'], 'session_host_exec')
        self.assertTrue(current['retired'])
        self.assertFalse(current['legacy_loop']['active'])
        self.assertEqual(current['incident']['outcome'], 'recovered')
        self.assertEqual(current['legacy_loop']['snapshot']['status'], 'need_human')
        self.assertEqual(self.db.query_one("SELECT status FROM ops_loop_state WHERE incident_id='inc'")[0], 'need_human')
