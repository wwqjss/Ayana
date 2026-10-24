"""P4.1：幂等台账 unknown / 竞态 / 租约。"""

from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ayana.db import Database, now  # noqa: E402
from ayana.session_bridge import SessionBridge  # noqa: E402


def make_db():
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db = Database(Path(tmp.name) / "t.db")
    return tmp, db


def insert_incident(db, inc_id="inc_1"):
    t = now()
    db.execute(
        "INSERT INTO incidents(id, title, asset_id, object_id, severity, status, stage,"
        " generation, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (inc_id, "t", "nerv", "frps", "warning", "open", "pending", 1, t, t),
    )


class TestWriteOpsStateMachine(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.br = SessionBridge(self.db)
        self.br.lease_ttl_sec = 60.0
        insert_incident(self.db)
        self.br.ensure_session("inc_1")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_done_permanent(self):
        self.br.claim_write("inc_1", "k1")
        self.br.complete_write("inc_1", "k1", ok=True, result="ok")
        for _ in range(3):
            c = self.br.claim_write("inc_1", "k1")
            self.assertTrue(c["already_done"])
            self.assertFalse(c["claimed"])

    def test_unknown_not_replayable(self):
        self.br.claim_write("inc_1", "k2")
        self.br.mark_unknown("inc_1", "k2", reason="ssh_timeout")
        c = self.br.claim_write("inc_1", "k2")
        self.assertFalse(c["claimed"])
        self.assertTrue(c.get("unknown"))
        r = self.br.release_write("inc_1", "k2")
        self.assertFalse(r["ok"], "unknown 默认不得放行重试")

    def test_unknown_requires_confirmed_safe_to_release(self):
        self.br.claim_write("inc_1", "k3")
        self.br.mark_unknown("inc_1", "k3", reason="disconnect")
        r = self.br.release_write("inc_1", "k3", confirmed_safe=True, reason="manual verify not applied")
        self.assertTrue(r["ok"])
        c = self.br.claim_write("inc_1", "k3")
        self.assertTrue(c["claimed"])

    def test_failed_requires_retry_safe(self):
        self.br.claim_write("inc_1", "k4")
        self.br.complete_write("inc_1", "k4", ok=False, result="denied")
        c = self.br.claim_write("inc_1", "k4")
        self.assertFalse(c["claimed"])
        self.assertEqual(c.get("error"), "retry_requires_confirmed_safe")
        c2 = self.br.claim_write("inc_1", "k4", retry_safe=True)
        self.assertTrue(c2["claimed"])

    def test_lease_expired_becomes_unknown_not_retry(self):
        self.br.claim_write("inc_1", "k5")
        # 手动把租约推到过去，模拟崩溃后过期
        self.db.execute(
            "UPDATE session_write_ops SET lease_expires_at=? WHERE action_key='k5'",
            (now() - 1,),
        )
        c = self.br.claim_write("inc_1", "k5")
        self.assertFalse(c["claimed"])
        self.assertTrue(c.get("unknown"), "租约过期 ≠ 未执行，必须 unknown")
        self.assertEqual(c.get("reason"), "lease_expired")
        row = self.db.query_one("SELECT status FROM session_write_ops WHERE action_key='k5'")
        self.assertEqual(row["status"], "unknown")

    def test_in_flight_blocks_second_claim(self):
        self.br.claim_write("inc_1", "k6")
        c = self.br.claim_write("inc_1", "k6")
        self.assertFalse(c["claimed"])
        self.assertTrue(c.get("in_flight"))

    def test_concurrent_claim_single_winner(self):
        results = []
        def worker():
            results.append(self.br.claim_write("inc_1", "kc"))
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        winners = [r for r in results if r.get("claimed")]
        self.assertEqual(len(winners), 1, f"exactly one winner, got {len(winners)}")

    def test_concurrent_reclaim_after_release_single_winner(self):
        self.br.claim_write("inc_1", "kr")
        self.br.complete_write("inc_1", "kr", ok=False, result="fail")
        self.br.release_write("inc_1", "kr", confirmed_safe=True)
        results = []
        def worker():
            results.append(self.br.claim_write("inc_1", "kr", retry_safe=True))
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        winners = [r for r in results if r.get("claimed")]
        self.assertEqual(len(winners), 1, f"reclaim race must be single winner, got {len(winners)}")

    def test_make_action_key_binds_target_and_params(self):
        k1 = self.br.make_action_key("nerv:frps", "restart", {"unit": "frps"})
        k2 = self.br.make_action_key("nerv:frps", "restart", {"unit": "frps"})
        k3 = self.br.make_action_key("nerv:frps", "restart", {"unit": "other"})
        k4 = self.br.make_action_key("kanata:mysql", "restart", {"unit": "frps"})
        self.assertEqual(k1, k2, "同参数同键")
        self.assertNotEqual(k1, k3, "参数变则键变")
        self.assertNotEqual(k1, k4, "目标变则键变")
        self.assertIn("nerv", k1)

    def test_complete_only_from_claimed(self):
        self.br.claim_write("inc_1", "k7")
        self.br.mark_unknown("inc_1", "k7", reason="x")
        # complete 不得把 unknown 改成 done
        self.br.complete_write("inc_1", "k7", ok=True, result="late")
        row = self.db.query_one("SELECT status FROM session_write_ops WHERE action_key='k7'")
        self.assertEqual(row["status"], "unknown", "unknown 不得被迟到的 complete 洗成 done")


if __name__ == "__main__":
    unittest.main()
