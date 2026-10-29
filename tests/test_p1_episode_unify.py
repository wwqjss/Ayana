"""P1-1 / P1-2 回归测试。

P1-1: alert_episodes 三套写入统一为 upsert_episode 单一入口
  - 幂等：同 fingerprint 未解决时更新而不是新建
  - 重复告警不堆 episode
  - resolved 不因迟到 firing 自动复活
  - starts_at_norm 退避在统一入口内

P1-2: 自动恢复阻塞判定单点 has_blocking_obligations
  - state 集合以 incidents.reconcile 为准
  - exttx 差异用 include_proposed 表达
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from ayana.alertmanager import fingerprint_of, upsert_episode
from ayana.db import Database, new_id, now
from ayana.incidents import IncidentService


class RecoveryProm:
    """Supply fresh, target-matched recovery evidence for recovery debounce."""

    def evaluate_recovery_evidence_sync(self, profile, *, asset_id, service):
        return {"verdict": "green", "contract": profile.id,
                "asset": asset_id, "service": service}


def make_db():
    tmp = tempfile.TemporaryDirectory()
    db = Database(str(Path(tmp.name) / "t.db"))
    return tmp, db


def close(tmp, db):
    db.close()
    tmp.cleanup()


# ---------------------------------------------------------------------------
# P1-1: upsert_episode 幂等
# ---------------------------------------------------------------------------

class TestUpsertEpisodeIdempotent(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.addCleanup(close, self.tmp, self.db)

    def _upsert(self, **kw):
        defaults = dict(
            source_id="test_src",
            fingerprint="fp1",
            labels={"alertname": "TestAlert", "asset": "host1", "severity": "warning"},
            annotations={"msg": "hello"},
            status="firing",
            source_state="firing",
            t=now(),
        )
        defaults.update(kw)
        return upsert_episode(self.db, **defaults)

    def test_same_fingerprint_firing_updates_not_inserts(self):
        t1 = now()
        ep1, created1, _, _ = self._upsert(t=t1, annotations={"msg": "first"})
        self.assertTrue(created1)
        ep2, created2, prev, new = self._upsert(t=t1 + 1, annotations={"msg": "second"})
        self.assertFalse(created2)
        self.assertEqual(ep1, ep2)
        self.assertEqual(prev, "firing")
        self.assertEqual(new, "firing")
        rows = self.db.query("SELECT * FROM alert_episodes")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["receive_count"], 2)

    def test_different_fingerprint_creates_separate_episode(self):
        t1 = now()
        ep1, _, _, _ = self._upsert(t=t1, fingerprint="fp1")
        ep2, created2, _, _ = self._upsert(t=t1, fingerprint="fp2")
        self.assertTrue(created2)
        self.assertNotEqual(ep1, ep2)
        rows = self.db.query("SELECT * FROM alert_episodes")
        self.assertEqual(len(rows), 2)

    def test_resolved_episode_not_revived_by_late_firing(self):
        """alertmanager 语义：显式 starts_at_norm 时 resolved 不复活。"""
        t1 = now()
        ep1, _, _, _ = self._upsert(t=t1, starts_at_norm="norm1")
        # resolve
        self.db.execute(
            "UPDATE alert_episodes SET status='resolved' WHERE id=?", (ep1,)
        )
        # late firing with same starts_at_norm
        ep2, created, prev, new = self._upsert(
            t=t1 + 5, starts_at_norm="norm1", status="firing"
        )
        self.assertFalse(created)
        self.assertEqual(ep1, ep2)
        self.assertEqual(prev, "resolved")
        self.assertEqual(new, "resolved")

    def test_new_failure_after_resolve_creates_new_episode(self):
        """exttx 语义：resolved 后新失败应建新 episode（同秒退避）。"""
        t1 = now()
        ep1, _, _, _ = self._upsert(t=t1)
        self.db.execute(
            "UPDATE alert_episodes SET status='resolved' WHERE id=?", (ep1,)
        )
        ep2, created, prev, new = self._upsert(t=t1)  # same second
        self.assertTrue(created)
        self.assertNotEqual(ep1, ep2)
        self.assertEqual(prev, "")
        self.assertEqual(new, "firing")
        rows = self.db.query("SELECT * FROM alert_episodes")
        self.assertEqual(len(rows), 2)

    def test_starts_at_norm_backoff_on_collision(self):
        t1 = now()
        ep1, _, _, _ = self._upsert(t=t1)
        # force resolve so next upsert creates new
        self.db.execute(
            "UPDATE alert_episodes SET status='resolved' WHERE id=?", (ep1,)
        )
        ep2, created, _, _ = self._upsert(t=t1)
        self.assertTrue(created)
        # starts_at_norm should differ (backoff)
        r1 = self.db.query_one("SELECT starts_at_norm FROM alert_episodes WHERE id=?", (ep1,))
        r2 = self.db.query_one("SELECT starts_at_norm FROM alert_episodes WHERE id=?", (ep2,))
        self.assertNotEqual(r1["starts_at_norm"], r2["starts_at_norm"])

    def test_updates_all_fields(self):
        t1 = now()
        ep1, _, _, _ = self._upsert(
            t=t1, annotations={"msg": "v1"}, silenced=0, inhibited=0
        )
        ep2, _, _, _ = self._upsert(
            t=t1 + 1, annotations={"msg": "v2"}, silenced=1, inhibited=1
        )
        self.assertEqual(ep1, ep2)
        row = self.db.query_one("SELECT * FROM alert_episodes WHERE id=?", (ep1,))
        self.assertEqual(row["receive_count"], 2)
        self.assertIn("v2", row["annotations_json"])
        self.assertEqual(row["silenced"], 1)
        self.assertEqual(row["inhibited"], 1)


class TestUpsertEpisodeChecksPath(unittest.TestCase):
    """checks 路径：连续失败不堆重复 episode。"""

    def setUp(self):
        self.tmp, self.db = make_db()
        self.addCleanup(close, self.tmp, self.db)

    def test_repeated_failures_single_episode(self):
        labels = {
            "alertname": "CheckFailed_ping",
            "asset": "host1",
            "check": "ping",
            "check_kind": "ping",
            "severity": "warning",
            "source": "ayana_check",
        }
        fp = fingerprint_of(labels)
        for i in range(5):
            t = now() + i
            ep_id, created, _, _ = upsert_episode(
                self.db,
                source_id="ayana_check",
                fingerprint=fp,
                labels=labels,
                annotations={"detail": f"fail {i}", "check_id": "c1"},
                status="firing",
                source_state="firing",
                t=t,
            )
            self.assertTrue(ep_id)
            if i == 0:
                self.assertTrue(created)
            else:
                self.assertFalse(created)
        rows = self.db.query("SELECT * FROM alert_episodes")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["receive_count"], 5)


class TestUpsertEpisodeAlertmanagerPath(unittest.TestCase):
    """alertmanager 路径：精确键命中 + resolved 不复活。"""

    def setUp(self):
        self.tmp, self.db = make_db()
        self.addCleanup(close, self.tmp, self.db)

    def test_exact_key_late_firing_not_revived(self):
        t1 = now()
        labels = {"alertname": "TargetDown", "asset": "nerv", "service": "frps"}
        fp = fingerprint_of(labels)
        starts_norm = "2025-01-01T00:00:00Z"
        ep1, _, _, _ = upsert_episode(
            self.db,
            source_id="alertmanager",
            fingerprint=fp,
            labels=labels,
            annotations={},
            status="firing",
            source_state="firing",
            t=t1,
            starts_at_norm=starts_norm,
        )
        self.db.execute("UPDATE alert_episodes SET status='resolved' WHERE id=?", (ep1,))
        ep2, created, prev, new = upsert_episode(
            self.db,
            source_id="alertmanager",
            fingerprint=fp,
            labels=labels,
            annotations={},
            status="firing",
            source_state="firing",
            t=t1 + 60,
            starts_at_norm=starts_norm,
        )
        self.assertFalse(created)
        self.assertEqual(ep1, ep2)
        self.assertEqual(new, "resolved")

    def test_new_start_time_creates_new_episode(self):
        t1 = now()
        labels = {"alertname": "TargetDown", "asset": "nerv", "service": "frps"}
        fp = fingerprint_of(labels)
        ep1, _, _, _ = upsert_episode(
            self.db,
            source_id="alertmanager",
            fingerprint=fp,
            labels=labels,
            status="firing",
            source_state="firing",
            t=t1,
            starts_at_norm="2025-01-01T00:00:00Z",
        )
        ep2, created, _, _ = upsert_episode(
            self.db,
            source_id="alertmanager",
            fingerprint=fp,
            labels=labels,
            status="firing",
            source_state="firing",
            t=t1,
            starts_at_norm="2025-01-01T01:00:00Z",
        )
        self.assertTrue(created)
        self.assertNotEqual(ep1, ep2)


# ---------------------------------------------------------------------------
# P1-2: has_blocking_obligations
# ---------------------------------------------------------------------------

class TestHasBlockingObligations(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.addCleanup(close, self.tmp, self.db)
        self.inc = IncidentService(self.db)
        self._seed_incident()

    def _seed_incident(self):
        self.db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage,"
            " need_human, generation, created_at, updated_at)"
            " VALUES('inc1','t','host1','obj1','open','pending',0,1,?,?)",
            (now(), now()),
        )

    def _add_episode(self, ep_id="ep1", status="firing"):
        self.db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm,"
            " alertname, status, asset_id, object_id, incident_id, first_seen, last_seen,"
            " receive_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)",
            (ep_id, "am", f"fp_{ep_id}", "s1", "TestAlert", status,
             "host1", "obj1", "inc1", now(), now()),
        )

    def _add_action(self, act_id="act1", state="success"):
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " state, mode, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (act_id, "inc1", "host1", "obj1", "service.restart", state, "manual", now()),
        )

    def _add_verification(self, ver_id="ver1", action_id="act1", status="pending"):
        self.db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, started_at)"
            " VALUES(?,?,?,?,?)",
            (ver_id, action_id, "inc1", status, now()),
        )

    def test_no_obligations(self):
        self.assertFalse(self.inc.has_blocking_obligations("inc1"))

    def test_firing_episode_blocks(self):
        self._add_episode()
        self.assertTrue(self.inc.has_blocking_obligations("inc1"))

    def test_resolved_episode_does_not_block(self):
        self._add_episode(status="resolved")
        self.assertFalse(self.inc.has_blocking_obligations("inc1"))

    def test_unknown_action_blocks(self):
        self._add_action(state="unknown")
        self.assertTrue(self.inc.has_blocking_obligations("inc1"))

    def test_dispatched_action_blocks(self):
        self._add_action(state="dispatched")
        self.assertTrue(self.inc.has_blocking_obligations("inc1"))

    def test_success_with_pending_verification_blocks(self):
        self._add_action(state="success")
        self._add_verification(status="pending")
        self.assertTrue(self.inc.has_blocking_obligations("inc1"))

    def test_success_with_passed_verification_does_not_block(self):
        self._add_action(state="success")
        self._add_verification(status="passed")
        self.assertFalse(self.inc.has_blocking_obligations("inc1"))

    def test_pending_verification_blocks(self):
        self._add_action(state="success")
        self._add_verification(status="pending")
        self.assertTrue(self.inc.has_blocking_obligations("inc1"))

    def test_need_human_blocks(self):
        self.db.execute("UPDATE incidents SET need_human=1 WHERE id='inc1'")
        self.assertTrue(self.inc.has_blocking_obligations("inc1"))

    def test_proposed_blocks_only_with_include_proposed(self):
        self._add_action(state="proposed")
        self.assertFalse(self.inc.has_blocking_obligations("inc1"))
        self.assertTrue(self.inc.has_blocking_obligations("inc1", include_proposed=True))

    def test_approved_blocks_only_with_include_proposed(self):
        self._add_action(state="approved")
        self.assertFalse(self.inc.has_blocking_obligations("inc1"))
        self.assertTrue(self.inc.has_blocking_obligations("inc1", include_proposed=True))

    def test_failure_action_does_not_block(self):
        self._add_action(state="failure")
        self.assertFalse(self.inc.has_blocking_obligations("inc1"))

    def test_empty_inc_id_returns_false(self):
        self.assertFalse(self.inc.has_blocking_obligations(""))


class TestObjectActionsLocked(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.addCleanup(close, self.tmp, self.db)
        self.inc = IncidentService(self.db)

    def _add_action(self, act_id="act1", state="dispatched", asset="host1", obj="obj1"):
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " state, mode, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (act_id, "inc1", asset, obj, "service.restart", state, "manual", now()),
        )

    def test_locked_when_dispatched(self):
        self._add_action(state="dispatched")
        self.assertTrue(self.inc.object_actions_locked("host1", "obj1"))

    def test_not_locked_when_success(self):
        self._add_action(state="success")
        self.assertFalse(self.inc.object_actions_locked("host1", "obj1"))

    def test_exclude_self(self):
        self._add_action(act_id="act1", state="dispatched")
        self.assertFalse(self.inc.object_actions_locked("host1", "obj1", exclude="act1"))

    def test_different_object_not_locked(self):
        self._add_action(state="dispatched", obj="other")
        self.assertFalse(self.inc.object_actions_locked("host1", "obj1"))


# ---------------------------------------------------------------------------
# P1-2: on_episode_resolved 恢复防抖
# ---------------------------------------------------------------------------

class TestRecoveryDebounce(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db = make_db()
        self.addCleanup(close, self.tmp, self.db)
        self.inc = IncidentService(self.db)
        self.inc.prom = RecoveryProm()
        self.db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage,"
            " need_human, generation, created_at, updated_at)"
            " VALUES('inc1','t','host1','obj1','open','pending',0,1,?,?)",
            (now(), now()),
        )
        self.db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm,"
            " alertname, status, asset_id, object_id, incident_id, first_seen, last_seen,"
            " receive_count,problem_family) VALUES('ep1','am','fp1','s1','TargetDown','resolved',"
            " 'host1','obj1','inc1',?,?,1,'availability')",
            (now(), now()),
        )

    def test_resolved_with_no_obligations_recovers(self):
        # 告警恢复须有当前目标的新鲜契约证据，passed 状态本身不足以证明恢复。
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " state, mode, created_at) VALUES('act1','inc1','host1','obj1',"
            " 'service.restart','success','manual',?)",
            (now(),),
        )
        self.db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, started_at)"
            " VALUES('ver1','act1','inc1','passed',?)",
            (now(),),
        )
        self.inc.on_episode_resolved("ep1")
        row = self.db.query_one("SELECT status, outcome FROM incidents WHERE id='inc1'")
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["outcome"], "recovered")

    def test_resolved_with_unknown_action_still_recovers(self):
        # 目标已恢复即闭环，不被 unknown action 卡住
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " state, mode, created_at) VALUES('act1','inc1','host1','obj1',"
            " 'service.restart','unknown','manual',?)",
            (now(),),
        )
        self.inc.on_episode_resolved("ep1")
        row = self.db.query_one(
            "SELECT status, outcome, close_reason, resolution_basis FROM incidents WHERE id='inc1'"
        )
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["outcome"], "recovered")
        self.assertEqual(row["close_reason"], "目标已恢复")
        self.assertEqual(row["resolution_basis"], "target_recovered")

    def test_resolved_with_pending_verification_still_recovers(self):
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " state, mode, created_at) VALUES('act1','inc1','host1','obj1',"
            " 'service.restart','success','manual',?)",
            (now(),),
        )
        self.db.execute(
            "INSERT INTO verifications(id, action_id, incident_id, status, started_at)"
            " VALUES('ver1','act1','inc1','pending',?)",
            (now(),),
        )
        self.inc.on_episode_resolved("ep1")
        row = self.db.query_one("SELECT status, outcome, close_reason FROM incidents WHERE id='inc1'")
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["outcome"], "recovered")
        self.assertEqual(row["close_reason"], "目标已恢复")

    def test_resolved_with_need_human_still_recovers(self):
        self.db.execute("UPDATE incidents SET need_human=1 WHERE id='inc1'")
        self.inc.on_episode_resolved("ep1")
        row = self.db.query_one(
            "SELECT status, outcome, need_human, close_reason FROM incidents WHERE id='inc1'"
        )
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["outcome"], "recovered")
        self.assertEqual(row["need_human"], 0)
        self.assertEqual(row["close_reason"], "目标已恢复")

    def test_other_firing_episode_blocks_recover(self):
        self.db.execute(
            "INSERT INTO alert_episodes(id, source_id, fingerprint, starts_at_norm,"
            " alertname, status, asset_id, object_id, incident_id, first_seen, last_seen,"
            " receive_count) VALUES('ep2','am','fp2','s2','OtherAlert','firing',"
            " 'host1','obj1','inc1',?,?,1)",
            (now(), now()),
        )
        self.inc.on_episode_resolved("ep1")
        row = self.db.query_one("SELECT status FROM incidents WHERE id='inc1'")
        self.assertEqual(row["status"], "open")

    def test_recover_not_duplicated(self):
        self.inc.on_episode_resolved("ep1")
        self.inc.on_episode_resolved("ep1")
        self.inc.on_episode_resolved("ep1")
        n = self.db.query_one(
            "SELECT COUNT(*) AS n FROM events WHERE incident_id='inc1'"
            " AND type='incident_resolved'"
        )
        self.assertEqual(n["n"], 1)


class TestExtRecoverySemantics(unittest.TestCase):
    """exttx include_proposed=True 语义回归。"""

    def setUp(self):
        self.tmp, self.db = make_db()
        self.addCleanup(close, self.tmp, self.db)
        self.inc = IncidentService(self.db)
        self.db.execute(
            "INSERT INTO incidents(id, title, asset_id, object_id, status, stage,"
            " need_human, generation, created_at, updated_at)"
            " VALUES('inc1','t','host1','obj1','open','pending',0,1,?,?)",
            (now(), now()),
        )

    def _add_action(self, state):
        self.db.execute(
            "INSERT INTO actions(id, incident_id, asset_id, object_id, capability,"
            " state, mode, created_at) VALUES(?, 'inc1','host1','obj1',"
            " 'service.restart', ?, 'manual', ?)",
            (new_id("act"), state, now()),
        )

    def test_proposed_blocks_ext_recovery(self):
        self._add_action("proposed")
        self.assertTrue(
            self.inc.has_blocking_obligations("inc1", include_proposed=True)
        )

    def test_approved_blocks_ext_recovery(self):
        self._add_action("approved")
        self.assertTrue(
            self.inc.has_blocking_obligations("inc1", include_proposed=True)
        )

    def test_dispatched_blocks_both(self):
        self._add_action("dispatched")
        self.assertTrue(self.inc.has_blocking_obligations("inc1"))
        self.assertTrue(
            self.inc.has_blocking_obligations("inc1", include_proposed=True)
        )


if __name__ == "__main__":
    unittest.main()
