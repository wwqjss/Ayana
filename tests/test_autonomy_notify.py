"""Durable AI notices follow the current generation and actionable condition."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ayana.db import Database, now
from ayana.notify import Notifier


class AutonomyNotifyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name) / "notices.db")
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES('nerv','nerv','nerv','nerv-exec',?,?)", (now(), now()))
        self.db.execute("INSERT INTO incidents(id,title,asset_id,object_id,status,stage,generation,created_at,updated_at) VALUES('inc1','frps down','nerv','frps','open','watching',2,?,?)", (now(), now()))
        self.db.execute("CREATE TABLE autonomy_state (incident_id TEXT NOT NULL,generation INTEGER NOT NULL,phase TEXT NOT NULL,PRIMARY KEY(incident_id,generation))")
        self.db.execute("INSERT INTO autonomy_state VALUES('inc1',2,'manual')")
        self.notifier = Notifier(self.db)
        self.sender = AsyncMock(return_value=(True, ""))
        self.routes = [{"id": "channel1", "kind": "qq", "targets": ["user:admin"]}]
        self.notifier.set_channel_store(SimpleNamespace(list_enabled=lambda: self.routes, send=self.sender))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def notice(self, kind="manual", *, generation=2, body="三轮方案与完整证据", **extra):
        self.db.event("autonomy_notice", incident_id="inc1", payload={"notice_kind": kind, "generation": generation, "body": body, **extra})
        return self.db.query_one("SELECT MAX(id) id FROM events")["id"]

    def phase(self, value):
        self.db.execute("UPDATE autonomy_state SET phase=?", (value,))

    def pending(self):
        return self.db.query("SELECT * FROM notification_outbox WHERE state='pending'")

    async def test_restart_compensation_recovers_adjudication_bundle_exactly_once(self):
        for part in (1, 2, 3):
            self.notice(part=part, parts=3, body="完整证据第" + str(part) + "部分")
        self.assertEqual(self.notifier.compensate_missing(), 3)
        self.assertEqual(len(self.pending()), 3)
        self.assertEqual(self.notifier.compensate_missing(), 0)
        self.assertEqual(await self.notifier.flush(), 3)
        self.assertEqual(self.sender.await_count, 3)
        self.assertEqual(self.notifier.compensate_missing(), 0)

    async def test_fanout_failure_retains_original_admin_targets_for_retry(self):
        event_id = self.notice()
        with patch.object(self.notifier, "_insert_outbox", side_effect=RuntimeError("temporary storage failure")):
            self.assertFalse(self.notifier.enqueue_for_event(event_id, body="ignored body"))
        self.routes[0]["targets"] = ["user:different"]
        self.assertEqual(self.notifier.compensate_missing(), 1)
        row = self.pending()[0]
        self.assertEqual(row["target"], "user:admin")
        self.assertEqual(row["body"], "三轮方案与完整证据")

    async def test_recovery_cancels_pending_manual_notice_and_prevents_compensation(self):
        event_id = self.notice()
        self.assertTrue(self.notifier.enqueue_for_event(event_id, body="ignored"))
        self.db.execute("UPDATE incidents SET status='resolved',stage='done'")
        self.assertEqual(await self.notifier.flush(), 0)
        self.assertEqual(self.notifier.compensate_missing(), 0)
        self.assertEqual(self.db.query_one("SELECT state FROM notification_outbox")["state"], "cancelled")
        self.sender.assert_not_awaited()

    async def test_generation_change_invalidates_both_existing_and_missing_obligations(self):
        event_id = self.notice()
        self.assertTrue(self.notifier.enqueue_for_event(event_id, body="ignored"))
        self.notice(body="not yet enqueued")
        self.db.execute("UPDATE incidents SET generation=3,status='open'")
        self.assertEqual(self.notifier.compensate_missing(), 0)
        self.assertEqual(await self.notifier.flush(), 0)
        self.sender.assert_not_awaited()

    async def test_manual_release_suppresses_stale_adjudication_request(self):
        self.notice()
        self.phase("investigating")
        self.assertEqual(self.notifier.compensate_missing(), 0)

    async def test_goal_barrier_is_actionable_before_engine_phase_update(self):
        self.phase("reviewing")
        self.db.execute("INSERT INTO council_goals(id,incident_id,generation,asset_id,object_id,repair_goal,manual_required,created_at,updated_at) VALUES('goal1','inc1',2,'nerv','frps','restore_registered_object',1,?,?)", (now(), now()))
        self.notice()
        self.assertEqual(self.notifier.compensate_missing(), 1)
        self.db.execute("UPDATE council_goals SET manual_required=0")
        self.assertEqual(await self.notifier.flush(), 0)
        self.sender.assert_not_awaited()

    async def test_provider_notice_waits_for_actual_unavailable_phase_and_cancels_when_model_recovers(self):
        event_id = self.notice("provider")
        self.phase("drafting")
        self.assertFalse(self.notifier.enqueue_for_event(event_id, body="ignored"))
        self.phase("provider_unavailable")
        self.assertEqual(self.notifier.compensate_missing(), 1)
        self.phase("investigating")
        self.assertEqual(await self.notifier.flush(), 0)
        self.sender.assert_not_awaited()

    async def test_budget_notice_does_not_block_existing_non_ai_notifications(self):
        self.phase("budget_blocked")
        self.db.event("incident_opened", incident_id="inc1", payload={"body": "core alert"})
        self.notice("budget")
        self.assertEqual(self.notifier.compensate_missing(), 2)
        self.assertEqual(await self.notifier.flush(), 2)
        self.assertEqual(self.sender.await_count, 2)

    async def test_new_bundle_replaces_old_bundle_but_keeps_every_new_part(self):
        for part in (1, 2):
            self.notice(part=part, parts=2, body="旧裁决" + str(part))
        for part in (1, 2, 3):
            self.notice(part=part, parts=3, body="新裁决" + str(part))
        self.assertEqual(self.notifier.compensate_missing(), 3)
        self.assertEqual([row["body"] for row in self.pending()], ["新裁决1", "新裁决2", "新裁决3"])

    async def test_malformed_or_unscoped_notice_cannot_turn_into_a_fallback_alert(self):
        for generation, body in ((None, "body"), (True, "body"), ("2", "body"), (2, "")):
            self.notice(generation=generation, body=body)
        self.notice("unrecognized")
        self.notice({"malformed": "kind"})
        self.assertEqual(self.notifier.compensate_missing(), 0)
        self.assertFalse(self.pending())

    async def test_optional_ai_storage_missing_does_not_block_core_compensation(self):
        self.db.execute("DROP TABLE autonomy_state")
        self.notice()
        self.db.event("incident_opened", incident_id="inc1", payload={"body": "core alert"})
        self.assertEqual(self.notifier.compensate_missing(), 1)
        self.assertEqual(await self.notifier.flush(), 1)

    async def test_new_generation_boundary_prevents_forged_current_number_on_old_message(self):
        self.notice()
        self.db.event("generation_bumped", incident_id="inc1", payload={"generation": 2})
        self.assertEqual(self.notifier.compensate_missing(), 0)


if __name__ == "__main__":
    unittest.main()
