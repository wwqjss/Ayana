"""Real notification obligations across channel setup, state changes and retries."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from ayana.agent import AgentLoop
from ayana.db import Database, now
from ayana.notify import Notifier
from ayana.notify_channels import ChannelStore
from ayana.runbook import RunbookRule


class NotificationObligationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary_root = Path(__file__).resolve().parents[1] / ".test-tmp"
        temporary_root.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="notification-obligations-", dir=temporary_root)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES('nerv','NERV','nerv','nerv',?,?)", (now(), now()))
        self.db.execute("INSERT INTO objects(id,asset_id,kind,name,unit,created_at) VALUES('nerv:service:frps','nerv','service','frps','frps',?)", (now(),))
        self.db.execute("INSERT INTO incidents(id,title,asset_id,object_id,status,stage,generation,created_at,updated_at) VALUES('inc1','nerv / frps: TargetDown','nerv','frps','open','pending',1,?,?)", (now(), now()))
        self.db.event("incident_opened", incident_id="inc1")
        self.store = ChannelStore(self.db, master_key="test-notify-key" * 3)
        self.store.send = AsyncMock(return_value=(True, ""))
        self.notifier = Notifier(self.db)
        self.notifier.set_channel_store(self.store)
        self.rule = RunbookRule(id="rb-frps", name="frps 探测失败自动重启", asset_id="nerv", object_name="frps", capability="service.restart")
        self.agent = AgentLoop.__new__(AgentLoop)
        self.agent.db = self.db
        self.agent.notifier = self.notifier

    def channel(self, enabled=True):
        return self.store.create(name="告警", kind="qq", config={"target": "user:123"}, enabled=enabled)

    def incident(self):
        return dict(self.db.query_one("SELECT * FROM incidents WHERE id='inc1'"))

    def authorization(self):
        self.db.execute("INSERT INTO actions(id,incident_id,asset_id,object_id,capability,state,proposer_type,proposer_id,created_at,approval_deadline,params_json,policy_snapshot_json) VALUES('act1','inc1','nerv','nerv:service:frps','service.restart','proposed','auto_rule','agent',?,?,?, '{}')", (now(), now() + 600, json.dumps({"tokens": ["systemctl", "restart", "frps"], "object_name": "frps"})))
        self.db.event("action_proposed", incident_id="inc1", payload={"action_id": "act1"})
        self.agent._notify_awaiting_approval("inc1", "act1", self.rule, {"decision": "confirm"}, {"status": "satisfied"})
        return self.db.query_one("SELECT id FROM events WHERE type='proposal_waiting'")["id"]

    def waiting(self, *, retry_at, reason="冷却中"):
        self.agent._wait_for_preconditions(self.incident(), self.rule, {}, {
            "blockers": ["budget"], "reasons": ["budget: unsatisfied"],
            "budget_reason": reason, "retry_at": retry_at,
        })

    def pending_rows(self):
        return [dict(row) for row in self.db.query("SELECT * FROM notification_outbox WHERE state='pending'")]

    async def test_existing_disabled_channel_can_deliver_current_authorization_when_enabled(self):
        channel = self.channel(enabled=False)
        event_id = self.authorization()
        self.assertEqual(self.pending_rows(), [])
        self.store.set_enabled(channel["id"], True)
        self.notifier.compensate_missing()
        rows = self.pending_rows()
        request = [row for row in rows if row["dedup_key"].startswith(f"ev:{event_id}:")]
        self.assertEqual(len(request), 1)
        self.assertIn("需要你授权", request[0]["body"])
        self.assertIn("执行一次", request[0]["body"])
        self.notifier.compensate_missing()
        self.assertEqual(len(self.pending_rows()), len(rows))

    async def test_first_channel_created_after_authorization_receives_current_obligation(self):
        event_id = self.authorization()
        self.assertEqual(self.pending_rows(), [])
        self.channel()
        self.notifier.compensate_missing()
        request = [row for row in self.pending_rows() if row["dedup_key"].startswith(f"ev:{event_id}:")]
        self.assertEqual(len(request), 1, "A current approval obligation must survive configuring the first channel")

    async def test_original_recipient_snapshot_does_not_replay_to_later_channels(self):
        self.channel()
        event_id = self.authorization()
        self.assertEqual(await self.notifier.flush(), 1)
        self.store.create(name="后来新增", kind="qq", config={"target": "user:456"})
        self.notifier.compensate_missing()
        matching = [dict(row) for row in self.db.query("SELECT * FROM notification_outbox WHERE dedup_key LIKE ?", (f"ev:{event_id}:%",))]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["target"], "user:123")

    async def test_compensation_does_not_reclassify_legacy_history_as_new_deferred_notification(self):
        old_event = self.db.event("incident_resolved", incident_id="old-incident", payload={"body": "旧历史恢复消息"})
        self.db.execute("UPDATE events SET at=? WHERE id=?", (now() - 86400, old_event))
        self.notifier.compensate_missing()
        self.channel()
        self.notifier.compensate_missing()
        matching = self.db.query("SELECT id FROM notification_outbox WHERE dedup_key LIKE ?", (f"ev:{old_event}:%",))
        self.assertEqual(matching, [], "Compensation must not create proof that an old unsnapshotted event was deferred at creation")

    async def test_failed_authorization_is_canceled_after_target_recovers(self):
        self.channel()
        self.authorization()
        self.store.send.return_value = (False, "temporary_failure")
        self.assertEqual(await self.notifier.flush(), 0)
        self.store.send.assert_awaited_once()
        self.db.execute("UPDATE incidents SET status='resolved',stage='done' WHERE id='inc1'")
        self.db.execute("UPDATE notification_outbox SET next_try_at=0")
        self.store.send.return_value = (True, "")
        self.assertEqual(await self.notifier.flush(), 0)
        self.assertEqual(self.store.send.await_count, 1)
        self.assertEqual(self.db.query_one("SELECT state FROM notification_outbox")["state"], "cancelled")

    async def test_pending_authorization_canceled_after_another_actor_approves(self):
        self.channel()
        self.authorization()
        self.db.execute("UPDATE actions SET state='approved' WHERE id='act1'")
        self.assertEqual(await self.notifier.flush(), 0)
        self.store.send.assert_not_awaited()
        self.assertEqual(self.db.query_one("SELECT state FROM notification_outbox")["state"], "cancelled")

    async def test_older_generation_authorization_never_delivered_after_reopen(self):
        self.channel()
        self.authorization()
        self.db.execute("UPDATE incidents SET generation=2,need_human=0 WHERE id='inc1'")
        self.db.event("incident_reopened", incident_id="inc1", payload={"generation": 2})
        self.assertEqual(await self.notifier.flush(), 0)
        self.store.send.assert_not_awaited()
        self.assertEqual(self.db.query_one("SELECT state FROM notification_outbox")["state"], "cancelled")

    async def test_same_waiting_state_reuses_one_event_and_one_notification(self):
        self.channel()
        self.waiting(retry_at=now() + 60)
        self.assertEqual(await self.notifier.flush(), 1)
        self.waiting(retry_at=now() + 120)
        self.notifier.compensate_missing()
        self.assertEqual(await self.notifier.flush(), 0)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) AS n FROM events WHERE type='agent_waiting'")["n"], 1)
        self.assertEqual(self.store.send.await_count, 1)

    async def test_undelivered_waiting_notification_uses_latest_reason(self):
        self.channel()
        self.waiting(retry_at=now() + 60, reason="冷却中")
        self.store.send.return_value = (False, "temporary_failure")
        await self.notifier.flush()
        self.waiting(retry_at=now() + 3600, reason="已达二十四小时执行上限")
        self.db.execute("UPDATE notification_outbox SET next_try_at=0")
        self.store.send.return_value = (True, "")
        await self.notifier.flush()
        delivered = self.store.send.await_args.args[1]
        self.assertIn("已达二十四小时执行上限", delivered)
        self.assertNotIn("冷却中", delivered)

    async def test_outdated_waiting_canceled_when_authorization_takes_over(self):
        self.channel()
        self.waiting(retry_at=now() + 60)
        self.authorization()
        self.assertEqual(await self.notifier.flush(), 1)
        self.assertIn("需要你授权", self.store.send.await_args.args[1])
        states = [row["state"] for row in self.db.query("SELECT state FROM notification_outbox")]
        self.assertEqual(sorted(states), ["cancelled", "sent"])

    async def test_same_waiting_reason_in_new_generation_creates_new_obligation(self):
        self.channel()
        self.waiting(retry_at=now() + 60)
        self.db.execute("UPDATE incidents SET generation=2,stage='pending' WHERE id='inc1'")
        self.db.event("incident_reopened", incident_id="inc1", payload={"generation": 2})
        self.waiting(retry_at=now() + 120)
        self.assertEqual(await self.notifier.flush(), 1)
        self.assertEqual(self.db.query_one("SELECT COUNT(*) AS n FROM events WHERE type='agent_waiting'")["n"], 2)
        states = [row["state"] for row in self.db.query("SELECT state FROM notification_outbox")]
        self.assertEqual(sorted(states), ["cancelled", "sent"])

    async def test_waiting_does_not_resurface_while_completed_action_is_being_verified(self):
        self.channel()
        self.waiting(retry_at=now() + 60)
        self.authorization()
        self.db.execute("UPDATE actions SET state='success' WHERE id='act1'")
        self.db.execute("UPDATE incidents SET stage='watching',need_human=0,need_human_reason='' WHERE id='inc1'")
        self.assertEqual(await self.notifier.flush(), 0)
        self.store.send.assert_not_awaited()

    async def test_escalation_is_bound_to_its_exact_human_obligation(self):
        self.channel()
        self.agent._escalate(dict(self.db.query_one("SELECT * FROM incidents WHERE id='inc1'")), "no_runbook_match")
        self.db.execute("UPDATE incidents SET need_human=1,need_human_reason='verify_failed:ver1' WHERE id='inc1'")
        self.assertEqual(await self.notifier.flush(), 0)
        self.store.send.assert_not_awaited()
        self.assertEqual(self.db.query_one("SELECT state FROM notification_outbox")["state"], "cancelled")


if __name__ == "__main__":
    unittest.main()
