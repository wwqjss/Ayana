"""等待和升级消息必须对应仍然有效的当前义务。"""
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from ayana.db import Database, now
from ayana.notify import Notifier


class AgentNotificationLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "notifications.db")
        self.addCleanup(self.db.close)
        self.db.execute(
            "INSERT INTO incidents(id,title,asset_id,object_id,status,stage,generation,created_at,updated_at)"
            " VALUES('i','nerv / frps: TargetDown','nerv','frps','open','watching',1,?,?)",
            (now(), now()),
        )
        self.notifier = Notifier(self.db)
        self.send = AsyncMock(return_value=(True, ""))
        send = self.send
        class Channels:
            def list_enabled(self):
                return [{"id": "wecom", "kind": "wecom_aibot", "targets": ["chat"], "created_at": 0}]
            async def send(self, *args, **kwargs):
                return await send(*args, **kwargs)
        self.notifier.set_channel_store(Channels())

    def test_wait_notice_queued_before_execution_is_cancelled_after_dispatch(self):
        event = self.db.event("agent_waiting", incident_id="i", payload={
            "generation": 1, "rule": "rb", "blockers": ["budget"], "body": "冷却中",
        })
        self.assertTrue(self.notifier.enqueue_for_event(event, body="冷却中"))
        self.db.execute(
            "INSERT INTO actions(id,incident_id,asset_id,object_id,capability,state,mode,created_at,dispatched_at)"
            " VALUES('executed','i','nerv','frps','service.restart','success','auto',?,?)",
            (now(), now()),
        )
        self.assertEqual(self.notifier._event_plan(event), [])
        asyncio.run(self.notifier.flush())
        self.send.assert_not_awaited()
        self.assertEqual(self.notifier.outbox_summary()[0]["state"], "cancelled")

    def test_old_escalation_is_cancelled_when_only_another_human_obligation_remains(self):
        self.db.execute(
            "UPDATE incidents SET need_human=1,need_human_reason='precondition_unknown:verification_contract'"
        )
        event = self.db.event("agent_escalated", incident_id="i", payload={
            "generation": 1, "reason": "precondition_unknown:verification_contract", "body": "缺少验证契约",
        })
        self.assertTrue(self.notifier.enqueue_for_event(event, body="缺少验证契约"))
        self.db.execute(
            "UPDATE incidents SET need_human_reason='awaiting_approval:new-action',stage='awaiting_approval'"
        )
        self.assertEqual(self.notifier._event_plan(event), [])
        asyncio.run(self.notifier.flush())
        self.send.assert_not_awaited()
        self.assertEqual(self.notifier.outbox_summary()[0]["state"], "cancelled")


if __name__ == "__main__":
    unittest.main()
