"""Cross-module lifecycle boundaries: stale evidence and persistent notification intent."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
from unittest.mock import patch

from ayana.alertmanager import AlertIngest
from ayana.db import Database, now
from ayana.incidents import IncidentService
from ayana.notify import Notifier

import test_phase_c_p0 as fixtures


class LifecycleConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.db, _, self.prom, self.actions, self.incidents = fixtures.make_env()
        self.addCleanup(fixtures.close, self.tmp, self.db)
        fixtures.seed_incident(self.db)
        fixtures.seed_success_action(self.db)

    def incident(self):
        return dict(self.db.query_one("SELECT * FROM incidents WHERE id='inc1'"))

    def test_stale_failure_does_not_add_human_obligation_to_new_generation(self):
        self.db.execute("UPDATE incidents SET generation=2,stage='pending' WHERE id='inc1'")
        result = self.incidents.on_verification_finished('inc1', 'act1', 'old-ver', 1, 'failed')
        self.assertEqual(result['skipped'], 'stale_generation')
        self.assertEqual(self.incident()['stage'], 'pending')
        self.assertFalse(self.incident()['need_human'])

    def test_confirmed_recovery_is_not_reopened_by_late_unknown(self):
        self.incidents._force_recovered('inc1')
        self.incidents.on_verification_finished('inc1', 'act1', 'late-ver', 1, 'unknown')
        self.assertEqual(self.incident()['status'], 'resolved')
        self.assertEqual(self.incident()['close_reason'], '目标已恢复')
        self.assertFalse(self.incident()['need_human'])

    def test_closed_incident_keeps_its_human_decision(self):
        self.incidents.close_manual('inc1', 'operator decision')
        self.incidents.on_verification_finished('inc1', 'act1', 'late-ver', 1, 'failed')
        self.assertEqual(self.incident()['status'], 'closed')
        self.assertFalse(self.incident()['need_human'])

    def test_current_failure_requires_review_instead_of_another_auto_restart(self):
        self.incidents.on_verification_finished('inc1', 'act1', 'current-ver', 1, 'failed')
        self.assertEqual(self.incident()['status'], 'open')
        self.assertTrue(self.incident()['need_human'])
        self.assertIn('verify_failed:current-ver', self.incident()['need_human_reason'])

    def test_verifier_saves_stale_result_without_mutating_current_incident(self):
        self.db.execute("UPDATE incidents SET generation=2,stage='pending' WHERE id='inc1'")
        self.db.execute(
            "INSERT INTO verifications(id,action_id,incident_id,status,started_at,generation,"
            " profile_id,criteria_json,deadline_at) VALUES('old-ver','act1','inc1','pending',?,1,"
            " 'svc.recover',?,?)",
            (now()-10, json.dumps({'baseline_finished_at': now()-10, 'service': 'frps'}), now()-1),
        )
        result = asyncio.run(self.actions._run_verification('old-ver', 'act1'))
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(self.db.query_one("SELECT status FROM verifications WHERE id='old-ver'")['status'], 'unknown')
        self.assertFalse(self.incident()['need_human'])
        self.assertEqual(self.incident()['stage'], 'pending')

    def test_recovery_cancels_approved_but_not_dispatched_action(self):
        self.db.execute("UPDATE actions SET state='approved' WHERE id='act1'")
        self.incidents._force_recovered('inc1')
        self.assertEqual(self.actions.get_action('act1')['state'], 'cancelled')

    def test_reverification_keeps_original_action_generation(self):
        self.db.execute("UPDATE incidents SET generation=4 WHERE id='inc1'")
        self.db.execute("INSERT INTO verifications(id,action_id,incident_id,status,started_at,generation)"
                        " VALUES('old','act1','inc1','failed',?,3)", (now()-60,))
        with patch.object(self.actions, '_run_verification', new=AsyncMock(return_value={})):
            asyncio.run(self.actions.verify('act1'))
        verification = self.db.query_one("SELECT generation FROM verifications WHERE action_id='act1'"
                                         " AND status='pending'")
        self.assertEqual(verification['generation'], 3)

    def test_first_manual_verification_uses_action_generation_event(self):
        self.db.execute("UPDATE incidents SET generation=4 WHERE id='inc1'")
        eid = self.db.event('incident_reopened',incident_id='inc1',payload={'generation':4})
        self.db.execute('UPDATE events SET at=? WHERE id=?',(now()-10,eid))
        with patch.object(self.actions, '_run_verification', new=AsyncMock(return_value={})):
            asyncio.run(self.actions.verify('act1'))
        verification = self.db.query_one("SELECT generation FROM verifications WHERE action_id='act1'")
        self.assertEqual(verification['generation'], 4)

    def test_quarantine_is_not_hidden_by_an_unavailable_source(self):
        self.db.execute("UPDATE alert_episodes SET source_health='unavailable' WHERE id='ep_inc1'")
        self.db.execute("INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,incident_id,"
                        " alertname,status,first_seen,last_seen,source_state,source_health)"
                        " VALUES('q','am','q','q','inc1','TargetDown','firing',?,?,'quarantine','quarantine')",
                        (now(),now()))
        self.assertTrue(self.incidents.source_block_reason('inc1').startswith('quarantined_source:'))

    def test_stage_tracks_current_execution_and_verification(self):
        self.db.execute("UPDATE incidents SET stage='pending'")
        self.db.execute("UPDATE actions SET state='dispatched'")
        self.assertEqual(self.incidents.reconcile('inc1')['stage'],'executing')
        self.db.execute("UPDATE actions SET state='success'")
        self.db.execute("INSERT INTO verifications(id,action_id,incident_id,status,started_at,generation)"
                        " VALUES('pending','act1','inc1','pending',?,1)",(now(),))
        self.assertEqual(self.incidents.reconcile('inc1')['stage'],'verifying')

    def test_approval_stage_is_preserved_until_decision(self):
        self.db.execute("UPDATE actions SET state='proposed'")
        self.incidents.set_need_human('inc1','awaiting_approval:act1 decision=approval_required')
        self.assertEqual(self.incidents.reconcile('inc1')['stage'],'awaiting_approval')
        self.incidents.set_need_human('inc1','inspect_disk')
        self.assertEqual(self.incidents.reconcile('inc1')['stage'],'need_human')

    def test_old_episode_cannot_close_new_not_seen_failure(self):
        self.db.execute("UPDATE alert_episodes SET status='resolved',first_seen=? WHERE id='ep_inc1'",(now()-100,))
        self.db.event('incident_resolved',incident_id='inc1',episode_id='ep_inc1',payload={'generation':1})
        self.db.execute("UPDATE incidents SET generation=2,status='open',stage='pending' WHERE id='inc1'")
        self.db.execute("INSERT INTO alert_episodes(id,source_id,fingerprint,starts_at_norm,incident_id,"
                        " alertname,status,asset_id,object_id,first_seen,last_seen,source_state,source_health)"
                        " VALUES('new','am','new','new','inc1','TargetDown','firing','nerv','frps',?,?,'not_seen','ok')",
                        (now(),now()))
        self.db.event('incident_reopened',incident_id='inc1',episode_id='new',payload={'generation':2,'episode_id':'new'})
        self.incidents.on_episode_resolved('ep_inc1')
        self.assertEqual(self.incident()['status'],'open')
        self.assertEqual(self.db.query_one("SELECT status FROM alert_episodes WHERE id='new'")['status'],'firing')
        # 后台补偿也不得借旧 episode 消除本代未见的故障。
        from ayana.main import App
        app=App.__new__(App)
        app.db,app.incidents=self.db,self.incidents
        app.alert_ingest=AlertIngest(self.db,incidents=self.incidents)
        app._stop=asyncio.Event()
        async def stop_after_one_pass(_):
            app._stop.set()
        with patch('ayana.main.asyncio.sleep',side_effect=stop_after_one_pass):
            asyncio.run(app._bg_correlate())
        self.assertEqual(self.incident()['status'],'open')
        self.db.execute("UPDATE alert_episodes SET status='resolved',source_state='resolved' WHERE id='new'")
        self.incidents.on_episode_resolved('new')
        self.assertEqual(self.incident()['status'],'resolved')
        recovered = self.db.query("SELECT payload_json FROM events WHERE type='incident_resolved'")
        self.assertEqual([json.loads(r['payload_json'])['generation'] for r in recovered],[1,2])
        self.incidents.on_episode_resolved('new')
        self.assertEqual(len(self.db.query("SELECT id FROM events WHERE type='incident_resolved'")),2)

    def test_verification_recovery_also_creates_one_notification_event(self):
        self.db.execute("UPDATE alert_episodes SET status='resolved'")
        self.db.execute("INSERT INTO verifications(id,action_id,incident_id,status,started_at,generation)"
                        " VALUES('passed','act1','inc1','passed',?,1)",(now(),))
        self.incidents.reconcile('inc1')
        self.incidents.reconcile('inc1')
        rows=self.db.query("SELECT payload_json FROM events WHERE type='incident_resolved'")
        self.assertEqual(len(rows),1)
        self.assertIn('已恢复',json.loads(rows[0]['payload_json'])['body'])

    def test_terminal_incident_cannot_acquire_a_new_human_obligation(self):
        self.incidents._force_recovered('inc1')
        self.incidents.set_need_human('inc1','late_agent_error')
        self.assertFalse(self.incident()['need_human'])
        self.assertEqual(self.incident()['stage'],'done')


class NotificationIntentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tmp.name)/'test.db')
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.close)
        self.db.execute("INSERT INTO incidents(id,title,asset_id,object_id,status,created_at,updated_at)"
                        " VALUES('i','nerv / frps: TargetDown','nerv','frps','open',?,?)", (now(), now()))
        self.notifier = Notifier(self.db)
        class Channels:
            send = AsyncMock(return_value=(True, ''))
            def list_enabled(self):
                return [{'id':'wecom','kind':'wecom_aibot','targets':['test-chat'],'created_at':0}]
        self.notifier.set_channel_store(Channels())

    def event(self, kind, *, at, episode=''):
        eid = self.db.event(kind, incident_id='i', episode_id=episode, payload={'body':'test notice'})
        self.db.execute('UPDATE events SET at=? WHERE id=?', (at,eid))
        return eid

    async def test_reopen_suppression_survives_compensation(self):
        self.event('incident_resolved', at=now()-60)
        event_id = self.event('incident_reopened', at=now(), episode='new')
        self.assertFalse(self.notifier.enqueue_for_event(event_id, body='should stay quiet'))
        self.notifier.compensate_missing()
        rows = self.notifier.outbox_summary()
        self.assertFalse(any(r['dedup_key'].startswith(f'ev:{event_id}:') for r in rows))
        payload = json.loads(self.db.query_one('SELECT payload_json FROM events WHERE id=?',(event_id,))['payload_json'])
        self.assertEqual(payload['_notification_suppressed'], 'quiet_window')

    async def test_quiet_hour_allows_exactly_one_refire(self):
        self.event('incident_resolved', at=now()-3601)
        event_id = self.event('incident_reopened', at=now(), episode='new')
        self.notifier.enqueue_for_event(event_id, body='告警复发')
        self.notifier.compensate_missing()
        self.notifier.enqueue_for_event(event_id, body='告警复发')
        rows = [r for r in self.notifier.outbox_summary() if r['dedup_key'].startswith(f'ev:{event_id}:')]
        self.assertEqual(len(rows),1)

    async def test_current_attachment_is_excluded_from_quiet_interval(self):
        self.event('incident_opened', at=now()-4000)
        self.event('alert_fired', at=now(), episode='new')
        self.event('episode_attached', at=now(), episode='new')
        ingest = AlertIngest(self.db)
        self.assertTrue(ingest._quiet_elapsed('i', episode_id='new'))

    async def test_old_direct_agent_delivery_is_not_replayed_as_a_new_alert(self):
        self.db.event('agent_auto_exec',incident_id='i',payload={'action_id':'old-action','rule':'old-rule'})
        self.notifier.compensate_missing()
        self.assertEqual(self.notifier.outbox_summary(),[])

    async def test_live_recovery_uses_same_generation_snapshot_as_compensation(self):
        event_id=self.db.event('incident_resolved',incident_id='i',payload={'body':'已恢复：本次 17:22 → 17:42'})
        self.notifier.enqueue_for_event(event_id,body='过时的原始创建时间 10-08')
        self.assertEqual(self.notifier.outbox_summary()[0]['body'],'已恢复：本次 17:22 → 17:42')


class BatchedEpisodeBoundaryTests(unittest.TestCase):
    def test_last_attached_alert_can_finish_a_batched_incident(self):
        tmp=tempfile.TemporaryDirectory()
        db=Database(Path(tmp.name)/'test.db')
        self.addCleanup(tmp.cleanup)
        self.addCleanup(db.close)
        incidents=IncidentService(db)
        ingest=AlertIngest(db,incidents=incidents)
        alerts=[{'status':'firing','startsAt':'2026-10-21T09:00:00Z',
                 'labels':{'alertname':name,'asset':'nerv','service':'frps'}}
                for name in ('TargetDown','ServiceDown')]
        ingest.ingest_webhook({'alerts':alerts})
        inc=db.query_one('SELECT * FROM incidents')
        attached=db.query_one("SELECT episode_id FROM events WHERE type='episode_attached'")
        self.assertTrue(attached['episode_id'])
        # 旧格式关联记录也必须可识别。
        db.execute("UPDATE events SET episode_id='' WHERE type='episode_attached'")
        for alert in alerts:
            alert['status']='resolved'
            ingest.ingest_webhook({'alerts':[alert]})
        self.assertEqual(incidents.get_incident(inc['id'])['status'],'resolved')
        self.assertEqual(len(db.query("SELECT id FROM events WHERE type='incident_resolved'")),1)
