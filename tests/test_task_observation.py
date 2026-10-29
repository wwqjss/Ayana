"""Task status and exact native-message observation; no model or production calls."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.main import App
from ayana.mimo_serve import MimoServeError
from ayana.native_turns import NativeTurns


class TaskObservationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / 'task.db')
        self.duty = DutySessionManager(self.db)
        self.sid = self.duty.create(origin='auto')['session_id']
        self.rid = 'ses_owned'
        self.db.execute('UPDATE duty_sessions SET remote_session_id=? WHERE id=?', (self.rid, self.sid))
        self.duty.set_runtime_state(self.sid, 'idle')
        self.engine = {'owner_start': 'same-engine'}
        self.messages = []

        async def status(rid=None):
            return {'type': 'idle'} if rid else {}

        async def messages(rid, **kwargs):
            return self.messages

        async def receipt(rid, receipt_id):
            raise MimoServeError('http_404')

        self.client = SimpleNamespace(_admit=lambda: None, session_status=status,
                                      messages=messages, receipt=receipt)
        self.manager = SimpleNamespace(serve_client_factory=lambda: self.client,
                                       engine_signature=lambda: self.engine)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def tracked_turn(self):
        self.duty.record_native_turn(self.sid, self.rid, 'msg_owned', 'submitting', engine=self.engine)
        self.duty.record_receipt(self.sid, self.rid, 'receipt_owned', status='unknown')
        self.duty.record_native_turn(self.sid, self.rid, 'msg_owned', 'accepted', receipt_id='receipt_owned')
        self.duty.set_runtime_state(self.sid, 'running', receipt_id='receipt_owned', receipt_status='accepted')

    def final(self, parent='msg_owned', finish='stop'):
        return {'info': {'id': 'msg_final', 'role': 'assistant', 'parentID': parent,
                         'finish': finish, 'time': {'created': 1, 'completed': 2}}, 'parts': []}

    def test_unknown_receipt_overrides_stale_running_binding(self):
        self.tracked_turn()
        self.assertEqual(self.duty.task_info(self.sid)['task_state'], 'unknown')
        self.assertIn('native_turn_unknown', self.duty.native_admission_blockers(self.sid))

    def test_unknown_write_is_not_presented_as_idle_or_running(self):
        self.db.execute("INSERT INTO session_write_ops(id,incident_id,session_id,action_key,status,created_at,updated_at)"
                        " VALUES('write','_session',?,'key','unknown',?,?)", (self.sid, time.time(), time.time()))
        self.assertEqual(self.duty.task_info(self.sid)['task_state'], 'unknown')
        self.duty.set_runtime_state(self.sid, 'running', receipt_status='accepted')
        self.assertEqual(self.duty.task_info(self.sid)['task_state'], 'unknown')

    def test_interrupted_owned_job_is_visible_without_a_native_owner(self):
        t = time.time()
        self.db.execute("INSERT INTO incidents(id,title,status,generation,created_at,updated_at) VALUES('inc','fault','open',1,?,?)", (t, t))
        self.duty.join_incident(self.sid, 'inc')
        self.db.execute("INSERT INTO investigation_jobs(incident_id,status,phase,generation,updated_at,created_at)"
                        " VALUES('inc','failed','interrupted',1,?,?)", (t, t))
        self.assertEqual(self.duty.task_info(self.sid)['task_state'], 'interrupted')

    async def test_exact_final_message_settles_missing_receipt_but_preserves_unknown_write(self):
        self.tracked_turn()
        self.db.execute("INSERT INTO session_write_ops(id,incident_id,session_id,action_key,status,created_at,updated_at)"
                        " VALUES('write','_session',?,'key','unknown',?,?)", (self.sid, time.time(), time.time()))
        self.messages = [self.final()]
        app = App.__new__(App)
        app.db, app.duty, app.agent_tui = self.db, self.duty, self.manager
        app.mimo_serve = SimpleNamespace(client=lambda: self.client)
        await app._reconcile_native_receipts_once()
        self.assertEqual(self.db.query_one("SELECT status FROM agent_runtime_receipts")[0], 'completed')
        self.assertEqual(self.db.query_one("SELECT state FROM agent_runtime_bindings WHERE session_id=?", (self.sid,))[0], 'idle')
        self.assertEqual(self.db.query_one("SELECT status FROM session_write_ops")[0], 'unknown')
        self.assertEqual(self.duty.task_info(self.sid)['task_state'], 'unknown')

    async def test_idle_or_foreign_or_tool_step_does_not_settle_unknown_receipt(self):
        self.tracked_turn()
        for history in ([], [self.final(parent='other_input')], [self.final(finish='tool-calls')]):
            self.messages = history
            await NativeTurns(self.db).reconcile(self.manager)
            self.assertEqual(self.db.query_one('SELECT status FROM agent_runtime_receipts')[0], 'unknown')
            self.assertEqual(self.duty.task_info(self.sid)['task_state'], 'unknown')

    async def test_native_recovery_candidate_proves_interruption_and_never_success(self):
        self.tracked_turn()
        self.messages = [{'info': {'id': 'msg_interrupted', 'role': 'assistant',
                                   'parentID': 'msg_owned', 'time': {'created': 2}}}]

        async def recovery(method, path, **kwargs):
            self.assertEqual(method, 'GET')
            return {'candidates': [{'kind': 'assistant', 'assistantMessageID': 'msg_interrupted',
                                     'parentMessageID': 'msg_owned'}]}

        self.client._request = recovery
        await NativeTurns(self.db).reconcile(self.manager)
        self.assertEqual(self.db.query_one('SELECT status FROM agent_runtime_receipts')[0], 'cancelled')
        self.assertEqual(self.duty.task_info(self.sid)['task_state'], 'interrupted')
        self.assertTrue(self.duty.task_info(self.sid)['can_recover'])

    async def test_native_receipt_can_recover_old_automatic_input_linkage(self):
        self.duty.record_receipt(self.sid, self.rid, 'receipt_owned', status='unknown')
        self.duty.set_runtime_state(self.sid, 'running', receipt_id='receipt_owned', receipt_status='accepted')
        self.messages = [self.final()]

        async def receipt(rid, receipt_id):
            return {'id': receipt_id, 'lane': {'sessionID': rid}, 'state': 'claimed',
                    'inputMessageID': 'msg_owned'}

        self.client.receipt = receipt
        app = App.__new__(App)
        app.db, app.duty, app.agent_tui = self.db, self.duty, self.manager
        app.mimo_serve = SimpleNamespace(client=lambda: self.client)
        await app._reconcile_native_receipts_once()
        self.assertEqual(self.db.query_one('SELECT status FROM agent_runtime_receipts')[0], 'completed')
        tracked = self.db.query_one('SELECT payload_json FROM agent_native_submissions')
        self.assertEqual(json.loads(tracked[0])['messageID'], 'msg_owned')

    def test_automatic_linkage_survives_reopen_and_late_receipt_cannot_regress_terminal(self):
        self.tracked_turn()
        self.duty.record_native_turn(self.sid, self.rid, 'msg_owned', 'completed', receipt_id='receipt_owned')
        self.duty.record_native_turn(self.sid, self.rid, 'msg_owned', 'accepted', receipt_id='receipt_owned')
        self.db.close()
        self.db = Database(Path(self.tmp.name) / 'task.db')
        row = self.db.query_one('SELECT * FROM agent_native_submissions')
        self.assertEqual(row['state'], 'completed')
        self.assertEqual(row['receipt_id'], 'receipt_owned')
        self.assertEqual(json.loads(row['payload_json']), {'messageID': 'msg_owned', 'engine': self.engine})
        self.assertEqual(self.db.query_one('SELECT human_message_revision FROM duty_sessions WHERE id=?', (self.sid,))[0], 0)

    async def test_missing_prompt_message_id_is_persisted_before_uncertain_post(self):
        self.manager.require_live_controller = lambda sid, expected=None: ('admin', 'connection')
        self.manager._binding = lambda sid: {}
        self.db.execute("UPDATE agent_runtime_bindings SET controller='admin',controller_connection_id='connection',control_expires_at=? WHERE session_id=?", (time.time()+60, self.sid))
        posted = []

        async def request(method, path, **kwargs):
            posted.append(kwargs['body'])
            raise MimoServeError('timeout')

        self.client._request = request
        with self.assertRaises(MimoServeError):
            await NativeTurns(self.db).prompt(self.manager, self.sid, self.rid, '/prompt_async', {'parts': []})
        saved = self.db.query_one('SELECT payload_json,state FROM agent_native_submissions')
        self.assertEqual(saved['state'], 'unknown')
        message_id = json.loads(saved['payload_json'])['messageID']
        self.assertTrue(message_id.startswith('msg_'))
        self.assertEqual(posted[0]['messageID'], message_id)
        self.messages = [self.final(parent=message_id)]
        await NativeTurns(self.db).reconcile(self.manager)
        self.assertEqual(self.db.query_one('SELECT state FROM agent_native_submissions')[0], 'completed')
