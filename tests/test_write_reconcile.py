"""Safe retry observations never replay a shell command or fabricate success."""
import asyncio
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from ayana.db import Database
from ayana.duty_session import DutySessionManager
from ayana.exec_facts import NTResult
from ayana.session_bridge import SessionBridge
from ayana.write_reconcile import observe_host_write, pull_image, recover_host_operation


class HostWriteObservationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / 'test.db')
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.db.close)
        self.duty = DutySessionManager(self.db)
        self.sid = self.duty.create(origin='manual')['session_id']
        self.bridge = SessionBridge(self.db, duty=self.duty)
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) "
                        "VALUES('kanata','kanata','kanata-read','kanata-write',1,1)")
        self.db.execute("INSERT INTO ssh_endpoints(id,asset_id,role,host,username,created_at,updated_at) "
                        "VALUES('endpoint','kanata','default','10.0.0.1','root',1,1)")
        self.command = 'docker pull gcr.io/cadvisor/cadvisor:latest'
        self.key = self.bridge.make_action_key('kanata', 'exec_shell',
            {'command': self.command, 'channel': 'write', 'classified': 'write'}, context='mcp-host-exec')
        self.incident = '_session:' + self.sid
        self.bridge.claim_write(self.incident, self.key, target='kanata',
            params={'command': self.command, 'channel': 'write', '_ayana_session_id': self.sid},
            authority_session_id=self.sid)
        self.bridge.mark_unknown(self.incident, self.key, reason='timeout')
        self.db.audit('agent', 'mcp_agent', 'mcp_host_exec_write', asset_id='kanata',
            action_id=self.key, detail={'command': self.command, 'state': 'unknown',
                'purpose': 'execute', 'session_id': self.sid, 'ssh_account_group': 'default',
                'ssh_account': 'root'})
        self.row = dict(self.db.query_one('SELECT * FROM session_write_ops WHERE action_key=?', (self.key,)))
        self.calls = []

    def transport(self, **overrides):
        facts = {'pull_active': False, 'process_view_complete': True, 'image_available': False,
                 'image_inspected': True, **overrides}
        async def execute(asset, command, timeout, *, channel):
            self.calls.append((asset, command, channel))
            return NTResult(True, json.dumps(facts), returncode=0, account='root', account_group='default')
        return SimpleNamespace(exec_shell=execute)

    async def test_legacy_audit_recovery_is_bound_to_both_fingerprints(self):
        operation = recover_host_operation(self.db, self.row)
        self.assertEqual(operation['arguments']['command'], self.command)
        self.assertEqual(recover_host_operation(self.db, {**self.row, 'params_hash': 'wrong'}), {})
        self.assertEqual(recover_host_operation(self.db, {**self.row, 'action_key': 'wrong'}), {})
        self.assertEqual(recover_host_operation(self.db, {**self.row, 'session_id': 'other'}), {})

    async def test_completed_process_allows_retry_without_claiming_success(self):
        result = await observe_host_write(self.db, self.transport(), self.row, {})
        self.assertEqual(result['outcome'], 'retry_safe')
        self.assertFalse(result['evidence']['image_available'])
        self.assertEqual(self.calls[0][2], 'read')
        self.assertNotIn('docker pull ', self.calls[0][1])
        unchanged = self.db.query_one('SELECT status,result FROM session_write_ops WHERE action_key=?', (self.key,))
        self.assertEqual(unchanged['status'], 'unknown')
        self.assertEqual(unchanged['result'], 'unknown:timeout')

    async def test_existing_mutable_tag_is_not_proof_of_pull_success(self):
        result = await observe_host_write(self.db, self.transport(image_available=True), self.row, {})
        self.assertEqual(result['outcome'], 'retry_safe')

    async def test_running_or_incomplete_observation_keeps_protection(self):
        for overrides in ({'pull_active': True}, {'process_view_complete': False},
                          {'image_inspected': False}, {'pull_active': 'false'}):
            with self.subTest(overrides=overrides):
                result = await observe_host_write(self.db, self.transport(**overrides), self.row, {})
                self.assertEqual(result['status'], 'pending')
                self.assertNotIn('outcome', result)

    async def test_group_change_never_uses_new_account_to_settle_old_write(self):
        self.db.execute('UPDATE duty_sessions SET ssh_account_group=? WHERE id=?', ('other', self.sid))
        result = await observe_host_write(self.db, self.transport(), self.row, {})
        self.assertEqual(result['status'], 'blocked')
        self.assertFalse(self.calls)

    async def test_app_background_hook_uses_shell_transport_and_preserves_unknown_fact(self):
        from ayana.main import App
        app = SimpleNamespace(db=self.db, session_bridge=self.bridge,
                              ssh_transport=self.transport(), transport=object())
        self.assertEqual(await App._reconcile_write_results_once(app), 1)
        row = self.db.query_one('SELECT * FROM session_write_ops WHERE action_key=?', (self.key,))
        self.assertEqual(row['status'], 'released')
        self.assertEqual(row['adjudication'], 'auto_retry_safe')
        self.assertEqual(row['result'], 'unknown:timeout')
        self.assertEqual(len(self.calls), 1)

    async def test_rebound_host_does_not_settle_an_old_hosts_write(self):
        self.db.execute("UPDATE ssh_endpoints SET host='10.0.0.2',updated_at=? WHERE id='endpoint'",
                        (self.row['created_at'] + 1,))
        result = await observe_host_write(self.db, self.transport(), self.row, {})
        self.assertEqual(result['status'], 'blocked')
        self.assertFalse(self.calls)

    async def test_endpoint_change_during_observation_keeps_protection(self):
        original = self.transport().exec_shell
        async def execute(*args, **kwargs):
            result = await original(*args, **kwargs)
            self.db.execute("UPDATE ssh_endpoints SET host='10.0.0.2' WHERE id='endpoint'")
            return result
        result = await observe_host_write(self.db, SimpleNamespace(exec_shell=execute), self.row, {})
        self.assertEqual(result['status'], 'blocked')

    async def test_general_commands_remain_protected(self):
        result = await observe_host_write(self.db, self.transport(), self.row,
            {'tool': 'host.exec', 'arguments': {'command': 'rm -rf /', 'asset_id': 'kanata'}})
        # The matching legacy audit remains authoritative over unrelated input.
        self.assertEqual(result['outcome'], 'retry_safe')
        row = {**self.row, 'action_key': 'unrelated'}
        result = await observe_host_write(self.db, self.transport(), row, {})
        self.assertEqual(result['status'], 'unsupported')


class StrictPullSyntaxTests(unittest.TestCase):
    def test_only_one_plain_pull_without_options_is_supported(self):
        self.assertEqual(pull_image('docker pull repo/image:tag'), 'repo/image:tag')
        for command in ('docker pull x; reboot', 'docker pull x && true', 'docker pull $(id)',
                        'docker pull `id`', 'docker pull --all-tags x', 'docker pull x\nid',
                        'docker -H remote pull x', 'X=y docker pull x', 'sudo docker pull x'):
            with self.subTest(command=command):
                self.assertEqual(pull_image(command), '')
