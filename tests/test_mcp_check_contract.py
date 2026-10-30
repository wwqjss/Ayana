"""Native monitoring tools use the real payload and preserve write uncertainty."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ayana.checks import CheckError, CheckService
from ayana.db import Database, now
from ayana.duty_session import DutySessionManager
from ayana.mcp_tools import McpToolError, OpsContext, OpsTools
from ayana.mcp_server import McpStdioServer, TURN_LIFECYCLE_CAPABILITY
from ayana.msgentry import classify_shell_command
from ayana.ops_constraints import OpsConstraints
from ayana.session_bridge import SessionBridge


class NativeCheckToolContractTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / 'monitor.db')
        self.addCleanup(self.db.close)
        stamp = now()
        self.db.execute("INSERT INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES('host','Host','host','host',?,?)", (stamp, stamp))
        duty = DutySessionManager(self.db)
        self.sid = duty.create(origin='manual')['session_id']
        self.db.execute("UPDATE duty_sessions SET remote_session_id='ses_native' WHERE id=?", (self.sid,))
        duty.set_runtime_state(self.sid, 'idle')
        self.bridge = SessionBridge(self.db, duty=duty)
        self.checks = CheckService(self.db, None)
        self.tools = OpsTools(OpsContext(None, None, None, None, db=self.db,
            session_bridge=self.bridge, checks=self.checks, constraints=OpsConstraints(self.db), managed_context=True))
        self.meta = {'sessionId': 'ses_native', 'turnId': 'turn_native', 'actorId': 'ayana'}

    async def call(self, name, args):
        return await self.tools.call(name, args, invocation_context=self.meta)

    def payload(self, **fields):
        return {'asset_id': 'host', 'kind': 'command', 'name': 'HTTP health', 'params': {'argv': ['true']}, **fields}

    async def test_advertised_command_and_port_payloads_create_real_checks(self):
        command = await self.call('config.check_add', self.payload())
        port = await self.call('config.check_add', self.payload(kind='port', name='HTTPS', params={'port': 443, 'protocol': 'tcp'}))
        self.assertEqual(command['check']['params'], {'argv': ['true']})
        self.assertEqual(port['check']['params'], {'port': 443, 'protocol': 'tcp'})
        self.assertTrue(all(row['status'] == 'done' for row in self.db.query('SELECT status FROM session_write_ops')))

    async def test_validation_rejection_does_not_create_unknown_writes(self):
        invalid = [{'params': {'cmd': 'true'}}, {'params': {'argv': ['true']}, 'expect': {'mode': 'exit0'}},
                   {'kind': 'port', 'params': {'port': 443, 'proto': 'tcp'}},
                   {'interval_sec': 0}, {'fail_threshold': 11}, {'params': {'argv': ['hostname']}}]
        for fields in invalid:
            with self.subTest(fields=fields), self.assertRaises(McpToolError) as caught:
                await self.call('config.check_add', self.payload(**fields))
            self.assertTrue(caught.exception.dispatch_not_started)
            self.assertTrue(caught.exception.detail['issues'])
            self.assertIn('argv', caught.exception.detail['expected_params']['command'])
        self.assertEqual(self.db.query_one('SELECT count(*) FROM checks')[0], 0)
        self.assertEqual(self.db.query_one("SELECT count(*) FROM session_write_ops WHERE status='unknown'")[0], 0)
        self.assertEqual({r['status'] for r in self.db.query('SELECT status FROM session_write_ops')}, {'released'})
        result = await self.call('config.check_add', self.payload())
        self.assertTrue(result['ok'])

    async def test_mutation_then_audit_error_is_still_unknown(self):
        original = self.db.audit
        def audit(*args, **kwargs):
            if len(args) > 2 and args[2] == 'check_create':
                raise CheckError('audit_failed_after_insert', 'result cannot be confirmed')
            return original(*args, **kwargs)
        with patch.object(self.db, 'audit', side_effect=audit):
            with self.assertRaises(McpToolError) as caught:
                await self.call('config.check_add', self.payload())
        self.assertFalse(caught.exception.dispatch_not_started)
        self.assertEqual(self.db.query_one('SELECT count(*) FROM checks')[0], 1)
        operation = self.db.query_one('SELECT status,result FROM session_write_ops')
        self.assertEqual(operation['status'], 'unknown')
        self.assertIn('audit_failed_after_insert', operation['result'])
        duplicate = await self.call('config.check_add', self.payload())
        self.assertEqual(duplicate['error'], 'idempotent_block')

    async def test_missing_update_or_delete_is_known_not_executed(self):
        for tool in ('config.check_update', 'config.check_delete'):
            with self.subTest(tool=tool), self.assertRaises(McpToolError) as caught:
                await self.call(tool, {'id': 'does-not-exist', 'name': 'new'})
            self.assertTrue(caught.exception.dispatch_not_started)
        self.assertEqual(self.db.query_one("SELECT count(*) FROM session_write_ops WHERE status='unknown'")[0], 0)

    async def test_constraints_expose_native_monitor_contract_without_prometheus(self):
        response = await self.call('ops.constraints', {})
        self.assertFalse(response['native_checks']['requires_prometheus'])
        self.assertIn('curl', response['native_checks']['command_programs'])
        self.assertIn('argv', response['native_checks']['params']['command'])
        specs = {spec['name']: spec for spec in self.tools.specs()}
        properties = specs['config.check_add']['inputSchema']['properties']
        self.assertIn('argv', properties['params']['properties'])
        self.assertNotIn('cmd', properties['params']['properties'])
        self.assertEqual(properties['fail_threshold']['maximum'], 10)

    async def test_missing_prometheus_is_nonfatal_mcp_data_and_never_creates_write_records(self):
        response = await McpStdioServer(self.tools).handle({'jsonrpc':'2.0','id':5,'method':'tools/call','params':{
            'name':'metrics.query','arguments':{'query':'up'},'_meta':{TURN_LIFECYCLE_CAPABILITY:self.meta}}})
        self.assertFalse(response['result']['isError'])
        import json
        value = json.loads(response['result']['content'][0]['text'])
        self.assertFalse(value['ok'])
        self.assertFalse(value['available'])
        self.assertIsNone(value['result'])
        self.assertEqual(value['next_tool'], 'ayana_config_check_list')
        self.assertEqual(self.db.query_one('SELECT count(*) FROM session_write_ops')[0],0)


class DiagnosticClassifierTests(unittest.TestCase):
    def test_observed_hostname_lookup_and_service_listing_chain_is_readonly(self):
        command = ('hostname; getent hosts os.example.com || true; ss -lntp 2>/dev/null | head -30; '
                   'systemctl list-units --type=service --state=running --no-pager --no-legend | head -30')
        self.assertEqual(classify_shell_command(command), 'read')

    def test_nss_overrides_credentials_enumeration_and_mutations_are_not_read(self):
        for command in ('getent shadow', 'getent passwd root', 'getent -s malicious hosts example.com',
                        'getent hosts example.com; touch /tmp/changed',
                        'getent hosts example.com >/tmp/out', 'getent hosts $(id)',
                        'systemctl list-units --state=running; systemctl stop nginx'):
            with self.subTest(command=command):
                self.assertNotEqual(classify_shell_command(command), 'read')


if __name__ == '__main__':
    unittest.main()
