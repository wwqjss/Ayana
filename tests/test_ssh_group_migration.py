"""SSH account-group upgrades preserve connections and select one live group."""
import json
import tempfile
import time
import unittest
from pathlib import Path

from ayana.agent_authority import resolve_authority
from ayana.db import Database, SCHEMA_VERSION
from ayana.duty_session import DutySessionManager


class DatabaseFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.path = Path(self.tmp.name) / 'groups.db'
        self.db = Database(self.path)
        self.duty = DutySessionManager(self.db)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def group(self, name):
        self.db.execute("INSERT OR IGNORE INTO ssh_account_groups(name,label,created_at,updated_at) VALUES(?,?,?,?)",
                        (name, name, time.time(), time.time()))

    def upgrade_from(self, version):
        self.db.execute("UPDATE meta SET value=? WHERE key='schema_version'", (str(version),))
        self.db.execute('DELETE FROM schema_migrations WHERE version>?', (version,))
        self.db.close()
        self.db = Database(self.path)
        self.duty = DutySessionManager(self.db)


class LegacyEndpointMigrationTests(DatabaseFixture):
    def setUp(self):
        super().setUp()
        self.db.execute("INSERT INTO ssh_credentials(id,name,kind,secret_enc,created_at,updated_at)"
                        " VALUES('legacy-key','legacy','private_key',?,1,1)",
                        (b'SECRET-KEY-MATERIAL-MUST-NOT-ENTER-AUDIT',))

    def endpoint(self, ident, role, *, asset='host', host='10.0.0.1', port=22, username='root',
                 credential='', fingerprint='', key_line='', trusted_at=None, enabled=1):
        self.db.execute("INSERT OR IGNORE INTO assets(id,display_name,read_alias,write_alias,created_at,updated_at) VALUES(?,?,?,?,1,1)",
                        (asset, asset, asset+'-read', asset+'-write'))
        self.db.execute(
            "INSERT INTO ssh_endpoints(id,asset_id,role,host,port,username,credential_id,"
            "host_key_sha256,host_key_line,host_key_trusted_at,enabled,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,1,1)",
            (ident, asset, role, host, port, username, credential, fingerprint, key_line, trusted_at, enabled))

    def audits(self):
        return [json.loads(row[0]) for row in self.db.query(
            "SELECT detail_json FROM audit_log WHERE entry='ssh_account_groups_migrated'")]

    def test_default_placeholder_inherits_matching_credential_and_public_trust(self):
        self.endpoint('placeholder', 'default')
        self.endpoint('verified-write', 'write', credential='legacy-key', fingerprint='SHA256:key',
                      key_line='10.0.0.1 ssh-ed25519 AAAAPUBLIC', trusted_at=123)
        self.upgrade_from(30)
        current = dict(self.db.query_one("SELECT * FROM ssh_endpoints WHERE role='default'"))
        self.assertEqual(current['id'], 'placeholder')
        self.assertEqual(current['credential_id'], 'legacy-key')
        self.assertEqual((current['host_key_sha256'], current['host_key_line'], current['host_key_trusted_at']),
                         ('SHA256:key', '10.0.0.1 ssh-ed25519 AAAAPUBLIC', 123))
        self.assertEqual((current['host'], current['port'], current['username'], current['created_at']),
                         ('10.0.0.1', 22, 'root', 1))
        audit = self.audits()[0]
        self.assertEqual(audit['legacy_endpoints'][0]['id'], 'verified-write')
        self.assertEqual(audit['legacy_endpoints'][0]['credential_id'], 'legacy-key')
        rendered = json.dumps(audit)
        self.assertNotIn('SECRET-KEY-MATERIAL', rendered)
        self.assertNotIn('secret_enc', rendered)
        self.assertEqual(self.db.query_one('SELECT COUNT(*) FROM ssh_endpoints')[0], 1)
        self.assertEqual(self.db.schema_version(), SCHEMA_VERSION)

    def test_different_host_port_or_username_never_inherits(self):
        identities = [('other-host', {'host': '10.0.0.2'}), ('other-port', {'port': 2222}),
                      ('other-user', {'username': 'operator'})]
        for asset, changed in identities:
            self.endpoint(asset+'-default', 'default', asset=asset, **changed)
            self.endpoint(asset+'-old', 'write', asset=asset, credential='legacy-key',
                          fingerprint='SHA256:key', key_line='public', trusted_at=123)
        self.upgrade_from(30)
        for asset, changed in identities:
            current = self.db.query_one("SELECT * FROM ssh_endpoints WHERE asset_id=? AND role='default'", (asset,))
            self.assertEqual((current['credential_id'], current['host_key_sha256'], current['host_key_line']), ('', '', ''))
            self.assertIsNone(current['host_key_trusted_at'])
        self.assertEqual(len(self.audits()), 3)
        self.assertTrue(all(not audit['merged_fields'] for audit in self.audits()))

    def test_explicit_default_selection_and_disabled_state_are_preserved(self):
        self.endpoint('chosen', 'default', credential='explicit-key', fingerprint='SHA256:chosen',
                      key_line='chosen-public', trusted_at=456, enabled=0)
        self.endpoint('old', 'write', credential='legacy-key', fingerprint='SHA256:old',
                      key_line='old-public', trusted_at=123)
        before = dict(self.db.query_one("SELECT * FROM ssh_endpoints WHERE id='chosen'"))
        self.upgrade_from(30)
        after = dict(self.db.query_one("SELECT * FROM ssh_endpoints WHERE id='chosen'"))
        self.assertEqual(after, before)
        self.assertEqual(self.audits()[0]['legacy_endpoints'][0]['id'], 'old')

    def test_read_and_write_without_default_do_not_collide_or_create_ghost_groups(self):
        self.group('read'); self.group('write'); self.group('custom')
        self.endpoint('read-old', 'read', credential='read-key', fingerprint='SHA256:read',
                      key_line='read-public', trusted_at=123)
        self.endpoint('write-old', 'write', credential='legacy-key', fingerprint='SHA256:write',
                      key_line='write-public', trusted_at=456)
        self.upgrade_from(30)
        rows = self.db.query('SELECT * FROM ssh_endpoints')
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['id'], rows[0]['role'], rows[0]['credential_id']),
                         ('write-old', 'default', 'legacy-key'))
        self.assertEqual({row[0] for row in self.db.query('SELECT name FROM ssh_account_groups')}, {'default', 'custom'})
        self.assertEqual({row['id'] for row in self.audits()[0]['legacy_endpoints']}, {'read-old', 'write-old'})

    def test_conflicting_public_key_cannot_fill_missing_trust_metadata(self):
        self.endpoint('chosen', 'default', fingerprint='SHA256:chosen')
        self.endpoint('old', 'write', credential='legacy-key', fingerprint='SHA256:old',
                      key_line='old-public', trusted_at=123)
        self.upgrade_from(30)
        current = self.db.query_one("SELECT * FROM ssh_endpoints WHERE id='chosen'")
        self.assertEqual(current['credential_id'], 'legacy-key')
        self.assertEqual(current['host_key_sha256'], 'SHA256:chosen')
        self.assertEqual(current['host_key_line'], '')
        self.assertIsNone(current['host_key_trusted_at'])

    def test_empty_legacy_role_also_archives_without_default_collision(self):
        self.endpoint('chosen', 'default')
        self.endpoint('old-empty', '', credential='legacy-key')
        self.upgrade_from(30)
        self.assertEqual(self.db.query_one("SELECT credential_id FROM ssh_endpoints WHERE id='chosen'")[0], 'legacy-key')
        self.assertEqual(self.db.query_one('SELECT COUNT(*) FROM ssh_endpoints')[0], 1)


class SessionGroupMigrationTests(DatabaseFixture):
    def legacy_setting(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO agent_settings(key,value,updated_at,updated_by) VALUES(?,?,1,?)',
                        (key, value, 'legacy'))

    def prepare_v31(self):
        self.db.execute("ALTER TABLE duty_sessions DROP COLUMN ssh_account_group")
        self.db.execute("DELETE FROM agent_settings WHERE key='ssh_default_group'")

    def test_v32_uses_shared_legacy_group_and_new_sessions_inherit(self):
        self.group('ops')
        self.prepare_v31()
        self.legacy_setting('ssh_investigate_role', 'ops')
        self.legacy_setting('ssh_execute_role', 'ops')
        self.upgrade_from(31)
        sid = self.duty.create(origin='auto')['session_id']
        self.assertEqual(self.duty.settings()['ssh_default_group'], 'ops')
        self.assertEqual(self.duty.get(sid)['ssh_account_group'], '')
        authority = resolve_authority(self.db, sid)
        self.assertEqual((authority['ssh_account_group'], authority['ssh_account_group_source']), ('ops', 'global'))
        self.assertEqual(set(self.duty.settings()), {'archive_delay_sec', 'ssh_default_group'})

    def test_different_legacy_groups_choose_execution_and_record_reason(self):
        self.group('observer'); self.group('operator')
        self.prepare_v31()
        self.legacy_setting('ssh_investigate_role', 'observer')
        self.legacy_setting('ssh_execute_role', 'operator')
        self.upgrade_from(31)
        self.assertEqual(self.duty.settings()['ssh_default_group'], 'operator')
        audit = json.loads(self.db.query_one("SELECT detail_json FROM audit_log WHERE entry='ssh_default_group_migrated' ORDER BY id DESC LIMIT 1")[0])
        self.assertEqual(audit['selection_reason'], 'legacy_execution_group')
        self.assertEqual(audit['legacy_stage_selections']['ssh_investigate_role'], 'observer')

    def test_existing_new_default_and_session_selection_survive_migration_reentry(self):
        self.group('chosen'); self.group('session-choice')
        sid = self.duty.create()['session_id']
        self.legacy_setting('ssh_default_group', 'chosen')
        self.db.execute("UPDATE duty_sessions SET ssh_account_group='session-choice' WHERE id=?", (sid,))
        self.legacy_setting('ssh_execute_role', 'default')
        self.upgrade_from(31)
        self.assertEqual(self.duty.settings()['ssh_default_group'], 'chosen')
        self.assertEqual(resolve_authority(self.db, sid)['ssh_account_group'], 'session-choice')


class SessionAccountGroupTests(DatabaseFixture):
    def setUp(self):
        super().setUp()
        self.group('ops'); self.group('reader')
        self.sid = self.duty.create(origin='manual')['session_id']

    def test_global_changes_update_inherited_sessions_only_and_increment_revision(self):
        other = self.duty.create(origin='auto')['session_id']
        self.duty.set_session_account_group(other, 'reader', actor='admin')
        previous = resolve_authority(self.db, self.sid)['revision']
        self.duty.set_setting('ssh_default_group', 'ops', actor='admin')
        self.assertGreater(resolve_authority(self.db, self.sid)['revision'], previous)
        self.assertEqual(resolve_authority(self.db, self.sid)['ssh_account_group'], 'ops')
        self.assertEqual(resolve_authority(self.db, other)['ssh_account_group'], 'reader')

    def test_session_selection_is_persistent_audited_and_can_return_to_inheritance(self):
        previous = resolve_authority(self.db, self.sid)['revision']
        result = self.duty.set_session_account_group(self.sid, 'reader', actor='admin')
        self.assertEqual((result['ssh_account_group'], result['ssh_account_group_source']), ('reader', 'session'))
        self.assertGreater(result['effective_permissions']['revision'], previous)
        self.assertFalse(self.duty.set_session_account_group(self.sid, 'reader', actor='admin')['changed'])
        self.db.close(); self.db = Database(self.path); self.duty = DutySessionManager(self.db)
        self.assertEqual(resolve_authority(self.db, self.sid)['ssh_account_group'], 'reader')
        self.assertTrue(self.db.query_one("SELECT 1 FROM audit_log WHERE entry='agent_session_account_group_changed'"))
        self.duty.set_setting('ssh_default_group', 'ops')
        result = self.duty.set_session_account_group(self.sid, '', actor='admin')
        self.assertEqual((result['ssh_account_group'], result['ssh_account_group_source']), ('ops', 'global'))

    def test_invalid_selection_never_mutates_session_or_other_settings(self):
        for group in (None, [], 'missing'):
            with self.subTest(group=group), self.assertRaises(ValueError):
                self.duty.set_session_account_group(self.sid, group, actor='admin')
        before = dict(self.duty.settings())
        with self.assertRaises(ValueError):
            self.duty.set_settings({'archive_delay_sec': '123', 'ssh_default_group': 'missing'})
        self.assertEqual(self.duty.settings(), before)
        self.assertEqual(self.duty.get(self.sid)['ssh_account_group'], '')

    def test_archived_deleted_or_deleting_sessions_reject_changes(self):
        for updates, error in (("status='archived'", 'session_not_open'),
                               ("status='open',deleted_at=1", 'session_deleted'),
                               ("deleted_at=0,delete_requested_at=1", 'session_deleting')):
            self.db.execute('UPDATE duty_sessions SET ' + updates + ' WHERE id=?', (self.sid,))
            with self.assertRaisesRegex(ValueError, error):
                self.duty.set_session_account_group(self.sid, 'ops')
        self.assertEqual(self.duty.get(self.sid)['ssh_account_group'], '')

    def test_paused_session_can_select_group_but_cannot_dispatch(self):
        self.duty.pause_session(self.sid, actor='admin')
        result = self.duty.set_session_account_group(self.sid, 'ops', actor='admin')
        self.assertEqual(result['ssh_account_group'], 'ops')
        self.assertEqual(result['effective_permissions']['lifecycle_block'], 'session_paused')
        self.assertFalse(result['effective_permissions']['write_allowed'])
