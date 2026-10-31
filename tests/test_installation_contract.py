"""Portable deployment fixtures: no real services, package installs or production I/O."""
from __future__ import annotations

import contextlib
from copy import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installation_contract', ROOT / 'deploy/installation.py')
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)
sys.path.insert(0, str(ROOT / 'scripts'))
from release_manifest import release_files
from build_release import build


class DeploymentFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        for path in release_files(ROOT):
            target = self.source / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        self.args = deployment.normalise(deployment.parser().parse_args([
            '--system', '--no-start', '--skip-pip', '--prefix', str(self.base / 'code'),
            '--data', str(self.base / 'data'), '--conf-dir', str(self.base / 'config'),
            '--backup-dir', str(self.base / 'backups'), '--unit-dir', str(self.base / 'units'),
            '--mimo-bin', '/usr/local/bin/mimo']))
        self.run = self.enterContext(patch.object(deployment, 'run', side_effect=AssertionError('unexpected real process')))
        self.enterContext(patch.object(deployment, 'environment_report', return_value=[]))
        self.enterContext(patch.object(deployment, 'install_dependencies'))
        self.native = self.enterContext(patch.object(deployment, 'native_status', return_value=False))
        self.enterContext(patch.object(deployment, 'web_is_online', return_value=False))

    def install(self):
        with contextlib.redirect_stdout(io.StringIO()):
            deployment.install(self.args, self.source)

    def make_db(self, value='before'):
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection, connection:
            connection.execute('CREATE TABLE IF NOT EXISTS facts(value TEXT)')
            connection.execute('DELETE FROM facts')
            connection.execute('INSERT INTO facts VALUES(?)', (value,))

    def test_install_configures_two_independent_units_and_shared_provider_path(self):
        self.install()
        config = deployment.read_json(self.args.conf_dir / 'config.json')
        self.assertTrue(config['mimo_serve_external'])
        self.assertEqual(config['mimo_config_dir'], str(self.args.data / '.config/mimocode'))
        self.assertEqual(config['db_path'], str(self.args.data / 'ayana.db'))
        for name in deployment.UNITS:
            unit = (self.args.unit_dir / name).read_text(encoding='utf-8')
            self.assertIn(str(self.args.prefix), unit)
            self.assertIn(str(self.args.data), unit)
            self.assertNotIn('PartOf=', unit)
            self.assertNotIn('BindsTo=', unit)
        self.assertIn('-m ayana.agent_runtime', (self.args.unit_dir / deployment.UNITS[1]).read_text())
        self.run.assert_not_called()

    def test_repeat_upgrade_preserves_config_secrets_database_and_knowledge(self):
        self.install()
        self.make_db()
        config = self.args.conf_dir / 'config.json'
        original = config.read_bytes().replace(b'6200', b'7312')
        config.write_bytes(original)
        secret = (self.args.conf_dir / 'secrets.json').read_bytes()
        knowledge = self.args.data / 'knowledge/user-owned.md'
        knowledge.write_text('private notes')
        (self.args.prefix / 'ayana/obsolete_removed_module.py').write_text('retired = True')
        (self.args.prefix / 'unmanaged-user-file.txt').write_text('keep')
        self.install()
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual((self.args.conf_dir / 'secrets.json').read_bytes(), secret)
        self.assertEqual(knowledge.read_text(), 'private notes')
        self.assertFalse((self.args.prefix / 'ayana/obsolete_removed_module.py').exists())
        self.assertEqual((self.args.prefix / 'unmanaged-user-file.txt').read_text(), 'keep')
        self.assertTrue((self.args.backup_dir / 'LAST').is_file())
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection, connection:
            self.assertEqual(connection.execute('SELECT value FROM facts').fetchone()[0], 'before')
        self.run.assert_not_called()

    def test_lite_install_has_two_services_without_mimo_or_terminal_configuration(self):
        self.args.agent_mode = 'lite'
        self.args.mimo_bin = None
        self.install()
        config = deployment.read_json(self.args.conf_dir / 'config.json')
        self.assertEqual(config['agent_mode'], 'lite')
        self.assertFalse(config['agent_tui_enabled'])
        self.assertNotIn('mimo_bin', config)
        self.assertNotIn('mimo_config_dir', config)
        for name in deployment.UNITS:
            self.assertTrue((self.args.unit_dir / name).is_file())
        before = (self.args.conf_dir / 'config.json').read_bytes()
        secrets = (self.args.conf_dir / 'secrets.json').read_bytes()
        self.args.agent_mode = None
        self.install()
        self.assertEqual((self.args.conf_dir / 'config.json').read_bytes(), before)
        self.assertEqual((self.args.conf_dir / 'secrets.json').read_bytes(), secrets)
        self.assertEqual(deployment.selected_agent_mode(self.args), 'lite')

    def test_explicit_mode_switch_preserves_configuration_and_has_a_paired_backup(self):
        self.install()
        config = deployment.read_json(self.args.conf_dir / 'config.json')
        config['custom_setting'] = {'preserve': 'user value'}
        path = self.args.conf_dir / 'config.json'
        path.write_text(json.dumps(config))
        original = path.read_bytes()
        secrets = (self.args.conf_dir / 'secrets.json').read_bytes()
        self.args.agent_mode = 'lite'
        self.install()
        current = deployment.read_json(path)
        self.assertEqual(current['agent_mode'], 'lite')
        self.assertFalse(current['agent_tui_enabled'])
        self.assertEqual(current['custom_setting'], config['custom_setting'])
        self.assertEqual(current['mimo_bin'], config['mimo_bin'])
        self.assertEqual((self.args.conf_dir / 'secrets.json').read_bytes(), secrets)
        backup = Path((self.args.backup_dir / 'LAST').read_text())
        self.assertEqual((backup / 'config/config.json').read_bytes(), original)
        self.args.agent_mode = 'mimo'
        self.install()
        self.assertTrue(deployment.read_json(path)['agent_tui_enabled'])

    def test_mode_switch_does_not_bypass_unknown_writes(self):
        self.install()
        self.make_db()
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection, connection:
            connection.execute('CREATE TABLE session_write_ops(status TEXT)')
            connection.execute("INSERT INTO session_write_ops VALUES('unknown')")
        config = (self.args.conf_dir / 'config.json').read_bytes()
        self.args.agent_mode = 'lite'
        with self.assertRaisesRegex(deployment.InstallError, 'pending work'):
            self.install()
        self.assertEqual((self.args.conf_dir / 'config.json').read_bytes(), config)
        self.run.assert_not_called()

    def test_failed_mode_switch_restores_the_previous_mode_and_secrets(self):
        self.install()
        config = (self.args.conf_dir / 'config.json').read_bytes()
        secrets = (self.args.conf_dir / 'secrets.json').read_bytes()
        self.args.agent_mode = 'lite'
        with patch.object(deployment, 'install_dependencies', side_effect=deployment.InstallError('simulated dependency failure')):
            with self.assertRaisesRegex(deployment.InstallError, 'simulated dependency failure'):
                self.install()
        self.assertEqual((self.args.conf_dir / 'config.json').read_bytes(), config)
        self.assertEqual((self.args.conf_dir / 'secrets.json').read_bytes(), secrets)
        self.assertEqual(deployment.read_json(self.args.conf_dir / 'config.json')['agent_mode'], 'mimo')

    def test_backup_records_configuration_and_external_provider_ownership(self):
        self.install()
        self.make_db()
        config_path = self.args.conf_dir / 'config.json'
        config = deployment.read_json(config_path)
        config['mimo_config_dir'] = str(self.base / 'external-provider')
        config_path.write_text(json.dumps(config))
        provider = self.base / 'external-provider/mimocode.json'
        provider.parent.mkdir()
        provider.write_text('{"key":"private"}')
        snapshot = deployment.backup(self.args)
        metadata = deployment.read_json(snapshot / 'backup.json')
        self.assertEqual(metadata['database_permissions'], deployment.permission_record(self.args.data / 'ayana.db'))
        recorded = next(item for item in metadata['provider_files'] if item['path'] == str(provider))
        self.assertEqual(recorded['permissions'], deployment.permission_record(provider))
        self.assertEqual(recorded['parent_permissions'], deployment.permission_record(provider.parent))
        recorded_config = next(item for item in metadata['config_permissions'] if item['relative'] == 'config.json')
        self.assertEqual({key: recorded_config[key] for key in ('uid', 'gid', 'mode')},
                         deployment.permission_record(config_path))
        self.assertTrue(any(item['relative'] == '.' for item in metadata['config_permissions']))

    def test_managed_restore_repairs_service_access_then_restores_exact_external_secret_permissions(self):
        self.install()
        config_path = self.args.conf_dir / 'config.json'
        config = deployment.read_json(config_path)
        config['mimo_config_dir'] = str(self.base / 'external-provider')
        config_path.write_text(json.dumps(config))
        provider = self.base / 'external-provider/mimocode.json'
        provider.parent.mkdir()
        provider.write_text('{"key":"original"}')
        snapshot = deployment.backup(self.args)
        metadata = deployment.read_json(snapshot / 'backup.json')
        for item in metadata['provider_files']:
            if item['path'] == str(provider):
                item['permissions'] = {'uid': 2345, 'gid': 3456, 'mode': 0o600}
                item['parent_permissions'] = {'uid': 2345, 'gid': 3456, 'mode': 0o700}
        (snapshot / 'backup.json').write_text(json.dumps(metadata))
        provider.write_text('{"key":"new"}')
        self.args.no_start = False
        events = []
        with patch.object(deployment, 'set_permissions', side_effect=lambda args: events.append('repair')) as repair:
            with patch.object(deployment.os, 'chown', side_effect=lambda *args: events.append(args), create=True):
                deployment.restore(self.args, snapshot)
        repair.assert_called_once_with(self.args)
        self.assertEqual(events[0], 'repair')
        self.assertIn((provider, 2345, 3456), events)
        self.assertIn((provider.parent, 2345, 3456), events)
        self.assertEqual(provider.read_text(), '{"key":"original"}')
        self.assertEqual(deployment.stat.S_IMODE(provider.stat().st_mode) & 0o600, 0o600)

    def test_failed_managed_mode_switch_repairs_restored_access_before_restarting_services(self):
        self.install()
        self.args.no_start = False
        self.args.agent_mode = 'lite'
        events = []
        self.run.side_effect = lambda *args: events.append(args)
        with patch.object(deployment, 'ensure_quiescent', return_value=True):
            with patch.object(deployment, 'set_permissions', side_effect=lambda args: events.append(('restore_permissions',))):
                with patch.object(deployment.os, 'chown', create=True):
                    with patch.object(deployment, 'install_dependencies', side_effect=deployment.InstallError('simulated failure')):
                        with self.assertRaisesRegex(deployment.InstallError, 'simulated failure'):
                            self.install()
        repair = events.index(('restore_permissions',))
        restart = next(index for index, event in enumerate(events) if event[:2] == ('systemctl', 'start'))
        self.assertLess(repair, restart)
        self.assertEqual(deployment.read_json(self.args.conf_dir / 'config.json')['agent_mode'], 'mimo')

    def test_backup_and_restore_pair_code_database_config_and_provider(self):
        self.install()
        self.make_db()
        provider = self.args.data / '.config/mimocode/mimocode.jsonc'
        provider.parent.mkdir(parents=True)
        provider.write_text('{"provider":"old-private-key"}')
        snapshot = deployment.backup(self.args)
        config_bytes = (self.args.conf_dir / 'config.json').read_bytes()
        (self.args.prefix / 'ayana/__init__.py').write_text('new version')
        (self.args.prefix / 'ayana/not_in_snapshot.py').write_text('remove me')
        (self.args.conf_dir / 'config.json').write_text('{"new":true}')
        provider.write_text('new provider')
        self.make_db('after')
        deployment.restore(self.args, snapshot)
        self.assertNotEqual((self.args.prefix / 'ayana/__init__.py').read_text(encoding='utf-8'), 'new version')
        self.assertFalse((self.args.prefix / 'ayana/not_in_snapshot.py').exists())
        self.assertEqual((self.args.conf_dir / 'config.json').read_bytes(), config_bytes)
        self.assertEqual(provider.read_text(), '{"provider":"old-private-key"}')
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection, connection:
            self.assertEqual(connection.execute('SELECT value FROM facts').fetchone()[0], 'before')

    def test_update_checks_database_unknown_before_touching_code(self):
        self.install()
        self.make_db()
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection, connection:
            connection.execute('CREATE TABLE session_write_ops(status TEXT)')
            connection.execute("INSERT INTO session_write_ops VALUES('unknown')")
        before = (self.args.prefix / 'ayana/main.py').read_bytes()
        with self.assertRaisesRegex(deployment.InstallError, 'pending work'):
            self.install()
        self.assertEqual((self.args.prefix / 'ayana/main.py').read_bytes(), before)
        self.run.assert_not_called()

    def test_active_takeover_blocks_without_clearing_the_lease(self):
        self.install()
        self.make_db()
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection, connection:
            connection.execute('CREATE TABLE agent_runtime_bindings(controller_connection_id TEXT,control_expires_at REAL)')
            connection.execute("INSERT INTO agent_runtime_bindings VALUES('owner',9999999999)")
        with self.assertRaisesRegex(deployment.InstallError, 'release control'):
            self.install()
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection, connection:
            self.assertEqual(connection.execute('SELECT * FROM agent_runtime_bindings').fetchone(), ('owner', 9999999999))
            connection.execute('UPDATE agent_runtime_bindings SET control_expires_at=1')
        deployment.ensure_quiescent(self.args)
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection:
            self.assertEqual(connection.execute('SELECT * FROM agent_runtime_bindings').fetchone(), ('owner', 1))
        self.run.assert_not_called()

    def test_external_busy_native_runtime_blocks_even_when_database_has_no_work(self):
        self.install()
        self.native.side_effect = deployment.InstallError('native runtime is busy')
        with self.assertRaisesRegex(deployment.InstallError, 'busy'):
            self.install()
        self.assertFalse(self.args.backup_dir.exists())
        self.run.assert_not_called()

    def test_unmanaged_upgrade_requires_web_offline_even_if_native_unconfigured(self):
        self.install()
        self.args.system = False
        self.args.no_start = False
        with patch.object(deployment, 'web_is_online', return_value=True):
            with self.assertRaisesRegex(deployment.InstallError, 'offline Web'):
                self.install()
        self.run.assert_not_called()

    def test_new_native_task_after_web_stop_restores_web_without_stopping_runtime(self):
        self.install()
        self.args.no_start = False
        self.run.side_effect = None
        with patch.object(deployment, 'ensure_quiescent', side_effect=[True, deployment.InstallError('new task')]):
            with self.assertRaisesRegex(deployment.InstallError, 'new task'):
                self.install()
        self.assertEqual(self.run.call_args_list, [
            unittest.mock.call('systemctl', 'stop', 'ayana.service'),
            unittest.mock.call('systemctl', 'start', 'ayana.service'),
        ])

    def test_first_install_partial_start_failure_stops_both_units_without_success(self):
        self.args.no_start = False
        def run_command(*argv):
            if argv[:2] == ('systemctl', 'start'):
                raise subprocess.CalledProcessError(1, argv)
        self.run.side_effect = run_command
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(deployment, 'set_permissions'):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                with self.assertRaises(subprocess.CalledProcessError):
                    deployment.install(self.args, self.source)
        self.assertIn(unittest.mock.call('systemctl', 'stop', *deployment.UNITS), self.run.call_args_list)
        self.assertNotIn('健康检查通过', output.getvalue())
        self.assertIn('journalctl', errors.getvalue())

    def test_prepared_install_does_not_claim_services_are_running(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            deployment.install(self.args, self.source)
        self.assertIn('have not been started', output.getvalue())
        self.assertNotIn('= active', output.getvalue())

    def test_rollback_makes_rescue_backup_before_restoring_old_database(self):
        self.install()
        self.make_db('old')
        snapshot = deployment.backup(self.args)
        self.make_db('new')
        arguments = ['rollback', '--system', '--no-start', '--prefix', str(self.args.prefix),
                     '--data', str(self.args.data), '--conf-dir', str(self.args.conf_dir),
                     '--backup-dir', str(self.args.backup_dir), '--unit-dir', str(self.args.unit_dir),
                     '--backup', str(snapshot)]
        with contextlib.redirect_stdout(io.StringIO()):
            deployment.main(arguments)
        rescue = Path((self.args.backup_dir / 'LAST').read_text())
        self.assertNotEqual(rescue, snapshot)
        with contextlib.closing(sqlite3.connect(rescue / 'ayana.db')) as connection:
            self.assertEqual(connection.execute('SELECT value FROM facts').fetchone()[0], 'new')
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection:
            self.assertEqual(connection.execute('SELECT value FROM facts').fetchone()[0], 'old')
        self.run.assert_not_called()

    def test_rollback_to_single_unit_snapshot_starts_only_the_original_unit(self):
        self.install()
        (self.args.unit_dir / 'ayana-agent-runtime.service').unlink()
        snapshot = deployment.backup(self.args)
        for name, text in deployment.render_units(self.args, self.source).items():
            (self.args.unit_dir / name).write_text(text)
        arguments = ['rollback', '--system', '--prefix', str(self.args.prefix),
                     '--data', str(self.args.data), '--conf-dir', str(self.args.conf_dir),
                     '--backup-dir', str(self.args.backup_dir), '--unit-dir', str(self.args.unit_dir),
                     '--backup', str(snapshot)]
        self.run.side_effect = None
        with patch.object(deployment, 'set_permissions'), patch.object(deployment, 'wait_health') as health:
            with contextlib.redirect_stdout(io.StringIO()):
                deployment.main(arguments)
        starts = [call.args for call in self.run.call_args_list if call.args[:2] == ('systemctl', 'start')]
        self.assertEqual(starts, [('systemctl', 'start', 'ayana.service')])
        self.assertEqual(health.call_args.args[1], ['ayana.service'])
        self.assertFalse((self.args.unit_dir / 'ayana-agent-runtime.service').exists())

    def test_external_runtime_data_paths_require_a_complete_manual_snapshot(self):
        self.install()
        config = deployment.read_json(self.args.conf_dir / 'config.json')
        config['knowledge_dir'] = str(self.base / 'outside-knowledge')
        (self.args.conf_dir / 'config.json').write_text(json.dumps(config))
        with self.assertRaisesRegex(deployment.InstallError, 'outside --data'):
            deployment.backup(self.args)
        self.assertFalse(self.args.backup_dir.exists())

    def test_failed_code_upgrade_restores_previous_database_and_config(self):
        self.install()
        self.make_db()
        before = (self.args.prefix / 'ayana/main.py').read_bytes()
        def failed_replace(*_):
            (self.args.prefix / 'ayana/main.py').write_text('broken')
            self.make_db('mutated')
            raise deployment.InstallError('simulated copy failure')
        with patch.object(deployment, 'replace_code', side_effect=failed_replace):
            with self.assertRaisesRegex(deployment.InstallError, 'simulated'):
                self.install()
        self.assertEqual((self.args.prefix / 'ayana/main.py').read_bytes(), before)
        with contextlib.closing(sqlite3.connect(self.args.data / 'ayana.db')) as connection, connection:
            self.assertEqual(connection.execute('SELECT value FROM facts').fetchone()[0], 'before')

    def test_check_has_no_writes_network_or_subprocess_actions(self):
        arguments = ['--check', '--system', '--no-start', '--prefix', str(self.args.prefix),
                     '--data', str(self.args.data), '--conf-dir', str(self.args.conf_dir),
                     '--backup-dir', str(self.args.backup_dir), '--unit-dir', str(self.args.unit_dir)]
        before = set(self.base.rglob('*'))
        with patch.object(deployment, 'native_status', side_effect=AssertionError('network')):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(deployment.main(arguments), 0)
        self.assertEqual(set(self.base.rglob('*')), before)
        self.run.assert_not_called()

    def test_all_managed_directories_must_be_disjoint(self):
        for field, value in (('backup_dir', self.args.conf_dir / 'backups'),
                             ('conf_dir', self.base), ('data', self.base), ('data', self.args.prefix)):
            with self.subTest(field=field, value=value):
                candidate = copy(self.args)
                setattr(candidate, field, value)
                with self.assertRaises(deployment.InstallError):
                    deployment.validate_paths(candidate)

    def test_manifest_is_verified_before_managed_tree_replacement(self):
        self.install()
        deployment.write_json(self.source / 'RELEASE-MANIFEST.json', {'files': {'ayana/main.py': 'wrong'}})
        before = (self.args.prefix / 'ayana/main.py').read_bytes()
        with self.assertRaisesRegex(deployment.InstallError, 'manifest'):
            deployment.replace_code(self.source, self.args.prefix)
        self.assertEqual((self.args.prefix / 'ayana/main.py').read_bytes(), before)

    def test_release_is_whitelisted_and_contains_nested_terminal_assets(self):
        for relative in ('secrets.json', '.test-tmp/private.json', 'deploy/internal-report.md',
                         'docs/OLD-DELIVERY.md', 'ayana/private.db', 'ayana/static/secrets.json'):
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('private')
        output = self.base / 'output'
        result = build(self.source, output)
        with tarfile.open(result['archive']) as archive:
            names = set(archive.getnames())
            manifest = json.load(archive.extractfile('RELEASE-MANIFEST.json'))
        self.assertIn('ayana/static/xterm/xterm.js', names)
        self.assertIn('ayana/static/xterm/xterm.css', names)
        self.assertIn('docs/INSTALL.md', names)
        self.assertNotIn('secrets.json', names)
        self.assertNotIn('ayana/static/secrets.json', names)
        self.assertNotIn('docs/OLD-DELIVERY.md', names)
        self.assertFalse(any(name.startswith('.test-tmp/') for name in names))
        self.assertEqual(set(manifest['files']), names - {'RELEASE-MANIFEST.json'})
        self.assertEqual(Path(result['archive']).read_bytes(), Path(result['stable_archive']).read_bytes())
        self.assertTrue(Path(result['archive'] + '.sha256').exists())

    def test_release_refuses_missing_nested_assets_or_public_guide(self):
        for relative in ('ayana/static/xterm/xterm.js', 'docs/INSTALL.md'):
            path = self.source / relative
            before = path.read_bytes()
            path.unlink()
            with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, 'incomplete release'):
                build(self.source, self.base / 'bad-output')
            path.write_bytes(before)

    def test_wheel_contains_nested_terminal_resources(self):
        python = os.environ.get('AYANA_BUILD_PYTHON') or sys.executable
        if python == sys.executable and importlib.util.find_spec('setuptools') is None:
            self.skipTest('set AYANA_BUILD_PYTHON to an environment with setuptools and wheel')
        result = subprocess.run([python, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
                                 str(self.source), '--wheel-dir', str(self.base / 'wheels')],
                                capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        import zipfile
        wheel = next((self.base / 'wheels').glob('*.whl'))
        with zipfile.ZipFile(wheel) as archive:
            self.assertIn('ayana/static/xterm/xterm.js', archive.namelist())
            self.assertIn('ayana/static/xterm/xterm-addon-fit.js', archive.namelist())



class WebStartupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.args = deployment.normalise(deployment.parser().parse_args([
            '--system', '--prefix', str(base / 'code'), '--data', str(base / 'data'),
            '--conf-dir', str(base / 'config'), '--unit-dir', str(base / 'units')]))
        self.args.prefix.mkdir()
        (self.args.prefix / 'pyproject.toml').write_text('[project]\nversion = "0.8.2"\n')

    def response(self, value):
        response = io.BytesIO(json.dumps(value).encode())
        response.status = 200
        return response

    def test_other_service_or_old_version_on_the_port_cannot_pass_startup(self):
        for value in ({'ok': True}, {'ok': True, 'service': 'other', 'version': '0.8.2'},
                      {'ok': True, 'service': 'ayana', 'version': '0.8.1'}, []):
            with self.subTest(value=value):
                with patch.object(deployment, 'urlopen', return_value=self.response(value)):
                    with self.assertRaisesRegex(deployment.InstallError, 'did not confirm'):
                        deployment.health(self.args)

    def test_correct_web_version_still_requires_both_services_active(self):
        value = {'ok': True, 'service': 'ayana', 'version': '0.8.2'}
        with patch.object(deployment, 'urlopen', return_value=self.response(value)):
            with patch.object(deployment, 'run') as run:
                self.assertEqual(deployment.health(self.args), value)
        self.assertEqual(run.call_args_list, [
            unittest.mock.call('systemctl', 'is-active', '--quiet', name) for name in deployment.UNITS])

    def test_lite_health_requires_the_selected_mode_and_a_live_worker(self):
        self.args.conf_dir.mkdir()
        (self.args.conf_dir / 'config.json').write_text(json.dumps({'agent_mode': 'lite'}))
        value = {'ok': True, 'service': 'ayana', 'version': '0.8.2', 'agent_mode': 'mimo'}
        with patch.object(deployment, 'urlopen', return_value=self.response(value)):
            with self.assertRaisesRegex(deployment.InstallError, 'did not confirm'):
                deployment.health(self.args)
        value['agent_mode'] = 'lite'
        for ready in (False, True):
            with self.subTest(ready=ready), patch.object(deployment, 'urlopen', return_value=self.response(value)):
                with patch.object(deployment, 'run'), patch.object(deployment, 'native_status', return_value=ready):
                    if ready:
                        self.assertEqual(deployment.health(self.args), value)
                    else:
                        with self.assertRaisesRegex(deployment.InstallError, 'not confirmed startup'):
                            deployment.health(self.args)

    def test_specific_host_and_ipv6_health_use_the_configured_listener(self):
        self.args.conf_dir.mkdir()
        for host, expected in [('192.0.2.10', '192.0.2.10'), ('::', '[::1]'),
                               ('::1', '[::1]'), ('0.0.0.0', '127.0.0.1')]:
            with self.subTest(host=host):
                (self.args.conf_dir / 'config.json').write_text(json.dumps({'http_host': host, 'http_port': 7012}))
                with patch.object(deployment, 'urlopen', return_value=self.response(
                        {'ok': True, 'service': 'ayana', 'version': '0.8.2'})) as open_url:
                    with patch.object(deployment, 'run'):
                        deployment.health(self.args)
                open_url.assert_called_once_with(f'http://{expected}:7012/health', timeout=5)

    def test_slow_start_can_pass_after_the_previous_ten_second_limit(self):
        with patch.object(deployment, 'health', side_effect=[URLError('starting')] * 12 + [{'ok': True}]):
            with patch.object(deployment.time, 'sleep') as sleep:
                self.assertEqual(deployment.wait_health(self.args), {'ok': True})
        self.assertEqual(sleep.call_count, 12)

    def test_first_health_request_timeout_is_retried(self):
        with patch.object(deployment, 'health', side_effect=[TimeoutError(), {'ok': True}]):
            with patch.object(deployment.time, 'sleep') as sleep:
                self.assertEqual(deployment.wait_health(self.args), {'ok': True})
        sleep.assert_called_once_with(1)

    def test_access_summary_uses_actual_database_directory_and_hides_token(self):
        self.args.conf_dir.mkdir()
        custom = self.args.data / 'database'
        custom.mkdir(parents=True)
        token = custom / 'setup-admin.token'
        token.write_text('must-not-appear-in-install-logs')
        (self.args.conf_dir / 'config.json').write_text(json.dumps({'db_path': str(custom / 'ayana.db')}))
        output = io.StringIO()
        with patch.dict(os.environ, {'SSH_CONNECTION': '192.0.2.1 1234 192.0.2.2 22', 'USER': 'root'}, clear=True):
            with contextlib.redirect_stdout(output):
                deployment.report_installation(self.args, running=True)
        self.assertIn('root@192.0.2.2', output.getvalue())
        self.assertIn(str(token), output.getvalue())
        self.assertNotIn('must-not-appear-in-install-logs', output.getvalue())
        self.assertIn('API Key', output.getvalue())
        self.assertNotIn('sudo cat', output.getvalue())

    def test_sudo_access_summary_preserves_the_ssh_port_and_admin_commands(self):
        output = io.StringIO()
        with patch.dict(os.environ, {'SUDO_USER': 'operator', 'SSH_CONNECTION': '192.0.2.1 1234 192.0.2.2 2222'}, clear=True):
            with contextlib.redirect_stdout(output):
                deployment.report_installation(self.args, running=True)
        self.assertIn('ssh -N -p 2222 -L 6200:127.0.0.1:6200 operator@192.0.2.2', output.getvalue())
        self.assertIn('sudo systemctl', output.getvalue())


class NativeObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.args = deployment.normalise(deployment.parser().parse_args([
            '--no-start', '--prefix', str(base/'code'), '--data', str(base/'data'),
            '--conf-dir', str(base/'config'), '--unit-dir', str(base/'units')]))

    def test_only_explicit_connection_refusal_without_attestation_counts_as_unconfigured(self):
        with patch.object(deployment, 'urlopen', side_effect=URLError(ConnectionRefusedError(111, 'refused'))):
            self.assertFalse(deployment.native_status(self.args))
        errors = [HTTPError('http://runtime', 401, 'denied', {}, None),
                  HTTPError('http://runtime', 500, 'broken', {}, None), URLError(TimeoutError())]
        for error in errors:
            with self.subTest(error=error), patch.object(deployment, 'urlopen', side_effect=error):
                with self.assertRaises(deployment.InstallError):
                    deployment.native_status(self.args)

    def test_previously_attested_runtime_cannot_be_declared_offline(self):
        state = self.args.data / 'agent-runtime/attestation.json'
        state.parent.mkdir(parents=True)
        state.write_text('{}')
        with patch.object(deployment, 'urlopen', side_effect=URLError(ConnectionRefusedError(111, 'refused'))):
            with self.assertRaisesRegex(deployment.InstallError, 'previously verified'):
                deployment.native_status(self.args)

    def test_valid_attestation_with_a_proven_dead_owner_allows_offline_upgrade(self):
        state = self.args.data / 'agent-runtime/attestation.json'
        state.parent.mkdir(parents=True)
        state.write_text(json.dumps({'owner_pid': 12345, 'owner_start': 'recorded-start'}))
        proc = self.args.data / 'fake-proc'
        proc.mkdir()
        with patch.object(deployment, 'PROC', proc), patch.object(deployment, 'urlopen', side_effect=URLError(ConnectionRefusedError(111, 'refused'))):
            self.assertFalse(deployment.native_status(self.args))
            (proc / '12345').mkdir()
            with self.assertRaises(deployment.InstallError):
                deployment.native_status(self.args)
        self.assertTrue(state.exists())

    def test_busy_or_invalid_native_responses_are_never_idle(self):
        for value in ({'rid': {'type': 'busy'}}, {'rid': {}}, []):
            with self.subTest(value=value):
                response = io.BytesIO(json.dumps(value).encode())
                with patch.object(deployment, 'urlopen', return_value=response):
                    with self.assertRaises(deployment.InstallError):
                        deployment.native_status(self.args)

    def test_dependency_install_uses_project_metadata(self):
        python = deployment.venv_python(self.args.prefix)
        python.parent.mkdir(parents=True)
        python.write_text('fixture')
        with patch.object(deployment, 'run') as run:
            deployment.install_dependencies(self.args)
        run.assert_called_once_with(str(python), '-m', 'pip', 'install', str(self.args.prefix))

    def test_explicit_mimo_binary_cannot_silently_disagree_with_existing_config(self):
        self.args.mimo_bin = str(self.args.data / 'new-mimo')
        self.args.conf_dir.mkdir()
        (self.args.conf_dir / 'config.json').write_text(json.dumps({'mimo_bin': str(self.args.data / 'old-mimo')}))
        with patch.object(deployment.shutil, 'which', return_value=None):
            missing = deployment.environment_report(self.args)
        self.assertTrue(any('conflicts with existing config' in item for item in missing))

    def test_lite_prerequisites_do_not_require_mimo_or_tmux(self):
        self.args.agent_mode = 'lite'
        self.args.mimo_bin = '/unavailable/mimo'
        with patch.object(deployment.shutil, 'which', side_effect=lambda name: '/tools/' + name if name in ('ssh', 'ssh-keyscan') else None):
            self.assertEqual(deployment.environment_report(self.args), [])
        self.args.agent_mode = 'mimo'
        with patch.object(deployment.shutil, 'which', return_value=None):
            missing = deployment.environment_report(self.args)
        self.assertIn('tmux', missing)
        self.assertTrue(any('MiMo CLI' in item for item in missing))

    def test_switch_to_lite_still_observes_the_installed_mimo_runtime(self):
        self.args.agent_mode = 'lite'
        self.args.conf_dir.mkdir()
        (self.args.conf_dir / 'config.json').write_text('{}')
        response = io.BytesIO(json.dumps({'session': {'type': 'busy'}}).encode())
        with patch.object(deployment, 'urlopen', return_value=response) as request:
            with self.assertRaisesRegex(deployment.InstallError, 'busy'):
                deployment.native_status(self.args)
        request.assert_called_once()

    def test_lite_runtime_observation_requires_matching_live_fresh_owner(self):
        self.args.conf_dir.mkdir()
        (self.args.conf_dir / 'config.json').write_text(json.dumps({'agent_mode': 'lite'}))
        state = self.args.data / 'agent-runtime/lite-attestation.json'
        state.parent.mkdir(parents=True)
        proc = self.args.data / 'proc'
        process = proc / '1234'
        process.mkdir(parents=True)
        (process / 'stat').write_text('1234 (worker with spaces) ' + ' '.join(['S'] + ['0'] * 18 + ['12345']))
        value = {'mode': 'lite', 'owner_pid': 1234, 'owner_start': '12345',
                 'updated_at': deployment.time.time(), 'status': 'idle'}
        with patch.object(deployment, 'PROC', proc), patch.object(deployment, 'urlopen', side_effect=AssertionError('MiMo network call')):
            for status in ('idle', 'waiting_configuration'):
                value['status'] = status
                state.write_text(json.dumps(value))
                self.assertTrue(deployment.native_status(self.args))
            value['status'] = 'busy'
            state.write_text(json.dumps(value))
            with self.assertRaisesRegex(deployment.InstallError, 'busy'):
                deployment.native_status(self.args)
            self.assertTrue(deployment.native_status(self.args, require_idle=False))
            value.update(status='idle', updated_at=1)
            state.write_text(json.dumps(value))
            with self.assertRaisesRegex(deployment.InstallError, 'cannot be verified'):
                deployment.native_status(self.args)
            value.update(owner_start='different-process', updated_at=deployment.time.time())
            state.write_text(json.dumps(value))
            self.assertFalse(deployment.native_status(self.args))
            (process / 'stat').unlink()
            process.rmdir()
            value['owner_start'] = '12345'
            state.write_text(json.dumps(value))
            self.assertFalse(deployment.native_status(self.args))

    def test_unknown_agent_mode_is_not_silently_treated_as_mimo(self):
        self.args.conf_dir.mkdir()
        (self.args.conf_dir / 'config.json').write_text(json.dumps({'agent_mode': 'typo'}))
        with self.assertRaisesRegex(deployment.InstallError, 'agent_mode'):
            deployment.environment_report(self.args)

    def test_missing_lite_heartbeat_cannot_hide_a_held_runtime_lock(self):
        self.args.conf_dir.mkdir()
        (self.args.conf_dir / 'config.json').write_text(json.dumps({'agent_mode': 'lite'}))
        lock = self.args.data / 'agent-runtime/lite-runtime.lock'
        lock.parent.mkdir(parents=True)
        lock.write_text('unchanged lock contents')
        fcntl = Mock(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8)
        with patch.dict(sys.modules, {'fcntl': fcntl}):
            fcntl.flock.side_effect = BlockingIOError()
            with self.assertRaisesRegex(deployment.InstallError, 'running without a verifiable heartbeat'):
                deployment.native_status(self.args)
            self.assertEqual(lock.read_text(), 'unchanged lock contents')
            fcntl.flock.side_effect = None
            self.assertFalse(deployment.native_status(self.args))
        self.assertTrue(lock.exists())
        self.assertEqual(lock.read_text(), 'unchanged lock contents')

    def test_service_venv_access_preserves_executables_and_skips_python_symlink(self):
        root = self.args.prefix / '.venv'
        (root / 'bin').mkdir(parents=True)
        executable = root / 'bin/pip'
        executable.write_text('fixture')
        executable.chmod(0o700)
        library = root / 'library.py'
        library.write_text('fixture')
        library.chmod(0o600)
        link = root / 'bin/python'
        link.write_text('simulated link; do not modify')
        real_is_symlink = Path.is_symlink
        with patch.object(Path, 'is_symlink', lambda path: path == link or real_is_symlink(path)):
            with patch.object(deployment.os, 'chown', create=True) as chown:
                deployment.grant_venv_access(root, 123)
        self.assertFalse(any(call.args[0] == link for call in chown.call_args_list))
        self.assertTrue(any(call.args[0] == executable for call in chown.call_args_list))


if __name__ == '__main__':
    unittest.main()
