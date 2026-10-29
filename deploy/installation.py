#!/usr/bin/env python3
"""One installation/update/rollback implementation; --check never mutates state."""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
import errno
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
PROC = Path('/proc') if os.name == 'posix' else None
sys.path.insert(0, str(ROOT / 'scripts'))
from release_manifest import release_files

MANAGED_DIRS = ('ayana', 'deploy', 'scripts', 'docs')
MANAGED_FILES = ('README.md', 'LICENSE', 'CHANGELOG.md', 'pyproject.toml', 'config.example.json', 'RELEASE-MANIFEST.json')
UNITS = ('ayana.service', 'ayana-agent-runtime.service')


class InstallError(RuntimeError):
    pass


def attested_owner_stopped(path: Path) -> bool:
    if PROC is None or not PROC.is_dir() or path.is_symlink():
        return False
    try:
        data = read_json(path)
        pid = data.get('owner_pid')
        return (type(pid) is int and pid > 0 and isinstance(data.get('owner_start'), str)
                and bool(data['owner_start']) and not (PROC / str(pid)).exists())
    except (OSError, ValueError):
        return False


def run(*argv: str, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, **kwargs)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}


def write_json(path: Path, value: dict, *, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    path.chmod(mode)


def effective_config(args) -> dict:
    config = read_json(args.conf_dir / 'config.json')
    config.update(read_json(args.conf_dir / 'secrets.json'))
    return config


def db_path(args) -> Path:
    value = Path(effective_config(args).get('db_path') or args.data / 'ayana.db')
    return value if value.is_absolute() else args.conf_dir / value


def native_status(args, *, require_idle=True):
    cfg = effective_config(args)
    port = int(cfg.get('mimo_serve_port') or 6290)
    password = str(cfg.get('mimo_serve_password') or cfg.get('webhook_token') or '')
    home = Path(cfg.get('agent_runtime_home') or args.data)
    directory = str(cfg.get('mimo_workdir') or home / 'agent-workspace')
    auth = base64.b64encode(('mimocode:' + password).encode()).decode()
    request = Request(f'http://127.0.0.1:{port}/session/status', headers={
        'Authorization': 'Basic ' + auth, 'x-mimocode-directory': quote(directory, safe='')})
    try:
        with urlopen(request, timeout=3) as response:
            value = json.load(response)
        if not isinstance(value, dict) or not all(isinstance(item, dict) and isinstance(item.get('type'), str)
                                               and (not require_idle or item['type'] == 'idle') for item in value.values()):
            raise InstallError('native runtime is busy or its state is uncertain; finish/reconcile tasks first')
        return True
    except HTTPError as exc:
        raise InstallError(f'native runtime returned HTTP {exc.code}; refuse unobserved update') from exc
    except URLError as exc:
        state = Path(cfg.get('agent_runtime_state_dir') or home / 'agent-runtime') / 'attestation.json'
        refused = isinstance(exc.reason, ConnectionRefusedError) or getattr(exc.reason, 'errno', None) == errno.ECONNREFUSED
        if state.exists() and not (refused and attested_owner_stopped(state)):
            raise InstallError('previously verified native runtime cannot be observed; refuse update') from exc
        if refused:
            # An unconfigured first installation may not have opened the native port.
            return False
        raise InstallError('native runtime state cannot be observed; refuse update') from exc
    except (ValueError, TimeoutError) as exc:
        raise InstallError('native runtime returned an invalid or incomplete state') from exc


def web_is_online(args):
    port = int(effective_config(args).get('http_port') or args.http_port)
    try:
        with urlopen(f'http://127.0.0.1:{port}/health', timeout=3):
            return True
    except HTTPError:
        return True
    except URLError as exc:
        if isinstance(exc.reason, ConnectionRefusedError) or getattr(exc.reason, 'errno', None) == errno.ECONNREFUSED:
            return False
        raise InstallError('Web process state cannot be observed; stop it before an unmanaged update') from exc


def ensure_quiescent(args):
    path = db_path(args)
    if path.exists():
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            probes = {
                'agent_runtime_receipts': "status IN ('accepted','pending','queued','running','unknown')",
                'agent_native_submissions': "state IN ('submitting','recovering','unknown')",
                'investigation_jobs': "status IN ('queued','running')",
                'session_write_ops': "status IN ('claimed','unknown')",
                'agent_session_turns': f'expires_at>{time.time()}',
            }
            for table, condition in probes.items():
                if table in tables and conn.execute(f'SELECT 1 FROM {table} WHERE {condition} LIMIT 1').fetchone():
                    raise InstallError(f'pending work in {table}; finish/reconcile it before update')
            if 'agent_runtime_bindings' in tables:
                columns = {row[1] for row in conn.execute('PRAGMA table_info(agent_runtime_bindings)')}
                if {'controller_connection_id', 'control_expires_at'}.issubset(columns) and conn.execute(
                        "SELECT 1 FROM agent_runtime_bindings WHERE controller_connection_id<>'' AND control_expires_at>? LIMIT 1",
                        (time.time(),)).fetchone():
                    raise InstallError('active takeover lease; release control and wait for tasks to become idle before update')
    ready = native_status(args)
    if (args.no_start or not args.system) and (ready or web_is_online(args)):
        raise InstallError('unmanaged/--no-start updates require offline Web and native processes; stop them manually first')
    return ready


def validate_paths(args):
    for name in ('prefix', 'data', 'conf_dir', 'backup_dir', 'unit_dir'):
        path = getattr(args, name).expanduser().resolve()
        if path == Path(path.anchor) or any(parent.is_symlink() for parent in [getattr(args, name), *getattr(args, name).parents]):
            raise InstallError(f'unsafe {name} path')
        setattr(args, name, path)
    paths = (args.prefix, args.data, args.conf_dir, args.backup_dir, args.unit_dir)
    for index, left in enumerate(paths):
        for right in paths[index + 1:]:
            if left.is_relative_to(right) or right.is_relative_to(left):
                raise InstallError('code, data, config, backup and unit directories must not overlap')
    if not 1 <= args.http_port <= 65535:
        raise InstallError('invalid HTTP port')


def environment_report(args) -> list[str]:
    missing = []
    if sys.version_info < (3, 11):
        missing.append('Python >= 3.11')
    for binary in ('ssh', 'ssh-keyscan', 'tmux'):
        if shutil.which(binary) is None:
            missing.append(binary)
    cfg = effective_config(args)
    configured = cfg.get('mimo_bin') or (cfg.get('auto_investigate') or {}).get('mimo_bin')
    if args.mimo_bin and configured:
        selected_path = Path(shutil.which(str(args.mimo_bin)) or args.mimo_bin).resolve()
        configured_path = Path(shutil.which(str(configured)) or configured).resolve()
        if selected_path != configured_path:
            missing.append('--mimo-bin conflicts with existing config; explicitly update config before installation')
    candidate = args.mimo_bin or configured or shutil.which('mimo')
    if not candidate or not (Path(candidate).is_file() or shutil.which(str(candidate))):
        missing.append('MiMo CLI (install it separately, then pass --mimo-bin /usr/local/bin/mimo)')
    else:
        args.mimo_bin = str(Path(shutil.which(str(candidate)) or candidate).resolve())
        if not os.access(args.mimo_bin, os.X_OK):
            missing.append('MiMo CLI must be executable')
        if args.system and (args.mimo_bin.startswith('/root/') or args.mimo_bin.startswith('/home/')):
            missing.append('MiMo CLI in a system-readable path outside /root and /home (ProtectHome=true)')
    if args.system and not args.no_start:
        if os.name != 'posix' or os.geteuid() != 0:
            missing.append('root for --system')
        if shutil.which('systemctl') is None:
            missing.append('systemd')
    try:
        import ensurepip, venv  # noqa: F401
    except ImportError:
        missing.append('Python venv/ensurepip (install python3-venv)')
    return missing


def render_units(args, template_root: Path) -> dict[str, str]:
    replacements = {'/opt/ayana': str(args.prefix), '/var/lib/ayana': str(args.data),
                    '/etc/ayana': str(args.conf_dir), 'User=ayana': f'User={args.service_user}',
                    'Group=ayana': f'Group={args.service_user}'}
    result = {}
    for name in UNITS:
        text = (template_root / 'deploy' / name).read_text(encoding='utf-8')
        for before, after in replacements.items():
            text = text.replace(before, after)
        result[name] = text
    return result


def provider_config_files(args) -> list[Path]:
    cfg = effective_config(args)
    home = Path(cfg.get('agent_runtime_home') or args.data)
    directories = [Path(cfg['mimo_config_dir'])] if cfg.get('mimo_config_dir') else [home / '.config/mimocode', home / '.mimocode']
    return [directory / name for directory in directories
            for name in ('mimocode.jsonc', 'mimocode.json', 'config.jsonc', 'config.json')]


def validate_backup_scope(args):
    cfg = effective_config(args)
    for key in ('mimo_workdir', 'agent_runtime_state_dir', 'knowledge_dir', 'agent_runtime_home'):
        if cfg.get(key) and not Path(cfg[key]).resolve().is_relative_to(args.data):
            raise InstallError(f'{key} is outside --data; take a complete offline snapshot and relocate it before managed upgrades')
    if (args.prefix / '.venv').is_symlink():
        raise InstallError('venv directory cannot be a symlink')


def backup(args) -> Path:
    validate_backup_scope(args)
    destination = args.backup_dir / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    destination.mkdir(parents=True, mode=0o700)
    code = destination / 'code'
    code.mkdir()
    for name in (*MANAGED_DIRS, *MANAGED_FILES):
        source = args.prefix / name
        if source.is_dir():
            shutil.copytree(source, code / name, symlinks=True)
        elif source.is_file():
            shutil.copy2(source, code / name)
    if (args.prefix / '.venv').exists():
        shutil.copytree(args.prefix / '.venv', destination / 'venv', symlinks=True)
    if args.conf_dir.exists():
        shutil.copytree(args.conf_dir, destination / 'config', symlinks=True)
    provider_files = []
    for index, path in enumerate(provider_config_files(args)):
        if path.is_symlink():
            raise InstallError('provider configuration cannot be a symlink')
        provider_files.append({'path': str(path), 'present': path.is_file(), 'backup': f'provider-{index}.json'})
        if path.is_file():
            shutil.copy2(path, destination / f'provider-{index}.json')
    database = db_path(args)
    if database.exists():
        with closing(sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)) as source, closing(sqlite3.connect(destination / 'ayana.db')) as target:
            source.backup(target)
    units = destination / 'units'
    units.mkdir()
    for name in UNITS:
        if (args.unit_dir / name).is_file():
            shutil.copy2(args.unit_dir / name, units / name)
    write_json(destination / 'backup.json', {'prefix': str(args.prefix), 'data': str(args.data),
                                           'conf_dir': str(args.conf_dir), 'database': str(database),
                                           'had_database': database.exists(), 'provider_files': provider_files,
                                           'units': [name for name in UNITS if (units / name).is_file()]})
    (args.backup_dir / 'LAST').write_text(str(destination), encoding='utf-8')
    return destination


def validate_source(source: Path):
    files = release_files(source)
    required = {'ayana/main.py', 'ayana/agent_runtime.py', 'deploy/installation.py', 'pyproject.toml'}
    if not required.issubset({path.relative_to(source).as_posix() for path in files}):
        raise InstallError('incomplete source/package')
    manifest_path = source / 'RELEASE-MANIFEST.json'
    if manifest_path.exists():
        expected = read_json(manifest_path).get('files') or {}
        actual = {path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
        if expected != actual:
            raise InstallError('release manifest does not match package files')
    return files


def replace_code(source: Path, prefix: Path):
    files = validate_source(source)
    manifest_path = source / 'RELEASE-MANIFEST.json'
    prefix.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ayana-code-', dir=prefix.parent) as staging_dir:
        stage = Path(staging_dir)
        for path in files:
            relative = path.relative_to(source)
            if relative.parts[0] == 'knowledge':
                continue  # Knowledge seeds are copied to writable data, only when absent.
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        if manifest_path.exists():
            shutil.copy2(manifest_path, stage / manifest_path.name)
        for name in (*MANAGED_DIRS, *MANAGED_FILES):
            previous = prefix / name
            if previous.is_symlink():
                raise InstallError(f'unsafe managed symlink: {previous}')
            if previous.is_dir():
                shutil.rmtree(previous)
            elif previous.exists():
                previous.unlink()
            current = stage / name
            if current.exists():
                shutil.move(str(current), str(previous))


def venv_python(prefix: Path) -> Path:
    return prefix / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def configure(args, source: Path):
    for folder in (args.data, args.data / 'log', args.data / 'knowledge', args.data / 'agent-workspace',
                   args.data / 'agent-runtime', args.conf_dir):
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    config = args.conf_dir / 'config.json'
    if not config.exists():
        write_json(config, {'http_host': args.http_host, 'http_port': args.http_port,
                           'ws_host': '127.0.0.1', 'ws_port': 6199, 'db_path': str(args.data / 'ayana.db'),
                           'log_file': str(args.data / 'log/ayana.log'), 'knowledge_dir': str(args.data / 'knowledge'),
                           'agent_runtime_home': str(args.data), 'mimo_workdir': str(args.data / 'agent-workspace'),
                           'agent_runtime_state_dir': str(args.data / 'agent-runtime'),
                           'mimo_config_dir': str(args.data / '.config/mimocode'),
                           'mimo_bin': args.mimo_bin or '/usr/local/bin/mimo',
                           'mimo_serve_external': True, 'agent_tui_enabled': True,
                           'prometheus_url': 'http://127.0.0.1:9090', 'alertmanager_url': 'http://127.0.0.1:9093'})
    secret_file = args.conf_dir / 'secrets.json'
    if not secret_file.exists():
        write_json(secret_file, {key: secrets.token_urlsafe(32) for key in (
            'onewbot_token', 'webhook_token', 'web_auth_pepper', 'totp_encrypt_key', 'ssh_credential_key', 'notify_channel_key')})
    for seed in (source / 'knowledge').glob('*.md'):
        if seed.relative_to(source).as_posix() in {path.relative_to(source).as_posix() for path in release_files(source)}:
            target = args.data / 'knowledge' / seed.name
            if not target.exists():
                shutil.copy2(seed, target)


def install_dependencies(args):
    python = venv_python(args.prefix)
    if not python.exists():
        run(sys.executable, '-m', 'venv', str(args.prefix / '.venv'))
    if not args.skip_pip:
        run(str(python), '-m', 'pip', 'install', str(args.prefix))


def set_permissions(args):
    if not args.system or args.no_start:
        return
    import pwd
    try:
        account = pwd.getpwnam(args.service_user)
    except KeyError:
        run('useradd', '--system', '--home', str(args.data), '--shell', '/usr/sbin/nologin', args.service_user)
        account = pwd.getpwnam(args.service_user)
    for path in [args.data, *args.data.rglob('*')]:
        if not path.is_symlink():
            os.chown(path, account.pw_uid, account.pw_gid)
    args.prefix.chmod(0o750)
    os.chown(args.prefix, 0, account.pw_gid)
    for directory in MANAGED_DIRS:
        for path in [args.prefix / directory, *(args.prefix / directory).rglob('*')]:
            if path.exists() and not path.is_symlink():
                os.chown(path, 0, account.pw_gid)
                path.chmod(0o750 if path.is_dir() or path.suffix == '.sh' else 0o640)
    grant_venv_access(args.prefix / '.venv', account.pw_gid)
    args.conf_dir.chmod(0o750)
    os.chown(args.conf_dir, 0, account.pw_gid)
    for path in args.conf_dir.iterdir():
        if path.is_file() and not path.is_symlink():
            os.chown(path, 0, account.pw_gid)
            path.chmod(0o640)


def grant_venv_access(root: Path, group_id: int):
    """Give the service group access without following links to system Python."""
    if root.is_symlink():
        raise InstallError('venv directory cannot be a symlink')
    for path in [root, *root.rglob('*')]:
        if not path.exists() or path.is_symlink():
            continue
        mode = stat.S_IMODE(path.stat().st_mode) | stat.S_IRGRP
        if path.is_dir() or mode & stat.S_IXUSR:
            mode |= stat.S_IXGRP
        os.chown(path, 0, group_id)
        path.chmod(mode)


def health(args, units=None):
    cfg = effective_config(args)
    port = int(cfg.get('http_port') or args.http_port)
    with urlopen(f'http://127.0.0.1:{port}/health', timeout=5) as response:
        if response.status != 200 or not json.load(response).get('ok'):
            raise InstallError('Web health failed')
    if args.system and not args.no_start:
        for name in (UNITS if units is None else units):
            run('systemctl', 'is-active', '--quiet', name)


def wait_health(args, units=None):
    for attempt in range(10):
        try:
            health(args, units)
            return
        except (URLError, InstallError, subprocess.CalledProcessError):
            if attempt == 9:
                raise
            time.sleep(1)


def validate_snapshot(args, snapshot: Path):
    snapshot = snapshot.resolve()
    if not snapshot.is_relative_to(args.backup_dir) or snapshot == args.backup_dir:
        raise InstallError('backup must be inside the configured backup directory')
    meta = read_json(snapshot / 'backup.json')
    if meta.get('prefix') != str(args.prefix) or meta.get('conf_dir') != str(args.conf_dir):
        raise InstallError('backup belongs to a different installation')
    if 'database' not in meta or 'had_database' not in meta or not (snapshot / 'code').is_dir():
        raise InstallError('incomplete backup')
    if meta['had_database'] and not (snapshot / 'ayana.db').is_file():
        raise InstallError('backup database is missing')
    if any(item['present'] and not (snapshot / item['backup']).is_file() for item in meta.get('provider_files', [])):
        raise InstallError('backup provider configuration is missing')
    return snapshot, meta


def restore(args, snapshot: Path):
    snapshot, meta = validate_snapshot(args, snapshot)
    for name in (*MANAGED_DIRS, *MANAGED_FILES, '.venv'):
        target = args.prefix / name
        if target.is_symlink():
            raise InstallError('unsafe restore target')
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
        source = snapshot / ('venv' if name == '.venv' else 'code/' + name)
        if source.is_dir():
            shutil.copytree(source, target, symlinks=True)
        elif source.is_file():
            shutil.copy2(source, target)
    if (snapshot / 'config').exists():
        if args.conf_dir.exists():
            shutil.rmtree(args.conf_dir)
        shutil.copytree(snapshot / 'config', args.conf_dir, symlinks=True)
    database = Path(meta['database'])
    for path in (database, Path(str(database) + '-wal'), Path(str(database) + '-shm')):
        if path.exists():
            path.unlink()
    if meta['had_database']:
        database.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(snapshot / 'ayana.db', database)
    for item in meta.get('provider_files', []):
        target = Path(item['path'])
        if target.is_symlink():
            raise InstallError('unsafe provider configuration restore target')
        if target.exists():
            target.unlink()
        if item['present']:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snapshot / item['backup'], target)
    for name in UNITS:
        target = args.unit_dir / name
        if (snapshot / 'units' / name).exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snapshot / 'units' / name, target)
        elif target.exists():
            target.unlink()


def install(args, source: Path):
    source = source.resolve()
    if source == args.prefix:
        # Replacement deletes managed directories; keep the source independent.
        with tempfile.TemporaryDirectory(prefix='ayana-source-') as temporary:
            copied = Path(temporary)
            for path in release_files(source):
                target = copied / path.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
            return install(args, copied)
    missing = environment_report(args)
    if missing:
        raise InstallError('missing prerequisites: ' + '; '.join(missing))
    validate_source(source)
    validate_backup_scope(args)
    cfg = effective_config(args)
    if cfg and cfg.get('mimo_serve_external') is not True and not args.no_start:
        raise InstallError('existing config must explicitly set mimo_serve_external=true before installing the independent runtime')
    existing = (args.prefix / 'ayana/main.py').exists()
    has_state = existing or (args.conf_dir / 'config.json').exists() or db_path(args).exists()
    was_ready = ensure_quiescent(args) if has_state else False
    managed = args.system and not args.no_start
    snapshot = None
    web_stopped = runtime_stopped = False
    started_new = False
    try:
        if managed and has_state:
            run('systemctl', 'stop', 'ayana.service')
            web_stopped = True
            ensure_quiescent(args)
            if (args.unit_dir / 'ayana-agent-runtime.service').is_file():
                run('systemctl', 'stop', 'ayana-agent-runtime.service')
            runtime_stopped = True
        if has_state:
            snapshot = backup(args)
            print(f'Backup: {snapshot}')
        replace_code(source, args.prefix)
        configure(args, source)
        install_dependencies(args)
        if args.system or args.unit_dir_explicit:
            args.unit_dir.mkdir(parents=True, exist_ok=True)
            for name, text in render_units(args, args.prefix).items():
                (args.unit_dir / name).write_text(text, encoding='utf-8', newline='\n')
        set_permissions(args)
        if managed:
            run('systemctl', 'daemon-reload')
            run('systemctl', 'enable', *UNITS)
            run('systemctl', 'start', 'ayana-agent-runtime.service', 'ayana.service')
            started_new = True
            wait_health(args)
            if was_ready:
                for attempt in range(10):
                    try:
                        if not native_status(args, require_idle=False):
                            raise InstallError('previously ready native runtime did not return')
                        break
                    except InstallError:
                        if attempt == 9:
                            raise
                        time.sleep(1)
        print('Installed. Register using setup-admin.token, then save and verify the MiMo provider/model in Web settings.')
        if args.no_start:
            print('No services or system accounts were changed (--no-start).')
        if not args.system:
            print(f'Runtime: {venv_python(args.prefix)} -m ayana.agent_runtime {args.conf_dir / "config.json"}')
            print(f'Web: {venv_python(args.prefix)} -m ayana.main {args.conf_dir / "config.json"}')
    except BaseException:
        if managed and (runtime_stopped or started_new):
            run('systemctl', 'stop', *UNITS)
        if snapshot is not None:
            restore(args, snapshot)
        if managed and runtime_stopped:
            run('systemctl', 'daemon-reload')
            prior_units = read_json(snapshot / 'backup.json')['units'] if snapshot else list(UNITS)
            if prior_units:
                run('systemctl', 'start', *prior_units)
        elif managed and web_stopped:
            run('systemctl', 'start', 'ayana.service')
        raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('command', nargs='?', default='install', choices=['install', 'init', 'update', 'rollback', 'status', 'health'])
    mode = result.add_mutually_exclusive_group()
    mode.add_argument('--system', action='store_true')
    mode.add_argument('--user', action='store_true')
    result.add_argument('--prefix', type=Path)
    result.add_argument('--data', type=Path)
    result.add_argument('--conf-dir', '--conf', dest='conf_dir', type=Path)
    result.add_argument('--backup-dir', type=Path)
    result.add_argument('--unit-dir', type=Path)
    result.add_argument('--service-user', default='ayana')
    result.add_argument('--http-host', default='127.0.0.1')
    result.add_argument('--http-port', type=int, default=6200)
    result.add_argument('--mimo-bin')
    result.add_argument('--skip-pip', action='store_true')
    result.add_argument('--no-start', action='store_true')
    result.add_argument('--check', action='store_true')
    result.add_argument('--force', action='store_true', help='compatibility alias; installs always synchronize the exact public code tree')
    result.add_argument('--source', type=Path)
    result.add_argument('--git', default='https://github.com/wwqjss/Ayana.git')
    result.add_argument('--ref', '--branch', dest='ref', default='main')
    result.add_argument('--backup', type=Path)
    return result


def normalise(args):
    args.prefix = args.prefix or Path('/opt/ayana' if args.system else '~/.local/share/ayana').expanduser()
    args.data = args.data or Path('/var/lib/ayana' if args.system else '~/.local/share/ayana-data').expanduser()
    args.conf_dir = args.conf_dir or Path('/etc/ayana' if args.system else '~/.config/ayana').expanduser()
    args.backup_dir = args.backup_dir or args.prefix.parent / (args.prefix.name + '-backups')
    args.unit_dir_explicit = args.unit_dir is not None
    args.unit_dir = args.unit_dir or Path('/etc/systemd/system')
    validate_paths(args)
    return args


def main(argv=None):
    args = normalise(parser().parse_args(argv))
    if args.check:
        missing = environment_report(args)
        print(json.dumps({'missing_prerequisites': missing, 'installed': (args.prefix / 'ayana/main.py').is_file(),
                          'config_present': (args.conf_dir / 'config.json').is_file(),
                          'units_present': {name: (args.unit_dir / name).is_file() for name in UNITS}}))
        return 1 if missing else 0
    if args.command == 'status':
        print(json.dumps({'prefix': str(args.prefix), 'data': str(args.data), 'config': str(args.conf_dir / 'config.json'),
                          'last_backup': (args.backup_dir / 'LAST').read_text() if (args.backup_dir / 'LAST').is_file() else None}))
        return 0
    if args.command == 'health':
        health(args)
        return 0
    if args.command == 'rollback':
        snapshot = args.backup or Path((args.backup_dir / 'LAST').read_text())
        _, snapshot_meta = validate_snapshot(args, snapshot)
        validate_backup_scope(args)
        ensure_quiescent(args)
        managed = args.system and not args.no_start
        web_stopped = runtime_stopped = False
        rescue = None
        try:
            if managed:
                run('systemctl', 'stop', 'ayana.service')
                web_stopped = True
                ensure_quiescent(args)
                if (args.unit_dir / 'ayana-agent-runtime.service').is_file():
                    run('systemctl', 'stop', 'ayana-agent-runtime.service')
                runtime_stopped = True
            rescue = backup(args)
            restore(args, snapshot)
            set_permissions(args)
            if managed:
                run('systemctl', 'daemon-reload')
                prior_units = snapshot_meta['units']
                if prior_units:
                    run('systemctl', 'start', *prior_units)
                wait_health(args, prior_units)
        except BaseException:
            if managed and runtime_stopped:
                run('systemctl', 'stop', *UNITS)
            if rescue is not None:
                restore(args, rescue)
            if managed and runtime_stopped:
                run('systemctl', 'daemon-reload')
                rescue_units = read_json(rescue / 'backup.json')['units'] if rescue else list(UNITS)
                if rescue_units:
                    run('systemctl', 'start', *rescue_units)
            elif managed and web_stopped:
                run('systemctl', 'start', 'ayana.service')
            raise
        print(f'Pre-rollback rescue backup: {rescue}')
        print(f'Restored paired code/config/database snapshot: {snapshot}')
        return 0
    if args.source or args.command == 'install':
        install(args, args.source or ROOT)
    else:
        with tempfile.TemporaryDirectory(prefix='ayana-fetch-') as temporary:
            source = Path(temporary) / 'source'
            run('git', 'clone', '--no-checkout', '--', args.git, str(source))
            run('git', '-C', str(source), 'checkout', '--detach', args.ref)
            install(args, source)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (InstallError, OSError, subprocess.CalledProcessError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        raise SystemExit(1)
