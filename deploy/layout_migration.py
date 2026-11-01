"""Offline, backed-up consolidation of a legacy Ayana installation.

This is a separate lifecycle operation. Ordinary updates discover and retain
their installed paths; they never silently create a second empty instance.
"""
from __future__ import annotations

from copy import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid

DEDICATED_LOG_DIR = Path('/var/log/ayana')


def dedicated_log_directory(config: dict, deployment):
    """Only relocate the known Ayana-owned legacy log directory.

    An arbitrary configured log directory can belong to a shared service.
    Never move it merely because Ayana writes one file there.
    """
    configured = config.get('log_file')
    if not configured or not Path(configured).is_absolute():
        return None
    path = Path(configured)
    if not path.is_relative_to(DEDICATED_LOG_DIR):
        return None
    if any(item.is_symlink() for item in (DEDICATED_LOG_DIR, *DEDICATED_LOG_DIR.parents)):
        raise deployment.InstallError('legacy log directory symlinks require a reviewed migration')
    return DEDICATED_LOG_DIR


def archive_tree(source: Path, destination: Path, name: str):
    with tarfile.open(destination, 'w:gz') as archive:
        def regular(entry):
            return entry if entry.isfile() or entry.isdir() or entry.issym() or entry.islnk() else None
        archive.add(source, arcname=name, recursive=True, filter=regular)
    destination.chmod(0o600)


def rewrite_paths(value: str, replacements: dict[Path, Path]) -> str:
    """Replace original paths once, without rewriting newly generated paths.

    Both the host-native and the POSIX spelling of each path are recognised, so
    Linux unit files are rewritten correctly when this runs on a Windows host.
    """
    table: dict[str, str] = {}
    for old, new in replacements.items():
        if old == new:
            continue
        table.setdefault(str(old), str(new))
        table.setdefault(old.as_posix(), new.as_posix())
    if not table:
        return value
    pattern = '|'.join(re.escape(key) for key in sorted(table, key=len, reverse=True))
    return re.sub(r'(?<![A-Za-z0-9_.-])(?:' + pattern + r')(?=$|[/\\\s"\':;])',
                  lambda match: table[match.group()], value)


def rewrite_configuration(config: dict, replacements: dict[Path, Path]) -> dict:
    path_keys = {'db_path', 'log_file', 'knowledge_dir', 'agent_runtime_home',
                 'agent_runtime_state_dir', 'mimo_bin', 'mimo_config_dir', 'mimo_workdir'}
    def convert(value, key=''):
        if isinstance(value, dict):
            return {child: convert(item, child) for child, item in value.items()}
        if isinstance(value, list):
            return [convert(item, key) for item in value]
        if isinstance(value, str) and key in path_keys:
            return rewrite_paths(value, replacements)
        return value
    return convert(config)


def _owned_copy(source: Path, target: Path):
    # shutil.copytree passes strings to custom copy functions on Linux.
    source, target = Path(source), Path(target)
    shutil.copy2(source, target)
    if os.name == 'posix' and os.geteuid() == 0:
        info = source.stat()
        os.chown(target, info.st_uid, info.st_gid)
    return str(target)


def copy_tree(source: Path, target: Path, ignored: list[str]):
    def ignore(directory, names):
        transient = []
        for name in names:
            item = Path(directory) / name
            mode = item.lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                transient.append(name)
                ignored.append(str(item.relative_to(source)))
        return transient
    shutil.copytree(source, target, symlinks=True, copy_function=_owned_copy, ignore=ignore)
    preserve_ownership(source, target)


def preserve_ownership(source: Path, target: Path):
    if os.name != 'posix' or os.geteuid() != 0:
        return
    for previous in (source, *source.rglob('*')):
        current = target / previous.relative_to(source)
        if previous.is_symlink() or not current.exists() or current.is_symlink():
            continue
        info = previous.stat()
        os.chown(current, info.st_uid, info.st_gid)
        current.chmod(stat.S_IMODE(info.st_mode))


def tree_digest(path: Path) -> str:
    result = hashlib.sha256()
    for item in sorted((path, *path.rglob('*')) if path.is_dir() else (path,)):
        result.update(str(item.relative_to(path) if item != path else '.').encode())
        if item.is_symlink():
            result.update(b'link:' + os.readlink(item).encode())
        elif item.is_file():
            with item.open('rb') as stream:
                while chunk := stream.read(1024 * 1024):
                    result.update(chunk)
        elif item.is_dir():
            result.update(b'directory')
    return result.hexdigest()


def target_arguments(args, deployment):
    target = copy(args)
    target.prefix = args.root / 'app'
    target.data = args.root / 'data'
    target.conf_dir = args.root / 'config'
    target.backup_dir = args.root / 'backups'
    target.layout = 'unified'
    target.skip_pip = False
    deployment.validate_paths(target)
    return target


def _remove_owned(path: Path, root: Path, deployment):
    if path == root or not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
        raise deployment.InstallError('unsafe migration cleanup target')
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _replace_json(path: Path, value: dict):
    temporary = path.with_name('.layout-' + uuid.uuid4().hex + '.json')
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
        shutil.copystat(path, temporary)
        if os.name == 'posix' and os.geteuid() == 0:
            info = path.stat()
            os.chown(temporary, info.st_uid, info.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _replace_unit(path: Path, text: str):
    temporary = path.with_name('.layout-' + uuid.uuid4().hex + '.conf')
    try:
        with temporary.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        shutil.copystat(path, temporary)
        if os.name == 'posix' and os.geteuid() == 0:
            info = path.stat()
            os.chown(temporary, info.st_uid, info.st_gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _units(args, deployment):
    result = []
    for name in deployment.UNITS:
        unit = args.unit_dir / name
        if unit.is_file():
            result.append(unit)
        dropin = args.unit_dir / (name + '.d')
        if dropin.is_symlink():
            raise deployment.InstallError('unit/drop-in symlinks require a manual reviewed migration')
        if dropin.is_dir():
            result.extend(dropin.glob('*.conf'))
    for path in result:
        if path.is_symlink():
            raise deployment.InstallError('unit/drop-in symlinks require a manual reviewed migration')
    return result


def _active_units(args, deployment):
    result = []
    for name in deployment.UNITS:
        try:
            deployment.run('systemctl', 'is-active', '--quiet', name)
            result.append(name)
        except subprocess.CalledProcessError:
            pass
    if result and len(result) != len(deployment.UNITS):
        raise deployment.InstallError('both Ayana services must be consistently active or stopped before migration')
    return result


def _legacy_mimo_paths(config: dict, old_data: Path):
    home = Path(config.get('agent_runtime_home') or old_data)
    workdir = config.get('mimo_workdir') or str(home / 'agent-workspace')
    config_dir = config.get('mimo_config_dir') or ''
    if not config_dir:
        names = ('mimocode.jsonc', 'mimocode.json', 'config.jsonc', 'config.json')
        for directory in (home / '.config/mimocode', home / '.mimocode'):
            if any((directory / name).is_file() for name in names):
                config_dir = str(directory)
                break
        config_dir = config_dir or str(home / '.config/mimocode')
    return {'mimo_workdir': str(workdir), 'mimo_config_dir': str(config_dir)}


def _regular_bytes(path: Path) -> int:
    if not path.exists() or path.is_symlink():
        return 0
    return sum(item.stat().st_size for item in ((path, *path.rglob('*')) if path.is_dir() else (path,))
               if item.is_file() and not item.is_symlink())


def _free_space(args, target, deployment):
    root_parent = args.root
    while not root_parent.exists():
        root_parent = root_parent.parent
    logs = dedicated_log_directory(deployment.read_json(args.conf_dir / 'config.json'), deployment)
    data_bytes = _regular_bytes(args.data) + (_regular_bytes(logs) if logs else 0)
    venv_bytes = _regular_bytes(args.prefix / '.venv')
    backup_bytes = _regular_bytes(args.backup_dir)
    same_backup_device = args.backup_dir.exists() and args.backup_dir.stat().st_dev == root_parent.stat().st_dev
    required = data_bytes + max(128 * 1024 * 1024, venv_bytes * 2) + (0 if same_backup_device else backup_bytes)
    if shutil.disk_usage(root_parent).free < required + 64 * 1024 * 1024:
        raise deployment.InstallError('insufficient space for the consolidated copy and new virtual environment')
    backup_parent = args.backup_dir
    while not backup_parent.exists():
        backup_parent = backup_parent.parent
    if shutil.disk_usage(backup_parent).free < data_bytes + venv_bytes + 64 * 1024 * 1024:
        raise deployment.InstallError('insufficient space for a complete offline migration backup')


def migrate_layout(args, deployment):
    target = target_arguments(args, deployment)
    if all(getattr(args, name) == getattr(target, name) for name in ('prefix', 'data', 'conf_dir')):
        print(json.dumps({'ok': True, 'action': 'already_unified', 'root': str(args.root)}))
        return 0
    if args.skip_pip:
        raise deployment.InstallError('layout migration prepares a fresh virtual environment; omit --skip-pip')
    if not (args.prefix / 'ayana/main.py').is_file() or not (args.conf_dir / 'config.json').is_file() or not args.data.is_dir():
        raise deployment.InstallError('complete existing code, configuration and data are required for migration')
    for source in (args.data, args.conf_dir, args.backup_dir):
        if args.root.is_relative_to(source):
            raise deployment.InstallError('unified root cannot be inside the old data/config/backup directory')
    for name in ('prefix', 'data', 'conf_dir'):
        path = getattr(target, name)
        if path.exists() or path.is_symlink():
            raise deployment.InstallError(f'migration target already exists: {path}; inspect it before retrying')
    cfg = deployment.read_json(args.conf_dir / 'config.json')
    old_mode = deployment.configured_agent_mode(cfg)
    if args.agent_mode not in (None, old_mode):
        raise deployment.InstallError('migrate the layout first, then switch the Agent mode separately')
    target.agent_mode = old_mode
    deployment.validate_source(deployment.ROOT)
    deployment.validate_backup_scope(args)
    missing = deployment.environment_report(args)
    if missing:
        raise deployment.InstallError('missing prerequisites: ' + '; '.join(missing))
    was_ready = deployment.ensure_quiescent(args)
    _free_space(args, target, deployment)
    managed = args.system and not args.no_start
    active = _active_units(args, deployment) if managed else []
    if managed and was_ready and not active:
        raise deployment.InstallError('an unmanaged Agent runtime is still active; stop and verify it before migration')
    _units(args, deployment) if args.system or args.unit_dir_explicit else []
    mapping = {args.prefix: target.prefix, args.data: target.data, args.conf_dir: target.conf_dir,
               args.backup_dir: target.backup_dir / 'legacy'}
    ignored = []
    snapshot = None
    stashes = []
    changed_units = []
    prepared = []
    old_web_stopped = old_runtime_stopped = new_started = backups_moved = committed = False
    token = uuid.uuid4().hex[:12]
    target.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    report_path = target.backup_dir / ('layout-migration-' + token + '.json')
    report = {'kind': 'layout_migration', 'old': {key: str(getattr(args, key)) for key in ('prefix', 'data', 'conf_dir', 'backup_dir')},
              'new': {key: str(getattr(target, key)) for key in ('prefix', 'data', 'conf_dir', 'backup_dir')},
              'status': 'preparing', 'ignored_transient_entries': ignored,
              'compatibility': 'MiMo provider/workdir logical paths retain their verified/session identity through old-path symlinks.'}
    deployment.write_json(report_path, report)
    try:
        print('Preparing the new program and virtual environment before stopping services.', flush=True)
        prepared.append(target.prefix)
        deployment.replace_code(deployment.ROOT, target.prefix)
        if (args.prefix / 'bin').is_dir():
            copy_tree(args.prefix / 'bin', target.prefix / 'bin', ignored)
        deployment.install_dependencies(target)
        if managed:
            deployment.run('systemctl', 'stop', 'ayana.service')
            old_web_stopped = True
            deployment.ensure_quiescent(args)
            deployment.run('systemctl', 'stop', 'ayana-agent-runtime.service')
            old_runtime_stopped = True
        deployment.ensure_quiescent(args)
        # Preparing the venv may take minutes. Read the final offline facts,
        # rather than overwrite settings/drop-ins changed during preparation.
        config_bytes = (args.conf_dir / 'config.json').read_bytes()
        cfg = json.loads(config_bytes.decode('utf-8'))
        if deployment.configured_agent_mode(cfg) != old_mode:
            raise deployment.InstallError('Agent mode changed during preparation; retry the migration')
        deployment.validate_backup_scope(args)
        unit_paths = _units(args, deployment) if args.system or args.unit_dir_explicit else []
        logs = dedicated_log_directory(cfg, deployment)
        if logs:
            mapping[logs] = target.data / 'log'
        _free_space(args, target, deployment)
        snapshot = deployment.backup(args)
        # The regular snapshot contains code/venv/config/SQLite/provider files.
        # Add the complete native history, knowledge and runtime data offline.
        archive_tree(args.data, snapshot / 'runtime-data.tar.gz', 'data')
        if logs and logs.exists():
            archive_tree(logs, snapshot / 'external-logs.tar.gz', 'log')
        for path in unit_paths:
            saved = snapshot / 'units' / path.relative_to(args.unit_dir)
            saved.parent.mkdir(parents=True, exist_ok=True)
            _owned_copy(path, saved)
        report.update(status='copying', snapshot=str(snapshot), snapshot_usage='migration recovery; not a new-layout ordinary rollback snapshot')
        _replace_json(report_path, report)
        for source, destination in ((args.data, target.data), (args.conf_dir, target.conf_dir)):
            prepared.append(destination)
            copy_tree(source, destination, ignored)
        if logs and logs.exists():
            destination = target.data / 'log'
            if destination.exists():
                if not destination.is_dir() or destination.is_symlink() or any(destination.iterdir()):
                    raise deployment.InstallError('both legacy data/log and external logs contain files; review before merging')
                destination.rmdir()
            copy_tree(logs, destination, ignored)
        if (args.conf_dir / 'config.json').read_bytes() != config_bytes:
            raise deployment.InstallError('configuration changed during copying; retry without concurrent edits')
        updated = rewrite_configuration(cfg, mapping)
        old_home = Path(cfg.get('agent_runtime_home') or args.data)
        has_mimo_history = (old_mode == 'mimo' or bool(cfg.get('mimo_config_dir') or cfg.get('mimo_workdir'))
                            or any((old_home / path).exists() for path in ('.config/mimocode', '.mimocode', '.local/share/mimocode')))
        if has_mimo_history:
            # Fingerprints include the literal provider path; native session
            # projects include their directory. Preserve both logical names.
            updated.update(_legacy_mimo_paths(cfg, args.data))
            binary = cfg.get('mimo_bin') or (cfg.get('auto_investigate') or {}).get('mimo_bin') or args.mimo_bin
            if binary:
                updated['mimo_bin'] = rewrite_paths(str(binary), mapping)
        _replace_json(target.conf_dir / 'config.json', updated)
        deployment.set_permissions(target)
        preserve_ownership(args.data, target.data)
        preserve_ownership(args.conf_dir, target.conf_dir)
        if logs and logs.exists():
            preserve_ownership(logs, target.data / 'log')
        if (args.conf_dir / 'config.json').read_bytes() != config_bytes:
            raise deployment.InstallError('configuration changed during copying; retry without concurrent edits')
        if (args.system or args.unit_dir_explicit) and set(_units(args, deployment)) != set(unit_paths):
            raise deployment.InstallError('service drop-ins changed during copying; retry without concurrent edits')
        sources = [(args.data, target.data), (args.conf_dir, target.conf_dir)]
        if logs and logs.exists():
            sources.append((logs, target.data / 'log'))
        scripts = args.prefix / 'scripts'
        saved_scripts = snapshot / 'code/scripts'
        if scripts.is_dir() and not scripts.is_symlink() and saved_scripts.is_dir() and tree_digest(scripts) == tree_digest(saved_scripts):
            # Cron can still call the legacy public collector path. Move the
            # entire directory into the rollback holding area before linking.
            sources.append((scripts, target.prefix / 'scripts'))
            report['legacy_scripts_compatibility_link'] = str(scripts)
        for source, destination in sources:
            stash = source.with_name('.' + source.name + '-layout-' + token)
            if stash.exists() or stash.is_symlink():
                raise deployment.InstallError('migration holding path already exists')
            source.rename(stash)
            stashes.append((source, stash, destination))
            source.symlink_to(destination, target_is_directory=True)
        for path in unit_paths:
            saved = snapshot / 'units' / path.relative_to(args.unit_dir)
            if path.read_bytes() != saved.read_bytes():
                raise deployment.InstallError('service configuration changed during copying; retry without concurrent edits')
            original = saved.read_text(encoding='utf-8')
            revised = rewrite_paths(original, mapping)
            changed_units.append(path)
            _replace_unit(path, revised)
        if managed:
            deployment.run('systemctl', 'daemon-reload')
            if active:
                new_started = True
                deployment.run('systemctl', 'start', *active)
                deployment.wait_health(target, active)
                if was_ready or old_mode == 'lite':
                    for attempt in range(30):
                        try:
                            if deployment.native_status(target, require_idle=False):
                                break
                        except deployment.InstallError:
                            pass
                        if attempt == 29:
                            raise deployment.InstallError('new Agent runtime did not return after directory migration')
                        deployment.time.sleep(1)
        # Do not delete a legacy file edited by another process after backup.
        # Unknown root files are deliberately left for human classification.
        preserved = []
        old_cleanup = []
        for name in (*deployment.MANAGED_DIRS, *deployment.MANAGED_FILES, '.venv', 'bin'):
            old = args.prefix / name
            previous = snapshot / ('venv' if name == '.venv' else 'code/' + name)
            if not old.exists():
                continue
            if old.is_symlink() and any(source == old for source, _, _ in stashes):
                continue
            if old.is_symlink() or not previous.exists() or tree_digest(old) != tree_digest(previous):
                preserved.append(str(old))
                continue
            old_cleanup.append((old, previous))
        legacy_backups = target.backup_dir / 'legacy'
        if args.backup_dir != target.backup_dir:
            if legacy_backups.exists() or legacy_backups.is_symlink():
                raise deployment.InstallError('legacy backup destination already exists')
            shutil.move(str(args.backup_dir), str(legacy_backups))
            backups_moved = True
            snapshot = legacy_backups / snapshot.name
            args.backup_dir.symlink_to(legacy_backups, target_is_directory=True)
        for source, stash, destination in stashes:
            if not source.is_symlink() or source.resolve() != destination.resolve():
                raise deployment.InstallError('compatibility link changed during migration')
            if stash.parent != source.parent or stash.name != '.' + source.name + '-layout-' + token:
                raise deployment.InstallError('unsafe holding directory cleanup')
        report.update(status='complete', snapshot=str(snapshot), preserved_legacy_files=preserved,
                      active_services_preserved=active, old_path_compatibility_links=True,
                      relocated_log_directory=str(logs) if logs else None,
                      external_log_file_preserved=cfg.get('log_file') if not logs else None)
        _replace_json(report_path, report)
        (target.backup_dir / 'MIGRATION-LAST').write_text(str(report_path), encoding='utf-8')
        committed = True
        # Cleanup is after the commit point. A transient removal error leaves a
        # documented old holding copy, never a half-restored live installation.
        holding_copies = []
        for old, previous in old_cleanup:
            try:
                # Recheck immediately before removal. Changes during the
                # final switch are preserved as user material, not erased.
                if old.is_symlink() or tree_digest(old) != tree_digest(previous):
                    preserved.append(str(old))
                    continue
                _remove_owned(old, args.prefix, deployment)
            except OSError:
                preserved.append(str(old))
        for source, stash, destination in stashes:
            try:
                shutil.rmtree(stash)
            except OSError:
                holding_copies.append(str(stash))
        known_new = {target.prefix, target.data, target.conf_dir, target.backup_dir}
        known_new.update(source for source, _, _ in stashes)
        report['unrecognized_legacy_root_entries'] = [str(path) for path in args.prefix.iterdir()
                                                       if path not in known_new]
        report['preserved_legacy_files'] = preserved
        if holding_copies:
            report['holding_copies_to_review'] = holding_copies
        if holding_copies or preserved or report['unrecognized_legacy_root_entries'] or logs:
            try:
                _replace_json(report_path, report)
            except OSError:
                print('Migration committed; some old copies remain for review.', file=sys.stderr)
        print(json.dumps({'ok': True, 'action': 'layout_migrated', 'root': str(args.root),
                          'report': str(report_path), 'snapshot': str(snapshot),
                          'preserved_legacy_files': preserved, 'model_requests_sent': False,
                          'managed_host_commands_executed': False}), flush=True)
        return 0
    except BaseException:
        if committed:
            raise
        # If new work appeared after startup, never replace its facts or stop
        # its runtime just to force a rollback. Leave the backed-up new layout.
        if new_started:
            try:
                deployment.ensure_quiescent(target)
            except Exception:
                report.update(status='requires_review', reason='new work appeared; new data retained')
                _replace_json(report_path, report)
                raise deployment.InstallError('migration requires review; new work/data retained without rollback')
            deployment.run('systemctl', 'stop', *deployment.UNITS)
        for path in reversed(changed_units):
            saved = snapshot / 'units' / path.relative_to(args.unit_dir)
            _owned_copy(saved, path)
        for source, stash, destination in reversed(stashes):
            if source.is_symlink() and source.resolve() == destination.resolve():
                source.unlink()
            if not source.exists() and stash.exists():
                stash.rename(source)
        if backups_moved:
            legacy_backups = target.backup_dir / 'legacy'
            if args.backup_dir.is_symlink() and args.backup_dir.resolve() == legacy_backups.resolve():
                args.backup_dir.unlink()
            if not args.backup_dir.exists() and legacy_backups.exists():
                shutil.move(str(legacy_backups), str(args.backup_dir))
                snapshot = args.backup_dir / snapshot.name
        # Legacy managed files are removed only after new health passes. If a
        # late finalization failure occurred, use the exact paired snapshot.
        if snapshot is not None and snapshot.exists():
            missing_old = not (args.prefix / 'ayana/main.py').is_file()
            if missing_old:
                deployment.restore(args, snapshot)
        for path in reversed(prepared):
            if path.exists() and path != args.prefix:
                _remove_owned(path, args.root, deployment)
        if managed and (old_runtime_stopped or old_web_stopped):
            deployment.run('systemctl', 'daemon-reload')
            if active:
                deployment.run('systemctl', 'start', *active)
        report.update(status='rolled_back', snapshot=str(snapshot) if snapshot else None)
        _replace_json(report_path, report)
        raise
