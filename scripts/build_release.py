"""Build public, version-independent installation archives and SHA256 sidecars."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tomllib

from release_manifest import release_files


def build(root: Path, output: Path) -> dict:
    root, output = root.resolve(), output.resolve()
    version = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    if not version or any(char not in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-' for char in version):
        raise ValueError('invalid project version')
    files = release_files(root)
    names = {path.relative_to(root).as_posix() for path in files}
    required = {'ayana/main.py', 'ayana/agent_runtime.py', 'deploy/install.sh',
                'deploy/installation.py', 'deploy/ayana-agent-runtime.service', 'pyproject.toml',
                'docs/README.md', 'docs/INSTALL.md', 'docs/CONFIGURATION.md',
                'docs/OPERATIONS.md', 'docs/TESTING.md', 'docs/mcp-operations.md',
                'ayana/static/index.html', 'ayana/static/app.js', 'ayana/static/app.css',
                'ayana/static/settings.js', 'ayana/static/workbench.js', 'ayana/static/workbench.css',
                'ayana/static/terminal_clipboard.js', 'ayana/static/xterm/xterm.js',
                'ayana/static/xterm/xterm.css', 'ayana/static/xterm/xterm-addon-fit.js'}
    if missing := required - names:
        raise ValueError(f'incomplete release: {sorted(missing)}')
    manifest = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f'ayana-{version}-install.tar.gz'
    with tarfile.open(archive, 'w:gz', format=tarfile.PAX_FORMAT) as package:
        for path in files:
            name = path.relative_to(root).as_posix()
            info = package.gettarinfo(str(path), arcname=name)
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mode = 0o755 if path.suffix == '.sh' else 0o644
            with path.open('rb') as stream:
                package.addfile(info, stream)
        data = (json.dumps({'version': version, 'files': manifest}, indent=2, sort_keys=True) + '\n').encode()
        info = tarfile.TarInfo('RELEASE-MANIFEST.json')
        info.size, info.mode = len(data), 0o644
        package.addfile(info, io.BytesIO(data))
    stable = output / 'ayana-install.tar.gz'
    shutil.copyfile(archive, stable)
    for path in (archive, stable):
        path.with_name(path.name + '.sha256').write_text(
            hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n', encoding='ascii')
    (output / 'release-manifest.json').write_bytes(data)
    return {'version': version, 'archive': str(archive), 'stable_archive': str(stable), 'files': len(manifest)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.root, args.output_dir or args.root / 'dist'), ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
