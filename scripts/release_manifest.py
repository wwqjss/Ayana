"""The public release/install allowlist. User data and delivery evidence are absent."""
from pathlib import Path

PUBLIC_FILES = (
    'README.md', 'LICENSE', 'CHANGELOG.md', 'pyproject.toml', 'config.example.json',
    'docs/README.md', 'docs/INSTALL.md', 'docs/CONFIGURATION.md', 'docs/OPERATIONS.md',
    'docs/TESTING.md', 'docs/mcp-operations.md',
    'deploy/bootstrap.sh', 'deploy/install.sh', 'deploy/ayana-setup.sh',
    'deploy/installation.py', 'deploy/ayana.service', 'deploy/ayana-agent-runtime.service',
    'scripts/gen-secrets.py', 'scripts/export_retired_tables.py',
    'scripts/mcp_stdio_launcher.py', 'scripts/fnbk_collector.py',
    'scripts/migrate_monitor_config.py', 'scripts/build_release.py', 'scripts/release_manifest.py',
    'knowledge/ayana-port-bind-failed.md', 'knowledge/service-probe-example.md',
)
STATIC_SUFFIXES = {'.html', '.js', '.cjs', '.css', '.svg', '.png', '.ico', '.jpg', '.jpeg',
                   '.webp', '.gif', '.woff', '.woff2', '.ttf', '.map', '.json'}
PRIVATE_NAMES = {'config.json', 'secrets.json', 'setup-admin.token', 'bootstrap-admin.password'}


def release_files(root: Path) -> list[Path]:
    root = root.resolve()
    paths = {root / name for name in PUBLIC_FILES if (root / name).is_file()}
    for path in (root / 'ayana').rglob('*'):
        rel = path.relative_to(root)
        if not path.is_file() or any(part.startswith('.') or part == '__pycache__' for part in rel.parts):
            continue
        if path.name in PRIVATE_NAMES:
            continue
        if (len(rel.parts) > 2 and rel.parts[1] == 'static' and path.suffix.lower() in STATIC_SUFFIXES
                or path.suffix == '.py' and 'static' not in rel.parts):
            paths.add(path)
    for path in paths:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError(f'release contains a symlink: {path.relative_to(root)}')
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())
