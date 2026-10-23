"""Build v0.7.3 release tarball excluding personal/historical bulk."""
from __future__ import annotations

import tarfile
from pathlib import Path

ROOT = Path(r"C:\Users\karory\Git\Ayana")
OUT = ROOT / "ayana-v0.7.3-install.tar.gz"

EXCLUDE_DIRS = {
    ".git", ".venv", "__pycache__", "node_modules",
    ".pw-verify", ".playwright-cli", "backups",
    ".deploy-stage",
}
# 发行包不带历史评审证据目录（仓库内保留）
EXCLUDE_PATH_PREFIXES = (
    "docs/reviews/",
    "docs/evidence/",
)
EXCLUDE_NAME_PREFIX = ("_rt_", "patch_", "fix_", "ayana-deploy", "deploy-v", "ayana-review", "deploy_yomi")
EXCLUDE_SUFFIX = (".tar", ".tar.gz", ".db", ".db-shm", ".db-wal", ".log", ".pyc", ".png")
EXCLUDE_NAMES = {
    "secrets.json", "config.json",
    "bootstrap-admin.password", "setup-admin.token",
    "ayana-v073-test-install.tar.gz",
    "ayana-v073-monitor-isolation.tar.gz",
}


def skip(rel: str, name: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    if set(parts) & EXCLUDE_DIRS:
        return True
    norm = rel.replace("\\", "/")
    for p in EXCLUDE_PATH_PREFIXES:
        if norm.startswith(p) or f"/{p}" in f"/{norm}":
            return True
    if name in EXCLUDE_NAMES:
        return True
    if name.startswith(EXCLUDE_NAME_PREFIX):
        return True
    if name.startswith("ayana-v") and name.endswith((".tar", ".tar.gz")):
        return True
    if name.endswith(EXCLUDE_SUFFIX) and name != "package-lock.json":
        if parts and parts[0] not in ("deploy", "docs", "tests", "ayana", "scripts", "knowledge"):
            return True
    return False


def main() -> int:
    if OUT.exists():
        OUT.unlink()
    n = 0
    with tarfile.open(OUT, "w:gz") as tar:
        for p in ROOT.rglob("*"):
            if not p.is_file():
                continue
            rel = str(p.relative_to(ROOT))
            if skip(rel, p.name):
                continue
            tar.add(p, arcname=rel.replace("\\", "/"))
            n += 1
    print(f"packed {n} files -> {OUT} ({OUT.stat().st_size} bytes)")
    # sanity: must contain main package + install.sh + changelog
    with tarfile.open(OUT, "r:gz") as tar:
        names = tar.getnames()
    for need in ("ayana/main.py", "ayana/health.py", "deploy/install.sh", "CHANGELOG.md", "scripts/migrate_monitor_config.py"):
        assert need in names, f"missing {need}"
    for bad in ("docs/reviews/2026-10-12-full-review.md",):
        assert bad not in names, f"should not pack {bad}"
    print("package sanity ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
