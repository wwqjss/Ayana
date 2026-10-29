"""Run the real bootstrap with local archives and a fake fetcher; never install or use the network."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def find_bash() -> str | None:
    override = os.environ.get("AYANA_BASH")
    candidates = [override] if override else []
    if not override:
        if os.name == "nt":
            candidates.extend(str(Path(base) / "Git/bin/bash.exe") for base in (
                os.environ.get("ProgramFiles", "C:/Program Files"),
                os.environ.get("ProgramW6432", "C:/Program Files"),
            ))
        candidates.append(shutil.which("bash"))
    for candidate in candidates:
        if not candidate:
            continue
        resolved = shutil.which(candidate) or candidate
        if not Path(resolved).is_file():
            continue
        try:
            result = subprocess.run([resolved, "--version"], capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and b"GNU bash" in result.stdout:
            return str(resolved)
    return None


def bash_path(path: Path) -> str:
    value = path.resolve().as_posix()
    if os.name == "nt" and len(value) > 2 and value[1:3] == ":/":
        return "/" + value[0].lower() + value[2:]
    return value


class BootstrapContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = find_bash()
        if cls.bash is None:
            raise unittest.SkipTest("GNU Bash is unavailable; set AYANA_BASH to a Bash executable")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ayana-bootstrap-contract-", ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.bin = self.folder / "bin"
        self.bin.mkdir()
        self.work = self.folder / "work"
        self.work.mkdir()
        self.archive = self.folder / "fixture.tar.gz"
        self.urls = self.folder / "fetch-urls.txt"
        self.execution = self.folder / "installation-executed.txt"
        self.mktemp_log = self.folder / "mktemp-used.txt"
        self.check_log = self.folder / "check-args.json"
        self.write_shell("curl", r'''#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
printf '%s\n' "$url" >> "$BOOTSTRAP_TEST_URLS"
case "$url" in
  *.sha256)
    case "${BOOTSTRAP_TEST_SHA_MODE:-valid}" in
      missing) exit 22 ;;
      mismatch) printf '%064d  fixture.tar.gz\n' 0 ;;
      valid) printf '%s  fixture.tar.gz\n' "$BOOTSTRAP_TEST_DIGEST" ;;
      *) exit 90 ;;
    esac ;;
  *.tar.gz) cat "$BOOTSTRAP_TEST_PACKAGE" ;;
  *) exit 91 ;;
esac
''')
        self.make_archive()

    def write_shell(self, name: str, source: str):
        target = self.bin / name
        target.write_text(source, encoding="utf-8", newline="\n")
        target.chmod(0o755)

    def make_archive(self, *, dangerous: str = ""):
        install = b'#!/usr/bin/env bash\nset -eu\nprintf "%s\\n" "$@" > "$BOOTSTRAP_TEST_EXECUTION"\n'
        with tarfile.open(self.archive, "w:gz") as archive:
            entry = tarfile.TarInfo("deploy/install.sh")
            entry.size, entry.mode = len(install), 0o755
            archive.addfile(entry, io.BytesIO(install))
            if dangerous in ("traversal", "absolute"):
                entry = tarfile.TarInfo("../escape.txt" if dangerous == "traversal" else "/escape.txt")
                entry.size = 4
                archive.addfile(entry, io.BytesIO(b"evil"))
            elif dangerous in ("symlink", "hardlink"):
                entry = tarfile.TarInfo("linked")
                entry.type = tarfile.SYMTYPE if dangerous == "symlink" else tarfile.LNKTYPE
                entry.linkname = "deploy/install.sh"
                archive.addfile(entry)

    def run_bootstrap(self, *args: str, version: str | None = None, sha_mode="valid"):
        environment = dict(os.environ)
        for key in ("AYANA_VERSION", "AYANA_SHA256", "AYANA_REPO"):
            environment.pop(key, None)
        environment.update({
            "PYTHON_BIN": bash_path(Path(sys.executable)),
            "TMPDIR": bash_path(self.work),
            "BOOTSTRAP_TEST_BIN": bash_path(self.bin),
            "BOOTSTRAP_UNDER_TEST": bash_path(ROOT / "deploy/bootstrap.sh"),
            "BOOTSTRAP_TEST_PACKAGE": bash_path(self.archive),
            "BOOTSTRAP_TEST_URLS": bash_path(self.urls),
            "BOOTSTRAP_TEST_EXECUTION": bash_path(self.execution),
            "BOOTSTRAP_TEST_MKTEMP": bash_path(self.mktemp_log),
            # Native Python does not interpret Git Bash's /c mount syntax.
            "BOOTSTRAP_TEST_CHECK_LOG_NATIVE": str(self.check_log),
            "BOOTSTRAP_TEST_DIGEST": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "BOOTSTRAP_TEST_SHA_MODE": sha_mode,
        })
        if version is not None:
            environment["AYANA_VERSION"] = version
        command = 'export PATH="$BOOTSTRAP_TEST_BIN:/usr/bin:/bin"; exec bash "$BOOTSTRAP_UNDER_TEST" "$@"'
        return subprocess.run([self.bash, "--noprofile", "--norc", "-c", command, "bootstrap-contract", *args],
                              env=environment, capture_output=True, timeout=30, encoding="utf-8", errors="replace")

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.execution.exists(), "Rejected archive reached its installation entry point")

    def test_latest_selects_the_stable_asset_and_defaults_to_user_mode(self):
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.urls.read_text().splitlines(), [
            "https://github.com/wwqjss/Ayana/releases/latest/download/ayana-install.tar.gz",
            "https://github.com/wwqjss/Ayana/releases/latest/download/ayana-install.tar.gz.sha256",
        ])
        self.assertEqual(self.execution.read_text().splitlines(), ["--user"])
        self.assertEqual(list(self.work.iterdir()), [], "Bootstrap temporary directory was not removed")

    def test_explicit_release_selects_the_versioned_asset_and_passes_installer_options(self):
        result = self.run_bootstrap("--system", "--no-start", version="v0.8.1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.urls.read_text().splitlines(), [
            "https://github.com/wwqjss/Ayana/releases/download/v0.8.1/ayana-0.8.1-install.tar.gz",
            "https://github.com/wwqjss/Ayana/releases/download/v0.8.1/ayana-0.8.1-install.tar.gz.sha256",
        ])
        self.assertEqual(self.execution.read_text().splitlines(), ["--system", "--no-start"])

    def test_checksum_mismatch_never_executes_the_package(self):
        result = self.run_bootstrap(sha_mode="mismatch")
        self.assert_rejected(result)
        self.assertIn("SHA256 mismatch", result.stderr)

    def test_missing_checksum_sidecar_never_executes_the_package(self):
        result = self.run_bootstrap(sha_mode="missing")
        self.assert_rejected(result)
        self.assertEqual(len(self.urls.read_text().splitlines()), 2)

    def test_tar_traversal_and_absolute_paths_are_rejected_before_extraction(self):
        for dangerous in ("traversal", "absolute"):
            with self.subTest(member=dangerous):
                self.make_archive(dangerous=dangerous)
                result = self.run_bootstrap()
                self.assert_rejected(result)
                self.assertIn("Unsafe release archive", result.stderr)
                self.assertFalse((self.work / "escape.txt").exists())

    def test_tar_symbolic_and_hard_links_are_rejected_before_extraction(self):
        for dangerous in ("symlink", "hardlink"):
            with self.subTest(member=dangerous):
                self.make_archive(dangerous=dangerous)
                result = self.run_bootstrap()
                self.assert_rejected(result)
                self.assertIn("Unsafe release archive", result.stderr)

    def reject_mktemp(self):
        self.write_shell("mktemp", r'''#!/usr/bin/env bash
printf 'unexpected\n' > "$BOOTSTRAP_TEST_MKTEMP"
exit 97
''')

    def test_uninstalled_check_never_fetches_or_creates_a_work_directory(self):
        self.reject_mktemp()
        prefix = self.folder / "not-installed"
        result = self.run_bootstrap("--check", "--prefix", bash_path(prefix))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.mktemp_log.exists())
        self.assertFalse(prefix.exists())
        self.assertFalse(self.execution.exists())

    def test_installed_check_invokes_only_the_local_verifier(self):
        self.reject_mktemp()
        prefix = self.folder / "installed"
        (prefix / "deploy").mkdir(parents=True)
        (prefix / "deploy/installation.py").write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['BOOTSTRAP_TEST_CHECK_LOG_NATIVE']).write_text(json.dumps(sys.argv[1:]))\n",
            encoding="utf-8")
        result = self.run_bootstrap("--check", "--prefix", bash_path(prefix))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(self.check_log.read_text())[:2], ["install", "--check"])
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.mktemp_log.exists())
        self.assertFalse(self.execution.exists())


if __name__ == "__main__":
    unittest.main()
