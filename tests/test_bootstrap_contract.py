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
import time


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
        self.native_binary = Path(self.bash)
        if os.name == "nt" and (self.native_binary.parent.parent / "usr/bin/bash.exe").is_file():
            self.native_binary = self.native_binary.parent.parent / "usr/bin/bash.exe"
        self.bin = self.folder / "bin"
        self.bin.mkdir()
        self.work = self.folder / "work"
        self.work.mkdir()
        self.archive = self.folder / "fixture.tar.gz"
        self.urls = self.folder / "fetch-urls.txt"
        self.execution = self.folder / "installation-executed.txt"
        self.mktemp_log = self.folder / "mktemp-used.txt"
        self.check_log = self.folder / "check-args.json"
        self.package_log = self.folder / "packages.txt"
        self.mimo_log = self.folder / "mimo-install-args.txt"
        self.sudo_log = self.folder / "sudo-args.bin"
        self.stage_log = self.folder / "staged-execution.txt"
        self.destination = self.folder / "public/mimo"
        self.home = self.folder / "home"
        self.home.mkdir()
        self.conf_dir = self.folder / "conf"
        self.conf_dir.mkdir()
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
  https://mimo.xiaomi.com/install)
    cat <<'INSTALL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$BOOTSTRAP_TEST_MIMO_LOG"
[[ "${BOOTSTRAP_TEST_MIMO_FAIL:-0}" != 1 ]] || exit 42
mkdir -p "$HOME/.mimocode/bin"
cp "$BOOTSTRAP_TEST_NATIVE_BINARY" "$HOME/.mimocode/bin/mimo"
chmod "${BOOTSTRAP_TEST_MIMO_MODE:-755}" "$HOME/.mimocode/bin/mimo"
INSTALL
    ;;
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

    def bootstrap_invocation(self, args, *, version=None, sha_mode="valid", extra_env=None, default_mode="mimo"):
        # Most archive/dependency contracts select their mode explicitly. Menu
        # contracts pass default_mode=None to exercise a genuinely omitted flag.
        args = list(args or ("--user",))
        if (default_mode is not None and not any(arg == "--agent-mode" or arg.startswith("--agent-mode=") for arg in args)
                and not any(arg in ("--check", "--help", "-h") for arg in args)):
            args.extend(("--agent-mode", default_mode))
        environment = dict(os.environ)
        for key in ("AYANA_VERSION", "AYANA_SHA256", "AYANA_REPO", "AYANA_MIMO_VERSION", "AYANA_MIMO_INSTALL_PATH", "BASH_ENV", "AYANA_BOOTSTRAP_ELEVATED"):
            environment.pop(key, None)
        environment.update({
            "PYTHON_BIN": bash_path(Path(sys.executable)),
            "HOME": bash_path(self.home),
            "AYANA_MIMO_INSTALL_PATH": bash_path(self.destination),
            "BOOTSTRAP_TEST_PACKAGE_LOG": bash_path(self.package_log),
            "BOOTSTRAP_TEST_MIMO_LOG": bash_path(self.mimo_log),
            "BOOTSTRAP_TEST_SUDO_LOG": bash_path(self.sudo_log),
            "BOOTSTRAP_TEST_STAGE_LOG": bash_path(self.stage_log),
            "BOOTSTRAP_TEST_NATIVE_BINARY": bash_path(self.native_binary),
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
        if extra_env:
            environment.update(extra_env)
        if version is not None:
            environment["AYANA_VERSION"] = version
        command = 'export PATH="$BOOTSTRAP_TEST_BIN:/usr/bin:/bin"; exec bash "$BOOTSTRAP_UNDER_TEST" "$@"'
        return [self.bash, "--noprofile", "--norc", "-c", command, "bootstrap-contract", *args], environment

    def run_bootstrap(self, *args: str, version: str | None = None, sha_mode="valid", extra_env=None, default_mode="mimo", cwd=None):
        command, environment = self.bootstrap_invocation(args, version=version, sha_mode=sha_mode,
                                                         extra_env=extra_env, default_mode=default_mode)
        return subprocess.run(command, env=environment, capture_output=True, timeout=30, encoding="utf-8", errors="replace",
                              start_new_session=os.name != "nt", cwd=cwd)

    def run_interactive(self, *args, answer="\n", extra_env=None, stdin_pipe=False):
        if os.name != "posix":
            self.skipTest("PTY menu contracts require POSIX; also exercised by the Linux release smoke")
        import pty
        import select
        command, environment = self.bootstrap_invocation(args, extra_env=extra_env, default_mode=None)
        master, slave = pty.openpty()
        def terminal_session():
            import fcntl
            import termios
            os.setsid()
            fcntl.ioctl(1, termios.TIOCSCTTY, 0)

        process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL if stdin_pipe else slave,
                                   stdout=slave, stderr=slave, start_new_session=not stdin_pipe,
                                   preexec_fn=terminal_session if stdin_pipe else None)
        os.close(slave)
        output = bytearray()
        deadline = time.monotonic() + 30
        try:
            os.write(master, answer.encode())
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        block = os.read(master, 65536)
                    except OSError:
                        break
                    if not block:
                        break
                    output.extend(block)
                elif process.poll() is not None:
                    break
            else:
                self.fail("interactive bootstrap did not terminate")
            process.wait(timeout=5)
            return process.returncode, output.decode("utf-8", errors="replace")
        finally:
            os.close(master)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

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
        self.assertEqual(self.execution.read_text().splitlines(), ["--user", "--agent-mode", "mimo"])
        self.assertEqual(list(self.work.iterdir()), [], "Bootstrap temporary directory was not removed")

    def test_explicit_release_selects_the_versioned_asset_and_passes_installer_options(self):
        result = self.run_bootstrap("--system", "--no-start", version="v0.8.1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.urls.read_text().splitlines(), [
            "https://github.com/wwqjss/Ayana/releases/download/v0.8.1/ayana-0.8.1-install.tar.gz",
            "https://github.com/wwqjss/Ayana/releases/download/v0.8.1/ayana-0.8.1-install.tar.gz.sha256",
        ])
        self.assertEqual(self.execution.read_text().splitlines(), ["--system", "--no-start", "--agent-mode", "mimo"])

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

    def automatic_system(self, *, manager="apt-get", missing="tmux"):
        # Only these harmless fixtures are discoverable as package managers.
        # The real script still runs; no real package manager or installer can run.
        self.write_shell("uname", '#!/usr/bin/env bash\nprintf "Linux\\n"\n')
        self.write_shell("id", '#!/usr/bin/env bash\nprintf "0\\n"\n')
        for name in ("apt-get", "dnf", "yum"):
            self.write_shell(name, r'''#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\n' "${0##*/}" "$*" >> "$BOOTSTRAP_TEST_PACKAGE_LOG"
[[ "${BOOTSTRAP_TEST_PACKAGE_FAIL:-0}" != 1 ]] || exit 43
if [[ "$*" == *install* ]]; then
  touch "$BOOTSTRAP_TEST_BIN/dependencies-ready"
  for package in "$@"; do
    case "$package" in
      openssh-client|openssh-clients) touch "$BOOTSTRAP_TEST_BIN/ready-ssh" "$BOOTSTRAP_TEST_BIN/ready-ssh-keyscan" ;;
      *) touch "$BOOTSTRAP_TEST_BIN/ready-$package" ;;
    esac
  done
fi
''')
        for binary in missing.split():
            if not (self.bin / binary).exists():
                self.write_shell(binary, "#!/usr/bin/env bash\nexit 0\n")
        env_file = self.folder / "mock-command.bash"
        env_file.write_text(r'''command() {
  if [[ "${1:-}" == -v ]]; then
    case "${2:-}" in
      sudo) [[ "${BOOTSTRAP_TEST_NO_SUDO:-0}" != 1 ]] || return 1 ;;
      apt-get|dnf|yum) [[ "$2" == "$BOOTSTRAP_TEST_MANAGER" ]] || return 1 ;;
    esac
    if [[ "${BOOTSTRAP_TEST_OLD_PYTHON:-0}" == 1 && ! -e "$BOOTSTRAP_TEST_BIN/ready-python3.11" ]]; then
      case "$2" in python3|python3.11|python3.12|python3.13) return 1 ;; esac
    fi
    if [[ "${BOOTSTRAP_TEST_MISSING_PYTHON:-0}" == 1 && ! -e "$BOOTSTRAP_TEST_BIN/dependencies-ready" ]]; then
      case "$2" in "$PYTHON_BIN"|python3|python3.11|python3.12|python3.13) return 1 ;; esac
    fi
    if [[ ! -e "$BOOTSTRAP_TEST_BIN/ready-$2" && " ${BOOTSTRAP_TEST_MISSING:-} " == *" $2 "* ]]; then return 1; fi
  fi
  builtin command "$@"
}
''', encoding="utf-8", newline="\n")
        return {"BASH_ENV": bash_path(env_file), "BOOTSTRAP_TEST_MANAGER": manager,
                "BOOTSTRAP_TEST_MISSING": missing}

    def non_root_system(self):
        env = self.automatic_system()
        self.write_shell("id", '#!/usr/bin/env bash\nprintf "1000\\n"\n')
        self.write_shell("sudo", r'''#!/usr/bin/env bash
set -euo pipefail
printf '%s\0' "$@" > "$BOOTSTRAP_TEST_SUDO_LOG"
''')
        return env

    def test_non_root_system_requests_sudo_with_only_allowlisted_options(self):
        env = self.non_root_system()
        values = {"AYANA_REPO": "example/Ayana", "AYANA_SHA256": "f" * 64,
                  "AYANA_MIMO_VERSION": "0.1.17", "SSH_CONNECTION": "192.0.2.1 1234 192.0.2.2 22",
                  "SSH_CLIENT": "192.0.2.1 1234 22", "SSH_TTY": "/dev/pts/7",
                  "UNRELATED_SECRET": "never forward", "AYANA_UNRELATED": "never forward either"}
        env.update(values)
        args = self.system_args("--mimo-bin", "/custom directory/mimo;$(echo untouched)")
        result = self.run_bootstrap(*args, version="v0.8.2", extra_env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        logged = self.sudo_log.read_bytes().decode().rstrip("\0").split("\0")
        self.assertEqual(logged[:2], ["-H", "env"])
        command_at = logged.index("bash")
        passed = dict(item.split("=", 1) for item in logged[2:command_at])
        self.assertEqual(set(passed), {"AYANA_BOOTSTRAP_ELEVATED", "AYANA_VERSION", "AYANA_REPO", "AYANA_SHA256",
                                       "AYANA_MIMO_VERSION", "AYANA_MIMO_INSTALL_PATH", "PYTHON_BIN",
                                       "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"})
        self.assertEqual(passed["AYANA_BOOTSTRAP_ELEVATED"], "1")
        self.assertEqual(passed["AYANA_VERSION"], "v0.8.2")
        for key, value in values.items():
            if key not in {"UNRELATED_SECRET", "AYANA_UNRELATED"}:
                self.assertEqual(passed[key], value)
        self.assertEqual(logged[command_at + 1:], [bash_path(ROOT / "deploy/bootstrap.sh"), *args, "--agent-mode", "mimo"])
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.package_log.exists())
        self.assertFalse(self.execution.exists())

    def test_non_root_without_sudo_explains_root_shell_and_changes_nothing(self):
        env = self.non_root_system()
        env["BOOTSTRAP_TEST_NO_SUDO"] = "1"
        result = self.run_bootstrap(*self.system_args(), extra_env=env)
        self.assert_rejected(result)
        self.assertIn("sudo is unavailable", result.stderr)
        self.assertIn("root shell", result.stderr)
        self.assertFalse(self.sudo_log.exists())
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.package_log.exists())

    def test_failed_sudo_root_transition_does_not_reenter_indefinitely(self):
        env = self.non_root_system()
        env["AYANA_BOOTSTRAP_ELEVATED"] = "1"
        result = self.run_bootstrap(*self.system_args(), extra_env=env)
        self.assert_rejected(result)
        self.assertIn("sudo did not provide root access", result.stderr)
        self.assertFalse(self.sudo_log.exists())
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.package_log.exists())

    def test_root_entry_needs_no_sudo_even_after_elevation_marker(self):
        env = self.automatic_system()
        env.update({"AYANA_BOOTSTRAP_ELEVATED": "1", "BOOTSTRAP_TEST_NO_SUDO": "1"})
        result = self.run_bootstrap(*self.system_args("--mimo-bin", "/existing/mimo"), extra_env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.sudo_log.exists())
        self.assertTrue(self.execution.exists())

    def test_non_root_check_help_no_start_and_user_never_request_sudo(self):
        env = self.non_root_system()
        for args, expected in ((("--system", "--check", "--prefix", bash_path(self.folder / "absent")), 2),
                               (("--system", "--help"), 0), (("--system", "--no-start"), 0), (("--user",), 0)):
            with self.subTest(args=args):
                result = self.run_bootstrap(*args, extra_env=env)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertFalse(self.sudo_log.exists())
                self.assertFalse(self.package_log.exists())
                self.assertFalse(self.mimo_log.exists())

    def system_args(self, *args):
        return ("--system", "--conf-dir", bash_path(self.conf_dir), "--prefix", bash_path(self.folder / "app"), *args)

    def test_system_installs_missing_dependencies_and_official_pinned_mimo(self):
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("apt-get update", self.package_log.read_text())
        self.assertIn("apt-get install -y --no-install-recommends", self.package_log.read_text())
        self.assertIn("tmux", self.package_log.read_text())
        self.assertEqual(self.mimo_log.read_text().splitlines(), ["--no-modify-path", "--version", "0.1.16"])
        self.assertTrue(self.destination.is_file())
        self.assertFalse(self.destination.is_symlink())
        self.assertEqual(list(self.destination.parent.glob(".ayana-mimo.*")), [])
        self.assertEqual(self.execution.read_text().splitlines()[-2:], ["--mimo-bin", bash_path(self.destination)])
        self.assertEqual(self.urls.read_text().splitlines()[-1], "https://mimo.xiaomi.com/install")
        self.assertEqual(list(self.work.iterdir()), [])

    def test_lite_system_install_skips_mimo_and_tmux(self):
        result = self.run_bootstrap(*self.system_args('--agent-mode', 'lite'),
                                    extra_env=self.automatic_system(missing='tmux'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        if self.package_log.exists():
            self.assertNotIn('tmux', self.package_log.read_text(), 'Lite attempted to install its missing terminal dependency')
        self.assertFalse(self.mimo_log.exists())
        self.assertFalse(self.destination.exists())
        self.assertNotIn('https://mimo.xiaomi.com/install', self.urls.read_text())
        self.assertIn('background automatic duty only', result.stdout)
        self.assertIn('--agent-mode\nlite', self.execution.read_text())

    def test_fresh_noninteractive_install_requires_a_mode_before_any_changes(self):
        self.reject_mktemp()
        result = self.run_bootstrap(default_mode=None)
        self.assert_rejected(result)
        self.assertIn('--agent-mode lite', result.stderr)
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.package_log.exists())
        self.assertFalse(self.mktemp_log.exists())

    def test_interactive_default_selects_lightweight_before_download(self):
        code, output = self.run_interactive('--user', answer='\n')
        self.assertEqual(code, 0, output)
        self.assertIn('轻量安装', output)
        self.assertIn('完整安装', output)
        self.assertIn('占用较低', output)
        self.assertLess(output.index('请选择 Ayana'), output.index('Downloading Ayana'))
        self.assertEqual(self.execution.read_text().splitlines(), ['--user', '--agent-mode', 'lite'])
        self.assertFalse(self.mimo_log.exists())

    def test_interactive_invalid_input_can_be_corrected_to_complete_mode(self):
        code, output = self.run_interactive('--user', answer='invalid\n2\n')
        self.assertEqual(code, 0, output)
        self.assertIn('请输入 1（轻量）或 2（完整）', output)
        self.assertEqual(self.execution.read_text().splitlines()[-2:], ['--agent-mode', 'mimo'])

    def test_interactive_eof_stops_without_download_or_installation(self):
        code, output = self.run_interactive('--user', answer='\x04')
        self.assertNotEqual(code, 0, output)
        self.assertIn('未读取到安装选择', output)
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.package_log.exists())
        self.assertFalse(self.execution.exists())

    def test_interactive_upgrade_defaults_to_its_current_mode(self):
        (self.conf_dir / 'config.json').write_text(json.dumps({'agent_mode': 'mimo'}))
        code, output = self.run_interactive('--user', '--conf-dir', bash_path(self.conf_dir), answer='\n')
        self.assertEqual(code, 0, output)
        self.assertIn('沿用当前完整安装', output)
        self.assertEqual(self.execution.read_text().splitlines()[-2:], ['--agent-mode', 'mimo'])

    def test_interactive_choice_is_forwarded_to_sudo_without_reprompting(self):
        env = self.non_root_system()
        self.write_shell('id', r'''#!/usr/bin/env bash
if [[ "${AYANA_BOOTSTRAP_ELEVATED:-0}" == 1 ]]; then printf '0\n'; else printf '1000\n'; fi
''')
        self.write_shell('sudo', r'''#!/usr/bin/env bash
set -euo pipefail
printf '%s\0' "$@" > "$BOOTSTRAP_TEST_SUDO_LOG"
[[ "${1:-}" != -H ]] || shift
exec "$@"
''')
        code, output = self.run_interactive(*self.system_args(), answer='1\n', extra_env=env)
        self.assertEqual(code, 0, output)
        self.assertEqual(output.count('请选择 Ayana 安装方式'), 1)
        logged = self.sudo_log.read_bytes().decode().rstrip('\0').split('\0')
        self.assertEqual(logged[-2:], ['--agent-mode', 'lite'])
        self.assertTrue(self.execution.exists())
        self.assertFalse(self.mimo_log.exists())

    def test_interactive_menu_reads_the_controlling_terminal_when_stdin_is_piped(self):
        code, output = self.run_interactive('--user', answer='1\n', stdin_pipe=True)
        self.assertEqual(code, 0, output)
        self.assertEqual(self.execution.read_text().splitlines()[-2:], ['--agent-mode', 'lite'])

    def test_explicit_mode_skips_the_interactive_menu(self):
        result = self.run_bootstrap('--user', '--agent-mode', 'lite', default_mode=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('请选择 Ayana', result.stdout + result.stderr)
        self.assertIn('--agent-mode\nlite', self.execution.read_text())

    def test_root_discovers_saved_mode_and_keeps_all_installer_arguments(self):
        managed = self.folder / 'managed'
        (managed / 'config').mkdir(parents=True)
        (managed / 'config/config.json').write_text(json.dumps({'agent_mode': 'lite'}))
        result = self.run_bootstrap('--user', '--root', bash_path(managed), default_mode=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.execution.read_text().splitlines(), ['--user', '--root', bash_path(managed)])
        self.assertIn('Agent mode: lite', result.stdout)
        self.assertFalse(self.mimo_log.exists())

    def test_new_full_install_places_its_cli_under_the_program_directory(self):
        env = self.automatic_system()
        env['AYANA_MIMO_INSTALL_PATH'] = ''
        result = self.run_bootstrap(*self.system_args(), extra_env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        destination = self.folder / 'app/bin/mimo'
        self.assertTrue(destination.is_file())
        self.assertEqual(self.execution.read_text().splitlines()[-2:], ['--mimo-bin', bash_path(destination)])

    def test_relative_root_still_places_the_cli_in_the_resolved_app_directory(self):
        env = self.automatic_system()
        env['AYANA_MIMO_INSTALL_PATH'] = ''
        result = self.run_bootstrap('--system', '--root', 'managed', extra_env=env, cwd=self.folder)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        destination = self.folder / 'managed/app/bin/mimo'
        self.assertTrue(destination.is_file())
        passed = self.execution.read_text().splitlines()[-2:]
        self.assertEqual(passed[0], '--mimo-bin')
        if os.name == 'nt':
            converted = subprocess.run([self.bash, '--noprofile', '--norc', '-c', 'cygpath -w "$1"', 'path-check', passed[1]],
                                       capture_output=True, text=True, check=True, timeout=5)
            self.assertEqual(Path(converted.stdout.strip()).resolve(), destination.resolve())
        else:
            self.assertEqual(Path(passed[1]).resolve(), destination.resolve())

    def test_omitted_mode_preserves_an_installed_lite_configuration(self):
        path = self.conf_dir / 'config.json'
        original = json.dumps({'agent_mode': 'lite', 'mimo_bin': '/old/unavailable/mimo'})
        path.write_text(original)
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system(missing='tmux'), default_mode=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        if self.package_log.exists():
            self.assertNotIn('tmux', self.package_log.read_text())
        self.assertFalse(self.mimo_log.exists())
        self.assertNotIn('--mimo-bin', self.execution.read_text())
        self.assertEqual(path.read_text(), original)

    def test_switch_from_lite_to_mimo_can_prepare_the_missing_cli(self):
        path = self.conf_dir / 'config.json'
        path.write_text(json.dumps({'agent_mode': 'lite'}))
        result = self.run_bootstrap(*self.system_args('--agent-mode=mimo'), extra_env=self.automatic_system())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.destination.is_file())
        self.assertTrue(self.mimo_log.exists())
        self.assertIn('tmux', self.package_log.read_text())
        self.assertEqual(json.loads(path.read_text())['agent_mode'], 'lite',
                         'Bootstrap changed the mode before the real installer checked old tasks')

    def test_invalid_mode_is_rejected_before_download_or_package_installation(self):
        for option in (('--agent-mode', 'typo'), ('--agent-mode=',)):
            with self.subTest(option=option):
                result = self.run_bootstrap(*self.system_args(*option), extra_env=self.automatic_system())
                self.assert_rejected(result)
                self.assertFalse(self.urls.exists())
                self.assertFalse(self.package_log.exists())
                self.assertFalse(self.mimo_log.exists())

    def test_fresh_apt_host_installs_python_venv_before_download(self):
        env = self.automatic_system(missing="curl tmux")
        env["BOOTSTRAP_TEST_MISSING_PYTHON"] = "1"
        result = self.run_bootstrap(*self.system_args("--mimo-bin", "/existing/mimo"), extra_env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("python3 python3-venv python3-pip", self.package_log.read_text())
        self.assertIn("curl", self.package_log.read_text())
        self.assertFalse(self.mimo_log.exists())

    def test_old_default_python_tries_versioned_apt_python(self):
        self.write_shell("old-python", r'''#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == -c && "${2:-}" == *sys.version_info* && ! -e "$BOOTSTRAP_TEST_BIN/ready-python3.11" ]]; then exit 1; fi
exec "$BOOTSTRAP_TEST_REAL_PYTHON" "$@"
''')
        env = self.automatic_system()
        env.update({"PYTHON_BIN": bash_path(self.bin / "old-python"),
                    "BOOTSTRAP_TEST_REAL_PYTHON": bash_path(Path(sys.executable)), "BOOTSTRAP_TEST_OLD_PYTHON": "1"})
        result = self.run_bootstrap(*self.system_args("--mimo-bin", "/existing/mimo"), extra_env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("python3.11 python3.11-venv python3-pip", self.package_log.read_text())

    def test_dnf_and_yum_use_their_package_manager(self):
        for manager in ("dnf", "yum"):
            with self.subTest(manager=manager):
                self.package_log.unlink(missing_ok=True)
                (self.bin / "dependencies-ready").unlink(missing_ok=True)
                for marker in self.bin.glob("ready-*"):
                    marker.unlink()
                env = self.automatic_system(manager=manager, missing="ssh ssh-keyscan tmux")
                result = self.run_bootstrap(*self.system_args("--mimo-bin", "/existing/mimo"), extra_env=env)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(manager + " install -y", self.package_log.read_text())
                self.assertIn("openssh-clients", self.package_log.read_text())
                self.assertFalse(self.mimo_log.exists())

    def test_explicit_mimo_is_forwarded_without_third_party_installation(self):
        result = self.run_bootstrap(*self.system_args("--mimo-bin=/custom/mimo"), extra_env=self.automatic_system())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--mimo-bin=/custom/mimo", self.execution.read_text().splitlines())
        self.assertFalse(self.mimo_log.exists())
        self.assertFalse(self.destination.exists())

    def test_existing_configuration_is_authoritative_including_legacy_binding(self):
        for config in ({"mimo_bin": "/existing/mimo"}, {"auto_investigate": {"mimo_bin": "/legacy/mimo"}}):
            with self.subTest(config=config):
                (self.conf_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")
                result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("--mimo-bin", self.execution.read_text().splitlines())
                self.assertFalse(self.mimo_log.exists())
                self.assertFalse(self.destination.exists())

    def test_existing_installation_without_cli_is_not_silently_upgraded(self):
        (self.conf_dir / "config.json").write_text("{}", encoding="utf-8")
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assert_rejected(result)
        self.assertIn("Existing Ayana installation", result.stderr)
        self.assertFalse(self.mimo_log.exists())

    def test_public_cli_is_reused_without_overwriting_it(self):
        self.write_shell("mimo", '#!/usr/bin/env bash\nprintf "existing\\n"\n')
        original = (self.bin / "mimo").read_bytes()
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.bin / "mimo").read_bytes(), original)
        self.assertFalse(self.mimo_log.exists())
        self.assertEqual(self.execution.read_text().splitlines()[-2:], ["--mimo-bin", bash_path(self.bin / "mimo")])

    def test_home_path_shadowing_reuses_existing_public_cli_without_overwriting(self):
        self.write_shell("mimo", '#!/usr/bin/env bash\nexit 99\n')
        self.write_shell("realpath", r'''#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == "$BOOTSTRAP_TEST_BIN/mimo" ]]; then printf '/root/.mimocode/bin/mimo\n'; else exec /usr/bin/realpath "$@"; fi
''')
        self.destination.parent.mkdir()
        shutil.copyfile(self.native_binary, self.destination)
        self.destination.chmod(0o755)
        original = self.destination.read_bytes()
        # This also covers a prior Ayana installation whose CLI was never bound.
        (self.conf_dir / "config.json").write_text("{}", encoding="utf-8")
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.destination.read_bytes(), original)
        self.assertFalse(self.mimo_log.exists())
        self.assertEqual(self.execution.read_text().splitlines()[-2:], ["--mimo-bin", bash_path(self.destination)])
        self.assertEqual(list(self.destination.parent.glob(".ayana-mimo.*")), [])

    def test_existing_public_destination_resolving_into_home_is_rejected(self):
        self.destination.parent.mkdir()
        shutil.copyfile(self.native_binary, self.destination)
        self.destination.chmod(0o755)
        # Simulate a protected symlink without requiring Windows symlink rights.
        self.write_shell("realpath", r'''#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == "$AYANA_MIMO_INSTALL_PATH" ]]; then printf '/root/.mimocode/bin/mimo\n'; else exec /usr/bin/realpath "$@"; fi
''')
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assert_rejected(result)
        self.assertIn("protected home directory", result.stderr)
        self.assertFalse(self.mimo_log.exists())
        self.assertEqual(self.destination.read_bytes(), self.native_binary.read_bytes())

    def test_root_home_standalone_binary_is_copied_without_official_download(self):
        source = self.home / ".mimocode/bin/mimo"
        source.parent.mkdir(parents=True)
        shutil.copyfile(self.native_binary, source)
        source.chmod(0o644)
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(source.read_bytes(), self.destination.read_bytes())
        self.assertFalse(self.mimo_log.exists())

    def test_noexec_download_candidate_is_never_run_before_public_staging(self):
        env = self.automatic_system()
        env["BOOTSTRAP_TEST_MIMO_MODE"] = "644"
        # Git Bash does not enforce POSIX execute bits. Guard the exact source
        # invocation too, so this noexec contract has the same meaning there.
        with (self.folder / "mock-command.bash").open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(r'''
bootstrap_execution_guard() {
  case "${BASH_COMMAND:-}" in
    '"$candidate" --version'*) printf 'source executed\n' >> "$BOOTSTRAP_TEST_STAGE_LOG"; exit 97 ;;
    '"$STAGED_MIMO" --version'*) printf 'staged:%s\n' "$STAGED_MIMO" >> "$BOOTSTRAP_TEST_STAGE_LOG" ;;
  esac
}
set -o functrace
trap bootstrap_execution_guard DEBUG
''')
        result = self.run_bootstrap(*self.system_args(), extra_env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        logged = self.stage_log.read_text().splitlines()
        self.assertEqual(len(logged), 1)
        self.assertTrue(logged[0].startswith("staged:" + bash_path(self.destination.parent) + "/.ayana-mimo."), logged)
        self.assertTrue(self.destination.is_file())
        self.assertEqual(list(self.destination.parent.glob(".ayana-mimo.*")), [])
        self.assertEqual(list(self.work.iterdir()), [])

    def test_failed_staged_version_cleans_staging_and_never_publishes_destination(self):
        self.write_shell("install", r'''#!/usr/bin/env bash
set -euo pipefail
/usr/bin/install "$@"
target="${@: -1}"
printf '#!/usr/bin/env bash\nexit 54\n' > "$target"
chmod 755 "$target"
''')
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assert_rejected(result)
        self.assertIn("Staged MiMoCode --version failed", result.stderr)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.destination.parent.glob(".ayana-mimo.*")), [])
        self.assertEqual(list(self.work.iterdir()), [])

    def test_racing_destination_is_never_replaced_and_staging_is_cleaned(self):
        self.write_shell("ln", r'''#!/usr/bin/env bash
set -euo pipefail
target="${@: -1}"
printf 'concurrent installation\n' > "$target"
exec /usr/bin/ln "$@"
''')
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assert_rejected(result)
        self.assertIn("without replacing an existing destination", result.stderr)
        self.assertEqual(self.destination.read_text(), "concurrent installation\n")
        self.assertEqual(list(self.destination.parent.glob(".ayana-mimo.*")), [])
        self.assertEqual(list(self.work.iterdir()), [])

    def test_home_wrapper_is_rejected_without_copying_incomplete_runtime(self):
        source = self.home / ".mimocode/bin/mimo"
        source.parent.mkdir(parents=True)
        source.write_text('#!/usr/bin/env bash\nexit 0\n', encoding="utf-8", newline="\n")
        source.chmod(0o755)
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assert_rejected(result)
        self.assertIn("standalone binary", result.stderr)
        self.assertFalse(self.destination.exists())

    def test_existing_destination_is_never_overwritten(self):
        self.destination.parent.mkdir()
        self.destination.write_text("do not replace", encoding="utf-8")
        self.destination.chmod(0o644)
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system())
        self.assert_rejected(result)
        self.assertEqual(self.destination.read_text(), "do not replace")
        self.assertFalse(self.mimo_log.exists())

    def test_package_manager_failure_stops_before_download_or_execution(self):
        env = self.automatic_system(missing="curl")
        env["BOOTSTRAP_TEST_PACKAGE_FAIL"] = "1"
        result = self.run_bootstrap(*self.system_args(), extra_env=env)
        self.assert_rejected(result)
        self.assertIn("failed", result.stderr)
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.mimo_log.exists())

    def test_official_installer_failure_never_executes_ayana_installer(self):
        env = self.automatic_system()
        env["BOOTSTRAP_TEST_MIMO_FAIL"] = "1"
        result = self.run_bootstrap(*self.system_args(), extra_env=env)
        self.assert_rejected(result)
        self.assertIn("Official MiMoCode installation failed", result.stderr)
        self.assertFalse(self.destination.exists())

    def test_system_bad_archive_never_installs_runtime_dependencies_or_mimo(self):
        self.make_archive(dangerous="symlink")
        result = self.run_bootstrap(*self.system_args(), extra_env=self.automatic_system(missing="tmux"))
        self.assert_rejected(result)
        self.assertFalse(self.mimo_log.exists())
        if self.package_log.exists():
            self.assertNotIn("tmux", self.package_log.read_text())

    def test_no_start_and_user_do_not_prepare_environment(self):
        for args in (("--system", "--no-start"), ("--user",)):
            with self.subTest(args=args):
                result = self.run_bootstrap(*args, extra_env=self.automatic_system())
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.package_log.exists())
                self.assertFalse(self.mimo_log.exists())
                self.assertFalse(self.destination.exists())

    def test_system_check_and_help_do_not_prepare_environment(self):
        self.reject_mktemp()
        for args in (("--system", "--check", "--prefix", bash_path(self.folder / "absent")), ("--system", "--help")):
            with self.subTest(args=args):
                result = self.run_bootstrap(*args, extra_env=self.automatic_system())
                self.assertIn(result.returncode, (0, 2), result.stdout + result.stderr)
                self.assertFalse(self.urls.exists())
                self.assertFalse(self.mktemp_log.exists())
                self.assertFalse(self.package_log.exists())
                self.assertFalse(self.mimo_log.exists())

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

    def test_unified_root_check_invokes_only_the_local_app_verifier(self):
        self.reject_mktemp()
        managed = self.folder / 'managed'
        (managed / 'app/deploy').mkdir(parents=True)
        (managed / 'app/deploy/installation.py').write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['BOOTSTRAP_TEST_CHECK_LOG_NATIVE']).write_text(json.dumps(sys.argv[1:]))\n",
            encoding='utf-8')
        result = self.run_bootstrap('--check', '--root', bash_path(managed), default_mode=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        logged = json.loads(self.check_log.read_text())
        self.assertEqual(logged[:3], ['install', '--check', '--root'])
        self.assertEqual(Path(logged[3]).resolve(), managed.resolve())
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.mktemp_log.exists())

    def test_default_check_can_find_a_legacy_user_verifier_without_configuration(self):
        self.reject_mktemp()
        managed = self.home / '.local/share/ayana'
        (managed / 'deploy').mkdir(parents=True)
        (managed / 'deploy/installation.py').write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['BOOTSTRAP_TEST_CHECK_LOG_NATIVE']).write_text(json.dumps(sys.argv[1:]))\n",
            encoding='utf-8')
        result = self.run_bootstrap('--user', '--check', default_mode=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(self.check_log.read_text()), ['install', '--user', '--check'])
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.mktemp_log.exists())

    def test_explicit_missing_prefix_does_not_fall_back_to_another_installation(self):
        self.reject_mktemp()
        managed = self.home / '.local/share/ayana'
        (managed / 'deploy').mkdir(parents=True)
        (managed / 'deploy/installation.py').write_text(
            "import os, pathlib\npathlib.Path(os.environ['BOOTSTRAP_TEST_CHECK_LOG_NATIVE']).write_text('wrong verifier')\n",
            encoding='utf-8')
        result = self.run_bootstrap('--user', '--check', '--prefix', bash_path(self.folder / 'absent'), default_mode=None)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(self.check_log.exists())
        self.assertFalse(self.urls.exists())
        self.assertFalse(self.mktemp_log.exists())


if __name__ == "__main__":
    unittest.main()
