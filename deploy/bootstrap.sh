#!/usr/bin/env bash
# Download the current public release; verify SHA256 before extraction/execution.
# AYANA_VERSION=latest (default) or a tag such as vX.Y.Z. No unverified fallback.
set -euo pipefail
VERSION="${AYANA_VERSION:-latest}"
REPO="${AYANA_REPO:-wwqjss/Ayana}"
ARGS=("$@")
[[ ${#ARGS[@]} -gt 0 ]] || ARGS=(--user)
fail() { printf '%s\n' "$*" >&2; exit 1; }
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 20 "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO- "$1"
  else printf 'Need curl or wget\n' >&2; return 1; fi
}
# A bootstrap check neither downloads nor creates a work directory.
CHECK=0; SYSTEM=0; NO_START=0; PREFIX=""; CONF_DIR=/etc/ayana; EXPLICIT_MIMO=0
for ((i=0; i<${#ARGS[@]}; i++)); do
  case "${ARGS[i]}" in
    -h|--help) printf 'Usage: bootstrap.sh [--system|--user] [installer options]\n--system prepares Linux dependencies and MiMoCode; --user/--no-start use existing dependencies.\nAYANA_VERSION=latest or a release tag; SHA256 verification is required.\nAYANA_MIMO_VERSION=0.1.16 by default; AYANA_MIMO_INSTALL_PATH=/usr/local/bin/mimo.\n'; exit 0 ;;
    --check) CHECK=1 ;;
    --system) SYSTEM=1 ;;
    --no-start) NO_START=1 ;;
    --prefix) PREFIX="${ARGS[i+1]:?missing prefix}" ;;
    --prefix=*) PREFIX="${ARGS[i]#*=}" ;;
    --conf-dir|--conf) CONF_DIR="${ARGS[i+1]:?missing config directory}" ;;
    --conf-dir=*|--conf=*) CONF_DIR="${ARGS[i]#*=}" ;;
    --mimo-bin|--mimo-bin=*) EXPLICIT_MIMO=1 ;;
  esac
done
if [[ "$CHECK" == 1 ]]; then
  if [[ -z "$PREFIX" ]]; then
    if [[ "$SYSTEM" == 1 ]]; then PREFIX=/opt/ayana; else PREFIX="$HOME/.local/share/ayana"; fi
  fi
  if [[ -f "$PREFIX/deploy/installation.py" ]]; then
    exec "${PYTHON_BIN:-python3}" "$PREFIX/deploy/installation.py" install "${ARGS[@]}"
  fi
  printf 'No installed verifier at %s; no files downloaded or changed.\n' "$PREFIX" >&2
  exit 2
fi
if [[ "$VERSION" == latest ]]; then
  PART=latest/download; ASSET=ayana-install.tar.gz
else
  [[ "$VERSION" =~ ^v?[0-9][0-9A-Za-z.-]*$ ]] || fail 'Invalid version'
  PART="download/$VERSION"; ASSET="ayana-${VERSION#v}-install.tar.gz"
fi
AUTO=0
if [[ "$SYSTEM" == 1 && "$NO_START" == 0 ]]; then
  [[ "$(uname -s)" == Linux ]] || fail 'Automatic system installation requires Linux; use --user or --no-start with prepared dependencies.'
  if [[ "$(id -u)" != 0 ]]; then
    [[ "${AYANA_BOOTSTRAP_ELEVATED:-0}" != 1 ]] || fail 'sudo did not provide root access; run this installer from a root shell.'
    command -v sudo >/dev/null 2>&1 || fail 'System installation needs root access and sudo is unavailable; switch to a root shell and run bash ayana-bootstrap.sh --system.'
    # Preserve only installer choices and SSH access context across sudo. Do not
    # forward the caller's entire environment (PATH, shell hooks or credentials).
    ELEVATED_ENV=(AYANA_BOOTSTRAP_ELEVATED=1)
    for name in AYANA_VERSION AYANA_REPO AYANA_SHA256 AYANA_MIMO_VERSION AYANA_MIMO_INSTALL_PATH PYTHON_BIN SSH_CONNECTION SSH_CLIENT SSH_TTY; do
      if [[ -v "$name" ]]; then ELEVATED_ENV+=("$name=${!name}"); fi
    done
    printf 'Requesting root access for system installation.\n'
    exec sudo -H env "${ELEVATED_ENV[@]}" bash "$0" "${ARGS[@]}"
  fi
  AUTO=1
fi
select_python() {
  local candidate
  for candidate in "${PYTHON_BIN:-python3}" python3.13 python3.12 python3.11; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3,11))' >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"; export PYTHON_BIN; return 0
    fi
  done
  return 1
}
package_install() {
  if command -v apt-get >/dev/null 2>&1; then
    if [[ "${APT_UPDATED:-0}" != 1 ]]; then apt-get update || fail 'apt-get update failed; installation stopped.'; APT_UPDATED=1; fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" || fail 'System dependency installation failed; installation stopped.'
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$@" || fail 'System dependency installation failed; installation stopped.'
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$@" || fail 'System dependency installation failed; installation stopped.'
  else
    fail 'No supported package manager (apt-get/dnf/yum); prepare Python >=3.11, venv, curl, CA certificates, tmux and OpenSSH, then retry.'
  fi
}
prepare_dependencies() {
  local packages=() apt=0 phase="${1:-all}"
  command -v apt-get >/dev/null 2>&1 && apt=1
  if ! select_python; then
    if [[ "$apt" == 1 ]]; then packages+=(python3 python3-venv python3-pip)
    else packages+=(python3.11 python3.11-pip); fi
  elif ! "$PYTHON_BIN" -c 'import ensurepip, venv' >/dev/null 2>&1; then
    if [[ "$apt" == 1 ]]; then
      packages+=("$("$PYTHON_BIN" -c 'import sys; print("python%d.%d-venv" % sys.version_info[:2])')")
    else packages+=(python3.11-pip); fi
  fi
  command -v curl >/dev/null 2>&1 || packages+=(curl)
  if [[ "$phase" == all ]]; then
    command -v tmux >/dev/null 2>&1 || packages+=(tmux)
    if ! command -v ssh >/dev/null 2>&1 || ! command -v ssh-keyscan >/dev/null 2>&1; then
      if [[ "$apt" == 1 ]]; then packages+=(openssh-client); else packages+=(openssh-clients); fi
    fi
    command -v tar >/dev/null 2>&1 || packages+=(tar)
  fi
  if ! command -v sha256sum >/dev/null 2>&1 || ! command -v install >/dev/null 2>&1 || ! command -v realpath >/dev/null 2>&1 || ! command -v ln >/dev/null 2>&1; then packages+=(coreutils); fi
  # Certificate locations used by Debian/Ubuntu and Red Hat families.
  if [[ ! -s /etc/ssl/certs/ca-certificates.crt && ! -s /etc/pki/tls/certs/ca-bundle.crt ]]; then packages+=(ca-certificates); fi
  if [[ "${#packages[@]}" -gt 0 ]]; then package_install "${packages[@]}"; fi
  if ! select_python; then
    if [[ "$apt" == 1 ]]; then package_install python3.11 python3.11-venv python3-pip
    else package_install python3.11 python3.11-pip; fi
  fi
  select_python || fail 'Python >=3.11 is unavailable after package installation; install a supported Python and retry.'
  "$PYTHON_BIN" -c 'import ensurepip, venv' >/dev/null 2>&1 || fail 'Python venv/ensurepip is unavailable; install the venv package for the selected Python.'
  local binary
  local required=(curl sha256sum install realpath ln)
  if [[ "$phase" == all ]]; then required+=(tmux ssh ssh-keyscan tar); fi
  for binary in "${required[@]}"; do
    command -v "$binary" >/dev/null 2>&1 || fail "Missing dependency after package installation: $binary"
  done
}
# Download, digest and archive inspection require these tools even on a fresh host.
# Failures stop here; no release or third-party installer has executed yet.
if [[ "$AUTO" == 1 ]]; then
  printf 'Preparing download and verification tools.\n'
  prepare_dependencies download
else
  select_python || fail 'Prepare Python >=3.11 before --user/--no-start installation.'
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ayana-install.XXXXXXXX")"
STAGED_MIMO=""
cleanup() {
  if [[ -n "$STAGED_MIMO" ]]; then rm -f -- "$STAGED_MIMO"; fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
URL="https://github.com/$REPO/releases/$PART/$ASSET"
printf 'Downloading Ayana release %s.\n' "$VERSION"
fetch "$URL" > "$WORK/package.tar.gz"
if [[ -n "${AYANA_SHA256:-}" ]]; then
  EXPECT="$AYANA_SHA256"
else
  EXPECT="$(fetch "$URL.sha256" | awk 'NR==1 {print $1}')"
fi
[[ "$EXPECT" =~ ^[0-9a-fA-F]{64}$ ]] || fail 'A valid SHA256 sidecar is required'
ACTUAL="$(sha256sum "$WORK/package.tar.gz" | awk '{print $1}')"
[[ "${ACTUAL,,}" == "${EXPECT,,}" ]] || fail 'SHA256 mismatch'
printf 'SHA256 verified; checking and unpacking the release.\n'
# Reject traversal, links, devices and oversized layouts before extraction.
"$PYTHON_BIN" - "$WORK" <<'PY'
from pathlib import Path, PurePosixPath
import sys, tarfile
root = Path(sys.argv[1])
with tarfile.open(root/'package.tar.gz', 'r:gz') as archive:
    members = archive.getmembers()
    if sum(member.size for member in members) > 256*1024*1024:
        raise SystemExit('Release too large')
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
            raise SystemExit('Unsafe release archive')
    options = {'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}
    archive.extractall(root/'source', members=members, **options)
PY
prepare_mimo() {
  [[ "$EXPLICIT_MIMO" == 0 ]] || return 0
  local configured candidate destination version destination_dir
  configured="$("$PYTHON_BIN" - "$CONF_DIR/config.json" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1]).expanduser()
if path.exists():
    config = json.loads(path.read_text(encoding='utf-8'))
    print(config.get('mimo_bin') or (config.get('auto_investigate') or {}).get('mimo_bin') or '')
PY
)" || fail 'Could not read existing Ayana config; no MiMo installation was attempted.'
  # Existing configuration is authoritative. The installer reports invalid paths;
  # silently replacing them could disturb the runtime that owns active sessions.
  if [[ -n "$configured" ]]; then return 0; fi
  candidate="$(command -v mimo || true)"
  if [[ -n "$candidate" ]]; then
    candidate="$(realpath "$candidate")"
    case "$candidate" in /root/*|/home/*) ;; *) ARGS+=(--mimo-bin "$candidate"); return 0 ;; esac
  fi
  destination="${AYANA_MIMO_INSTALL_PATH:-/usr/local/bin/mimo}"
  [[ "$destination" == /* ]] || fail 'AYANA_MIMO_INSTALL_PATH must be an absolute system-readable path.'
  # A home installation can shadow this public CLI in PATH, including after a
  # successful earlier run. Reuse the executable itself without replacing it.
  if [[ -e "$destination" || -L "$destination" ]]; then
    if [[ -f "$destination" && -x "$destination" ]]; then
      candidate="$(realpath "$destination")"
      case "$candidate" in
        /root/*|/home/*) fail 'Existing MiMo destination resolves to a protected home directory (ProtectHome=true).' ;;
        *) ARGS+=(--mimo-bin "$candidate"); return 0 ;;
      esac
    fi
    fail "MiMo destination already exists but is not executable; use --mimo-bin to select a valid CLI: $destination"
  fi
  # A prior Ayana install must never upgrade/install a CLI behind active tasks.
  if [[ -f "$CONF_DIR/config.json" || -f "${PREFIX:-/opt/ayana}/deploy/installation.py" ]]; then
    fail 'Existing Ayana installation has no public MiMo CLI; set --mimo-bin to its existing system-readable CLI.'
  fi
  destination="$(realpath -m "$destination")"
  case "$destination" in /root/*|/home/*) fail 'MiMo destination must be outside /root and /home (ProtectHome=true).' ;; esac
  [[ ! -e "$destination" && ! -L "$destination" ]] || fail "MiMo destination already exists; use --mimo-bin to select it: $destination"
  if [[ -f "$HOME/.mimocode/bin/mimo" ]]; then
    candidate="$HOME/.mimocode/bin/mimo"
  else
    version="${AYANA_MIMO_VERSION:-0.1.16}"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || fail 'Invalid AYANA_MIMO_VERSION'
    printf 'Installing official MiMoCode %s for the system service.\n' "$version"
    fetch https://mimo.xiaomi.com/install > "$WORK/mimo-install.sh"
    mkdir -p "$WORK/mimo-home"
    HOME="$WORK/mimo-home" bash "$WORK/mimo-install.sh" --no-modify-path --version "$version" || fail 'Official MiMoCode installation failed; installation stopped.'
    candidate="$WORK/mimo-home/.mimocode/bin/mimo"
  fi
  # Copy the actual standalone executable, never a wrapper/symlink to a home.
  candidate="$(realpath "$candidate")"
  if ! "$PYTHON_BIN" - "$candidate" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1]).resolve(strict=True)
with path.open('rb') as stream:
    magic = stream.read(4)
if magic != b'\x7fELF' and magic[:2] != b'MZ':
    raise SystemExit('MiMo is not a standalone binary; install its complete runtime in a system-readable location and pass --mimo-bin.')
PY
  then fail 'Could not prepare a standalone MiMoCode executable.'; fi
  # /tmp and home directories may be mounted noexec. Validate only the copy on
  # the final filesystem, then publish it atomically without replacing a file
  # created by another installation after the earlier destination check.
  destination_dir="${destination%/*}"
  [[ -n "$destination_dir" ]] || destination_dir=/
  mkdir -p -- "$destination_dir" || fail 'Could not create the public MiMoCode directory.'
  STAGED_MIMO="$(mktemp "$destination_dir/.ayana-mimo.XXXXXXXX")" || fail 'Could not stage the public MiMoCode executable.'
  install -m0755 "$candidate" "$STAGED_MIMO" || fail 'Could not copy the staged MiMoCode executable.'
  "$STAGED_MIMO" --version || fail 'Staged MiMoCode --version failed; installation stopped.'
  ln -T -- "$STAGED_MIMO" "$destination" || fail 'Could not publish MiMoCode without replacing an existing destination.'
  rm -f -- "$STAGED_MIMO"
  STAGED_MIMO=""
  ARGS+=(--mimo-bin "$destination")
}
if [[ "$AUTO" == 1 ]]; then
  printf 'Preparing system runtime dependencies.\n'
  prepare_dependencies
  prepare_mimo
fi
printf 'Installing Ayana from the verified release.\n'
bash "$WORK/source/deploy/install.sh" "${ARGS[@]}"
