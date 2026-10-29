#!/usr/bin/env bash
# Download the current public release; verify SHA256 before extraction/execution.
# AYANA_VERSION=latest (default) or a tag such as vX.Y.Z. No unverified fallback.
set -euo pipefail
VERSION="${AYANA_VERSION:-latest}"
REPO="${AYANA_REPO:-wwqjss/Ayana}"
ARGS=("$@")
[[ ${#ARGS[@]} -gt 0 ]] || ARGS=(--user)
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 20 "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO- "$1"
  else printf 'Need curl or wget\n' >&2; return 1; fi
}
# A bootstrap check neither downloads nor creates a work directory.
CHECK=0; SYSTEM=0; PREFIX=""
for ((i=0; i<${#ARGS[@]}; i++)); do
  case "${ARGS[i]}" in
    -h|--help) printf 'Usage: bootstrap.sh [--system|--user] [installer options]\nAYANA_VERSION=latest or a release tag; SHA256 verification is required.\n'; exit 0 ;;
    --check) CHECK=1 ;;
    --system) SYSTEM=1 ;;
    --prefix) PREFIX="${ARGS[i+1]:?missing prefix}" ;;
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
  [[ "$VERSION" =~ ^v?[0-9][0-9A-Za-z.-]*$ ]] || { printf 'Invalid version\n' >&2; exit 1; }
  PART="download/$VERSION"; ASSET="ayana-${VERSION#v}-install.tar.gz"
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ayana-install.XXXXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
URL="https://github.com/$REPO/releases/$PART/$ASSET"
fetch "$URL" > "$WORK/package.tar.gz"
if [[ -n "${AYANA_SHA256:-}" ]]; then
  EXPECT="$AYANA_SHA256"
else
  EXPECT="$(fetch "$URL.sha256" | awk 'NR==1 {print $1}')"
fi
[[ "$EXPECT" =~ ^[0-9a-fA-F]{64}$ ]] || { printf 'A valid SHA256 sidecar is required\n' >&2; exit 1; }
ACTUAL="$(sha256sum "$WORK/package.tar.gz" | awk '{print $1}')"
[[ "${ACTUAL,,}" == "${EXPECT,,}" ]] || { printf 'SHA256 mismatch\n' >&2; exit 1; }
# Reject traversal, links, devices and oversized layouts before extraction.
"${PYTHON_BIN:-python3}" - "$WORK" <<'PY'
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
bash "$WORK/source/deploy/install.sh" "${ARGS[@]}"
