#!/usr/bin/env bash
# Unified Linux installer. --check is read-only; --no-start never changes services/accounts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "${PYTHON_BIN:-python3}" "$ROOT/deploy/installation.py" install "$@"
