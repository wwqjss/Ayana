#!/usr/bin/env bash
# One lifecycle implementation: init/update/rollback/status/health.
# init/update fetch main by default; --source DIR installs a reviewed local package.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "${PYTHON_BIN:-python3}" "$ROOT/deploy/installation.py" "$@"
