#!/usr/bin/env bash
set -euo pipefail

# Run all tests under bitcointx/tests_core
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    PYTHON=python
fi

exec "$PYTHON" -m pytest "$SCRIPT_DIR" -vv "$@"
