#!/usr/bin/env bash
set -euo pipefail

# Run all tests: general suite plus tests_core
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGETS=(
  "$REPO_ROOT/bitcointx/tests"
  "$SCRIPT_DIR"
)

if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    PYTHON=python
fi

exec "$PYTHON" -m pytest "${TARGETS[@]}" -vv "$@"
