#!/usr/bin/env bash
# RedJohn workspace check: ruff + the default pytest suites.
# Load tests (marker `load`) are deselected by default; OV live tests skip
# unless a server is reachable (RJ_OV_LIVE=1 boots the fixture compose stack).
set -euo pipefail
cd "$(dirname "$0")/.."

RUNNER="${REDJOHN_PYTHON_BIN_DIR:-.venv/bin}"

echo "== ruff =="
"$RUNNER/ruff" check packages/core packages/cli packages/tui tests/load tests/ov_integration

echo "== pytest: core =="
"$RUNNER/pytest" packages/core/tests -q

echo "== pytest: cli + tui =="
"$RUNNER/pytest" packages/cli packages/tui -q

echo "== pytest: desktop & e2e =="
"$RUNNER/pytest" tests/e2e tests/test_m1_rechallenge.py tests/test_native_memory_supervisor.py -q

echo "[ok] all checks passed"
