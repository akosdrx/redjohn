#!/usr/bin/env bash
set -euo pipefail
task_script_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
"${PYTHON:-python3}" "$task_script_root/install-source-scanners.py" semgrep
"${PYTHON:-python3}" "$task_script_root/install-source-scanners.py" trivy
