#!/usr/bin/env bash
set -euo pipefail
base="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
"${PYTHON:-python3}" "$base/install-network-scanners.py" naabu
"${PYTHON:-python3}" "$base/install-network-scanners.py" dnsx
