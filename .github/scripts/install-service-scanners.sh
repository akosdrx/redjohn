#!/usr/bin/env bash
# This explicit CI-owned build does not grant product redistribution rights.
set -euo pipefail
mkdir -p artifacts/tool-receipts
python scripts/install-service-scanners.py nmap --owned-fixture-build
python - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path(".tools/nmap/7.992")
raw = (root / "receipt.json").read_bytes()
receipt = json.loads(raw)
digest = hashlib.sha256((root / "nmap").read_bytes()).hexdigest()
if receipt["version"] != "7.992" or receipt["source_macro_version"] != "7.992" or receipt["binary_sha256"] != digest:
    raise SystemExit("service_scanner_receipt_mismatch")
Path("artifacts/tool-receipts/nmap.json").write_bytes(raw)
Path("artifacts/service-scanner-versions.json").write_text(json.dumps({
    "nmap": {"version": receipt["version"], "binary_sha256": digest,
             "receipt_sha256": hashlib.sha256(raw).hexdigest(),
             "source_sha256": receipt["source_sha256"],
             "license_sha256": receipt["license_sha256"],
             "probe_profile": receipt["probe_profile"],
             "build_toolchain": receipt["build_toolchain"],
             "shared_libraries": receipt["shared_libraries"],
             "license_scope": receipt["license_scope"]},
}, indent=2) + "\n")
PY
