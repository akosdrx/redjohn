#!/usr/bin/env bash
# Downloads only the reviewed optional kube-bench executable/license; no audit.
set -euo pipefail
mkdir -p artifacts/tool-receipts
python scripts/install-preparation-pinned.py --tool kube-bench
python - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path(".tools/kube-bench/0.16.0")
raw = (root / "provenance.json").read_bytes()
receipt = json.loads(raw)
digest = hashlib.sha256((root / "kube-bench").read_bytes()).hexdigest()
if receipt["version"] != "0.16.0" or receipt["binary"]["sha256"] != digest or receipt["engine_executed"] or receipt["audit_executed"]:
    raise SystemExit("preparation_install_receipt_mismatch")
Path("artifacts/tool-receipts/kube-bench.json").write_bytes(raw)
Path("artifacts/preparation-tool-versions.json").write_text(json.dumps({
    "kube-bench": {"version": receipt["version"], "binary_sha256": digest,
                   "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                   "source_commit": receipt["source_commit"],
                   "license_sha256": receipt["license_sha256"],
                   "engine_executed_during_install": False, "audit_executed": False},
    "prowler": {"version": "5.45.0", "status": "blocked_pinned_dependency_snapshot_unavailable",
                "engine_executed": False, "audit_executed": False},
}, indent=2) + "\n")
PY
