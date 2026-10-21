#!/usr/bin/env bash
# Reviewed native engines install sequentially, with receipts retained on CI.
set -euo pipefail
mkdir -p artifacts/tool-receipts
PYTHON=python bash scripts/install-source-scanners.sh
python - <<'PY'
import hashlib
import json
from pathlib import Path

versions = {}
for tool, version in (("semgrep", "1.181.0"), ("trivy", "0.76.0")):
    root = Path(".tools") / tool / version
    receipt = root / "receipt.json"
    data = receipt.read_bytes()
    payload = json.loads(data)
    if payload["version"] != version:
        raise SystemExit("source_scanner_receipt_version_mismatch")
    Path("artifacts/tool-receipts", tool + ".json").write_bytes(data)
    versions[tool] = {
        "version": version,
        "receipt_sha256": hashlib.sha256(data).hexdigest(),
        "installed_files": {
            str(path.relative_to(root)): {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                         "bytes": path.stat().st_size}
            for path in sorted(root.rglob("*")) if path.is_file()
        },
    }
Path("artifacts/source-scanner-versions.json").write_text(json.dumps(versions, indent=2) + "\n")
PY
