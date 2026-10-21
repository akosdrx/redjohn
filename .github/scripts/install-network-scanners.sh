#!/usr/bin/env bash
# Install reviewed native engines sequentially and retain exact dependency evidence.
set -euo pipefail
mkdir -p artifacts/tool-receipts
PYTHON=python bash scripts/install-network-scanners.sh
python - <<'PY'
import hashlib
import json
import subprocess
from pathlib import Path

versions = {}
for tool, version in (("naabu", "2.6.1"), ("dnsx", "1.3.1")):
    root = Path(".tools") / tool / version
    data = (root / "receipt.json").read_bytes()
    payload = json.loads(data)
    binary = root / tool
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if payload["version"] != version or payload["binary_sha256"] != digest:
        raise SystemExit("network_scanner_receipt_mismatch")
    Path("artifacts/tool-receipts", tool + ".json").write_bytes(data)
    versions[tool] = {"version": version, "binary_sha256": digest,
                      "receipt_sha256": hashlib.sha256(data).hexdigest()}
package = "libpcap0.8t64"
metadata = subprocess.check_output(
    ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n", package], text=True
).strip()
files = {}
for name in subprocess.check_output(["dpkg-query", "-L", package], text=True).splitlines():
    path = Path(name)
    if path.is_file() and path.name.startswith("libpcap.so"):
        resolved = path.resolve(strict=True)
        files[str(resolved)] = {"sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
                                "bytes": resolved.stat().st_size}
if not files:
    raise SystemExit("required_libpcap_dependency_unverified")
versions["libpcap"] = {"package_version_architecture": metadata, "shared_objects": files}
Path("artifacts/network-scanner-versions.json").write_text(json.dumps(versions, indent=2) + "\n")
PY
