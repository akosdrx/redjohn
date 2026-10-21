#!/usr/bin/env python3
"""Write a content-pinned lab-only lock from an already verified local engine."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, default=root / ".tools/nuclei/3.11.1")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    install = args.installation.resolve()
    spec = importlib.util.spec_from_file_location(
        "pinned_installer", root / "scripts/install-nuclei-pinned.py"
    )
    assert spec is not None and spec.loader is not None
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    receipt = json.loads((install / "receipt.json").read_text())
    binary = install / "nuclei"
    allowed_archive_hashes = {item[1] for item in installer.ARCHIVES.values()}
    if (
        receipt["version"] != installer.VERSION
        or receipt["source_commit"] != installer.COMMIT
        or receipt["archive_sha256"] not in allowed_archive_hashes
        or receipt["checksums_sha256"] != installer.CHECKSUMS_SHA256
        or sha((install / "checksums.txt").read_bytes()) != installer.CHECKSUMS_SHA256
        or sha(binary.read_bytes()) != receipt["binary_sha256"]
        or receipt["license_sha256"] != installer.LICENSE_SHA256
        or sha((install / "LICENSE.md").read_bytes()) != installer.LICENSE_SHA256
    ):
        raise SystemExit("installed artifact provenance/digest differs from the reviewed receipt")
    bundle = root / "examples/nuclei-fixture"
    files = {"marker.yaml": sha((bundle / "marker.yaml").read_bytes())}
    lock = {
        "binary": {
            "path": str(binary),
            "version": receipt["version"],
            "sha256": receipt["binary_sha256"],
            "source": receipt["archive_url"] + "#sha256=" + receipt["archive_sha256"],
            "license": "MIT; " + receipt["license_url"],
        },
        "bundle": {
            "root": str(bundle),
            "version": "redjohn-loopback-marker-v1",
            "sha256": sha(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()),
            "source": "RedJohn own harmless loopback fixture; content SHA256 pinned below",
            "license": "Apache-2.0; SPDX-License-Identifier in marker.yaml",
            "files": files,
            "templates": [
                {
                    "path": "marker.yaml",
                    "id": "redjohn-loopback-marker",
                    "profiles": ["isolated-lab"],
                    "effect": "read-only",
                    "protocol": "http",
                }
            ],
        },
    }
    output = (args.output or install / "fixture-lock.json").resolve()
    output.write_text(json.dumps(lock, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    main()
