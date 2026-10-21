#!/usr/bin/env python3
"""Explicit kube-bench binary preparation; never contacts a cluster or runs it."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path


def download(url: str, digest: str, maximum: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "RedJohn-pinned-preparation"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("preparation_download_digest_or_size_mismatch")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=("kube-bench", "prowler"), required=True)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    if args.tool == "prowler":
        raise SystemExit("blocked: prowler_pinned_python_dependency_snapshot_unavailable")
    root = Path(__file__).resolve().parents[1]
    provenance = json.loads(
        (root / "redjohn/assessment/notices/preparation-provenance.json").read_text()
    )["tools"][args.tool]
    machine = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform.machine().lower(), "unsupported"
    )
    target = platform.system().lower() + "_" + machine
    release = provenance["release_archives"].get(target)
    if release is None:
        raise SystemExit("blocked: preparation_platform_archive_not_reviewed")
    destination = args.destination or root / ".tools" / args.tool / provenance["version"]
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise SystemExit("blocked: preparation_destination_already_exists")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".redjohn-preparation-", dir=destination.parent))
    try:
        archive = temporary / "archive.tar.gz"
        archive.write_bytes(download(release["url"], release["sha256"], 24 * 1024**2))
        with tarfile.open(archive) as bundle:
            matches = [
                member for member in bundle if member.name == "kube-bench" and member.isfile()
            ]
            if len(matches) != 1 or matches[0].size > 80 * 1024**2:
                raise ValueError("preparation_archive_executable_shape_denied")
            stream = bundle.extractfile(matches[0])
            assert stream is not None
            binary = stream.read(80 * 1024**2 + 1)
            if len(binary) != matches[0].size:
                raise ValueError("preparation_archive_truncated")
        executable = temporary / "kube-bench"
        executable.write_bytes(binary)
        executable.chmod(0o500)
        license_record = provenance["source_files"]["LICENSE"]
        (temporary / "LICENSE.kube-bench.txt").write_bytes(
            download(license_record["url"], license_record["sha256"], 65536)
        )
        archive.unlink()
        receipt = {
            "tool": args.tool,
            "version": provenance["version"],
            "platform": target,
            "binary": {
                "path": str(destination / "kube-bench"),
                "sha256": hashlib.sha256(binary).hexdigest(),
                "version": provenance["version"],
            },
            "archive": release,
            "source_commit": provenance["commit"],
            "license": provenance["license"],
            "license_sha256": license_record["sha256"],
            "engine_executed": False,
            "audit_executed": False,
        }
        (temporary / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if destination.exists() or destination.is_symlink():
            raise ValueError("preparation_destination_changed_during_download")
        temporary.rename(destination)
        print(json.dumps(receipt, indent=2))
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


if __name__ == "__main__":
    main()
