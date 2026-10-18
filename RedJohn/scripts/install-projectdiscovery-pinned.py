#!/usr/bin/env python3
"""Explicitly install one reviewed release; never execute upstream install scripts."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import platform
import tempfile
import urllib.request
import zipfile
from pathlib import Path


def fetch(url: str, maximum: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "RedJohn-pinned-installer"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise RuntimeError("official artifact exceeds installer byte limit")
    return data


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("httpx", "katana", "vulnx"))
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    pin = json.loads(Path(__file__).with_name("projectdiscovery-pins.json").read_text())[args.tool]
    version, commit = pin["version"], pin["commit"]
    target = (
        args.destination or Path(__file__).resolve().parents[1] / ".tools" / args.tool / version
    ).resolve()
    if target.exists():
        raise SystemExit(f"refusing to overwrite existing installation: {target}")
    system = {"Darwin": "macOS", "Linux": "linux"}.get(platform.system())
    architecture = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    suffix = f"{system}_{architecture}"
    if suffix not in pin["archives"]:
        raise SystemExit("unsupported installer platform; no download attempted")
    base = f"https://github.com/projectdiscovery/{args.tool}/releases/download/v{version}/"
    checksums = fetch(base + pin["checksums"], 16384)
    if sha(checksums) != pin["checksums_sha256"]:
        raise RuntimeError("official checksums file differs from reviewed pin")
    name = f"{args.tool}_{version}_{suffix}.zip"
    published = {
        parts[1]: parts[0] for line in checksums.decode().splitlines() if (parts := line.split())
    }
    if published.get(name) != pin["archives"][suffix]:
        raise RuntimeError("official checksum differs from reviewed archive pin")
    archive = fetch(base + name, 128 * 1024**2)
    if sha(archive) != pin["archives"][suffix]:
        raise RuntimeError("downloaded archive checksum mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        members = [item for item in bundle.infolist() if item.filename == args.tool]
        if len(members) != 1:
            raise RuntimeError("release must contain exactly one executable")
        info = members[0]
        mode = info.external_attr >> 16
        if info.is_dir() or mode & 0o170000 == 0o120000 or not 1 <= info.file_size <= 128 * 1024**2:
            raise RuntimeError("invalid executable member")
        with bundle.open(info) as handle:
            binary = handle.read(128 * 1024**2 + 1)
        if len(binary) != info.file_size:
            raise RuntimeError("invalid executable content")
    license_url = f"https://raw.githubusercontent.com/projectdiscovery/{args.tool}/{commit}/{pin['license_file']}"
    license_data = fetch(license_url, 16384)
    if sha(license_data) != pin["license_sha256"]:
        raise RuntimeError("reviewed release license could not be verified")
    receipt = {
        "tool": args.tool,
        "version": version,
        "source_commit": commit,
        "release": f"https://github.com/projectdiscovery/{args.tool}/releases/tag/v{version}",
        "archive_url": base + name,
        "archive_sha256": sha(archive),
        "checksums_url": base + pin["checksums"],
        "checksums_sha256": sha(checksums),
        "binary_sha256": sha(binary),
        "binary_bytes": len(binary),
        "license": "MIT_CLI_only_provider_data_and_optional_datasets_separate",
        "license_url": license_url,
        "license_sha256": sha(license_data),
        "verification": "embedded SHA256 pin + official release checksums; not an independent signature",
        "platform": [platform.system(), platform.machine()],
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".redjohn-pd-install-", dir=target.parent) as temp:
        stage = Path(temp)
        (stage / args.tool).write_bytes(binary)
        (stage / args.tool).chmod(0o700)
        (stage / "LICENSE.md").write_bytes(license_data)
        (stage / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        (stage / "checksums.txt").write_bytes(checksums)
        target.mkdir(mode=0o700)
        for source in stage.iterdir():
            with (target / source.name).open("xb") as stream:
                stream.write(source.read_bytes())
            (target / source.name).chmod(source.stat().st_mode & 0o777)
    print(json.dumps({"installation": str(target), **receipt}, indent=2))


if __name__ == "__main__":
    main()
