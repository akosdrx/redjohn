#!/usr/bin/env python3
"""Install exactly the reviewed official ffuf release, never templates or shell code."""

from __future__ import annotations
import argparse
import hashlib
import io
import json
import platform
import tempfile
import urllib.request
import tarfile
from pathlib import Path

VERSION = "2.1.0"
COMMIT = "7a2756a8f367c69c261544ae83d52e86b1ca52d0"
CHECKSUMS_SHA256 = "2fc5c8d66f67edcf4be778d264269a9aeca929f3c52595ef579c22bda542adb9"
ARCHIVES = {
    ("Darwin", "arm64"): (
        "macOS_arm64",
        "df1fdfbdc7ab6abb54cdf212452d585121bf291512649cf36c43a18d849f960e",
    ),
    ("Darwin", "x86_64"): (
        "macOS_amd64",
        "d2d8a561f166d34d60d90f2f9b0a7ebe1414c0836549a1292e8da3206ac8781d",
    ),
    ("Linux", "aarch64"): (
        "linux_arm64",
        "6ae920d09d5202762fca21967a460c6fb88135bdfa806bee4d3d2c430dcedeea",
    ),
    ("Linux", "x86_64"): (
        "linux_amd64",
        "fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5",
    ),
}
BASE = f"https://github.com/ffuf/ffuf/releases/download/v{VERSION}/"
LICENSE_SHA256 = "27efda573d21acd87c68e008a190c7456bcd93b510b8c35a1500088249d5d930"
LICENSE_URL = f"https://raw.githubusercontent.com/ffuf/ffuf/{COMMIT}/LICENSE"


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
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(__file__).resolve().parents[1] / ".tools" / "ffuf" / VERSION,
    )
    args = parser.parse_args()
    target = args.destination.resolve()
    if target.exists():
        raise SystemExit(f"refusing to overwrite existing installation: {target}")
    try:
        suffix, digest = ARCHIVES[(platform.system(), platform.machine())]
    except KeyError as error:
        raise SystemExit("unsupported installer platform; no download attempted") from error
    name = f"ffuf_{VERSION}_{suffix}.tar.gz"
    checksums = fetch(BASE + f"ffuf_{VERSION}_checksums.txt", 16384)
    if sha(checksums) != CHECKSUMS_SHA256:
        raise RuntimeError("official checksums file differs from reviewed pin")
    expected_line = next(
        (line.split() for line in checksums.decode().splitlines() if line.split()[-1] == name), None
    )
    if not expected_line or expected_line[0] != digest:
        raise RuntimeError("official checksum differs from reviewed archive pin")
    archive = fetch(BASE + name, 128 * 1024**2)
    if sha(archive) != digest:
        raise RuntimeError("downloaded archive checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        info = bundle.getmember("ffuf")
        if not info.isfile() or not 1 <= info.size <= 64 * 1024**2:
            raise RuntimeError("invalid ffuf executable size")
        handle = bundle.extractfile(info)
        if handle is None:
            raise RuntimeError("missing ffuf executable")
        with handle:
            binary = handle.read(64 * 1024**2 + 1)
        if len(binary) != info.size:
            raise RuntimeError("invalid ffuf executable content")
    license_data = fetch(LICENSE_URL, 16384)
    if sha(license_data) != LICENSE_SHA256:
        raise RuntimeError("reviewed release license could not be verified")
    receipt = {
        "version": VERSION,
        "source_commit": COMMIT,
        "release": f"https://github.com/ffuf/ffuf/releases/tag/v{VERSION}",
        "archive_url": BASE + name,
        "archive_sha256": digest,
        "checksums_url": BASE + f"ffuf_{VERSION}_checksums.txt",
        "checksums_sha256": sha(checksums),
        "binary_sha256": sha(binary),
        "binary_bytes": len(binary),
        "license": "MIT",
        "license_url": LICENSE_URL,
        "license_sha256": sha(license_data),
        "verification": "embedded SHA256 pin + official release checksums; not an independent signature",
        "platform": [platform.system(), platform.machine()],
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".redjohn-ffuf-install-", dir=target.parent) as temp:
        stage = Path(temp) / "installation"
        stage.mkdir(mode=0o700)
        (stage / "ffuf").write_bytes(binary)
        (stage / "ffuf").chmod(0o700)
        (stage / "LICENSE.md").write_bytes(license_data)
        (stage / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        (stage / "checksums.txt").write_bytes(checksums)
        # mkdir is the atomic no-replace operation: even a concurrently created
        # empty user directory is preserved. Each destination file also uses xb.
        target.mkdir(mode=0o700)
        for source in stage.iterdir():
            with (target / source.name).open("xb") as stream:
                stream.write(source.read_bytes())
            (target / source.name).chmod(source.stat().st_mode & 0o777)
    print(json.dumps({"installation": str(target), **receipt}, indent=2))


if __name__ == "__main__":
    main()
