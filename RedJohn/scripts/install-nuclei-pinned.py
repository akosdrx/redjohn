#!/usr/bin/env python3
"""Install exactly the reviewed official Nuclei release, never templates or shell code."""

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

VERSION = "3.11.1"
COMMIT = "a8c88feb4a1c8e961b7902534ce3af97e9d524a4"
CHECKSUMS_SHA256 = "8c55f4113c54dfa4a202e32eaaa8b78abc741a13ed7941651322748fb233a05e"
ARCHIVES = {
    ("Darwin", "arm64"): (
        "macOS_arm64",
        "7d7e291addd1fc29a9bf8d089afe878a9799b20229cbea2fb1693fc40fd4c5f0",
    ),
    ("Darwin", "x86_64"): (
        "macOS_amd64",
        "75c47ce11e9dbd4288a1c895ed85e3c4df9f4acb8237d6d178da6dccd1628f2a",
    ),
    ("Linux", "aarch64"): (
        "linux_arm64",
        "8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07",
    ),
    ("Linux", "x86_64"): (
        "linux_amd64",
        "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
    ),
}
BASE = f"https://github.com/projectdiscovery/nuclei/releases/download/v{VERSION}/"
LICENSE_SHA256 = "5fa6644d2dd1987a79c06f4af210d2cf8cfc4ee799999029d0f9980c9cf95a2c"
LICENSE_URL = f"https://raw.githubusercontent.com/projectdiscovery/nuclei/{COMMIT}/LICENSE.md"


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
        default=Path(__file__).resolve().parents[1] / ".tools" / "nuclei" / VERSION,
    )
    args = parser.parse_args()
    target = args.destination.resolve()
    if target.exists():
        raise SystemExit(f"refusing to overwrite existing installation: {target}")
    try:
        suffix, digest = ARCHIVES[(platform.system(), platform.machine())]
    except KeyError as error:
        raise SystemExit("unsupported installer platform; no download attempted") from error
    name = f"nuclei_{VERSION}_{suffix}.zip"
    checksums = fetch(BASE + f"nuclei_{VERSION}_checksums.txt", 16384)
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
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        info = bundle.getinfo("nuclei")
        if not 1 <= info.file_size <= 256 * 1024**2:
            raise RuntimeError("invalid Nuclei executable size")
        binary = bundle.read(info)
    license_data = fetch(LICENSE_URL, 16384)
    if sha(license_data) != LICENSE_SHA256:
        raise RuntimeError("reviewed release license could not be verified")
    receipt = {
        "version": VERSION,
        "source_commit": COMMIT,
        "release": f"https://github.com/projectdiscovery/nuclei/releases/tag/v{VERSION}",
        "archive_url": BASE + name,
        "archive_sha256": digest,
        "checksums_url": BASE + f"nuclei_{VERSION}_checksums.txt",
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
    with tempfile.TemporaryDirectory(prefix=".redjohn-nuclei-install-", dir=target.parent) as temp:
        stage = Path(temp) / "installation"
        stage.mkdir(mode=0o700)
        (stage / "nuclei").write_bytes(binary)
        (stage / "nuclei").chmod(0o700)
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
