#!/usr/bin/env python3
"""Explicit pinned native source engines; no project/installer code execution.

Only the native OCaml Semgrep CE binary and exact bundled shared libraries are
extracted from its official wheel.
Its reviewed argv[0] dispatch selects the native osemgrep CLI; no Python package
or dependency is installed into RedJohn. Runtime worker scans remain offline.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import platform
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path


ARCHIVE_LIMIT = 128 * 1024**2
BINARY_LIMIT = 256 * 1024**2
LIBRARY_LIMIT = 16 * 1024**2
LIBRARY_TOTAL_LIMIT = 32 * 1024**2


def fetch(url: str, digest: str, maximum: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "RedJohn-pinned-source-installer"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("source_tool_download_digest_or_size_mismatch")
    return data


def executable(data: bytes, kind: str, member_name: str) -> bytes:
    if kind == "wheel":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [member for member in archive.infolist() if member.filename == member_name]
            if len(members) != 1:
                raise ValueError("source_wheel_native_member_missing_or_duplicate")
            member = members[0]
            if (
                not 1 <= member.file_size <= BINARY_LIMIT
                or member.is_dir()
                or member.external_attr >> 16 & 0o170000 == 0o120000
            ):
                raise ValueError("source_wheel_native_member_invalid")
            result = archive.read(member)
    elif kind == "tar.gz":
        result = None
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for index, member in enumerate(archive):
                if index > 32768:
                    raise ValueError("source_archive_member_limit")
                if member.name != member_name:
                    continue
                if (
                    result is not None
                    or not member.isfile()
                    or not 1 <= member.size <= BINARY_LIMIT
                ):
                    raise ValueError("source_archive_executable_invalid")
                handle = archive.extractfile(member)
                assert handle is not None
                with handle:
                    result = handle.read(BINARY_LIMIT + 1)
        if result is None:
            raise ValueError("source_archive_executable_missing")
    else:
        raise ValueError("source_archive_kind_denied")
    if not result.startswith(b"\x7fELF") or not 1 <= len(result) <= BINARY_LIMIT:
        raise ValueError("source_native_elf_required")
    return result


def native_libraries(data: bytes, member: str, names: list[str]) -> dict[str, bytes]:
    """Extract only reviewed library names from an already SHA-verified wheel."""
    if len(names) > 32 or len(set(names)) != len(names):
        raise ValueError("source_native_library_manifest_invalid")
    result: dict[str, bytes] = {}
    prefix = str(Path(member).parent) + "/libs/"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in names:
            if Path(name).name != name or not name.startswith("lib") or ".so" not in name:
                raise ValueError("source_native_library_name_invalid")
            matches = [entry for entry in archive.infolist() if entry.filename == prefix + name]
            if len(matches) != 1:
                raise ValueError("source_native_library_missing_or_duplicate")
            entry = matches[0]
            if (
                entry.is_dir()
                or entry.external_attr >> 16 & 0o170000 == 0o120000
                or not 1 <= entry.file_size <= LIBRARY_LIMIT
            ):
                raise ValueError("source_native_library_invalid")
            payload = archive.read(entry)
            if not payload.startswith(b"\x7fELF"):
                raise ValueError("source_native_library_elf_required")
            result[name] = payload
            if sum(map(len, result.values())) > LIBRARY_TOTAL_LIMIT:
                raise ValueError("source_native_library_total_limit")
    return result


def install(tool: str, destination: Path | None = None) -> dict[str, object]:
    pins = json.loads(Path(__file__).with_name("source-scanner-pins.json").read_text())
    pin = pins[tool]
    arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    metadata = pin["assets"].get(f"{platform.system()}-{arch}")
    if metadata is None:
        raise ValueError("source_native_platform_not_reviewed")
    target = (
        destination or Path(__file__).resolve().parents[1] / ".tools" / tool / pin["version"]
    ).resolve()
    if target.exists():
        raise ValueError("source_native_install_exists_no_overwrite")
    archive = fetch(metadata["url"], metadata["sha256"], ARCHIVE_LIMIT)
    binary = executable(archive, metadata["archive_kind"], metadata["member"])
    libraries = (
        native_libraries(archive, metadata["member"], pin.get("native_libraries", []))
        if metadata["archive_kind"] == "wheel"
        else {}
    )
    license_data = fetch(pin["license_url"], pin["license_sha256"], 65536)
    receipt = {
        "tool": tool,
        "version": pin["version"],
        "source_commit": pin["commit"],
        "source": pin["source"],
        "license": pin["license"],
        "license_url": pin["license_url"],
        "license_sha256": pin["license_sha256"],
        "archive_url": metadata["url"],
        "archive_sha256": metadata["sha256"],
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "binary_bytes": len(binary),
        "native_libraries": [
            {"name": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in sorted(libraries.items())
        ],
        "executable": pin["executable"],
        "platform": f"{platform.system()}-{arch}",
        "verification": "embedded official release/PyPI SHA256; not an independent signature",
    }
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".redjohn-source-install-", dir=target.parent) as tmp:
        stage = Path(tmp)
        (stage / pin["executable"]).write_bytes(binary)
        (stage / pin["executable"]).chmod(0o700)
        if libraries:
            (stage / "libs").mkdir(mode=0o700)
            for name, data in libraries.items():
                (stage / "libs" / name).write_bytes(data)
                (stage / "libs" / name).chmod(0o600)
        (stage / "LICENSE").write_bytes(license_data)
        (stage / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        # Directory rename publishes a complete install in one operation.
        stage.rename(target)
    return {"installation": str(target), **receipt}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("semgrep", "trivy"))
    parser.add_argument("--destination", type=Path)
    arguments = parser.parse_args()
    print(json.dumps(install(arguments.tool, arguments.destination), indent=2))


if __name__ == "__main__":
    main()
