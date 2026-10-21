#!/usr/bin/env python3
"""Explicit optional installs from reviewed hashes, never at adapter startup.

Schemathesis wheels are extracted without running package/setup scripts or
installing into RedJohn. Platform + Python minor are part of its dependency lock.
The Interactsh server is optional owned test infrastructure, never auto-started.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import platform
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


LIMIT = 128 * 1024**2


def fetch(url: str, digest: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "RedJohn-pinned-installer"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("download_digest_or_size_mismatch")
    return data


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError("unsafe_archive_path")
    return str(path)


def zip_files(data: bytes) -> dict[str, bytes]:
    result = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            name = safe_name(member.filename)
            total += member.file_size
            if (
                total > LIMIT
                or len(result) > 8192
                or member.external_attr >> 16 & 0o170000 == 0o120000
            ):
                raise ValueError("unsafe_or_oversized_zip")
            if not member.is_dir():
                if name in result:
                    raise ValueError("duplicate_zip_member")
                result[name] = archive.read(member)
    return result


def install(tool: str, root: Path) -> dict[str, object]:
    pin = json.loads(Path(__file__).with_name("schema-oast-pins.json").read_text())[tool]
    system = platform.system()
    arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}[platform.machine()]
    directory = (
        root.resolve() / ("interactsh-server" if tool == "interactsh" else tool) / pin["version"]
    )
    if directory.exists():
        raise ValueError("install_directory_exists_no_overwrite")
    lock = None
    if tool == "schemathesis":
        key = f"{system}-{arch}-{sys.version_info.major}.{sys.version_info.minor}"
        lock = pin["wheel_locks"].get(key)
        if lock is None:
            raise ValueError("platform_python_dependency_lock_unavailable")
    directory.mkdir(mode=0o700, parents=True)
    try:
        if lock is not None:
            files = {}
            for wheel in lock:
                for name, data in zip_files(fetch(wheel["url"], wheel["sha256"])).items():
                    name = "package/" + name
                    if name in files:
                        raise ValueError("dependency_path_collision")  # noqa: TRY301 - archive boundary
                    files[name] = data
            if len(files) > 8192 or sum(map(len, files.values())) > LIMIT:
                raise ValueError("python_bundle_limit")  # noqa: TRY301 - archive boundary
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as archive:
                for name, data in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = len(data), 0o400, 0
                    archive.addfile(info, io.BytesIO(data))
            payload, filename = stream.getvalue(), "schemathesis.tar"
        else:
            if tool == "tinja":
                asset = f"TInjA_{pin['version']}_{system.lower()}_{arch}.tar.gz"
            else:
                asset = f"interactsh-server_{pin['version']}_{'macOS' if system == 'Darwin' else 'linux'}_{arch}.zip"
            metadata = pin["assets"].get(asset)
            if metadata is None:
                raise ValueError("platform_binary_lock_unavailable")  # noqa: TRY301 - platform boundary
            data = fetch(metadata["url"], metadata["sha256"])
            if tool == "tinja":
                files = {}
                total = 0
                with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                    for member in archive:
                        name = safe_name(member.name)
                        if member.isdir():
                            continue
                        if not member.isfile():
                            raise ValueError("unsafe_tar_member")  # noqa: TRY301 - archive boundary
                        total += member.size
                        if total > LIMIT or name in files:
                            raise ValueError("tar_limit_or_duplicate")  # noqa: TRY301 - archive boundary
                        handle = archive.extractfile(member)
                        assert handle is not None
                        files[name] = handle.read()
            else:
                files = zip_files(data)
            candidates = [
                v
                for k, v in files.items()
                if Path(k).name.lower() == ("tinja" if tool == "tinja" else "interactsh-server")
            ]
            if len(candidates) != 1:
                raise ValueError("release_executable_missing")  # noqa: TRY301 - archive boundary
            payload, filename = candidates[0], "tinja" if tool == "tinja" else "interactsh-server"
            for name, content in files.items():
                if Path(name).name.lower().startswith(("license", "notice")):
                    (directory / Path(name).name).write_bytes(content)
        target = directory / filename
        target.write_bytes(payload)
        target.chmod(0o400 if lock is not None else 0o500)
        license_data = fetch(pin["license_file"]["url"], pin["license_file"]["sha256"])
        (directory / "UPSTREAM-LICENSE.txt").write_bytes(license_data)
        receipt = {
            "path": str(target),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "version": pin["version"],
            "source_commit": pin["commit"],
            "source_archive_sha256": pin["archive_sha256"],
            "license": pin["license"],
            "license_sha256": pin["license_file"]["sha256"],
            "dependencies": lock or [],
            "platform": system + "-" + arch,
            "python_minor": f"{sys.version_info.major}.{sys.version_info.minor}" if lock else None,
        }
        (directory / "install-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    except BaseException:
        # Incomplete installs stay visibly incomplete; never overwrite or delete
        # an existing tool tree as a recovery shortcut.
        (directory / "INSTALL_INCOMPLETE").touch()
        raise
    else:
        return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("tinja", "schemathesis", "interactsh"))
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1] / ".tools")
    args = parser.parse_args()
    print(json.dumps(install(args.tool, args.root), indent=2))
