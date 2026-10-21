#!/usr/bin/env python3
"""Explicit, digest-verified optional installs; no upstream install scripts.

Python tools and their reviewed dependencies become a deterministic tar bundle.
They never install into RedJohn's Python environment or import into its process.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import platform
import tarfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


LIMIT = 64 * 1024 * 1024


def fetch(url: str, digest: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "RedJohn-pinned-installer"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("download_digest_or_size_mismatch")
    return data


def tar_files(data: bytes) -> dict[str, bytes]:
    result = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
                raise ValueError("unsafe_upstream_archive")
            if not member.isfile():
                continue
            total += member.size
            if total > LIMIT or len(result) >= 4096:
                raise ValueError("upstream_archive_limit")
            handle = archive.extractfile(member)
            assert handle is not None
            name = str(PurePosixPath(*(path.parts[1:] if len(path.parts) > 1 else path.parts)))
            if name in result:
                raise ValueError("duplicate_upstream_archive_member")
            result[name] = handle.read()
    return result


def install(tool: str, root: Path) -> dict[str, object]:
    pin = json.loads(Path(__file__).with_name("specialist-pins.json").read_text())[tool]
    directory = root.resolve() / tool / pin["version"]
    if directory.exists():
        raise ValueError("install_directory_exists_no_overwrite")
    directory.mkdir(mode=0o700, parents=True)
    try:
        if tool == "dalfox":
            system = {"Darwin": "macos", "Linux": "linux"}[platform.system()]
            arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}[
                platform.machine()
            ]
            asset = f"dalfox-v{pin['version']}-{system}-{arch}"
            asset += "-musl.tar.gz" if system == "linux" else ".tar.gz"
            source = pin["assets"][asset]
            files = tar_files(fetch(source["url"], source["sha256"]))
            candidates = [value for name, value in files.items() if Path(name).name == "dalfox"]
            if len(candidates) != 1:
                raise ValueError("release_binary_missing")  # noqa: TRY301 - archive boundary
            payload, filename = candidates[0], "dalfox"
        else:
            files = tar_files(fetch(pin["source_url"], pin["source_sha256"]))
            files = {"package/" + name: data for name, data in files.items()}
            for dependency in pin.get("dependencies", []):
                data = fetch(dependency["url"], dependency["sha256"])
                if dependency["filename"].endswith(".whl"):
                    with zipfile.ZipFile(io.BytesIO(data)) as wheel:
                        for info in wheel.infolist():
                            path = PurePosixPath(info.filename)
                            if path.is_absolute() or ".." in path.parts or info.file_size > LIMIT:
                                raise ValueError("unsafe_dependency_wheel")  # noqa: TRY301 - archive boundary
                            if not info.is_dir():
                                files["package/" + str(path)] = wheel.read(info)
                else:
                    for name, value in tar_files(data).items():
                        if name.startswith("ratelimit/") or name in {"LICENSE", "PKG-INFO"}:
                            files[
                                "package/" + name
                                if name.startswith("ratelimit/")
                                else "dependency-licenses/ratelimit/" + name
                            ] = value
            if sum(map(len, files.values())) > LIMIT or len(files) > 4096:
                raise ValueError("bundle_limit")  # noqa: TRY301 - archive boundary
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as archive:
                for name, data in sorted(files.items()):
                    member = tarfile.TarInfo(name)
                    member.size, member.mode, member.mtime = len(data), 0o400, 0
                    archive.addfile(member, io.BytesIO(data))
            payload, filename = stream.getvalue(), tool + ".tar"
        target = directory / filename
        target.write_bytes(payload)
        target.chmod(0o700 if tool == "dalfox" else 0o600)
        receipt = {
            "tool": tool,
            "path": str(target),
            "version": pin["version"],
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
            "upstream": pin,
            "installation_only_not_live_proof": True,
        }
        (directory / "install-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        return receipt  # noqa: TRY300 - rollback owns only this new directory
    except BaseException:
        # Only this newly created, exclusively owned installation directory.
        import shutil  # noqa: PLC0415

        shutil.rmtree(directory)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("arjun", "sqlmap", "dalfox"))
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1] / ".tools")
    args = parser.parse_args()
    print(json.dumps(install(args.tool, args.root), indent=2))
