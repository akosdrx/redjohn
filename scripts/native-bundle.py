"""Build-only checksum and extraction helpers for reviewed native resources."""
from __future__ import annotations

import hashlib
import json
import os
import tarfile
import zipfile
from pathlib import Path

import httpx


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(source: dict, cache: Path) -> Path:
    cache.mkdir(parents=True, exist_ok=True)
    name = source.get("file") or source["url"].rsplit("/", 1)[-1]
    destination = cache / name
    expected = source["sha256"]
    if not expected or len(expected) != 64:
        raise ValueError(f"Missing reviewed SHA-256 for {name}")
    if destination.is_file() and sha256(destination) == expected:
        return destination
    temporary = destination.with_suffix(".part")
    with httpx.Client(follow_redirects=True, timeout=120) as client, client.stream("GET", source["url"]) as response:
        response.raise_for_status()
        with temporary.open("wb") as stream:
            for chunk in response.iter_bytes():
                stream.write(chunk)
    if sha256(temporary) != expected:
        temporary.unlink(missing_ok=True)
        raise ValueError(f"Checksum mismatch for {name}")
    os.replace(temporary, destination)
    print(f"[native-tools] verified {name}", flush=True)
    return destination


def extract(archive: Path, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as content:
            for item in content.infolist():
                path = (directory / item.filename).resolve()
                if not path.is_relative_to(directory.resolve()):
                    raise ValueError("Archive path escapes its destination")
            content.extractall(directory)
    else:
        with tarfile.open(archive) as content:
            content.extractall(directory, filter="data")


def digest_tree(directory: Path) -> dict[str, dict[str, str]]:
    result = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if relative == "build-info.json":
            continue
        if path.is_symlink():
            result[relative] = {"kind": "symlink", "target": os.readlink(path)}
        elif path.is_file():
            result[relative] = {"kind": "file", "sha256": sha256(path)}
    return result


def save_manifest(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")
