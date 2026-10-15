"""On-demand download of the lightweight single-binary scanners into the profile.

Nothing is bundled into the app. The pinned manifest (data/tool-downloads.json,
mirrored from packaging/tool-versions.json) lists the single-binary Go scanners
(nuclei, httpx, katana, subfinder, ffuf, dalfox, gau), which are downloaded,
SHA-256 verified and extracted into <profile>/tools/bin on demand. The heavy
tools (Metasploit, ZAP, Chromium/Node- and Python-based) are optional and
resolved from the system PATH instead — never downloaded here.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import httpx

from .errors import RJError

MANIFEST = Path(__file__).with_name("data") / "tool-downloads.json"


def current_platform() -> str | None:
    system = "darwin" if sys.platform == "darwin" else "linux" if sys.platform == "linux" else None
    machine = platform.machine()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64" if machine in ("x86_64", "amd64") else None
    return f"{system}-{arch}" if system and arch else None


def load_manifest() -> dict[str, Any]:
    try:
        return json.loads(MANIFEST.read_text())
    except (OSError, ValueError):
        return {}


def profile_tools_root(settings: Any) -> Path:
    return settings.profile_dir / "tools"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, expected: str, destination: Path) -> None:
    if not expected or len(expected) != 64:
        raise RJError(
            "tool_manifest_invalid", "A tool download is missing its reviewed checksum.", status=500
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    try:
        client = httpx.Client(follow_redirects=True, timeout=120)
        with client, client.stream("GET", url) as response:
            response.raise_for_status()
            with temporary.open("wb") as stream:
                for chunk in response.iter_bytes():
                    stream.write(chunk)
        if _sha256(temporary) != expected:
            raise RJError(
                "tool_download_corrupt", "A downloaded tool failed its checksum; retry.", status=502
            )
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _extract_binary(archive: Path, binary: str, target: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="rj-tool-") as temporary:
        directory = Path(temporary)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as content:
                for item in content.infolist():
                    if not (directory / item.filename).resolve().is_relative_to(directory.resolve()):
                        raise RJError(
                            "tool_archive_unsafe", "A tool archive tried to escape its directory.", status=502
                        )
                content.extractall(directory)
        else:
            with tarfile.open(archive) as content:
                content.extractall(directory, filter="data")
        found = directory / binary
        if not found.is_file():
            matches = [p for p in directory.rglob(binary) if p.is_file()]
            if len(matches) != 1:
                raise RJError(
                    "tool_archive_layout",
                    f"Could not locate '{binary}' in the downloaded archive.",
                    status=502,
                )
            found = matches[0]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(found, target)
        target.chmod(target.stat().st_mode | 0o111)


def _write_index(root: Path, tools: dict[str, Any]) -> None:
    index_path = root / "tool-index.json"
    existing: dict[str, Any] = {}
    try:
        existing = json.loads(index_path.read_text()).get("tools", {})
    except (OSError, ValueError):
        pass
    existing.update(tools)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = index_path.with_suffix(".json.part")
    document = {"platform": sys.platform, "arch": current_platform() or "", "tools": existing}
    temporary.write_text(json.dumps(document, indent=2) + "\n")
    os.replace(temporary, index_path)


def provision(settings: Any, ids: list[str] | None = None) -> dict[str, Any]:
    """Download (if missing) and install the requested light tools; returns status."""
    plat = current_platform()
    if plat is None:
        raise RJError(
            "tool_platform_unsupported", "Automatic tool download supports macOS and Linux only.", status=503
        )
    manifest = load_manifest()
    root = profile_tools_root(settings)
    cache = root / ".downloads"
    installed: dict[str, Any] = {}
    for tid in (ids or list(manifest)):
        entry = manifest.get(tid)
        artifact = entry and entry.get("artifacts", {}).get(plat)
        if not artifact:
            continue
        target = root / "bin" / tid
        if not (target.is_file() and os.access(target, os.X_OK)):
            archive = cache / artifact["file"]
            if not (archive.is_file() and _sha256(archive) == artifact["sha256"]):
                _download(artifact["url"], artifact["sha256"], archive)
            _extract_binary(archive, entry.get("binary", tid), target)
        installed[tid] = {
            "command": ["{root}/bin/" + tid],
            "version": entry.get("version", ""),
            "origin": "downloaded",
        }
    if installed:
        _write_index(root, installed)
    return provision_status(settings)


def provision_status(settings: Any) -> dict[str, Any]:
    """Which light tools are present on disk vs. downloadable on this platform."""
    plat = current_platform()
    manifest = load_manifest()
    root = profile_tools_root(settings)
    items = [
        {
            "id": tid,
            "version": entry.get("version", ""),
            "downloadable": plat in entry.get("artifacts", {}),
            "present": (root / "bin" / tid).is_file(),
        }
        for tid, entry in manifest.items()
    ]
    return {"platform": plat, "tools_root": str(root), "items": items}
