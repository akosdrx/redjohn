#!/usr/bin/env python3
"""Prepare a separate pinned RedJohn environment; never replace an existing one.

The inventory contains package identities and sizes, never environment variables,
provider configuration, index credentials or process arguments.
"""

from __future__ import annotations

import argparse
import importlib
from importlib import metadata
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / ".github/requirements-ci.lock"
LOCAL_TOOLS = ("pytest", "pytest-asyncio", "mypy", "ruff")
FOREIGN = {"strix-agent", "redjohn-core", "redjohn-cli", "redjohn-tui"}


def local_origin(value: str | None) -> str | None:
    parsed = urlsplit(value or "")
    if parsed.scheme == "file" and parsed.netloc in ("", "localhost"):
        return unquote(parsed.path)
    return None


def save_report(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077):
            raise ValueError("report_must_be_private_owned_regular_file")
    fd, temporary = tempfile.mkstemp(prefix=".redjohn-environment-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def inventory() -> dict:
    prefix = Path(sys.prefix)
    files = python_files = bytes_total = 0
    for directory, _dirs, names in os.walk(prefix, followlinks=False):
        for name in names:
            path = Path(directory) / name
            if path.is_symlink():
                continue
            files += 1
            python_files += name.endswith(".py")
            bytes_total += path.stat().st_size
    packages = []
    for distribution in metadata.distributions():
        direct = json.loads(distribution.read_text("direct_url.json") or "{}")
        editable = bool(direct.get("dir_info", {}).get("editable"))
        packages.append({
            "name": distribution.metadata["Name"],
            "version": distribution.version,
            "editable": editable,
            "editable_origin": local_origin(direct.get("url")) if editable else None,
        })
    return {
        "python": sys.version,
        "prefix": str(prefix),
        "python_files": python_files,
        "regular_files": files,
        "apparent_bytes": bytes_total,
        "packages": sorted(packages, key=lambda item: item["name"].lower()),
    }


def verify() -> dict:
    subprocess.run([sys.executable, "-m", "pip", "check"], check=True)
    modules = ("redjohn", "agents", "litellm", "openai", "playwright", "graphql", "mcp")
    origins = {}
    for name in modules:
        module = importlib.import_module(name)
        origins[name] = str(Path(module.__file__).resolve()) if module.__file__ else None
        if name != "redjohn" and (
            origins[name] is None or not Path(origins[name]).is_relative_to(Path(sys.prefix))
        ):
            raise RuntimeError("dependency_import_is_not_isolated:" + name)
    if not Path(origins["redjohn"]).is_relative_to(ROOT / "RedJohn/redjohn"):
        raise RuntimeError("redjohn_import_is_not_current_checkout")
    result = inventory()
    for package in result["packages"]:
        if package["name"].lower().replace("_", "-") in FOREIGN:
            raise RuntimeError("foreign_checkout_package_present")
        if package["editable"] and package["name"].lower() != "redjohn-agent":
            raise RuntimeError("unreviewed_editable_package_present")
    result["verified_import_origins"] = origins
    result["pip_check"] = "passed"
    result["profile"] = "RedJohn[browser,graphql]+pytest,pytest-asyncio,mypy,ruff"
    return result


def prepare(destination: Path, base_python: Path, report: Path) -> None:
    if not destination.is_absolute() or destination.exists() or destination.is_symlink():
        raise ValueError("destination_must_be_new_absolute_path")
    if (not base_python.is_absolute() or not base_python.is_file()
            or not os.access(base_python, os.X_OK)):
        raise ValueError("base_python_must_be_existing_absolute_executable")
    pins = {}
    for line in LOCK.read_text().splitlines():
        if "==" in line and not line.startswith("#"):
            name, version = line.split("==", 1)
            pins[name] = version
    tools = [name + "==" + pins[name] for name in LOCAL_TOOLS]
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    subprocess.run([str(base_python), "-m", "venv", str(destination)], check=True)
    python = destination / "bin/python"
    pip = [str(python), "-m", "pip", "--disable-pip-version-check"]
    subprocess.run([
        *pip, "install", "--constraint", str(LOCK),
        "pip==26.2.1", "hatchling==1.27.0", "editables==0.5",
    ], check=True)
    subprocess.run([
        *pip, "install", "--constraint", str(LOCK), "--no-build-isolation",
        "--editable", str(ROOT / "RedJohn") + "[browser,graphql]", *tools,
    ], check=True)
    subprocess.run([
        str(python), str(Path(__file__).resolve()), "verify", "--report", str(report),
    ], check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inventory", "prepare", "verify"))
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if not args.report.is_absolute():
        parser.error("report must be absolute")
    if args.action == "prepare":
        if args.destination is None or args.python is None:
            parser.error("prepare requires --destination and --python")
        prepare(args.destination, args.python, args.report)
        return
    result = verify() if args.action == "verify" else inventory()
    save_report(args.report, result)
    print(json.dumps({key: result[key] for key in ("prefix", "python_files", "regular_files", "apparent_bytes")}))


if __name__ == "__main__":
    main()
