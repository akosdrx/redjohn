"""Reproducible native Debian/Ubuntu/Kali build environment, without containers."""
from __future__ import annotations

import importlib.util
import json
import os
import platform
import shlex
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_bundle", BASE / "scripts/native-bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def main() -> int:
    if sys.platform != "linux":
        raise SystemExit("Build the Linux release on a native Linux host.")
    arch = {"aarch64": "arm64", "x86_64": "x64"}.get(platform.machine())
    if arch is None:
        raise SystemExit("Supported Linux architectures: x64 and arm64.")
    build = BASE / "rj-linux-desktop/.build"
    build.mkdir(exist_ok=True)
    cache = build / "downloads"
    sources = json.loads((BASE / "packaging/python-linux.json").read_text())
    python_home = build / "python"
    if not python_home.is_dir():
        bundle.extract(bundle.download(sources[arch], cache), build)
    python = python_home / "bin/python3"
    # Upstream's install-only distribution contains PYTHON.json, rather than
    # uv's BUILD marker. Preserve the authenticated source metadata for the
    # shared native-memory builder's relocatable-runtime check.
    if not (python_home / "BUILD").is_file():
        (python_home / "BUILD").write_text(json.dumps({"distribution": "python-build-standalone", "source": sources[arch]}))
    environment = build / "venv"
    if not environment.is_dir():
        subprocess.run([str(python), "-m", "venv", str(environment)], check=True)
    build_python = environment / "bin/python"
    subprocess.run([
        str(build_python), "-m", "pip", "install", "--disable-pip-version-check",
        "-c", str(BASE / "packaging/core-constraints.txt"),
        "pyinstaller>=6.12,<7", "httpx>=0.28", "pytest", "pytest-asyncio", "ruff", "pyyaml",
        str(BASE / "packages/core") + "[anthropic]",
    ], check=True)
    versions = json.loads((BASE / "packaging/tool-versions.json").read_text())
    node = build / f"node-{versions['node']['version']}-linux-{arch}"
    if not node.is_dir():
        bundle.extract(bundle.download(versions["node"]["artifacts"][f"linux-{arch}"], cache), build)
    npm = node / "lib/node_modules/npm/bin/npm-cli.js"
    frontend = build / "frontend"
    node_env = {**os.environ, "PATH": str(node / "bin") + os.pathsep + os.environ.get("PATH", os.defpath)}
    subprocess.run([str(node / "bin/node"), str(npm), "install", "--prefix", str(frontend), "pnpm@12.11.2"], check=True, env=node_env)
    paths = [str(node / "bin"), str(frontend / "node_modules/.bin"), str(environment / "bin")]
    settings = build / "environment.sh"
    # Use shell quoting (shlex.quote), NOT Python repr(): repr switches to
    # double quotes around a value containing an apostrophe, and inside shell
    # double quotes `$(...)`/backticks execute — a path with `'` plus command
    # substitution would run on `source environment.sh`.
    settings.write_text(
        "# Generated native build paths; no credentials are stored here.\n"
        f"export PATH={shlex.quote(':'.join(paths))}:\"$PATH\"\n"
        f"export REDJOHN_BUILD_PYTHON={shlex.quote(str(build_python))}\n"
        f"export RJ_LINUX_ARCH={shlex.quote(arch)}\n"
    )
    print(f"Native build environment ready. Run: source {settings}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
