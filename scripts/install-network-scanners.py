#!/usr/bin/env python3
"""Explicit native Naabu/dnsx installation from reviewed release SHA256 pins."""

from __future__ import annotations
import argparse
import hashlib
import json
import platform
import runpy
import tempfile
from pathlib import Path


def install(tool: str, destination: Path | None = None) -> dict[str, object]:
    base = Path(__file__).resolve().parent
    pin = json.loads((base / "network-scanner-pins.json").read_text())[tool]
    arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    asset = pin["assets"].get(platform.system() + "-" + str(arch))
    if asset is None:
        raise ValueError("network_native_platform_not_reviewed")
    target = (destination or base.parent / ".tools" / tool / pin["version"]).resolve()
    if target.exists():
        raise ValueError("network_native_install_exists_no_overwrite")
    helpers = runpy.run_path(str(base / "install-source-scanners.py"))
    archive = helpers["fetch"](asset["url"], asset["sha256"], 32 * 1024**2)
    binary = helpers["executable"](archive, "wheel", asset["member"])
    license_data = helpers["fetch"](pin["license_url"], pin["license_sha256"], 65536)
    receipt = {
        "tool": tool,
        "version": pin["version"],
        "source_commit": pin["commit"],
        "license": pin["license"],
        "license_sha256": pin["license_sha256"],
        "source": pin["source"],
        "archive_url": asset["url"],
        "archive_sha256": asset["sha256"],
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "binary_bytes": len(binary),
        "platform": platform.system() + "-" + str(arch),
        "verification": "official release SHA256 pin, not independent signature",
    }
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".redjohn-network-install-", dir=target.parent) as temp:
        stage = Path(temp)
        (stage / tool).write_bytes(binary)
        (stage / tool).chmod(0o700)
        (stage / "LICENSE").write_bytes(license_data)
        (stage / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        stage.rename(target)
    return {"installation": str(target), **receipt}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("naabu", "dnsx"))
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(install(args.tool, args.destination), indent=2))


if __name__ == "__main__":
    main()
