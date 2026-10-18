#!/usr/bin/env python3
"""Explicit Linux CI-owned fixture build of pinned external service engines.

This is not a product redistributor or a license entitlement. Production users
configure their independently obtained, content-pinned Nmap installation. No
engine is installed or built by runtime startup/capability discovery.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath


CONFIGURE = (
    "--without-zenmap",
    "--without-ncat",
    "--without-nping",
    "--without-liblua",
    "--without-openssl",
    "--with-libpcap=included",
    "--with-libpcre=included",
    "--with-libdnet=included",
    "--with-libz=included",
    "--with-liblinear=included",
)


def fetch(url: str, digest: str, maximum: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "RedJohn-owned-service-fixture"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data: bytes = response.read(maximum + 1)
    if len(data) > maximum or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("service_source_download_digest_or_size_mismatch")
    return data


def run_fixed(
    command: list[str],
    root: Path,
    environment: dict[str, str],
    timeout: int,
    *,
    output_file: Path | None = None,
) -> None:
    """Keep a timed-out configure/compiler process group owned until killed."""
    with contextlib.ExitStack() as stack:
        output = stack.enter_context(output_file.open("wb")) if output_file is not None else None
        process = subprocess.Popen(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output if output is not None else sys.stderr,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            # Kill the owned group before reaping its leader, so a timed-out
            # compiler child cannot survive a leader which exits first.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
            raise
        if code:
            raise subprocess.CalledProcessError(code, command)


def inspect_fixed(command: list[str], root: Path, environment: dict[str, str], name: str) -> str:
    output = root / name
    run_fixed(command, root, environment, 5, output_file=output)
    if output.stat().st_size > 64 * 1024:
        raise ValueError("service_build_identity_output_limit")
    return output.read_text()


def source_version(source: Path) -> str:
    header = (source / "nmap.h").read_text()
    major = re.search(r"^#define NMAP_MAJOR ([0-9]+)$", header, re.M)
    minor = re.search(r"^#define NMAP_MINOR ([0-9]+)$", header, re.M)
    special = re.search(r'^#define NMAP_SPECIAL "([^"\\]*)"$', header, re.M)
    if major is None or minor is None or special is None:
        raise ValueError("service_source_version_macros_missing")
    return major[1] + "." + minor[1] + special[1]


def library_identities(ldd_output: str) -> list[dict[str, object]]:
    paths: set[Path] = set()
    for line in ldd_output.splitlines():
        for candidate in re.findall(r"(?:=> )?(/[^\s()]+)", line):
            paths.add(Path(candidate).resolve())
    if len(paths) > 32 or not paths:
        raise ValueError("service_build_shared_library_identity_unavailable")
    result = []
    for path in sorted(paths):
        if not path.is_file() or not 1 <= path.stat().st_size <= 32 * 1024**2:
            raise ValueError("service_build_shared_library_size_invalid")
        data = path.read_bytes()
        result.append(
            {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )
    return result


def profile_identity() -> dict[str, object]:
    # Read the literal public probe bytes without executing project code.
    source = Path(__file__).resolve().parents[1] / "redjohn/assessment/service_tools.py"
    if source.stat().st_size > 128 * 1024:
        raise ValueError("service_probe_source_size_invalid")
    tree = ast.parse(source.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "SERVICE_PROBES"
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if not isinstance(value, bytes) or not 1 <= len(value) <= 8192:
                break
            return {
                "name": "redjohn-nmap-service-profile-1",
                "bytes": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }
    raise ValueError("service_probe_literal_missing")


def extract(archive_path: Path, root: Path, prefix: str) -> Path:
    total, seen = 0, set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for index, member in enumerate(archive):
            path = PurePosixPath(member.name)
            total += member.size
            if (
                index >= 4096
                or total > 128 * 1024**2
                or member.size > 16 * 1024**2
                or not path.parts
                or path.parts[0] != prefix
                or path.is_absolute()
                or ".." in path.parts
                or member.name in seen
                or not (member.isdir() or member.isfile())
            ):
                raise ValueError("service_source_archive_schema_or_budget_denied")
            seen.add(member.name)
            target = root / str(path)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            handle = archive.extractfile(member)
            assert handle is not None
            with handle:
                target.write_bytes(handle.read(16 * 1024**2 + 1))
            target.chmod(0o700 if member.mode & 0o111 else 0o600)
    return root / prefix


def build(destination: Path | None = None) -> dict[str, object]:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "aarch64", "arm64"}:
        raise ValueError("service_fixture_build_requires_reviewed_linux_x64_or_arm64")
    pin = json.loads(Path(__file__).with_name("service-scanner-pins.json").read_text())["nmap"]
    target = (
        destination or Path(__file__).resolve().parents[1] / ".tools" / "nmap" / pin["version"]
    ).resolve()
    if target.exists():
        raise ValueError("service_install_exists_no_overwrite")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".redjohn-service-build-", dir=target.parent
    ) as temporary:
        root = Path(temporary)
        archive_path = root / "source.tar.gz"
        archive_path.write_bytes(fetch(pin["source_url"], pin["source_sha256"], 32 * 1024**2))
        source = extract(archive_path, root, pin["source_directory"])
        actual_source_version = source_version(source)
        if actual_source_version != pin["version"]:
            raise ValueError("service_source_version_mismatch")
        license_bytes = (source / "LICENSE").read_bytes()
        if hashlib.sha256(license_bytes).hexdigest() != pin["license_sha256"]:
            raise ValueError("service_source_license_digest_mismatch")
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(root),
            "TMPDIR": str(root),
            "LANG": "C.UTF-8",
            "CFLAGS": "-O2",
            "CXXFLAGS": "-O2",
        }
        # Fixed reviewed build commands, no shell or dependency/network installer.
        run_fixed([str(source / "configure"), *CONFIGURE], source, environment, 300)
        run_fixed(["make", "-j2", "nmap"], source, environment, 600)
        binary = (source / "nmap").read_bytes()
        if not binary.startswith(b"\x7fELF") or not 1 <= len(binary) <= 64 * 1024**2:
            raise ValueError("service_built_elf_required")
        native_version = inspect_fixed(
            [str(source / "nmap"), "--version"], root, environment, "native-version.txt"
        )
        if (
            re.search(r"Nmap version " + re.escape(pin["version"]) + r"(?:\s|$)", native_version)
            is None
            or re.search(r"Compiled without:.*liblua", native_version) is None
            or re.search(r"Compiled without:.*openssl", native_version) is None
        ):
            raise ValueError("service_built_version_or_nse_exclusion_mismatch")
        toolchain = {
            name: inspect_fixed(
                [command, "--version"], root, environment, name + "-version.txt"
            ).splitlines()[0]
            for name, command in (
                ("cc", "/usr/bin/cc"),
                ("cxx", "/usr/bin/c++"),
                ("make", "/usr/bin/make"),
            )
        }
        linked = inspect_fixed(
            ["/usr/bin/ldd", str(source / "nmap")], root, environment, "linked-libraries.txt"
        )
        libraries = library_identities(linked)
        profile = profile_identity()
        stage = root / "installation"
        stage.mkdir(mode=0o700)
        (stage / "nmap").write_bytes(binary)
        (stage / "nmap").chmod(0o700)
        (stage / "LICENSE").write_bytes(license_bytes)
        receipt = {
            **pin,
            "tool": "nmap",
            "binary_sha256": hashlib.sha256(binary).hexdigest(),
            "binary_bytes": len(binary),
            "source_macro_version": actual_source_version,
            "native_version_output": native_version,
            "build_toolchain": toolchain,
            "shared_libraries": libraries,
            "probe_profile": profile,
            "build_configure": list(CONFIGURE),
            "build_make": ["make", "-j2", "nmap"],
            "platform": platform.system() + "-" + platform.machine(),
            "license_scope": "owned_fixture_build_no_product_redistribution_entitlement",
            "dependencies": "bundled source identities inherit pinned source archive; no independent license/version attestations claimed",
        }
        (stage / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        stage.rename(target)
    return {"installation": str(target), **receipt}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("nmap",))
    parser.add_argument("--owned-fixture-build", action="store_true", required=True)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.destination), indent=2))


if __name__ == "__main__":
    main()
