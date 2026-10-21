"""Fixed owned WP observation file preparer; no input code/commands/network.

Invoked only by the trusted selected-job supervisor. This file has its own WP
nonce/owner protocol; no Trivy database grant or report can authorize its IO.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import re
import shutil
import signal
import stat
import sys
from pathlib import Path
from typing import Any


def directory(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("wpscan_absolute_directory_required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def owner(value: dict[str, Any]) -> None:
    group = Path(value["fence_path"])
    membership = next(
        line[3:]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    if (
        platform.system() != "Linux"
        or os.getuid() != value["uid"]
        or not group.is_absolute()
        or group.resolve() != group
        or group.stat().st_ino != value["fence_inode"]
        or Path("/sys/fs/cgroup") / membership.lstrip("/") != group
        or not os.statvfs("/sys/fs/cgroup").f_flag & os.ST_RDONLY
        or status["NoNewPrivs"].strip() != "1"
        or any(int(status[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapAmb"))
    ):
        raise ValueError("wpscan_io_owner_fence_unverified")
    parent = os.getppid()
    seen: set[int] = set()
    initial_parent = parent
    while parent != value["controller"]:
        if parent < 2 or parent in seen or len(seen) >= 8:
            raise ValueError("wpscan_io_controller_ancestry_unverified")
        seen.add(parent)
        row = next(
            line
            for line in Path(f"/proc/{parent}/status").read_text().splitlines()
            if line.startswith("PPid:")
        )
        parent = int(row.split(":", 1)[1])
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) or os.getppid() != initial_parent:
        raise ValueError("wpscan_io_parent_death_fence_unavailable")


def marker(value: dict[str, Any]) -> bytes:
    return json.dumps(
        {k: value[k] for k in ("nonce", "controller", "uid", "fence_path", "fence_inode")},
        sort_keys=True,
    ).encode()


def create_root(path: Path, value: dict[str, Any]) -> None:
    parent = directory(path.parent)
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("wpscan_io_private_parent_required")
        os.mkdir(path.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    root = directory(path)
    try:
        handle = os.open(
            ".redjohn-wpscan-owner",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
            dir_fd=root,
        )
        with os.fdopen(handle, "wb") as stream:
            stream.write(marker(value))
    finally:
        os.close(root)


def remove_root(path: Path, value: dict[str, Any]) -> None:
    parent = directory(path.parent)
    try:
        try:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("wpscan_io_cleanup_owner_unverified")
        root = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            handle = os.open(
                ".redjohn-wpscan-owner", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root
            )
            with os.fdopen(handle, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or stream.read(
                    1025
                ) != marker(value):
                    raise ValueError("wpscan_io_cleanup_nonce_unverified")
        finally:
            os.close(root)
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError("wpscan_io_descriptor_cleanup_required")
        shutil.rmtree(path.name, dir_fd=parent)
    finally:
        os.close(parent)


def prepare(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    from redjohn.assessment.source_tools import read_source_file  # noqa: PLC0415
    from redjohn.assessment.wpscan_component import component_payload  # noqa: PLC0415
    from redjohn.assessment.wpscan_observe import WPScanObserveConfig  # noqa: PLC0415
    from redjohn.assessment.wpscan_runtime import MAX_RUNTIME_BYTES, MAX_RUNTIME_FILE_BYTES  # noqa: PLC0415

    config = WPScanObserveConfig.from_mapping(value["configuration"])
    runtime = config.runtime.load_manifest()
    if platform.machine() != runtime.architecture:
        raise ValueError("wpscan_io_runtime_architecture_mismatch")
    create_root(path, value)
    engine = path / "engine"
    engine.mkdir(mode=0o700)
    total = 0
    for entry in runtime.files:
        data = read_source_file(runtime.root, entry.path, entry.sha256, MAX_RUNTIME_FILE_BYTES)
        total += len(data)
        if total > MAX_RUNTIME_BYTES:
            raise ValueError("wpscan_io_runtime_total_budget")
        target = engine / entry.path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o500 if entry.executable else 0o400)
    for name, data in component_payload(config.component, config.artifact).items():
        (engine / name).write_bytes(data)
        (engine / name).chmod(0o400)
    (path / "source").mkdir(mode=0o700)
    return {
        "prepared": True,
        "nonce": value["nonce"],
        "configuration_revision": config.revision,
        "manifest_sha256": runtime.manifest_sha256,
        "architecture": runtime.architecture,
        "binary_sha256": runtime.binary.sha256,
        "load_paths": runtime.load_paths,
        "expected_features": runtime.expected_features,
        "runtime_files": len(runtime.files),
        "runtime_bytes": total,
    }


def main() -> int:
    try:
        if len(sys.argv) != 2 or len(sys.argv[1].encode()) > 32768:
            raise ValueError("wpscan_io_frame_budget")  # noqa: TRY301
        value = json.loads(sys.argv[1])
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "operation",
                "configuration",
                "destination",
                "nonce",
                "controller",
                "uid",
                "fence_path",
                "fence_inode",
            }
            or value["operation"] not in {"prepare", "cleanup"}
            or not isinstance(value["configuration"], dict)
            or any(
                type(value[key]) is not int or value[key] < 1
                for key in ("controller", "fence_inode")
            )
            or type(value["uid"]) is not int
            or value["uid"] < 0
            or not isinstance(value["nonce"], str)
            or re.fullmatch(r"[a-f0-9]{32}", value["nonce"]) is None
            or any(
                not isinstance(value[key], str) or len(value[key].encode()) > 4096
                for key in ("destination", "fence_path")
            )
            or not Path(value["destination"]).is_absolute()
            or ".." in Path(value["destination"]).parts
        ):
            raise ValueError("wpscan_io_frame_schema")  # noqa: TRY301
        owner(value)
        path = Path(value["destination"])
        if value["operation"] == "prepare":
            result = prepare(path, value)
        else:
            if value["configuration"]:
                raise ValueError("wpscan_io_cleanup_schema")  # noqa: TRY301
            remove_root(path, value)
            result = {"cleaned": True, "nonce": value["nonce"]}
        encoded = json.dumps(result, separators=(",", ":"))
        if len(encoded.encode()) > 192 * 1024:
            raise ValueError("wpscan_io_result_budget")  # noqa: TRY301
        sys.stdout.write(encoded + "\n")
    except Exception:  # noqa: BLE001 - fixed helper never emits operator paths/content
        sys.stdout.write('{"error":"wpscan_owned_file_preparation_unavailable"}\n')
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
