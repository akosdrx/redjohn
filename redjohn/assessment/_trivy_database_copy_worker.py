"""Fixed standard-library DB copier; no scanner, network or command dispatch.

The owning supervisor supplies only exact file pins and private destination.
This helper independently verifies the inherited Linux owner fence before IO.
"""

from __future__ import annotations

import ctypes
import hashlib
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


def _directory(path: str) -> int:
    selected = Path(path)
    if not selected.is_absolute() or ".." in selected.parts:
        raise ValueError("absolute_directory_required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in selected.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _owner(value: dict[str, Any]) -> None:
    group = Path(value["fence_path"])
    if (
        platform.system() != "Linux"
        or os.getuid() != value["uid"]
        or os.getppid() != value["parent"]
        or not group.is_absolute()
        or group.resolve() != group
        or group.stat().st_ino != value["fence_inode"]
        or not os.statvfs("/sys/fs/cgroup").f_flag & os.ST_RDONLY
    ):
        raise ValueError("owner_fence_unverified")
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    membership = next(
        line[3:].strip()
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    if (
        Path("/sys/fs/cgroup") / membership.lstrip("/") != group
        or status["NoNewPrivs"].strip() != "1"
        or any(int(status[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapAmb"))
    ):
        raise ValueError("owner_fence_unverified")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != value["parent"]:
        raise ValueError("parent_death_fence_unavailable")


def _stream_file(source: Path, target: Path, expected: str, maximum: int) -> int:
    source_root = _directory(str(source.parent))
    target_root = None
    descriptor = None
    try:
        target_root = _directory(str(target.parent))
        info = os.fstat(target_root)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("destination_not_private")
        descriptor = os.open(
            source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_root
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise ValueError("source_type_or_size_mismatch")
        output = os.open(
            target.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o500,
            dir_fd=target_root,
        )
        digest, count = hashlib.sha256(), 0
        with os.fdopen(output, "wb") as handle:
            while chunk := os.read(descriptor, min(65536, before.st_size + 1 - count)):
                count += len(chunk)
                if count > before.st_size:
                    raise ValueError("source_byte_limit")
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        after = os.fstat(descriptor)
        names = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            any(getattr(before, key) != getattr(after, key) for key in names)
            or count != before.st_size
            or digest.hexdigest() != expected
        ):
            raise ValueError("source_changed_or_digest_mismatch")
        return count
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(source_root)
        if target_root is not None:
            os.close(target_root)


def _marker(nonce: str) -> bytes:
    return json.dumps(
        {"nonce": nonce, "uid": os.getuid(), "parent": os.getppid()}, sort_keys=True
    ).encode()


def _parent(destination: Path) -> int:
    try:
        return _directory(str(destination.parent))
    except FileNotFoundError:
        descriptor = _directory(str(destination.parent.parent))
        try:
            os.mkdir(destination.parent.name, 0o700, dir_fd=descriptor)
        except FileExistsError:
            pass
        finally:
            os.close(descriptor)
        return _directory(str(destination.parent))


def _create_owned_root(destination: Path, nonce: str) -> None:
    descriptor = _parent(destination)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("private_output_parent_unverified")
        os.mkdir(destination.name, 0o700, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    root = _directory(str(destination))
    try:
        marker = os.open(
            ".redjohn-trivy-owner",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
            dir_fd=root,
        )
        with os.fdopen(marker, "wb") as handle:
            handle.write(_marker(nonce))
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(root)


def _remove_owned_root(destination: Path, nonce: str) -> dict[str, Any]:
    try:
        parent = _directory(str(destination.parent))
    except FileNotFoundError:
        return {"cleaned": True, "nonce": nonce}
    try:
        try:
            info = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return {"cleaned": True, "nonce": nonce}
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("cleanup_owner_unverified")
        root = os.open(
            destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        try:
            marker = os.open(
                ".redjohn-trivy-owner", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root
            )
            with os.fdopen(marker, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode) or handle.read(
                    513
                ) != _marker(nonce):
                    raise ValueError("cleanup_nonce_unverified")
        finally:
            os.close(root)
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError("descriptor_safe_cleanup_unavailable")
        shutil.rmtree(destination.name, dir_fd=parent)
    finally:
        os.close(parent)
    return {"cleaned": True, "nonce": nonce}


def _prepare(
    operation: str, configuration: dict[str, Any], destination: Path, nonce: str, ca_pem: str = ""
) -> dict[str, Any]:
    # Imports are fixed project modules, not operator-selected code/plugins.
    # The supervisor supplies their trusted installation root to isolated Python.
    from redjohn.assessment.trivy_database import (  # noqa: PLC0415
        MAX_PROVENANCE_BYTES,
        DatabaseSnapshot,
        bounded_document,
        timestamp,
    )

    _create_owned_root(destination, nonce)
    if operation == "database":
        database = DatabaseSnapshot.from_mapping(configuration)
        revision = database.revision
        database_root = destination / "db"
        packages: list[dict[str, Any]] = []
        artifact = ""
        engine_bytes = 0
    elif operation == "sbom":
        from dataclasses import asdict  # noqa: PLC0415

        from redjohn.assessment.source_tools import read_source_file  # noqa: PLC0415
        from redjohn.assessment.trivy_sbom import (  # noqa: PLC0415
            MAX_SBOM_BYTES,
            TrivySBOMConfig,
            parse_cyclonedx,
        )

        selected = TrivySBOMConfig.from_mapping(configuration)
        database, revision, artifact = (
            selected.database,
            selected.revision,
            selected.artifact_sha256,
        )
        workspace = destination / "workspace"
        workspace.mkdir(mode=0o700)
        (workspace / "proxy-ca.pem").write_text(ca_pem)
        (workspace / "proxy-ca.pem").chmod(0o600)
        (workspace / "empty-ca-directory").mkdir(mode=0o700)
        snapshot = destination / "snapshot"
        snapshot.mkdir(mode=0o700)
        (snapshot / "cache").mkdir(mode=0o700)
        database_root = snapshot / "cache" / "db"
        (snapshot / "engine").mkdir(mode=0o700)
        engine_bytes = _stream_file(
            selected.source.binary.path,
            snapshot / "engine" / "trivy",
            selected.source.binary.sha256,
            256 * 1024**2,
        )
        relative, expected = selected.source.files[0]
        raw = read_source_file(selected.source.source_root, relative, expected, MAX_SBOM_BYTES)
        packages = [asdict(package) for package in parse_cyclonedx(raw)]
        target = snapshot / "source" / relative
        target.parent.mkdir(mode=0o700, parents=True)
        with target.open("xb") as handle:
            handle.write(raw)
        target.chmod(0o400)
        (snapshot / "empty-ignore").touch(mode=0o400)
    else:
        raise ValueError("unsupported_owned_operation")
    sources = database.snapshot(database_root)
    metadata_raw, provenance_raw, _ = database.read_metadata()
    metadata = bounded_document(metadata_raw, 2048)
    provenance = bounded_document(provenance_raw, MAX_PROVENANCE_BYTES)
    valid_until = min(
        timestamp(metadata["NextUpdate"]),
        timestamp(metadata["UpdatedAt"]) + database.max_age_seconds,
        timestamp(provenance["acquired_at"]) + database.max_age_seconds,
    )
    return {
        "prepared": True,
        "operation": operation,
        "configuration_revision": revision,
        "database_bytes": database.database_bytes,
        "database_sha256": database.database_sha256,
        "metadata_sha256": database.metadata_sha256,
        "provenance_sha256": database.provenance_sha256,
        "data_sources": list(sources),
        "valid_until": valid_until,
        "packages": packages,
        "artifact_sha256": artifact,
        "engine_bytes": engine_bytes,
    }


def main() -> int:
    try:
        if len(sys.argv) != 2 or len(sys.argv[1].encode()) > 32768:
            raise ValueError("configuration_byte_limit")  # noqa: TRY301 - fixed worker emits no private exception detail
        value = json.loads(sys.argv[1])
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "operation",
                "configuration",
                "destination",
                "nonce",
                "ca_pem",
                "fence_path",
                "fence_inode",
                "uid",
                "parent",
            }
            or value["operation"] not in {"database", "sbom", "cleanup"}
            or not isinstance(value["configuration"], dict)
            or any(
                type(value[key]) is not int or value[key] < 1 for key in ("fence_inode", "parent")
            )
            or type(value["uid"]) is not int
            or value["uid"] < 0
            or not isinstance(value["destination"], str)
            or not Path(value["destination"]).is_absolute()
            or ".." in Path(value["destination"]).parts
            or len(value["destination"].encode()) > 4096
            or not isinstance(value["nonce"], str)
            or re.fullmatch(r"[a-f0-9]{32}", value["nonce"]) is None
            or not isinstance(value["ca_pem"], str)
            or len(value["ca_pem"].encode()) > 8192
        ):
            raise ValueError("configuration_not_supported")  # noqa: TRY301 - fixed worker emits no private exception detail
        _owner(value)
        if value["operation"] == "cleanup":
            if value["configuration"] or value["ca_pem"]:
                raise ValueError("cleanup_schema")  # noqa: TRY301 - no raw diagnostics
            result = _remove_owned_root(Path(value["destination"]), value["nonce"])
        else:
            result = _prepare(
                value["operation"],
                value["configuration"],
                Path(value["destination"]),
                value["nonce"],
                value["ca_pem"],
            )
    except (OSError, ValueError, TypeError, KeyError, StopIteration, RecursionError):
        sys.stdout.write(
            json.dumps({"prepared": False, "error": "owned_snapshot_prepare_failed"}) + "\n"
        )
        return 2
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
