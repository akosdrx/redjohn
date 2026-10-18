"""Fault/configuration contracts; these are not kernel enforcement evidence."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from redjohn.assessment import memory_pool, os_memory
from redjohn.assessment.memory_exec import _save, supervise
from redjohn.assessment.memory_pool import LinuxMemoryPool
from redjohn.assessment.os_memory import LinuxMemoryBoundary, MemoryLimitUnavailableError
from redjohn.assessment.resources import MIB, ResourceGovernor
from redjohn.runtime import backends


@pytest.mark.parametrize("aggregate", [True, 0, 63 * MIB, 2**51])
def test_invalid_aggregate_budget_cannot_create_a_pool(tmp_path, aggregate):
    with pytest.raises(ValueError, match="invalid_aggregate_memory_budget"):
        LinuxMemoryBoundary(
            {"delegated_root": str(tmp_path), "aggregate_memory_budget_bytes": aggregate},
            64 * MIB,
        )
    assert list(tmp_path.iterdir()) == []


def test_pool_never_adopts_or_reconfigures_unknown_existing_group(tmp_path, monkeypatch):
    monkeypatch.setattr(memory_pool, "_MOUNT", tmp_path)
    root, state = tmp_path / "root", tmp_path / "private"
    root.mkdir()
    pool = LinuxMemoryPool(root, 128 * MIB, state)
    pool.group.mkdir()
    marker = pool.group / "keep"
    marker.write_text("unrelated data")
    with pytest.raises(MemoryLimitUnavailableError, match="aggregate_memory_pool_unavailable"):
        pool.ensure()
    assert marker.read_text() == "unrelated data"


def test_pool_state_symlink_cannot_overwrite_a_private_file(tmp_path, monkeypatch):
    monkeypatch.setattr(memory_pool, "_MOUNT", tmp_path)
    root, state = tmp_path / "root", tmp_path / "state"
    root.mkdir()
    state.mkdir(mode=0o700)
    target = tmp_path / "preserve.json"
    target.write_text("preserve")
    (state / (hashlib.sha256(str(root).encode()).hexdigest() + ".json")).symlink_to(target)
    with pytest.raises(OSError):
        LinuxMemoryPool(root, 128 * MIB, state).ensure()
    assert target.read_text() == "preserve"


def test_receipt_symlink_is_rejected_without_changing_target(tmp_path):
    target, link = tmp_path / "preserve", tmp_path / "receipt"
    target.write_text("keep")
    link.symlink_to(target)
    with pytest.raises(ValueError, match="memory_receipt_not_private"):
        _save(link, {"enforced": True})
    assert target.read_text() == "keep"


def test_already_contained_owner_cannot_escape_into_another_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(os_memory.platform, "system", lambda: "Linux")
    monkeypatch.setattr(Path, "is_file", lambda _path: True)
    monkeypatch.setattr(os_memory, "current_memory_fence", lambda: ("owned", 1))
    with (
        pytest.raises(MemoryLimitUnavailableError, match="must_reuse_existing_memory_fence"),
        LinuxMemoryBoundary({"delegated_root": str(tmp_path)}, 64 * MIB),
    ):
        pytest.fail("a contained owner moved outside its existing hard limit")


@pytest.mark.parametrize("name", ["docker", "custom_unattested"])
def test_hard_profile_rejects_daemon_and_custom_backends_without_starting(name, monkeypatch):
    monkeypatch.setattr(os_memory, "current_memory_fence", lambda: ("owned", 1))
    monkeypatch.setenv("REDJOHN_REQUIRE_OWNED_MEMORY", "1")
    if name == "custom_unattested":
        monkeypatch.setitem(backends._BACKENDS, name, backends._docker_backend)
    with pytest.raises(MemoryLimitUnavailableError, match="backend_ownership_unverified"):
        backends.get_backend(name)
    assert backends.get_backend("local") is backends._local_backend


def test_missing_fence_is_not_software_admission_success(monkeypatch):
    monkeypatch.setattr(os_memory, "current_memory_fence", lambda: None)
    result = ResourceGovernor().snapshot()["os_memory"]
    assert result["enforced"] is False
    monkeypatch.setenv("REDJOHN_REQUIRE_OWNED_MEMORY", "1")
    with pytest.raises(MemoryLimitUnavailableError, match="membership_not_enforced"):
        backends.get_backend("local")


def test_missing_kernel_backend_writes_blocked_receipt_without_starting(tmp_path, monkeypatch):
    monkeypatch.setattr(os_memory.platform, "system", lambda: "Darwin")
    receipt = tmp_path / "receipt.json"
    marker = tmp_path / "must-not-exist"
    code = supervise(
        [sys.executable, "-c", f"open({str(marker)!r},'w').write('started')"],
        {"delegated_root": str(tmp_path)},
        64 * MIB,
        timeout=1,
        receipt=receipt,
    )
    assert code == 2 and not marker.exists()
    result = json.loads(receipt.read_text())
    assert result["outcome"] == "blocked"
    assert result["reason"] == "linux_cgroup_v2_required"
    assert result["process_cleanup_verified"] is False
    assert "argv" not in result and receipt.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("kind", ["fifo", "incomplete_json"])
def test_owner_attestation_is_regular_bounded_and_schema_checked(tmp_path, kind):
    boundary = LinuxMemoryBoundary({"delegated_root": str(tmp_path)}, 64 * MIB)
    boundary._attestation_directory = tempfile.TemporaryDirectory(dir=tmp_path)
    try:
        marker = Path(boundary._attestation_directory.name) / "attestation.json"
        if kind == "fifo":
            os.mkfifo(marker, mode=0o600)
        else:
            marker.write_text('{"verified":true}')
            marker.chmod(0o600)
        assert boundary._owner_attestation()["verified"] is False
    finally:
        boundary._release_attestation()


def _current_guard_fixture(tmp_path, monkeypatch):
    proc, mount = tmp_path / "proc", tmp_path / "cgroup"
    group = mount / ("redjohn-" + "a" * 32)
    group.mkdir(parents=True)
    for name, value in {"memory.max": 64 * MIB, "memory.swap.max": 0, "pids.max": 512}.items():
        (group / name).write_text(str(value))
    (proc / "self/fd").mkdir(parents=True)
    (proc / "self/ns").mkdir()
    (proc / "self/ns/user").symlink_to("user:[1234]")
    (proc / "self/ns/mnt").symlink_to("mnt:[1235]")
    status = "CapInh: 0\nCapPrm: 0\nCapEff: 0\nCapAmb: 0\nNoNewPrivs: 1\nPPid: 1\n"
    (proc / "self/status").write_text(status)
    (proc / "self/uid_map").write_text(f"{os.getuid()} {os.getuid()} 1\n")
    (proc / "1").mkdir()
    (proc / "1/status").write_text("PPid: 0\n")
    monkeypatch.setattr(os_memory, "_PROC", proc)
    monkeypatch.setattr(os_memory, "_MOUNT", mount)
    monkeypatch.setattr(
        os_memory, "current_memory_fence", lambda: (str(group), group.stat().st_ino)
    )
    monkeypatch.setattr(os_memory.os, "statvfs", lambda _path: SimpleNamespace(f_flag=os.ST_RDONLY))
    monkeypatch.setattr(os_memory, "_write_open_denied", lambda _path: True)
    monkeypatch.setenv("REDJOHN_CONTAINED_GROUP", str(group))
    monkeypatch.setenv("REDJOHN_MEMORY_OWNER_NAMESPACE", "readonly_cgroupfs_no_capabilities")
    return proc, mount, group


@pytest.mark.parametrize(
    "fault",
    [
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapAmb",
        "NoNewPrivs",
        "uid_map",
        "writable_mount",
        "direct_alias",
        "ancestor_alias",
        "inherited_descriptor",
        "inherited_directory",
    ],
)
def test_matching_membership_and_forged_marker_cannot_replace_current_kernel_guard(
    tmp_path, monkeypatch, fault
):
    proc, mount, group = _current_guard_fixture(tmp_path, monkeypatch)
    if fault.startswith("Cap") or fault == "NoNewPrivs":
        status = proc / "self/status"
        old, new = ("0", "1") if fault.startswith("Cap") else ("1", "0")
        status.write_text(status.read_text().replace(f"{fault}: {old}", f"{fault}: {new}"))
    elif fault == "uid_map":
        (proc / "self/uid_map").write_text("0 0 4294967295\n")
    elif fault == "writable_mount":
        monkeypatch.setattr(os_memory.os, "statvfs", lambda _path: SimpleNamespace(f_flag=0))
    elif fault == "inherited_descriptor":
        (proc / "self/fd/99").symlink_to(group)
    elif fault == "inherited_directory":
        # A different device still supplies a traversal handle. The guard must
        # reject its directory mode independently of cgroupfs device identity.
        assert Path("/dev").stat().st_dev != mount.stat().st_dev
        (proc / "self/fd/99").symlink_to("/dev", target_is_directory=True)
    else:
        monkeypatch.setattr(
            os_memory,
            "_write_open_denied",
            lambda path: (
                proc in path.parents if fault == "direct_alias" else proc not in path.parents
            ),
        )
    with pytest.raises(MemoryLimitUnavailableError, match="owner_guard_unverified"):
        os_memory.require_inline_memory_boundary(
            {"os_memory": {"delegated_root": str(mount)}}, 64 * MIB
        )
    assert (group / "memory.max").read_text() == str(64 * MIB)


def test_borrowed_current_boundary_records_independent_kernel_guard(tmp_path, monkeypatch):
    _proc, mount, _group = _current_guard_fixture(tmp_path, monkeypatch)
    borrowed = LinuxMemoryBoundary.current({"delegated_root": str(mount)}, 64 * MIB)
    assert borrowed is not None and borrowed.borrowed
    proof = borrowed._owner_attestation()
    assert proof["verified"] and proof["source"] == "current_kernel_state_rechecked"
