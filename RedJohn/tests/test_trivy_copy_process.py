"""Actual small owned Python copier/stall PID lifecycles; no Trivy engine.

Kernel admission is explicitly doubled on this cross-platform contract suite.
DB bytes/terms are synthetic; these are not Linux guard or official-feed E2Es.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import signal
import sys
import time
from pathlib import Path

import pytest

from redjohn.assessment import trivy_copy, trivy_database, trivy_sbom
from redjohn.assessment.host_resources import process_identity
from redjohn.assessment.trivy_copy import (
    OwnedDatabaseCopier,
    TrivyCopyCleanupUnverified,
    TrivyCopyUnavailable,
)
from redjohn.assessment.trivy_database import DatabaseSnapshot
from tests.test_trivy_database_contract import synthetic_database
from tests.test_trivy_sbom_contract import configured


def fixture_copier(tmp_path, monkeypatch, *, stall=False, timeout=1):
    raw, _ = synthetic_database(tmp_path)
    config = DatabaseSnapshot.from_mapping(raw)
    copier = OwnedDatabaseCopier(timeout_seconds=timeout)
    marker = tmp_path / "owned-pid"
    monkeypatch.setattr(
        trivy_copy, "_owner_fence", lambda: ("synthetic-kernel-admission-double", 1)
    )

    def fixed_fixture_command(payload):
        root = str(Path(__file__).resolve().parents[1])
        bootstrap = (
            f"import sys,json;sys.path.insert(0,{root!r});"
            "from redjohn.assessment import _trivy_database_copy_worker as worker;"
        )
        if stall and payload["operation"] != "cleanup":
            script = (
                bootstrap + "import os,signal,time;from pathlib import Path;"
                "value=json.loads(sys.argv[1]);"
                "worker._create_owned_root(Path(value['destination']),value['nonce']);"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                f"Path({str(marker)!r}).write_text(str(os.getpid()));time.sleep(60)"
            )
        else:
            # Only Linux admission is doubled; fixed production prepare/cleanup
            # reads, hashes, copies and removes every fixture file in the child.
            script = bootstrap + "worker._owner=lambda value:None;raise SystemExit(worker.main())"
        return [sys.executable, "-I", "-S", "-c", script, json.dumps(payload)]

    monkeypatch.setattr(copier, "_command", fixed_fixture_command)
    return copier, config, marker


async def ready(marker):
    async with asyncio.timeout(3):
        while not marker.is_file():
            await asyncio.sleep(0.005)
    return int(marker.read_text())


async def test_actual_owned_copy_process_streams_synthetic_bytes_and_reaps(tmp_path, monkeypatch):
    copier, config, _ = fixture_copier(tmp_path, monkeypatch)
    destination = tmp_path / "snapshot"
    assert await copier.snapshot(config, destination) == ("synthetic-advisory",)
    assert (destination / "db" / "trivy.db").read_bytes() == (config.root / "trivy.db").read_bytes()
    assert copier.process is None and copier.proof["process_cleanup_verified"] is True
    assert process_identity(copier.proof["pid"]) is None
    assert copier.proof["reservation_retention_wired"] is False
    assert copier.resource_cleanup_verified() is False
    await copier.cleanup()
    assert copier.resource_cleanup_verified() is True and not destination.exists()


@pytest.mark.parametrize("cancel", [False, True])
async def test_actual_stalled_copier_timeout_or_cancel_is_reaped_while_heartbeat_runs(
    tmp_path, monkeypatch, cancel
):
    copier, config, marker = fixture_copier(
        tmp_path, monkeypatch, stall=True, timeout=30 if cancel else 0.4
    )
    destination = tmp_path / "snapshot"
    ticks = []

    async def heartbeat():
        while True:
            ticks.append(time.monotonic())
            await asyncio.sleep(0.01)

    beat = asyncio.create_task(heartbeat())
    started = time.monotonic()
    task = asyncio.create_task(copier.snapshot(config, destination))
    try:
        pid = await ready(marker)
        await asyncio.sleep(0.05)
        if cancel:
            task.cancel()
        with pytest.raises(asyncio.CancelledError if cancel else TimeoutError):
            await asyncio.wait_for(task, 4)
        assert time.monotonic() - started < 3
        assert len(ticks) >= 3
        assert process_identity(pid) is None
        assert copier.process is None and copier.proof["cleanup_verified"] is True
        assert not destination.exists()
    finally:
        beat.cancel()
        await asyncio.gather(beat, return_exceptions=True)
        await copier.cleanup()


async def test_unverified_reap_fault_retains_process_and_paths_with_typed_retention_request(
    tmp_path, monkeypatch
):
    """Real stalled PID + injected unverified wait; this is not a real D-state test."""
    copier, config, _ = fixture_copier(tmp_path, monkeypatch, stall=True, timeout=0.25)
    destination = tmp_path / "quarantine"
    actual_reaped = copier._reaped

    async def cannot_prove_reaped(_seconds):
        return False

    monkeypatch.setattr(copier, "_reaped", cannot_prove_reaped)
    try:
        with pytest.raises(TrivyCopyCleanupUnverified) as caught:
            await copier.snapshot(config, destination)
        assert copier.process is caught.value.process
        assert caught.value.requires_lease_retention is True
        assert caught.value.partial_proof["cleanup_verified"] is False
        assert caught.value.partial_proof["reservation_retention_wired"] is False
        assert copier.cleanup_unverified is True and destination.exists()
    finally:
        monkeypatch.setattr(copier, "_reaped", actual_reaped)
        await copier.cleanup()
        if destination.exists():
            shutil.rmtree(destination)
    assert copier.process is None and copier.cleanup_unverified is False


async def test_signal_permission_error_requires_confirmed_reap_instead_of_false_cleanup(
    tmp_path, monkeypatch
):
    """Actual stalled child; denied TERM still requires a real KILL and wait."""
    copier, config, marker = fixture_copier(tmp_path, monkeypatch, stall=True, timeout=0.3)
    actual_signal = os.killpg
    denied = []

    def deny_term(pid, selected_signal):
        if selected_signal == signal.SIGTERM:
            denied.append(pid)
            raise PermissionError("injected_signal_denial")
        actual_signal(pid, selected_signal)

    monkeypatch.setattr(trivy_copy.os, "killpg", deny_term)
    task = asyncio.create_task(copier.snapshot(config, tmp_path / "snapshot"))
    pid = await ready(marker)
    try:
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(task, 3)
        assert denied == [pid]
        assert copier.process is None and copier.proof["cleanup_verified"] is True
        assert process_identity(pid) is None
    finally:
        monkeypatch.setattr(trivy_copy.os, "killpg", actual_signal)
        await copier.cleanup()


async def test_repeated_cancellation_joins_actual_child_cleanup_before_return(
    tmp_path, monkeypatch
):
    copier, config, marker = fixture_copier(tmp_path, monkeypatch, stall=True, timeout=30)
    actual_reaped = copier._reaped
    cleanup_entered = asyncio.Event()

    async def observe_cleanup(seconds):
        cleanup_entered.set()
        return await actual_reaped(seconds)

    monkeypatch.setattr(copier, "_reaped", observe_cleanup)
    destination = tmp_path / "snapshot"
    task = asyncio.create_task(copier.snapshot(config, destination))
    pid = await ready(marker)
    try:
        task.cancel()
        await asyncio.wait_for(cleanup_entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        assert copier.process is None and copier.proof["cleanup_verified"] is True
        assert process_identity(pid) is None
        assert not destination.exists()
    finally:
        await copier.cleanup()
        if destination.exists():
            shutil.rmtree(destination)


async def test_repeated_cancellation_during_spawn_still_acquires_and_reaps_child(
    tmp_path, monkeypatch
):
    copier, config, _ = fixture_copier(tmp_path, monkeypatch, stall=True, timeout=30)
    actual_spawn = asyncio.create_subprocess_exec
    created = []
    started, deliver = asyncio.Event(), asyncio.Event()

    async def delayed_delivery(*args, **kwargs):
        process = await actual_spawn(*args, **kwargs)
        created.append(process)
        started.set()
        await deliver.wait()
        return process

    monkeypatch.setattr(trivy_copy.asyncio, "create_subprocess_exec", delayed_delivery)
    destination = tmp_path / "snapshot"
    task = asyncio.create_task(copier.snapshot(config, destination))
    try:
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        deliver.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        assert created[0].returncode is not None
        assert copier.process is None and copier.proof["cleanup_verified"] is True
        assert process_identity(created[0].pid) is None
        assert not destination.exists()
    finally:
        deliver.set()
        await copier.cleanup()
        for process in created:
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
            await process.wait()
        if destination.exists():
            shutil.rmtree(destination)


async def test_missing_actual_kernel_fence_blocks_before_spawn_or_destination_creation(
    tmp_path, monkeypatch
):
    raw, _ = synthetic_database(tmp_path)
    config = DatabaseSnapshot.from_mapping(raw)
    monkeypatch.setattr(trivy_copy, "current_memory_fence", lambda: None)
    copier = OwnedDatabaseCopier()
    with pytest.raises(TrivyCopyUnavailable, match="attested_current_owner"):
        await copier.snapshot(config, tmp_path / "never-created")
    assert copier.process is None and not (tmp_path / "never-created").exists()


async def test_pending_process_delivery_has_absolute_deadline_and_owned_late_reaper(
    tmp_path, monkeypatch
):
    copier, config, marker = fixture_copier(tmp_path, monkeypatch, stall=True, timeout=0.1)
    actual_spawn = asyncio.create_subprocess_exec
    started, deliver = asyncio.Event(), asyncio.Event()
    created = []

    async def delayed_delivery(*args, **kwargs):
        process = await actual_spawn(*args, **kwargs)
        created.append(process)
        if len(created) == 1:
            started.set()
            await deliver.wait()
        return process

    monkeypatch.setattr(trivy_copy.asyncio, "create_subprocess_exec", delayed_delivery)
    destination = tmp_path / "quarantine"
    task = asyncio.create_task(copier.snapshot(config, destination))
    began = time.monotonic()
    try:
        await asyncio.wait_for(started.wait(), 2)
        assert copier.requires_lease_retention and not copier.resource_cleanup_verified()
        assert copier._pending_spawn is not None and copier.process is None
        with pytest.raises(TrivyCopyCleanupUnverified) as caught:
            await asyncio.wait_for(task, 2)
        assert time.monotonic() - began < 1.5
        assert caught.value.pending_spawn is copier._pending_spawn
        assert caught.value.process is None and copier.requires_lease_retention
        assert process_identity(await ready(marker)) is not None
        deliver.set()
        async with asyncio.timeout(3):
            while copier._pending_spawn is not None or copier.process is not None:
                await asyncio.sleep(0.005)
        assert process_identity(created[0].pid) is None
        # Late reap alone does not release the remaining private path ownership.
        assert copier.requires_lease_retention
        await copier.cleanup()
        assert copier.resource_cleanup_verified() and not destination.exists()
    finally:
        deliver.set()
        with contextlib.suppress(TrivyCopyCleanupUnverified):
            await copier.cleanup()
        for process in created:
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
            await process.wait()


async def test_concurrent_prepare_cannot_replace_first_process_or_output_ownership(
    tmp_path, monkeypatch
):
    copier, config, marker = fixture_copier(tmp_path, monkeypatch, stall=True, timeout=30)
    first = tmp_path / "first"
    task = asyncio.create_task(copier.snapshot(config, first))
    pid = await ready(marker)
    try:
        with pytest.raises(TrivyCopyUnavailable, match="previous_resources"):
            await copier.snapshot(config, tmp_path / "second")
        assert copier.destination == first and copier.process.pid == pid
        assert not (tmp_path / "second").exists()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 3)
        assert copier.resource_cleanup_verified() and process_identity(pid) is None
    finally:
        await copier.cleanup()


async def test_concurrent_cancel_and_cleanup_preserve_one_owned_cleanup_operation(
    tmp_path, monkeypatch
):
    copier, config, marker = fixture_copier(tmp_path, monkeypatch, stall=True, timeout=30)
    task = asyncio.create_task(copier.snapshot(config, tmp_path / "snapshot"))
    pid = await ready(marker)
    await asyncio.wait_for(asyncio.gather(copier.cancel(), copier.cleanup()), 3)
    with pytest.raises(asyncio.CancelledError):
        await task
    assert copier.resource_cleanup_verified() and process_identity(pid) is None


async def test_nonce_mismatch_retains_private_paths_without_false_cleanup(tmp_path, monkeypatch):
    copier, config, _ = fixture_copier(tmp_path, monkeypatch)
    destination = tmp_path / "snapshot"
    await copier.snapshot(config, destination)
    marker = destination / ".redjohn-trivy-owner"
    original = marker.read_bytes()
    marker.chmod(0o600)
    marker.write_text("another-owner")
    try:
        with pytest.raises(TrivyCopyCleanupUnverified):
            await copier.cleanup()
        assert destination.exists() and copier.requires_lease_retention
        assert not copier.resource_cleanup_verified()
    finally:
        marker.write_bytes(original)
        marker.chmod(0o400)
        await copier.cleanup()
    assert copier.resource_cleanup_verified() and not destination.exists()


async def test_actual_stalled_cleanup_retains_paths_until_a_confirmed_retry(tmp_path, monkeypatch):
    copier, config, _ = fixture_copier(tmp_path, monkeypatch)
    destination = tmp_path / "snapshot"
    await copier.snapshot(config, destination)
    actual_command = copier._command
    marker = tmp_path / "cleanup-pid"

    def stall_cleanup(payload):
        if payload["operation"] != "cleanup":
            return actual_command(payload)
        script = (
            "import os,signal,time;from pathlib import Path;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            f"Path({str(marker)!r}).write_text(str(os.getpid()));time.sleep(60)"
        )
        return [sys.executable, "-I", "-S", "-c", script]

    monkeypatch.setattr(copier, "_command", stall_cleanup)
    try:
        with pytest.raises(TrivyCopyCleanupUnverified):
            await asyncio.wait_for(copier.cleanup(), 8)
        assert process_identity(await ready(marker)) is None
        assert destination.exists() and copier.requires_lease_retention
        assert copier.proof["cleanup_verified"] is False
    finally:
        monkeypatch.setattr(copier, "_command", actual_command)
        await copier.cleanup()
    assert copier.resource_cleanup_verified() and not destination.exists()


def full_configuration(tmp_path):
    area = tmp_path / "full-inputs"
    area.mkdir()
    return configured(area)


async def test_actual_helper_prepares_all_pinned_inputs_without_parent_original_path_io(
    tmp_path, monkeypatch
):
    config = full_configuration(tmp_path)
    area = tmp_path / "copier"
    area.mkdir()
    copier, _, _ = fixture_copier(area, monkeypatch)

    def forbidden_parent_io(*_args, **_kwargs):
        raise AssertionError("operator IO belongs to the supervised child")

    monkeypatch.setattr(trivy_database, "read_source_file", forbidden_parent_io)
    monkeypatch.setattr(trivy_sbom, "read_source_file", forbidden_parent_io)
    # Composition and authority checks are structural even with this IO fence.
    config = trivy_sbom.TrivySBOMConfig.from_mapping(config.to_dict())
    config.database.validate()
    destination = tmp_path / "prepared"
    try:
        value = await copier.prepare(config, destination, b"synthetic public CA fixture")
        assert value["packages"][0]["purl"] == "pkg:pypi/requests@2.20.0"
        assert value["artifact_sha256"] == config.artifact_sha256
        assert value["configuration_revision"] == config.revision
        assert (destination / "snapshot/cache/db/trivy.db").read_bytes() == (
            config.database.root / "trivy.db"
        ).read_bytes()
        assert (
            destination / "snapshot/engine/trivy"
        ).read_bytes() == b"SYNTHETIC_NOT_AN_EXECUTABLE"
        assert (destination / "snapshot/source/bom.cdx.json").is_file()
        assert (destination / "snapshot/cache/db/terms/0.txt").is_file()
        assert value["valid_until"] > time.time()
        assert copier.requires_lease_retention  # Native reader has not finished.
    finally:
        await copier.cleanup()
    assert copier.resource_cleanup_verified() and not destination.exists()


@pytest.mark.parametrize(
    "selected", ["binary", "sbom", "database", "metadata", "provenance", "terms"]
)
async def test_actual_helper_denies_operator_fifo_without_blocking_parent(
    tmp_path, monkeypatch, selected
):
    config = full_configuration(tmp_path)
    paths = {
        "binary": config.binary.path,
        "sbom": config.source.source_root / config.source.files[0][0],
        "database": config.database.root / "trivy.db",
        "metadata": config.database.root / "metadata.json",
        "provenance": config.database.provenance_file,
        "terms": config.database.provenance_file.parent / "synthetic-terms.txt",
    }
    paths[selected].unlink()
    os.mkfifo(paths[selected], 0o600)
    area = tmp_path / "copier"
    area.mkdir()
    copier, _, _ = fixture_copier(area, monkeypatch)
    destination = tmp_path / "prepared"
    started = time.monotonic()
    with pytest.raises(TrivyCopyUnavailable):
        await asyncio.wait_for(
            copier.prepare(config, destination, b"synthetic public CA fixture"), 3
        )
    assert time.monotonic() - started < 3
    assert copier.resource_cleanup_verified() and not destination.exists()
