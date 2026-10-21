"""Real native supervisor/process tests with an explicitly fake Nuclei engine."""

from __future__ import annotations

import asyncio
import hashlib
import json
import stat
import sys
import uuid
from pathlib import Path

import pytest

from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.tools.hunt.nuclei import (
    NucleiAdapter,
    NucleiLock,
    TemplateSelection,
    bundle_digest,
)
from tests.test_hunt_nuclei import TEMPLATE


@pytest.fixture
def native_factory(tmp_path):
    sessions = []

    def create(*, scan="candidate", sleep_version=False, max_output_bytes=4 * 1024**2):
        binary = tmp_path / (uuid.uuid4().hex + "-fake-nuclei")
        binary.write_text(f"""#!{sys.executable}
import json, os, sys, time
if '-version' in sys.argv:
    if {sleep_version!r}: time.sleep(30)
    print('Nuclei Engine Version: v3.5.1', file=sys.stderr)
else:
    if {scan!r} == 'oversized':
        print('x'*20000)
    else:
        print(json.dumps({{"template-id":"fixture-marker","type":"http","matcher-status":True,"matched-at":"http://127.0.0.1:8123/marker","info":{{"name":"fixture","severity":"info"}},"env_secret":os.environ.get('REDJOHN_TEST_PROVIDER_SECRET','absent')}}))
""")
        binary.chmod(0o700)
        bundle = tmp_path / (uuid.uuid4().hex + "-templates")
        bundle.mkdir()
        (bundle / "marker.yaml").write_bytes(TEMPLATE)
        files = {"marker.yaml": hashlib.sha256(TEMPLATE).hexdigest()}
        lock = NucleiLock(
            str(binary),
            "3.5.1",
            hashlib.sha256(binary.read_bytes()).hexdigest(),
            "local-test-double",
            "test-only",
            str(bundle),
            "fixture-1",
            bundle_digest(files),
            "local-test-fixture",
            "Apache-2.0",
            files,
            (TemplateSelection("marker.yaml", "fixture-marker", ("isolated-lab",)),),
        )
        policy = EngagementPolicy(
            "native-test",
            "owner",
            ("http://127.0.0.1:8123",),
            profile="isolated-lab",
            egress_mode="local-fixture",
        )
        session = NativeFixtureSession(
            policy, tmp_path / uuid.uuid4().hex, lock, max_output_bytes=max_output_bytes
        )
        sessions.append(session)
        return session, lock, policy

    yield create
    assert all(not session._active and not session._reservations for session in sessions)


def version_command(session, lock):
    config = {
        "token": uuid.uuid4().hex,
        "argv": [lock.binary_path, "-version"],
        "timeout": 180,
        "max_output_bytes": 65536,
        "digests": {lock.binary_path: lock.binary_sha256},
        "nuclei": False,
        "snapshot_files": [],
    }
    return ("python3", "-c", session._source, json.dumps(config))


async def test_mock_engine_through_real_native_supervisor_uses_pins_and_sanitized_environment(
    native_factory, monkeypatch
):
    session, lock, policy = native_factory()
    monkeypatch.setenv("REDJOHN_TEST_PROVIDER_SECRET", "must-not-reach-child")
    evidence = []
    adapter = NucleiAdapter(
        session, lock, evidence_sink=lambda raw: evidence.append(raw) or "raw-ref"
    )
    result = await adapter.run("http://127.0.0.1:8123", policy=policy)
    assert result["execution_status"] == "succeeded", result
    assert result["findings"][0]["finding_status"] == "candidate"
    assert '"env_secret": "absent"' in evidence[0]["stdout"]
    assert "must-not-reach-child" not in json.dumps(evidence)
    assert stat.S_IMODE(session.workspace.stat().st_mode) == 0o700
    assert not list(session.workspace.glob(".redjohn-hunt/*"))
    assert not list(session.workspace.glob(".redjohn-nuclei-*"))
    await session.aclose()


async def test_native_session_refuses_arbitrary_code_shell_unpinned_files_and_targets(
    native_factory,
):
    session, lock, _policy = native_factory()
    with pytest.raises(PolicyDenied, match="trusted_worker"):
        await session.exec("sh", "-c", "echo bypass", "", timeout=1, shell=False)
    with pytest.raises(PolicyDenied, match="trusted_worker"):
        await session.exec("python3", "-c", "print('bypass')", "", timeout=1, shell=False)
    with pytest.raises(PolicyDenied):
        await session.exec(*version_command(session, lock), timeout=1, shell=True)  # noqa: S604 - assert refusal
    command = list(version_command(session, lock))
    config = json.loads(command[-1])
    config["argv"] = ["/bin/sh", "-c", "true"]
    command[-1] = json.dumps(config)
    with pytest.raises(PolicyDenied):
        await session.exec(*command, timeout=1, shell=False)
    with pytest.raises(PolicyDenied, match="read_denied"):
        await session.read(Path("/etc/passwd"))
    await session.aclose()
    with pytest.raises(PolicyDenied):
        await session.exec(*version_command(session, lock), timeout=1, shell=False)


async def test_native_template_read_is_bounded_even_if_file_grows(native_factory):
    session, lock, _policy = native_factory()
    path = Path(lock.bundle_root) / "marker.yaml"
    stream = await session.read(path)
    path.write_bytes(b"x" * 100000)
    try:
        with pytest.raises(ValueError, match="file_limit"):
            stream.read()
    finally:
        stream.close()
    with pytest.raises(ValueError, match="file_limit"):
        await session.read(path)


async def test_native_outer_deadline_cleans_supervisor_and_descendant_groups(native_factory):
    session, lock, _policy = native_factory(sleep_version=True)
    with pytest.raises(TimeoutError):
        await session.exec(*version_command(session, lock), timeout=0.1, shell=False)
    assert not session._active and not session._reservations
    assert not list(session.workspace.glob(".redjohn-hunt/*"))
    assert not list(session.workspace.glob(".redjohn-nuclei-*"))


async def test_native_cancellation_cleans_processes_and_lease_token(native_factory):
    session, lock, _policy = native_factory(sleep_version=True)
    task = asyncio.create_task(NucleiAdapter(session, lock).healthcheck())
    for _ in range(100):
        if list(session.workspace.glob(".redjohn-hunt/*.child")):
            break
        await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not session._active and not session._reservations
    assert not list(session.workspace.glob(".redjohn-hunt/*"))


async def test_native_outer_output_limit_fails_without_negative_scan(native_factory):
    session, lock, policy = native_factory(scan="oversized", max_output_bytes=8192)
    result = await NucleiAdapter(session, lock).run("http://127.0.0.1:8123", policy=policy)
    assert result["error"]["code"] == "worker_transport_error"
    assert result["coverage_status"] == "blocked" and result["no_finding_observed"] is False
    assert not list(session.workspace.glob(".redjohn-hunt/*"))


def test_native_session_is_unavailable_for_production_or_unenforced_egress(
    native_factory, tmp_path
):
    _session, lock, _policy = native_factory()
    policy = EngagementPolicy(
        "remote",
        "owner",
        ("https://example.invalid",),
        profile="safe-production",
        egress_mode="unavailable",
    )
    with pytest.raises(PolicyDenied, match="local_fixture_lab"):
        NativeFixtureSession(policy, tmp_path / "blocked", lock)


def test_native_proxy_binding_is_host_exact_and_busy_state_is_not_mutable(native_factory):
    session, _lock, _policy = native_factory()
    for invalid in (
        "http://localhost:8123",
        "https://127.0.0.1:8123",
        "http://127.0.0.1:8123/",
        "http://user@127.0.0.1:8123",
    ):
        with pytest.raises(ValueError):
            session.bind_proxy(invalid)
    session.bind_proxy("http://127.0.0.1:8123")
    session._reservations.add("busy")
    with pytest.raises(PolicyDenied, match="proxy_binding_busy"):
        session.bind_proxy(None)
    session._reservations.clear()
    session.bind_proxy(None)
