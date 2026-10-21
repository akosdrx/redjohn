"""Synthetic lifetime/schema faults, separate from real owner-death/E2E tests."""

import json
import os
import sqlite3
from dataclasses import asdict

import pytest

from redjohn.assessment import host_resources
from redjohn.assessment.host_resources import HostResourceLimits, HostResourcePool
from redjohn.assessment.resources import ResourceAdmissionError, ResourceGovernor


def test_process_only_claim_does_not_turn_observation_failure_into_owner_death(
    tmp_path, monkeypatch
):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    governor = ResourceGovernor(host_pool=pool)
    with governor.acquire(owner_process_only=True):
        with monkeypatch.context() as fault:
            fault.setattr(host_resources, "process_identity", lambda _pid: None)
            assert pool.recover() == 0
            assert pool.snapshot()["admission_blocked"] is True
        assert pool.snapshot()["active"] == {"worker": 1}
    assert pool.snapshot()["active"] == {}


def test_legacy_claim_is_never_reclassified_as_process_only(tmp_path):
    path = tmp_path / "host.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)
    with sqlite3.connect(path) as db:
        db.executescript(
            "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);"
            "CREATE TABLE leases (id TEXT PRIMARY KEY, owner TEXT NOT NULL, "
            "pid INTEGER NOT NULL, identity TEXT NOT NULL, kind TEXT NOT NULL, "
            "estimated_bytes INTEGER NOT NULL);"
        )
        db.execute(
            "INSERT INTO metadata VALUES ('policy', ?)",
            (json.dumps({"schema": 1, "limits": asdict(HostResourceLimits())}),),
        )
        # A synthetic old PID identity mismatch stands for an unclassified
        # legacy process. Its old row cannot prove that descendants are gone.
        db.execute(
            "INSERT INTO leases VALUES (?, ?, ?, ?, 'worker', 1048576)",
            ("1" * 32, "2" * 32, os.getpid(), "old-process-identity"),
        )
    pool = HostResourcePool(path)
    assert pool.recover() == 0
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT owner_process_only FROM leases").fetchall() == [(0,)]
    with pytest.raises(ResourceAdmissionError, match="host_owner_lost_requires_recovery"):
        ResourceGovernor(host_pool=pool).acquire()
    assert pool.snapshot()["reserved_bytes"] == 1048576


@pytest.mark.parametrize("kind", ["browser", "scanner", "page", "context"])
def test_process_owning_resources_cannot_claim_controller_only_lifetime(tmp_path, kind):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    with pytest.raises(ValueError, match="owner_process_only"):
        ResourceGovernor(host_pool=pool).acquire(kind, owner_process_only=True)
    assert pool.snapshot()["active"] == {}
