"""Host resource policy persistence: operator intent survives, defaults migrate once."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from typing import TYPE_CHECKING

from redjohn.assessment.host_resources import (
    _LEGACY_DEFAULT_LIMITS,
    HostResourceLimits,
    HostResourcePool,
    _host_derived_limits,
)


if TYPE_CHECKING:
    from pathlib import Path


def _write_legacy_policy(pool_path: Path, limits: HostResourceLimits) -> None:
    db = sqlite3.connect(pool_path)
    try:
        db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")
        db.execute(
            "INSERT INTO metadata VALUES ('policy', ?)",
            (json.dumps({"schema": 1, "limits": asdict(limits)}, sort_keys=True),),
        )
        db.commit()
    finally:
        db.close()
    pool_path.chmod(0o600)


def test_first_open_uses_host_derived_default(tmp_path) -> None:
    pool = HostResourcePool(tmp_path / "host.db")
    assert pool.limits == _host_derived_limits()

    db = sqlite3.connect(tmp_path / "host.db")
    record = json.loads(db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()[0])
    db.close()
    assert record["schema"] == 2
    assert record["source"] == "default"


def test_operator_narrowed_policy_survives_reopen(tmp_path) -> None:
    pool_path = tmp_path / "host.db"
    pool = HostResourcePool(pool_path)
    narrowed = HostResourceLimits(
        memory_budget_bytes=2048 * 1024 * 1024,
        max_workers=2,
        max_browsers=1,
        max_pages=2,
        max_contexts=2,
    )
    pool.configure(narrowed)
    assert HostResourcePool(pool_path).limits == narrowed


def test_untouched_legacy_default_migrates_once(tmp_path) -> None:
    pool_path = tmp_path / "host.db"
    _write_legacy_policy(pool_path, _LEGACY_DEFAULT_LIMITS)

    pool = HostResourcePool(pool_path)
    assert pool.limits == _host_derived_limits()
    # Reopening must not drift the policy further.
    assert HostResourcePool(pool_path).limits == _host_derived_limits()

    db = sqlite3.connect(pool_path)
    record = json.loads(db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()[0])
    db.close()
    assert record["schema"] == 2
    assert record["source"] == "default"


def test_operator_tuned_legacy_policy_is_never_widened(tmp_path) -> None:
    pool_path = tmp_path / "host.db"
    tuned = HostResourceLimits(
        memory_budget_bytes=2048 * 1024 * 1024,
        max_workers=2,
        max_browsers=1,
        max_pages=2,
        max_contexts=2,
    )
    _write_legacy_policy(pool_path, tuned)

    assert HostResourcePool(pool_path).limits == tuned
    assert HostResourcePool(pool_path).limits == tuned
