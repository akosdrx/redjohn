"""The private vault is published only after the fenced SQLite commit."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from redjohn.assessment.session_refresh import (
    SessionRefreshDenied,
    _activate_staged_private_json,
    _discard_staged_private_json,
    _fingerprint,
    _stage_private_json,
    _staged_path,
)


def _vault(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def test_staged_vault_does_not_change_the_active_file_before_commit(tmp_path):
    path = tmp_path / "vault.json"
    original = {"version": 2, "entries": [{"generation": "old"}]}
    replacement = {"version": 2, "entries": [{"generation": "new"}]}
    _vault(path, original)
    expected = _fingerprint(path.stat(follow_symlinks=False))
    staged = _stage_private_json(path, replacement, expected)

    assert json.loads(path.read_text()) == original
    assert staged == _staged_path(path)
    assert staged.exists()
    assert staged.stat().st_mode & 0o777 == 0o600

    _activate_staged_private_json(path)
    assert json.loads(path.read_text()) == replacement
    assert not staged.exists()


def test_failed_database_commit_discards_the_staged_credentials(tmp_path):
    path = tmp_path / "vault.json"
    original = {"version": 2, "entries": [{"generation": "old"}]}
    _vault(path, original)
    expected = _fingerprint(path.stat(follow_symlinks=False))
    _stage_private_json(path, {"version": 2, "entries": [{"generation": "new"}]}, expected)

    # This is the failure path used by finish_capture/finish_session_refresh.
    _discard_staged_private_json(path)
    assert json.loads(path.read_text()) == original
    assert not _staged_path(path).exists()


def test_changed_active_vault_rejects_staging(tmp_path):
    path = tmp_path / "vault.json"
    _vault(path, {"version": 2, "entries": [{"generation": "old"}]})
    expected = _fingerprint(path.stat(follow_symlinks=False))
    _vault(path, {"version": 2, "entries": [{"generation": "operator"}]})
    with pytest.raises(SessionRefreshDenied, match="session_refresh_vault_changed"):
        _stage_private_json(path, {"version": 2, "entries": []}, expected)
    assert not _staged_path(path).exists()
