"""Installation presence/configured versions remain distinct from live proof."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from redjohn.assessment.registry import CapabilityRegistry


def _nuclei_health(registry: CapabilityRegistry) -> dict:
    return next(row for row in registry.health() if row["id"] == "nuclei_scan")


def test_repo_managed_nuclei_presence_is_not_binary_or_live_verification(tmp_path, monkeypatch):
    binary = tmp_path / ".tools/nuclei/3.11.1/nuclei"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"presence fixture")
    binary.chmod(0o700)
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: None)
    registry = CapabilityRegistry(repository_root=tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("health must neither read/launch nor hash a binary")

    monkeypatch.setattr(
        "redjohn.assessment.registry._playwright_chromium_executable", lambda: None
    )
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    for _ in range(2):
        row = _nuclei_health(registry)
        assert row["binary_path"] == str(binary)
        assert row["binary_path_source"] == "repo_managed"
        assert row["binary_presence_only"] is True
        assert row["live_verified"] is False
        assert row["status"] == "blocked_configuration"
        assert row["reason"] == "reviewed_template_lock_not_configured"


def test_missing_managed_nuclei_retains_path_lookup_and_missing_status(tmp_path, monkeypatch):
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: None)
    registry = CapabilityRegistry(repository_root=tmp_path)
    missing = _nuclei_health(registry)
    assert missing["binary_path"] is None
    assert missing["binary_presence_only"] is False
    assert missing["status"] == "blocked_missing_dependency"
    assert missing["reason"] == "binary_not_installed"
    monkeypatch.setattr(
        "redjohn.assessment.registry.shutil.which",
        lambda name: "/configured/path/nuclei" if name == "nuclei" else None,
    )
    present = _nuclei_health(registry)
    assert present["binary_path"] == "/configured/path/nuclei"
    assert present["binary_path_source"] == "PATH"
    assert present["live_verified"] is False
    assert present["status"] == "blocked_configuration"


def test_explicit_binary_path_presence_is_configurable_and_has_no_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: "/other/nuclei")
    selected = tmp_path / "explicit-nuclei"
    registry = CapabilityRegistry(repository_root=tmp_path, nuclei_binary_path=selected)
    assert _nuclei_health(registry)["binary_path"] is None
    selected.write_bytes(b"explicit engine presence")
    selected.chmod(0o700)
    row = _nuclei_health(registry)
    assert row["binary_path"] == str(selected)
    assert row["binary_path_source"] == "configured"
    assert row["live_verified"] is False
    assert row["status"] == "blocked_configuration"
    selected.unlink()
    assert _nuclei_health(registry)["status"] == "blocked_missing_dependency"


def test_explicit_lock_supplies_binary_presence_and_execution_identity(tmp_path, monkeypatch):
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: None)
    binary = tmp_path / "locked-nuclei"
    binary.write_bytes(b"file presence is sufficient for the catalogue")
    binary.chmod(0o700)
    registry = CapabilityRegistry(
        repository_root=tmp_path,
        nuclei_lock={
            "binary": {"path": str(binary), "version": "3.11.1"},
            "bundle": {"sha256": "a" * 64},
        },
    )
    row = _nuclei_health(registry)
    assert row["binary_path"] == str(binary)
    assert row["binary_path_source"] == "configured"
    assert row["live_verified"] is False
    assert row["status"] == "implemented_fixture_tested"
    assert registry.execution_versions("nuclei_scan") == {
        "tool_version": "3.11.1",
        "template_version": "a" * 64,
    }
    returned = registry.execution_versions("nuclei_scan")
    returned["tool_version"] = "mutated"
    assert registry.execution_versions("nuclei_scan")["tool_version"] == "3.11.1"


def test_empty_explicit_lock_does_not_make_present_binary_ready(tmp_path, monkeypatch):
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: "/path/nuclei")
    registry = CapabilityRegistry(repository_root=tmp_path, nuclei_lock={})
    row = _nuclei_health(registry)
    assert row["binary_path"] == "/path/nuclei"
    assert row["status"] == "blocked_configuration"
    assert row["reason"] == "reviewed_template_lock_not_configured"


def test_default_registry_execution_identity_retains_existing_job_defaults(tmp_path):
    registry = CapabilityRegistry(repository_root=tmp_path)
    expected = {"tool_version": "1", "template_version": ""}
    assert registry.execution_versions("nuclei_scan") == expected
    assert registry.execution_versions("browser_discover") == expected
    assert CapabilityRegistry().get("nuclei_scan") is not None


@pytest.mark.parametrize(
    "lock",
    [
        {"binary": []},
        {"bundle": []},
        {"binary": {"version": None}},
        {"bundle": {"sha256": 1}},
    ],
)
def test_registry_rejects_malformed_explicit_metadata_without_launching(tmp_path, lock):
    with pytest.raises(TypeError, match="invalid_nuclei_registry_lock_metadata"):
        CapabilityRegistry(repository_root=tmp_path, nuclei_lock=lock)


def test_archive_on_managed_path_is_not_an_installed_executable(tmp_path, monkeypatch):
    monkeypatch.setattr("redjohn.assessment.registry.shutil.which", lambda _name: None)
    archive = tmp_path / ".tools/arjun/2.2.7/arjun.tar"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"not an executable")
    registry = CapabilityRegistry(repository_root=tmp_path)
    row = next(item for item in registry.health() if item["id"] == "arjun_parameters")
    assert row["binary_path"] is None
    assert row["archive_present"] is True
    assert row["status"] == "blocked_missing_dependency"


def test_browser_health_requires_the_playwright_chromium_executable(tmp_path, monkeypatch):
    root = tmp_path / "ms-playwright"
    executable = root / "chromium_headless_shell-999/chrome-linux/headless_shell"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"fixture")
    executable.chmod(0o700)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(root))
    monkeypatch.setattr(
        "redjohn.assessment.registry._playwright_browser_revisions",
        lambda: {"chromium-headless-shell": "999"},
    )
    registry = CapabilityRegistry(repository_root=tmp_path)
    row = next(item for item in registry.health() if item["id"] == "browser_discover")
    assert row["binary_path"] == str(executable)
    assert row["binary_path_source"] == "playwright_cache"
    assert row["status"] != "blocked_missing_dependency"


def test_browser_health_blocks_missing_chromium_without_launching(tmp_path, monkeypatch):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty"))
    monkeypatch.setattr(
        "redjohn.assessment.registry._playwright_browser_revisions",
        lambda: {"chromium": "999", "chromium-headless-shell": "999"},
    )
    registry = CapabilityRegistry(repository_root=tmp_path)
    row = next(item for item in registry.health() if item["id"] == "browser_discover")
    assert row["binary_path"] is None
    assert row["status"] == "blocked_missing_dependency"
    assert row["reason"] == "chromium_executable_missing"
