"""Installer integrity fault tests with mocked downloads; never engine integration."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import sys
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def installer(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location(
        "redjohn_pinned_installer", Path(__file__).parents[1] / "scripts/install-nuclei-pinned.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(module.platform, "machine", lambda: "arm64")
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("nuclei", b"explicit-fake-installer-test-binary")
    binary_zip = data.getvalue()
    digest = hashlib.sha256(binary_zip).hexdigest()
    checksum = f"{digest}  nuclei_{module.VERSION}_macOS_arm64.zip\n".encode()
    license_data = b"MIT License\nProjectDiscovery test-double license"
    monkeypatch.setattr(module, "ARCHIVES", {("Darwin", "arm64"): ("macOS_arm64", digest)})
    monkeypatch.setattr(module, "CHECKSUMS_SHA256", hashlib.sha256(checksum).hexdigest())
    monkeypatch.setattr(module, "LICENSE_SHA256", hashlib.sha256(license_data).hexdigest())
    target = tmp_path / "engine"
    monkeypatch.setattr(sys, "argv", ["installer", "--destination", str(target)])
    responses = {
        module.BASE + f"nuclei_{module.VERSION}_checksums.txt": checksum,
        module.BASE + f"nuclei_{module.VERSION}_macOS_arm64.zip": binary_zip,
        module.LICENSE_URL: license_data,
    }
    monkeypatch.setattr(module, "fetch", lambda url, _maximum: responses[url])
    return module, target, responses


def test_mock_installer_download_success_writes_verified_receipt(installer):
    module, target, _responses = installer
    module.main()
    assert (target / "nuclei").read_bytes() == b"explicit-fake-installer-test-binary"
    assert (target / "receipt.json").is_file()
    assert (target / "LICENSE.md").is_file()


def test_mock_installer_refuses_existing_target_without_fetch(installer, monkeypatch):
    module, target, _responses = installer
    target.mkdir()
    (target / "preserve").write_text("user-data")
    monkeypatch.setattr(
        module, "fetch", lambda *_args: pytest.fail("download before overwrite refusal")
    )
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        module.main()
    assert (target / "preserve").read_text() == "user-data"


def test_mock_installer_atomic_directory_race_preserves_even_empty_target(installer, monkeypatch):
    module, target, responses = installer

    def fetch(url, _maximum):
        if url == module.LICENSE_URL:
            target.mkdir()
        return responses[url]

    monkeypatch.setattr(module, "fetch", fetch)
    with pytest.raises(FileExistsError):
        module.main()
    assert target.is_dir()
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("artifact", ["archive", "checksums", "license"])
def test_mock_installer_checksum_failure_never_installs(installer, artifact):
    module, target, responses = installer
    url = (
        module.BASE + f"nuclei_{module.VERSION}_macOS_arm64.zip"
        if artifact == "archive"
        else module.BASE + f"nuclei_{module.VERSION}_checksums.txt"
        if artifact == "checksums"
        else module.LICENSE_URL
    )
    responses[url] = b"tampered-content"
    with pytest.raises(RuntimeError):
        module.main()
    assert not target.exists()
