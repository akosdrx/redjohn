"""On-demand light-tool provisioning: download, SHA-256 verify, extract, index."""

from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile

import httpx
import pytest
from redjohn_core import tool_provisioner as prov
from redjohn_core.errors import RJError
from redjohn_core.settings import Settings


def _fake_zip(binary_name: str, content: bytes = b"#!/bin/sh\necho redjohn\n") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(binary_name, content)
    return buffer.getvalue()


def _manifest(url: str, sha: str) -> dict:
    return {
        "nuclei": {
            "version": "v9.9.9",
            "binary": "nuclei",
            "artifacts": {prov.current_platform(): {"url": url, "sha256": sha, "file": "nuclei.zip"}},
        }
    }


def _mock_httpx(monkeypatch, payload: bytes):
    original = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=payload)

    def client(*args, **kwargs):
        return original(*args, **kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(prov.httpx, "Client", client)


def test_provision_downloads_verifies_and_indexes(tmp_path, monkeypatch):
    payload = _fake_zip("nuclei")
    sha = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(prov, "load_manifest", lambda: _manifest("https://example/nuclei.zip", sha))
    _mock_httpx(monkeypatch, payload)
    settings = Settings(redjohn_home=tmp_path)
    status = prov.provision(settings)
    root = settings.profile_dir / "tools"
    binary = root / "bin" / "nuclei"
    assert binary.is_file() and os.access(binary, os.X_OK)
    index = json.loads((root / "tool-index.json").read_text())
    assert index["tools"]["nuclei"]["command"] == ["{root}/bin/nuclei"]
    assert next(t for t in status["items"] if t["id"] == "nuclei")["present"] is True


def test_provision_rejects_checksum_mismatch(tmp_path, monkeypatch):
    payload = _fake_zip("nuclei")
    monkeypatch.setattr(prov, "load_manifest", lambda: _manifest("https://example/nuclei.zip", "0" * 64))
    _mock_httpx(monkeypatch, payload)
    settings = Settings(redjohn_home=tmp_path)
    with pytest.raises(RJError, match="checksum"):
        prov.provision(settings)
    assert not (settings.profile_dir / "tools" / "bin" / "nuclei").exists()


def test_shipped_manifest_lists_the_light_tools_with_pinned_artifacts():
    manifest = prov.load_manifest()
    assert set(manifest) == {"nuclei", "httpx", "katana", "subfinder", "ffuf", "dalfox", "gau"}
    for entry in manifest.values():
        assert entry["artifacts"], "each light tool must list platform artifacts"
        for artifact in entry["artifacts"].values():
            assert artifact["url"].startswith("https://") and len(artifact["sha256"]) == 64
