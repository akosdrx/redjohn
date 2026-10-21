"""Real local HTTP regressions for the authenticated Viewer metadata routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest

from redjohn.config import load_settings
from redjohn.interface.viewer import server
from redjohn.skills import get_available_skills


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("endpoint", ["skills", "config"])
def test_authenticated_metadata_endpoints_use_current_redjohn_contracts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, endpoint: str
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "index.html").write_text("<!doctype html><title>RedJohn metadata fixture</title>")
    monkeypatch.setattr(server, "bundle_dir", lambda: assets)
    # Keep local-account bootstrap out of the operator's profile. The actual
    # HTTP capability/cookie authorization and endpoint handlers stay intact.
    monkeypatch.setattr(server.auth, "ensure_local_verified", lambda: None)
    httpd, base, token = server.serve(tmp_path / "run", open_browser=False)
    try:
        with httpx.Client(trust_env=False, timeout=5) as client:
            assert client.get(f"{base}/api/{endpoint}").status_code == 403
            bootstrap = client.get(server.authorized_url(base, token))
            assert bootstrap.status_code == 200
            assert client.cookies
            response = client.get(f"{base}/api/{endpoint}")
            assert response.status_code == 200
            payload = response.json()
            if endpoint == "skills":
                available = get_available_skills()
                assert payload == {
                    "total": sum(len(items) for items in available.values()),
                    "categories": available,
                }
                assert payload["total"] >= 47
            else:
                settings = load_settings()
                assert payload == {
                    "model_name": settings.llm.model,
                    "reasoning_effort": settings.llm.reasoning_effort,
                    "runtime_backend": settings.runtime.backend,
                    "telemetry_enabled": settings.telemetry.enabled,
                }
                assert "api_key" not in payload
    finally:
        httpd.shutdown()
        httpd.server_close()
