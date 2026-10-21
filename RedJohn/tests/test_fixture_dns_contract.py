"""Owned numeric fixture must not initialize a process-global DNS resolver.

The DNS guard is a deliberate contract double. HTTP/TLS sockets, certificate
verification, actor cookies and server cleanup remain actual implementations.
"""

from __future__ import annotations

import ssl

import httpx
import pytest

from redjohn.assessment.fixture import FixtureServer
from redjohn.assessment.tls_fixture import TLSFixtureServer


@pytest.mark.parametrize("tls", [False, True])
def test_owned_literal_fixture_never_reverse_resolves_and_preserves_http_tls(
    monkeypatch: pytest.MonkeyPatch, tls: bool
) -> None:
    def forbidden_reverse_lookup(_address: str) -> str:
        raise AssertionError("owned_literal_fixture_must_not_reverse_resolve")

    monkeypatch.setattr("socket.getfqdn", forbidden_reverse_lookup)
    fixture = TLSFixtureServer() if tls else FixtureServer()
    with fixture:
        assert fixture.server.server_name == "127.0.0.1"
        assert fixture.server.server_port > 0
        context = ssl.create_default_context(cafile=str(fixture.ca_file)) if tls else True
        with httpx.Client(verify=context, trust_env=False, timeout=5) as client:
            response = client.get(
                fixture.origin + "/api/me", headers={"Cookie": "fixture_actor=alice"}
            )
            assert response.status_code == 200
            assert response.json()["actor"] == "alice"
            assert response.headers["X-RedJohn-Fixture"] == "initial"
            fixture.fixed = True
            fixed = client.get(fixture.origin + "/api/me")
            assert fixed.headers["Content-Security-Policy"] == "default-src 'self'"
            assert fixed.headers["X-RedJohn-Fixture"] == "fixed"
    assert not fixture.thread.is_alive()
    assert fixture.server.socket.fileno() == -1
