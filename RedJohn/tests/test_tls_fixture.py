"""Actual Python TLS handshakes against the ephemeral local HTTPS fixture."""

# ruff: noqa: S310 -- URLs are generated literal-loopback HTTPS fixture addresses.

from __future__ import annotations

import ipaddress
import json
import ssl
import stat
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest
from cryptography import x509

from redjohn.assessment.fixture import PAGE
from redjohn.assessment.tls_fixture import TLSFixtureServer


def test_tls_fixture_explicit_ca_preserves_spa_api_cookie_and_controls():
    with TLSFixtureServer() as fixture:
        context = ssl.create_default_context(cafile=str(fixture.ca_file))
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        with urlopen(fixture.origin, context=context, timeout=5) as response:
            assert response.read() == PAGE
            assert response.headers["X-RedJohn-Fixture"] == "initial"
        request = Request(fixture.origin + "/api/me", headers={"Cookie": "fixture_actor=alice"})
        with urlopen(request, context=context, timeout=5) as response:
            assert json.loads(response.read())["actor"] == "alice"
        assert {"path": "/api/me", "actor": "alice", "method": "GET"} in fixture.observed_actors
        fixture.fixed = True
        with urlopen(fixture.origin + "/api/items", context=context, timeout=5) as response:
            assert response.headers["X-RedJohn-Fixture"] == "fixed"
            assert response.headers["X-Content-Type-Options"] == "nosniff"
        with pytest.raises(HTTPError) as limited:
            urlopen(fixture.origin + "/rate-limit", context=context, timeout=5)
        assert limited.value.code == 429
        assert limited.value.headers["Retry-After"] == "1"
        assert fixture.counts == {"/": 1, "/api/me": 1, "/api/items": 1, "/rate-limit": 1}
        cookie = fixture.actor_state("alice")["cookies"][0]
        assert cookie["secure"] is True
        assert cookie["domain"] == "127.0.0.1"
        assert cookie["httpOnly"] is True
        assert cookie["value"] == "alice"


@pytest.mark.parametrize(
    ("certificate_mode", "trust_file", "error_fragment"),
    [
        ("trusted", "wrong_ca_file", "unable to get local issuer"),
        ("self_signed", "ca_file", "self-signed certificate"),
        ("hostname_mismatch", "ca_file", "IP address mismatch"),
    ],
)
def test_tls_fixture_rejects_untrusted_or_wrong_hostname(
    certificate_mode, trust_file, error_fragment
):
    with TLSFixtureServer(certificate_mode=certificate_mode) as fixture:
        context = ssl.create_default_context(cafile=str(getattr(fixture, trust_file)))
        with pytest.raises(URLError) as rejected:
            urlopen(fixture.origin + "/", context=context, timeout=5)
        assert isinstance(rejected.value.reason, ssl.SSLCertVerificationError)
        assert error_fragment in str(rejected.value.reason)
        assert fixture.counts == {}, "rejected TLS must not send an HTTP request"


def test_tls_fixture_certificates_permissions_and_complete_cleanup():
    fixture = TLSFixtureServer()
    directory = fixture.certificate_directory
    paths = [fixture.ca_file, fixture.wrong_ca_file, fixture.cert_file, fixture.key_file]
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths)
    certificate = x509.load_pem_x509_certificate(fixture.cert_file.read_bytes())
    assert certificate.not_valid_before_utc <= datetime.now(UTC) <= certificate.not_valid_after_utc
    assert set(
        certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.IPAddress)
    ) == {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
    fixture.close()  # Also safe before starting the server thread.
    fixture.close()
    assert not directory.exists()
    assert not any(path.exists() for path in paths)


def test_tls_fixture_cleans_up_after_context_exception():
    with (
        pytest.raises(RuntimeError, match="fixture test exception"),
        TLSFixtureServer() as fixture,
    ):
        directory = fixture.certificate_directory
        raise RuntimeError("fixture test exception")
    assert not directory.exists()
    assert not fixture.thread.is_alive()
