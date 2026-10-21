"""Ephemeral, loopback-only TLS version of the harmless SPA/API fixture.

``ca_file`` is an explicit per-client trust anchor; this fixture never changes
the machine/browser trust store. Negative modes retain strict client validation.
"""

from __future__ import annotations

import ipaddress
import os
import ssl
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from redjohn.assessment.fixture import FixtureServer


if TYPE_CHECKING:
    from http.server import BaseHTTPRequestHandler

    from redjohn.assessment.fixture import FixtureStorageState


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate_builder(subject: x509.Name, issuer: x509.Name) -> x509.CertificateBuilder:
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
    )


def _authority(common_name: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name(common_name)
    certificate = (
        _certificate_builder(name, name)
        .public_key(key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _write_private(path: Path, data: bytes) -> None:
    """Create every TLS file with restrictive permissions from its first write."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


class TLSFixtureServer(FixtureServer):
    """Reuse the existing fixture handlers over a locally generated TLS chain.

    ``trusted`` has IP SANs for 127.0.0.1 and ::1. ``hostname_mismatch`` is signed
    by ``ca_file`` but deliberately has the wrong IP SAN. ``self_signed`` has a
    valid matching IP SAN but is not signed by ``ca_file``. ``wrong_ca_file``
    always holds an unrelated, otherwise valid CA for explicit negative checks.

    The listener binds only to a dynamic port on literal IPv4 loopback, as the
    original fixture does. All certificates/private keys are deleted on close.
    """

    def __init__(
        self,
        *,
        certificate_mode: Literal["trusted", "self_signed", "hostname_mismatch"] = "trusted",
    ) -> None:
        if certificate_mode not in {"trusted", "self_signed", "hostname_mismatch"}:
            raise ValueError("unknown TLS fixture certificate mode")
        self.certificate_mode = certificate_mode
        self.observed_actors: list[dict[str, str]] = []
        self._observation_lock = threading.Lock()
        self._started = False
        self._closed = False
        self._certificate_directory = tempfile.TemporaryDirectory(prefix="redjohn-tls-fixture-")
        self.certificate_directory = Path(self._certificate_directory.name)
        self.certificate_directory.chmod(0o700)
        self.ca_file = self.certificate_directory / "ca.pem"
        self.wrong_ca_file = self.certificate_directory / "unrelated-ca.pem"
        self.cert_file = self.certificate_directory / "server.pem"
        self.key_file = self.certificate_directory / "server-key.pem"
        try:
            self._write_certificates()
            super().__init__()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(self.cert_file), str(self.key_file))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            self._observe_requests()
        except BaseException:
            if hasattr(self, "server"):
                self.server.server_close()
            self._certificate_directory.cleanup()
            raise

    def _observe_requests(self) -> None:
        """Record bounded server-side fixture actor metadata for real E2E proof."""

        def observe(handler: BaseHTTPRequestHandler) -> None:
            cookie = SimpleCookie()
            cookie.load(handler.headers.get("Cookie", ""))
            actor = cookie.get("fixture_actor")
            with self._observation_lock:
                if len(self.observed_actors) < 128:
                    self.observed_actors.append(
                        {
                            "path": urlsplit(handler.path).path[:4096],
                            "actor": actor.value[:128] if actor is not None else "anonymous",
                            "method": "GET",
                        }
                    )

        self._get_observer = observe

    def _write_certificates(self) -> None:
        authority_key, authority = _authority("RedJohn ephemeral fixture CA")
        _, unrelated = _authority("RedJohn unrelated fixture CA")
        key = ec.generate_private_key(ec.SECP256R1())
        subject = _name("RedJohn loopback fixture")
        issuer = subject if self.certificate_mode == "self_signed" else authority.subject
        addresses = (
            ["192.0.2.1"] if self.certificate_mode == "hostname_mismatch" else ["127.0.0.1", "::1"]
        )
        certificate = (
            _certificate_builder(subject, issuer)
            .public_key(key.public_key())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    key.public_key()
                    if self.certificate_mode == "self_signed"
                    else authority_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address(address)) for address in addresses]
                ),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key if self.certificate_mode == "self_signed" else authority_key, hashes.SHA256())
        )
        for path, cert in (
            (self.ca_file, authority),
            (self.wrong_ca_file, unrelated),
            (self.cert_file, certificate),
        ):
            _write_private(path, cert.public_bytes(serialization.Encoding.PEM))
        _write_private(
            self.key_file,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    @property
    def origin(self) -> str:
        return f"https://127.0.0.1:{self.server.server_port}"

    def actor_state(self, actor: str) -> FixtureStorageState:
        state = super().actor_state(actor)
        state["cookies"][0]["secure"] = True
        return state

    def __enter__(self) -> Self:
        if self._closed:
            raise RuntimeError("TLS fixture has already been closed")
        if not self._started:
            super().__enter__()
            self._started = True
        return self

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._started:
                self.server.shutdown()
            self.server.server_close()
            if self._started:
                self.thread.join(timeout=3)
        finally:
            self._certificate_directory.cleanup()
            self._closed = True

    def __exit__(self, *_args: object) -> None:
        self.close()
