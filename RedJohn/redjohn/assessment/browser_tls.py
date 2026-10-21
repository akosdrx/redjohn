"""Per-browser ephemeral TLS identity and strictly verified upstream transport.

The certificate exception Chromium receives is a single ephemeral leaf SPKI,
owned by this proxy process. It does not disable upstream certificate checking,
modify the system trust store, or trust another browser's interception key.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory


@dataclass(frozen=True)
class BrowserTLSConfig:
    """Optional additional CA for an explicitly authorized local HTTPS lab."""

    upstream_ca_file: str | Path | None = None

    def upstream_context(self) -> ssl.SSLContext:
        # CERT_REQUIRED and hostname verification remain enabled in both modes.
        context = ssl.create_default_context(cafile=self.upstream_ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        return context


class BrowserTLSIdentity:
    """One private temporary CA/leaf pair, bounded by one browser lifecycle."""

    def __init__(self, hosts: tuple[str, ...]) -> None:
        # Cryptography remains an optional-adapter import, off the core path.
        from cryptography import x509  # noqa: PLC0415
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: PLC0415

        hosts = tuple(dict.fromkeys(hosts))
        if not hosts or len(hosts) > 128:
            raise ValueError("browser_tls_requires_bounded_hosts")
        names: list[x509.GeneralName] = []
        for host in hosts:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(host)))
            except ValueError:
                name = host.encode("idna").decode("ascii").lower()
                if len(name) > 253 or any(
                    not label or len(label) > 63 or not all(c.isalnum() or c == "-" for c in label)
                    for label in name.split(".")
                ):
                    raise ValueError("browser_tls_invalid_hostname") from None
                names.append(x509.DNSName(name))
        self._directory = TemporaryDirectory(prefix="redjohn-browser-tls-")
        self.directory = Path(self._directory.name)
        self.directory.chmod(0o700)
        try:
            now = datetime.now(UTC)
            ca_key = ec.generate_private_key(ec.SECP256R1())
            leaf_key = ec.generate_private_key(ec.SECP256R1())
            ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RedJohn ephemeral CA")])
            ca = (
                x509.CertificateBuilder()
                .subject_name(ca_name)
                .issuer_name(ca_name)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=2))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=False,
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
                .sign(ca_key, hashes.SHA256())
            )
            leaf = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RedJohn browser guard")])
                )
                .issuer_name(ca_name)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=2))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.SubjectAlternativeName(names),
                    critical=False,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
                )
                .sign(ca_key, hashes.SHA256())
            )
            certificate = self.directory / "chain.pem"
            key_file = self.directory / "leaf-key.pem"
            # Directory 0700 protects creation as well as the subsequent chmod.
            certificate.write_bytes(
                leaf.public_bytes(serialization.Encoding.PEM)
                + ca.public_bytes(serialization.Encoding.PEM)
            )
            key_file.write_bytes(
                leaf_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            certificate.chmod(0o600)
            key_file.chmod(0o600)
            self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.server_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.server_context.set_alpn_protocols(["http/1.1"])
            self.server_context.load_cert_chain(certificate, key_file)
            self.client_context = ssl.create_default_context(cafile=certificate)
            self.client_context.minimum_version = ssl.TLSVersion.TLSv1_2
            spki = leaf_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self.spki_sha256 = base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self._directory.cleanup()
