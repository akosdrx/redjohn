"""Owned non-loopback HTTPS fixture for Linux namespace integration tests."""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import shutil
import ssl
import subprocess
import threading
from collections import Counter
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from redjohn.assessment.tls_fixture import (
    _authority,
    _certificate_builder,
    _name,
    _write_private,
)


if TYPE_CHECKING:
    from pathlib import Path


def fixture_host() -> str:
    """Select an actual local interface; never send requests to a public target."""
    command = shutil.which("ip")
    if command is None:
        raise RuntimeError("blocked_iproute2_missing")
    result = subprocess.run(  # noqa: S603 - fixed local inventory command
        [command, "-j", "address", "show"],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    addresses = {
        item["local"]
        for interface in json.loads(result.stdout)
        for item in interface.get("addr_info", [])
        if item.get("family") == "inet" and item.get("scope") == "global"
    }
    requested = os.environ.get("REDJOHN_REMOTE_FIXTURE_HOST")
    if requested is not None and requested not in addresses:
        raise RuntimeError("configured_fixture_ip_is_not_a_local_interface")
    for value in sorted(addresses if requested is None else {requested}):
        address = ipaddress.ip_address(value)
        if not (
            address.is_loopback
            or address.is_unspecified
            or address.is_link_local
            or address.is_multicast
        ):
            return str(address)
    raise RuntimeError("blocked_nonloopback_fixture_interface_missing")


class RemoteHTTPSFixture:
    """Temporary CA and real HTTPS server bound to an owned non-loopback IP."""

    def __init__(self, host: str, directory: Path) -> None:
        self.host = host
        self.directory = directory
        directory.mkdir(mode=0o700, parents=True)
        directory.chmod(0o700)
        self.ca_file = directory / "ca.pem"
        self.cert_file = directory / "server.pem"
        self.key_file = directory / "server-key.pem"
        self.credential = secrets.token_urlsafe(32)
        self.counts: Counter[str] = Counter()
        self.observed: list[dict] = []
        self.mode = "marker"
        self._lock = threading.Lock()
        self._started = False
        self._certificates()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.partition("?")[0]
                cookie = SimpleCookie()
                cookie.load(self.headers.get("Cookie", ""))
                session = cookie.get("fixture_session")
                authorized = session is not None and session.value == fixture.credential
                with fixture._lock:
                    fixture.counts[path] += 1
                    fixture.observed.append(
                        {"path": path, "actor": "alice" if authorized else "anonymous"}
                    )
                headers = {}
                if path == "/":
                    status, content_type = 200, "text/html"
                    body = b"""<!doctype html><html><body><div>Owned RedJohn HTTPS fixture</div>
<script>fetch('/private').then(r=>r.text()).then(()=>document.body.dataset.ready='yes');</script>
</body></html>"""
                elif path == "/private":
                    content_type = "text/plain"
                    if not authorized:
                        status, body = 401, b"authentication required"
                    elif fixture.mode == "redirect":
                        status, body = 302, b""
                        headers["Location"] = fixture.origin + "/credential-trap"
                    else:
                        status = 200
                        body = (
                            b"redjohn-fixture-marker"
                            if fixture.mode == "marker"
                            else b"fixed-control"
                        )
                elif path == "/favicon.ico":
                    status, body, content_type = 204, b"", "image/x-icon"
                else:
                    status, body, content_type = 404, b"unexpected endpoint", "text/plain"
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer((host, 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert_file, self.key_file)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _certificates(self) -> None:
        authority_key, authority = _authority("RedJohn owned remote fixture CA")
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            _certificate_builder(_name("RedJohn owned non-loopback fixture"), authority.subject)
            .public_key(key.public_key())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(self.host))]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()),
                critical=False,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(authority_key, hashes.SHA256())
        )
        _write_private(self.ca_file, authority.public_bytes(serialization.Encoding.PEM))
        _write_private(self.cert_file, certificate.public_bytes(serialization.Encoding.PEM))
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
        return f"https://{self.host}:{self.server.server_port}"

    def actor_state(self) -> dict:
        return {
            "actor_id": "alice",
            "tenant_id": "tenant-a",
            "session_revision": "7",
            "storage_state": {
                "cookies": [
                    {
                        "name": "fixture_session",
                        "value": self.credential,
                        "domain": self.host,
                        "path": "/",
                        "expires": -1,
                        "httpOnly": True,
                        "secure": True,
                        "sameSite": "Lax",
                    }
                ],
                "origins": [],
            },
        }

    def __enter__(self):
        self.thread.start()
        self._started = True
        return self

    def __exit__(self, *_args):
        try:
            if self._started:
                self.server.shutdown()
            self.server.server_close()
            if self._started:
                self.thread.join(timeout=3)
        finally:
            for path in (self.key_file, self.cert_file, self.ca_file):
                path.unlink(missing_ok=True)
