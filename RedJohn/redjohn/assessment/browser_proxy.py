"""Bounded HTTP(S) egress guard owned by one browser service.

CONNECT is terminated with a per-process ephemeral certificate. Every decrypted
HTTP/1.1 request is checked and admitted before opening its upstream connection;
upstream TLS always verifies the target chain and hostname. Remote workers
additionally run inside the separately attested Linux namespace boundary;
only this trusted controller proxy may open an approved upstream connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import ssl
from typing import TYPE_CHECKING, Protocol
from urllib.parse import urldefrag, urlsplit, urlunsplit

from redjohn.assessment.browser_tls import BrowserTLSConfig, BrowserTLSIdentity
from redjohn.assessment.policy import origin_for


if TYPE_CHECKING:
    from collections.abc import Callable

    from redjohn.assessment.policy import EngagementPolicy


_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_HEADER_LIMIT = 16 * 1024
_BODY_LIMIT = 64 * 1024
_HOP_HEADERS = {
    "host",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "transfer-encoding",
    "content-length",
}


class _IdleClientClosedError(Exception):
    """A speculative client connection closed before sending a request."""


class ProxyCaptureTicket(Protocol):
    """Trusted host reservation; completion requires a fully framed response."""

    def admit(self) -> None: ...

    def complete(self, status: int, headers: dict[str, str]) -> None: ...

    def fail(self) -> None: ...


class BrowserEgressProxy:
    def __init__(
        self,
        policy: EngagementPolicy,
        *,
        max_connections: int = 16,
        timeout_seconds: float = 10.0,
        max_wire_bytes: int = 8 * 1024 * 1024,
        request_admission: Callable[[str], None] | None = None,
        tls_config: BrowserTLSConfig | None = None,
        on_response: Callable[[str, int, dict[str, str]], None] | None = None,
        on_complete: Callable[[str, str, int, dict[str, str]], None] | None = None,
        response_policy: Callable[[str, int, tuple[tuple[str, str], ...]], None] | None = None,
        request_headers: Callable[[str, str, list[tuple[str, str]]], list[tuple[str, str]]]
        | None = None,
        rewrite_url: Callable[[str, str], str] | None = None,
        connect_policy: Callable[[str], None] | None = None,
        request_replay: Callable[
            [str, str, list[tuple[str, str]], bytes], tuple[list[tuple[str, str]], bytes]
        ]
        | None = None,
        request_transform: Callable[
            [str, str, list[tuple[str, str]], bytes],
            tuple[str, str, list[tuple[str, str]], bytes],
        ]
        | None = None,
        request_policy: Callable[[str, str], None] | None = None,
        request_capture: Callable[[str, str, list[tuple[str, str]], bytes], ProxyCaptureTicket]
        | None = None,
    ) -> None:
        if not 1 <= max_connections <= 128 or not 0 < timeout_seconds <= 60:
            raise ValueError("invalid_browser_proxy_connection_limits")
        if not 1024 <= max_wire_bytes <= 64 * 1024 * 1024:
            raise ValueError("invalid_browser_proxy_wire_limit")
        self.policy = policy
        self.max_connections = max_connections
        self.timeout_seconds = timeout_seconds
        self.max_wire_bytes = max_wire_bytes
        self.request_admission = request_admission
        self.on_response = on_response
        self.on_complete = on_complete
        self.response_policy = response_policy
        self.request_headers = request_headers
        self.rewrite_url = rewrite_url
        self.connect_policy = connect_policy
        self.request_replay = request_replay
        self.request_transform = request_transform
        self.request_policy = request_policy
        self.request_capture = request_capture
        self.tls_config = tls_config or BrowserTLSConfig()
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._capture_tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._tls_identity: BrowserTLSIdentity | None = None
        self._upstream_tls: ssl.SSLContext | None = None
        self.denied_requests = 0
        self.blocked_proxy_type_probes = 0
        self.limit_drops = 0
        self.forwarded_requests = 0
        self.peak_connections = 0
        self.admission_denials = 0
        self.upstream_tls_failures = 0
        self.navigation_urls: set[str] | None = None

    @property
    def url(self) -> str:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("browser proxy is not started")
        port = self._server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}"

    @property
    def chromium_tls_arguments(self) -> list[str]:
        if self._tls_identity is None:
            return []
        return [f"--ignore-certificate-errors-spki-list={self._tls_identity.spki_sha256}"]

    @property
    def client_tls_context(self) -> ssl.SSLContext:
        if self._tls_identity is None:
            raise RuntimeError("proxy_tls_identity_not_started")
        return self._tls_identity.client_context

    @property
    def client_ca_certificate(self) -> bytes | None:
        """Public trust material for a confined non-browser client; never keys."""
        if self._tls_identity is None:
            return None
        return (self._tls_identity.directory / "chain.pem").read_bytes()

    async def start(self) -> None:
        if self._server is not None:
            return
        https_hosts = tuple(
            str(urlsplit(origin).hostname)
            for origin in self.policy.allowed_origins
            if urlsplit(origin).scheme == "https"
        )
        try:
            # Check the actual destinations before generating a key or listening.
            for origin in self.policy.allowed_origins:
                self.policy.check_scope_url(origin)
            if https_hosts:
                self._upstream_tls = self.tls_config.upstream_context()
                self._tls_identity = BrowserTLSIdentity(https_hosts)
            self._server = await asyncio.start_server(
                self._accept,
                "127.0.0.1",
                0,
                limit=_HEADER_LIMIT,
            )
        except BaseException:
            await self.close()
            raise

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self._tasks) >= self.max_connections:
            self.limit_drops += 1
            writer.close()
            return
        self._writers.add(writer)
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        self.peak_connections = max(self.peak_connections, len(self._tasks))
        task.add_done_callback(self._tasks.discard)

    async def _copy(  # noqa: PLR0912, PLR0915 - bounded response framing
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        url: str,
        method: str,
        *,
        max_wire_bytes: int | None = None,
    ) -> tuple[int, dict[str, str]]:
        wire_limit = min(self.max_wire_bytes, max_wire_bytes or self.max_wire_bytes)
        header = await reader.readuntil(b"\r\n\r\n")
        if len(header) > _HEADER_LIMIT or len(header) > wire_limit:
            raise asyncio.LimitOverrunError("browser_proxy_response_header_limit", len(header))
        lines = header.decode("latin-1").split("\r\n")
        protocol, status, _reason = lines[0].split(" ", 2)
        if protocol not in {"HTTP/1.0", "HTTP/1.1"} or not 200 <= int(status) <= 599:
            raise ValueError("unsupported_browser_proxy_response")
        metadata: dict[str, str] = {}
        framing: dict[str, str] = {}
        response_fields: list[tuple[str, str]] = []
        for line in lines[1:-2]:
            name, separator, value = line.partition(":")
            if not separator or not _HEADER_NAME.fullmatch(name):
                raise ValueError("invalid_browser_proxy_response_header")
            normalized, value = name.lower(), value.strip()
            if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
                raise ValueError("invalid_browser_proxy_response_header")
            response_fields.append((normalized, value))
            if normalized in {"content-type", "retry-after"}:
                metadata[normalized] = value[:256]
            if normalized in {"content-length", "transfer-encoding"}:
                if normalized in framing:
                    raise ValueError("ambiguous_browser_proxy_response_framing")
                framing[normalized] = value
        if len(framing) > 1:
            raise ValueError("ambiguous_browser_proxy_response_framing")
        if self.response_policy is not None:
            self.response_policy(url, int(status), tuple(response_fields))
        count = len(header)

        async def emit(data: bytes) -> None:
            nonlocal count
            count += len(data)
            if count > wire_limit:
                raise asyncio.LimitOverrunError("browser_proxy_wire_limit", count)
            writer.write(data)
            await writer.drain()

        async def exact(size: int) -> None:
            if size < 0 or size > wire_limit - count:
                raise asyncio.LimitOverrunError("browser_proxy_wire_limit", size)
            while size:
                part = await reader.readexactly(min(size, 64 * 1024))
                await emit(part)
                size -= len(part)

        writer.write(header)
        await writer.drain()
        if method == "HEAD" or int(status) in {204, 304}:
            pass
        elif "transfer-encoding" in framing:
            if framing["transfer-encoding"].lower() != "chunked":
                raise ValueError("unsupported_browser_proxy_transfer_encoding")
            while True:
                chunk_line = await reader.readuntil(b"\r\n")
                if len(chunk_line) > 1024 or not re.fullmatch(rb"[0-9A-Fa-f]+\r\n", chunk_line):
                    raise ValueError("unsupported_browser_proxy_chunk_framing")
                size = int(chunk_line.strip(), 16)
                await emit(chunk_line)
                if not size:
                    trailer_bytes = 0
                    while True:
                        trailer = await reader.readuntil(b"\r\n")
                        trailer_bytes += len(trailer)
                        if trailer_bytes > _HEADER_LIMIT:
                            raise asyncio.LimitOverrunError(
                                "browser_proxy_trailer_limit", trailer_bytes
                            )
                        if trailer != b"\r\n":
                            name, separator, value = trailer[:-2].decode("latin-1").partition(":")
                            if (
                                not separator
                                or not _HEADER_NAME.fullmatch(name)
                                or name.lower() in {"content-length", "transfer-encoding", "host"}
                                or any(
                                    (ord(char) < 32 and char != "\t") or ord(char) == 127
                                    for char in value
                                )
                            ):
                                raise ValueError("invalid_browser_proxy_response_trailer")
                        await emit(trailer)
                        if trailer == b"\r\n":
                            break
                    break
                await exact(size)
                tail = await reader.readexactly(2)
                if tail != b"\r\n":
                    raise ValueError("invalid_browser_proxy_chunk_framing")
                await emit(tail)
        elif "content-length" in framing:
            if not framing["content-length"].isascii() or not framing["content-length"].isdigit():
                raise ValueError("invalid_browser_proxy_content_length")
            await exact(int(framing["content-length"]))
        else:
            while True:
                chunk = await reader.read(min(64 * 1024, wire_limit - count + 1))
                if not chunk:
                    break
                await emit(chunk)
        # An empty scanner result is useful negative evidence only after a
        # complete, correctly framed bounded upstream response was forwarded.
        if self.on_complete is not None:
            self.on_complete(url, method, int(status), metadata)
        if self.on_response is not None:
            self.on_response(url, int(status), metadata)
        return int(status), metadata

    async def _read_request(
        self, reader: asyncio.StreamReader
    ) -> tuple[str, str, list[tuple[str, str]], dict[str, str], bytes]:
        try:
            header = await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError as exc:
            if not exc.partial:
                raise _IdleClientClosedError from None
            raise
        if len(header) > _HEADER_LIMIT:
            raise ValueError("browser_proxy_header_limit")
        lines = header.decode("latin-1").split("\r\n")
        method, target, protocol = lines[0].split(" ")
        if protocol != "HTTP/1.1" or len(target.encode("latin-1")) > 4096:
            raise ValueError("unsupported_browser_proxy_request")
        headers: list[tuple[str, str]] = []
        lookup: dict[str, str] = {}
        for line in lines[1:-2]:
            name, separator, value = line.partition(":")
            if not separator or not _HEADER_NAME.fullmatch(name):
                raise ValueError("invalid_browser_proxy_header")
            value = value.strip(" \t")
            if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
                raise ValueError("invalid_browser_proxy_header")
            normalized = name.lower()
            # Chromium emits one value per name. Fail closed on ambiguous framing.
            if normalized in lookup:
                raise ValueError("duplicate_browser_proxy_header")
            lookup[normalized] = value
            headers.append((name, value))
        length = lookup.get("content-length", "0")
        if (
            not length.isascii()
            or not length.isdigit()
            or str(int(length)) != length
            or int(length) > _BODY_LIMIT
            or "transfer-encoding" in lookup
            or "expect" in lookup
        ):
            raise ValueError("browser_request_body_framing_denied")
        if (
            method != "POST" or (self.request_replay is None and self.request_capture is None)
        ) and int(length):
            raise ValueError("browser_get_body_unsupported")
        if "upgrade" in lookup:
            raise ValueError("browser_upgrade_unsupported")
        body = await reader.readexactly(int(length))
        return method, target, headers, lookup, body

    @staticmethod
    async def _reject(writer: asyncio.StreamWriter, status: bytes) -> None:
        writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        with contextlib.suppress(OSError):
            await writer.drain()

    async def _handle(  # noqa: PLR0912, PLR0915 - one bounded connection lifecycle
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        remote_writer: asyncio.StreamWriter | None = None
        capture: ProxyCaptureTicket | None = None
        capture_completed = False
        capture_task = asyncio.current_task()
        method, url = "", ""
        try:
            async with asyncio.timeout(self.timeout_seconds):
                method, target, headers, lookup, body = await self._read_request(reader)
                tunnel_origin: str | None = None
                if method == "CONNECT":
                    parsed = urlsplit("https://" + target)
                    if parsed.path or parsed.query or parsed.fragment or self._tls_identity is None:
                        raise ValueError("unsupported_browser_connect")  # noqa: TRY301
                    tunnel_origin = origin_for("https://" + target)
                    if self.connect_policy is not None:
                        # Alias-only workers must not bypass request rewriting
                        # by opening their own HTTPS tunnel, even in scope.
                        self.connect_policy(tunnel_origin)
                    self.policy.check_scope_url(tunnel_origin)
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()
                    await writer.start_tls(
                        self._tls_identity.server_context,
                        ssl_handshake_timeout=min(self.timeout_seconds, 5.0),
                        ssl_shutdown_timeout=1.0,
                    )
                    method, target, headers, lookup, body = await self._read_request(reader)
                if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
                    raise ValueError("unsupported_browser_proxy_method")  # noqa: TRY301
                if tunnel_origin is not None:
                    if not target.startswith("/") or target.startswith("//") or "#" in target:
                        raise ValueError("invalid_browser_tls_request_target")  # noqa: TRY301
                    url = tunnel_origin + target
                    if origin_for("https://" + lookup.get("host", "")) != tunnel_origin:
                        raise ValueError("browser_connect_authority_mismatch")  # noqa: TRY301
                else:
                    url = target
                    if urlsplit(url).scheme != "http":
                        raise ValueError("unsupported_browser_proxy_protocol")  # noqa: TRY301
                    if self.rewrite_url is not None:
                        # Canonical authorization still precedes admission,
                        # credentials, DNS resolution and every upstream socket.
                        url = self.rewrite_url(url, method)
                # Remove client-nominated hop fields before any host transform
                # injects private framing/type or credentials. A worker cannot
                # suppress host Content-Type using Connection: Content-Type.
                nominated = {
                    value.strip().lower() for value in lookup.get("connection", "").split(",")
                }
                headers = [
                    (name, value) for name, value in headers if name.lower() not in nominated
                ]
                if self.request_transform is not None:
                    # A trusted host bridge may materialize private POST bytes
                    # from an already validated public worker carrier. The real
                    # method/URL still pass policy before admission or connect.
                    url, method, headers, body = self.request_transform(url, method, headers, body)
                if method == "POST":
                    if (
                        self.request_replay is None
                        and self.request_capture is None
                        and self.request_transform is None
                    ) or (tunnel_origin is None and self.request_transform is None):
                        raise ValueError("post_replay_binding_required")  # noqa: TRY301
                    (self.request_policy or self.policy.check_replay_request)(url, method)
                else:
                    self.policy.check_readonly_request(url, method)
                if (
                    lookup.get("sec-fetch-dest") == "document"
                    and self.navigation_urls is not None
                    and urldefrag(url)[0] not in self.navigation_urls
                ):
                    raise ValueError("browser_unapproved_navigation")  # noqa: TRY301
                parsed = urlsplit(url)
                path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                if not parsed.query and url.partition("#")[0].endswith("?"):
                    path += "?"  # an explicit empty query is part of the recorded request
                rewritten = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
                if self.request_replay is not None:
                    headers, body = self.request_replay(url, method, headers, body)
                if not isinstance(body, bytes) or len(body) > _BODY_LIMIT:
                    raise ValueError("post_replay_body_limit")  # noqa: TRY301
                if self.request_headers is not None:
                    headers = self.request_headers(url, method, headers)
                if any(
                    not _HEADER_NAME.fullmatch(name)
                    or any(
                        (ord(char) < 32 and char != "\t") or ord(char) == 127 or ord(char) > 255
                        for char in value
                    )
                    for name, value in headers
                ):
                    raise ValueError("invalid_host_replay_header")  # noqa: TRY301
                rewritten.extend(
                    f"{name}: {value}"
                    for name, value in headers
                    if name.lower() not in _HOP_HEADERS and not name.lower().startswith("proxy-")
                )
                if method == "POST":
                    rewritten.append(f"Content-Length: {len(body)}")
                rewritten.append("Connection: close")
                wire_header = ("\r\n".join(rewritten) + "\r\n\r\n").encode("latin-1")
                if len(wire_header) > _HEADER_LIMIT:
                    raise ValueError("host_replay_header_limit")  # noqa: TRY301
                wire_request = wire_header + body
                if self.request_capture is not None and method == "POST":
                    capture = self.request_capture(url, method, headers, body)
                    if capture_task is not None:
                        self._capture_tasks.add(capture_task)
                if capture is not None or self.request_admission is not None:
                    try:
                        if capture is not None:
                            capture.admit()
                        elif self.request_admission is not None:
                            self.request_admission(url)
                    except (ValueError, RuntimeError, PermissionError):
                        self.admission_denials += 1
                        raise ValueError("browser_request_admission_denied") from None
                # Resolve once, validate every answer, then connect numerically.
                # Preserve the original TLS server name; no second DNS lookup.
                address = await asyncio.to_thread(self.policy.connection_ip, url)
                if parsed.scheme == "https":
                    if self._upstream_tls is None:
                        raise ValueError("verified_upstream_tls_context_required")  # noqa: TRY301
                    remote_reader, remote_writer = await asyncio.open_connection(
                        address,
                        parsed.port or 443,
                        limit=_HEADER_LIMIT,
                        ssl=self._upstream_tls,
                        server_hostname=parsed.hostname,
                        ssl_handshake_timeout=min(self.timeout_seconds, 5.0),
                        ssl_shutdown_timeout=1.0,
                    )
                else:
                    remote_reader, remote_writer = await asyncio.open_connection(
                        address, parsed.port or 80, limit=_HEADER_LIMIT
                    )
                self._writers.add(remote_writer)
                remote_writer.write(wire_request)
                self.forwarded_requests += 1
                await remote_writer.drain()
                status, response_headers = await self._copy(
                    remote_reader,
                    writer,
                    url,
                    method,
                    max_wire_bytes=80 * 1024 if capture is not None else None,
                )
                if capture is not None:
                    capture.complete(status, response_headers)
                    capture_completed = True
        except _IdleClientClosedError:
            pass
        except ssl.SSLCertVerificationError:
            self.upstream_tls_failures += 1
            await self._reject(writer, b"502 Bad Gateway")
        except (ValueError, RuntimeError, PermissionError) as exc:
            self.denied_requests += 1
            # Katana's reviewed proxy utility probes this fixed pseudo-host to
            # detect Burp. It remains rejected; no DNS/socket/admission occurs.
            # Consumers may distinguish this optional startup diagnostic from
            # missing target responses without relaxing the scope boundary.
            if method == "GET" and url == "http://burpsuite/" and str(exc) == "origin_denied":
                self.blocked_proxy_type_probes += 1
            await self._reject(writer, b"403 Forbidden")
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
            self.limit_drops += 1
        finally:
            if capture is not None and not capture_completed:
                with contextlib.suppress(Exception):
                    capture.fail()
            if capture_task is not None:
                self._capture_tasks.discard(capture_task)
            for item in (remote_writer, writer):
                if item is not None:
                    self._writers.discard(item)
                    item.close()
                    with contextlib.suppress(OSError, TimeoutError):
                        await asyncio.wait_for(item.wait_closed(), 1.0)

    async def drain_captures(self, timeout_seconds: float = 5.0) -> None:
        """Finish old-identity POSTs before another context can bind the proxy."""
        if not 0 < timeout_seconds <= 30:
            raise ValueError("invalid_browser_capture_drain_timeout")
        tasks = tuple(self._capture_tasks)
        if not tasks:
            return
        _, pending = await asyncio.wait(tasks, timeout=timeout_seconds)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
        for writer in tuple(self._writers):
            writer.close()
        for task in tuple(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
        self._tasks.clear()
        self._writers.clear()
        if server is not None:
            await server.wait_closed()
        if self._tls_identity is not None:
            self._tls_identity.close()
            self._tls_identity = None
        self._upstream_tls = None
