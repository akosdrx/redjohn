"""Real TLS/socket guard tests independent of Playwright request routing."""

from __future__ import annotations

import asyncio
import ssl
from contextlib import asynccontextmanager, suppress
from urllib.parse import urlsplit

import pytest

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig, BrowserTLSIdentity
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.tls_fixture import TLSFixtureServer


def _policy(origin: str) -> EngagementPolicy:
    return EngagementPolicy(
        engagement_id="proxy-tls-fixture",
        owner_id="operator",
        allowed_origins=(origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )


@asynccontextmanager
async def _tls_client(proxy: BrowserEgressProxy, origin: str):
    address = urlsplit(proxy.url)
    reader, writer = await asyncio.open_connection(address.hostname, address.port)
    try:
        authority = urlsplit(origin).netloc
        writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        await writer.drain()
        assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200 ")
        assert proxy._tls_identity is not None
        context = ssl.create_default_context(cafile=proxy._tls_identity.directory / "chain.pem")
        await writer.start_tls(context, server_hostname=urlsplit(origin).hostname)
        yield reader, writer
    finally:
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_proxy_decrypted_authority_body_method_and_budget_checked_before_upstream():
    with TLSFixtureServer() as fixture:
        admitted, responses = [], []

        def admit(url):
            if admitted:
                raise RuntimeError("budget_exhausted")
            admitted.append(url)

        proxy = BrowserEgressProxy(
            _policy(fixture.origin),
            tls_config=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            request_admission=admit,
            on_response=lambda *args: responses.append(args),
        )
        await proxy.start()
        host = urlsplit(fixture.origin).netloc
        try:
            malformed = (
                f"GET /logout?all=true HTTP/1.1\r\nHost: {host}\r\n\r\n",
                f"GET /api/delete HTTP/1.1\r\nHost: {host}\r\n\r\n",
                "GET /api/me HTTP/1.1\r\nHost: localhost\r\n\r\n",
                f"GET /api/me HTTP/1.1\r\nHost: {host}\r\nContent-Length: 9\r\n\r\nbody",
                f"GET /api/me HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\n\r\n",
                f"POST /api/me HTTP/1.1\r\nHost: {host}\r\n\r\n",
                f"GET https://localhost/api/me HTTP/1.1\r\nHost: {host}\r\n\r\n",
            )
            for request in malformed:
                async with _tls_client(proxy, fixture.origin) as (reader, writer):
                    writer.write(request.encode())
                    await writer.drain()
                    assert (await reader.read()).startswith(b"HTTP/1.1 403 ")
            assert not admitted and not responses and not fixture.counts
            for _ in range(2):
                async with _tls_client(proxy, fixture.origin) as (reader, writer):
                    writer.write(f"GET /api/me HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                    await writer.drain()
                    await reader.read()
            assert admitted == [fixture.origin + "/api/me"]
            assert fixture.counts["/api/me"] == proxy.forwarded_requests == len(responses) == 1
            assert responses[0][0:2] == (fixture.origin + "/api/me", 200)
            assert responses[0][2] == {"content-type": "application/json"}
            assert proxy.admission_denials == 1
        finally:
            identity_directory = proxy._tls_identity.directory
            await proxy.close()
        assert not identity_directory.exists()
        assert not proxy._tasks and not proxy._writers


@pytest.mark.asyncio
async def test_real_chromium_certificate_exception_accepts_only_this_proxy_key():
    from playwright.async_api import Error, async_playwright  # noqa: PLC0415

    with TLSFixtureServer() as fixture:
        proxy = BrowserEgressProxy(
            _policy(fixture.origin),
            tls_config=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
        )
        await proxy.start()
        other_identity = BrowserTLSIdentity(("127.0.0.1",))
        try:
            async with async_playwright() as driver:
                browser = await driver.chromium.launch(
                    headless=True,
                    chromium_sandbox=True,
                    proxy={"server": proxy.url, "bypass": "<-loopback>"},
                    args=[
                        "--disable-quic",
                        "--disable-background-networking",
                        f"--ignore-certificate-errors-spki-list={other_identity.spki_sha256}",
                    ],
                )
                try:
                    page = await browser.new_page(ignore_https_errors=False)
                    with pytest.raises(Error, match="ERR_CERT_AUTHORITY_INVALID"):
                        await page.goto(fixture.origin + "/", timeout=3000)
                    assert not fixture.counts
                    assert proxy.forwarded_requests == 0
                finally:
                    await browser.close()
        finally:
            other_identity.close()
            await proxy.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["truncated_length", "truncated_chunk", "oversized"])
async def test_proxy_complete_response_observer_excludes_partial_or_oversized_response(kind):
    response = {
        "truncated_length": b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial",
        "truncated_chunk": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nshort\r\n",
        "oversized": b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n" + b"x" * 2048,
    }[kind]
    tasks = []

    async def upstream(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    def accepted(reader, writer):
        tasks.append(asyncio.create_task(upstream(reader, writer)))

    server = await asyncio.start_server(accepted, "127.0.0.1", 0)
    origin = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    observed = []
    proxy = BrowserEgressProxy(
        _policy(origin), max_wire_bytes=1024, on_response=lambda *args: observed.append(args)
    )
    try:
        await proxy.start()
        address = urlsplit(proxy.url)
        reader, writer = await asyncio.open_connection(address.hostname, address.port)
        writer.write(f"GET {origin}/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
        await writer.drain()
        await reader.read()
        writer.close()
        await writer.wait_closed()
        assert not observed
        assert proxy.limit_drops == 1
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()
        await asyncio.gather(*tasks)


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["plaintext", "tls"])
async def test_proxy_empty_speculative_client_connection_is_not_lost_response_coverage(transport):
    with TLSFixtureServer() as fixture:
        observed = []
        proxy = BrowserEgressProxy(
            _policy(fixture.origin),
            tls_config=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
            on_response=lambda *args: observed.append(args),
        )
        await proxy.start()
        try:
            if transport == "tls":
                async with _tls_client(proxy, fixture.origin):
                    pass
            else:
                address = urlsplit(proxy.url)
                _reader, writer = await asyncio.open_connection(address.hostname, address.port)
                writer.close()
                await writer.wait_closed()
            for _ in range(100):
                if not proxy._tasks:
                    break
                await asyncio.sleep(0.01)
            assert not proxy._tasks
            assert proxy.limit_drops == proxy.denied_requests == proxy.forwarded_requests == 0
            assert not observed and not fixture.counts
        finally:
            await proxy.close()
