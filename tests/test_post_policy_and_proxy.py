"""Policy/store contracts and actual TLS proxy framing, without a mock engine."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.capture import CaptureDenied, capture_authenticated_request
from redjohn.assessment.models import JobSpec, Surface, stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer


if TYPE_CHECKING:
    from pathlib import Path


def remote_policy(profile="active-staging") -> EngagementPolicy:
    return EngagementPolicy(
        "post-contract",
        "owner",
        ("https://192.0.2.10:443",),
        allowed_ips=("192.0.2.10/32",),
        profile=profile,
        egress_mode="enforced",
        actor_ids=("anonymous", "alice"),
        allowed_replay_urls=("https://192.0.2.10/query?a=1&a=2",),
        allowed_refresh_urls=("https://192.0.2.10/session/refresh",),
    )


def test_explicit_post_and_refresh_permissions_never_expand_each_other():
    policy = remote_policy()
    policy.check_replay_request("https://192.0.2.10:443/query?a=1&a=2", "POST")
    policy.check_refresh_request("https://192.0.2.10:443/session/refresh", "POST")
    with pytest.raises(PolicyDenied, match="post_replay_not_authorized"):
        policy.check_replay_request(policy.allowed_refresh_urls[0], "POST")
    with pytest.raises(PolicyDenied, match="session_refresh_not_authorized"):
        policy.check_refresh_request(policy.allowed_replay_urls[0], "POST")


@pytest.mark.parametrize(
    "url",
    [
        "https://192.0.2.10/query?a=2&a=1",
        "https://192.0.2.10/query?a=1&a=2&",
        "https://192.0.2.10/qu%65ry?a=1&a=2",
        "https://192.0.2.10/query?a=1&a=2#fragment",
        "https://192.0.2.10:444/query?a=1&a=2",
    ],
)
def test_post_authorization_retains_exact_encoded_path_query_order_and_port(url):
    with pytest.raises(PolicyDenied):
        remote_policy().check_replay_request(url, "POST")


def test_safe_production_denies_post_even_with_explicit_endpoint_allowlist():
    with pytest.raises(PolicyDenied, match="post_requires_active_profile"):
        remote_policy("safe-production")
    policy = replace(
        remote_policy(), profile="safe-production", allowed_replay_urls=(), allowed_refresh_urls=()
    )
    with pytest.raises(PolicyDenied, match="post_replay_not_authorized"):
        policy.check_replay_request("https://192.0.2.10/query?a=1&a=2", "POST")
    with pytest.raises(PolicyDenied, match="session_refresh_not_authorized"):
        policy.check_refresh_request("https://192.0.2.10/session/refresh", "POST")


def test_surface_body_digest_changes_post_identity_but_preserves_legacy_get_identity():
    get = Surface("https://example.test/path?a=1&a=2", actor_id="alice", request_ref="capture-1")
    # Literal pre-extension payload: asdict(current Surface) would include
    # newly introduced fields and silently redefine the historical oracle.
    legacy = {
        "url": "https://example.test/path?a=1&a=2",
        "method": "GET",
        "content_type": "",
        "input_location": "",
        "input_name": "",
        "actor_id": "alice",
        "tenant_id": "",
        "session_revision": "1",
        "workflow_state": "initial",
    }
    assert stable_key(legacy) == "6f30e083826efb51bfe303c03d644ed5a7edb03c39ad3bfacd5d540b8667d2d7"
    assert get.key == "6f30e083826efb51bfe303c03d644ed5a7edb03c39ad3bfacd5d540b8667d2d7"
    post = replace(get, method="POST", content_type="application/json", body_sha256="a" * 64)
    assert post.key != replace(post, body_sha256="b" * 64).key
    assert post.key == replace(post, request_ref="fresh-capture", source="imported").key


def test_durable_post_jobs_require_nonidempotent_execution(tmp_path: Path):
    store = AssessmentStore(tmp_path / "agents.db")
    try:
        policy = store.register(remote_policy())
        surface = Surface(
            policy.allowed_replay_urls[0],
            method="POST",
            actor_id="alice",
            content_type="application/json",
            body_sha256="a" * 64,
            request_ref="observed-post",
        )
        surface_id = store.upsert_surface(policy.engagement_id, surface)
        spec = JobSpec(surface_id, "web", "nuclei", policy_revision=policy.revision)
        with pytest.raises(PolicyDenied, match="post_replay_requires_nonidempotent_job"):
            store.submit(policy, [spec])
        assert store.db.execute("SELECT count(*) FROM rj_job").fetchone()[0] == 0
        identifiers = store.submit(policy, [replace(spec, idempotent=False)])
        assert len(identifiers) == 1
        assert store.db.execute("SELECT count(*) FROM rj_job").fetchone()[0] == 1
        assert store.submit(policy, [replace(spec, idempotent=False)]) == identifiers
    finally:
        store.close()


def fixture_policy(origin: str) -> EngagementPolicy:
    return EngagementPolicy(
        "proxy-post-framing",
        "owner",
        (origin,),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("anonymous", "alice"),
        allowed_replay_urls=(origin + "/post",),
    )


async def tls_proxy_client(proxy: BrowserEgressProxy, origin: str):
    reader, writer = await asyncio.open_connection("127.0.0.1", urlsplit(proxy.url).port)
    authority = urlsplit(origin).netloc
    writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    await writer.drain()
    assert await reader.readuntil(b"\r\n\r\n") == b"HTTP/1.1 200 Connection Established\r\n\r\n"
    await writer.start_tls(proxy.client_tls_context, server_hostname="127.0.0.1")
    return reader, writer


def request_bytes(origin: str, method: str, framing: list[str], body: bytes) -> bytes:
    return (
        f"{method} /post HTTP/1.1\r\nHost: {urlsplit(origin).netloc}\r\n"
        "Content-Type: application/json\r\n" + "\r\n".join(framing) + "\r\n\r\n"
    ).encode() + body


def post_observer(seen: list):
    class Observer(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append((self.path, body))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self):
            seen.append((self.path, b"unexpected-get"))
            self.send_error(500)

        def log_message(self, *_args):
            pass

    return Observer


@pytest.mark.parametrize(
    "method,framing,body,replay_mode",
    [
        ("POST", ["Content-Length: 65537"], b"", "identity"),
        ("POST", ["Content-Length: 0", "content-length: 0"], b"", "identity"),
        ("POST", ["Content-Length: 0", "Transfer-Encoding: chunked"], b"", "identity"),
        ("POST", ["Transfer-Encoding: chunked"], b"0\r\n\r\n", "identity"),
        ("POST", ["Content-Length: 01"], b"x", "identity"),
        ("GET", ["Content-Length: 1"], b"x", "identity"),
        ("POST", ["Content-Length: 0"], b"", "none"),
        ("POST", ["Content-Length: 1"], b"x", "oversize"),
    ],
)
async def test_actual_tls_proxy_rejects_unsafe_framing_before_target_io(
    method, framing, body, replay_mode
):
    seen = []
    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = post_observer(seen)

        def replay(_url, _method, headers, data):
            return headers, b"x" * 65537 if replay_mode == "oversize" else data

        proxy = BrowserEgressProxy(
            fixture_policy(fixture.origin),
            tls_config=BrowserTLSConfig(fixture.ca_file),
            request_replay=replay if replay_mode != "none" else None,
            timeout_seconds=2,
        )
        await proxy.start()
        try:
            reader, writer = await tls_proxy_client(proxy, fixture.origin)
            try:
                writer.write(request_bytes(fixture.origin, method, framing, body))
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), 2)
                assert response.startswith(b"HTTP/1.1 403 Forbidden"), response
                assert proxy.denied_requests == 1
                assert proxy.forwarded_requests == 0
                assert seen == []
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
        finally:
            await proxy.close()


async def test_actual_tls_proxy_accepts_exact_64k_post_body():
    seen = []
    body = b'{"x":"' + b"x" * (65536 - 8) + b'"}'
    assert len(body) == 65536
    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = post_observer(seen)
        proxy = BrowserEgressProxy(
            fixture_policy(fixture.origin),
            tls_config=BrowserTLSConfig(fixture.ca_file),
            request_replay=lambda _url, _method, headers, data: (headers, data),
        )
        await proxy.start()
        try:
            reader, writer = await tls_proxy_client(proxy, fixture.origin)
            try:
                writer.write(request_bytes(fixture.origin, "POST", ["Content-Length: 65536"], body))
                await writer.drain()
                response = await asyncio.wait_for(reader.read(), 2)
                assert b"200 OK\r\n" in response and response.endswith(b"ok")
                assert seen == [("/post", body)]
                assert proxy.forwarded_requests == 1
                assert proxy.denied_requests == 0
            finally:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
        finally:
            await proxy.close()


async def test_proxy_close_cancels_incomplete_post_body_without_target_io():
    seen = []
    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = post_observer(seen)
        proxy = BrowserEgressProxy(
            fixture_policy(fixture.origin),
            tls_config=BrowserTLSConfig(fixture.ca_file),
            request_replay=lambda _url, _method, headers, data: (headers, data),
        )
        await proxy.start()
        _reader, writer = await tls_proxy_client(proxy, fixture.origin)
        try:
            writer.write(request_bytes(fixture.origin, "POST", ["Content-Length: 65536"], b"short"))
            await writer.drain()
            await asyncio.wait_for(proxy.close(), 2)
            assert proxy.forwarded_requests == 0
            assert seen == []
            assert not proxy._tasks
            assert not proxy._writers
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            await proxy.close()


CAPTURE_BODY = b'{"private":"private-sdk-capture-body"}'
CAPTURE_HEADERS = {
    "Authorization": "Bearer private-sdk-capture-auth",
    "X-CSRF-Token": "private-sdk-capture-csrf",
}


def capture_context(tmp_path: Path, origin: str):
    store = AssessmentStore(tmp_path / "capture.db")
    policy = store.register(fixture_policy(origin))
    surface = Surface(
        origin + "/post",
        method="POST",
        content_type="application/json",
        actor_id="alice",
        tenant_id="tenant-a",
        session_revision="7",
    )
    return store, policy, surface


def capture_observer(seen: list, *, mode="success", accepted=None, release=None):
    class CaptureObserver(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            authenticated = all(
                self.headers.get(name) == value for name, value in CAPTURE_HEADERS.items()
            )
            seen.append((self.path, authenticated, body))
            if accepted is not None:
                accepted.set()
            if mode == "lost_response":
                self.close_connection = True
                return
            if release is not None:
                release.wait(2)
            response = json.dumps(
                {
                    "reflected_body": body.decode(),
                    "reflected_auth": self.headers.get("Authorization"),
                    "reflected_csrf": self.headers.get("X-CSRF-Token"),
                }
            ).encode()
            self.send_response(200 if authenticated else 401)
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            with contextlib.suppress(OSError):
                self.wfile.write(response)

        def log_message(self, *_args):
            pass

    return CaptureObserver


def assert_private_capture_values_absent(store: AssessmentStore):
    # iterdump renders BLOBs as hexadecimal literals. Inspect decoded evidence
    # bytes too, otherwise a credential in a JSON BLOB could evade this check.
    chunks = ["\n".join(store.db.iterdump()).encode()]
    chunks += [bytes(row[0]) for row in store.db.execute("SELECT payload FROM rj_evidence")]
    raw = b"\n".join(chunks)
    assert CAPTURE_BODY not in raw
    assert b"private-sdk-capture-body" not in raw
    assert all(value.encode() not in raw for value in CAPTURE_HEADERS.values())
    assert b"private-sdk-capture-auth" not in raw
    assert b"private-sdk-capture-csrf" not in raw
    return raw


async def test_actual_sdk_capture_verified_post_secret_isolation_and_restart_dedup(tmp_path: Path):
    seen = []
    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = capture_observer(seen)
        store, policy, surface = capture_context(tmp_path, fixture.origin)
        try:
            observed = await capture_authenticated_request(
                policy,
                store,
                surface,
                body=CAPTURE_BODY,
                headers=CAPTURE_HEADERS,
                tls_config=BrowserTLSConfig(fixture.ca_file),
            )
            assert seen == [("/post", True, CAPTURE_BODY)]
            assert observed.source == "observed" and observed.request_ref
            assert observed.body_sha256 == hashlib.sha256(CAPTURE_BODY).hexdigest()
            evidence = json.loads(
                store.evidence_get(policy.engagement_id, observed.request_ref)["excerpt"]
            )
            assert evidence["sent"] is True
            assert evidence["response_complete"] is True
            assert evidence["status"] == 200
            assert evidence["body_sha256"] == observed.body_sha256
            assert evidence["actor_id"] == "alice"
            assert_private_capture_values_absent(store)
            store.close()
            store = AssessmentStore(tmp_path / "capture.db")
            replayed = await capture_authenticated_request(
                policy,
                store,
                surface,
                body=CAPTURE_BODY,
                headers=CAPTURE_HEADERS,
                tls_config=BrowserTLSConfig(fixture.ca_file),
            )
            assert replayed == observed
            assert len(seen) == 1
            assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 1
            assert (
                store.db.execute("SELECT state FROM rj_request_capture").fetchone()[0]
                == "succeeded"
            )
            assert_private_capture_values_absent(store)
        finally:
            store.close()


async def test_actual_sdk_capture_lost_response_is_durable_uncertain_without_resend(tmp_path: Path):
    seen = []
    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = capture_observer(seen, mode="lost_response")
        store, policy, surface = capture_context(tmp_path, fixture.origin)
        try:
            with pytest.raises(CaptureDenied, match="capture_transport_inconclusive"):
                await capture_authenticated_request(
                    policy,
                    store,
                    surface,
                    body=CAPTURE_BODY,
                    headers=CAPTURE_HEADERS,
                    tls_config=BrowserTLSConfig(fixture.ca_file),
                )
            assert seen == [("/post", True, CAPTURE_BODY)]
            row = store.db.execute(
                "SELECT state,admitted,error_code FROM rj_request_capture"
            ).fetchone()
            assert row["state"] == "uncertain" and row["admitted"] == 1
            assert row["error_code"].startswith("capture_")
            assert store.surfaces(policy.engagement_id) == []
            assert store.findings(policy.engagement_id) == []
            assert_private_capture_values_absent(store)
            store.close()
            store = AssessmentStore(tmp_path / "capture.db")
            with pytest.raises(PolicyDenied, match="capture_uncertain"):
                await capture_authenticated_request(
                    policy,
                    store,
                    surface,
                    body=CAPTURE_BODY,
                    headers=CAPTURE_HEADERS,
                    tls_config=BrowserTLSConfig(fixture.ca_file),
                )
            assert len(seen) == 1
            assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 1
        finally:
            store.close()


async def test_actual_sdk_capture_rejected_session_is_unverified_not_negative(tmp_path: Path):
    seen = []
    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = capture_observer(seen)
        store, policy, surface = capture_context(tmp_path, fixture.origin)
        try:
            with pytest.raises(CaptureDenied, match="capture_response_unverified"):
                await capture_authenticated_request(
                    policy,
                    store,
                    surface,
                    body=CAPTURE_BODY,
                    headers={**CAPTURE_HEADERS, "Authorization": "Bearer expired-fixture-token"},
                    tls_config=BrowserTLSConfig(fixture.ca_file),
                )
            assert seen == [("/post", False, CAPTURE_BODY)]
            evidence = json.loads(store.db.execute("SELECT payload FROM rj_evidence").fetchone()[0])
            assert evidence["status"] == 401 and evidence["sent"] is True
            assert (
                store.db.execute("SELECT state FROM rj_request_capture").fetchone()[0]
                == "uncertain"
            )
            assert store.surfaces(policy.engagement_id) == []
            assert store.findings(policy.engagement_id) == []
            assert b"expired-fixture-token" not in assert_private_capture_values_absent(store)
            with pytest.raises(PolicyDenied, match="capture_uncertain"):
                await capture_authenticated_request(
                    policy,
                    store,
                    surface,
                    body=CAPTURE_BODY,
                    headers=CAPTURE_HEADERS,
                    tls_config=BrowserTLSConfig(fixture.ca_file),
                )
            assert len(seen) == 1
        finally:
            store.close()


@pytest.mark.parametrize(
    "body,headers,code",
    [
        (b"x" * 65537, CAPTURE_HEADERS, "capture_body_limit"),
        (
            CAPTURE_BODY,
            {"Authorization": "value\r\nInjected: yes"},
            "capture_private_auth_headers_invalid",
        ),
        (CAPTURE_BODY, {"Authorization": "x" * 8193}, "capture_private_auth_headers_invalid"),
        (CAPTURE_BODY, {"Host": "other.example"}, "capture_private_auth_headers_invalid"),
    ],
    ids=["oversize_body", "header_crlf", "oversize_header", "unapproved_header"],
)
async def test_sdk_capture_invalid_private_input_zero_target_io_and_no_reservation(
    tmp_path: Path, body, headers, code
):
    seen = []
    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = capture_observer(seen)
        store, policy, surface = capture_context(tmp_path, fixture.origin)
        try:
            with pytest.raises(CaptureDenied, match=code):
                await capture_authenticated_request(
                    policy,
                    store,
                    surface,
                    body=body,
                    headers=headers,
                    tls_config=BrowserTLSConfig(fixture.ca_file),
                )
            assert seen == []
            assert store.db.execute("SELECT count(*) FROM rj_request_capture").fetchone()[0] == 0
            assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 0
        finally:
            store.close()


async def test_actual_sdk_capture_cancelled_after_delivery_is_uncertain_and_not_retried(
    tmp_path: Path,
):
    seen = []
    accepted, release = threading.Event(), threading.Event()
    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = capture_observer(
            seen, accepted=accepted, release=release
        )
        store, policy, surface = capture_context(tmp_path, fixture.origin)
        task = asyncio.create_task(
            capture_authenticated_request(
                policy,
                store,
                surface,
                body=CAPTURE_BODY,
                headers=CAPTURE_HEADERS,
                tls_config=BrowserTLSConfig(fixture.ca_file),
            )
        )
        try:
            assert await asyncio.to_thread(accepted.wait, 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
            assert seen == [("/post", True, CAPTURE_BODY)]
            assert (
                store.db.execute("SELECT state FROM rj_request_capture").fetchone()[0]
                == "uncertain"
            )
            assert store.surfaces(policy.engagement_id) == []
            assert_private_capture_values_absent(store)
            store.close()
            store = AssessmentStore(tmp_path / "capture.db")
            with pytest.raises(PolicyDenied, match="capture_uncertain"):
                await capture_authenticated_request(
                    policy,
                    store,
                    surface,
                    body=CAPTURE_BODY,
                    headers=CAPTURE_HEADERS,
                    tls_config=BrowserTLSConfig(fixture.ca_file),
                )
            assert len(seen) == 1
        finally:
            release.set()
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            store.close()
