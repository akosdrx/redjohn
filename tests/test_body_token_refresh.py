"""Lossless token-binding units and real HTTPS session/body-rotation integration."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler

import pytest

from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault
from redjohn.assessment.body_tokens import (
    BodyTokenDenied,
    matches_refreshed_capture,
    rotate_body_tokens,
    validate_body_token_bindings,
    validate_response_body_tokens,
    validate_rotation_token_budget,
)
from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.capture import capture_authenticated_request
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.request_body import (
    HOST_REPLAY_BODY_MARKER,
    HOST_REPLAY_MULTIPART_CONTENT_TYPE,
    ApprovedRequestBody,
)
from redjohn.assessment.session_refresh import SessionRefreshService
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.tools.hunt.nuclei import NucleiAdapter, NucleiOptions
from tests.test_assessment_session_refresh import (
    claim_refresh,
    private_file,
    provider_data,
    refresh_policy,
    refresh_surface,
    vault_data,
)
from tests.test_nuclei_post_live import post_fixture_lock


def binding(location, selector, source_kind="header", source_name="X-CSRF-Token", occurrence=0):
    return {
        "location": location,
        "selector": selector,
        "occurrence": occurrence,
        "source": {"kind": source_kind, "name": source_name},
    }


def multipart(boundary="oldBoundary", token=b"old-token", upload=b"\x00old-token\n\xff"):
    return (
        b"--"
        + boundary.encode()
        + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n'
        + token
        + b"\r\n--"
        + boundary.encode()
        + b'\r\nContent-Disposition: form-data; name="file"; filename="fixture.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + upload
        + b"\r\n--"
        + boundary.encode()
        + b'\r\nContent-Disposition: form-data; name="unchanged"\r\n\r\nold-token'
        b"\r\n--" + boundary.encode() + b"--\r\n"
    )


def request(content_type, data, declarations):
    return {
        "url": "https://127.0.0.1:8443/private",
        "method": "POST",
        "request_ref": "old-observed-ref",
        "content_type": content_type,
        "body_base64": base64.b64encode(data).decode(),
        "body_sha256": hashlib.sha256(data).hexdigest(),
        "replay_safety": "operator-approved",
        "body_tokens": declarations,
    }


def response():
    return {
        "headers": {"Authorization": "Bearer new-session-token", "X-CSRF-Token": "new-token"},
        "cookies": [{"name": "csrf_cookie", "value": "new-cookie-token"}],
        "expires_at": time.time() + 300,
        "body_tokens": {"csrf_body": "new-response-token"},
    }


@pytest.mark.parametrize("location", ["json", "form", "multipart"])
def test_only_reviewed_token_field_changes_and_old_approval_is_revoked(location):
    if location == "json":
        content_type = "application/json"
        body = (
            b'{ "unchanged":"old-token", "csrf" : "old-token", '
            b'"csrf":"keep-duplicate", "utf8":"\xc3\xa1" }\n'
        )
        declarations = [binding(location, "/csrf")]
        expected = body.replace(b'"csrf" : "old-token"', b'"csrf" : "new-token"')
    elif location == "form":
        content_type = "application/x-www-form-urlencoded"
        body = b"csrf=old%2Dtoken&unchanged=old%2Dtoken&csrf=keep+duplicate&percent=%2f&empty="
        declarations = [binding(location, "csrf")]
        expected = b"csrf=new-token&unchanged=old%2Dtoken&csrf=keep+duplicate&percent=%2f&empty="
    else:
        content_type = "multipart/form-data; boundary=oldBoundary"
        body = multipart()
        declarations = [binding(location, "csrf")]
        expected = multipart(token=b"new-token")
    original = request(content_type, body, declarations)
    updated = rotate_body_tokens(original, response())
    assert base64.b64decode(updated["body_base64"]) == expected
    assert updated["body_sha256"] == hashlib.sha256(expected).hexdigest()
    assert updated["replay_safety"] == "fresh-capture-required"
    assert updated["request_ref"] == "pending-capture:" + updated["body_sha256"]
    assert original["replay_safety"] == "operator-approved"
    assert base64.b64decode(original["body_base64"]) == body


def test_json_pointer_duplicate_occurrence_array_and_escaped_key_preserve_wire():
    body = b'{"csrf":"unchanged", "csrf":"second", "nested": [ {"a/b~c":"third"} ], "n":1e3}'
    declarations = [
        binding("json", "/csrf", occurrence=1),
        binding("json", "/nested/0/a~1b~0c", "response", "csrf_body"),
    ]
    updated = rotate_body_tokens(request("application/json", body, declarations), response())
    expected = (
        b'{"csrf":"unchanged", "csrf":"new-token", '
        b'"nested": [ {"a/b~c":"new-response-token"} ], "n":1e3}'
    )
    assert base64.b64decode(updated["body_base64"]) == expected


def test_form_repeated_token_cookie_source_changes_only_selected_occurrence():
    body = b"csrf=first&csrf=old+token&x=%2f%2F+space"
    updated = rotate_body_tokens(
        request(
            "application/x-www-form-urlencoded",
            body,
            [binding("form", "csrf", "cookie", "csrf_cookie", occurrence=1)],
        ),
        response(),
    )
    assert (
        base64.b64decode(updated["body_base64"])
        == b"csrf=first&csrf=new-cookie-token&x=%2f%2F+space"
    )


@pytest.mark.parametrize(
    "declarations",
    [
        [binding("json", "/missing")],
        [binding("json", "/csrf", occurrence=2)],
        [binding("json", "/bad~2pointer")],
        [binding("form", "csrf")],
        [binding("json", "/csrf"), binding("json", "/csrf")],
        [{**binding("json", "/csrf"), "occurrence": True}],
    ],
)
def test_invalid_or_overlapping_bindings_are_blocked_before_rotation(declarations):
    body = ApprovedRequestBody.from_mapping(request("application/json", b'{"csrf":"old"}', []))
    with pytest.raises(BodyTokenDenied):
        validate_body_token_bindings(body, declarations)


@pytest.mark.parametrize(
    "content_type,data,selector",
    [
        ("application/json", b'{"csrf":123}', "/csrf"),
        ("application/x-www-form-urlencoded", b"csrf", "csrf"),
        ("multipart/form-data; boundary=oldBoundary", multipart(), "file"),
    ],
)
def test_token_binding_cannot_change_non_string_json_or_upload_bytes(content_type, data, selector):
    location = (
        "json"
        if content_type == "application/json"
        else ("form" if content_type == "application/x-www-form-urlencoded" else "multipart")
    )
    body = ApprovedRequestBody.from_mapping(request(content_type, data, []))
    with pytest.raises(BodyTokenDenied, match="string_field_required"):
        validate_body_token_bindings(body, [binding(location, selector)])


@pytest.mark.parametrize(
    "value", ["", "x" * 4097, "unsafe\r\nnewpart", "unsafe\x00value", "\ud800"]
)
def test_refreshed_values_are_bounded_and_cannot_inject_framing(value):
    with pytest.raises(BodyTokenDenied):
        validate_response_body_tokens({"csrf": value})


def test_refreshed_token_collection_total_and_binding_limits():
    with pytest.raises(BodyTokenDenied):
        validate_response_body_tokens({"token" + str(i): "x" for i in range(17)})
    with pytest.raises(BodyTokenDenied):
        validate_response_body_tokens({"token" + str(i): "x" * 4096 for i in range(5)})
    body = ApprovedRequestBody.from_mapping(request("application/json", b'{"csrf":"old"}', []))
    with pytest.raises(BodyTokenDenied):
        validate_body_token_bindings(body, [binding("json", "/csrf")] * 17)


def test_cross_request_unique_source_budget_and_empty_field_overlap_are_bounded():
    refreshed = response()
    refreshed["headers"]["X-CSRF-Token"] = "h" * 4096
    refreshed["body_tokens"] = dict.fromkeys(("a", "b", "c", "d"), "x" * 4096)
    first = request(
        "application/json",
        b'{"a":"x","b":"x","c":"x"}',
        [binding("json", "/" + name, "response", name) for name in ("a", "b", "c")],
    )
    second = request(
        "application/json",
        b'{"d":"x","e":"x"}',
        [binding("json", "/d", "response", "d"), binding("json", "/e")],
    )
    with pytest.raises(BodyTokenDenied, match="rotation_token_budget"):
        validate_rotation_token_budget([first, second], refreshed)
    empty = ApprovedRequestBody.from_mapping(
        request("application/x-www-form-urlencoded", b"csrf=", [])
    )
    with pytest.raises(BodyTokenDenied, match="overlapping_bindings"):
        validate_body_token_bindings(empty, [binding("form", "csrf")] * 2)


def test_refreshed_multipart_value_cannot_create_a_new_boundary():
    refreshed = response()
    refreshed["headers"]["X-CSRF-Token"] = "--oldBoundary"
    with pytest.raises(BodyTokenDenied, match="multipart_delimiter_in_value"):
        rotate_body_tokens(
            request(
                "multipart/form-data; boundary=oldBoundary",
                multipart(),
                [binding("multipart", "csrf")],
            ),
            refreshed,
        )


def test_fresh_multipart_capture_may_change_only_boundary_framing():
    expected = multipart()
    actual = multipart(boundary="freshChromiumBoundary")
    assert matches_refreshed_capture(
        "multipart/form-data; boundary=oldBoundary",
        expected,
        "multipart/form-data; boundary=freshChromiumBoundary",
        actual,
    )
    assert not matches_refreshed_capture(
        "multipart/form-data; boundary=oldBoundary",
        expected,
        "multipart/form-data; boundary=freshChromiumBoundary",
        multipart(boundary="freshChromiumBoundary", token=b"different"),
    )
    assert not matches_refreshed_capture(
        "multipart/form-data; boundary=oldBoundary",
        expected,
        "multipart/form-data; boundary=freshChromiumBoundary",
        multipart(boundary="freshChromiumBoundary", upload=b"changed-file"),
    )
    assert not matches_refreshed_capture(
        "application/json", b'{"csrf":"new"}', "application/json", b'{ "csrf":"new"}'
    )
    assert not matches_refreshed_capture(
        "application/x-www-form-urlencoded",
        b"csrf=new%20token",
        "application/x-www-form-urlencoded",
        b"csrf=new+token",
    )


@pytest.mark.parametrize("kind", ["json", "form", "multipart"])
async def test_actual_https_refresh_updates_bound_body_and_requires_real_fresh_capture(
    tmp_path, kind
):
    seen = []
    rotation_response = response()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(self.path)
            raw = json.dumps(rotation_response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        store = AssessmentStore(tmp_path / "agents.db")
        base = refresh_surface(fixture.origin)
        policy = replace(refresh_policy(fixture.origin), allowed_replay_urls=(base.url,))
        if kind == "json":
            content_type, body, selector, source_kind, source_name = (
                "application/json",
                b'{ "csrf":"old-token", "keep":"old-token" }',
                "/csrf",
                "header",
                "X-CSRF-Token",
            )
        elif kind == "form":
            content_type, body, selector, source_kind, source_name = (
                "application/x-www-form-urlencoded",
                b"csrf=old-token&keep=old-token",
                "csrf",
                "cookie",
                "csrf_cookie",
            )
        else:
            content_type, body, selector, source_kind, source_name = (
                "multipart/form-data; boundary=oldBoundary",
                multipart(),
                "csrf",
                "response",
                "csrf_body",
            )
        surface = replace(
            base,
            method="POST",
            content_type=content_type,
            body_sha256=hashlib.sha256(body).hexdigest(),
        )
        policy, spec, job = claim_refresh(store, policy, surface)
        data = vault_data(policy, surface)
        data["version"] = 2
        candidate = request(content_type, body, [binding(kind, selector, source_kind, source_name)])
        candidate.update(url=surface.url, request_ref=surface.request_ref)
        data["entries"][0]["allowed_requests"] = [candidate]
        vault = private_file(tmp_path / "vault.json", data)
        providers = private_file(
            tmp_path / "providers.json", provider_data(policy, surface, "provider-secret")
        )
        result = await SessionRefreshService(
            policy, store, vault, providers, tls_config=BrowserTLSConfig(fixture.ca_file)
        ).run(job, surface, spec)
        assert result.execution_status == "succeeded", result
        assert result.summary["body_credentials_rotated"] is True
        assert result.summary["body_token_requests"] == 1
        assert seen == ["/refresh"]
        rotated = json.loads(vault.read_text())
        pending = rotated["entries"][0]["allowed_requests"][0]
        assert pending["body_sha256"] != surface.body_sha256
        assert pending["replay_safety"] == "fresh-capture-required"
        forged = replace(
            surface,
            session_revision="8",
            request_ref=pending["request_ref"],
            body_sha256=pending["body_sha256"],
        )
        with pytest.raises(AuthReplayDenied, match="fresh_capture_required"):
            AuthReplayVault.from_file(vault, policy).authorize(forged)
        dump = "\n".join(store.db.iterdump())
        for private in (
            "old-token",
            "new-token",
            "new-cookie-token",
            "new-response-token",
            "provider-secret",
        ):
            assert private not in dump
            assert private not in repr(result)
        assert store.session_state(policy, surface)["revision"] == "8"
        store.close()


async def test_actual_https_missing_refreshed_token_is_uncertain_and_preserves_vault(tmp_path):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(self.path)
            raw = json.dumps(
                {
                    "headers": {"Authorization": "Bearer new-session"},
                    "cookies": [],
                    "expires_at": time.time() + 300,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        store = AssessmentStore(tmp_path / "agents.db")
        surface = refresh_surface(fixture.origin)
        policy = replace(refresh_policy(fixture.origin), allowed_replay_urls=(surface.url,))
        surface = replace(
            surface,
            method="POST",
            content_type="application/json",
            body_sha256=hashlib.sha256(b'{"csrf":"old"}').hexdigest(),
        )
        policy, spec, job = claim_refresh(store, policy, surface)
        data = vault_data(policy, surface)
        data["version"] = 2
        candidate = request("application/json", b'{"csrf":"old"}', [binding("json", "/csrf")])
        candidate.update(url=surface.url, request_ref=surface.request_ref)
        data["entries"][0]["allowed_requests"] = [candidate]
        vault = private_file(tmp_path / "vault.json", data)
        providers = private_file(
            tmp_path / "providers.json", provider_data(policy, surface, "provider-secret")
        )
        service = SessionRefreshService(
            policy, store, vault, providers, tls_config=BrowserTLSConfig(fixture.ca_file)
        )
        result = await service.run(job, surface, spec)
        assert result.coverage_status == "inconclusive"
        assert (
            result.error["code"] == "auth_replay_body_token_refreshed_source_missing_or_ambiguous"
        )
        assert store.session_state(policy, surface)["status"] == "uncertain"
        assert json.loads(vault.read_text()) == data
        assert seen == ["/refresh"]
        duplicate = await service.run(job, surface, spec)
        assert duplicate.coverage_status == "blocked"
        assert seen == ["/refresh"]
        store.close()


@pytest.mark.parametrize("kind", ["json", "multipart"])
def test_public_multipart_header_sentinel_is_exact_and_multipart_only(kind):

    policy = replace(refresh_policy(), allowed_replay_urls=(refresh_surface().url,))
    ct = "application/json" if kind == "json" else "multipart/form-data; boundary=oldBoundary"
    body = b'{"csrf":"old-token"}' if kind == "json" else multipart()
    surface = replace(
        refresh_surface(),
        method="POST",
        content_type=ct,
        body_sha256=hashlib.sha256(body).hexdigest(),
    )
    data = vault_data(policy, surface)
    data["version"] = 2
    item = request(ct, body, [binding(kind, "/csrf" if kind == "json" else "csrf")])
    item["request_ref"] = surface.request_ref
    data["entries"][0]["allowed_requests"] = [item]
    replay = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    if kind == "json":
        with pytest.raises(AuthReplayDenied, match="worker_body_mismatch"):
            replay.validate_template_request(
                surface.url,
                "POST",
                HOST_REPLAY_BODY_MARKER,
                HOST_REPLAY_MULTIPART_CONTENT_TYPE,
                policy,
            )
    else:
        replay.validate_template_request(
            surface.url, "POST", HOST_REPLAY_BODY_MARKER, HOST_REPLAY_MULTIPART_CONTENT_TYPE, policy
        )
        headers, output = replay.rewrite_request(
            surface.url,
            "POST",
            [("Content-Type", HOST_REPLAY_MULTIPART_CONTENT_TYPE)],
            HOST_REPLAY_BODY_MARKER.encode(),
        )
        assert output == body
        assert dict(headers)["Content-Type"] == ct
        for unrelated in (
            "multipart/form-data; boundary=unreviewed",
            "application/json",
            "multipart/form-data",
        ):
            with pytest.raises(AuthReplayDenied, match="worker_body_mismatch"):
                replay.validate_template_request(
                    surface.url, "POST", HOST_REPLAY_BODY_MARKER, unrelated, policy
                )
        with pytest.raises(AuthReplayDenied, match="worker_body_mismatch"):
            replay.rewrite_request(
                surface.url,
                "POST",
                [("Content-Type", HOST_REPLAY_MULTIPART_CONTENT_TYPE)],
                b"unreviewed body",
            )


async def test_actual_nuclei_public_multipart_template_survives_refreshed_boundary(tmp_path):

    seen = []
    state = {"body": b"", "content_type": "", "marker": True}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            valid = (
                body == state["body"] and self.headers.get("Content-Type") == state["content_type"]
            )
            seen.append(valid)
            output = b"redjohn-fixture-marker" if state["marker"] else b"fixed-control"
            self.send_response(200 if valid else 400)
            self.send_header("Content-Length", str(len(output)))
            self.end_headers()
            self.wfile.write(output)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = Handler
        store = AssessmentStore(tmp_path / "agents.db")
        surface = refresh_surface(fixture.origin)
        policy = store.register(
            replace(refresh_policy(fixture.origin), allowed_replay_urls=(surface.url,))
        )
        tls = BrowserTLSConfig(fixture.ca_file)
        lock = post_fixture_lock(
            tmp_path / "same-reviewed-template", HOST_REPLAY_MULTIPART_CONTENT_TYPE, path="/private"
        )
        bundle_digest = lock.bundle_sha256
        headers = {"Authorization": "Bearer actual-test-session"}
        try:
            async with NativeFixtureSession(policy, tmp_path / "worker", lock) as session:
                for revision, boundary, token in (
                    ("7", "oldBoundary", b"old-token"),
                    ("8", "freshBrowserBoundary", b"new-token"),
                ):
                    body = multipart(boundary=boundary, token=token)
                    ct = "multipart/form-data; boundary=" + boundary
                    state.update(body=body, content_type=ct, marker=True)
                    candidate = replace(
                        surface, session_revision=revision, method="POST", content_type=ct
                    )
                    observed = await capture_authenticated_request(
                        policy, store, candidate, body=body, headers=headers, tls_config=tls
                    )
                    data = vault_data(policy, observed)
                    data["version"] = 2
                    data["entries"][0]["headers"] = headers
                    item = request(ct, body, [binding("multipart", "csrf")])
                    item.update(url=observed.url, request_ref=observed.request_ref)
                    data["entries"][0]["allowed_requests"] = [item]
                    replay = AuthReplayVault.from_mapping(data, policy).authorize(observed)
                    for marker in (True,) if revision == "7" else (True, False):
                        state["marker"] = marker
                        responses = []
                        proxy = BrowserEgressProxy(
                            policy,
                            tls_config=tls,
                            request_replay=replay.rewrite_request,
                            on_response=lambda url, status, response_headers, responses=responses: (
                                responses.append(
                                    {"url": url, "status": status, "headers": response_headers}
                                )
                            ),
                        )
                        await proxy.start()
                        session.bind_proxy(proxy.url)
                        try:
                            adapter = NucleiAdapter(
                                session,
                                lock,
                                proxy_url=proxy.url,
                                response_observations=lambda responses=responses: tuple(responses),
                                auth_replay=replay,
                            )
                            result = await adapter.run(
                                surface.url, NucleiOptions(timeout_seconds=30), policy=policy
                            )
                        finally:
                            session.bind_proxy(None)
                            await proxy.close()
                        assert result["coverage_status"] == "completed", result
                        assert len(result["findings"]) == int(marker)
                        assert result["no_finding_observed"] is not marker
                        assert lock.bundle_sha256 == bundle_digest
            assert seen == [True] * 5
        finally:
            store.close()
