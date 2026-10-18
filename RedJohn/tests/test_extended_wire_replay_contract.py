"""Actual wire parsers/token rotation contracts, without scanner transport doubles."""

from __future__ import annotations

import json
from base64 import b64decode, b64encode
from urllib.parse import quote_from_bytes

import pytest

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.body_tokens import (
    BodyTokenDenied,
    matches_refreshed_capture,
    rotate_body_tokens,
)
from redjohn.assessment.browser_capture import BrowserCaptureDenied
from redjohn.assessment.request_body import (
    HOST_REPLAY_BODY_MARKER,
    ApprovedRequestBody,
    RequestBodyDenied,
)
from tests.test_body_token_refresh import binding, multipart, request, response
from tests.test_browser_post_capture import configured_capture
from tests.test_mime_replay_contract import fields
from tests.test_replay_body_contract import URL, post_fixture


@pytest.mark.parametrize(
    "codec",
    ["utf-8", "iso-8859-1", "windows-1250", "windows-1252", "utf-16", "utf-16-le", "utf-16-be"],
)
def test_v3_vendor_json_rotation_preserves_codec_bom_duplicate_keys_and_other_bytes(codec):
    original = '{ "label":"café", "csrf":"old-token", "csrf":"old-token", "number":1e2 }'.encode(
        codec
    )
    content_type = 'Application/vnd.redjohn+json; Charset="' + codec + '"'
    private = request(content_type, original, [binding("json", "/csrf", occurrence=1)])
    private["body_contract_version"] = 3
    updated = rotate_body_tokens(private, response())
    actual = b64decode(updated["body_base64"])
    assert (
        actual
        == '{ "label":"café", "csrf":"old-token", "csrf":"new-token", "number":1e2 }'.encode(codec)
    )
    assert updated["content_type"] == content_type and updated["body_contract_version"] == 3
    assert updated["replay_safety"] == "fresh-capture-required"
    assert "café" in ApprovedRequestBody.from_mapping(updated).redaction_values


@pytest.mark.parametrize("codec", ["utf-8", "iso-8859-1", "windows-1250", "utf-16", "utf-16-be"])
@pytest.mark.parametrize("selector", ["/r/csrf", "/r/@csrf"])
def test_v3_xml_attribute_or_text_rotation_keeps_declaration_and_unselected_bytes(codec, selector):
    original = (
        f'<?xml version="1.0" encoding="{codec}"?><r csrf="old-token">'
        "<label>café</label><csrf>old-token</csrf></r>"
    )
    content_type = "application/soap+xml; charset=" + codec
    private = request(content_type, original.encode(codec), [binding("xml", selector)])
    private["body_contract_version"] = 3
    result = response()
    result["headers"]["X-CSRF-Token"] = 'new<&"token'
    updated = rotate_body_tokens(private, result)
    replacement = "new&lt;&amp;&quot;token" if selector.endswith("@csrf") else 'new&lt;&amp;"token'
    expected = (
        original.replace('csrf="old-token"', 'csrf="' + replacement + '"')
        if selector.endswith("@csrf")
        else original.replace("<csrf>old-token</csrf>", "<csrf>" + replacement + "</csrf>")
    )
    assert b64decode(updated["body_base64"]) == expected.encode(codec)
    assert "café" in ApprovedRequestBody.from_mapping(updated).redaction_values


def test_v3_form_uses_approved_charset_and_repeated_field_occurrence():
    content_type = "application/x-www-form-urlencoded; charset=iso-8859-1"
    private = request(
        content_type,
        b"label=caf%E9&csrf=old-token&csrf=old-token",
        [binding("form", "csrf", occurrence=1)],
    )
    private["body_contract_version"] = 3
    result = response()
    result["headers"]["X-CSRF-Token"] = "café"
    updated = rotate_body_tokens(private, result)
    assert b64decode(updated["body_base64"]) == b"label=caf%E9&csrf=old-token&csrf=caf%E9"


def test_v3_multipart_part_charsets_do_not_bleed_into_next_part_and_binary_is_unchanged():
    body = (
        b'--b\r\nContent-Disposition: form-data; name="one"\r\n'
        b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\ncaf\xe9"
        b'\r\n--b\r\nContent-Disposition: form-data; name="csrf"\r\n\r\nold-token'
        b'\r\n--b\r\nContent-Disposition: form-data; name="label"\r\n\r\ncaf\xc3\xa9'
        b'\r\n--b\r\nContent-Disposition: form-data; name="upload"; filename="fixture.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n\x00\xff\r\n--b--\r\n"
    )
    private = request("multipart/form-data; boundary=b", body, [binding("multipart", "csrf")])
    private["body_contract_version"] = 3
    assert ApprovedRequestBody.from_mapping(private).redaction_values.count("café") == 1
    assert b64decode(rotate_body_tokens(private, response())["body_base64"]) == body.replace(
        b"old-token", b"new-token"
    )


@pytest.mark.parametrize("codec", ["utf-8", "iso-8859-1", "utf-16"])
def test_v3_explicit_text_file_binding_preserves_file_headers_bom_and_other_parts(codec):
    payload = "old-token".encode(codec)
    body = multipart(upload=payload).replace(
        b"Content-Type: application/octet-stream",
        ("Content-Type: text/plain; charset=" + codec).encode(),
    )
    private = request(
        "multipart/form-data; boundary=oldBoundary", body, [binding("multipart_file", "file")]
    )
    private["body_contract_version"] = 3
    actual = b64decode(rotate_body_tokens(private, response())["body_base64"])
    file_header = ("Content-Type: text/plain; charset=" + codec + "\r\n\r\n").encode()
    assert actual == body.replace(file_header + payload, file_header + "new-token".encode(codec))


@pytest.mark.parametrize("version", [1, 2, 3])
def test_binary_upload_cannot_become_a_token_binding(version):
    private = request(
        "multipart/form-data; boundary=oldBoundary",
        multipart(),
        [binding("multipart_file", "file")],
    )
    private["body_contract_version"] = version
    with pytest.raises(BodyTokenDenied):
        rotate_body_tokens(private, response())


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize(
    "media,body",
    [
        ("application/xml", b"<r/>"),
        ("application/vnd.redjohn+json", b"{}"),
        ("application/json; charset=iso-8859-1", b'{"x":"caf\xe9"}'),
    ],
)
def test_legacy_approval_never_acquires_v3_media_or_codec_authority(version, media, body):
    with pytest.raises(RequestBodyDenied):
        ApprovedRequestBody.from_mapping(fields(media, body, version))


@pytest.mark.parametrize(
    "content_type,body",
    [
        ("application/xml; charset=iso-8859-1", b"<r><csrf>old-token</csrf></r>"),
        (
            "application/vnd.redjohn+json; charset=utf-16",
            json.dumps({"csrf": "old-token"}).encode("utf-16"),
        ),
    ],
)
def test_v3_private_vault_restores_exact_body_and_charset_and_capture_cannot_downgrade(
    content_type, body
):
    policy, surface, data = post_fixture(content_type, body)
    data["entries"][0]["allowed_requests"][0]["body_contract_version"] = 3
    approved = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    approved.validate_template_request(URL, "POST", HOST_REPLAY_BODY_MARKER, content_type, policy)
    headers, actual = approved.rewrite_request(
        URL, "POST", [("Content-Type", content_type)], HOST_REPLAY_BODY_MARKER.encode()
    )
    assert actual == body and ("Content-Type", content_type) in headers
    assert matches_refreshed_capture(
        content_type,
        body,
        content_type,
        body,
        expected_body_contract_version=3,
        actual_body_contract_version=3,
    )
    assert not matches_refreshed_capture(
        content_type,
        body,
        content_type,
        body,
        expected_body_contract_version=3,
        actual_body_contract_version=2,
    )


def test_unrepresentable_xml_or_file_token_fails_without_reencoding_body():
    private = request(
        "application/xml; charset=iso-8859-1",
        b"<r><csrf>old-token</csrf></r>",
        [binding("xml", "/r/csrf")],
    )
    private["body_contract_version"] = 3
    result = response()
    result["headers"]["X-CSRF-Token"] = "\u2603"
    with pytest.raises(BodyTokenDenied, match="not_representable"):
        rotate_body_tokens(private, result)
    assert b64decode(private["body_base64"]) == b"<r><csrf>old-token</csrf></r>"


@pytest.mark.parametrize("explicit", [False, True])
def test_browser_rule_requires_explicit_v3_before_xml_can_be_reserved(tmp_path, explicit):
    _policy, store, capture, _vault, rules_file = configured_capture(
        tmp_path, "https://127.0.0.1:8443"
    )
    rules = json.loads(rules_file.read_text())
    rule = rules["rules"][0]
    rule["content_type"] = "application/xml"
    rule["body_tokens"] = [binding("xml", "/request/csrf")]
    if explicit:
        rule["body_contract_version"] = 3
    rules_file.write_text(json.dumps(rules))
    try:
        if not explicit:
            with pytest.raises(BrowserCaptureDenied, match="invalid_rule"):
                capture.bind_context("alice", "tenant-a", "7")
            assert store.db.execute("SELECT count(*) FROM rj_request_capture").fetchone()[0] == 0
        else:
            capture.bind_context("alice", "tenant-a", "7")
            headers = capture.headers_for_request(
                rule["url"], "POST", [("Content-Type", "application/xml; charset=iso-8859-1")]
            )
            ticket = capture.before_request(
                rule["url"],
                "POST",
                headers,
                b"<request><csrf>old-token</csrf><value>caf\xe9</value></request>",
            )
            assert ticket.entry["allowed_requests"][0]["body_contract_version"] == 3
            ticket.fail()
            assert capture.observations() == ()
    finally:
        capture.end_context()
        store.close()


@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be", "iso-8859-1"])
def test_v3_private_text_wire_encoding_reflections_are_redacted_without_changing_counts(codec):
    private_text = "private-café-body-token"
    body = json.dumps({"secret": private_text}, ensure_ascii=False).encode(codec)
    policy, surface, data = post_fixture("application/vnd.redjohn+json; charset=" + codec, body)
    data["entries"][0]["allowed_requests"][0]["body_contract_version"] = 3
    replay = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    encoded = private_text.encode(codec)
    reflections = [
        encoded.decode("utf-8", errors="replace"),
        encoded.decode("iso-8859-1"),
        b64encode(encoded).decode(),
        quote_from_bytes(encoded, safe=""),
    ]
    result = replay.redact_worker_output(
        {"stdout": json.dumps({"response": reflections, "requests": 1, "matcher-status": True})}
    )
    parsed = json.loads(result["stdout"])
    assert parsed["response"] == ["[redacted]"] * 4
    assert parsed["requests"] == 1 and parsed["matcher-status"] is True
