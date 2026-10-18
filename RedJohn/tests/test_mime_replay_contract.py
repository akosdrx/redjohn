"""Versioned MIME syntax, exact wire preservation and legacy rejection controls."""

from __future__ import annotations

import hashlib
from base64 import b64decode, b64encode

import pytest

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.body_tokens import matches_refreshed_capture, rotate_body_tokens
from redjohn.assessment.request_body import (
    HOST_REPLAY_BODY_MARKER,
    HOST_REPLAY_MULTIPART_CONTENT_TYPE,
    ApprovedRequestBody,
    RequestBodyDenied,
)
from tests.test_body_token_refresh import binding, multipart, request, response
from tests.test_replay_body_contract import MULTIPART, URL, post_fixture


def fields(content_type: str, body: bytes, version: object = 2) -> dict:
    return {
        "content_type": content_type,
        "body_base64": b64encode(body).decode(),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_contract_version": version,
    }


@pytest.mark.parametrize(
    "content_type,body",
    [
        ("Application/JSON", '{"value":"árvíz"}'.encode()),
        ("application/json;charset=UTF-8", b'{"value":"one"}'),
        ('application/json; CHARSET="utf-8"', b'{"value":"one"}'),
        ('Application/JSON ; charset = "UTF-8"', b'{"value":"one"}'),
        ("APPLICATION/X-WWW-FORM-URLENCODED;charset=UTF-8", b"value=%C3%A1rv%C3%ADz"),
        ('application/x-www-form-urlencoded; Charset="UTF-8"', b"value=a%20b&tag=1&tag=2"),
        ('multipart/form-data; boundary="redjohn_boundary"', MULTIPART),
        ('Multipart/Form-Data; BOUNDARY="redjohn_boundary"', MULTIPART),
    ],
)
def test_v2_mime_body_retains_exact_header_and_bytes(content_type: str, body: bytes):
    approved = ApprovedRequestBody.from_mapping(fields(content_type, body))
    assert approved.content_type == content_type
    assert approved.data == body
    assert approved.body_contract_version == 2


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json; charset=utf-8; CHARSET=utf-8",
        "application/json; charset=iso-8859-1",
        'application/json; charset="utf-8',
        "application/json\r\nEvil: yes",
        "application/json; unknown=one",
        "application/json,application/json",
        'multipart/form-data; boundary="one"; boundary=two',
    ],
)
def test_v2_mime_ambiguity_or_unsupported_encoding_is_not_accepted(content_type: str):
    with pytest.raises(RequestBodyDenied):
        ApprovedRequestBody.from_mapping(fields(content_type, b"{}"))


@pytest.mark.parametrize("version", [True, "2", 0, 3])
def test_unknown_body_contract_version_fails_closed(version: object):
    with pytest.raises(RequestBodyDenied, match="contract_version"):
        ApprovedRequestBody.from_mapping(fields("application/json", b"{}", version))


def test_legacy_body_contract_still_rejects_extended_mime_syntax():
    data = fields("application/json; charset=UTF-8", b"{}")
    data.pop("body_contract_version")
    with pytest.raises(RequestBodyDenied):
        ApprovedRequestBody.from_mapping(data)


@pytest.mark.parametrize(
    "content_type,body,template_type",
    [
        ('Application/JSON; Charset="UTF-8"', b'{"value":"one"}', "application/json"),
        (
            "application/x-www-form-urlencoded;charset=UTF-8",
            b"value=one",
            "application/x-www-form-urlencoded",
        ),
        (
            'Multipart/Form-Data; BOUNDARY="redjohn_boundary"',
            MULTIPART,
            HOST_REPLAY_MULTIPART_CONTENT_TYPE,
        ),
    ],
)
def test_extended_private_binding_restores_original_wire_after_public_template(
    content_type, body, template_type
):
    policy, surface, vault = post_fixture(content_type, body)
    vault["entries"][0]["allowed_requests"][0]["body_contract_version"] = 2
    approved = AuthReplayVault.from_mapping(vault, policy).authorize(surface)
    approved.validate_template_request(URL, "POST", HOST_REPLAY_BODY_MARKER, template_type, policy)
    headers, data = approved.rewrite_request(
        URL, "POST", [("Content-Type", template_type)], HOST_REPLAY_BODY_MARKER.encode()
    )
    assert data == body
    assert [v for k, v in headers if k.lower() == "content-type"] == [content_type]


@pytest.mark.parametrize(
    "content_type,body,location,selector",
    [
        (
            'Application/JSON; charset="UTF-8"',
            b'{"csrf":"old-token","unchanged":"old-token"}',
            "json",
            "/csrf",
        ),
        (
            "application/x-www-form-urlencoded;charset=UTF-8",
            b"csrf=old-token&unchanged=old-token",
            "form",
            "csrf",
        ),
        (
            'Multipart/Form-Data; CHARSET="UTF-8"; Boundary="oldBoundary"',
            multipart(),
            "multipart",
            "csrf",
        ),
    ],
)
def test_extended_refresh_rotates_only_selected_token_and_keeps_wire_contract(
    content_type, body, location, selector
):
    private = request(content_type, body, [binding(location, selector)])
    private["body_contract_version"] = 2
    updated = rotate_body_tokens(private, response())
    assert updated["body_contract_version"] == 2 and updated["content_type"] == content_type
    actual = b64decode(updated["body_base64"])
    assert b"old-token" in actual and b"new-token" in actual
    assert matches_refreshed_capture(
        content_type,
        actual,
        content_type,
        actual,
        expected_body_contract_version=2,
        actual_body_contract_version=2,
    )
    assert not matches_refreshed_capture(
        content_type,
        actual,
        content_type,
        actual + b"x",
        expected_body_contract_version=2,
        actual_body_contract_version=2,
    )
    if location == "multipart":
        assert b"\x00old-token\n\xff" in actual
        assert matches_refreshed_capture(
            content_type,
            actual,
            'multipart/form-data;boundary="newBoundary"',
            actual.replace(b"--oldBoundary", b"--newBoundary"),
            expected_body_contract_version=2,
            actual_body_contract_version=2,
        )
