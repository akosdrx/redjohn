"""Local schema/proxy-hook regressions; actual transport proof lives in E2E tests."""

from __future__ import annotations

import copy
import hashlib
import json
import time
from base64 import b64encode
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from redjohn.assessment.auth_replay import AuthReplayDenied, AuthReplayVault
from redjohn.assessment.models import Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.request_body import (
    HOST_REPLAY_BODY_MARKER,
    MAX_REPLAY_BODY_BYTES,
    ApprovedRequestBody,
    RequestBodyDenied,
)


if TYPE_CHECKING:
    from pathlib import Path


URL = "https://127.0.0.1:8443/query?b=2&a=1"
MULTIPART = (
    b'--redjohn_boundary\r\nContent-Disposition: form-data; name="tag"\r\n\r\none\r\n'
    b'--redjohn_boundary\r\nContent-Disposition: form-data; name="tag"\r\n\r\ntwo\r\n'
    b'--redjohn_boundary\r\nContent-Disposition: form-data; name="upload"; filename="proof.txt"\r\n'
    b"Content-Type: text/plain\r\n\r\nprivate-file-content\r\n\r\n--redjohn_boundary--\r\n"
)
BODY_CASES = [
    ("application/json", b'{ "tag":"one", "tag":"two", "secret":"private-json-value" }'),
    ("application/json; charset=utf-8", '{"value":"árvíz"}'.encode()),
    ("application/x-www-form-urlencoded", b"tag=one&tag=two&secret=private%2Bform%3Dvalue&empty="),
    ("application/x-www-form-urlencoded; charset=utf-8", b"value=%C3%A1rv%C3%ADz"),
    ("multipart/form-data; boundary=redjohn_boundary", MULTIPART),
]


def body_fields(content_type: str, body: bytes) -> dict:
    return {
        "content_type": content_type,
        "body_base64": b64encode(body).decode(),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }


def post_fixture(content_type: str, body: bytes) -> tuple[EngagementPolicy, Surface, dict]:
    policy = EngagementPolicy(
        "post-fixture",
        "owner",
        ("https://127.0.0.1:8443",),
        allowed_replay_urls=(URL,),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("anonymous", "alice"),
    )
    surface = Surface(
        URL,
        method="POST",
        content_type=content_type,
        body_sha256=hashlib.sha256(body).hexdigest(),
        actor_id="alice",
        tenant_id="tenant-a",
        session_revision="7",
        request_ref="captured-post-1",
    )
    data = {
        "version": 2,
        "entries": [
            {
                "engagement_id": policy.engagement_id,
                "owner_id": policy.owner_id,
                "actor_id": surface.actor_id,
                "tenant_id": surface.tenant_id,
                "session_revision": surface.session_revision,
                "policy_revision": policy.revision,
                "expires_at": time.time() + 300,
                "origin": "https://127.0.0.1:8443",
                "allowed_requests": [
                    {
                        "url": surface.url,
                        "method": surface.method,
                        "request_ref": surface.request_ref,
                        "replay_safety": "operator-approved",
                        **body_fields(content_type, body),
                    }
                ],
                "headers": {"Authorization": "Bearer private-post-token"},
                "cookies": [],
            }
        ],
    }
    return policy, surface, data


@pytest.mark.parametrize("content_type,body", BODY_CASES)
def test_exact_post_bytes_and_duplicate_fields_survive_host_replay(content_type: str, body: bytes):
    policy, surface, data = post_fixture(content_type, body)
    vault = AuthReplayVault.from_mapping(data, policy)
    assert vault.to_mapping() == data
    binding = vault.authorize(surface)
    binding.validate_template_request(URL, "POST", HOST_REPLAY_BODY_MARKER, content_type, policy)
    headers, actual_body = binding.rewrite_request(
        URL,
        "POST",
        [("Content-Type", content_type), ("Content-Length", "25"), ("Authorization", "wrong")],
        HOST_REPLAY_BODY_MARKER.encode(),
    )
    assert actual_body == body
    assert dict(headers)["Content-Length"] == str(len(body))
    assert dict(headers)["Content-Type"] == content_type
    assert dict(headers)["Authorization"] == "Bearer private-post-token"
    assert binding.metadata()["body_sha256"] == surface.body_sha256
    assert data["entries"][0]["allowed_requests"][0]["body_base64"] not in repr(binding)
    assert "private-json-value" not in json.dumps(binding.metadata())
    cloned = vault.to_mapping()
    cloned["entries"][0]["headers"]["Authorization"] = "mutated"
    assert vault.to_mapping() == data


@pytest.mark.parametrize(
    "changes",
    [
        {"body_sha256": "a" * 64},
        {"content_type": "text/plain"},
        {"request_ref": "other"},
        {"session_revision": "8"},
    ],
)
def test_capture_body_and_identity_must_match(changes: dict):
    policy, surface, data = post_fixture(*BODY_CASES[0])
    with pytest.raises(AuthReplayDenied):
        AuthReplayVault.from_mapping(data, policy).authorize(replace(surface, **changes))


@pytest.mark.parametrize(
    "headers,body",
    [
        ([("Content-Type", "application/json")], b"{}"),
        ([("Content-Type", "text/plain")], HOST_REPLAY_BODY_MARKER.encode()),
        ([], HOST_REPLAY_BODY_MARKER.encode()),
        (
            [("Content-Type", "application/json"), ("content-type", "application/json")],
            HOST_REPLAY_BODY_MARKER.encode(),
        ),
    ],
)
def test_worker_cannot_expand_or_change_post_wire_request(headers: list, body: bytes):
    policy, surface, data = post_fixture(*BODY_CASES[0])
    binding = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    with pytest.raises(AuthReplayDenied, match="worker_body_mismatch"):
        binding.rewrite_request(URL, "POST", headers, body)


def test_post_needs_v2_exact_operator_and_policy_approval():
    policy, _surface, data = post_fixture(*BODY_CASES[0])
    version1 = copy.deepcopy(data)
    version1["version"] = 1
    with pytest.raises(AuthReplayDenied, match="invalid_requests"):
        AuthReplayVault.from_mapping(version1, policy)
    no_approval = copy.deepcopy(data)
    no_approval["entries"][0]["allowed_requests"][0]["replay_safety"] = "inferred"
    with pytest.raises(AuthReplayDenied, match="operator_approval_required"):
        AuthReplayVault.from_mapping(no_approval, policy)
    with pytest.raises(AuthReplayDenied):
        AuthReplayVault.from_mapping(data, replace(policy, allowed_replay_urls=()))


@pytest.mark.parametrize(
    "content_type,body",
    [
        ("Application/JSON", b"{}"),
        ("application/json; charset=UTF-8", b"{}"),
        ("application/json; charset=utf-8; charset=utf-8", b"{}"),
        ("application/json", b'{"number":NaN}'),
        ("application/json", b"\xff"),
        ("application/x-www-form-urlencoded", b"value=%xx"),
        ("application/x-www-form-urlencoded", b"value=%FF"),
        ('multipart/form-data; boundary="redjohn_boundary"', MULTIPART),
        ("multipart/form-data; boundary=redjohn_boundary; boundary=evil", MULTIPART),
        (
            "multipart/form-data; boundary=redjohn_boundary",
            MULTIPART.replace(b'filename="proof.txt"', b'filename="../proof.txt"'),
        ),
        (
            "multipart/form-data; boundary=redjohn_boundary",
            MULTIPART.replace(b'filename="proof.txt"', b'filename="proof\r\nEvil: yes"'),
        ),
        (
            "multipart/form-data; boundary=redjohn_boundary",
            MULTIPART.replace(b"Content-Type: text/plain", b"Content-Length: 100"),
        ),
        (
            "multipart/form-data; boundary=redjohn_boundary",
            MULTIPART.replace(
                b"Content-Type: text/plain", b"Content-Disposition: form-data; name=evil"
            ),
        ),
    ],
)
def test_ambiguous_or_unsupported_body_schema_is_denied(content_type: str, body: bytes):
    with pytest.raises(RequestBodyDenied):
        ApprovedRequestBody.from_mapping(body_fields(content_type, body))


def test_body_size_hash_and_base64_are_checked_before_authorization():
    fields = body_fields("application/json", b"{}")
    with pytest.raises(RequestBodyDenied, match="hash_mismatch"):
        ApprovedRequestBody.from_mapping({**fields, "body_sha256": "0" * 64})
    with pytest.raises(RequestBodyDenied, match="invalid_base64"):
        ApprovedRequestBody.from_mapping({**fields, "body_base64": "!!"})
    with pytest.raises(RequestBodyDenied):
        ApprovedRequestBody.from_mapping(
            body_fields("application/json", b" " * MAX_REPLAY_BODY_BYTES + b"{}")
        )


@pytest.mark.parametrize("content_type,body", [BODY_CASES[0], BODY_CASES[2], BODY_CASES[4]])
def test_reflected_body_values_and_keys_are_redacted(content_type: str, body: bytes):
    policy, surface, data = post_fixture(content_type, body)
    binding = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    secrets = ["private-json-value", "private+form=value", "private-file-content"]
    raw = {
        secret: {"reflected": secret}
        for secret in secrets
        if secret.encode() in body
        or ("form" in secret and content_type.startswith("application/x-www-form-urlencoded"))
    }
    sanitized = json.dumps(binding.redact_raw(raw))
    assert raw
    assert "[redacted]" in sanitized
    assert all(secret not in sanitized for secret in raw)


def test_expired_vault_can_be_validated_for_rotation_but_not_authorized(tmp_path: Path):
    policy, surface, data = post_fixture(*BODY_CASES[0])
    data["entries"][0]["expires_at"] = time.time() - 1
    path = tmp_path / "private-vault.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    with pytest.raises(AuthReplayDenied, match="expired"):
        AuthReplayVault.from_file(path, policy)
    rotation = AuthReplayVault.read_for_rotation(path, policy)
    assert rotation.to_mapping() == data
    with pytest.raises(AuthReplayDenied, match="expired"):
        rotation.authorize(surface)
    path.chmod(0o644)
    with pytest.raises(AuthReplayDenied, match="not_private"):
        AuthReplayVault.read_for_rotation(path, policy)


def test_selected_live_actor_loads_with_unrelated_expired_actor(tmp_path: Path):
    policy, surface, data = post_fixture(*BODY_CASES[0])
    policy = replace(policy, actor_ids=("anonymous", "alice", "bob"))
    expired_bob = copy.deepcopy(data["entries"][0])
    expired_bob["actor_id"] = "bob"
    expired_bob["expires_at"] = time.time() - 1
    data["entries"].append(expired_bob)
    path = tmp_path / "private-vault.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    with pytest.raises(AuthReplayDenied, match="expired"):
        AuthReplayVault.from_file(path, policy)
    selected = AuthReplayVault.from_file_for_surface(path, policy, surface)
    assert selected.authorize(surface).actor_id == "alice"
    with pytest.raises(AuthReplayDenied, match="expired"):
        AuthReplayVault.from_file_for_surface(path, policy, replace(surface, actor_id="bob"))
    rotation = AuthReplayVault.for_rotation_mapping(data, policy)
    assert rotation.to_mapping() == data
    with pytest.raises(AuthReplayDenied, match="expired"):
        rotation.authorize(replace(surface, actor_id="bob"))


def test_redaction_preserves_public_json_keys_numbers_and_duplicate_secret_values():
    body = b'{"id":1,"secret":"one","secret":"two"}'
    policy, surface, data = post_fixture("application/json", body)
    binding = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    assert binding.redact_raw({"id": 1, "value": "one two"}) == {
        "id": 1,
        "value": "[redacted] [redacted]",
    }
    short_body = b'{"secret":"a"}'
    policy, surface, data = post_fixture("application/json", short_body)
    binding = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    # Replacement text is never processed again, even for one-character data.
    assert binding.redact_raw("a") == "[redacted]"


@pytest.mark.parametrize("name", ["X-CSRF-Token", "X-XSRF-Token"])
def test_post_csrf_header_exact_injection_and_reflection_redaction(name: str):
    policy, surface, data = post_fixture(*BODY_CASES[0])
    data["entries"][0]["headers"][name] = "private-csrf-header-value"
    binding = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    headers, _body = binding.rewrite_request(
        URL,
        "POST",
        [("Content-Type", surface.content_type), (name, "wrong-worker-token")],
        HOST_REPLAY_BODY_MARKER.encode(),
    )
    assert [value for header, value in headers if header.lower() == name.lower()] == [
        "private-csrf-header-value"
    ]
    assert binding.redact_raw({"response": "private-csrf-header-value"}) == {
        "response": "[redacted]"
    }
    data["entries"][0]["headers"][name] = "secret\r\nX-Evil: yes"
    with pytest.raises(AuthReplayDenied, match="invalid_secret_schema"):
        AuthReplayVault.from_mapping(data, policy)
