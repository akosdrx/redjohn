"""Synthetic private-input and recovery contracts, separate from actual E2Es."""

import hashlib
import time
from base64 import b64encode
from contextlib import closing
from dataclasses import replace

import pytest

from redjohn.assessment.auth_replay import AuthReplayBinding
from redjohn.assessment.body_tokens import validate_body_token_bindings
from redjohn.assessment.input_replay import PrivateBodyInput, carrier_surface, validate_post_input
from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.request_body import ApprovedRequestBody
from redjohn.assessment.session_recovery import auth_recovery_marker, validate_recovery_event
from redjohn.assessment.store import AssessmentStore


def approved(kind, *, duplicate=False, selected="value"):
    if kind == "json":
        content_type = "application/json"
        raw = (
            '{ "value" : "benign", "csrf":"private-token", "other":"árvíz", '
            '"keep":1,"keep":2' + (',"value":"again"' if duplicate else "") + "}\n"
        ).encode()
    elif kind == "form":
        content_type = "application/x-www-form-urlencoded"
        raw = b"keep=one%20two&value=benign&csrf=private-token&keep=one+two" + (
            b"&value=again" if duplicate else b""
        )
    else:
        content_type = "multipart/form-data; boundary=RedJohnBoundary"
        raw = (
            b'--RedJohnBoundary\r\nContent-Disposition: form-data; name="value"\r\n\r\nbenign\r\n'
            b'--RedJohnBoundary\r\nContent-Disposition: form-data; name="csrf"\r\n'
            b"\r\nprivate-token\r\n"
            b'--RedJohnBoundary\r\nContent-Disposition: form-data; name="upload";'
            b' filename="fixture.bin"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\xff\r\n'
            b"--RedJohnBoundary--\r\n"
        )
    body = ApprovedRequestBody.from_mapping(
        {
            "content_type": content_type,
            "body_base64": b64encode(raw).decode(),
            "body_sha256": hashlib.sha256(raw).hexdigest(),
        }
    )
    protected = validate_body_token_bindings(
        body,
        [
            {
                "location": kind,
                "selector": "/csrf" if kind == "json" else "csrf",
                "occurrence": 0,
                "source": {"kind": "header", "name": "X-CSRF-Token"},
            }
        ],
    )
    surface = Surface(
        "https://127.0.0.1:4443/input?keep=raw%20value",
        method="POST",
        content_type=content_type,
        input_location=kind,
        input_name=("/" + selected) if kind == "json" else selected,
        actor_id="alice",
        tenant_id="tenant-a",
        session_revision="7",
        request_ref="capture-reference",
        body_sha256=body.sha256,
    )
    binding = AuthReplayBinding(
        "engagement",
        "operator",
        "alice",
        "tenant-a",
        "7",
        "1",
        surface.request_ref,
        surface.url,
        "POST",
        time.time() + 600,
        (("Authorization", "Bearer private-header"),),
        ("private-header",),
        _body=body,
        _body_tokens=protected,
    )
    return surface, binding, body


@pytest.mark.parametrize("kind", ["json", "form", "multipart"])
def test_lossless_selected_field_keeps_every_other_wire_byte_and_upload(kind):
    surface, binding, body = approved(kind)
    selected = PrivateBodyInput.from_binding(binding, surface)
    changed = selected.mutate("{{7*7}}")
    assert changed.startswith(body.data[: selected.start])
    assert changed.endswith(body.data[selected.end :])
    assert selected.mutate("RJBASELINE") == body.data
    assert b"private-token" in changed
    assert "private-token" not in repr(selected) and "private-header" not in repr(binding)
    carrier = carrier_surface(surface)
    assert carrier.url.endswith("?rj_input=RJBASELINE")
    assert "keep=raw" not in carrier.url
    assert carrier.method == "GET" and not carrier.content_type and not carrier.body_sha256


@pytest.mark.parametrize("kind", ["json", "form", "multipart"])
def test_reviewed_session_token_can_never_be_selected_as_a_mutation_input(kind):
    surface, binding, _body = approved(kind, selected="csrf")
    with pytest.raises(ValueError, match="overlaps_session_token"):
        PrivateBodyInput.from_binding(binding, surface)


@pytest.mark.parametrize("kind", ["json", "form"])
def test_duplicate_selected_field_is_rejected_while_unselected_duplicates_are_preserved(kind):
    surface, binding, _body = approved(kind, duplicate=True)
    with pytest.raises(ValueError, match="missing_or_ambiguous"):
        PrivateBodyInput.from_binding(binding, surface)


def test_binary_upload_is_not_a_string_mutation_input():
    surface, binding, _body = approved("multipart", selected="upload")
    with pytest.raises(ValueError, match="scalar_type_unsupported"):
        PrivateBodyInput.from_binding(binding, surface)


@pytest.mark.parametrize("kind", ["json", "form", "multipart"])
@pytest.mark.parametrize("bad", ["missing", "oversize"])
def test_missing_selector_and_mutation_size_stop_before_any_transport(kind, bad):
    surface, binding, _body = approved(kind, selected="missing" if bad == "missing" else "value")
    with pytest.raises(ValueError):
        PrivateBodyInput.from_binding(binding, surface).mutate("x" * 4097)


@pytest.mark.parametrize(
    "change",
    [
        {"idempotent": True},
        {"actor_id": "anonymous"},
        {"request_ref": ""},
        {"body_sha256": ""},
        {"input_location": "file"},
    ],
)
def test_post_admission_requires_named_observation_nonidempotence_and_supported_field(change):
    surface, _binding, _body = approved("json")
    policy = EngagementPolicy(
        "engagement",
        "operator",
        ("https://127.0.0.1:4443",),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("alice", "anonymous"),
        allowed_replay_urls=(surface.url,),
    )
    spec = JobSpec("surface", "ssti", "tinja_validate", idempotent=False)
    if "idempotent" in change:
        spec = replace(spec, **change)
    else:
        surface = replace(surface, **change)
    with pytest.raises(ValueError):
        validate_post_input(policy, surface, spec)


@pytest.mark.parametrize(
    "capability", ["tinja_validate", "schemathesis_validate", "oast_correlate"]
)
@pytest.mark.parametrize("signal", ["http_401", "credential_expired"])
def test_new_adapter_auth_failure_enters_existing_atomic_recovery_outbox(
    tmp_path, capability, signal
):
    surface, _binding, _body = approved("json")
    policy = EngagementPolicy(
        "engagement",
        "operator",
        ("https://127.0.0.1:4443",),
        profile="isolated-lab",
        egress_mode="local-fixture",
        actor_ids=("alice",),
        allowed_replay_urls=(surface.url,),
    )
    with closing(AssessmentStore(tmp_path / "state.db")) as store:
        store.register(policy)
        sid = store.upsert_surface(policy.engagement_id, surface)
        spec = JobSpec(sid, "test", capability, idempotent=False)
        store.submit(policy, [spec])
        job = store.claim(policy, "synthetic-contract-worker")
        code = "authentication_expired" if signal == "http_401" else "auth_replay_expired"
        result = AdapterResult(
            "failed",
            "blocked",
            {"auth_recovery": auth_recovery_marker(surface, signal)},
            error=error_record(code, coverage_effect="blocked"),
        )
        assert store.finish(job, result)
        events = store.pending_followups(policy)
        assert len(events) == 1 and events[0]["kind"] == "auth_failure"
        validate_recovery_event(events[0], surface)
        assert store.jobs(policy.engagement_id)[0]["attempt"] == 1


@pytest.mark.parametrize(
    "capability", ["tinja_validate", "schemathesis_validate", "oast_correlate"]
)
@pytest.mark.parametrize(
    "change",
    [{"status": 403}, {"response_complete": False}, {"actor_id": "bob"}, {"session_revision": "8"}],
)
def test_partial_challenge_cross_identity_or_cross_revision_does_not_authorize_refresh(
    capability, change
):
    surface, _binding, _body = approved("json")
    event = {
        "capability": capability,
        "result": {
            "execution_status": "failed",
            "coverage_status": "blocked",
            "summary": {"auth_recovery": {**auth_recovery_marker(surface, "http_401"), **change}},
            "error": {"code": "authentication_expired"},
        },
    }
    with pytest.raises(ValueError):
        validate_recovery_event(event, surface)
