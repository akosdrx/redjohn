"""Redaction/normalization unit regressions using an explicit transport double."""

from __future__ import annotations

import copy
import json
from unittest.mock import AsyncMock

import pytest

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.request_body import HOST_REPLAY_BODY_MARKER, ApprovedRequestBody
from redjohn.tools.hunt.nuclei import (
    NucleiAdapter,
    NucleiLock,
    ReviewedHTTPRequest,
    TemplateSelection,
    bundle_digest,
    normalize_nuclei,
)
from tests.test_replay_body_contract import body_fields, post_fixture


@pytest.mark.parametrize("body", [b"1", b"true", b"false", b"null"])
def test_json_scalar_reflections_are_masked_without_changing_typed_protocol_data(body):
    approved = ApprovedRequestBody.from_mapping(body_fields("application/json", body))
    assert body.decode() in approved.redaction_values
    policy, surface, data = post_fixture("application/json", body)
    binding = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    stats = '{"requests":1,"errors":0,"matcher-status":true,"cancelled":false}'
    masked = binding.redact_worker_output({"stdout": stats})
    assert json.loads(masked["stdout"]) == json.loads(stats)


@pytest.mark.parametrize(
    "body,reflections",
    [
        (b'{"pin":1234}', ("1234", "1234.0")),
        (b'{"pin":1.25e3}', ("1.25e3", "1250.0", "1250")),
        (b'{"pin":-2.5E-2}', ("-2.5E-2", "-0.025")),
        (b'{"pin":1e9999}', ("1e9999",)),
        (b"1", ("1", "1.0")),
        (b"true", ("true",)),
        (b"null", ("null",)),
    ],
)
def test_private_numeric_lexemes_and_scalar_text_reflections_are_masked(body, reflections):
    policy, surface, data = post_fixture("application/json", body)
    binding = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    stdout = json.dumps(
        {
            "type": "http",
            "matcher-status": True,
            "extracted-results": list(reflections),
            "response": "reflected pin=" + " ".join(reflections),
        }
    )
    stats = {"requests": 1, "errors": 0, "completed": True, "pending": None}
    raw = {
        "stdout": stdout + "\n" + "\n".join(reflections),
        "stderr": json.dumps(stats),
        "exit_code": 0,
        "truncated": False,
    }
    masked = binding.redact_worker_output(raw)
    lines = masked["stdout"].splitlines()
    parsed = json.loads(lines[0])
    assert parsed["extracted-results"] == ["[redacted]"] * len(reflections)
    assert parsed["response"] == "reflected pin=" + " ".join(["[redacted]"] * len(reflections))
    assert lines[1:] == ["[redacted]"] * len(reflections)
    assert parsed["type"] == "http" and parsed["matcher-status"] is True
    assert json.loads(masked["stderr"]) == stats
    assert masked["exit_code"] == 0 and masked["truncated"] is False


@pytest.mark.parametrize(
    "body,auth_token,flags",
    [
        (b"1", "private-post-token", {}),
        (b"true", "private-post-token", {}),
        (b'{"private":"stdout"}', "private-post-token", {}),
        (b'{"private":"truncated"}', "private-post-token", {"truncated": True}),
        (b'{"private":"timed_out"}', "private-post-token", {"timed_out": True}),
        (b'{"private":"ordinary-private-string"}', "stdout", {}),
        (b'{"private":"ordinary-private-string"}', "1", {}),
    ],
)
@pytest.mark.parametrize("candidate", [True, False])
async def test_redaction_cannot_erase_candidates_or_change_execution_classification(
    tmp_path, monkeypatch, body, auth_token, flags, candidate
):
    policy, surface, data = post_fixture("application/json", body)
    data["entries"][0]["headers"]["Authorization"] = "Bearer " + auth_token
    binding = AuthReplayVault.from_mapping(data, policy).authorize(surface)
    selection = TemplateSelection(
        "post.yaml", "fixture-post", ("isolated-lab",), effect="authenticated-replay"
    )
    files = {"post.yaml": "a" * 64}
    # This lock never executes a binary: only the adapter's bounded transport
    # seam is replaced below. Real-engine coverage remains in *_post_live.py.
    lock = NucleiLock(
        "/contract-double/nuclei",
        "3.11.1",
        "b" * 64,
        "explicit-contract-test-double",
        "test-only",
        str(tmp_path),
        "test-only",
        bundle_digest(files),
        "explicit-contract-test-double",
        "test-only",
        files,
        (selection,),
    )
    private_text = "ordinary-private-string stdout truncated timed_out " + auth_token
    finding = {
        "template-id": selection.template_id,
        "type": "http",
        "matched-at": surface.url,
        "info": {"name": private_text, "severity": "info"},
        "matcher-status": True,
    }
    raw = {
        "stdout": json.dumps(finding) if candidate else "",
        "stderr": json.dumps({"requests": 1, "errors": 0}),
        "exit_code": 0,
        "truncated": False,
        "timed_out": False,
        **flags,
    }
    responses = ({"url": surface.url, "status": 200},)
    expected_raw = {**raw, "response_observations": list(responses)}
    expected = normalize_nuclei(
        copy.deepcopy(expected_raw),
        (selection,),
        policy,
        expected_requests=1,
        expected_request_urls=(surface.url,),
    )
    snapshots = []

    def sink(value):
        snapshots.append(copy.deepcopy(value))
        return "redacted-evidence-reference"

    adapter = NucleiAdapter(
        None,
        lock,
        proxy_url="http://127.0.0.1:9000",
        response_observations=lambda: responses,
        evidence_sink=sink,
        auth_replay=binding,
    )
    adapter.prepared_request_count = 1
    adapter.prepared_template_requests = (
        ReviewedHTTPRequest("POST", "{{BaseURL}}", HOST_REPLAY_BODY_MARKER, "application/json"),
    )
    adapter.prepared_http_requests = (("POST", "{{BaseURL}}"),)
    monkeypatch.setattr(
        adapter, "healthcheck", AsyncMock(return_value={"execution_status": "succeeded"})
    )
    monkeypatch.setattr(adapter, "prepare", AsyncMock(return_value={}))
    monkeypatch.setattr(adapter, "_execute", AsyncMock(return_value=copy.deepcopy(raw)))
    actual = await adapter.run(surface.url, policy=policy)
    assert actual["execution_status"] == expected["execution_status"]
    assert actual["coverage_status"] == expected["coverage_status"]
    assert actual["no_finding_observed"] == expected["no_finding_observed"]
    assert len(actual["findings"]) == len(expected["findings"]) == int(candidate)
    assert actual.get("error", {}).get("code") == expected.get("error", {}).get("code")
    assert len(snapshots) == 1
    assert "stdout" in snapshots[0] and "truncated" in snapshots[0] and "timed_out" in snapshots[0]
    if candidate:
        assert "Bearer " + auth_token not in actual["findings"][0]["name"]
        assert auth_token not in actual["findings"][0]["name"]
        assert auth_token not in snapshots[0]["stdout"]
        assert actual["findings"][0]["finding_status"] == "candidate"
        assert actual["no_finding_observed"] is False
