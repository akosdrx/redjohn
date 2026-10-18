"""Actual loopback HTTP header/control validation; no generated-code execution."""

from __future__ import annotations

import ast
import json
import time
from contextlib import contextmanager
from dataclasses import replace

import httpx
import pytest

from redjohn.assessment.fixture import FixtureServer
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.reproducer import (
    AIExploitGenerator,
    ReproducerRequest,
    SafeReproducerGenerator,
)
from redjohn.assessment.resources import ResourceEnvelope, ResourceGovernor
from redjohn.assessment.store import AssessmentStore


@contextmanager
def lab(tmp_path, *, max_observations=64):
    with FixtureServer() as fixture:
        policy = EngagementPolicy(
            "reproducer-lab",
            "owner",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice"),
            request_budget=16,
        )
        store = AssessmentStore(tmp_path / "agents.db")
        store.register(policy)
        governor = ResourceGovernor(ResourceEnvelope(total_memory_budget=2 * 1024**3))
        generator = SafeReproducerGenerator(
            policy,
            caller="owner",
            governor=governor,
            evidence_reader=lambda ref: store.evidence_get(policy.engagement_id, ref),
            evidence_sink=lambda value: store.evidence_put(
                policy.engagement_id, value, kind="safe_reproducer_observation"
            ),
            request_admission=lambda count: store.consume_requests(policy, count),
            max_observations=max_observations,
        )
        try:
            yield fixture, policy, store, generator
        finally:
            store.close()


async def observed_candidate(fixture, policy, store, *, kind="header"):
    store.consume_requests(policy)
    async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
        response = await client.get(fixture.origin + "/")
    ref = store.evidence_put(
        policy.engagement_id,
        {
            "url": str(response.url),
            "status": response.status_code,
            "headers": dict(response.headers),
            "actor_id": "anonymous",
        },
    )
    extra = {"kind": kind}
    if kind == "harmless_marker":
        extra.update(header_name="x-redjohn-fixture", expected_value="fixed")
    return ReproducerRequest(
        "header-candidate-1",
        "local-fixture:read-only-headers",
        "fixture-http-asset",
        "anonymous",
        fixture.origin + "/",
        (ref,),
        **extra,
    )


async def test_real_header_positive_fixed_control_and_static_regression_export(tmp_path):
    started = time.monotonic()
    with lab(tmp_path) as (fixture, policy, store, generator):
        request = await observed_candidate(fixture, policy, store)
        plan = generator.generate(request)
        assert plan == generator.generate(request)  # deterministic serialization
        before = await generator.observe(plan, phase="candidate", deployment_ref="fixture-before-1")
        fixture.fixed = True
        fixed = await generator.observe(
            plan, phase="fixed_control", deployment_ref="fixture-fixed-2"
        )
        result = generator.validate_pair(plan, before.observation_ref, fixed.observation_ref)
        assert result["finding_status"] == "confirmed_weakness"
        assert result["observed"] is None and result["control_observed"] == "nosniff"
        assert result["coverage_status"] == "completed" and result["control_status"] == "fixed"
        assert result["original_rce_status"] == "not_reproduced_missing_fixture"
        assert len(result["evidence_refs"]) == 3
        assert store.db.execute("SELECT requests_used FROM rj_engagement").fetchone()[0] == 3
        assert fixture.counts["/"] == 3
        assert generator.governor.snapshot()["active"] == {}
        source = generator.regression_source(plan)
        ast.parse(source)  # syntax validation only, never exec generated source
        assert "subprocess" not in source and "exec(" not in source
        assert "client.close()" in source and "response.status, 200" in source
        assert AIExploitGenerator is SafeReproducerGenerator
        measurements = {
            "test": "real_local_header_reproducer_positive_fixed_control",
            "duration_seconds": round(time.monotonic() - started, 6),
            "http_requests": fixture.counts["/"],
            "request_charges": 3,
            "confirmed_weakness": 1,
            "confirmed_impact": 0,
            "model_calls": 0,
            "generated_code_executions": 0,
        }
        (tmp_path / "reproducer-measurements.json").write_text(json.dumps(measurements))
        print("REPRODUCER_MEASUREMENTS=" + json.dumps(measurements))  # noqa: T201


async def test_real_harmless_marker_is_routing_only_even_after_fixed_control(tmp_path):
    with lab(tmp_path) as (fixture, policy, store, generator):
        plan = generator.generate(
            await observed_candidate(fixture, policy, store, kind="harmless_marker")
        )
        before = await generator.observe(plan, phase="candidate", deployment_ref="before")
        fixture.fixed = True
        fixed = await generator.observe(plan, phase="fixed_control", deployment_ref="fixed")
        result = generator.validate_pair(plan, before.observation_ref, fixed.observation_ref)
        assert result["proof_level"] == "routing_fixture_marker"
        assert result["finding_status"] == "candidate"
        assert result["original_rce_status"] == "not_reproduced_missing_fixture"


async def test_same_or_failed_control_never_confirms_weakness(tmp_path):
    with lab(tmp_path) as (fixture, policy, store, generator):
        plan = generator.generate(await observed_candidate(fixture, policy, store))
        before = await generator.observe(plan, phase="candidate", deployment_ref="unchanged")
        same = await generator.observe(plan, phase="fixed_control", deployment_ref="unchanged")
        with pytest.raises(ValueError, match="independent_owned"):
            generator.validate_pair(plan, before.observation_ref, same.observation_ref)
        missing_fix = await generator.observe(
            plan, phase="fixed_control", deployment_ref="changed-but-not-fixed"
        )
        result = generator.validate_pair(plan, before.observation_ref, missing_fix.observation_ref)
        assert result["coverage_status"] == "inconclusive"
        assert result["finding_status"] == "candidate"
        with pytest.raises(ValueError, match="independent_owned"):
            generator.validate_pair(plan, "invented-observation", missing_fix.observation_ref)


async def test_scope_actor_modified_plan_and_missing_evidence_are_blocked(tmp_path):
    with lab(tmp_path) as (fixture, policy, store, generator):
        request = await observed_candidate(fixture, policy, store)
        with pytest.raises(PolicyDenied):
            generator.generate(replace(request, url="https://outside.invalid/"))
        with pytest.raises(PolicyDenied, match="authenticated"):
            generator.generate(replace(request, actor_ref="alice"))
        with pytest.raises(PolicyDenied, match="evidence_access"):
            generator.generate(replace(request, evidence_refs=("invented-ref",)))
        plan = generator.generate(request)
        with pytest.raises(PolicyDenied, match="modified"):
            await generator.observe(
                replace(plan, timeout_seconds=180), phase="candidate", deployment_ref="before"
            )
        assert fixture.counts["/"] == 1


async def test_observation_quota_blocks_before_network_and_owned_state_stays_bounded(tmp_path):
    with lab(tmp_path, max_observations=2) as (fixture, policy, store, generator):
        plan = generator.generate(await observed_candidate(fixture, policy, store))
        for phase in ("candidate", "fixed_control"):
            await generator.observe(plan, phase=phase, deployment_ref=phase)
        with pytest.raises(ValueError, match="capacity"):
            await generator.observe(plan, phase="candidate", deployment_ref="again")
        assert len(generator._observations) == 2 and generator._pending == set()
        assert fixture.counts["/"] == 3


@pytest.mark.parametrize("status", [302, 401, 403, 429, 503])
async def test_real_response_failure_is_blocked_and_never_negative(tmp_path, status, monkeypatch):
    with lab(tmp_path) as (fixture, policy, store, generator):
        plan = generator.generate(await observed_candidate(fixture, policy, store))

        def blocked(handler):
            fixture.counts["blocked"] += 1
            handler.send_response(status)
            handler.send_header("Location", "http://localhost:1/forbidden")
            handler.send_header("Set-Cookie", "private-secret=do-not-log")
            handler.end_headers()

        monkeypatch.setattr(fixture.server.RequestHandlerClass, "do_GET", blocked)
        result = await generator.observe(plan, phase="candidate", deployment_ref="blocked-version")
        assert result.coverage_status == "blocked" and result.execution_status == "failed"
        evidence = store.evidence_get(policy.engagement_id, result.evidence_ref)
        assert "private-secret" not in evidence["excerpt"] and "Cookie" not in evidence["excerpt"]
        assert fixture.counts["blocked"] == 1
        assert generator.governor.snapshot()["active"] == {}


async def test_actual_oversized_body_is_inconclusive_with_partial_evidence(tmp_path, monkeypatch):
    with lab(tmp_path) as (fixture, policy, store, generator):
        plan = generator.generate(await observed_candidate(fixture, policy, store))

        def oversized(handler):
            handler.send_response(200)
            handler.end_headers()
            handler.wfile.write(b"x" * 70000)

        monkeypatch.setattr(fixture.server.RequestHandlerClass, "do_GET", oversized)
        result = await generator.observe(plan, phase="candidate", deployment_ref="oversized")
        assert result.coverage_status == "inconclusive" and result.body_bytes <= 65536
        assert result.evidence_ref and generator.governor.snapshot()["active"] == {}


def test_arbitrary_code_payload_and_non_candidate_inputs_have_no_schema():
    base = {
        "candidate_ref": "c",
        "fixture_ref": "f",
        "asset_ref": "a",
        "actor_ref": "anonymous",
        "url": "http://127.0.0.1:1234/",
        "evidence_refs": ("e",),
    }
    with pytest.raises(TypeError):
        ReproducerRequest(**base, code="import os")
    with pytest.raises(ValueError, match="candidate"):
        ReproducerRequest(**base, finding_status="confirmed_impact")
    with pytest.raises(ValueError, match="unsupported"):
        ReproducerRequest(**base, kind="rce")


async def test_actual_deadline_timeout_preserves_evidence_and_releases_resources(
    tmp_path, monkeypatch
):
    with lab(tmp_path) as (fixture, policy, store, generator):
        plan = generator.generate(await observed_candidate(fixture, policy, store))
        generator.policy = replace(policy, deadline=time.time() + 0.1)

        def slow(handler):
            handler.send_response(200)
            handler.end_headers()
            time.sleep(0.3)

        monkeypatch.setattr(fixture.server.RequestHandlerClass, "do_GET", slow)
        result = await generator.observe(plan, phase="candidate", deployment_ref="slow")
        assert result.execution_status == "timed_out" and result.coverage_status == "partial"
        assert result.evidence_ref and result.duration_seconds < 1
        assert generator._pending == set() and generator.governor.snapshot()["active"] == {}


async def test_storage_failure_does_not_create_a_validatable_observation(tmp_path):
    with lab(tmp_path) as (fixture, policy, store, generator):
        plan = generator.generate(await observed_candidate(fixture, policy, store))
        generator.evidence_sink = lambda _value: ""
        with pytest.raises(ValueError, match="evidence_write_failed"):
            await generator.observe(plan, phase="candidate", deployment_ref="before")
        assert generator._observations == {} and generator._pending == set()
        assert generator.governor.snapshot()["active"] == {}
