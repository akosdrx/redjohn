"""Deterministic local lab validation plans and exportable safe regressions.

AIExploitGenerator is retained as a compatibility name. This component does
not execute generated code, exploit a remote target, or infer RCE from markers.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit


if TYPE_CHECKING:
    from collections.abc import Callable

    from redjohn.assessment.resources import ResourceGovernor

from redjohn.assessment.models import error_record, stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied


_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.\-/]{0,127}")
_HEADERS = {"x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'"}
_ORIGINAL_RCE = "not_reproduced_missing_fixture"


@dataclass(frozen=True)
class ReproducerRequest:
    candidate_ref: str
    fixture_ref: str
    asset_ref: str
    actor_ref: str
    url: str
    evidence_refs: tuple[str, ...]
    kind: Literal["header", "harmless_marker"] = "header"
    header_name: str = "x-content-type-options"
    expected_value: str = "nosniff"
    finding_status: str = "candidate"
    source: str = "observed"

    def __post_init__(self) -> None:
        for value in (self.candidate_ref, self.fixture_ref, self.asset_ref, self.actor_ref):
            if not isinstance(value, str) or not _REF.fullmatch(value):
                raise ValueError("invalid_reproducer_reference")
        if (
            not isinstance(self.evidence_refs, tuple)
            or not 1 <= len(self.evidence_refs) <= 8
            or any(
                not isinstance(value, str) or not _REF.fullmatch(value)
                for value in self.evidence_refs
            )
        ):
            raise ValueError("observed_evidence_required")
        if self.finding_status != "candidate" or self.source != "observed":
            raise ValueError("observed_candidate_required")
        if self.kind == "header":
            if _HEADERS.get(self.header_name) != self.expected_value:
                raise ValueError("unsupported_header_assertion")
        elif self.kind == "harmless_marker":
            if self.header_name != "x-redjohn-fixture" or self.expected_value != "fixed":
                raise ValueError("only_static_harmless_fixture_marker_supported")
        else:
            raise ValueError("unsupported_reproducer_kind")
        if not isinstance(self.url, str) or len(self.url) > 2048 or urlsplit(self.url).fragment:
            raise ValueError("invalid_reproducer_url")


@dataclass(frozen=True)
class ReadOnlyAssertion:
    header_name: str
    expected_fixed_value: str
    expected_candidate_marker: str | None
    proof_level: str


@dataclass(frozen=True)
class ControlRequirement:
    phase: str = "fixed_control"
    distinct_deployment_required: bool = True
    same_url_actor_asset_required: bool = True


@dataclass(frozen=True)
class CleanupPlan:
    action: str = "close_http_client_and_release_lease"
    modifies_fixture: bool = False
    external_cleanup_required: bool = False


@dataclass(frozen=True)
class ReproducerPlan:
    plan_ref: str
    engagement_id: str
    policy_revision: str
    request: ReproducerRequest
    assertion: ReadOnlyAssertion
    control: ControlRequirement
    cleanup: CleanupPlan
    timeout_seconds: int = 5
    body_max_bytes: int = 65536
    method: str = "GET"
    schema_version: int = 1
    original_rce_status: str = _ORIGINAL_RCE

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReproducerObservation:
    observation_ref: str
    plan_ref: str
    phase: str
    deployment_ref: str
    status: int | None
    header_value: str | None
    body_sha256: str
    body_bytes: int
    execution_status: str
    coverage_status: str
    evidence_ref: str
    duration_seconds: float
    observed_at: float
    error: dict[str, Any] | None = None


class SafeReproducerGenerator:
    """Own bounded plan/observation state; reuse the existing protected store."""

    def __init__(
        self,
        policy: EngagementPolicy,
        *,
        caller: str,
        governor: ResourceGovernor,
        evidence_reader: Callable[[str], dict[str, Any]],
        evidence_sink: Callable[[dict[str, Any]], str],
        request_admission: Callable[[int], None],
        max_plans: int = 32,
        max_observations: int = 64,
    ) -> None:
        policy.authorize(caller)
        if not 1 <= max_plans <= 128 or not 2 <= max_observations <= 256:
            raise ValueError("invalid_reproducer_state_budget")
        self.policy, self.governor = policy, governor
        self.evidence_reader, self.evidence_sink = evidence_reader, evidence_sink
        self.request_admission = request_admission
        self.max_plans, self.max_observations = max_plans, max_observations
        self._plans: dict[str, ReproducerPlan] = {}
        self._observations: dict[str, ReproducerObservation] = {}
        self._pending: set[str] = set()

    def _authorize(self, request: ReproducerRequest) -> None:
        self.policy.check_capability(domains=("web",), profiles=("isolated-lab",))
        self.policy.check_actor(request.actor_ref)
        if request.actor_ref != "anonymous":
            raise PolicyDenied("authenticated_reproducer_not_implemented")
        self.policy.check_url(request.url)
        # Literal addresses only: no DNS aliases, public hosts or rebinding.
        if not ipaddress.ip_address(urlsplit(request.url).hostname or "").is_loopback:
            raise PolicyDenied("reproducer_requires_literal_loopback")

    def generate(self, request: ReproducerRequest) -> ReproducerPlan:
        self._authorize(request)
        for ref in request.evidence_refs:
            record = self.evidence_reader(ref)
            if record.get("truncated") or len(record.get("excerpt", "")) > 65536:
                raise ValueError("bounded_complete_evidence_required")
            evidence = json.loads(record["excerpt"])
            if (
                not isinstance(evidence, dict)
                or evidence.get("url") != request.url
                or evidence.get("actor_id") != request.actor_ref
                or evidence.get("status") != 200
                or not isinstance(evidence.get("headers"), dict)
            ):
                raise ValueError("candidate_evidence_context_mismatch")
            value = {str(key).lower(): val for key, val in evidence["headers"].items()}.get(
                request.header_name
            )
            if request.kind == "header" and value == request.expected_value:
                raise ValueError("candidate_contradicted_by_observed_evidence")
            if request.kind == "harmless_marker" and value != "initial":
                raise ValueError("harmless_marker_was_not_observed")
        assertion = ReadOnlyAssertion(
            request.header_name,
            request.expected_value,
            "initial" if request.kind == "harmless_marker" else None,
            "routing_fixture_marker"
            if request.kind == "harmless_marker"
            else "local_controlled_header_validation",
        )
        plan_ref = stable_key(
            [self.policy.engagement_id, self.policy.revision, asdict(request), asdict(assertion), 1]
        )
        if plan_ref not in self._plans and len(self._plans) >= self.max_plans:
            raise ValueError("reproducer_plan_capacity_exhausted")
        plan = ReproducerPlan(
            plan_ref,
            self.policy.engagement_id,
            self.policy.revision,
            request,
            assertion,
            ControlRequirement(),
            CleanupPlan(),
        )
        self._plans[plan_ref] = plan
        return plan

    def _plan(self, plan: ReproducerPlan) -> None:
        if self._plans.get(plan.plan_ref) != plan or self.policy.revision != plan.policy_revision:
            raise PolicyDenied("unknown_or_modified_reproducer_plan")
        self._authorize(plan.request)

    async def observe(
        self, plan: ReproducerPlan, *, phase: str, deployment_ref: str
    ) -> ReproducerObservation:
        if len(self._observations) + len(self._pending) >= self.max_observations:
            raise ValueError("reproducer_observation_capacity_exhausted")
        reservation = uuid.uuid4().hex
        self._pending.add(reservation)
        try:
            return await self._observe(plan, phase=phase, deployment_ref=deployment_ref)
        finally:
            self._pending.discard(reservation)

    async def _observe(  # noqa: PLR0912, PLR0915 - each bounded failure retains its coverage
        self, plan: ReproducerPlan, *, phase: str, deployment_ref: str
    ) -> ReproducerObservation:
        import httpx  # noqa: PLC0415 - optional HTTP work starts only when selected

        self._plan(plan)
        if phase not in {"candidate", "fixed_control"} or not _REF.fullmatch(deployment_ref):
            raise ValueError("invalid_control_phase_or_deployment")
        if len(self._observations) >= self.max_observations:
            raise ValueError("reproducer_observation_capacity_exhausted")
        lease = self.governor.acquire("worker", estimated_bytes=1024 * 1024)
        started = time.monotonic()
        status, value, data = None, None, bytearray()
        execution, coverage, error = "succeeded", "completed", None
        try:
            self.request_admission(1)
            timeout = float(plan.timeout_seconds)
            if self.policy.deadline:
                timeout = min(timeout, self.policy.deadline - time.time())
                if timeout <= 0:
                    raise PolicyDenied("campaign_deadline_exceeded")  # noqa: TRY301
            async with asyncio.timeout(timeout):
                async with (
                    httpx.AsyncClient(
                        trust_env=False, follow_redirects=False, timeout=timeout
                    ) as client,
                    client.stream(
                        "GET",
                        plan.request.url,
                        headers={"User-Agent": "RedJohn-local-regression/1"},
                    ) as response,
                ):
                    status = response.status_code
                    value = response.headers.get(plan.assertion.header_name)
                    if value is not None and len(value.encode()) > 1024:
                        value = None
                        raise ValueError("reproducer_header_limit")  # noqa: TRY301
                    async for chunk in response.aiter_bytes(chunk_size=4096):
                        if len(data) + len(chunk) > plan.body_max_bytes:
                            raise ValueError("reproducer_body_limit")  # noqa: TRY301
                        data.extend(chunk)
                    if status in {401, 403, 429, 503} or 300 <= status < 400:
                        execution, coverage = "failed", "blocked"
                        error = error_record(
                            "reproducer_response_blocked", coverage_effect="blocked"
                        )
                    elif status != 200:
                        execution, coverage = "failed", "inconclusive"
                        error = error_record("reproducer_response_unexpected")
        except (TimeoutError, httpx.TimeoutException):
            execution, coverage = "timed_out", "partial"
            error = error_record("scanner_timeout", coverage_effect="partial")
        except PolicyDenied:
            execution, coverage = "failed", "blocked"
            error = error_record("policy_denied", coverage_effect="blocked")
        except (httpx.HTTPError, ValueError):
            execution, coverage = "failed", "inconclusive"
            error = error_record("reproducer_response_incomplete")
        finally:
            lease.release()
        payload: dict[str, Any] = {
            "plan_ref": plan.plan_ref,
            "phase": phase,
            "deployment_ref": deployment_ref,
            "status": status,
            "header_name": plan.assertion.header_name,
            "header_value": value,
            "body_sha256": hashlib.sha256(data).hexdigest(),
            "body_bytes": len(data),
            "execution_status": execution,
            "coverage_status": coverage,
            "actor_id": plan.request.actor_ref,
            "asset_ref": plan.request.asset_ref,
            "fixture_ref": plan.request.fixture_ref,
            "error": error,
        }
        # A storage exception propagates, and no validatable observation is owned.
        evidence_ref = self.evidence_sink(payload)
        if not isinstance(evidence_ref, str) or not _REF.fullmatch(evidence_ref):
            raise ValueError("evidence_write_failed")
        observation = ReproducerObservation(
            uuid.uuid4().hex,
            plan.plan_ref,
            phase,
            deployment_ref,
            status,
            value,
            payload["body_sha256"],
            len(data),
            execution,
            coverage,
            evidence_ref,
            time.monotonic() - started,
            time.time(),
            error,
        )
        self._observations[observation.observation_ref] = observation
        return observation

    def validate_pair(
        self, plan: ReproducerPlan, before_ref: str, control_ref: str
    ) -> dict[str, Any]:
        self._plan(plan)
        before, control = self._observations.get(before_ref), self._observations.get(control_ref)
        if (
            before is None
            or control is None
            or before.plan_ref != plan.plan_ref
            or control.plan_ref != plan.plan_ref
            or before.phase != "candidate"
            or control.phase != "fixed_control"
            or before.deployment_ref == control.deployment_ref
            or control.observed_at < before.observed_at
        ):
            raise ValueError("independent_owned_fixed_control_required")
        complete = before.coverage_status == control.coverage_status == "completed"
        fixed = control.header_value == plan.assertion.expected_fixed_value
        observed = (
            before.header_value == "initial"
            if plan.request.kind == "harmless_marker"
            else before.header_value != plan.assertion.expected_fixed_value
        )
        validated = complete and observed and fixed
        finding_status = (
            "confirmed_weakness" if validated and plan.request.kind == "header" else "candidate"
        )
        return {
            "plan_ref": plan.plan_ref,
            "finding_status": finding_status,
            "execution_status": "succeeded" if complete else "failed",
            "coverage_status": "completed" if validated else "inconclusive",
            "proof_level": plan.assertion.proof_level,
            "expected": plan.assertion.expected_fixed_value,
            "observed": before.header_value,
            "control_observed": control.header_value,
            "control_status": "fixed" if validated else "not_validated",
            "actor_id": plan.request.actor_ref,
            "asset_ref": plan.request.asset_ref,
            "fixture_ref": plan.request.fixture_ref,
            "evidence_refs": [
                *plan.request.evidence_refs,
                before.evidence_ref,
                control.evidence_ref,
            ],
            "original_rce_status": _ORIGINAL_RCE,
            "limitation": (
                "Local header validation or harmless routing fixture; no RCE or CVE impact proof"
            ),
        }

    def regression_source(self, plan: ReproducerPlan) -> str:
        """Export fixed constant unittest source; no generated code is executed."""
        self._plan(plan)
        url, header, expected = map(
            json.dumps,
            (plan.request.url, plan.assertion.header_name, plan.assertion.expected_fixed_value),
        )
        return f'''"""RedJohn static local header regression; does not test RCE."""
import http.client
import ipaddress
import unittest
from urllib.parse import urlsplit

URL = {url}
EXPECTED_URL = {url}

class RedJohnLocalRegression(unittest.TestCase):
    def test_fixed_header(self):
        self.assertEqual(URL, EXPECTED_URL)
        parsed = urlsplit(URL)
        self.assertTrue(ipaddress.ip_address(parsed.hostname).is_loopback)
        self.assertIsNone(parsed.username)
        client_type = (http.client.HTTPSConnection if parsed.scheme == "https"
                       else http.client.HTTPConnection)
        client = client_type(parsed.hostname, parsed.port, timeout=5)
        try:
            path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
            client.request("GET", path)
            response = client.getresponse()
            self.assertEqual(response.status, 200)  # redirects are never followed
            self.assertEqual(response.getheader({header}), {expected})
            self.assertLessEqual(len(response.read(65537)), 65536)
        finally:
            client.close()

if __name__ == "__main__":
    unittest.main()
'''


AIExploitGenerator = SafeReproducerGenerator
