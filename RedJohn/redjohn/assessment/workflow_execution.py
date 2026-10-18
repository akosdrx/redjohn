"""Execute one reviewed workflow step, using private captured replay only.

No script, URL, body, credential, assertion code or shell command is accepted in
job options. The host registers a declarative definition and private capture;
this adapter resolves those exact records after a fenced scheduler admission.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.inventory import InventoryConflictError
from redjohn.assessment.models import AdapterResult, JobSpec, Surface, error_record, stable_key
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied, origin_for
from redjohn.assessment.request_body import HOST_REPLAY_BODY_MARKER
from redjohn.assessment.workflow_models import WorkflowDefinition, bounded_name


if TYPE_CHECKING:
    from redjohn.assessment.persistent_rate_limit import PersistentRateLimitDetector
    from redjohn.assessment.store import AssessmentStore
    from redjohn.assessment.workflow_models import WorkflowStep


@dataclass(frozen=True)
class WorkflowExecutionConfig:
    enabled: bool
    timeout_seconds: float = 10
    max_response_bytes: int = 256 * 1024
    definitions: tuple[WorkflowDefinition, ...] = ()

    def __post_init__(self) -> None:
        if (
            self.enabled is not True
            or isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 1 <= self.timeout_seconds <= 30
            or type(self.max_response_bytes) is not int
            or not 1024 <= self.max_response_bytes <= 1024 * 1024
            or not isinstance(self.definitions, tuple)
            or len(self.definitions) > 16
            or any(
                not isinstance(definition, WorkflowDefinition) for definition in self.definitions
            )
        ):
            raise ValueError("invalid_workflow_execution_config")

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> WorkflowExecutionConfig:
        if not isinstance(value, dict) or set(value) - set(cls.__dataclass_fields__):
            raise ValueError("invalid_workflow_execution_config_fields")
        converted = dict(value)
        if "definitions" in converted:
            if (
                not isinstance(converted["definitions"], list)
                or len(json.dumps(value).encode()) > 256 * 1024
            ):
                raise ValueError("invalid_workflow_definition_config_budget")
            converted["definitions"] = tuple(
                WorkflowDefinition.from_mapping(item) for item in converted["definitions"]
            )
        return cls(**converted)


def reviewed_step(
    store: AssessmentStore,
    policy: EngagementPolicy,
    instance_id: str,
    step_name: str,
    surface_id: str,
    expected_revision: int,
) -> WorkflowStep:
    """Read bounded host records without claiming a lease or granting permission."""
    for identity in (instance_id, step_name, surface_id):
        bounded_name(identity)
    if type(expected_revision) is not int or expected_revision < 1:
        raise ValueError("invalid_workflow_revision")
    with store._lock:
        inventory = store.inventory
        inventory._fence(store.db, policy)
        instance = inventory._instance(store.db, policy, instance_id)
        inventory._session(store.db, policy, instance)
        if instance["revision"] != expected_revision or instance["status"] != "active":
            raise InventoryConflictError("stale_or_terminal_workflow")
        step = inventory._definition(store.db, policy, instance["definition_id"]).step(step_name)
        step.authorize(policy)
        surface = store.surface(policy.engagement_id, surface_id)
        inventory.require_surface_active(store.db, policy, surface_id)
        if (
            step.from_state != instance["state"]
            or (
                surface.url,
                surface.method,
                surface.actor_id,
                surface.tenant_id,
                surface.session_revision,
            )
            != (
                step.url,
                step.method,
                instance["actor"],
                instance["tenant"],
                instance["session_revision"],
            )
            or surface.source != "observed"
            or surface.actor_id == "anonymous"
        ):
            raise PolicyDenied("workflow_execution_requires_exact_named_capture")
        return step


class WorkflowExecutionAdapter:
    resource_class = "worker"
    owner_process_only = True

    def __init__(
        self,
        config: WorkflowExecutionConfig,
        policy: EngagementPolicy,
        store: AssessmentStore,
        rate_limits: PersistentRateLimitDetector | None = None,
        *,
        tls_config: BrowserTLSConfig | None = None,
        auth_vault_file: Path,
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        self.rate_limits, self.tls_config = rate_limits, tls_config or BrowserTLSConfig()
        self.auth_vault_file = Path(auth_vault_file)
        # Construction validates private-file protection, not only existence.
        AuthReplayVault.from_file(self.auth_vault_file, policy)
        for definition in config.definitions:
            store.inventory.register_workflow(policy, definition)
        self._proxies: set[BrowserEgressProxy] = set()

    def _job_fence(self, job: dict[str, Any], spec: JobSpec) -> None:
        with self.store._lock:
            self.store.inventory._fence(self.store.db, self.policy)
            current = self.store.db.execute(
                "SELECT spec FROM rj_job WHERE id=? AND engagement=? AND owner=? "
                "AND attempt=? AND execution_status='running' AND cancel_requested=0 "
                "AND lease_until>? AND capability='workflow_execute'",
                (job["id"], self.policy.engagement_id, job["owner"], job["attempt"], time.time()),
            ).fetchone()
            if current is None or JobSpec(**json.loads(current[0])).key != spec.key:
                raise PolicyDenied("workflow_scheduler_lease_not_current")
            self.store.assert_session_revision(
                self.policy, self.store.surface(self.policy.engagement_id, spec.surface_id)
            )
            self.store.inventory.require_surface_active(self.store.db, self.policy, spec.surface_id)

    @staticmethod
    def _result(code: str, *, admitted: bool, evidence_ref: str = "") -> AdapterResult:
        return AdapterResult(
            "failed",
            "inconclusive" if admitted else "blocked",
            summary={
                "request_admitted": admitted,
                "outcome_ref": evidence_ref,
                "automatic_replay": False,
            },
            error=error_record(
                code,
                category="workflow",
                coverage_effect="inconclusive" if admitted else "blocked",
                recovery_action="reconcile_workflow_outcome"
                if admitted
                else "review_workflow_state",
            ),
        )

    async def run(  # noqa: PLR0912, PLR0915 - one bounded admitted request lifecycle
        self,
        job: dict[str, Any],
        surface: Surface,
        spec: JobSpec,
    ) -> AdapterResult:
        import httpx  # noqa: PLC0415 - explicit opt-in host adapter

        if (
            spec.capability != "workflow_execute"
            or spec.idempotent
            or set(spec.options) != {"instance_id", "step_name", "expected_revision"}
            or not all(isinstance(spec.options[name], str) for name in ("instance_id", "step_name"))
            or type(spec.options["expected_revision"]) is not int
        ):
            return self._result("workflow_execution_invalid_job", admitted=False)
        instance_id, step_name = spec.options["instance_id"], spec.options["step_name"]
        owner = stable_key([self.policy.owner_id, self.policy.engagement_id])
        lease = None
        admitted = False
        proxy = None
        framed = False
        outcome_ref = ""
        try:
            self._job_fence(job, spec)
            step = reviewed_step(
                self.store,
                self.policy,
                instance_id,
                step_name,
                spec.surface_id,
                spec.options["expected_revision"],
            )
            stored = self.store.surface(self.policy.engagement_id, spec.surface_id)
            if stored.key != surface.key:
                raise PolicyDenied("workflow_surface_changed")
            binding = AuthReplayVault.from_file(self.auth_vault_file, self.policy).authorize(
                surface
            )
            binding.validate(surface.url, surface.method, self.policy)
            if surface.method == "POST":
                binding.validate_capture(surface.content_type, surface.body_sha256)
                binding.body_for_mutation()
            timeout = min(self.config.timeout_seconds, spec.timeout_seconds)
            if self.policy.deadline:
                timeout = min(timeout, self.policy.deadline - time.time())
            if timeout <= 0:
                raise PolicyDenied("workflow_deadline_exceeded")
            lease = self.store.inventory.claim_step(
                self.policy,
                instance_id,
                step_name,
                spec.surface_id,
                expected_revision=spec.options["expected_revision"],
                owner=owner,
                seconds=min(600, timeout + 10),
            )

            def admit(url: str) -> None:
                nonlocal admitted
                self._job_fence(job, spec)
                if (
                    self.policy._request_url(url) != self.policy._request_url(surface.url)
                    or admitted
                ):
                    raise PolicyDenied("workflow_exactly_one_request_required")
                if self.rate_limits is not None and not self.rate_limits.admit(origin_for(url)):
                    raise PolicyDenied("workflow_rate_limited")
                self.store.consume_requests(self.policy)
                assert lease is not None
                self.store.inventory.mark_sent(
                    self.policy, instance_id, lease["lease_ref"], owner=owner
                )
                admitted = True

            def complete(url: str, method: str, _status: int, _headers: dict[str, str]) -> None:
                nonlocal framed
                framed = (self.policy._request_url(url), method) == (
                    self.policy._request_url(surface.url),
                    surface.method,
                )

            def observe(url: str, status: int, headers: dict[str, str]) -> None:
                if self.rate_limits is not None:
                    self.rate_limits.observe(origin_for(url), status, headers)

            proxy = BrowserEgressProxy(
                self.policy,
                max_connections=2,
                timeout_seconds=timeout,
                max_wire_bytes=min(8 * 1024 * 1024, self.config.max_response_bytes + 128 * 1024),
                tls_config=self.tls_config,
                request_admission=admit,
                request_policy=lambda url, method: binding.validate(url, method, self.policy),
                request_replay=binding.rewrite_request,
                on_response=observe,
                on_complete=complete,
            )
            self._proxies.add(proxy)
            await proxy.start()
            headers = {"Accept-Encoding": "identity"}
            body = b""
            if surface.method == "POST":
                headers["Content-Type"] = binding.content_type
                body = HOST_REPLAY_BODY_MARKER.encode("ascii")
            digest = hashlib.sha256()
            size = 0
            async with asyncio.timeout(timeout):
                async with (
                    httpx.AsyncClient(
                        proxy=proxy.url,
                        verify=proxy.client_tls_context,
                        trust_env=False,
                        follow_redirects=False,
                        timeout=timeout,
                    ) as client,
                    client.stream(
                        surface.method, surface.url, headers=headers, content=body
                    ) as response,
                ):
                    if response.headers.get("content-encoding", "identity") != "identity":
                        raise ValueError("workflow_encoded_response_denied")  # noqa: TRY301 - single lifecycle
                    async for chunk in response.aiter_raw(chunk_size=4096):
                        size += len(chunk)
                        if size > self.config.max_response_bytes:
                            raise ValueError("workflow_response_budget_exceeded")  # noqa: TRY301 - single lifecycle
                        digest.update(chunk)
            self._job_fence(job, spec)
            if not admitted or not framed or proxy.upstream_tls_failures:
                return self._result("workflow_response_not_proven_complete", admitted=admitted)
            valid = response.status_code in step.expected_statuses and (
                not step.response_sha256 or digest.hexdigest() == step.response_sha256
            )
            outcome_ref = self.store.inventory.record_http_outcome(
                self.policy,
                instance_id,
                lease["lease_ref"],
                owner=owner,
                status=response.status_code,
                response_sha256=digest.hexdigest(),
                assertion_passed=valid,
            )
            if not valid:
                return self._result(
                    "workflow_response_assertion_failed", admitted=True, evidence_ref=outcome_ref
                )
            state = self.store.inventory.complete_step(
                self.policy,
                instance_id,
                lease["lease_ref"],
                outcome_ref,
                owner=owner,
            )
            return AdapterResult(
                "succeeded",
                "completed",
                summary={
                    "instance_id": instance_id,
                    "step": step_name,
                    "state": state["state"],
                    "workflow_revision": state["revision"],
                    "outcome_ref": outcome_ref,
                    "request_admitted": True,
                    "requests": proxy.forwarded_requests,
                    "response_bytes": size,
                    "automatic_replay": False,
                },
            )
        except asyncio.CancelledError:
            raise
        except (ValueError, RuntimeError, OSError, httpx.HTTPError):
            return self._result(
                "workflow_execution_blocked_or_uncertain",
                admitted=admitted,
                evidence_ref=outcome_ref,
            )
        finally:
            if proxy is not None:
                await proxy.close()
                self._proxies.discard(proxy)
            if lease is not None and not admitted:
                with contextlib.suppress(PolicyDenied, InventoryConflictError):
                    self.store.inventory.release_prepared_step(
                        self.policy, instance_id, lease["lease_ref"], owner=owner
                    )

    async def cancel(self) -> None:
        await self.cleanup()

    async def cleanup(self) -> None:
        for proxy in tuple(self._proxies):
            await proxy.close()
            self._proxies.discard(proxy)
