"""Durable Chromium confirmation of a bounded Dalfox candidate."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from redjohn.assessment.browser import BrowserUnavailableError
from redjohn.assessment.models import (
    AdapterResult,
    CoverageStatus,
    JobSpec,
    Surface,
    error_record,
    stable_key,
)
from redjohn.assessment.specialists import captured_request, replace_query_value


if TYPE_CHECKING:
    from redjohn.assessment.browser import BrowserDiscoveryService
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


class BrowserXSSConfirmationAdapter:
    resource_class = "browser"

    def __init__(
        self, browser: BrowserDiscoveryService, policy: EngagementPolicy, store: AssessmentStore
    ) -> None:
        self.browser, self.policy, self.store = browser, policy, store
        self.partial_evidence_refs: tuple[str, ...] = ()

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:
        self.partial_evidence_refs = ()
        try:
            if (
                set(spec.options) != {"candidate_ref"}
                or surface.actor_id != "anonymous"
                or surface.method != "GET"
            ):
                raise ValueError("unsupported_confirmation_input")  # noqa: TRY301 - schema gate
            captured_request(self.store, self.policy, surface)
            ref = spec.options["candidate_ref"]
            plan = json.loads(self.store.evidence_get(self.policy.engagement_id, ref)["excerpt"])
            with self.store.transaction() as db:
                row = db.execute(
                    "SELECT f.*,j.execution_status,j.spec FROM rj_specialist_followup f "
                    "JOIN rj_job j ON f.parent_job=j.id WHERE f.engagement=? AND f.candidate_ref=?",
                    (self.policy.engagement_id, ref),
                ).fetchone()
            if (
                row is None
                or row["execution_status"] != "succeeded"
                or row["surface_id"] != spec.surface_id
            ):
                raise ValueError("confirmation_parent_not_committed")  # noqa: TRY301 - committed parent gate
            parent = JobSpec(**json.loads(row["spec"]))
            nonce = "redjohn-" + parent.key[:16]
            proof = replace_query_value(
                surface.url, surface.input_name, '<svg/onload=alert("' + nonce + '")>'
            )
            if (
                plan.get("tool") != "dalfox"
                or plan.get("nonce") != nonce
                or plan.get("url") != proof
                or plan.get("request_ref") != surface.request_ref
            ):
                raise ValueError("invalid_confirmation_plan")  # noqa: TRY301 - evidence gate
            self.partial_evidence_refs = (ref,)
            result = await self.browser.confirm_dialog(surface.url, proof, nonce)
            evidence = self.store.evidence_put(
                self.policy.engagement_id,
                {
                    **result,
                    "candidate_ref": ref,
                    "surface_id": spec.surface_id,
                    "model_calls": 0,
                    "validation": "target_delivered_javascript_nonce_alert_with_benign_control",
                },
                job_id=job["id"],
                kind="browser_xss_confirmation",
            )
            self.partial_evidence_refs += (evidence,)
            confirmed = result["confirmed"] and not result["upstream_tls_failures"]
            findings = (
                (
                    {
                        "id": stable_key([parent.key, "dalfox"]),
                        "finding_status": "confirmed_weakness",
                        "family": "xss",
                        "cwe": "CWE-79",
                        "surface_id": spec.surface_id,
                        "evidence_refs": [plan["scanner_evidence"], ref, evidence],
                        "validation": "chromium_nonce_alert_and_control",
                    },
                )
                if confirmed
                else ()
            )
            return AdapterResult(
                "succeeded",
                "completed" if not result["blocked_requests"] else "partial",
                {
                    **result,
                    "outcome": "confirmed_weakness" if confirmed else "not_confirmed",
                    "evidence_refs": list(self.partial_evidence_refs),
                    "model_calls": 0,
                },
                findings,
            )
        except BrowserUnavailableError:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(
                    "browser_confirmation_unavailable",
                    category="capability",
                    coverage_effect="blocked",
                ),
            )
        except ValueError:
            coverage: CoverageStatus = (
                "inconclusive" if self.partial_evidence_refs else "unsupported"
            )
            return AdapterResult(
                "failed",
                coverage,
                error=error_record(
                    "invalid_or_unsupported_xss_confirmation", coverage_effect=coverage
                ),
            )

    async def close_idle(self) -> None:
        await self.browser.close()

    async def cleanup(self) -> None:
        await self.browser.close()

    async def cancel(self) -> None:
        await self.browser.close()

    def healthcheck(self) -> dict[str, Any]:
        return self.browser.healthcheck()
