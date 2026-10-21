"""Bounded, escaped reports with three independent result dimensions."""

from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING, Any

from redjohn.assessment.control import public_view
from redjohn.assessment.registry import CapabilityRegistry


if TYPE_CHECKING:
    from pathlib import Path

    from redjohn.assessment.lab_validation import LabValidation
    from redjohn.assessment.store import AssessmentStore


def build_report(
    store: AssessmentStore,
    engagement: str,
    *,
    metrics: dict[str, Any] | None = None,
    registry: CapabilityRegistry | None = None,
    lab_validation: LabValidation | None = None,
) -> dict[str, Any]:
    from redjohn.assessment.lab_configuration import owned_lab_status  # noqa: PLC0415

    if lab_validation is not None:
        from redjohn.assessment.lab_validation import LabValidation  # noqa: PLC0415

        if type(lab_validation) is not LabValidation:
            raise TypeError("report_typed_owned_lab_validation_required")
        if lab_validation.store is not store or lab_validation.policy.engagement_id != engagement:
            raise ValueError("report_exact_owned_lab_store_required")
    jobs_page = store.jobs(engagement, limit=100)
    findings_page = store.findings(engagement, limit=100)
    job_metadata = store.job_page_metadata(engagement)
    findings_total = store.findings_total(engagement)
    return public_view(
        {
            "product": "RedJohn",
            "schema_version": 1,
            "engagement_id": engagement,
            "coverage": store.coverage(engagement),
            "findings_page": findings_page,
            "jobs_page": jobs_page,
            "pagination": {
                "page_limit": 100,
                "jobs_total": job_metadata["jobs_total"],
                "jobs_more": job_metadata["jobs_total"] > len(jobs_page),
                "active_jobs": job_metadata["active_jobs"],
                "findings_total": findings_total,
                "findings_more": findings_total > len(findings_page),
                "more_data": "use_control_api_keyset_pagination",
            },
            "capabilities": (registry or CapabilityRegistry()).health(),
            "metrics": metrics or {},
            "retention": store.retention_status(),
            "rce_regression": "not_reproduced_missing_fixture",
            "owned_lab": owned_lab_status(lab_validation),
            "limitations": [
                "Header observations and Nuclei matches remain candidate findings",
                "Browser metadata alone is not proxy-confirmed POST capture",
                "Missing capabilities never imply a negative vulnerability test",
                "Remote browser/scanner egress requires actual Linux namespace attestation",
                "Authenticated replay requires current captured requests and reviewed templates",
                "Network/cloud specialist adapters remain unavailable where not implemented",
            ],
        }
    )


def write_report(path: Path, report: dict[str, Any]) -> tuple[Path, Path]:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False)
    json_path, html_path = path / "assessment-report.json", path / "assessment-report.html"
    json_path.write_text(encoded + "\n")
    html_path.write_text(
        "<!doctype html><html lang='hu'><meta charset='utf-8'>"
        "<title>RedJohn assessment</title><h1>RedJohn</h1><pre>"
        + html.escape(encoded)
        + "</pre></html>"
    )
    for file in (json_path, html_path):
        file.chmod(0o600)
    return json_path, html_path
