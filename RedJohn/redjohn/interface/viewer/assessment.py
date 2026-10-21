"""Read-only projection of bounded assessment reports into the existing viewer.

Candidate matches never enter the legacy confirmed-vulnerability collection.
No private SQLite state, credential vault or raw evidence is read by this view.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path


REPORT_LIMIT = 1024 * 1024


def assessment_summary(run_dir: Path) -> dict[str, Any] | None:
    path = run_dir / "assessment-report.json"
    if not path.is_file():
        return None
    summary: dict[str, Any] = {
        "run_name": run_dir.name,
        "run_id": run_dir.name,
        "scan_mode": "bounded assessment",
        "non_interactive": True,
        "scope_mode": "explicit engagement policy",
        "status": "failed",
        "finished": False,
        "assessment": {"read_only": True, "error": "assessment_report_unavailable"},
    }
    try:
        if path.is_symlink():
            raise ValueError("assessment_report_symlink_denied")  # noqa: TRY301 - bounded file boundary
        with path.open("rb") as handle:
            raw = handle.read(REPORT_LIMIT + 1)
        if len(raw) > REPORT_LIMIT:
            raise ValueError("assessment_report_too_large")  # noqa: TRY301 - bounded file boundary
        report = json.loads(raw)
        if (
            not isinstance(report, dict)
            or report.get("product") != "RedJohn"
            or report.get("schema_version") != 1
        ):
            raise ValueError("assessment_report_schema_error")  # noqa: TRY301 - normalized projection failure
        collections = {
            name: report.get(name)
            for name in ("jobs_page", "findings_page", "coverage", "capabilities")
        }
        if any(
            not isinstance(items, list)
            or len(items) > 100
            or any(not isinstance(item, dict) for item in items)
            for items in collections.values()
        ):
            raise ValueError("assessment_report_schema_error")  # noqa: TRY301 - normalized projection failure
        jobs, findings = collections["jobs_page"], collections["findings_page"]
        assert isinstance(jobs, list) and isinstance(findings, list)
        capabilities = collections["capabilities"]
        assert isinstance(capabilities, list)
        pagination = report.get("pagination")
        if not isinstance(pagination, dict):
            pagination = {}
        jobs_more = pagination.get("jobs_more")
        active_jobs = pagination.get("active_jobs")
        if type(jobs_more) is not bool or type(active_jobs) is not int or active_jobs < 0:
            # Older/foreign reports cannot prove whole-campaign completion.
            jobs_more, active_jobs = True, 1
        terminal = {"succeeded", "failed", "cancelled", "timed_out", "resource_exhausted"}
        finished = (
            bool(jobs)
            and not jobs_more
            and active_jobs == 0
            and all(job.get("execution_status") in terminal for job in jobs)
        )
        # This is a bounded report snapshot, not a live SQLite query. A full
        # page with more rows (or an unknown pagination state) stays running.
        status = "stopped" if finished else "running"
        stamp = datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()
        summary.update(status=status, finished=finished, end_time=stamp if finished else None)
        summary["assessment"] = {
            "read_only": True,
            "snapshot": True,
            "error": None,
            "engagement_id": str(report.get("engagement_id", ""))[:128],
            "candidate_count": sum(item.get("status") == "candidate" for item in findings),
            "coverage": collections["coverage"],
            "capability_gaps": [
                {"id": item.get("id"), "status": item.get("status"), "reason": item.get("reason")}
                for item in capabilities
                if item.get("status")
                not in {"implemented_fixture_tested", "implemented_and_live_tested"}
            ],
            "rce_regression": report.get("rce_regression"),
            "page_limit": 100,
            "jobs_total": pagination.get("jobs_total"),
            "jobs_more": jobs_more,
            "active_jobs": active_jobs,
            "findings_total": pagination.get("findings_total"),
            "findings_more": pagination.get("findings_more"),
            "completion_claim": "complete" if finished else "visible_report_page_only",
        }
    except (OSError, ValueError, TypeError, KeyError):
        # Never turn an unreadable/oversized/malformed report into a clean scan.
        pass
    return summary
