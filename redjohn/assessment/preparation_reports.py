"""Bounded imported report summaries; never live findings or target attestation."""

from __future__ import annotations

from typing import Any

from redjohn.assessment.preparation_tools import VERSIONS, bounded_document


def _summary(rows: list[tuple[str, str]], expected: list[str]) -> dict[str, Any]:
    if not rows or len(rows) > 256:
        raise ValueError("preparation_report_record_limit")
    counts = dict.fromkeys(("PASS", "FAIL", "MANUAL", "INFO"), 0)
    public = []
    for check, status in rows:
        if check not in expected or status not in counts:
            raise ValueError("preparation_unreviewed_check_or_status")
        counts[status] += 1
        public.append({"check_id": check, "status": status})
    return {
        "source": "imported_unverified_report",
        "live_audit_verified": False,
        "target_identity_attested": False,
        "audit_coverage_status": "blocked",
        "records": len(rows),
        "status_counts": counts,
        "all_requested_checks_present": set(expected) == {check for check, _status in rows},
        "check_results": public,
    }


def summarize_prowler_ocsf(raw: bytes, manifest: dict[str, Any]) -> dict[str, Any]:
    """Read only reviewed status/identity fields; discard all resource data/text."""
    document = bounded_document(raw)
    if (
        manifest.get("tool") != "prowler"
        or not isinstance(document, list)
        or not 1 <= len(document) <= 256
    ):
        raise ValueError("unsupported_prowler_ocsf_report")
    rows = []
    for record in document:
        if not isinstance(record, dict):
            raise TypeError("invalid_prowler_record")
        metadata, cloud = record.get("metadata"), record.get("cloud")
        if not isinstance(metadata, dict) or not isinstance(cloud, dict):
            raise TypeError("prowler_identity_or_version_missing")
        product, account = metadata.get("product"), cloud.get("account")
        if (
            not isinstance(product, dict)
            or not isinstance(account, dict)
            or product.get("uid") != "prowler"
            or product.get("version") != VERSIONS["prowler"]
            or cloud.get("provider") != manifest["provider"]
            or account.get("uid") != manifest["account_id"]
        ):
            raise ValueError("prowler_claimed_identity_or_version_mismatch")
        check, status = metadata.get("event_code"), record.get("status_code")
        if not isinstance(check, str) or not isinstance(status, str):
            raise TypeError("prowler_check_or_status_missing")
        rows.append((check, status))
    return _summary(rows, manifest["checks"])


def summarize_kube_bench(raw: bytes, manifest: dict[str, Any]) -> dict[str, Any]:
    """kube-bench JSON does not attest cluster/node identity; keep that unknown."""
    document = bounded_document(raw)
    if (
        manifest.get("tool") != "kube-bench"
        or not isinstance(document, list)
        or not 1 <= len(document) <= 16
    ):
        raise ValueError("unsupported_kube_bench_json_report")
    rows = []
    for control in document:
        if (
            not isinstance(control, dict)
            or control.get("version") != manifest["benchmark"]
            or not isinstance(control.get("tests"), list)
            or len(control["tests"]) > 64
        ):
            raise ValueError("kube_bench_control_version_or_shape_mismatch")
        actual = dict.fromkeys(("PASS", "FAIL", "WARN", "INFO"), 0)
        for group in control["tests"]:
            if (
                not isinstance(group, dict)
                or not isinstance(group.get("results"), list)
                or len(group["results"]) > 256
            ):
                raise ValueError("kube_bench_group_limit")
            for result in group["results"]:
                if (
                    not isinstance(result, dict)
                    or not isinstance(result.get("test_number"), str)
                    or result.get("status") not in actual
                ):
                    raise ValueError("kube_bench_check_or_status_invalid")
                status = result["status"]
                actual[status] += 1
                rows.append((result["test_number"], "MANUAL" if status == "WARN" else status))
                if len(rows) > 256:
                    raise ValueError("preparation_report_record_limit")
        if any(
            type(control.get("total_" + status.lower())) is not int
            or control["total_" + status.lower()] != count
            for status, count in actual.items()
        ):
            raise ValueError("kube_bench_totals_do_not_match_records")
    return _summary(rows, manifest["checks"])
