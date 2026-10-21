"""Reporting tools — file vuln findings (with dedup + CVSS) and read them back.

``create_vulnerability_report`` / ``create_dependency_report`` file findings;
``list_reports`` / ``get_report`` let any agent (notably the root orchestrator)
review what's been filed so far across the whole scan.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from redjohn.tools.nullish import clean_optional
from redjohn.tools.proxy.tools import existing_request_ids


if TYPE_CHECKING:
    from redjohn.report.state import ReportState


logger = logging.getLogger(__name__)

_CREATE_LOCK = asyncio.Lock()


_CVSS_VALID = {
    "attack_vector": ["N", "A", "L", "P"],
    "attack_complexity": ["L", "H"],
    "privileges_required": ["N", "L", "H"],
    "user_interaction": ["N", "R"],
    "scope": ["U", "C"],
    "confidentiality": ["N", "L", "H"],
    "integrity": ["N", "L", "H"],
    "availability": ["N", "L", "H"],
}


_CODE_LOCATION_FIELDS = (
    "file",
    "start_line",
    "end_line",
    "snippet",
    "label",
    "fix_before",
    "fix_after",
)


def _validate_file_path(path: str) -> str | None:
    if not path or not path.strip():
        return "file path cannot be empty"
    p = PurePosixPath(path)
    if p.is_absolute():
        return f"file path must be relative, got absolute: '{path}'"
    if ".." in p.parts:
        return f"file path must not contain '..': '{path}'"
    return None


def _normalize_code_locations(
    raw: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if not raw:
        return None
    cleaned: list[dict[str, Any]] = []
    for loc in raw:
        normalized: dict[str, Any] = {}
        for field in _CODE_LOCATION_FIELDS:
            if field not in loc or loc[field] is None:
                continue
            value = loc[field]
            if field in ("start_line", "end_line"):
                try:
                    normalized[field] = int(value)
                except (TypeError, ValueError):
                    continue
            else:
                text = (
                    str(value).strip("\n")
                    if field in ("snippet", "fix_before", "fix_after")
                    else str(value).strip()
                )
                if text:
                    normalized[field] = text
        if normalized.get("file") and normalized.get("start_line") is not None:
            cleaned.append(normalized)
    return cleaned or None


def _validate_code_locations(locations: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for i, loc in enumerate(locations):
        path_err = _validate_file_path(loc.get("file", ""))
        if path_err:
            errors.append(f"code_locations[{i}]: {path_err}")
        start = loc.get("start_line")
        if not isinstance(start, int) or start < 1:
            errors.append(f"code_locations[{i}]: start_line must be a positive integer")
        end = loc.get("end_line")
        if end is None:
            errors.append(f"code_locations[{i}]: end_line is required")
        elif not isinstance(end, int) or end < 1:
            errors.append(f"code_locations[{i}]: end_line must be a positive integer")
        elif isinstance(start, int) and end < start:
            errors.append(f"code_locations[{i}]: end_line ({end}) must be >= start_line ({start})")
    return errors


def _extract_cve(cve: str) -> str:
    match = re.search(r"CVE-\d{4}-\d{4,}", cve)
    return match.group(0) if match else cve.strip()


def _validate_cve(cve: str) -> str | None:
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
        return f"invalid CVE format: '{cve}' (expected 'CVE-YYYY-NNNNN')"
    return None


def _extract_cwe(cwe: str) -> str:
    match = re.search(r"CWE-\d+", cwe)
    return match.group(0) if match else cwe.strip()


def _validate_cwe(cwe: str) -> str | None:
    if not re.match(r"^CWE-\d+$", cwe):
        return f"invalid CWE format: '{cwe}' (expected 'CWE-NNN')"
    return None


def _calculate_cvss(breakdown: dict[str, str]) -> tuple[float, str, str]:
    from cvss import CVSS3

    vector = (
        f"CVSS:3.1/AV:{breakdown['attack_vector']}/AC:{breakdown['attack_complexity']}/"
        f"PR:{breakdown['privileges_required']}/UI:{breakdown['user_interaction']}/"
        f"S:{breakdown['scope']}/C:{breakdown['confidentiality']}/"
        f"I:{breakdown['integrity']}/A:{breakdown['availability']}"
    )

    try:
        cvss = CVSS3(vector)
        score = cvss.scores()[0]
        base_severity = cvss.severities()[0].lower()
    except Exception as exc:
        msg = f"Failed to calculate CVSS for validated vector: {vector}"
        raise ValueError(msg) from exc

    severity = "info" if base_severity == "none" else base_severity
    return score, severity, vector


_REQUIRED_FIELDS = {
    "title": "Title cannot be empty",
    "description": "Description cannot be empty",
    "impact": "Impact cannot be empty",
    "target": "Target cannot be empty",
    "technical_analysis": "Technical analysis cannot be empty",
    "poc_description": "PoC description cannot be empty",
    "poc_script_code": "PoC script/code is REQUIRED - provide the actual exploit/payload",
    "remediation_steps": "Remediation steps cannot be empty",
    "evidence": "Evidence cannot be empty - provide concrete proof of the finding",
    "assumptions": "Assumptions cannot be empty - state exploitability prerequisites",
}

_VALID_FIX_EFFORT = frozenset({"trivial", "low", "medium", "high"})
_VALID_CONFIDENCE = frozenset({"high", "medium", "low"})
_MAX_HTTP_EXCHANGE_IDS = 10
_MAX_HTTP_EXCHANGE_ID_CHARS = 128


def _validate_required_text(fields: dict[str, str]) -> list[str]:
    """Report every ``_REQUIRED_FIELDS`` entry that arrived blank."""
    return [
        msg for name, msg in _REQUIRED_FIELDS.items() if not str(fields.get(name) or "").strip()
    ]


def _normalize_http_exchange_ids(raw: Any) -> tuple[list[str] | None, list[str]]:
    """Return distinct proxy exchange ids in their original order."""
    if raw is None:
        return None, []
    if not isinstance(raw, list):
        return None, ["http_exchange_ids must be a list of proxy request ids"]

    normalized: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(raw):
        if not isinstance(value, str):
            errors.append(f"http_exchange_ids[{index}] must be a string")
            continue
        request_id = value.strip()
        if not request_id:
            errors.append(f"http_exchange_ids[{index}] cannot be empty")
            continue
        if len(request_id) > _MAX_HTTP_EXCHANGE_ID_CHARS:
            errors.append(
                f"http_exchange_ids[{index}] must be {_MAX_HTTP_EXCHANGE_ID_CHARS} "
                "characters or fewer"
            )
            continue
        if any(ord(char) < 0x21 or ord(char) > 0x7E for char in request_id):
            errors.append(f"http_exchange_ids[{index}] must contain only visible ASCII characters")
            continue
        if not request_id.isdigit():
            errors.append(f"http_exchange_ids[{index}] must be a numeric proxy request id")
            continue
        if request_id not in seen:
            seen.add(request_id)
            normalized.append(request_id)
            if len(normalized) > _MAX_HTTP_EXCHANGE_IDS:
                errors.append(
                    f"http_exchange_ids can contain at most "
                    f"{_MAX_HTTP_EXCHANGE_IDS} distinct request ids"
                )
                break
    return normalized, errors


_HTTP_EXCHANGE_DROPPED_WARNING = (
    "http_exchange_ids were not stored: the proxy project could not be reached to verify "
    "them. Attach them with update_vulnerability_report when the proxy responds again."
)


async def _verify_http_exchange_ids(
    ctx: RunContextWrapper,
    raw: Any,
) -> tuple[list[str] | None, list[str], str | None]:
    """Verify proxy exchange IDs against the current Caido project.

    IDs the project does not know are rejected. When the proxy itself cannot be
    queried the IDs are dropped and a warning is returned instead, so a proxy
    outage never blocks a finding and unverified IDs are never recorded as
    evidence.
    """
    request_ids, errors = _normalize_http_exchange_ids(raw)
    if request_ids is None or errors or not request_ids:
        return request_ids, errors, None

    try:
        existing_ids = await existing_request_ids(ctx, request_ids)
    except Exception:
        logger.warning(
            "Could not verify HTTP exchange IDs against the current Caido project",
            exc_info=True,
        )
        return None, [], _HTTP_EXCHANGE_DROPPED_WARNING

    missing_ids = [request_id for request_id in request_ids if request_id not in existing_ids]
    if missing_ids:
        return (
            None,
            [
                "http_exchange_ids do not exist in the current proxy project: "
                + ", ".join(missing_ids)
            ],
            None,
        )
    return request_ids, [], None


def _with_warning(result: dict[str, Any], warning: str | None) -> dict[str, Any]:
    if warning and result.get("success"):
        result["warning"] = warning
    return result


def _validate_cvss_breakdown(breakdown: Any) -> list[str]:
    """Check the 8 CVSS metrics are all present with legal values."""
    if not isinstance(breakdown, dict) or not breakdown:
        return ["cvss_breakdown: must be an object with the 8 CVSS metrics"]
    return [
        f"Invalid {name}: {breakdown.get(name)}. Must be one of: {valid}"
        for name, valid in _CVSS_VALID.items()
        if breakdown.get(name) not in valid
    ]


def _validate_identifiers(
    cve: str | None, cwe: str | None
) -> tuple[str | None, str | None, list[str]]:
    """Normalize and validate the optional CVE / CWE identifiers."""
    errors: list[str] = []
    if cve:
        cve = _extract_cve(cve)
        cve_err = _validate_cve(cve)
        if cve_err:
            errors.append(cve_err)
    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)
    return cve, cwe, errors


def _validate_analysis_fields(
    *,
    counterevidence: str,
    confidence: str,
    confidence_rationale: str | None,
    severity_change_conditions: str,
) -> list[str]:
    """Validate the counterevidence / confidence closure metadata."""
    errors: list[str] = []
    if not str(counterevidence or "").strip():
        errors.append(
            "Counterevidence cannot be empty - state the strongest evidence against "
            "this finding, or what you checked and found none (e.g. 'no input "
            "validation, WAF, or authorization check found on this path')"
        )
    if not str(severity_change_conditions or "").strip():
        errors.append(
            "severity_change_conditions cannot be empty - state the one concrete piece "
            "of evidence that would raise or lower the severity"
        )
    if confidence not in _VALID_CONFIDENCE:
        errors.append(
            f"Invalid confidence: {confidence!r}. Must be one of: {sorted(_VALID_CONFIDENCE)}"
        )
    elif confidence != "high" and not str(confidence_rationale or "").strip():
        errors.append(
            "confidence_rationale is required when confidence is not 'high' - name the "
            "gap (e.g. static-only trace, unconfirmed reachability, no runtime access)"
        )
    return errors


_POC_PLACEHOLDER_RE = re.compile(
    r"(?:#\s*TODO|//\s*TODO|TODO:\s*insert|INSERT_PAYLOAD|"
    r"YOUR_PAYLOAD_HERE|PLACEHOLDER_PAYLOAD)",
    re.IGNORECASE,
)
_SPECULATIVE_EVIDENCE_RE = re.compile(
    r"\b(?:not\s+tested|untested|hypothetical\s+only|theoretical\s+only|"
    r"could\s+not\s+reproduce|unable\s+to\s+verify|assumed\s+vulnerable)\b",
    re.IGNORECASE,
)


def _validate_anti_hallucination(
    *,
    poc_script_code: str | None,
    evidence: str | None,
    confidence: str | None,
) -> list[str]:
    """Reject placeholder PoCs and speculative/untested claims disguised as high-confidence proof."""
    errors: list[str] = []
    if poc_script_code and _POC_PLACEHOLDER_RE.search(poc_script_code):
        errors.append(
            "Anti-hallucination gate rejected poc_script_code: contains unexecuted "
            "placeholder markers (TODO / INSERT_PAYLOAD / PLACEHOLDER). Provide the "
            "exact executed reproduction command or script."
        )
    if (
        confidence == "high"
        and evidence
        and _SPECULATIVE_EVIDENCE_RE.search(evidence)
    ):
        errors.append(
            "Anti-hallucination gate rejected evidence: cannot claim 'high' confidence "
            "while evidence states the issue is untested, hypothetical, or unverified. "
            "Execute a real verification probe and include verbatim output, or lower confidence."
        )
    return errors


def _validate_fix_verification(
    locations: list[dict[str, Any]] | None,
    fix_verification: str | None,
) -> list[str]:
    """Require a verification statement whenever an applyable fix is proposed."""
    if not locations or not any(loc.get("fix_after") for loc in locations):
        return []
    if str(fix_verification or "").strip():
        return []
    return [
        "fix_verification is REQUIRED when any code_location carries a 'fix_after' - "
        "a suggestion a reviewer can click to apply must be verified first. State, in "
        "order: (1) security closure - re-trace the source->sink path through the "
        "PATCHED code and say why it is now blocked; (2) bypass review - re-read the "
        "diff without your original rationale and name the equivalent sinks, sibling "
        "call sites, and alternate malicious input classes you checked; (3) preserved "
        "behavior - the legitimate inputs, APIs, and error semantics that still work; "
        "(4) how each was checked (executed vs. reasoned), naming any unrun check as "
        "an explicit gap. If you cannot make these statements, drop 'fix_after' and "
        "leave the location informational."
    ]


def _finding_class_of(report: dict[str, Any]) -> str:
    """Resolve the class of a stored finding.

    A finding filed before ``finding_class`` was persisted still carries the
    metadata of its class. A record with dependency metadata is a dependency
    finding even when the field is absent, so read the metadata before falling
    back to dynamic.
    """
    declared = str(report.get("finding_class") or "").lower()
    if declared:
        return declared
    if report.get("dependency_metadata"):
        return "dependency_cve"
    return "dynamic"


_UPDATE_TEXT_FIELDS = (
    "title",
    "description",
    "impact",
    "target",
    "technical_analysis",
    "poc_description",
    "poc_script_code",
    "remediation_steps",
    "evidence",
    "assumptions",
    "counterevidence",
    "confidence_rationale",
    "severity_change_conditions",
    "endpoint",
    "method",
    "fix_verification",
    "fix_pr_body",
    "contextual_cvss_reasoning",
)


def _collect_update_changes(  # noqa: PLR0912, PLR0915
    fields: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Validate the fields a revision replaces and return them with any errors."""
    errors: list[str] = []
    changes: dict[str, Any] = {}

    for name in _UPDATE_TEXT_FIELDS:
        value = clean_optional(fields.get(name))
        if value is not None:
            changes[name] = value

    confidence = clean_optional(fields.get("confidence"))
    if confidence is not None:
        confidence = confidence.lower()
        if confidence not in _VALID_CONFIDENCE:
            errors.append(
                f"Invalid confidence: {confidence!r}. Must be one of: {sorted(_VALID_CONFIDENCE)}"
            )
        else:
            changes["confidence"] = confidence

    fix_effort = clean_optional(fields.get("fix_effort"))
    if fix_effort is not None:
        fix_effort = fix_effort.lower()
        if fix_effort not in _VALID_FIX_EFFORT:
            errors.append(
                f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
            )
        else:
            changes["fix_effort"] = fix_effort

    breakdown = fields.get("cvss_breakdown")
    if breakdown is not None:
        breakdown_errors = _validate_cvss_breakdown(breakdown)
        errors.extend(breakdown_errors)
        if not breakdown_errors:
            try:
                cvss_score, severity, _vector = _calculate_cvss(breakdown)
            except ValueError as exc:
                errors.append(str(exc))
            else:
                # The rating belongs to the vector, so a revised vector carries
                # its own score and severity rather than leaving the old ones.
                changes["cvss_breakdown"] = breakdown
                changes["cvss"] = cvss_score
                changes["severity"] = severity

    raw_locations = fields.get("code_locations")
    locations = _normalize_code_locations(raw_locations)
    if locations:
        errors.extend(_validate_code_locations(locations))
        errors.extend(_validate_fix_verification(locations, changes.get("fix_verification")))
        changes["code_locations"] = locations
    elif raw_locations:
        errors.append(
            "code_locations were dropped as unusable - every location needs a relative "
            "'file' and an integer 'start_line'"
        )

    cve, cwe, identifier_errors = _validate_identifiers(
        clean_optional(fields.get("cve")), clean_optional(fields.get("cwe"))
    )
    errors.extend(identifier_errors)
    if cve:
        changes["cve"] = cve
    if cwe:
        changes["cwe"] = cwe

    raw_http_exchange_ids = fields.get("http_exchange_ids")
    http_exchange_ids, http_exchange_errors = _normalize_http_exchange_ids(raw_http_exchange_ids)
    errors.extend(http_exchange_errors)
    if raw_http_exchange_ids is not None and not http_exchange_errors:
        changes["http_exchange_ids"] = http_exchange_ids or []

    errors.extend(
        _validate_anti_hallucination(
            poc_script_code=changes.get("poc_script_code"),
            evidence=changes.get("evidence"),
            confidence=changes.get("confidence"),
        )
    )

    return changes, errors


# Evidence that only a dynamic finding carries. A dependency finding describes a
# package, not a request against an endpoint.
_DYNAMIC_ONLY_UPDATE_FIELDS = (
    "endpoint",
    "method",
    "poc_description",
    "poc_script_code",
    "http_exchange_ids",
)

# A dependency finding is rated in the context of the codebase that pins it, and
# that rating is only shown with the reasoning behind it.
_DEPENDENCY_ONLY_UPDATE_FIELDS = ("contextual_cvss_reasoning",)


def _reject_cross_class_revision(
    report_id: str,
    matched_class: str,
    offending: list[str],
) -> dict[str, Any]:
    logger.info(
        "Revision of %s carries fields (%s) a %s finding does not hold; rejecting",
        report_id,
        ", ".join(offending),
        matched_class,
    )
    return {
        "success": False,
        "error": (
            f"Report '{report_id}' is a {matched_class} finding, so it cannot carry "
            f"{', '.join(offending)}. File your proof as its own vulnerability report "
            "instead of writing it onto this one."
        ),
        "report_id": report_id,
        "finding_class": matched_class,
        "rejected_fields": offending,
    }


def _rate_dependency_revision(
    report_id: str,
    matched: dict[str, Any],
    changes: dict[str, Any],
) -> dict[str, Any] | None:
    """Turn a replacement ``cvss_breakdown`` into the contextual rating of a dependency.

    A dependency record keeps its rating as ``cvss``/``severity`` plus the
    contextual breakdown, vector and reasoning inside ``dependency_metadata``.
    The package identity in that metadata is copied over untouched. A new
    breakdown needs its own reasoning. The reasoning alone can be corrected
    when the record already carries the breakdown it explains.
    """
    breakdown = changes.pop("cvss_breakdown", None)
    reasoning = changes.pop("contextual_cvss_reasoning", None)
    if breakdown is None and reasoning is None:
        return None

    metadata = dict(matched.get("dependency_metadata") or {})
    if breakdown is None and not metadata.get("contextual_cvss_breakdown"):
        return {
            "success": False,
            "error": "Validation failed",
            "errors": [
                "cvss_breakdown is required: this dependency finding carries no "
                "contextual rating yet, so contextual_cvss_reasoning has nothing to explain"
            ],
            "report_id": report_id,
        }
    if reasoning is None:
        return {
            "success": False,
            "error": "Validation failed",
            "errors": [
                "contextual_cvss_reasoning is required: a dependency finding is re-rated "
                "with the cvss_breakdown observed in this codebase together with the "
                "reasoning a reader can check"
            ],
            "report_id": report_id,
        }

    if breakdown is not None:
        score, _severity, vector = _calculate_cvss(breakdown)
        metadata["contextual_cvss_breakdown"] = breakdown
        metadata["contextual_cvss_score"] = score
        metadata["contextual_cvss_vector"] = vector
    metadata["contextual_cvss_reasoning"] = reasoning[:_MAX_CONTEXTUAL_REASONING_CHARS]
    changes["dependency_metadata"] = metadata
    return None


def _fit_revision_to_class(
    report_state: ReportState,
    report_id: str,
    changes: dict[str, Any],
) -> dict[str, Any] | None:
    """Keep a revision inside the class of the finding it names.

    A finding keeps its class and the metadata that belongs to it. Writing an
    exploit onto a dependency record would leave it carrying a package pin next
    to a request against an endpoint, so the proof belongs in its own dynamic
    finding instead. A dependency finding is still re-rated, through the
    contextual CVSS it was filed with.
    """
    matched = next(
        (r for r in report_state.get_existing_vulnerabilities() if r.get("id") == report_id),
        None,
    )
    if matched is None:
        return None

    matched_class = _finding_class_of(matched)
    foreign = (
        _DEPENDENCY_ONLY_UPDATE_FIELDS
        if matched_class == "dynamic"
        else _DYNAMIC_ONLY_UPDATE_FIELDS
    )
    offending = [name for name in foreign if name in changes]
    if offending:
        return _reject_cross_class_revision(report_id, matched_class, offending)
    if matched_class == "dynamic":
        return None
    return _rate_dependency_revision(report_id, matched, changes)


def _read_revision(
    report_id: str, update_reason: str, fields: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return the changes a revision asks for, or the reason it cannot be acted on."""
    if not report_id or not str(update_reason or "").strip():
        missing = "report_id" if not report_id else "update_reason"
        return {}, {
            "success": False,
            "error": (
                f"{missing} cannot be empty - name the report you are revising and state "
                "what you learned that it does not yet carry"
            ),
        }

    changes, errors = _collect_update_changes(fields)
    if errors:
        return {}, {"success": False, "error": "Validation failed", "errors": errors}
    if not changes:
        return {}, {
            "success": False,
            "error": "No fields to update - pass at least one field you want to replace",
        }
    return changes, None


def _do_update(
    *,
    report_id: str,
    update_reason: str,
    fields: dict[str, Any],
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    """Apply an agent's own revision to a report it can name.

    Editing a finding is its own operation and the only way a filed finding
    changes. Deduplication never reaches this path: it only decides whether a
    new candidate is a finding already on file.
    """
    report_id = (report_id or "").strip()
    changes, rejection = _read_revision(report_id, update_reason, fields)
    if rejection is not None:
        return rejection

    from redjohn.report.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return {
            "success": False,
            "error": "Report state unavailable - no reports have been filed yet",
        }

    class_error = _fit_revision_to_class(report_state, report_id, changes)
    if class_error is not None:
        return class_error

    try:
        updated = report_state.update_vulnerability_report(
            report_id,
            changes,
            update_reason=update_reason,
            updated_by_agent_id=agent_id,
            updated_by_agent_name=agent_name,
        )
    except Exception as e:
        logger.exception("update_vulnerability_report persistence failed")
        return {
            "success": False,
            "error": (
                f"Failed to revise report '{report_id}': {e!s}. "
                "The report still carries its previous content; retry the update."
            ),
            "report_id": report_id,
        }
    if updated is None:
        known = [r.get("id") for r in report_state.get_existing_vulnerabilities()]
        if report_id not in known:
            error = f"Report with id '{report_id}' not found"
        else:
            error = f"Report '{report_id}' already says this - nothing in your update changes it"
        return {"success": False, "error": error, "report_id": report_id}

    logger.info(
        "Vulnerability report %s revised by its author: severity=%s cvss=%s fields=%s",
        report_id,
        updated.get("severity"),
        updated.get("cvss"),
        ", ".join(sorted(changes)),
    )
    return {
        "success": True,
        "action": "updated",
        "message": f"Report '{report_id}' now carries your revision. Do not file it again.",
        "report_id": report_id,
        "updated_fields": sorted(changes),
        "severity": updated.get("severity"),
        "cvss_score": updated.get("cvss"),
    }


def _do_delete(
    *,
    report_id: str,
    delete_reason: str,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    """Withdraw a report an agent filed and has since disproved.

    Deletion is for a finding that is not a vulnerability at all. A finding
    that is real but weaker than filed is revised, not deleted.
    """
    report_id = (report_id or "").strip()
    delete_reason = (delete_reason or "").strip()
    if not report_id or not delete_reason:
        missing = "report_id" if not report_id else "delete_reason"
        return {
            "success": False,
            "error": (
                f"{missing} cannot be empty - name the report you are withdrawing and state "
                "what disproved it"
            ),
        }

    from redjohn.report.state import ReportRollbackError, get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return {
            "success": False,
            "error": "Report state unavailable - no reports have been filed yet",
        }

    try:
        deleted = report_state.delete_vulnerability_report(
            report_id,
            delete_reason=delete_reason,
            deleted_by_agent_id=agent_id,
            deleted_by_agent_name=agent_name,
        )
    except Exception as e:
        logger.exception("delete_vulnerability_report persistence failed")
        if isinstance(e, ReportRollbackError):
            outcome = (
                f"{e.cause!s}. The report is still on file, but its on-disk indexes could "
                "not be rewritten and may be stale until the next report is saved"
            )
        else:
            outcome = f"{e!s}. The report is still on file"
        return {
            "success": False,
            "error": f"Failed to delete report '{report_id}': {outcome}; retry the deletion.",
            "report_id": report_id,
        }
    if deleted is None:
        return {
            "success": False,
            "error": f"Report with id '{report_id}' not found",
            "report_id": report_id,
        }

    logger.info(
        "Vulnerability report %s deleted by %s: %s",
        report_id,
        agent_name or agent_id or "an agent",
        delete_reason[:200],
    )
    return {
        "success": True,
        "action": "deleted",
        "message": (
            f"Report '{report_id}' ({deleted.get('title')}) is withdrawn and no longer "
            "counts as a finding of this scan. Do not file it again unless new evidence "
            "proves it."
        ),
        "report_id": report_id,
        "title": deleted.get("title"),
        "severity": deleted.get("severity"),
    }


async def _do_create(
    *,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    evidence: str,
    assumptions: str,
    counterevidence: str,
    confidence: str,
    severity_change_conditions: str,
    fix_effort: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None,
    method: str | None,
    cve: str | None,
    cwe: str | None,
    code_locations: list[dict[str, Any]] | None,
    http_exchange_ids: list[str] | None = None,
    confidence_rationale: str | None = None,
    fix_verification: str | None = None,
    fix_pr_body: str | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = _validate_required_text(
        {
            "title": title,
            "description": description,
            "impact": impact,
            "target": target,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": poc_script_code,
            "remediation_steps": remediation_steps,
            "evidence": evidence,
            "assumptions": assumptions,
        }
    )

    confidence = (confidence or "").strip().lower()
    errors.extend(
        _validate_analysis_fields(
            counterevidence=counterevidence,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            severity_change_conditions=severity_change_conditions,
        )
    )
    errors.extend(
        _validate_anti_hallucination(
            poc_script_code=poc_script_code,
            evidence=evidence,
            confidence=confidence,
        )
    )

    fix_effort = (fix_effort or "").strip().lower()
    if fix_effort not in _VALID_FIX_EFFORT:
        errors.append(
            f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
        )

    errors.extend(_validate_cvss_breakdown(cvss_breakdown))

    parsed_locations = _normalize_code_locations(code_locations)
    if parsed_locations:
        errors.extend(_validate_code_locations(parsed_locations))
    errors.extend(_validate_fix_verification(parsed_locations, fix_verification))
    cve, cwe, identifier_errors = _validate_identifiers(cve, cwe)
    errors.extend(identifier_errors)
    normalized_http_exchange_ids, http_exchange_errors = _normalize_http_exchange_ids(
        http_exchange_ids
    )
    errors.extend(http_exchange_errors)

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        cvss_score, severity, _vector = _calculate_cvss(cvss_breakdown)
    except ValueError as exc:
        return {"success": False, "error": "Validation failed", "errors": [str(exc)]}

    try:
        from redjohn.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; vulnerability report not persisted")
            return {
                "success": True,
                "message": f"Vulnerability report '{title}' created (not persisted)",
                "warning": "Report could not be persisted - report state unavailable",
            }

        from redjohn.report.dedupe import check_duplicate

        candidate = {
            "title": title,
            "description": description,
            "impact": impact,
            "target": target,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": poc_script_code,
            "endpoint": endpoint,
            "method": method,
        }
        report_fields: dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
            "impact": impact,
            "target": target,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": poc_script_code,
            "remediation_steps": remediation_steps,
            "evidence": evidence,
            "assumptions": assumptions,
            "counterevidence": counterevidence,
            "confidence": confidence,
            "confidence_rationale": confidence_rationale,
            "severity_change_conditions": severity_change_conditions,
            "fix_effort": fix_effort,
            "cvss": cvss_score,
            "cvss_breakdown": cvss_breakdown,
            "endpoint": endpoint,
            "method": method,
            "cve": cve,
            "cwe": cwe,
            "code_locations": parsed_locations,
            "fix_verification": fix_verification,
            "fix_pr_body": fix_pr_body,
            "http_exchange_ids": normalized_http_exchange_ids,
        }

        async with _CREATE_LOCK:
            existing = report_state.get_existing_vulnerabilities()
            dedupe = await check_duplicate(candidate, existing)
            if dedupe.get("is_duplicate"):
                duplicate_id = str(dedupe.get("duplicate_id") or "")
                duplicate_title = next(
                    (r.get("title", "Unknown") for r in existing if r.get("id") == duplicate_id),
                    "",
                )
                return {
                    "success": False,
                    "error": (
                        f"Potential duplicate of '{duplicate_title}' "
                        f"(id={duplicate_id[:8]}...) — do not re-report the same vulnerability"
                    ),
                    "duplicate_of": duplicate_id,
                    "duplicate_title": duplicate_title,
                    "confidence": dedupe.get("confidence", 0.0),
                    "reason": dedupe.get("reason", ""),
                }

            report_id = await asyncio.to_thread(
                lambda: report_state.add_vulnerability_report(
                    **report_fields,
                    agent_id=agent_id if isinstance(agent_id, str) else None,
                    agent_name=agent_name if isinstance(agent_name, str) else None,
                )
            )
    except Exception as e:
        logger.exception("create_vulnerability_report persistence failed")
        return {
            "success": False,
            "error": (
                f"Failed to create vulnerability report: {e!s}. "
                "The finding was not stored; file it again."
            ),
        }
    else:
        logger.info(
            "Vulnerability report created: id=%s severity=%s cvss=%.1f title=%s",
            report_id,
            severity,
            cvss_score,
            title,
        )
        return {
            "success": True,
            "message": f"Vulnerability report '{title}' created successfully",
            "report_id": report_id,
            "severity": severity,
            "cvss_score": cvss_score,
        }


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    """Return the (agent_id, agent_name) of the agent invoking this tool."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw_agent_name = names.get(agent_id)
            agent_name = raw_agent_name if isinstance(raw_agent_name, str) else None
    return agent_id, agent_name


@function_tool(timeout=180, strict_mode=False)
async def create_vulnerability_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    evidence: str,
    assumptions: str,
    counterevidence: str,
    confidence: str,
    severity_change_conditions: str,
    fix_effort: str,
    cvss_breakdown: dict[str, str],
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    http_exchange_ids: list[str] | None = None,
    confidence_rationale: str | None = None,
    fix_verification: str | None = None,
    fix_pr_body: str | None = None,
) -> str:
    """File a verified vulnerability report (one report per confirmed finding).

    Use for dynamically or statically proven vulnerabilities with concrete evidence
    and a working PoC. For known-CVE third-party dependency findings in manifests/lockfiles,
    use ``create_dependency_report`` instead. Automatic deduplication rejects duplicates
    (use ``update_vulnerability_report`` to revise an existing report).

    Formatting & calibration rules:
    - Formal third-person Markdown (``**bold**``, ``inline code``, language-tagged fenced code blocks).
    - Never mention internal paths (``/workspace``), agent names, proxy request IDs, or sandbox details in text fields.
    - ``poc_description`` is numbered steps only (no code); all exploit code/requests go in ``poc_script_code``.
    - ``remediation_steps`` is prose only (no code); source patches go in ``code_locations``.
    - Score only the impact demonstrated by the PoC in ``cvss_breakdown`` (all 8 CVSS v3.1 metrics required: ``attack_vector`` N/A/L/P, ``attack_complexity`` L/H, ``privileges_required`` N/L/H, ``user_interaction`` N/R, ``scope`` U/C, ``confidentiality``/``integrity``/``availability`` N/L/H).

    Nice to have: include relevant git blame details in technical_analysis when available.

    Args:
        title: Specific finding title (e.g. ``"SQL Injection in /api/users login parameter"``), without CVE ID.
        description: Concise 1-3 sentence overview of the vulnerability.
        impact: Concrete unauthorized consequence demonstrated by the PoC and affected scope.
        target: Affected URL, domain, or repository.
        technical_analysis: Root cause and vulnerable mechanism (with fenced code/HTTP excerpts).
        poc_description: Numbered step-by-step reproduction instructions (prose only, no code).
        poc_script_code: Executed PoC script, curl command, or raw HTTP payload.
        remediation_steps: Actionable remediation guidance (prose only, no code).
        evidence: Verbatim proof of exploitation (response headers/body, command output) in fenced blocks.
        assumptions: Prerequisites required for exploitation (e.g. ``"Requires low-privilege account"``).
        counterevidence: REQUIRED. Strongest case against exploitability/severity checked before filing (WAF, guards, auth checks).
        confidence: REQUIRED. ``high`` (working live PoC or complete reachable source-to-sink trace), ``medium`` (strong static trace not executed), or ``low``.
        confidence_rationale: Required when ``confidence`` is not ``high``. Name the specific verification gap.
        severity_change_conditions: REQUIRED. Concrete condition or evidence that would raise or lower severity.
        fix_effort: One of ``trivial`` / ``low`` / ``medium`` / ``high``.
        cvss_breakdown: Dict with all 8 CVSS v3.1 metrics (``attack_vector``, ``attack_complexity``, ``privileges_required``, ``user_interaction``, ``scope``, ``confidentiality``, ``integrity``, ``availability``).
        endpoint: Affected API route or path (e.g. ``/api/login``).
        method: HTTP method when applicable (e.g. ``POST``).
        cve: Bare ``CVE-YYYY-NNNNN`` identifier if verified, else omit.
        cwe: Specific child ``CWE-NNN`` identifier (e.g. ``CWE-89``, ``CWE-78``, ``CWE-502``), else omit.
        code_locations: White-box source locations: list of dicts with repo-relative ``file``, 1-based ``start_line``/``end_line``, optional ``snippet``, ``label``, and verbatim ``fix_before``/``fix_after``.
        http_exchange_ids: Numeric Caido proxy request IDs proving the finding (from ``list_requests``/``view_request``). Omit only when no HTTP traffic applies.
        fix_verification: REQUIRED whenever ``code_locations`` includes ``fix_after``. Document security closure, bypass review, preserved behavior, and test checks.
        fix_pr_body: Optional Markdown PR summary/rationale when source code fix is provided.
    """
    (
        http_exchange_ids,
        http_exchange_errors,
        http_exchange_warning,
    ) = await _verify_http_exchange_ids(ctx, http_exchange_ids)
    if http_exchange_errors:
        return json.dumps(
            {
                "success": False,
                "error": "Validation failed",
                "errors": http_exchange_errors,
            },
            ensure_ascii=False,
            default=str,
        )

    agent_id, agent_name = _caller_identity(ctx)

    result = await _do_create(
        title=title,
        description=description,
        impact=impact,
        target=target,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        evidence=evidence,
        assumptions=assumptions,
        counterevidence=counterevidence,
        confidence=confidence,
        confidence_rationale=confidence_rationale,
        severity_change_conditions=severity_change_conditions,
        fix_effort=fix_effort,
        cvss_breakdown=cvss_breakdown,
        endpoint=endpoint,
        method=method,
        cve=cve,
        cwe=cwe,
        code_locations=code_locations,
        http_exchange_ids=http_exchange_ids,
        fix_verification=fix_verification,
        fix_pr_body=fix_pr_body,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(_with_warning(result, http_exchange_warning), ensure_ascii=False, default=str)


@function_tool(timeout=60, strict_mode=False)
async def update_vulnerability_report(
    ctx: RunContextWrapper,
    report_id: str,
    update_reason: str,
    title: str | None = None,
    description: str | None = None,
    impact: str | None = None,
    target: str | None = None,
    technical_analysis: str | None = None,
    poc_description: str | None = None,
    poc_script_code: str | None = None,
    remediation_steps: str | None = None,
    evidence: str | None = None,
    assumptions: str | None = None,
    counterevidence: str | None = None,
    confidence: str | None = None,
    confidence_rationale: str | None = None,
    severity_change_conditions: str | None = None,
    fix_effort: str | None = None,
    cvss_breakdown: dict[str, str] | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    http_exchange_ids: list[str] | None = None,
    fix_verification: str | None = None,
    fix_pr_body: str | None = None,
    contextual_cvss_reasoning: str | None = None,
) -> str:
    """Revise a vulnerability report that is already filed, keeping its id.

    Use this when you learn something a filed finding does not yet carry:

    - You built the working exploit after filing the finding on static
      evidence, so the PoC and the confidence change.
    - You chained the finding with another one and the real impact is
      higher, so the impact narrative and the CVSS vector change.
    - Further testing narrowed or weakened the finding, so the severity
      must come down.
    - Counterevidence, remediation, or a code location was wrong or
      incomplete.

    This is not deduplication. You do not need a duplicate verdict to
    revise your own finding, and you must not file a second report for a
    finding you can revise. Call ``list_reports`` or ``get_report`` first
    to find the id and read what the report already says.

    Pass only the fields you want to replace. Every other field stays as
    it is. Reporting rules of ``create_vulnerability_report`` apply to
    every field you pass, including the markdown and tone rules.

    Notes on specific fields:

    - ``cvss_breakdown`` replaces the whole vector. The score and the
      severity are recalculated from it, so pass all 8 metrics. On a
      dependency finding it replaces the contextual rating and needs
      ``contextual_cvss_reasoning`` with it. Pass the reasoning alone to
      correct only the explanation of the rating already on file.
    - A dependency finding never carries ``endpoint``, ``method`` or a PoC.
      File a proven exploit of the package as its own report.
    - A field that only explains another field is dropped when the field
      it explains changes and you pass no replacement. Pass
      ``confidence_rationale`` with a new ``confidence``, and
      ``severity_change_conditions`` with a new ``cvss_breakdown``.
    - ``code_locations`` replaces the whole list. A location carrying
      ``fix_after`` needs ``fix_verification``.

    The report keeps its id, its original author, and its filing time. The
    revision is recorded in the report as update history, so state the
    reason plainly.

    Args:
        report_id: Id of the report to revise (format ``vuln-NNNN``).
        update_reason: What you learned that the report does not yet
            carry, in one or two sentences.
        title: Replacement title.
        description: Replacement overview.
        impact: Replacement impact narrative.
        target: Replacement affected asset.
        technical_analysis: Replacement technical details.
        poc_description: Replacement PoC steps (no code).
        poc_script_code: Replacement exploit script or payload.
        remediation_steps: Replacement remediation prose (no code).
        evidence: Replacement evidence.
        assumptions: Replacement exploitability prerequisites.
        counterevidence: Replacement case against the finding.
        confidence: ``high`` / ``medium`` / ``low``.
        confidence_rationale: The gap behind a confidence below ``high``.
        severity_change_conditions: What would move the severity now.
        fix_effort: ``trivial`` / ``low`` / ``medium`` / ``high``.
        cvss_breakdown: All 8 CVSS metrics. Replaces the score and the
            severity too.
        endpoint: Replacement endpoint.
        method: Replacement HTTP method.
        cve: Replacement CVE id.
        cwe: Replacement CWE id.
        code_locations: Replacement code locations.
        http_exchange_ids: Replacement proxy request ids. Pass an empty
            list to remove all linked exchanges.
        fix_verification: Verification statement for an applyable fix.
        fix_pr_body: Replacement fix PR body.
        contextual_cvss_reasoning: Dependency findings only. What you
            observed in this codebase that justifies the contextual
            ``cvss_breakdown``.
    """
    (
        http_exchange_ids,
        http_exchange_errors,
        http_exchange_warning,
    ) = await _verify_http_exchange_ids(ctx, http_exchange_ids)
    if http_exchange_errors:
        return json.dumps(
            {
                "success": False,
                "error": "Validation failed",
                "errors": http_exchange_errors,
            },
            ensure_ascii=False,
            default=str,
        )

    fields = {
        "title": title,
        "description": description,
        "impact": impact,
        "target": target,
        "technical_analysis": technical_analysis,
        "poc_description": poc_description,
        "poc_script_code": poc_script_code,
        "remediation_steps": remediation_steps,
        "evidence": evidence,
        "assumptions": assumptions,
        "counterevidence": counterevidence,
        "confidence": confidence,
        "confidence_rationale": confidence_rationale,
        "severity_change_conditions": severity_change_conditions,
        "fix_effort": fix_effort,
        "cvss_breakdown": cvss_breakdown,
        "endpoint": endpoint,
        "method": method,
        "cve": cve,
        "cwe": cwe,
        "code_locations": code_locations,
        "http_exchange_ids": http_exchange_ids,
        "fix_verification": fix_verification,
        "fix_pr_body": fix_pr_body,
        "contextual_cvss_reasoning": contextual_cvss_reasoning,
    }
    if http_exchange_warning and all(value is None for value in fields.values()):
        return json.dumps(
            {"success": False, "error": http_exchange_warning, "report_id": report_id},
            ensure_ascii=False,
            default=str,
        )

    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _do_update,
        report_id=report_id,
        update_reason=update_reason,
        fields=fields,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(_with_warning(result, http_exchange_warning), ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def delete_vulnerability_report(
    ctx: RunContextWrapper,
    report_id: str,
    delete_reason: str,
) -> str:
    """Withdraw a vulnerability report that later testing disproved.

    Use this when a finding you filed turns out not to be a vulnerability
    at all: the exploit only worked because of a mistake in your own test
    setup (a mixed-up session, a self-inflicted state change, a misread
    response), the behaviour is documented and intended, or the control
    you believed was missing is in fact enforced. The report is removed
    from the scan; it does not stay behind as a zero-severity entry.

    Do NOT use this for a finding that is real but weaker than filed —
    revise it with ``update_vulnerability_report`` so the severity, the
    impact and the counterevidence come down together. Do NOT rewrite a
    report into a "retracted" or "false positive" note either: delete it.

    Only withdraw a report you have re-tested yourself, whoever filed it.
    Call ``get_report`` first to read what it claims, then state in
    ``delete_reason`` exactly what disproved it, so the scan history shows
    who withdrew the finding and why. A withdrawn report cannot be restored; if new
    evidence later proves the issue, file it again.

    Args:
        report_id: Id of the report to withdraw (format ``vuln-NNNN``).
        delete_reason: What disproved the finding, in one or two
            sentences.
    """
    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _do_delete,
        report_id=report_id,
        delete_reason=delete_reason,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


_DEP_SEVERITY_FROM_CVSS = {
    (9.0, 10.0): "critical",
    (7.0, 9.0): "high",
    (4.0, 7.0): "medium",
    (0.0, 4.0): "low",
}


def _dependency_severity(advisory_cvss: float | None) -> tuple[float, str]:
    if advisory_cvss is None:
        return 0.0, "info"
    score = max(0.0, min(10.0, advisory_cvss))
    for (lo, hi), label in _DEP_SEVERITY_FROM_CVSS.items():
        if lo <= score < hi or (hi == 10.0 and score == 10.0):
            return score, label
    return score, "none"


_VALID_REACHABILITY = frozenset(
    {
        "not_imported",
        "imported",
        "vulnerable_symbol_used",
        "reachable_call_path",
        "unknown",
    }
)


def _validate_manifest_path(manifest_path: str | None) -> str | None:
    """Return an error message when manifest_path is missing or unsafe."""
    path = (manifest_path or "").strip()
    if not path:
        return (
            "manifest_path is required: pass the repo-relative path of the "
            "lockfile/manifest where the vulnerable version was observed "
            "(trivy's Target, e.g. 'package-lock.json' or "
            "'services/api/pom.xml'). It binds the finding to its exact file "
            "so remediation can target the right repository."
        )
    if path.startswith("/") or "\\" in path or path.split("/")[0].endswith(":"):
        return f"manifest_path must be a relative path within the repository, got {path!r}"
    segments = path.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        return f"manifest_path must not contain empty, '.', or '..' segments, got {path!r}"
    return None


_MAX_CONTEXTUAL_REASONING_CHARS = 2000


def _validate_contextual_cvss(
    breakdown: dict[str, str] | None,
    reasoning: str | None,
) -> list[str]:
    errors: list[str] = []
    if not breakdown:
        errors.append(
            "contextual_cvss_breakdown is required: rate the CVE in this codebase with "
            "all 8 CVSS v3.1 metrics (attack_vector, attack_complexity, "
            "privileges_required, user_interaction, scope, confidentiality, integrity, "
            "availability). When your trace does not change the published rating, repeat "
            "the advisory's own metrics and adjust only what the usage level proves - a "
            "package the code never imports is normally N on all three impact metrics."
        )
    else:
        for name, valid in _CVSS_VALID.items():
            value = breakdown.get(name)
            if value not in valid:
                errors.append(
                    f"Invalid contextual_cvss_breakdown {name}: {value}. Must be one of: {valid}"
                )
    if not (reasoning or "").strip():
        errors.append(
            "contextual_cvss_reasoning is required: state what you observed in this "
            "codebase that justifies the contextual rating. A contextual score with "
            "no reasoning is not shown."
        )
    return errors


def _validate_advisory_cvss(advisory_cvss: float | None) -> str | None:
    if advisory_cvss is None:
        return (
            "advisory_cvss is required: read the published advisory base score "
            "(0.0-10.0) off the advisory (trivy CVSS / NVD / GHSA). It is the "
            "published reference the finding is rated against — do not omit it "
            "or the finding cannot be rated."
        )
    if not 0.0 <= advisory_cvss <= 10.0:
        return f"advisory_cvss must be between 0.0 and 10.0, got {advisory_cvss}"
    return None


def _resolve_dependency_rating(
    advisory_cvss: float | None,
    contextual_cvss_breakdown: dict[str, str] | None,
) -> tuple[float | None, str, float | None, str | None]:
    """Rate the finding.

    A contextual breakdown works exactly like a normal finding's
    ``cvss_breakdown``: the agent supplies the 8 metrics as observed in this
    codebase and the score/vector are computed from them. When provided it
    rates the finding; the advisory score stays as the published reference.
    """
    if contextual_cvss_breakdown:
        score, severity, vector = _calculate_cvss(contextual_cvss_breakdown)
        return score, severity, score, vector
    score, severity = _dependency_severity(advisory_cvss)
    return score, severity, None, None


def _build_dependency_metadata(
    *,
    package_name: str,
    installed_version: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
    introduced_by: str | None,
    dependency_path: str | None,
    manifest_path: str | None = None,
    reachability: str | None = None,
    reachability_evidence: str | None = None,
    advisory_cvss: float | None = None,
    contextual_cvss_breakdown: dict[str, str] | None = None,
    contextual_cvss_score: float | None = None,
    contextual_cvss_vector: str | None = None,
    contextual_cvss_reasoning: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "package_name": package_name.strip(),
        "installed_version": installed_version.strip(),
    }
    if advisory_cvss is not None:
        metadata["advisory_cvss"] = advisory_cvss
    if package_ecosystem and package_ecosystem.strip():
        metadata["package_ecosystem"] = package_ecosystem.strip()
    if manifest_path and manifest_path.strip():
        metadata["manifest_path"] = manifest_path.strip()
    if fixed_version and fixed_version.strip():
        metadata["fixed_version"] = fixed_version.strip()
    if introduced_by and introduced_by.strip():
        metadata["introduced_by"] = introduced_by.strip()
    if dependency_path and dependency_path.strip():
        metadata["dependency_path"] = dependency_path.strip()
    if reachability and reachability.strip():
        metadata["reachability"] = reachability.strip()
        if reachability_evidence and reachability_evidence.strip():
            metadata["reachability_evidence"] = reachability_evidence.strip()
    # Contextual CVSS is only meaningful as the full breakdown, its computed
    # score/vector, and the reasoning a reader can check — an incomplete set
    # is dropped.
    reasoning = str(contextual_cvss_reasoning or "").strip()
    if (
        contextual_cvss_breakdown
        and contextual_cvss_score is not None
        and contextual_cvss_vector
        and reasoning
    ):
        metadata["contextual_cvss_breakdown"] = contextual_cvss_breakdown
        metadata["contextual_cvss_score"] = contextual_cvss_score
        metadata["contextual_cvss_vector"] = contextual_cvss_vector
        metadata["contextual_cvss_reasoning"] = reasoning[:_MAX_CONTEXTUAL_REASONING_CHARS]
    return metadata


_REACHABILITY_EVIDENCE_LABELS = {
    "not_imported": "not imported by application code",
    "imported": "imported by application code; affected API usage unconfirmed",
    "vulnerable_symbol_used": "the advisory's affected API is used in application code",
    "reachable_call_path": (
        "a call path from application code to the vulnerable function was proven"
    ),
}


def _build_dependency_evidence(
    *,
    cve: str,
    package_name: str,
    installed_version: str,
    fixed_version: str | None,
    introduced_by: str | None,
    dependency_path: str | None,
    reachability: str | None = None,
    reachability_evidence: str | None = None,
) -> str:
    evidence = (
        f"**Advisory evidence:** `{cve}` applies to `{package_name}` "
        f"at installed version `{installed_version}`."
    )
    if fixed_version and fixed_version.strip():
        evidence += f" The advisory is fixed in `{fixed_version.strip()}`."
    if introduced_by and introduced_by.strip():
        evidence += (
            f"\n\n**Transitive dependency:** introduced by the direct "
            f"dependency `{introduced_by.strip()}`."
        )
    if dependency_path and dependency_path.strip():
        evidence += f"\n\n**Dependency chain:** `{dependency_path.strip()}`"
    label = _REACHABILITY_EVIDENCE_LABELS.get((reachability or "").strip().lower())
    if label:
        evidence += f"\n\n**Usage analysis:** {label}."
        if reachability_evidence and reachability_evidence.strip():
            evidence += f" {reachability_evidence.strip()}"
    return evidence


async def _do_create_dependency(  # noqa: PLR0912, PLR0915
    *,
    title: str,
    description: str,
    target: str,
    cve: str,
    package_name: str,
    installed_version: str,
    impact: str,
    remediation_steps: str,
    assumptions: str,
    package_ecosystem: str | None,
    fixed_version: str | None,
    cwe: str | None,
    advisory_cvss: float | None,
    technical_analysis: str | None,
    fix_effort: str,
    introduced_by: str | None = None,
    dependency_path: str | None = None,
    manifest_path: str | None = None,
    reachability: str = "unknown",
    reachability_evidence: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    fix_verification: str | None = None,
    contextual_cvss_breakdown: dict[str, str] | None = None,
    contextual_cvss_reasoning: str | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    required = {
        "title": title,
        "description": description,
        "target": target,
        "package_name": package_name,
        "installed_version": installed_version,
        "package_ecosystem": package_ecosystem,
        "impact": impact,
        "remediation_steps": remediation_steps,
        "assumptions": assumptions,
    }
    for name, value in required.items():
        if not str(value or "").strip():
            errors.append(f"{name} cannot be empty")

    parsed_cve = _extract_cve(cve or "")
    cve_err = _validate_cve(parsed_cve)
    if cve_err:
        errors.append(cve_err)

    if cwe:
        cwe = _extract_cwe(cwe)
        cwe_err = _validate_cwe(cwe)
        if cwe_err:
            errors.append(cwe_err)

    fix_effort = (fix_effort or "").strip().lower()
    if fix_effort not in _VALID_FIX_EFFORT:
        errors.append(
            f"Invalid fix_effort: {fix_effort!r}. Must be one of: {sorted(_VALID_FIX_EFFORT)}"
        )

    manifest_err = _validate_manifest_path(manifest_path)
    if manifest_err:
        errors.append(manifest_err)

    parsed_locations = _normalize_code_locations(code_locations)
    if parsed_locations:
        errors.extend(_validate_code_locations(parsed_locations))
    elif code_locations:
        errors.append(
            "code_locations were dropped as unusable - every location needs a relative "
            "'file' and an integer 'start_line'"
        )
    errors.extend(_validate_fix_verification(parsed_locations, fix_verification))

    reachability = (reachability or "unknown").strip().lower()
    if reachability not in _VALID_REACHABILITY:
        errors.append(
            f"Invalid reachability: {reachability!r}. Must be one of: {sorted(_VALID_REACHABILITY)}"
        )
    elif not (reachability_evidence or "").strip():
        errors.append(
            "reachability_evidence is required: cite the concrete proof (import "
            "file:line, matched symbol usage, or govulncheck call path), or, for "
            "'unknown', say what you searched and why the result is inconclusive. "
            "Never claim a reachability level without evidence."
        )

    errors.extend(_validate_contextual_cvss(contextual_cvss_breakdown, contextual_cvss_reasoning))

    advisory_err = _validate_advisory_cvss(advisory_cvss)
    if advisory_err:
        errors.append(advisory_err)

    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        cvss_score, severity, contextual_score, contextual_vector = _resolve_dependency_rating(
            advisory_cvss, contextual_cvss_breakdown
        )
    except ValueError as exc:
        return {"success": False, "error": "Validation failed", "errors": [str(exc)]}
    dependency_metadata = _build_dependency_metadata(
        package_name=package_name,
        installed_version=installed_version,
        package_ecosystem=package_ecosystem,
        fixed_version=fixed_version,
        introduced_by=introduced_by,
        dependency_path=dependency_path,
        manifest_path=manifest_path,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
        advisory_cvss=advisory_cvss,
        contextual_cvss_breakdown=contextual_cvss_breakdown,
        contextual_cvss_score=contextual_score,
        contextual_cvss_vector=contextual_vector,
        contextual_cvss_reasoning=contextual_cvss_reasoning,
    )
    evidence = _build_dependency_evidence(
        cve=parsed_cve,
        package_name=package_name.strip(),
        installed_version=installed_version.strip(),
        fixed_version=fixed_version,
        introduced_by=introduced_by,
        dependency_path=dependency_path,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
    )

    try:
        from redjohn.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; dependency report not persisted")
            return {
                "success": True,
                "message": f"Dependency finding '{title}' created (not persisted)",
                "warning": "Report could not be persisted - report state unavailable",
            }

        from redjohn.report.dedupe import check_duplicate

        candidate = {
            "title": title,
            "description": description,
            "target": target,
            "cve": parsed_cve,
            "dependency_metadata": dependency_metadata,
            "technical_analysis": technical_analysis,
        }
        async with _CREATE_LOCK:
            existing = report_state.get_existing_vulnerabilities()
            dedupe = await check_duplicate(candidate, existing)
            if dedupe.get("is_duplicate"):
                duplicate_id = dedupe.get("duplicate_id", "")
                return {
                    "success": False,
                    "error": (
                        f"Potential duplicate (id={duplicate_id[:8]}...) — "
                        "do not re-report the same dependency finding"
                    ),
                    "duplicate_of": duplicate_id,
                    "confidence": dedupe.get("confidence", 0.0),
                    "reason": dedupe.get("reason", ""),
                }

            report_id = await asyncio.to_thread(
                lambda: report_state.add_vulnerability_report(
                    title=title,
                    description=description,
                    severity=severity,
                    impact=impact,
                    target=target,
                    technical_analysis=technical_analysis,
                    remediation_steps=remediation_steps,
                    evidence=evidence,
                    assumptions=assumptions,
                    fix_effort=fix_effort,
                    cvss=cvss_score if advisory_cvss is not None else None,
                    cve=parsed_cve,
                    cwe=cwe,
                    code_locations=parsed_locations,
                    fix_verification=fix_verification,
                    finding_class="dependency_cve",
                    dependency_metadata=dependency_metadata,
                    agent_id=agent_id if isinstance(agent_id, str) else None,
                    agent_name=agent_name if isinstance(agent_name, str) else None,
                )
            )
    except Exception as e:
        logger.exception("create_dependency_report persistence failed")
        return {
            "success": False,
            "error": (
                f"Failed to create dependency report: {e!s}. "
                "The finding was not stored; file it again."
            ),
        }
    else:
        logger.info(
            "Dependency report created: id=%s cve=%s package=%s severity=%s",
            report_id,
            parsed_cve,
            package_name,
            severity,
        )
        return {
            "success": True,
            "message": f"Dependency finding '{title}' created successfully",
            "report_id": report_id,
            "severity": severity,
            "cve": parsed_cve,
        }


@function_tool(timeout=180, strict_mode=False)
async def create_dependency_report(
    ctx: RunContextWrapper,
    title: str,
    description: str,
    target: str,
    cve: str,
    package_name: str,
    installed_version: str,
    advisory_cvss: float,
    impact: str,
    remediation_steps: str,
    assumptions: str,
    package_ecosystem: str,
    manifest_path: str | None = None,
    fixed_version: str | None = None,
    cwe: str | None = None,
    technical_analysis: str | None = None,
    fix_effort: str = "low",
    introduced_by: str | None = None,
    dependency_path: str | None = None,
    reachability: str = "unknown",
    reachability_evidence: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    fix_verification: str | None = None,
    contextual_cvss_breakdown: dict[str, str] | None = None,
    contextual_cvss_reasoning: str | None = None,
) -> str:
    """File a known-CVE dependency (SCA) finding (one report per CVE x package).

    Use for third-party packages pinned to a vulnerable version in a lockfile,
    manifest, or SBOM with reachability analysis. Dynamically exploited vulnerabilities use
    ``create_vulnerability_report`` instead.

    Args:
        title: Finding title, e.g. ``"CVE-2024-1234 in lodash 4.17.20 (prototype pollution)"``.
        description: What the CVE is and why the pinned version is affected.
        target: Affected repository / project / manifest.
        cve: Verified ``CVE-YYYY-NNNNN`` identifier (required).
        package_name: Affected package name (e.g. ``lodash``).
        installed_version: Currently pinned/installed version.
        advisory_cvss: Required published advisory base score (0.0-10.0) from NVD/GHSA/Trivy.
        impact: What the CVE enables and business risk in this codebase.
        remediation_steps: Actionable fix (usually upgrade to fixed version).
        assumptions: Exploitability/reachability assumptions and confidence.
        package_ecosystem: Ecosystem name, e.g. ``npm`` / ``pypi`` / ``maven`` / ``go``.
        manifest_path: Required repo-relative path of the manifest/lockfile (e.g. ``package-lock.json``).
        fixed_version: First non-vulnerable version, if known.
        cwe: Specific ``CWE-NNN`` identifier if known, else omit.
        technical_analysis: Optional deeper mechanism/root-cause detail.
        fix_effort: One of ``trivial`` / ``low`` / ``medium`` / ``high``.
        introduced_by: For transitive dependencies, direct dependency ``name@version`` pulling it in.
        dependency_path: Resolution chain joined with `` > ``, e.g. ``express@4.18.1 > qs@6.10.2``.
        reachability: One of ``not_imported`` / ``imported`` / ``vulnerable_symbol_used`` / ``reachable_call_path`` / ``unknown``.
        reachability_evidence: Required concrete proof for ``reachability`` (repo-relative ``file:line`` imports/call sites and source-to-sink trace).
        code_locations: Optional list of location dicts where the package is imported/called or manifest pin fix is proposed.
        fix_verification: Required whenever ``code_locations`` includes ``fix_after``.
        contextual_cvss_breakdown: Required 8-metric CVSS v3.1 dict rating the CVE in this codebase based on source-to-sink reachability (``attack_vector``, ``attack_complexity``, ``privileges_required``, ``user_interaction``, ``scope``, ``confidentiality``, ``integrity``, ``availability``).
        contextual_cvss_reasoning: Required 2-4 sentence justification citing repo-relative ``file:line`` call sites and source-to-sink trace.
    """
    agent_id, agent_name = _caller_identity(ctx)

    result = await _do_create_dependency(
        title=title,
        description=description,
        target=target,
        cve=cve,
        package_name=package_name,
        installed_version=installed_version,
        impact=impact,
        remediation_steps=remediation_steps,
        assumptions=assumptions,
        package_ecosystem=package_ecosystem,
        fixed_version=fixed_version,
        cwe=cwe,
        advisory_cvss=advisory_cvss,
        technical_analysis=technical_analysis,
        fix_effort=fix_effort,
        introduced_by=introduced_by,
        dependency_path=dependency_path,
        manifest_path=manifest_path,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
        code_locations=code_locations,
        fix_verification=fix_verification,
        contextual_cvss_breakdown=contextual_cvss_breakdown,
        contextual_cvss_reasoning=contextual_cvss_reasoning,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "none": 5,
}
_VALID_SEVERITIES = frozenset(_SEVERITY_ORDER)
_VALID_FINDING_CLASSES = frozenset({"dynamic", "dependency_cve"})
_REPORT_DESCRIPTION_PREVIEW_CHARS = 280

# Compact, listing-safe fields — no full bodies / PoC code / evidence.
_REPORT_SUMMARY_FIELDS = (
    "id",
    "title",
    "severity",
    "cvss",
    "confidence",
    "finding_class",
    "cve",
    "cwe",
    "target",
    "endpoint",
    "method",
    "fix_effort",
    "agent_name",
    "timestamp",
)


def _report_severity_rank(report: dict[str, Any]) -> int:
    return _SEVERITY_ORDER.get(str(report.get("severity", "")).lower(), 99)


def _report_matches_filters(
    report: dict[str, Any],
    *,
    severity: str | None,
    finding_class: str | None,
    target: str | None,
    search: str | None,
) -> bool:
    if severity and str(report.get("severity", "")).lower() != severity:
        return False
    if finding_class and str(report.get("finding_class", "dynamic")).lower() != finding_class:
        return False
    if target:
        target_lower = target.lower()
        haystack = f"{report.get('target', '')} {report.get('endpoint', '')}".lower()
        if target_lower not in haystack:
            return False
    if search:
        search_lower = search.lower()
        title_match = search_lower in str(report.get("title", "")).lower()
        desc_match = search_lower in str(report.get("description", "")).lower()
        if not (title_match or desc_match):
            return False
    return True


def _mark_authorship(
    entry: dict[str, Any], report: dict[str, Any], caller_agent_id: str | None
) -> dict[str, Any]:
    """Flag whether ``report`` was filed by the agent making this call."""
    if caller_agent_id is not None and report.get("agent_id") == caller_agent_id:
        entry["by_you"] = True
    return entry


def _to_report_summary_entry(
    report: dict[str, Any], caller_agent_id: str | None = None
) -> dict[str, Any]:
    entry = {
        field: report[field] for field in _REPORT_SUMMARY_FIELDS if report.get(field) is not None
    }
    description = str(report.get("description", "")).strip()
    if description:
        if len(description) > _REPORT_DESCRIPTION_PREVIEW_CHARS:
            entry["description_preview"] = (
                f"{description[:_REPORT_DESCRIPTION_PREVIEW_CHARS].rstrip()}..."
            )
        else:
            entry["description_preview"] = description
    return _mark_authorship(entry, report, caller_agent_id)


def _severity_counts(reports: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for report in reports:
        sev = str(report.get("severity", "")).lower() or "none"
        counts[sev] = counts.get(sev, 0) + 1
    return {sev: counts[sev] for sev in _SEVERITY_ORDER if sev in counts}


async def _run_report_reader(fn: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(fn, *args, **kwargs)
    except (ImportError, AttributeError) as e:
        logger.exception("report reader failed")
        return {"success": False, "error": f"Failed to read reports: {e!s}"}


def _do_list_reports(
    *,
    severity: str | None,
    finding_class: str | None,
    target: str | None,
    search: str | None,
    include_details: bool,
    caller_agent_id: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    severity = (clean_optional(severity) or "").lower() or None
    if severity and severity not in _VALID_SEVERITIES:
        errors.append(
            f"Invalid severity: {severity!r}. Must be one of: {sorted(_VALID_SEVERITIES)}"
        )
    finding_class = (clean_optional(finding_class) or "").lower() or None
    if finding_class and finding_class not in _VALID_FINDING_CLASSES:
        errors.append(
            f"Invalid finding_class: {finding_class!r}. "
            f"Must be one of: {sorted(_VALID_FINDING_CLASSES)}"
        )
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    from redjohn.report.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return {
            "success": True,
            "reports": [],
            "filtered_count": 0,
            "total_count": 0,
            "severity_counts": {},
            "warning": "Report state unavailable - no reports have been filed yet",
        }

    all_reports = report_state.get_existing_vulnerabilities()
    matched = [
        r
        for r in all_reports
        if _report_matches_filters(
            r,
            severity=severity,
            finding_class=finding_class,
            target=clean_optional(target),
            search=clean_optional(search),
        )
    ]
    matched.sort(key=lambda r: (_report_severity_rank(r), str(r.get("id", ""))))

    reports = [
        _mark_authorship(dict(r), r, caller_agent_id)
        if include_details
        else _to_report_summary_entry(r, caller_agent_id)
        for r in matched
    ]
    return {
        "success": True,
        "reports": reports,
        "filtered_count": len(reports),
        "total_count": len(all_reports),
        "severity_counts": _severity_counts(all_reports),
    }


def _do_get_report(report_id: str, caller_agent_id: str | None = None) -> dict[str, Any]:
    report_id = (report_id or "").strip()
    if not report_id:
        return {"success": False, "error": "report_id cannot be empty", "report": None}

    from redjohn.report.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return {
            "success": False,
            "error": "Report state unavailable - no reports have been filed yet",
            "report": None,
        }

    for report in report_state.get_existing_vulnerabilities():
        if report.get("id") == report_id:
            return {
                "success": True,
                "report": _mark_authorship(dict(report), report, caller_agent_id),
            }
    return {
        "success": False,
        "error": f"Report with id '{report_id}' not found",
        "report": None,
    }


@function_tool(timeout=30)
async def list_reports(
    ctx: RunContextWrapper,
    severity: str | None = None,
    finding_class: str | None = None,
    target: str | None = None,
    search: str | None = None,
    include_details: bool = False,
) -> str:
    """List vulnerability reports filed so far in this scan — metadata-first.

    **For the orchestrator / root agent.** This is an orchestration tool
    for tracking scan-wide coverage and assembling the final report — leaf
    / specialist agents do their own testing and file findings; they should
    NOT call this. If you are a subagent, ignore it and focus on your task.

    Reports are shared across **every** agent in the scan, so this returns
    findings filed by any agent (root or child), not just your own. As the
    root agent, use it to track progress, avoid dispatching work on
    already-covered ground, reason about attack-chaining across confirmed
    findings, and build the ``finish_scan`` executive summary.

    By default each entry is compact: ``id``, ``title``, ``severity``,
    ``cvss``, ``confidence``, ``finding_class``, ``cve`` / ``cwe``,
    ``target`` / ``endpoint``, ``fix_effort``, ``agent_name`` (who filed it), ``timestamp``,
    plus a 280-char ``description_preview``. Entries you filed yourself are
    flagged ``by_you: true``. The response also carries
    ``total_count`` and ``severity_counts`` (counts per severity across all
    reports, ignoring filters). Set ``include_details=True`` for full report
    bodies (PoC, evidence, remediation, code_locations) — token-expensive;
    prefer ``get_report`` to drill into a single finding.

    Filters compose (all must match): ``severity`` and ``finding_class``
    match exactly, ``target`` is a substring match against target/endpoint,
    and ``search`` is a substring match against title/description. Results
    are ordered by severity (critical -> info), then report id.

    This is read-only — it never files or dedupes anything.

    Args:
        severity: Filter to one of ``critical`` / ``high`` / ``medium`` /
            ``low`` / ``info`` / ``none``.
        finding_class: Filter to ``dynamic`` (PoC-backed) or
            ``dependency_cve`` (known-CVE supply-chain).
        target: Substring match against a report's target / endpoint.
        search: Substring match against title and description.
        include_details: When False (default) entries are compact; when
            True full report bodies are returned.
    """
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await _run_report_reader(
            _do_list_reports,
            severity=severity,
            finding_class=finding_class,
            target=target,
            search=search,
            include_details=include_details,
            caller_agent_id=caller_agent_id,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_report(ctx: RunContextWrapper, report_id: str) -> str:
    """Fetch one vulnerability report by its id (e.g. ``vuln-0001``).

    Returns the full report body — description, impact, technical analysis,
    PoC, evidence, remediation, CVSS breakdown, and any ``code_locations``.
    Use ``list_reports`` first to find ids; this is the cheap way to read a
    single finding in full without pulling every body.

    Read-only.

    Args:
        report_id: Report id from ``list_reports`` or a
            ``create_vulnerability_report`` / ``create_dependency_report``
            response (format ``vuln-NNNN``).
    """
    caller_agent_id, _ = _caller_identity(ctx)
    return json.dumps(
        await _run_report_reader(_do_get_report, report_id, caller_agent_id),
        ensure_ascii=False,
        default=str,
    )
