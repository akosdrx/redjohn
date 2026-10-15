#!/usr/bin/env python3
"""finding_format.py - validate and render a finding record
(90-evidence-reporting).

Reads one finding as JSON and validates the field contract from the skill's
finding record format:

  required fields : id, title, severity, cwe, cvss, component, version,
                    tier, evidence, poc, remediation, detection
  optional field  : description (required in the delivered record per
                    references/finding-template.md; a [gap] marker plus a
                    warning is emitted when absent)
  severity        : one of critical/high/medium/low/info (case-insensitive;
                    rendered capitalized)
  cwe             : pattern CWE-<int> (canonical pick from 70's mapping)
  cvss            : vector prefix CVSS:4 (CVSS 4.0, per 70)
  tier            : integer 1-4 (fingerprint tier from 10) or "n/a" for
                    config/logic findings not tied to a versioned component
  evidence        : non-empty string or non-empty list of non-empty strings
                    (file names per evidence-gates naming)

On success the markdown finding section is emitted to stdout in the shape of
references/finding-template.md. On any validation error all errors are listed
on stderr and the exit code is 1 - fix the JSON rather than hand-editing
around the validator.

Offline: no network, sends nothing, no scope guard applies.

Usage:
  python3 finding_format.py --finding finding.json [--compliance]
  python3 finding_format.py --self-test

Exit codes: 0 = valid (markdown rendered); 1 = validation error, unreadable
file, or bad arguments.
"""

import argparse
import json
import re
import sys

REQUIRED_FIELDS = ["id", "title", "severity", "cwe", "cvss", "component",
                   "version", "tier", "evidence", "poc", "remediation",
                   "detection"]
OPTIONAL_FIELDS = ["description"]
STRING_REQUIRED_FIELDS = ["id", "title", "severity", "cwe", "cvss", "component",
                          "version", "poc", "remediation", "detection"]
SEVERITIES = ("critical", "high", "medium", "low", "info")
CWE_RE = re.compile(r"^CWE-[0-9]+$")
CVSS_PREFIX = "CVSS:4"
ID_RE = re.compile(r"^F-\d{3}$")


def _is_filled(value):
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True                                  # tier: 1-4
    if isinstance(value, list):
        return len(value) > 0 and all(
            isinstance(item, str) and item.strip() != "" for item in value)
    return False


def validate(raw):
    """-> (normalized finding dict, errors list, warnings list)."""
    errors = []
    warnings = []
    finding = {}

    if not isinstance(raw, dict):
        return finding, ["finding JSON must be an object, got %s"
                         % type(raw).__name__], warnings

    for field in REQUIRED_FIELDS:
        if field not in raw:
            errors.append("missing required field '%s'" % field)

    for field in STRING_REQUIRED_FIELDS:
        if field in raw:
            if not isinstance(raw[field], str):
                errors.append("field '%s' must be a string" % field)
            elif not raw[field].strip():
                errors.append("required field '%s' is empty or the wrong shape"
                              % field)

    for field in OPTIONAL_FIELDS:
        if field in raw:
            if not isinstance(raw[field], str):
                errors.append("field '%s' must be a string" % field)
            elif not raw[field].strip():
                errors.append("optional field '%s' present but empty" % field)

    unknown = [key for key in raw
               if key not in REQUIRED_FIELDS and key not in OPTIONAL_FIELDS]
    if unknown:
        warnings.append("unknown field(s) ignored: %s" % ", ".join(unknown))

    if "id" in raw and isinstance(raw["id"], str) and raw["id"].strip():
        finding["id"] = raw["id"].strip()
        if not ID_RE.match(finding["id"]):
            warnings.append("id %r does not follow the F-NNN convention"
                            % finding["id"])

    if "title" in raw and isinstance(raw["title"], str) and raw["title"].strip():
        finding["title"] = raw["title"].strip()

    if "severity" in raw and isinstance(raw["severity"], str) and raw["severity"].strip():
        severity = raw["severity"].strip().lower()
        if severity not in SEVERITIES:
            errors.append("severity %r not one of %s"
                          % (raw["severity"], "/".join(SEVERITIES)))
        else:
            finding["severity"] = severity.capitalize()

    if "cwe" in raw and isinstance(raw["cwe"], str) and raw["cwe"].strip():
        cwe = raw["cwe"].strip()
        if not CWE_RE.match(cwe):
            errors.append("cwe %r does not match the canonical CWE-<int> "
                          "pattern (pick from 70's cwe-mapping.md)"
                          % raw["cwe"])
        else:
            finding["cwe"] = cwe

    if "cvss" in raw and isinstance(raw["cvss"], str) and raw["cvss"].strip():
        cvss = raw["cvss"].strip()
        if not cvss.startswith(CVSS_PREFIX):
            errors.append("cvss %r does not start with %r (CVSS 4.0 vector "
                          "from 70; use cvss4_render.py to validate it)"
                          % (raw["cvss"], CVSS_PREFIX))
        else:
            finding["cvss"] = cvss

    if "component" in raw and isinstance(raw["component"], str) and raw["component"].strip():
        finding["component"] = raw["component"].strip()
    if "version" in raw and isinstance(raw["version"], str) and raw["version"].strip():
        finding["version"] = raw["version"].strip()

    if "tier" in raw:
        tier = raw["tier"]
        if isinstance(tier, bool):
            errors.append("tier must be an integer 1-4 or 'n/a'")
        elif isinstance(tier, int):
            if not 1 <= tier <= 4:
                errors.append("tier %d outside 1-4 (fingerprint tiers; use "
                              "'n/a' for unversioned config/logic findings)"
                              % tier)
            else:
                finding["tier"] = tier
        elif isinstance(tier, str) and tier.strip().lower() == "n/a":
            finding["tier"] = "n/a"
        else:
            errors.append("tier %r must be an integer 1-4 or 'n/a'"
                          % (tier,))

    if "evidence" in raw:
        evidence = raw["evidence"]
        if isinstance(evidence, str):
            if not evidence.strip():
                errors.append("evidence must be a string or list of non-empty strings")
            else:
                finding["evidence"] = [evidence.strip()]
        elif isinstance(evidence, list):
            if not evidence or not all(isinstance(item, str) and item.strip() != "" for item in evidence):
                errors.append("evidence must be a string or list of non-empty strings")
            else:
                finding["evidence"] = [item.strip() for item in evidence]
        else:
            errors.append("evidence must be a string or list of non-empty strings")

    for field in ("poc", "remediation", "detection"):
        if field in raw and isinstance(raw[field], str) and raw[field].strip():
            finding[field] = raw[field].strip()

    if "description" in raw and isinstance(raw["description"], str) and raw["description"].strip():
        finding["description"] = raw["description"].strip()
    elif not errors and "description" not in raw:
        warnings.append("description missing - required in the delivered "
                        "record per finding-template.md; [gap] marker "
                        "emitted")

    return finding, errors, warnings


def verify_evidence_on_disk(finding, evidence_dir):
    """Verify every referenced evidence file exists under evidence_dir and is >0 bytes."""
    import os
    errors = []
    for ref in finding.get("evidence", []):
        if ref.startswith("evd_") and "/" not in ref and "." not in ref:
            continue
        target = ref if os.path.isabs(ref) else os.path.join(evidence_dir, ref)
        if not os.path.isfile(target):
            errors.append("evidence file not found on disk: %r" % ref)
        elif os.path.getsize(target) == 0:
            errors.append("evidence file is empty (0 bytes): %r" % ref)
    return errors


COMPLIANCE_MAPPINGS = {
    # Broken Access Control / IDOR
    "CWE-22": {
        "iso": "A.5.15, A.8.20, A.8.24, A.8.28",
        "nist": "PR.AA-05, PR.DS-01, PR.PS-01",
        "cis": "Control 3.3, Control 16.3",
        "owasp": "A01:2021-Broken Access Control, API1:2023-Broken Object Level Authorization",
    },
    "CWE-284": {
        "iso": "A.5.15, A.8.2, A.8.3",
        "nist": "PR.AA-01, PR.AA-05",
        "cis": "Control 6 (6.8), Control 16 (16.10)",
        "owasp": "A01:2021 (Broken Access Control) / API1:2023, API5:2023",
    },
    "CWE-639": {
        "iso": "A.5.15, A.8.2, A.8.3",
        "nist": "PR.AA-01, PR.AA-05",
        "cis": "Control 6 (6.8), Control 16 (16.10)",
        "owasp": "A01:2021 (Broken Access Control) / API1:2023 (BOLA)",
    },
    "CWE-862": {
        "iso": "A.5.15, A.8.2, A.8.3",
        "nist": "PR.AA-01, PR.AA-05",
        "cis": "Control 6 (6.8), Control 16 (16.10)",
        "owasp": "A01:2021 (Broken Access Control) / API5:2023 (BFLA)",
    },
    # Cryptographic Failures
    "CWE-327": {
        "iso": "A.8.24",
        "nist": "PR.DS-01, PR.DS-02",
        "cis": "Control 3 (3.10, 3.11)",
        "owasp": "A02:2021 (Cryptographic Failures) / API2:2023",
    },
    "CWE-319": {
        "iso": "A.8.20, A.8.24",
        "nist": "PR.DS-02",
        "cis": "Control 3 (3.10)",
        "owasp": "A02:2021 (Cryptographic Failures) / API2:2023",
    },
    "CWE-347": {
        "iso": "A.8.24",
        "nist": "PR.DS-01, PR.DS-02",
        "cis": "Control 3 (3.10, 3.11)",
        "owasp": "A02:2021 (Cryptographic Failures) / API2:2023",
    },
    "CWE-295": {
        "iso": "A.8.20, A.8.24",
        "nist": "PR.DS-02",
        "cis": "Control 3 (3.10)",
        "owasp": "A02:2021 (Cryptographic Failures)",
    },
    # Injection
    "CWE-89": {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.PS-01, DE.CM-01",
        "cis": "Control 16 (16.12, 16.13)",
        "owasp": "A03:2021 (Injection) / API8:2023",
    },
    "CWE-78": {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.PS-01, DE.CM-01",
        "cis": "Control 16 (16.12, 16.13)",
        "owasp": "A03:2021 (Injection) / API8:2023",
    },
    "CWE-1336": {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.PS-01, DE.CM-01",
        "cis": "Control 16 (16.12, 16.13)",
        "owasp": "A03:2021 (Injection) / API8:2023",
    },
    "CWE-94": {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.PS-01, DE.CM-01",
        "cis": "Control 16 (16.12, 16.13)",
        "owasp": "A03:2021 (Injection) / API8:2023",
    },
    "CWE-79": {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.PS-01, DE.CM-01",
        "cis": "Control 16 (16.12)",
        "owasp": "A03:2021 (Injection) / API8:2023",
    },
    # Insecure Design & Business Logic
    "CWE-840": {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.AA-05, PR.IR-02",
        "cis": "Control 16 (16.10, 16.13)",
        "owasp": "A04:2021 (Insecure Design) / API6:2023",
    },
    "CWE-362": {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.AA-05, PR.IR-02",
        "cis": "Control 16 (16.10, 16.13)",
        "owasp": "A04:2021 (Insecure Design) / API6:2023",
    },
    "CWE-670": {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.AA-05, PR.IR-02",
        "cis": "Control 16 (16.10, 16.13)",
        "owasp": "A04:2021 (Insecure Design) / API6:2023",
    },
    # Security Misconfiguration & WAF
    "CWE-16": {
        "iso": "A.8.9, A.8.20, A.8.21",
        "nist": "PR.PS-01, PR.IR-01",
        "cis": "Control 4 (4.1, 4.8), Control 13 (13.4)",
        "owasp": "A05:2021 (Security Misconfiguration) / API8:2023",
    },
    "CWE-942": {
        "iso": "A.8.9, A.8.20, A.8.21",
        "nist": "PR.PS-01, PR.IR-01",
        "cis": "Control 4 (4.1, 4.8), Control 13 (13.4)",
        "owasp": "A05:2021 (Security Misconfiguration) / API8:2023",
    },
    "CWE-693": {
        "iso": "A.8.9, A.8.20, A.8.21",
        "nist": "PR.PS-01, PR.IR-01",
        "cis": "Control 4 (4.1, 4.8), Control 13 (13.4)",
        "owasp": "A05:2021 (Security Misconfiguration) / API8:2023",
    },
    "CWE-200": {
        "iso": "A.8.3, A.8.9",
        "nist": "PR.DS-01, PR.PS-01",
        "cis": "Control 3 (3.11), Control 4 (4.1)",
        "owasp": "A05:2021 (Security Misconfiguration) / API8:2023",
    },
    # Vulnerable Components
    "CWE-1104": {
        "iso": "A.8.8",
        "nist": "PR.PS-02, ID.AM-02",
        "cis": "Control 7 (7.1, 7.7), Control 16 (16.4)",
        "owasp": "A06:2021 (Vulnerable and Outdated Components) / API9:2023",
    },
    "CWE-1395": {
        "iso": "A.8.8",
        "nist": "PR.PS-02, ID.AM-02",
        "cis": "Control 7 (7.1, 7.7), Control 16 (16.4)",
        "owasp": "A06:2021 (Vulnerable and Outdated Components) / API9:2023",
    },
    # Authentication & Session
    "CWE-287": {
        "iso": "A.5.15, A.8.5, A.8.26",
        "nist": "PR.AA-01, PR.AA-03, DE.CM-03",
        "cis": "Control 5 (5.1, 5.4), Control 6 (6.3, 6.5)",
        "owasp": "A07:2021 (Identification and Authentication Failures) / API2:2023",
    },
    "CWE-307": {
        "iso": "A.8.5",
        "nist": "PR.AA-03, DE.CM-03",
        "cis": "Control 6 (6.5)",
        "owasp": "A07:2021 (Identification and Authentication Failures) / API2:2023",
    },
    "CWE-294": {
        "iso": "A.8.5",
        "nist": "PR.AA-03",
        "cis": "Control 6 (6.3)",
        "owasp": "A07:2021 (Identification and Authentication Failures) / API2:2023",
    },
    "CWE-384": {
        "iso": "A.8.5",
        "nist": "PR.AA-01",
        "cis": "Control 5 (5.4)",
        "owasp": "A07:2021 (Identification and Authentication Failures)",
    },
    "CWE-613": {
        "iso": "A.8.5",
        "nist": "PR.AA-01",
        "cis": "Control 5 (5.4)",
        "owasp": "A07:2021 (Identification and Authentication Failures)",
    },
    "CWE-306": {
        "iso": "A.5.15, A.8.5",
        "nist": "PR.AA-01, PR.AA-03",
        "cis": "Control 5 (5.4), Control 6 (6.3)",
        "owasp": "A07:2021 (Identification and Authentication Failures) / API2:2023",
    },
    # Software & Data Integrity
    "CWE-502": {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.PS-01, PR.DS-10",
        "cis": "Control 16 (16.4, 16.13)",
        "owasp": "A08:2021 (Software and Data Integrity Failures) / API8:2023",
    },
    # Logging & Telemetry
    "CWE-778": {
        "iso": "A.8.15, A.8.16",
        "nist": "PR.PS-04, DE.CM-01, DE.CM-09",
        "cis": "Control 8 (8.2, 8.5, 8.9), Control 13 (13.1)",
        "owasp": "A09:2021 (Security Logging and Monitoring Failures) / API10:2023",
    },
    "CWE-117": {
        "iso": "A.8.15, A.8.28",
        "nist": "PR.PS-04, DE.CM-01",
        "cis": "Control 8 (8.2), Control 16 (16.12)",
        "owasp": "A09:2021 (Security Logging and Monitoring Failures) / API10:2023",
    },
    "CWE-532": {
        "iso": "A.8.15, A.8.24",
        "nist": "PR.DS-01, PR.PS-04",
        "cis": "Control 3 (3.11), Control 8 (8.2)",
        "owasp": "A09:2021 (Security Logging and Monitoring Failures)",
    },
    # SSRF
    "CWE-918": {
        "iso": "A.8.20, A.8.26, A.8.28",
        "nist": "PR.PS-01, PR.AA-05",
        "cis": "Control 13 (13.4), Control 16 (16.10)",
        "owasp": "A10:2021 (Server-Side Request Forgery) / API7:2023",
    },
    # CSRF
    "CWE-352": {
        "iso": "A.8.26",
        "nist": "PR.AA-05, PR.PS-01",
        "cis": "Control 16 (16.10)",
        "owasp": "A01:2021 (Broken Access Control) / API1:2023",
    },
}


def get_compliance_mapping(cwe):
    """Return dictionary with iso, nist, cis, owasp mappings for a canonical CWE."""
    if cwe in COMPLIANCE_MAPPINGS:
        return COMPLIANCE_MAPPINGS[cwe]
    return {
        "iso": "A.8.26, A.8.28",
        "nist": "PR.PS-01",
        "cis": "Control 16",
        "owasp": "Unclassified (see references/compliance-mapping.md)",
    }


def _cell(value):
    """Markdown table cell: pipes escaped, newlines flattened."""
    return (str(value)
            .replace("|", "\\|")
            .replace("\r\n", " ")
            .replace("\r", " ")
            .replace("\n", " "))


def render_markdown(finding, compliance=False):
    """-> markdown finding section (shape of finding-template.md)."""
    out = []
    out.append("## %s — %s" % (finding["id"], finding["title"]))
    out.append("")
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append("| Severity | %s (D3-locked) |" % finding["severity"])
    out.append("| CWE | %s |" % _cell(finding["cwe"]))
    out.append("| CVSS | %s |" % _cell(finding["cvss"]))
    out.append("| Affected component | %s %s (fingerprint tier %s) |"
               % (_cell(finding["component"]), _cell(finding["version"]),
                  finding["tier"]))
    out.append("| Evidence | %s |" % _cell("; ".join(finding["evidence"])))
    out.append("")
    out.append("**Description**")
    out.append("")
    out.append(finding.get("description",
                           "[gap] description missing - required before "
                           "delivery per finding-template.md"))
    out.append("")
    out.append("**Proof of concept**")
    out.append("")
    out.append(finding["poc"])
    out.append("")
    out.append("**Remediation**")
    out.append("")
    out.append(finding["remediation"])
    out.append("")
    out.append("**Detection coverage**")
    out.append("")
    out.append(finding["detection"])
    out.append("")
    if compliance:
        cm = get_compliance_mapping(finding.get("cwe", ""))
        out.append("**Compliance mappings**")
        out.append("")
        out.append("| Framework | Control / Standard Citation |")
        out.append("|---|---|")
        out.append("| ISO/IEC 27001:2022 | %s |" % _cell(cm["iso"]))
        out.append("| NIST CSF 2.0 | %s |" % _cell(cm["nist"]))
        out.append("| CIS Controls v8.1 | %s |" % _cell(cm["cis"]))
        out.append("| OWASP Top 10 | %s |" % _cell(cm["owasp"]))
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------- self-test


VALID = {
    "id": "F-001",
    "title": "SQL injection in invoice search via unparameterized q filter",
    "severity": "high",
    "cwe": "CWE-89",
    "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N",
    "component": "billing|api",
    "version": "2.4.1",
    "tier": 1,
    "evidence": ["evidence/p5-api-invoices-003.req.txt",
                 "evidence/p5-api-invoices-003.resp.txt",
                 "evidence/p5-api-invoices-004.req.txt",
                 "evidence/p5-api-invoices-004.resp.txt"],
    "description": "The `q` filter is concatenated into the SQL text. Both "
                   "D2 runs (003/004) returned the canary row.",
    "poc": "curl -sS -i 'https://target.example/api/invoices?q=rj-pt-eng1"
           "-ab12' -H 'Authorization: Bearer <session-token>'",
    "remediation": "Bind the filter value (parameterized query) per "
                   "remediation-library.md SQLi section.",
    "detection": "App log recorded the query error for both runs; no alert "
                 "raised (85 note: gap -> alert on rejection bursts).",
}


def _write(tmp, name, payload):
    import os
    path = os.path.join(tmp, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        if isinstance(payload, str):
            fh.write(payload)
        else:
            json.dump(payload, fh)
    return path


def self_test():
    import io
    import contextlib
    import tempfile

    # 1. valid fixture: normalized, no errors, markdown shape
    finding, errors, warnings = validate(dict(VALID))
    assert not errors, errors
    assert finding["severity"] == "High"
    assert finding["tier"] == 1
    assert len(finding["evidence"]) == 4
    md = render_markdown(finding)
    assert md.startswith("## F-001 — SQL injection in invoice search")
    for needle in ("| Severity | High (D3-locked) |",
                   "| CWE | CWE-89 |",
                   "| CVSS | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N"
                   "/VA:N |",
                   "| Affected component | billing\\|api 2.4.1 "
                   "(fingerprint tier 1) |",       # pipe escaped in cell
                   "evidence/p5-api-invoices-003.req.txt",
                   "**Proof of concept**", "**Remediation**",
                   "**Detection coverage**"):
        assert needle in md, needle

    # 2. tier 'n/a' accepted (config/logic findings); description gap warns
    cfg = {k: v for k, v in VALID.items()
           if k not in ("cwe", "cvss", "tier", "description")}
    cfg.update({"cwe": "CWE-693", "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/"
                "UI:N/VC:N/VI:L/VA:N", "tier": "n/a",
                "evidence": "evidence/p2-web-headers-001.req.txt"})
    finding, errors, warnings = validate(cfg)
    assert not errors, errors
    assert finding["tier"] == "n/a"
    assert any("description" in w for w in warnings)
    assert "[gap] description missing" in render_markdown(finding)

    # 3. invalid fixtures: each must fail with a matching message
    def expect_errors(mutate, needle):
        broken = dict(VALID)
        mutate(broken)
        _f, errors, _w = validate(broken)
        assert errors and any(needle in e for e in errors), \
            (needle, errors)

    expect_errors(lambda d: d.pop("title"), "missing required field 'title'")
    expect_errors(lambda d: d.update(title="   "), "title")
    expect_errors(lambda d: d.update(cwe="CWE89"), "CWE-<int>")
    expect_errors(lambda d: d.update(cwe="cwe-89"), "CWE-<int>")
    expect_errors(lambda d: d.update(cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N"
                                     "/C:H/I:N/A:N"), "CVSS:4")
    expect_errors(lambda d: d.update(severity="Extreme"), "severity")
    expect_errors(lambda d: d.update(tier=9), "tier 9 outside 1-4")
    expect_errors(lambda d: d.update(tier="banner"), "tier")
    expect_errors(lambda d: d.update(evidence=[]), "evidence")
    expect_errors(lambda d: d.update(evidence=["", "  "]), "evidence")

    # Type-confusion tests: invalid non-string inputs rejected gracefully
    expect_errors(lambda d: d.update(cwe=89), "cwe")
    expect_errors(lambda d: d.update(evidence=123), "evidence")
    expect_errors(lambda d: d.update(id=999), "id")
    expect_errors(lambda d: d.update(title=123), "title")
    expect_errors(lambda d: d.update(severity=1), "severity")
    expect_errors(lambda d: d.update(cvss=40), "cvss")
    expect_errors(lambda d: d.update(component=123), "component")
    expect_errors(lambda d: d.update(version=1), "version")
    expect_errors(lambda d: d.update(poc=123), "poc")
    expect_errors(lambda d: d.update(remediation=123), "remediation")
    expect_errors(lambda d: d.update(detection=123), "detection")
    expect_errors(lambda d: d.update(description=123), "description")
    expect_errors(lambda d: d.update(cwe=["CWE-89"]), "cwe")
    expect_errors(lambda d: d.update(evidence=[123]), "evidence")

    # Partial/type-confused dict validation without crashes
    _f, errs, _w = validate({"cwe": 89, "evidence": 123})
    assert len(errs) > 0
    assert any("cwe" in e for e in errs)
    assert any("evidence" in e for e in errs)

    # Carriage return & pipe escaping in table cells
    assert _cell("test\r\nline") == "test line"
    assert _cell("test\rline") == "test line"
    assert _cell("test\nline") == "test line"
    assert _cell("test|line") == "test\\|line"

    _f, errors, _w = validate(["not", "a", "dict"])
    assert errors and "object" in errors[0]
    _f, _e, warnings2 = validate(dict(VALID, id="finding-1", extra=1))
    assert any("F-NNN" in w for w in warnings2)
    assert any("extra" in w for w in warnings2)

    # 4. end-to-end through main(): exit codes, --evidence-dir, and output
    with tempfile.TemporaryDirectory() as tmp:
        good = _write(tmp, "f-valid.json", VALID)
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--finding", good])
        assert code == 0, err.getvalue()
        assert buf.getvalue().startswith("## F-001")

        # --evidence-dir fails when referenced evidence files do not exist
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--finding", good, "--evidence-dir", tmp])
        assert code == 1 and "evidence file not found" in err.getvalue()

        # create the referenced evidence files and re-verify
        for rel in VALID["evidence"]:
            _write(tmp, rel, "HTTP/1.1 200 OK\n\nbody\n")
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--finding", good, "--evidence-dir", tmp])
        assert code == 0, err.getvalue()

        bad = _write(tmp, "f-invalid.json",
                     dict(VALID, cwe="89", severity="Extreme", tier=7))
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--finding", bad])
        assert code == 1
        assert "[invalid]" in err.getvalue()
        assert "cwe" in err.getvalue() and "severity" in err.getvalue() \
            and "tier" in err.getvalue()

        bad_type = _write(tmp, "f-type-error.json",
                          dict(VALID, cwe=89, evidence=123, id=999))
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--finding", bad_type])
        assert code == 1
        assert "[invalid]" in err.getvalue()
        assert "cwe" in err.getvalue() and "evidence" in err.getvalue() and "id" in err.getvalue()

        malformed = _write(tmp, "f-bad.json", "{not json")
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--finding", malformed])
        assert code == 1 and "[error]" in err.getvalue()

        missing = tmp + "/does-not-exist.json"
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--finding", missing])
        assert code == 1 and "[error]" in err.getvalue()

        # 5. --compliance flag end-to-end and lookup assertions
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--finding", good, "--compliance"])
        assert code == 0, err.getvalue()
        c_out = buf.getvalue()
        assert "**Compliance mappings**" in c_out
        assert "ISO/IEC 27001:2022" in c_out
        assert "NIST CSF 2.0" in c_out
        assert "CIS Controls v8.1" in c_out
        assert "OWASP Top 10" in c_out
        assert "A.8.26, A.8.28" in c_out
        assert "Control 16" in c_out

        # Test CWE-22 compliance rendering
        cwe22_file = _write(tmp, "f-cwe22.json", dict(VALID, cwe="CWE-22"))
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--finding", cwe22_file, "--compliance"])
        assert code == 0, err.getvalue()
        c22_out = buf.getvalue()
        assert "A.5.15, A.8.20, A.8.24, A.8.28" in c22_out
        assert "PR.AA-05, PR.DS-01, PR.PS-01" in c22_out
        assert "Control 3.3, Control 16.3" in c22_out
        assert "A01:2021-Broken Access Control" in c22_out

        # Direct compliance cross-walk mapping tests
        c22 = get_compliance_mapping("CWE-22")
        assert "A.5.15" in c22["iso"] and "A.8.20" in c22["iso"]
        assert "PR.AA-05" in c22["nist"] and "PR.DS-01" in c22["nist"]
        assert "Control 3.3" in c22["cis"] and "Control 16.3" in c22["cis"]
        assert "A01:2021" in c22["owasp"] and "API1:2023" in c22["owasp"]

        c284 = get_compliance_mapping("CWE-284")
        assert "A.5.15" in c284["iso"] and "PR.AA-01" in c284["nist"]
        c_unmapped = get_compliance_mapping("CWE-9999")
        assert "Unclassified" in c_unmapped["owasp"]

    print("[self-test] finding_format: valid fixture rendered (severity "
          "normalized, tier n/a accepted, table pipe/CR escaping, description "
          "[gap] warning), compliance cross-walk rendering (ISO/IEC 27001, "
          "NIST CSF 2.0, CIS Controls, OWASP Top 10 with CWE-22), invalid cases "
          "rejected (type-confusion gracefully handled, missing/empty title, "
          "CWE89/cwe-89, CVSS:3.1, bad severity, tier 9/'banner', empty/blank "
          "evidence, non-object), --evidence-dir provenance check, id/unknown-field "
          "warnings, end-to-end exit codes 0/1 - passed")


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main(argv=None):
    parser = _Parser(
        description="Validate a finding JSON against the 90-evidence-"
                    "reporting field contract and emit the markdown "
                    "finding section (offline, stdlib only).")
    parser.add_argument("--finding", help="path to the finding JSON file "
                        "(fields: id,title,severity,cwe,cvss,component,"
                        "version,tier,evidence,poc,remediation,detection;"
                        " optional: description)")
    parser.add_argument("--evidence-dir", default=None,
                        help="optional directory to verify referenced "
                             "evidence files exist and are non-empty on disk")
    parser.add_argument("--compliance", action="store_true",
                        help="include compliance framework mappings "
                             "(ISO 27001:2022, NIST CSF 2.0, CIS Controls "
                             "v8.1, OWASP Top 10) in rendered output")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if not args.finding:
        parser.error("--finding is required (or --self-test)")

    try:
        with open(args.finding, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.stderr.write("[error] cannot read %s: %s\n" % (args.finding, exc))
        return 1

    finding, errors, warnings = validate(raw)
    if not errors and args.evidence_dir is not None:
        errors.extend(verify_evidence_on_disk(finding, args.evidence_dir))
    if errors:
        sys.stderr.write("[invalid] finding rejected (%d error(s)):\n"
                         % len(errors))
        for error in errors:
            sys.stderr.write("  - %s\n" % error)
        sys.stderr.write("fix the JSON; do not hand-edit around the "
                         "validator.\n")
        return 1

    for warning in warnings:
        sys.stderr.write("[warning] %s\n" % warning)
    sys.stderr.write("[evidence] findings cite evidence/"
                     "<phase>-<surface>-<seq>.<req|resp>.txt pairs - both "
                     "D2 runs.\n")
    sys.stdout.write(render_markdown(finding, compliance=args.compliance) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
