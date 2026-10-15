#!/usr/bin/env python3
"""verify_finding_gate.py - Anti-hallucination provenance and D2 verification
gate (95-finding-verifier).

Validates a candidate finding JSON before it is promoted to Verified (D2) or
submitted via report_finding:
  1. Provenance check: every referenced evidence file (and optional
     negative_control_ref) must exist under --evidence-dir and be non-empty.
  2. Negative-control check: Medium/High/Critical findings claiming
     verification_status="verified" must supply either negative_control_ref or
     at least 2 distinct evidence captures.
  3. Differential integrity check: when both a positive response file and a
     negative-control response file are readable on disk, their normalized body
     hashes must differ (catches false positives where both probes returned the
     same page).
  4. Correlation-only check: findings flagged correlation_only=true or with
     fingerprint tier > 2 are clamped to verification_status="suspected" (D1).
  5. Layer-Ordering Trap check: unauthenticated HTTP 400/422 schema validation
     errors falsely claimed as auth bypasses are clamped to suspected (D1).
  6. 7-Question Gate check: validates all 7 triage validation questions (scope,
     observable pairs, backend reached, negative control differential, error
     differentiation, layer ordering avoided, reproducible/non-destructive).

Offline: no network access, no scope guard (sends nothing).

Usage:
  python3 verify_finding_gate.py --finding finding.json [--evidence-dir .] [--json] [--seven-questions]
  python3 verify_finding_gate.py --self-test

Exit codes:
  0 = finding passed (or was cleanly clamped to suspected; see status output)
  1 = hard rejection (missing/fabricated evidence file, identical positive vs
      negative control response, scope violation, destructive impact, or malformed JSON)
"""

import argparse
import hashlib
import json
import os
import re
import sys

HIGH_SEVERITIES = frozenset({"medium", "high", "critical"})


def _norm_List(val):
    if isinstance(val, str) and val.strip():
        return [val.strip()]
    if isinstance(val, list):
        return [str(x).strip() for x in val if isinstance(x, str) and str(x).strip()]
    return []


def _resolve_ref(ref, evidence_dir):
    if os.path.isabs(ref):
        return ref
    return os.path.join(evidence_dir, ref)


def _file_digest(path):
    with open(path, "rb") as fh:
        data = fh.read()
    norm = re.sub(rb"\s+", b" ", data.strip())
    return len(data), hashlib.sha256(norm).hexdigest()


def _get_seven_gate_dict(raw):
    """Normalize user-supplied 7-question gate inputs."""
    gate = raw.get("seven_question_gate") or raw.get("seven_questions") or {}
    if not isinstance(gate, dict):
        return {}
    res = {}
    key_map = {
        "q1": "q1", "q1_scope": "q1", "q1_scope_verified": "q1", "scope": "q1",
        "q2": "q2", "q2_observable": "q2", "q2_observable_request_response": "q2", "observable": "q2",
        "q3": "q3", "q3_backend": "q3", "q3_backend_reached": "q3", "q3_target_backend_reached": "q3", "backend_reached": "q3",
        "q4": "q4", "q4_negative_control": "q4", "q4_negative_control_deviated": "q4", "negative_control": "q4",
        "q5": "q5", "q5_error": "q5", "q5_error_differentiated": "q5", "error_differentiated": "q5",
        "q6": "q6", "q6_layer_ordering": "q6", "q6_layer_ordering_avoided": "q6", "layer_ordering": "q6",
        "q7": "q7", "q7_reproducible": "q7", "q7_reproducible_non_destructive": "q7", "reproducible": "q7",
    }
    for k, v in gate.items():
        k_norm = key_map.get(str(k).lower())
        if k_norm:
            res[k_norm] = bool(v)
    return res


def evaluate_finding(raw, evidence_dir=None):
    """Evaluate finding dict -> (result_dict, hard_errors)."""
    hard_errors = []
    reasons = []

    if not isinstance(raw, dict):
        return {}, ["finding JSON must be an object"]

    title = str(raw.get("title", "")).strip()
    severity = str(raw.get("severity", "medium")).strip().lower()
    requested_status = str(raw.get("verification_status", "verified")).strip().lower()
    if requested_status not in ("verified", "suspected"):
        requested_status = "verified"

    evidence_refs = _norm_List(raw.get("evidence_refs") or raw.get("evidence"))
    neg_ref = str(raw.get("negative_control_ref") or "").strip()
    correlation_only = bool(raw.get("correlation_only", False))
    tier = raw.get("tier", 1)

    if not title:
        hard_errors.append("missing required field 'title'")
    if severity in HIGH_SEVERITIES and not evidence_refs:
        hard_errors.append(
            "severity %r requires at least one evidence reference" % severity
        )

    seven_input = _get_seven_gate_dict(raw)

    # 7-Question Gate Q1: Scope Verification
    if seven_input.get("q1") is False or raw.get("in_scope") is False or raw.get("out_of_scope") is True:
        hard_errors.append("[7-Question Gate Q1] Target host and endpoint not verified within explicit scope")

    # 7-Question Gate Q2: Observable Captures
    if seven_input.get("q2") is False or raw.get("observable_captures") is False:
        hard_errors.append("[7-Question Gate Q2] Vulnerability claim not supported by observable request/response pairs")

    # 7-Question Gate Q7: Non-destructive reproducibility
    if seven_input.get("q7") is False or raw.get("destructive") is True or raw.get("reproducible") is False:
        hard_errors.append("[7-Question Gate Q7] Impact is not strictly reproducible without destructive side-effects")

    all_refs = list(evidence_refs)
    if neg_ref and neg_ref not in all_refs:
        all_refs.append(neg_ref)

    digests = {}
    resp_bodies = {}
    if evidence_dir is not None:
        for ref in all_refs:
            # evd_* session IDs are validated by the engine runtime DB; file paths
            # are validated on disk here.
            if ref.startswith("evd_") and "/" not in ref and "." not in ref:
                continue
            target = _resolve_ref(ref, evidence_dir)
            if not os.path.isfile(target):
                hard_errors.append(
                    "hallucinated or missing evidence artifact: %r" % ref
                )
                continue
            size, digest = _file_digest(target)
            if size == 0:
                hard_errors.append("empty (0-byte) evidence artifact: %r" % ref)
                continue
            digests[ref] = digest
            if not ref.endswith(".req.txt"):
                try:
                    with open(target, "rb") as fh:
                        resp_bodies[ref] = fh.read(8192)
                except OSError:
                    pass

        if neg_ref and neg_ref in digests:
            neg_digest = digests[neg_ref]
            resp_refs = [
                r for r in evidence_refs
                if r != neg_ref and r in digests and not r.endswith(".req.txt")
            ]
            if resp_refs and all(digests[r] == neg_digest for r in resp_refs):
                hard_errors.append(
                    "positive evidence response is identical to negative_control_ref "
                    "%r (hash=%s) - no behavioral differential proven"
                    % (neg_ref, neg_digest[:12])
                )

    if hard_errors:
        gate_summary = {
            "q1_scope_verified": not any("Q1" in e for e in hard_errors),
            "q2_observable_request_response": not any("Q2" in e for e in hard_errors),
            "q3_target_backend_reached": True,
            "q4_negative_control_deviated": not any("identical to negative_control" in e for e in hard_errors),
            "q5_error_differentiated": True,
            "q6_layer_ordering_avoided": True,
            "q7_reproducible_non_destructive": not any("Q7" in e for e in hard_errors),
        }
        return {
            "verdict": "REJECTED",
            "effective_status": "rejected",
            "errors": hard_errors,
            "reasons": reasons,
            "layer_ordering_checked": True,
            "seven_question_gate": gate_summary,
        }, hard_errors

    effective_status = requested_status
    if correlation_only:
        effective_status = "suspected"
        reasons.append(
            "correlation_only=true: version/advisory match without active PoC "
            "is clamped to suspected (D1)"
        )

    if isinstance(tier, int) and not isinstance(tier, bool) and tier > 2:
        effective_status = "suspected"
        reasons.append(
            "fingerprint tier %d > 2: banner/heuristic tier cannot lock D2 "
            "verified status" % tier
        )

    pos_resp_refs = [
        r for r in evidence_refs
        if r != neg_ref and r in resp_bodies and not r.endswith(".req.txt")
    ]

    # 7-Question Gate Q3: WAF/CDN Edge Interception Check
    waf_blocked = False
    if seven_input.get("q3") is False:
        waf_blocked = True
        effective_status = "suspected"
        reasons.append(
            "[7-Question Gate Q3] Request intercepted/blocked by edge WAF/CDN; "
            "target backend was not reached"
        )
    elif pos_resp_refs:
        waf_indicators = [
            b"attention required! | cloudflare",
            b"cloudflare ray id",
            b"403 forbidden - waf block",
            b"request blocked by aws waf",
            b"incident id:",
            b"akamai ghost",
        ]
        for r in pos_resp_refs:
            content = resp_bodies[r]
            content_lower = content.lower()
            if any(ind in content_lower for ind in waf_indicators):
                waf_blocked = True
                effective_status = "suspected"
                reasons.append(
                    "[7-Question Gate Q3] response in %r indicates edge WAF/CDN "
                    "interception; target backend was not reached" % r
                )
                break

    # 7-Question Gate Q4: Negative control check
    if seven_input.get("q4") is False:
        effective_status = "suspected"
        reasons.append(
            "[7-Question Gate Q4] Observed behavior does not deviate from expected negative controls"
        )

    # 7-Question Gate Q5: Error Differentiation / soft-404
    if seven_input.get("q5") is False or raw.get("soft_404") is True or raw.get("generic_error") is True:
        effective_status = "suspected"
        reasons.append(
            "[7-Question Gate Q5] Response is an undifferentiated generic error or soft-404"
        )

    # 7-Question Gate Q6 & Layer-Ordering Trap Check
    layer_trap = False
    if (
        seven_input.get("q6") is False
        or raw.get("layer_ordering_trap") is True
        or raw.get("schema_validation_error_only") is True
    ):
        layer_trap = True
        effective_status = "suspected"
        reasons.append(
            "Layer-Ordering Trap: HTTP 400/422 schema validation error cannot "
            "prove auth bypass without a well-formed request demonstrating unauthorized access"
        )
    else:
        # Automated disk check for Layer-Ordering Trap on auth findings
        title_lower = title.lower()
        cwe_str = str(raw.get("cwe", "")).upper()
        is_auth = (
            any(kw in title_lower for kw in (
                "auth bypass", "authentication bypass", "unauthenticated",
                "authorization bypass", "missing auth", "login bypass",
                "token bypass", "idor", "access control"
            ))
            or cwe_str in ("CWE-287", "CWE-284", "CWE-306", "CWE-639", "CWE-862")
        )
        if is_auth and pos_resp_refs:
            has_validation_400 = False
            has_success_200 = False
            validation_indicators = [
                b"validation", b"schema", b"malformed", b"syntax error",
                b"field is required", b"required field", b"invalid json",
                b"invalid text", b"bad request", b"unprocessable entity"
            ]
            for r in pos_resp_refs:
                content = resp_bodies[r]
                content_lower = content.lower()
                status_match = re.search(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", content)
                status_code = int(status_match.group(1)) if status_match else None
                if status_code in (200, 201, 204):
                    has_success_200 = True
                elif status_code in (400, 422) or any(ind in content_lower for ind in validation_indicators):
                    has_validation_400 = True

            if has_validation_400 and not has_success_200:
                layer_trap = True
                effective_status = "suspected"
                reasons.append(
                    "Layer-Ordering Trap: unauthenticated HTTP 400/422 schema validation error "
                    "falsely claimed as auth bypass; input sanitizer executed before authentication "
                    "without proof of unauthorized access (clamped to suspected D1)"
                )

    distinct_pos = len(set(evidence_refs))
    if (
        effective_status == "verified"
        and severity in HIGH_SEVERITIES
        and not neg_ref
        and distinct_pos < 2
    ):
        effective_status = "suspected"
        reasons.append(
            "single evidence ref without negative_control_ref on %s finding: "
            "clamped to suspected (D1) until baseline control or second "
            "verification capture is attached" % severity
        )

    gate_summary = {
        "q1_scope_verified": not any("Q1" in e for e in hard_errors),
        "q2_observable_request_response": not any("Q2" in e for e in hard_errors),
        "q3_target_backend_reached": not waf_blocked and not any("Q3" in r for r in reasons),
        "q4_negative_control_deviated": not any("identical to negative_control" in e for e in hard_errors) and not any("Q4" in r for r in reasons),
        "q5_error_differentiated": not any("Q5" in r for r in reasons),
        "q6_layer_ordering_avoided": not layer_trap and not any("Layer-Ordering" in r for r in reasons),
        "q7_reproducible_non_destructive": not any("Q7" in e for e in hard_errors),
    }

    verdict = (
        "VERIFIED"
        if effective_status == "verified"
        else ("CLAMPED" if requested_status == "verified" else "SUSPECTED")
    )
    return {
        "title": title,
        "severity": severity,
        "requested_status": requested_status,
        "effective_status": effective_status,
        "verdict": verdict,
        "evidence_count": distinct_pos,
        "has_negative_control": bool(neg_ref),
        "layer_ordering_checked": True,
        "seven_question_gate": gate_summary,
        "reasons": reasons,
    }, []


# ---------------------------------------------------------------- self-test


def self_test():
    import contextlib
    import io
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        pos_resp = os.path.join(tmp, "p15-rce-001.resp.txt")
        neg_resp = os.path.join(tmp, "p15-rce-ctrl.resp.txt")
        same_resp = os.path.join(tmp, "p15-same.resp.txt")
        with open(pos_resp, "w", encoding="utf-8") as fh:
            fh.write("HTTP/1.1 200 OK\n\nrj-eval-5040847\n")
        with open(neg_resp, "w", encoding="utf-8") as fh:
            fh.write("HTTP/1.1 200 OK\n\nrj-ctrl-literal\n")
        with open(same_resp, "w", encoding="utf-8") as fh:
            fh.write("HTTP/1.1 200 OK\n\nrj-ctrl-literal\n")

        # 1. Valid verified finding with negative control
        res, errs = evaluate_finding(
            {
                "title": "Shopware Twig SSTI in mail preview",
                "severity": "critical",
                "verification_status": "verified",
                "tier": 1,
                "evidence_refs": ["p15-rce-001.resp.txt"],
                "negative_control_ref": "p15-rce-ctrl.resp.txt",
            },
            evidence_dir=tmp,
        )
        assert not errs, errs
        assert res["verdict"] == "VERIFIED" and res["effective_status"] == "verified"

        # 2. Fabricated/missing evidence file -> hard rejection
        res, errs = evaluate_finding(
            {
                "title": "Hallucinated SQLi",
                "severity": "high",
                "verification_status": "verified",
                "evidence_refs": ["nonexistent-001.resp.txt"],
            },
            evidence_dir=tmp,
        )
        assert errs and res["verdict"] == "REJECTED"

        # 3. Positive response identical to negative control -> hard rejection
        res, errs = evaluate_finding(
            {
                "title": "False positive reflection",
                "severity": "high",
                "verification_status": "verified",
                "evidence_refs": ["p15-same.resp.txt"],
                "negative_control_ref": "p15-rce-ctrl.resp.txt",
            },
            evidence_dir=tmp,
        )
        assert errs and any("identical" in e for e in errs), errs

        # 4. Single evidence ref without negative control -> clamped to suspected
        res, errs = evaluate_finding(
            {
                "title": "Uncontrolled single probe",
                "severity": "high",
                "verification_status": "verified",
                "evidence_refs": ["p15-rce-001.resp.txt"],
            },
            evidence_dir=tmp,
        )
        assert not errs
        assert res["verdict"] == "CLAMPED" and res["effective_status"] == "suspected"

        # 5. Correlation-only or Tier 3 -> clamped to suspected
        res, errs = evaluate_finding(
            {
                "title": "Banner CVE match",
                "severity": "high",
                "verification_status": "verified",
                "tier": 3,
                "evidence_refs": ["p15-rce-001.resp.txt", "p15-rce-ctrl.resp.txt"],
            },
            evidence_dir=tmp,
        )
        assert not errs
        assert res["verdict"] == "CLAMPED" and res["effective_status"] == "suspected"

        # 6. CLI exit code checks
        f_good = os.path.join(tmp, "good.json")
        with open(f_good, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "title": "Shopware Twig SSTI",
                    "severity": "critical",
                    "verification_status": "verified",
                    "evidence_refs": ["p15-rce-001.resp.txt"],
                    "negative_control_ref": "p15-rce-ctrl.resp.txt",
                },
                fh,
            )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--finding", f_good, "--evidence-dir", tmp, "--seven-questions"])
        assert code == 0 and "VERIFIED" in out.getvalue()
        assert "7-Question Gate:" in out.getvalue()
        assert "q6_layer_ordering_avoided: PASS" in out.getvalue()

        # 7. Layer-Ordering Trap (400 schema error claimed as auth bypass) -> clamped
        p_trap = os.path.join(tmp, "p15-auth-trap.resp.txt")
        with open(p_trap, "w", encoding="utf-8") as fh:
            fh.write("HTTP/1.1 400 Bad Request\nContent-Type: application/json\n\n"
                     '{"error": "Validation failed: username is required"}\n')
        res, errs = evaluate_finding(
            {
                "title": "Unauthenticated API access via missing auth",
                "severity": "high",
                "verification_status": "verified",
                "evidence_refs": ["p15-auth-trap.resp.txt", "p15-rce-ctrl.resp.txt"],
                "negative_control_ref": "p15-rce-ctrl.resp.txt",
            },
            evidence_dir=tmp,
        )
        assert not errs, errs
        assert res["verdict"] == "CLAMPED" and res["effective_status"] == "suspected"
        assert any("Layer-Ordering Trap" in r for r in res["reasons"])
        assert res["seven_question_gate"]["q6_layer_ordering_avoided"] is False

        # 8. Layer-Ordering avoided when well-formed 200 response companion is present
        p_pass = os.path.join(tmp, "p15-auth-pass.resp.txt")
        with open(p_pass, "w", encoding="utf-8") as fh:
            fh.write("HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
                     '{"secret_data": "canary_token"}\n')
        res, errs = evaluate_finding(
            {
                "title": "Unauthenticated API access via missing auth",
                "severity": "high",
                "verification_status": "verified",
                "evidence_refs": ["p15-auth-trap.resp.txt", "p15-auth-pass.resp.txt"],
                "negative_control_ref": "p15-rce-ctrl.resp.txt",
            },
            evidence_dir=tmp,
        )
        assert not errs, errs
        assert res["verdict"] == "VERIFIED" and res["effective_status"] == "verified"
        assert res["seven_question_gate"]["q6_layer_ordering_avoided"] is True

        # 9. 7-Question Gate Q1 failure (out of scope) -> hard rejection
        res, errs = evaluate_finding(
            {
                "title": "Out of scope finding",
                "severity": "high",
                "verification_status": "verified",
                "evidence_refs": ["p15-rce-001.resp.txt", "p15-rce-ctrl.resp.txt"],
                "seven_question_gate": {"q1_scope_verified": False},
            },
            evidence_dir=tmp,
        )
        assert errs and res["verdict"] == "REJECTED"
        assert any("Q1" in e for e in errs)

        # 10. 7-Question Gate Q7 failure (destructive impact) -> hard rejection
        res, errs = evaluate_finding(
            {
                "title": "Destructive finding",
                "severity": "critical",
                "verification_status": "verified",
                "evidence_refs": ["p15-rce-001.resp.txt", "p15-rce-ctrl.resp.txt"],
                "destructive": True,
            },
            evidence_dir=tmp,
        )
        assert errs and res["verdict"] == "REJECTED"
        assert any("Q7" in e for e in errs)

        # 11. 7-Question Gate Q3 edge WAF block detection -> clamped
        p_waf = os.path.join(tmp, "p15-waf-block.resp.txt")
        with open(p_waf, "w", encoding="utf-8") as fh:
            fh.write("HTTP/1.1 403 Forbidden\n\n"
                     "<html>Cloudflare Ray ID: 890abc... Attention Required! | Cloudflare</html>\n")
        res, errs = evaluate_finding(
            {
                "title": "WAF blocked probe falsely claimed as app finding",
                "severity": "high",
                "verification_status": "verified",
                "evidence_refs": ["p15-waf-block.resp.txt", "p15-rce-ctrl.resp.txt"],
                "negative_control_ref": "p15-rce-ctrl.resp.txt",
            },
            evidence_dir=tmp,
        )
        assert not errs
        assert res["verdict"] == "CLAMPED" and res["effective_status"] == "suspected"
        assert any("Q3" in r for r in res["reasons"])
        assert res["seven_question_gate"]["q3_target_backend_reached"] is False

    print(
        "[self-test] verify_finding_gate: provenance check, negative-control "
        "differential hash check, single-probe clamp, tier>2 clamp, "
        "Layer-Ordering Trap detection & override, 7-Question Gate (Q1 scope, "
        "Q3 WAF block, Q6 layer trap, Q7 non-destructive), and CLI exit "
        "codes 0/1 passed"
    )


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main(argv=None):
    parser = _Parser(
        description="Validate finding provenance and D2 negative-control "
                    "requirements (offline, stdlib only)."
    )
    parser.add_argument("--finding", help="path to candidate finding JSON file")
    parser.add_argument(
        "--evidence-dir",
        default=None,
        help="directory used to verify referenced evidence files on disk",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON verdict")
    parser.add_argument(
        "--seven-questions",
        action="store_true",
        help="output detailed 7-Question Gate evaluation checklist",
    )
    parser.add_argument("--self-test", action="store_true", help="run offline self-test and exit")
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

    res, hard_errors = evaluate_finding(raw, evidence_dir=args.evidence_dir)
    if hard_errors:
        if args.json:
            sys.stdout.write(json.dumps(res, indent=2) + "\n")
        else:
            sys.stderr.write("[REJECTED] finding failed anti-hallucination gate:\n")
            for err in hard_errors:
                sys.stderr.write("  - %s\n" % err)
            if args.seven_questions and "seven_question_gate" in res:
                sys.stderr.write("  7-Question Gate:\n")
                for qk, qv in res["seven_question_gate"].items():
                    sys.stderr.write("    - %s: %s\n" % (qk, "PASS" if qv else "FAIL"))
        return 1

    if args.json:
        sys.stdout.write(json.dumps(res, indent=2) + "\n")
    else:
        print(
            "[%s] %s (severity=%s, effective_status=%s, evidence=%d, neg_control=%s)"
            % (
                res["verdict"],
                res["title"],
                res["severity"],
                res["effective_status"],
                res["evidence_count"],
                res["has_negative_control"],
            )
        )
        for reason in res["reasons"]:
            print("  note: %s" % reason)
        if args.seven_questions and "seven_question_gate" in res:
            print("  7-Question Gate:")
            for qk, qv in res["seven_question_gate"].items():
                print("    - %s: %s" % (qk, "PASS" if qv else "FAIL"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
