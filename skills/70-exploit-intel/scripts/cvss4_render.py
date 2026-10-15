#!/usr/bin/env python3
"""cvss4_render.py - offline CVSS 4.0 vector validator and renderer
(70-exploit-intel).

Validates a CVSS 4.0 vector string against the metric/value sets, renders a
human-readable explanation of every field, and maps a numeric score supplied
via --score to its severity band.

It does NOT compute the CVSS 4.0 numeric score: scoring uses the official
FIRST CVSS 4.0 calculator (first.org/cvss/calculator/v4-0). This tool
validates and documents the vector; per references/cvss4-guide.md the
report always carries vector + score + calculator + date, and the score is
never hand-computed.

Offline: no network access, no scope guard (sends nothing).

Usage:
  python3 cvss4_render.py --vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N" [--score 8.7]
  python3 cvss4_render.py --self-test

Exit codes: 0 = vector valid (rendered); 1 = invalid vector, bad score,
or bad arguments.
"""

import argparse
import sys

PREFIX = "CVSS:4.0/"

BASE_ORDER = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
MANDATORY = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA"]
THREAT_ORDER = ["E"]
ENV_ORDER = ["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
             "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]
SUPP_ORDER = ["S", "AU", "R", "V", "RE", "U"]
FULL_ORDER = BASE_ORDER + THREAT_ORDER + ENV_ORDER + SUPP_ORDER

VALUES = {
    "AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "AT": ("N", "P"),
    "PR": ("N", "L", "H"), "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"), "VI": ("H", "L", "N"), "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"), "SI": ("H", "L", "N"), "SA": ("H", "L", "N"),
    "E": ("X", "A", "P", "U", "N"),
    "CR": ("H", "M", "L", "X"), "IR": ("H", "M", "L", "X"),
    "AR": ("H", "M", "L", "X"),
    "MAV": ("X", "N", "A", "L", "P"), "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"), "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"), "MVI": ("X", "H", "L", "N"),
    "MVA": ("X", "H", "L", "N"), "MSC": ("X", "H", "L", "N"),
    "MSI": ("X", "H", "L", "N", "S"), "MSA": ("X", "H", "L", "N", "S"),
    "S": ("P", "N"), "AU": ("Y", "N"), "R": ("A", "U", "I"),
    "V": ("D", "C"), "RE": ("L", "M", "H"),
    "U": ("Red", "Amber", "Green", "Clear"),
}

MEANINGS = {
    "AV": {"N": "network-reachable across network boundaries (internet-facing)",
           "A": "adjacent network only (same L2/VPN, Bluetooth-class)",
           "L": "local access or a dependent session required",
           "P": "physical access required"},
    "AC": {"L": "low - only normal effort beyond the average attack",
           "H": "high - must defeat mitigations or collect preceding info"},
    "AT": {"N": "no target-specific preconditions",
           "P": "preconditions present (race, specific config/role/deployment)"},
    "PR": {"N": "no privileges", "L": "basic authenticated user",
           "H": "administrative privileges on the vulnerable system"},
    "UI": {"N": "no user interaction",
           "P": "passive interaction (victim merely visits)",
           "A": "active interaction (attacker must induce a specific action)"},
    "VC": {"H": "total/serious confidentiality impact on the vulnerable system",
           "L": "limited confidentiality impact", "N": "no confidentiality impact"},
    "VI": {"H": "total/serious integrity impact on the vulnerable system",
           "L": "limited integrity impact", "N": "no integrity impact"},
    "VA": {"H": "denial of the vulnerable system's availability",
           "L": "reduced availability", "N": "no availability impact"},
    "SC": {"H": "serious confidentiality impact beyond the vulnerable system",
           "L": "limited subsequent-system confidentiality impact",
           "N": "no subsequent-system confidentiality impact"},
    "SI": {"H": "serious integrity impact beyond the vulnerable system",
           "L": "limited subsequent-system integrity impact",
           "N": "no subsequent-system integrity impact"},
    "SA": {"H": "serious availability impact beyond the vulnerable system",
           "L": "limited subsequent-system availability impact",
           "N": "no subsequent-system availability impact"},
    "E": {"X": "undefined (default)",
          "A": "attacked - exploitation observed in the wild (needs evidence)",
          "P": "public proof-of-concept exists",
          "U": "unreported - no known exploitation",
          "N": "none - fix available, no known exploitation"},
    "CR": "confidentiality mission weight for this deployment (H raises impact)",
    "IR": "integrity mission weight for this deployment (H raises impact)",
    "AR": "availability mission weight for this deployment (H raises impact)",
    "MAV": "overrides AV for the engagement environment (X = defer to base)",
    "MAC": "overrides AC for the engagement environment (X = defer to base)",
    "MAT": "overrides AT for the engagement environment (X = defer to base)",
    "MPR": "overrides PR for the engagement environment (X = defer to base)",
    "MUI": "overrides UI for the engagement environment (X = defer to base)",
    "MVC": "overrides VC (X = defer to base)",
    "MVI": "overrides VI (X = defer to base)",
    "MVA": "overrides VA (X = defer to base)",
    "MSC": "overrides SC (X = defer to base)",
    "MSI": {"S": "SAFETY - integrity impact could directly cause physical "
                 "harm; the only impact field that takes S",
            "X": "defer to base", "H": "high", "L": "low", "N": "none"},
    "MSA": {"S": "SAFETY - availability impact could directly cause physical "
                 "harm; the only impact field that takes S",
            "X": "defer to base", "H": "high", "L": "low", "N": "none"},
    "S": {"P": "safety - probable physical harm/death possible",
          "N": "negligible safety effect"},
    "AU": {"Y": "automatable - no human interaction across the chain",
           "N": "not automatable"},
    "R": {"A": "automated recovery", "U": "manual/user recovery",
          "I": "irrecoverable"},
    "V": {"D": "diffuse value", "C": "concentrated value"},
    "RE": {"L": "low responder effort", "M": "moderate", "H": "high"},
    "U": {"Red": "provider urgency red", "Amber": "provider urgency amber",
          "Green": "provider urgency green", "Clear": "provider urgency clear"},
}

GROUPS = [("base - exploitability", ["AV", "AC", "AT", "PR", "UI"]),
          ("base - vulnerable system impact", ["VC", "VI", "VA"]),
          ("base - subsequent system impact", ["SC", "SI", "SA"]),
          ("threat", THREAT_ORDER),
          ("environmental", ENV_ORDER),
          ("supplemental (does not change the score)", SUPP_ORDER)]

BANDS = ((0.0, 0.0, "None"), (0.1, 3.9, "Low"), (4.0, 6.9, "Medium"),
         (7.0, 8.9, "High"), (9.0, 10.0, "Critical"))


def band_for_score(score):
    for lo, hi, name in BANDS:
        if round(score, 1) >= lo and round(score, 1) <= hi:
            return name
    return None


def validate_vector(vector):
    """-> (metrics dict in canonical order, errors list)."""
    errors = []
    metrics = {}
    if not vector.startswith(PREFIX):
        return metrics, ["vector must start with %r" % PREFIX]
    body = vector[len(PREFIX):]
    if not body:
        return metrics, ["no metrics after the prefix"]
    seen = []
    for field in body.split("/"):
        if ":" not in field:
            errors.append("field %r is not ABBR:VALUE" % field)
            continue
        abbr, value = field.split(":", 1)
        if abbr not in VALUES:
            errors.append("unknown metric %r (known: %s)"
                          % (abbr, ",".join(FULL_ORDER)))
            continue
        if abbr in metrics:
            errors.append("duplicate metric %r" % abbr)
            continue
        if value not in VALUES[abbr]:
            errors.append("invalid value %r for %s (allowed: %s)"
                          % (value, abbr, "|".join(VALUES[abbr])))
            continue
        metrics[abbr] = value
        seen.append(abbr)
    for req in MANDATORY:
        if req not in metrics:
            errors.append("missing mandatory metric %s" % req)
    order = [abbr for abbr in seen if abbr in FULL_ORDER]
    expected = sorted(order, key=FULL_ORDER.index)
    if order != expected:
        errors.append("metrics out of canonical order %s (expected %s)"
                      % (order, expected))
    return metrics, errors


def _meaning(abbr, value):
    entry = MEANINGS.get(abbr)
    if isinstance(entry, dict):
        return entry.get(value, "")
    return entry or ""


def render(vector, score=None):
    metrics, errors = validate_vector(vector)
    if errors:
        sys.stderr.write("[invalid] CVSS 4.0 vector rejected:\n")
        for err in errors:
            sys.stderr.write("  - %s\n" % err)
        sys.stderr.write("expected order: %s\n" % "/".join(FULL_ORDER))
        return 1
    out = []
    out.append("== CVSS 4.0 vector (valid) ==")
    out.append(vector)
    for group_name, members in GROUPS:
        present = [(a, metrics[a]) for a in members if a in metrics]
        if not present:
            continue
        out.append("[%s]" % group_name)
        for abbr, value in present:
            out.append("  %s:%s  %s" % (abbr, value, _meaning(abbr, value)))
    if not any(a in metrics for a in ("SC", "SI", "SA")):
        out.append("[base - subsequent system impact]")
        out.append("  omitted -> treated as N (no cross-boundary impact "
                   "claimed)")
    if score is None:
        out.append("[score]")
        out.append("  not supplied - compute with the official FIRST CVSS "
                   "4.0 calculator")
        out.append("  (first.org/cvss/calculator/v4-0), then pass it back "
                   "via --score to record")
        out.append("  the band. This tool does NOT compute the score. "
                   "Bands: 0.0 None,")
        out.append("  0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, "
                   "9.0-10.0 Critical.")
    else:
        band = band_for_score(score)
        if band is None:
            sys.stderr.write("[invalid] score %s outside 0.0-10.0\n" % score)
            return 1
        out.append("[score]")
        out.append("  %.1f -> band: %s" % (score, band))
        out.append("  (score supplied externally; per this skill's "
                   "discipline it must come from")
        out.append("   the official FIRST CVSS 4.0 calculator - record "
                   "calculator + date in")
        out.append("   the intel card)")
    out.append("[discipline]")
    out.append("  when torn between two values, score LOWER and justify;")
    out.append("  impact fields describe demonstrated impact only; SC/SI/SA")
    out.append("  require a named downstream system; E:A requires evidence.")
    sys.stdout.write("\n".join(out) + "\n")
    return 0


# ---------------------------------------------------------------- self-test


VALID_MINIMAL = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                 "VC:N/VI:N/VA:N")
VALID_MAX = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
             "VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
VALID_FULL = ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:L/VI:L/VA:N/"
              "SC:L/SI:N/SA:N/E:P/CR:H/IR:H/AR:L/MAV:A/MAC:H/MAT:N/MPR:L/"
              "MUI:A/MVC:N/MVI:L/MVA:N/MSI:S/MSA:S/S:P/AU:Y/R:A/V:C/RE:L/"
              "U:Red")


def self_test():
    for vec in (VALID_MINIMAL, VALID_MAX, VALID_FULL):
        metrics, errors = validate_vector(vec)
        assert not errors, "%s -> %s" % (vec, errors)
        for req in MANDATORY:
            assert req in metrics, "%s missing %s" % (vec, req)
    assert validate_vector(VALID_MAX)[0]["SC"] == "H"
    assert validate_vector(VALID_FULL)[0]["MSI"] == "S", "MSI:S must be valid"
    assert validate_vector(VALID_FULL)[0]["U"] == "Red"

    bad_cases = [
        ("CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N",
         "prefix"),
        ("CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N", "value"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/UI:N/VC:N/VI:N/VA:N", "missing"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/FOO:X", "unknown"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/E:P/E:A",
         "duplicate"),
        ("CVSS:4.0/AV:N/PR:N/AC:L/AT:N/UI:N/VC:N/VI:N/VA:N", "order"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/U:red", "case"),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/E:K", "value 2"),
        ("CVSS:4.0/badfield", "field shape"),
    ]
    for vec, why in bad_cases:
        _m, errors = validate_vector(vec)
        assert errors, "expected failure (%s) for %s" % (why, vec)

    # bands
    assert band_for_score(0.0) == "None"
    assert band_for_score(3.9) == "Low"
    assert band_for_score(4.0) == "Medium"
    assert band_for_score(8.9) == "High"
    assert band_for_score(9.0) == "Critical"
    assert band_for_score(10.0) == "Critical"
    assert band_for_score(10.5) is None
    assert band_for_score(-1.0) is None

    # render honors the no-compute contract in both score modes
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert render(VALID_MAX, None) == 0
    text = buf.getvalue()
    assert "does NOT compute the score" in text
    assert "official FIRST CVSS 4.0 calculator" in text
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert render(VALID_MAX, 10.0) == 0
    assert "band: Critical" in buf.getvalue()
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert render("CVSS:4.0/AV:N", None) == 1
    assert "[invalid]" in err.getvalue()
    err2 = io.StringIO()
    with contextlib.redirect_stderr(err2):
        assert render(VALID_MINIMAL, 11.2) == 1
    assert "outside 0.0-10.0" in err2.getvalue()

    print("[self-test] cvss4_render: 3 valid vectors (minimal/max/full "
          "incl. MSI:S, U:Red), 9 invalid cases (prefix/value/missing/"
          "unknown/duplicate/order/case), band mapping incl. 0.0/10.0/10.5, "
          "no-compute contract passed")


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Offline CVSS 4.0 vector validator/renderer. Does not "
                    "compute the numeric score (official FIRST calculator "
                    "owns that).")
    parser.add_argument("--vector", help="full CVSS 4.0 vector string")
    parser.add_argument("--score", type=float, default=None,
                        help="numeric score from the official calculator; "
                             "mapped to its severity band")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.vector:
        parser.error("--vector is required (or --self-test)")
    sys.exit(render(args.vector, args.score))


if __name__ == "__main__":
    main()
