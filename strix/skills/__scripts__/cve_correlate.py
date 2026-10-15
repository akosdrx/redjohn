#!/usr/bin/env python3
"""cve_correlate.py - offline CVE-to-version correlation over a local
advisories file (70-exploit-intel).

Consumes a JSON array of advisory records plus a component name, version and
version-confidence tier (from 10-recon-endpoint-mapping) and prints matched
CVEs labeled with the engagement's confidence ladder:

  tier 1 (exact)  -> "likely vulnerable"
  tier 2 (banner) -> "version in range, impact unverified"

"confirmed vulnerable" is NEVER emitted: that rung requires in-scope D2
reproduction (45-rce-exploitation benign-proof doctrine), not correlation.
Tier 3/4 input is refused (exit 1) - CVE claims need version proof.

Advisories JSON schema:
  [
    {
      "cve": "CVE-2099-00001",
      "product": "ExampleWidget",
      "versions_affected": [">=1.0.0,<1.5.0", "1.6.x"],
      "cwe": "CWE-89",
      "cvss": "n/a",
      "advisory": "SYNTHETIC-FIXTURE-1"
    }
  ]
Records below in the self-test fixtures use synthetic CVE ids
(CVE-2099-NNNNN) - never copy them into real advisories files.

Range grammar (comma = AND):
  >=V  >V  <=V  <V  !=V  ==V  bare V (exact)  V with x/* wildcards (1.2.x)

Version normalization: leading v/V stripped; build metadata after '+' and
pre-release after '-' are split off before numeric comparison and FLAGGED
(never silently ignored); missing numeric components padded with 0; letter
suffixes ordered 1.0.1 < 1.0.1f < 1.0.1g < 1.0.2.

Offline: no network access, no scope guard (sends nothing).

Usage:
  python3 cve_correlate.py --advisories advisories.json \
      --component "ExampleWidget" --version 1.2.9 [--tier 1|2|exact|banner]
  python3 cve_correlate.py --self-test

Exit codes: 0 = correlation ran (matches or none); 1 = bad arguments,
unreadable/malformed advisories file, or a tier that cannot support CVE
claims (tier 3/4 -> re-fingerprint via 10 first).
"""

import argparse
import json
import os
import re
import sys
import tempfile

WILDCARDS = {"x", "X", "*"}
OP_ORDER = (">=", "<=", "!=", "==", ">", "<", "=")
TIER_NAMES = {"1": 1, "2": 2, "exact": 1, "banner": 2,
              "3": 3, "4": 4, "banner+behavior": 3, "source": 4}

LABEL_TIER1 = "likely vulnerable"
LABEL_TIER2 = "version in range, impact unverified"


# --------------------------------------------------------------- versions


def split_version(raw):
    """-> (numeric-core string, suffix or None). Strips v/V and +build."""
    v = str(raw).strip()
    if len(v) > 1 and v[0] in ("v", "V") and (v[1].isdigit() or v[1] == "."):
        v = v[1:]
    v = v.split("+", 1)[0]
    if "-" in v:
        core, suffix = v.split("-", 1)
        return core, suffix
    return v, None


def parse_component(token):
    """-> "WILD" | (int, letters) | None (unparseable)."""
    if token in WILDCARDS:
        return "WILD"
    match = re.match(r"^(\d+)([A-Za-z]*)$", token)
    if match:
        return int(match.group(1)), match.group(2).lower()
    return None


def parse_core(core):
    """-> (list of components, fully_parseable bool)."""
    comps = [parse_component(tok) for tok in core.split(".")]
    return comps, all(c is not None for c in comps)


def _cmp_component(a, b):
    if a == b:
        return 0
    if isinstance(a, tuple) and isinstance(b, tuple):
        if a[0] != b[0]:
            return -1 if a[0] < b[0] else 1
        if a[1] != b[1]:
            return -1 if a[1] < b[1] else 1
        return 0
    return -1


def compare_versions(x_raw, y_raw):
    """Compare numeric cores. -> (cmp int, notes list). Fails closed:
    unparseable sides fall back to string compare WITH a note; wildcards
    inside a bound raise ValueError (handled by satisfies)."""
    notes = []
    xc, xs = split_version(x_raw)
    yc, ys = split_version(y_raw)
    for raw, suf in ((x_raw, xs), (y_raw, ys)):
        if suf:
            notes.append("version %r carries a pre-release/build suffix "
                         "(%r); advisory semantics may differ - verify "
                         "against the advisory text" % (raw, suf))
    xcomps, xok = parse_core(xc)
    ycomps, yok = parse_core(yc)
    if "WILD" in xcomps or "WILD" in ycomps:
        raise ValueError("wildcard inside a comparator bound: %r" % y_raw)
    if not (xok and yok):
        notes.append("non-numeric component present; compared %r vs %r as "
                     "strings - verify manually" % (x_raw, y_raw))
        return (-1 if xc < yc else (1 if xc > yc else 0)), notes
    if len(xcomps) != len(ycomps):
        notes.append("component-count mismatch (%s vs %s); shorter side "
                     "padded with 0 - verify release-line semantics"
                     % (x_raw, y_raw))
    width = max(len(xcomps), len(ycomps))
    pad = (0, "")
    xcomps = list(xcomps) + [pad] * (width - len(xcomps))
    ycomps = list(ycomps) + [pad] * (width - len(ycomps))
    for a, b in zip(xcomps, ycomps):
        c = _cmp_component(a, b)
        if c:
            return c, notes
    return 0, notes


def exact_or_wildcard_match(version, pattern):
    """Exact or wildcard-prefix match (1.2.x matches 1.2.9 but not 1.20.0).
    -> (matched bool, notes list)."""
    notes = []
    vcore, vsuf = split_version(version)
    pcore, _ = split_version(pattern)
    vcomps, vok = parse_core(vcore)
    pcomps, pok = parse_core(pcore)
    if not vok:
        notes.append("target version %r not fully numeric - verify manually"
                     % version)
        return vcore == pcore, notes
    if not pok:
        # unparseable pattern: plain string equality on the core
        return vcore == pcore, notes
    if vsuf:
        notes.append("version %r carries a suffix; compared on the numeric "
                     "core only - verify advisory semantics" % version)
    width = max(len(vcomps), len(pcomps))
    pad = (0, "")
    vcomps = list(vcomps) + [pad] * (width - len(vcomps))
    pcomps = list(pcomps) + [pad] * (width - len(pcomps))
    for v, p in zip(vcomps, pcomps):
        if p == "WILD":
            return True, notes  # wildcard absorbs this and later components
        if v == "WILD":
            notes.append("wildcard on the target side ignored")
            continue
        if _cmp_component(v, p):
            return False, notes
    return True, notes


def parse_constraint(token):
    """-> (op, bound) where op in OP_ORDER or '' (bare exact)."""
    for op in OP_ORDER:
        if token.startswith(op):
            return op, token[len(op):].strip()
    return "", token.strip()


def satisfies(version, range_str):
    """Does `version` satisfy the comma-AND constraint list `range_str`?
    -> (bool, notes list)."""
    notes = []
    for token in (t.strip() for t in range_str.split(",")):
        if not token:
            continue
        op, bound = parse_constraint(token)
        try:
            if op in ("", "==", "="):
                ok, n = exact_or_wildcard_match(version, bound)
            elif op == "!=":
                ok, n = exact_or_wildcard_match(version, bound)
                ok = not ok
            else:
                cmp_val, n = compare_versions(version, bound)
                ok = {">=": cmp_val >= 0, ">": cmp_val > 0,
                      "<=": cmp_val <= 0, "<": cmp_val < 0}[op]
        except ValueError as exc:
            notes.append("constraint %r skipped (%s)" % (token, exc))
            return False, notes
        notes.extend(n)
        if not ok:
            return False, notes
    return True, notes


# ------------------------------------------------------------- correlation


def normalize_name(name):
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def load_advisories(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("advisories file must contain a JSON array")
    for row in data:
        for field in ("cve", "product", "versions_affected"):
            if field not in row:
                raise ValueError("advisory record missing %r: %r"
                                 % (field, row))
    return data


def tier_value(tier_arg):
    tier = TIER_NAMES.get(str(tier_arg).strip().lower())
    if tier is None:
        raise ValueError("unknown tier %r (use 1|2|exact|banner)" % tier_arg)
    return tier


def confidence_label(tier):
    if tier == 1:
        return LABEL_TIER1, ("tier 1 exact version inside the affected "
                             "range; in-scope D2 reproduction is required "
                             "for the 'confirmed vulnerable' rung")
    return LABEL_TIER2, ("tier 2 banner-sourced version; confirm the "
                         "banner truthfulness and distro patch status "
                         "before escalating")


def correlate(advisories, component, version, tier):
    """-> (match rows, product notes). A row: (advisory dict, matched
    ranges list, caveats list, label, label note)."""
    comp_n = normalize_name(component)
    rows, seen_notes = [], []
    if not comp_n:
        return rows, seen_notes
    for adv in advisories:
        prod_n = normalize_name(adv["product"])
        if not prod_n:
            continue
        if comp_n == prod_n:
            pass
        elif comp_n in prod_n or prod_n in comp_n:
            seen_notes.append("advisory product %r matched %r by name "
                              "substring - confirm the CPE (log4j vs log4j2 "
                              "are different products)" % (adv["product"],
                                                           component))
        else:
            continue
        matched, caveats = [], list()
        for rng in adv["versions_affected"]:
            ok, notes = satisfies(version, str(rng))
            for note in notes:
                if note not in caveats:
                    caveats.append(note)
            if ok:
                matched.append(str(rng))
        if matched:
            label, label_note = confidence_label(tier)
            rows.append((adv, matched, caveats, label, label_note))
    return rows, sorted(set(seen_notes))


def render(rows, product_notes, component, version, tier):
    label, note = confidence_label(tier)
    tier_name = "exact" if tier == 1 else "banner"
    out = []
    out.append("== cve_correlate: component=%s version=%s tier=%d (%s) =="
               % (component, version, tier, tier_name))
    if not rows:
        out.append("no matched CVEs in the provided advisories file.")
        out.append("novelty check: if the surface is custom/niche and this")
        out.append("file covered the right product, hand off to")
        out.append("75-zeroday-research with this output as part of the")
        out.append("search trail.")
    for idx, (adv, matched, caveats, lab, lab_note) in enumerate(rows, 1):
        out.append("[m%d] %s  advisory=%s  cwe=%s  cvss=%s"
                   % (idx, adv.get("cve", "?"), adv.get("advisory", "?"),
                      adv.get("cwe", "?"), adv.get("cvss", "?")))
        out.append("     affected-ranges: %s -> MATCHED %s"
                   % ("; ".join(str(r) for r in adv["versions_affected"]),
                      " + ".join(matched)))
        out.append("     confidence: %s (%s)" % (lab, lab_note))
        for cav in caveats:
            out.append("     caveat: %s" % cav)
    out.append("--")
    out.append("summary: %d matched | confidence ceiling for this tier: %r"
               % (len(rows), label))
    for pn in product_notes:
        out.append("note: %s" % pn)
    out.append("standing note: correlation never yields 'confirmed "
               "vulnerable' - that rung requires in-scope D2 reproduction")
    out.append("(45-rce-exploitation benign-proof doctrine).")
    out.append("evidence expectation: keep the fingerprint evidence file "
               "(tier source) and every cited advisory record; save this "
               "card as evidence/p7-intel-<component>-<seq>.txt")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- self-test


SYNTHETIC_FIXTURES = [
    {"cve": "CVE-2099-00001", "product": "ExampleWidget",
     "versions_affected": [">=1.0.0,<1.5.0"], "cwe": "CWE-89",
     "cvss": "n/a", "advisory": "SYNTHETIC-FIXTURE-1"},
    {"cve": "CVE-2099-00002", "product": "ExampleWidget",
     "versions_affected": ["1.6.x"], "cwe": "CWE-78",
     "cvss": "n/a", "advisory": "SYNTHETIC-FIXTURE-2"},
    {"cve": "CVE-2099-00003", "product": "ExampleWidget",
     "versions_affected": [">=2.0.0,<=2.3.0"], "cwe": "CWE-502",
     "cvss": "n/a", "advisory": "SYNTHETIC-FIXTURE-3"},
    {"cve": "CVE-2099-00004", "product": "ExampleWidget",
     "versions_affected": ["1.0.x,!=1.0.9"], "cwe": "CWE-79",
     "cvss": "n/a", "advisory": "SYNTHETIC-FIXTURE-4"},
    {"cve": "CVE-2099-00005", "product": "ExampleWidget",
     "versions_affected": ["<=1.0.1f"], "cwe": "CWE-611",
     "cvss": "n/a", "advisory": "SYNTHETIC-FIXTURE-5"},
    {"cve": "CVE-2099-00006", "product": "OtherProduct",
     "versions_affected": [">=1.0.0"], "cwe": "CWE-22",
     "cvss": "n/a", "advisory": "SYNTHETIC-FIXTURE-6"},
]


def self_test():
    # range edges
    assert satisfies("1.2.9", ">=1.0.0,<1.5.0") == (True, [])
    ok, _ = satisfies("1.5.0", ">=1.0.0,<1.5.0")
    assert not ok, "exclusive upper bound violated"
    ok, _ = satisfies("2.4.0", ">=2.0.0,<2.4.0")
    assert not ok, "exclusive upper bound violated (2)"
    ok, _ = satisfies("2.3.0", ">=2.0.0,<=2.3.0")
    assert ok, "inclusive upper bound broken"

    # wildcards: 1.2.x matches 1.2.9 and padded 1.2, never 1.20.0
    assert satisfies("1.2.9", "1.2.x")[0]
    assert satisfies("1.2", "1.2.x")[0]
    assert not satisfies("1.20.0", "1.2.x")[0], "prefix trap: 1.2.x matched 1.20.0"
    assert satisfies("1.2.9", "1.2.*")[0]

    # exclusion
    assert satisfies("1.0.8", "1.0.x,!=1.0.9")[0]
    assert not satisfies("1.0.9", "1.0.x,!=1.0.9")[0]
    # wildcards are invalid inside comparator bounds - fail closed
    ok, n = satisfies("2.0.0", ">=2.x")
    assert not ok and any("skipped" in note for note in n)

    # v prefix and build metadata
    assert split_version("v2.3.0") == ("2.3.0", None)
    ok, _ = compare_versions("v2.3.0", "2.3.0")
    assert ok == 0
    assert split_version("2.3.0+build.5") == ("2.3.0", None)
    core, suf = split_version("2.3.0-beta.1")
    assert core == "2.3.0" and suf == "beta.1"
    ok, notes = satisfies("2.3.0-beta.1", "<2.3.0")
    assert not ok, "semver would say pre-release < release; we compare the"
    " numeric core and flag - so no match here"
    assert any("suffix" in n for n in notes), "suffix not flagged"

    # letter-suffix components (OpenSSL-style)
    assert satisfies("1.0.1f", "<=1.0.1f")[0]
    assert satisfies("1.0.1e", "<=1.0.1f")[0]
    assert not satisfies("1.0.2", "<=1.0.1f")[0]
    ok, _ = compare_versions("1.0.1", "1.0.1f")
    assert ok < 0

    # tier gate
    assert tier_value("exact") == 1 and tier_value("banner") == 2
    assert tier_value("3") == 3 and tier_value("source") == 4
    label1, _ = confidence_label(1)
    label2, _ = confidence_label(2)
    assert label1 == LABEL_TIER1 and label2 == LABEL_TIER2

    # correlation end-to-end
    rows, notes = correlate(SYNTHETIC_FIXTURES, "example-widget", "1.2.9", 1)
    assert [r[0]["cve"] for r in rows] == ["CVE-2099-00001"], rows
    assert rows[0][3] == LABEL_TIER1
    rows, _ = correlate(SYNTHETIC_FIXTURES, "ExampleWidget", "1.6.2", 2)
    assert [r[0]["cve"] for r in rows] == ["CVE-2099-00002"]
    assert rows[0][3] == LABEL_TIER2, "tier 2 must use the weaker rung"
    rows, _ = correlate(SYNTHETIC_FIXTURES, "ExampleWidget", "1.5.0", 1)
    assert rows == [], "1.5.0 must match nothing (both ranges exclude it)"
    rows, notes = correlate(SYNTHETIC_FIXTURES, "Widget", "2.2.0", 2)
    assert [r[0]["cve"] for r in rows] == ["CVE-2099-00003"]
    assert any("substring" in n for n in notes), "substring caveat missing"
    assert correlate(SYNTHETIC_FIXTURES, "---", "1.2.9", 1) == ([], [])

    # render smoke + advisories-file round trip
    rows, prod_notes = correlate(SYNTHETIC_FIXTURES, "ExampleWidget",
                                 "1.6.2", 1)
    text = render(rows, prod_notes, "ExampleWidget", "1.6.2", 1)
    assert "[m1] CVE-2099-00002" in text and "summary: 1 matched" in text
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "advisories.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(SYNTHETIC_FIXTURES, fh)
        loaded = load_advisories(path)
        assert len(loaded) == 6
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write('{"not": "a list"}')
        try:
            load_advisories(bad)
            raise AssertionError("malformed advisories accepted")
        except ValueError:
            pass

    print("[self-test] cve_correlate: range edges, wildcards (1.2.x vs "
          "1.20.0), exclusions, v-prefix/build/suffix flags, letter "
          "components, tier gating, correlation and JSON round-trip passed")


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Offline CVE-to-version correlation over a local "
                    "advisories JSON file.")
    parser.add_argument("--advisories", help="path to advisories JSON array")
    parser.add_argument("--component", help="component name to correlate")
    parser.add_argument("--version", help="pinned version string")
    parser.add_argument("--tier", default="1",
                        help="version-confidence tier from 10-recon: "
                             "1|exact or 2|banner (default 1). Tier 3/4 "
                             "are refused - CVE claims need version proof")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    try:
        tier = tier_value(args.tier)
        if tier > 2:
            sys.stderr.write(
                "[refused] tier %d (%s) cannot support CVE claims - "
                "re-fingerprint via 10-recon-endpoint-mapping first "
                "(dispatch negative routing).\n"
                % (tier, args.tier))
            sys.exit(1)
        if not (args.advisories and args.component and args.version):
            parser.error("--advisories, --component and --version are "
                         "required")
        advisories = load_advisories(args.advisories)
    except ValueError as exc:
        sys.stderr.write("[error] %s\n" % exc)
        sys.exit(1)
    except OSError as exc:
        sys.stderr.write("[error] cannot read advisories file: %s\n" % exc)
        sys.exit(1)

    rows, notes = correlate(advisories, args.component, args.version, tier)
    sys.stdout.write(render(rows, notes, args.component, args.version, tier))


if __name__ == "__main__":
    main()
