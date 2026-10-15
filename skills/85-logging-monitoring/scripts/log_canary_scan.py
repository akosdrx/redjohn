#!/usr/bin/env python3
"""log_canary_scan.py - canary scanner for operator-provided log excerpts
(85-logging-monitoring).

Offline: scans an operator-provided log excerpt for this engagement's canary
strings (rj-pt-<engagement>-<nonce>) and reports which action classes appear
detected. With --map (the CSV written by canary_gen.py) each hit is linked to
its action class and missing classes are listed (detection gaps -> A09
assessment per references/detection-coverage.md).

This script never fetches logs: the excerpt arrives via the operator under
the engagement's data-access rules.

Usage:
  python3 log_canary_scan.py --log excerpt.log --engagement example-eng
  python3 log_canary_scan.py --log excerpt.log --engagement example-eng \
      --map canary-map-example-eng.csv

Exit codes: 0 = scan completed (also when zero canaries match - that is a
coverage result, not an error); 1 = unreadable file / bad map.
"""

import argparse
import csv
import os
import re
import sys

NONCE_RE = "[0-9a-f]{12}"
ENGAGEMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def canary_pattern(engagement):
    """Compiled regex matching this engagement's canaries."""
    return re.compile(r"rj-pt-%s-%s" % (re.escape(engagement.lower()),
                                        NONCE_RE))


def load_map(path):
    """Read a canary_gen CSV -> {canary: action_class}. Raise ValueError."""
    mapping = {}
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if header is None or header[0] != "action_class" or \
                "canary" not in header:
            raise ValueError("not a canary_gen CSV (header: %r)" % header)
        canary_idx = header.index("canary")
        for row in reader:
            if len(row) > canary_idx and row[canary_idx]:
                mapping[row[canary_idx]] = row[0]
    return mapping


def scan_log(path, engagement):
    """Return {canary: {"count": n, "lines": [line numbers]}}."""
    pattern = canary_pattern(engagement)
    found = {}
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as err:
        raise OSError("cannot read %s: %s" % (path, err))
    with fh:
        for lineno, line in enumerate(fh, 1):
            for match in pattern.findall(line):
                entry = found.setdefault(match, {"count": 0, "lines": []})
                entry["count"] += 1
                if len(entry["lines"]) < 5:
                    entry["lines"].append(lineno)
    return found


# ---------------------------------------------------------------- self-test


def self_test():
    import tempfile

    eng = "example-eng"
    other = "other-eng"
    c_hit = "rj-pt-%s-0a1b2c3d4e5f" % eng
    c_hit2 = "rj-pt-%s-ffeeddccbbaa" % eng
    c_miss = "rj-pt-%s-1234567890ab" % eng
    c_foreign = "rj-pt-%s-999999999999" % other
    assert not canary_pattern(eng).match(c_foreign)
    assert canary_pattern(eng).search("line " + c_foreign) is None
    assert canary_pattern(eng).search("x %s y" % c_hit).group(0) == c_hit
    # near-miss nonces must not match
    for bad in ("rj-pt-%s-0a1b2c3d4e5" % eng,
                "rj-pt-%s-0A1B2C3D4E5F" % eng,
                "rj-pt-%s-0a1b2c3d4e5g" % eng):
        assert canary_pattern(eng).search(bad) is None, bad
    # hyphenated engagement names are regex-escaped safely
    assert canary_pattern("eng-2").search(
        "rj-pt-eng-2-0a1b2c3d4e5f").group(0) == "rj-pt-eng-2-0a1b2c3d4e5f"

    with tempfile.TemporaryDirectory() as tmp:
        # --- fixture log: two hits (one twice), one missed, one foreign ---
        log_path = os.path.join(tmp, "excerpt.log")
        fixture_lines = [
            "2026-10-12T10:14:02Z auth failure user=%s" % c_hit,
            "2026-10-12T10:14:03Z access GET /login ua=probe",
            "2026-10-12T10:14:05Z waf alert payload contains %s" % c_hit,
            "2026-10-12T10:15:00Z unrelated noise from other test %s"
            % c_foreign,
            "2026-10-12T10:16:11Z export marker %s" % c_hit2,
        ]
        with open(log_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(fixture_lines) + "\n")

        found = scan_log(log_path, eng)
        assert c_hit in found and found[c_hit]["count"] == 2, found
        assert found[c_hit]["lines"] == [1, 3], found[c_hit]
        assert c_hit2 in found and found[c_hit2]["lines"] == [5]
        assert c_miss not in found, "never-sent canary must not appear"
        assert all(not k.startswith("rj-pt-%s" % other) for k in found)

        # --- map linkage ---
        map_path = os.path.join(tmp, "map.csv")
        with open(map_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["action_class", "canary", "timestamp_placeholder",
                             "expected_log_source"])
            writer.writerow(["auth_failure", c_hit, "", "auth log"])
            writer.writerow(["data_export", c_hit2, "", "app audit trail"])
            writer.writerow(["privilege_change", c_miss, "",
                             "app audit trail"])
        mapping = load_map(map_path)
        assert mapping[c_hit] == "auth_failure"
        assert mapping[c_miss] == "privilege_change"
        # classification outcome: detected/detected/missed
        detected = {cls for canary, cls in mapping.items() if canary in found}
        missed = {cls for canary, cls in mapping.items()
                  if canary not in found}
        assert detected == {"auth_failure", "data_export"}, detected
        assert missed == {"privilege_change"}, missed

        # --- bad map header rejected ---
        bad_path = os.path.join(tmp, "bad.csv")
        with open(bad_path, "w", encoding="utf-8", newline="") as fh:
            fh.write("a,b\n1,2\n")
        try:
            load_map(bad_path)
            raise AssertionError("bad map must raise")
        except ValueError:
            pass

    # --- engagement validation ---
    assert ENGAGEMENT_RE.match("example-eng")
    assert ENGAGEMENT_RE.match("Eng_02")
    assert not ENGAGEMENT_RE.match("has space")
    assert not ENGAGEMENT_RE.match("-lead")
    assert not ENGAGEMENT_RE.match("")

    print("[self-test] log_canary_scan: pattern/near-miss + fixture-log "
          "scan + map-linkage + bad-map fixtures passed")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Scan an operator-provided log excerpt for this "
                    "engagement's rj-pt-<engagement>-<nonce> canaries.")
    parser.add_argument("--log",
                        help="log excerpt file (operator-provided)")
    parser.add_argument("--engagement",
                        help="engagement id the canaries were generated for")
    parser.add_argument("--map",
                        help="canary_gen.py CSV mapping canaries to action "
                             "classes (enables per-class detected/missed "
                             "reporting)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.log or not args.engagement:
        parser.error("--log and --engagement are required")
    engagement = args.engagement.lower()
    if not ENGAGEMENT_RE.match(engagement):
        parser.error("--engagement must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}")

    try:
        found = scan_log(args.log, engagement)
    except OSError as err:
        sys.stderr.write("[error] %s\n" % err)
        sys.exit(1)

    mapping = {}
    if args.map:
        try:
            mapping = load_map(args.map)
        except (OSError, ValueError) as err:
            sys.stderr.write("[error] bad map %s: %s\n" % (args.map, err))
            sys.exit(1)

    print("[scan] log=%s engagement=%s canaries-found=%d"
          % (args.log, engagement, len(found)))
    for canary, entry in sorted(found.items()):
        action_class = mapping.get(canary)
        label = " action_class=%s" % action_class if action_class else ""
        print("[found ] %s count=%d lines=%s%s"
              % (canary, entry["count"], ",".join(map(str,
                                                      entry["lines"])),
                 label))

    if mapping:
        unmapped_hits = [c for c in found if c not in mapping]
        detected_classes = sorted({mapping[c] for c in found
                                   if c in mapping})
        missed_classes = sorted({mapping[c] for c in mapping
                                 if c not in found})
        print("[classes] detected=%s" % (",".join(detected_classes)
                                         or "none"))
        print("[classes] missed=%s" % (",".join(missed_classes) or "none"))
        if unmapped_hits:
            print("[classes] hits-not-in-map=%d (map them or regenerate)"
                  % len(unmapped_hits))
        for cls in missed_classes:
            print("[gap   ] action_class=%s shows no canary in this excerpt "
                  "- confirm excerpt covers the action window, then assess "
                  "A09 per references/detection-coverage.md" % cls)
        print("[summary] %d/%d mapped action classes evidenced in this "
              "excerpt" % (len(detected_classes), len(set(
                  mapping.values()))))
    elif found:
        print("[note] no --map given: canaries listed without action-class "
              "linkage; re-run with --map for detected/missed reporting")

    print("[evidence] store this output next to the excerpt "
          "(evidence/p85-logs-<source>-<window>.txt provenance header); "
          "detections cite excerpt line numbers in the 90 report table")


if __name__ == "__main__":
    main()
