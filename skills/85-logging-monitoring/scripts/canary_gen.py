#!/usr/bin/env python3
"""canary_gen.py - detection-coverage canary generator (85-logging-monitoring).

Offline helper: emits unique canary strings in the master format
rj-pt-<engagement>-<nonce> (nonce = 12 hex chars) and writes the per-action
mapping template CSV with columns:
  action_class,canary,timestamp_placeholder,expected_log_source

The timestamp_placeholder column is left empty and filled at execution time
(UTC) when each action runs; expected_log_source is prefilled from the
mapping table in references/detection-coverage.md.

Usage:
  python3 canary_gen.py --engagement example-eng --count 10
  python3 canary_gen.py --engagement example-eng --out my-map.csv

No network, no credentials. Exit codes: 0 = success, 1 = bad input/IO error.
"""

import argparse
import csv
import os
import re
import secrets
import sys

CANARY_PREFIX = "rj-pt"
NONCE_LEN = 12  # hex chars from secrets.token_hex(6)
ENGAGEMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
CANARY_RE = re.compile(r"^rj-pt-[a-z0-9_-]+-[0-9a-f]{%d}$" % NONCE_LEN)

# action class -> default expected log source(s) (mirrors
# references/detection-coverage.md; operator confirms which exist per target)
DEFAULT_ACTION_CLASSES = [
    ("auth_success", "auth log (sshd/PAM), app audit trail"),
    ("auth_failure", "auth log, app audit trail"),
    ("auth_lockout", "auth log, app audit trail"),
    ("privilege_change", "app audit trail, admin platform audit"),
    ("config_change", "app audit trail, config-mgmt log"),
    ("data_export", "app audit trail, DB audit"),
    ("command_exec", "host audit (auditd/syslog), app audit trail"),
    ("file_access", "app audit trail, file-server log"),
    ("injection_attempt", "WAF log, web access log"),
    ("session_event", "session store log, web access log"),
]


def validate_engagement(name):
    """Return normalized (lowercase) engagement slug or None."""
    if not name or not ENGAGEMENT_RE.match(name):
        return None
    return name.lower()


def make_canary(engagement, nonce=None):
    """One canary string rj-pt-<engagement>-<nonce12hex> (engagement
    canonicalized to lowercase)."""
    if nonce is None:
        nonce = secrets.token_hex(NONCE_LEN // 2)
    return "%s-%s-%s" % (CANARY_PREFIX, engagement.lower(), nonce)


def build_plan(engagement, count):
    """Return [(action_class, expected_log_source, canary), ...]."""
    rows = []
    classes = list(DEFAULT_ACTION_CLASSES)
    for i in range(count):
        if i < len(classes):
            action_class, source = classes[i]
        else:
            action_class, source = "unassigned_%02d" % (i + 1), "TBD"
        rows.append((action_class, source, make_canary(engagement)))
    return rows


def write_csv(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["action_class", "canary", "timestamp_placeholder",
                         "expected_log_source"])
        for action_class, source, canary in rows:
            writer.writerow([action_class, canary, "", source])


# ---------------------------------------------------------------- self-test


def self_test():
    # --- format and uniqueness ---
    eng = "example-eng"
    seen = set()
    for _ in range(500):
        canary = make_canary(eng)
        assert CANARY_RE.match(canary), canary
        assert canary not in seen, "nonce collision: %s" % canary
        seen.add(canary)
    assert len(seen) == 500
    # format edge: engagement with digits/underscores
    canary = make_canary("Eng_02-X")
    assert CANARY_RE.match(canary) and "eng_02-x" in canary, canary
    # explicit nonce is preserved (used by the scan script's world)
    assert make_canary(eng, "0a1b2c3d4e5f") == \
        "rj-pt-example-eng-0a1b2c3d4e5f"

    # --- engagement validation ---
    assert validate_engagement("example-eng") == "example-eng"
    assert validate_engagement("Eng_02") == "eng_02"
    assert validate_engagement("") is None
    assert validate_engagement("-leading-dash") is None
    assert validate_engagement("has space") is None
    assert validate_engagement("x" * 65) is None
    assert validate_engagement("bad+char") is None

    # --- plan building ---
    rows = build_plan(eng, len(DEFAULT_ACTION_CLASSES))
    assert [r[0] for r in rows] == [c[0] for c in DEFAULT_ACTION_CLASSES]
    assert len({r[2] for r in rows}) == len(rows), "canaries must be unique"
    small = build_plan(eng, 3)
    assert [r[0] for r in small] == ["auth_success", "auth_failure",
                                     "auth_lockout"]
    big = build_plan(eng, len(DEFAULT_ACTION_CLASSES) + 2)
    assert big[-1][0].startswith("unassigned_"), big[-1][0]
    for _cls, src, canary in rows:
        assert CANARY_RE.match(canary) and src

    # --- CSV roundtrip ---
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "map.csv")
        write_csv(path, rows)
        with open(path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            out_rows = list(reader)
        assert out_rows[0] == ["action_class", "canary",
                               "timestamp_placeholder",
                               "expected_log_source"], out_rows[0]
        assert len(out_rows) == len(rows) + 1
        for got, want in zip(out_rows[1:], rows):
            assert got[0] == want[0] and got[1] == want[2], got
            assert got[2] == "", "timestamp placeholder starts empty"
            assert got[3] == want[1]

    print("[self-test] canary_gen: format(500 unique) + engagement-"
          "validation + plan-building + csv-roundtrip fixtures passed")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Offline canary generator for detection-coverage "
                    "testing (rj-pt-<engagement>-<nonce> + mapping CSV).")
    parser.add_argument("--engagement",
                        help="engagement id (letters, digits, _ or -, "
                             "1-64 chars)")
    parser.add_argument("--count", type=int,
                        default=len(DEFAULT_ACTION_CLASSES),
                        help="number of canaries (default: one per built-in "
                             "action class = %d)"
                             % len(DEFAULT_ACTION_CLASSES))
    parser.add_argument("--out",
                        help="mapping CSV output path (default: "
                             "canary-map-<engagement>.csv)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.engagement:
        parser.error("--engagement is required")
    engagement = validate_engagement(args.engagement)
    if engagement is None:
        parser.error("--engagement must match [A-Za-z0-9][A-Za-z0-9_-]{0,63}")
    if args.count < 1 or args.count > 200:
        parser.error("--count must be between 1 and 200")

    rows = build_plan(engagement, args.count)
    out_path = args.out or "canary-map-%s.csv" % engagement

    print("[canary] engagement=%s count=%d" % (engagement, len(rows)))
    for action_class, source, canary in rows:
        print("[canary] %-18s %s  (expected: %s)" % (action_class, canary,
                                                     source))
    try:
        write_csv(out_path, rows)
    except OSError as err:
        sys.stderr.write("[error] cannot write %s: %s\n" % (out_path, err))
        sys.exit(1)
    print("[map] wrote %s (fill timestamp_placeholder in UTC when each "
          "action runs; operator confirms which expected sources exist)"
          % out_path)
    print("[evidence] the CSV is the tracking artifact for the "
          "detection-coverage table; scan excerpts with "
          "log_canary_scan.py --map %s" % out_path)


if __name__ == "__main__":
    main()
