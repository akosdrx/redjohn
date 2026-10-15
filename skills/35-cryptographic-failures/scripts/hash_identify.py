#!/usr/bin/env python3
# hash_identify.py - offline password-hash format identification.
#
# Identifies candidate storage formats by length, charset and prefix
# markers (md5/sha1/sha256/sha512, NTLM ambiguity, bcrypt and argon2
# prefixes, django markers, MySQL pre-4.1 and 4.1/5.x patterns, the crypt
# family, MSSQL/LDAP shapes), and prints risk notes (fast raw hash vs KDF,
# salted vs unsalted, CWE-916 relevance) plus hashcat modes for
# engagement-sanctioned cracking handoffs.
#
# Fully offline: no network, no cracking, no verification. Identification
# is evidence TRIAGE - the report finding needs the observation context
# (where the hash was captured), per the 35 SKILL evidence rules.
#
# Exit codes: 0 success (including "no candidates"), 1 other errors.

import argparse
import hashlib
import re
import sys

HEX_RE = re.compile(r"^(?:[0-9a-fA-F]+)$")
LOWER_HEX_RE = re.compile(r"^(?:[0-9a-f]+)$")
UPPER_HEX_RE = re.compile(r"^(?:[0-9A-F]+)$")
B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


def _hexlen(value):
    """Return (is_pure_hex, length) for the whole string."""
    return (bool(HEX_RE.match(value)), len(value))


def identify(value):
    """Return a list of candidate dicts for a stored-hash string."""
    value = value.strip()
    cands = []

    def add(name, why, salted, speed, mode=None, note=None):
        cands.append({"name": name, "why": why, "salted": salted,
                      "speed": speed, "mode": mode, "note": note})

    if not value:
        return cands

    low = value.lower()

    # --- prefix-marker formats (checked first: strongest signal) ---
    if low.startswith("$argon2"):
        if low.startswith("$argon2id$"):
            variant = "argon2id"
        elif low.startswith("$argon2i$"):
            variant = "argon2i"
        elif low.startswith("$argon2d$"):
            variant = "argon2d"
        else:
            variant = "argon2?"
        ok_params = ("m=" in low and "t=" in low and "p=" in low)
        add(variant, "$argon2 marker + cost params (m/t/p)",
            True, "KDF (memory-hard)", None,
            "hashcat: no argon2 support - do not hand off to cracking"
            if ok_params else "argon2 marker but cost params incomplete")
        return cands

    if re.match(r"^\$2[axyb]\$\d{2}\$", value):
        cost = value[4:6]
        add("bcrypt", "$2x$ marker + 2-digit cost %s + 53-char tail"
            % cost, True, "KDF (cost %s)" % cost, "3200",
            "quote the cost in the report; cost < 5 is below baseline")
        return cands

    if low.startswith("pbkdf2_sha256$") or low.startswith("pbkdf2_sha1$"):
        parts = value.split("$")
        iters = parts[1] if len(parts) > 2 else "?"
        add("django-pbkdf2", "pbkdf2_<alg>$<iter>$<salt>$<hash> marker",
            True, "KDF (%s iterations)" % iters, "10000",
            None if low.startswith("pbkdf2_sha256")
            else "pbkdf2_sha1 variant; confirm Django version")
        return cands

    for marker, name, mode in (("md5$", "django-md5-legacy", None),
                               ("sha1$", "django-sha1-legacy", None),
                               ("sha256$", "django-sha256-legacy", None),
                               ("sha512$", "django-sha512-legacy", None)):
        if low.startswith(marker):
            add(name, "%s<salt>$<hash> django-style marker" % marker,
                True, "fast per-iteration (legacy)", mode,
                "salted but cheap; CWE-916 variant")
            return cands

    if low.startswith("$6$"):
        add("sha512crypt", "$6$ marker (+ optional rounds=)",
            True, "KDF", "1800", None)
        return cands
    if low.startswith("$5$"):
        add("sha256crypt", "$5$ marker", True, "KDF", "7400", None)
        return cands
    if low.startswith("$apr1$"):
        add("apr1-md5-apache", "$apr1$ marker", True,
            "slow-ish (md5crypt family)", "1600", None)
        return cands
    if low.startswith("$1$"):
        add("md5crypt", "$1$ marker", True, "slow-ish (1000 iterations)",
            "500", "salted but computationally cheap (CWE-916 variant)")
        return cands

    if value.startswith("*") and len(value) == 41 and \
            UPPER_HEX_RE.match(value[1:]):
        add("mysql-4.1-5.x", "'*' + 40 uppercase hex = SHA1(SHA1(pw))",
            False, "fast (unsalted)", "300", None)
        return cands

    if low.startswith("0x0200") and HEX_RE.match(value[4:]):
        add("mssql-2012+", "0x0200 prefix (PBKDF2-SHA1)", True,
            "KDF", "1731", None)
        return cands
    if low.startswith("0x0100"):
        add("mssql-2000", "0x0100 prefix", True, "fast", None, None)
        return cands

    if value.startswith("{SSHA}"):
        add("ldap-ssha", "{SSHA} marker (salted SHA-1)", True,
            "fast (SHA-1 core)", None, None)
        return cands
    if value.startswith("{SHA}"):
        add("ldap-sha", "{SHA} marker (unsalted SHA-1)", False,
            "fast (SHA-1 core)", None, "CWE-916: fast unsalted")
        return cands
    if value.startswith("{CRYPT}"):
        add("ldap-crypt", "{CRYPT} wrapper", True, "depends on inner crypt",
            None, "unwrap the inner value to classify")
        return cands

    if low.startswith("md5") and len(value) == 35 and \
            LOWER_HEX_RE.match(value[3:]):
        add("postgres-md5", "literal 'md5' + 32 hex = md5(pw + username)",
            True, "fast (username as salt)", None,
            "salt is the username; offline cracking is still cheap")
        return cands

    # --- raw hex by length ---
    is_hex, n = _hexlen(value)
    if is_hex and n % 2 == 0:
        if n == 32:
            names = [("MD5", "0", "unsalted fast hash (CWE-916 if it "
                                 "protects passwords)")]
            if LOWER_HEX_RE.match(value):
                names.append(("NTLM", "1000",
                              "same shape as MD5; Windows context -> NTLM"))
            for name, mode, note in names:
                add(name, "32 hex chars", False, "fast", mode, note)
        elif n == 16:
            note = ("16 hex chars: MySQL pre-4.1 or Oracle 10/11 shape; "
                    "charset/case and context decide")
            add("mysql-pre-4.1-or-oracle", "16 hex chars", False,
                "fast", "200", note)
        elif n == 40:
            add("SHA-1", "40 hex chars", False, "fast", "100",
                "CWE-916 if it protects passwords; RIPEMD-160 has the "
                "same shape")
            if UPPER_HEX_RE.match(value) and not LOWER_HEX_RE.match(value):
                cands[-1]["note"] += "; uppercase hex is unusual - check sha1 uppercase variants"
        elif n == 56:
            add("SHA-224", "56 hex chars", False, "fast", None, None)
        elif n == 64:
            add("SHA-256", "64 hex chars", False, "fast", "1400",
                "CWE-916 if it protects passwords (fast unsalted)")
        elif n == 96:
            add("SHA-384", "96 hex chars", False, "fast", None, None)
        elif n == 128:
            add("SHA-512", "128 hex chars", False, "fast", "1700",
                "CWE-916 if it protects passwords (fast unsalted)")
        else:
            if n % 32 == 0:
                add("unknown-even-hex", "%d hex chars (multiple of 32)" % n,
                    False, "unknown", None,
                    "no standard single digest at this length")
        return cands

    # --- base64-ish leftovers ---
    if B64_RE.match(value) and len(value) >= 20:
        note = ("base64-shaped, not hex; could be a raw digest in base64 "
                "(len %d -> decoded %d bytes) or KDF output" %
                (len(value), len(value) * 3 // 4))
        add("base64-encoded", "base64 charset", False, "unknown", None, note)
    return cands


def format_report(value, cands):
    lines = ["value: %r" % value]
    if not cands:
        lines.append("no candidates: no format matched by length/charset/"
                     "marker; manual review (custom scheme or multi-part "
                     "encoding)")
        return "\n".join(lines)
    lines.append("candidates (%d):" % len(cands))
    for c in cands:
        lines.append("- %-24s %s" % (c["name"], c["why"]))
        lines.append("  salted=%s speed=%s%s"
                     % (c["salted"], c["speed"],
                        (" hashcat-mode=%s" % c["mode"]) if c["mode"]
                        else ""))
        if c["note"]:
            lines.append("  note: %s" % c["note"])
    fast_unsalted = [c for c in cands
                     if c["speed"].startswith("fast") and not c["salted"]]
    if fast_unsalted:
        lines.append("risk: fast unsalted candidate(s) present - if this "
                     "protects passwords, CWE-916 applies from the format "
                     "alone; confirm the observation context before "
                     "claiming.")
    lines.append("reminder: cracking handoff (hashcat modes above) only "
                 "with written engagement authorization; recovered "
                 "material leaves only via the D3 operator channel.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Offline hash format identification by length/charset/"
        "markers, with fast-vs-KDF risk notes and hashcat modes for "
        "sanctioned cracking handoffs. No network, no cracking.")
    ap.add_argument("--hash", dest="value",
                    help="The stored hash string to identify")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests (fixtures, no network)")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.value:
        sys.stderr.write("error: --hash is required\n")
        return 1
    print(format_report(args.value.strip(), identify(args.value)))
    print("evidence: keep the hash_identify output plus WHERE the hash was "
          "observed (login capture or sanctioned sample) as the finding "
          "context; a bare hash value is not evidence.")
    return 0


# ---------------------------------------------------------------------------
# Self-test: offline fixtures only. Raw digests are computed at runtime via
# hashlib over canary strings; marker formats use synthetic dummy shapes.
# ---------------------------------------------------------------------------

def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    def names(value):
        return [c["name"] for c in identify(value)]

    # --- raw hex (computed at runtime; not pre-embedded) ---
    md5v = hashlib.md5(b"rj-pt-fixture").hexdigest()
    got = names(md5v)
    assert "MD5" in got and "NTLM" in got, got
    ok("32 hex -> MD5 + NTLM ambiguity reported")

    sha1v = hashlib.sha1(b"rj-pt-fixture").hexdigest()
    got = names(sha1v)
    assert got == ["SHA-1"], got
    ok("40 hex -> SHA-1")

    sha256v = hashlib.sha256(b"rj-pt-fixture").hexdigest()
    sha512v = hashlib.sha512(b"rj-pt-fixture").hexdigest()
    assert names(sha256v) == ["SHA-256"]
    assert names(sha512v) == ["SHA-512"]
    ok("64/128 hex -> SHA-256 / SHA-512")

    assert names(md5v.upper()) == ["MD5"], names(md5v.upper())
    ok("uppercase 32 hex -> MD5 only (NTLM is lowercase-convention)")

    got = names("0123456789abcdef")
    assert got == ["mysql-pre-4.1-or-oracle"], got
    ok("16 hex -> mysql-pre-4.1-or-oracle with context note")

    # --- marker formats (synthetic dummy shapes) ---
    bcrypt_fixture = "$2b$12$" + "r" * 22 + "h" * 31  # exact 60-char shape
    got = names(bcrypt_fixture)
    assert got == ["bcrypt"], got
    cand = identify(bcrypt_fixture)[0]
    assert cand["mode"] == "3200" and "cost 12" in cand["why"]
    ok("bcrypt marker -> bcrypt, mode 3200, cost quoted")

    argon2_fixture = ("$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$"
                      "aGFzaGR1bW15dmFsdWV4YW1wbGU")
    got = names(argon2_fixture)
    assert got == ["argon2id"], got
    cand = identify(argon2_fixture)[0]
    assert "no argon2 support" in cand["note"]
    ok("argon2id marker -> argon2id, no-hashcat note present")

    got = names("*F2E17054D09BC5F5C0A2E1F11B1D3B0A5C6E7D89")
    assert got == ["mysql-4.1-5.x"], got
    ok("* + 40 uppercase hex -> mysql-4.1-5.x")

    got = names("md5" + md5v)
    assert got == ["postgres-md5"], got
    ok("md5-prefixed 32 hex -> postgres-md5")

    got = names("pbkdf2_sha256$260000$examplesalt$"
                "b64hashvaluedummyexample==")
    assert got == ["django-pbkdf2"], got
    cand = identify("pbkdf2_sha256$260000$examplesalt$"
                    "b64hashvaluedummyexample==")[0]
    assert "260000 iterations" in cand["speed"]
    ok("pbkdf2_sha256$ marker -> django-pbkdf2 with iteration count")

    got = names("md5$examplesalt$" + md5v)
    assert got == ["django-md5-legacy"], got
    ok("md5$salt$hash -> django-md5-legacy")

    got = names("$6$exsamplesalt$longhashvaluehereexampledummy")
    assert got == ["sha512crypt"], got
    got = names("$1$exsample$smallhashvaluehere")
    assert got == ["md5crypt"], got
    got = names("$apr1$exsample$smallhashvalue")
    assert got == ["apr1-md5-apache"], got
    ok("crypt family markers ($6$/$1$/$apr1$) resolved")

    got = names("0x0200" + "A1B2C3" * 20)
    assert got == ["mssql-2012+"], got
    ok("0x0200 prefix -> mssql-2012+")

    got = names("{SSHA}b64valueexample==")
    assert got == ["ldap-ssha"], got
    ok("{SSHA} marker -> ldap-ssha")

    # --- unknown shapes ---
    got = names("zz@@!!not-a-hash@@")
    assert got == [], got
    ok("unmatched shape -> no candidates")

    got = names("a" * 70)  # hex-shaped but odd length
    assert got == [], got
    ok("odd-length hex -> no candidates (no false positive)")

    # --- risk-note path ---
    report = format_report(md5v, identify(md5v))
    assert "CWE-916" in report
    assert "hashcat-mode=0" in report
    ok("report includes CWE-916 risk note and hashcat mode line")

    report = format_report("zz@@!!not-a-hash@@", [])
    assert "no candidates" in report
    ok("no-candidate report path")

    # --- CLI paths ---
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(["--hash", sha256v])
    assert code == 0 and "SHA-256" in buf.getvalue()
    ok("--hash happy path exits 0")

    assert main([]) == 1
    ok("missing --hash -> exit 1")

    print("[self-test] hash_identify: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
