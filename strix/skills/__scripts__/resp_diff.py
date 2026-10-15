#!/usr/bin/env python3
# resp_diff.py - offline structured diff of two raw HTTP response files.
#
# Compares status, headers-of-interest, body size, body sha256 and the first
# divergent body line. No network access; operates on saved evidence files.
#
# Exit codes: 0 success (identical or differing - the diff IS the result),
# 1 other errors (unreadable/malformed input).

import argparse
import hashlib
import os
import sys
import tempfile

HEADERS_OF_INTEREST = [
    "content-type", "content-length", "location", "set-cookie", "server",
    "x-powered-by", "cache-control", "www-authenticate", "retry-after",
    "x-frame-options", "content-security-policy", "allow",
    "access-control-allow-origin", "strict-transport-security",
]


def parse_response(data):
    """Parse a raw HTTP response (status line, headers, body). Pure."""
    if b"\r\n\r\n" in data:
        head, body = data.split(b"\r\n\r\n", 1)
        sep = "\r\n"
    elif b"\n\n" in data:
        head, body = data.split(b"\n\n", 1)
        sep = "\n"
    else:
        head, body = data, b""
        sep = "\r\n" if b"\r\n" in data else "\n"

    lines = [l for l in head.decode("latin-1").split(sep) if l.strip()]
    if not lines:
        raise ValueError("empty response file")
    status_parts = lines[0].split(None, 2)
    if len(status_parts) < 2 or not status_parts[0].startswith("HTTP/"):
        raise ValueError("malformed status line: %r" % lines[0])
    status = int(status_parts[1])
    reason = status_parts[2] if len(status_parts) > 2 else ""

    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ValueError("malformed header line: %r" % line)
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return {"status": status, "reason": reason, "headers": headers, "body": body}


def mask_cookie(value):
    """Mask cookie values; keep names and attributes for safe printing."""
    parts = value.split(";")
    first = parts[0]
    if "=" in first:
        name, _val = first.split("=", 1)
        parts[0] = "%s=<masked>" % name
    return ";".join(parts)


def mask_header(name, value):
    if name.lower() in ("set-cookie", "authorization", "proxy-authorization"):
        return mask_cookie(value) if name.lower() == "set-cookie" else "<masked>"
    if len(value) > 120:
        return value[:117] + "..."
    return value


def first_divergent_line(body_a, body_b):
    """Return (line_no, line_a, line_b) or ('extra', side, line_no) or None."""
    la = body_a.decode("utf-8", errors="replace").splitlines()
    lb = body_b.decode("utf-8", errors="replace").splitlines()
    for idx in range(max(len(la), len(lb))):
        a = la[idx] if idx < len(la) else None
        b = lb[idx] if idx < len(lb) else None
        if a != b:
            trunc = lambda s: s if len(s) <= 120 else s[:117] + "..."
            if a is None:
                return ("extra", "b", idx + 1, None, trunc(b))
            if b is None:
                return ("extra", "a", idx + 1, trunc(a), None)
            return ("diff", None, idx + 1, trunc(a), trunc(b))
    return None


def diff_responses(a, b):
    """Return dict with per-dimension results and the list of differing dims."""
    dims = []
    if a["status"] != b["status"]:
        dims.append("status")

    header_notes = []
    names = set(a["headers"]) | set(b["headers"])
    for name in sorted(names):
        va = a["headers"].get(name, [])
        vb = b["headers"].get(name, [])
        if va == vb:
            continue
        pretty = name if name in HEADERS_OF_INTEREST else name + " (other)"
        if not va:
            header_notes.append("%s: only-in-B %s"
                                % (pretty, mask_header(name, vb[0])))
            dims.append("headers")
        elif not vb:
            header_notes.append("%s: only-in-A %s"
                                % (pretty, mask_header(name, va[0])))
            dims.append("headers")
        else:
            header_notes.append(
                "%s: A=%s B=%s"
                % (pretty, mask_header(name, va[0]), mask_header(name, vb[0])))
            if name in HEADERS_OF_INTEREST:
                dims.append("headers")
            else:
                dims.append("headers-other")

    size_a, size_b = len(a["body"]), len(b["body"])
    if size_a != size_b:
        dims.append("size")
    hash_a = hashlib.sha256(a["body"]).hexdigest()
    hash_b = hashlib.sha256(b["body"]).hexdigest()
    body_differs = hash_a != hash_b
    if body_differs:
        dims.append("body-sha256")

    return {
        "status_a": a["status"], "status_b": b["status"],
        "size_a": size_a, "size_b": size_b,
        "sha256_a": hash_a, "sha256_b": hash_b,
        "header_notes": header_notes,
        "first_divergence": first_divergent_line(a["body"], b["body"]),
        "dims": dims,
    }


def render(d):
    out = []
    out.append("status:      A=%d B=%d%s"
               % (d["status_a"], d["status_b"],
                  "" if d["status_a"] == d["status_b"] else "  <-- DIFFERS"))
    out.append("size:        A=%d B=%d%s"
               % (d["size_a"], d["size_b"],
                  "" if d["size_a"] == d["size_b"] else "  <-- DIFFERS"))
    out.append("body sha256: A=%s" % d["sha256_a"])
    out.append("             B=%s%s"
               % (d["sha256_b"],
                  "" if d["sha256_a"] == d["sha256_b"] else "  <-- DIFFERS"))
    if d["header_notes"]:
        out.append("headers:")
        for note in d["header_notes"]:
            out.append("  %s" % note)
    else:
        out.append("headers:     no deltas")
    fd = d["first_divergence"]
    if fd:
        kind, side, line_no, la, lb = fd
        if kind == "extra":
            which = "B" if side == "b" else "A"
            out.append("first divergence: %s has extra content at line %d"
                       % (which, line_no))
        else:
            out.append("first divergence: line %d" % line_no)
            out.append("  A: %s" % la)
            out.append("  B: %s" % lb)
    else:
        out.append("first divergence: none (bodies line-identical)")
    if d["dims"]:
        out.append("--- VERDICT: DIFFERS [%s]" % ",".join(d["dims"]))
    else:
        out.append("--- VERDICT: IDENTICAL")
    out.append("note: Set-Cookie/Authorization values are masked here; "
               "redact secrets before D4. Run an A/A calibration pair "
               "before claiming any dimension as signal.")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Offline structured diff of two raw HTTP response files "
        "(status, headers-of-interest, size, body sha256, first divergent line).",
    )
    ap.add_argument("--a", dest="file_a", help="First raw HTTP response file")
    ap.add_argument("--b", dest="file_b", help="Second raw HTTP response file")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests with temp fixtures and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.file_a or not args.file_b:
        sys.stderr.write("error: --a and --b are required\n")
        return 1

    parsed = {}
    for label, path in (("A", args.file_a), ("B", args.file_b)):
        try:
            with open(path, "rb") as fh:
                parsed[label] = parse_response(fh.read())
        except OSError as exc:
            sys.stderr.write("error: cannot read %s: %s\n" % (path, exc))
            return 1
        except ValueError as exc:
            sys.stderr.write("error: malformed response %s: %s\n" % (label, exc))
            return 1

    print(render(diff_responses(parsed["A"], parsed["B"])))
    return 0


RESP_A = (b"HTTP/1.1 200 OK\r\n"
          b"Content-Type: text/html\r\n"
          b"Location: /a\r\n"
          b"Set-Cookie: sid=SECRETVALUEA; Path=/; HttpOnly\r\n"
          b"X-Request-Id: req-111\r\n"
          b"\r\n"
          b"<html><body>\nline1\nline2\nline3\n</body></html>\n")

RESP_B = (b"HTTP/1.1 200 OK\r\n"
          b"Content-Type: text/html\r\n"
          b"Location: /b\r\n"
          b"Set-Cookie: sid=SECRETVALUEB; Path=/; HttpOnly\r\n"
          b"X-Request-Id: req-222\r\n"
          b"\r\n"
          b"<html><body>\nline1\nlineX\nline3\n</body></html>\n")


def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    a = parse_response(RESP_A)
    b = parse_response(RESP_B)
    assert a["status"] == 200 and a["reason"] == "OK", a
    assert a["headers"]["content-type"] == ["text/html"], a
    assert a["body"].startswith(b"<html>"), a
    ok("parses status line, headers, body")

    d = diff_responses(a, b)
    assert "status" not in d["dims"], d["dims"]
    ok("status dimension equal when codes match")
    assert "headers" in d["dims"], d["dims"]
    notes = "\n".join(d["header_notes"])
    assert "location" in notes and "/a" in notes and "/b" in notes, notes
    ok("headers-of-interest delta reported (location)")
    assert "sid=<masked>" in notes and "SECRETVALUEA" not in notes, notes
    ok("Set-Cookie values masked in diff output")

    fd = d["first_divergence"]
    assert fd is not None and fd[0] == "diff" and fd[2] == 3, fd
    assert fd[3] == "line2" and fd[4] == "lineX", fd
    ok("first divergent body line located (line 3: line2 vs lineX)")
    assert "body-sha256" in d["dims"] and d["sha256_a"] != d["sha256_b"], d
    assert d["size_a"] == d["size_b"] and "size" not in d["dims"], d
    ok("body sha256 differs; equal sizes correctly not flagged")

    rendered = render(d)
    assert "VERDICT: DIFFERS" in rendered and "body-sha256" in rendered
    ok("rendered verdict lists differing dimensions")

    same = diff_responses(a, parse_response(RESP_A))
    assert same["dims"] == [], same["dims"]
    assert "VERDICT: IDENTICAL" in render(same)
    ok("identical pair -> IDENTICAL verdict, no dimensions")

    tail = diff_responses(parse_response(RESP_A),
                          parse_response(RESP_A + b"extra line\n"))
    assert tail["dims"] and "size" in tail["dims"], tail["dims"]
    assert tail["first_divergence"][0] == "extra", tail["first_divergence"]
    ok("extra-content tail detected (size + extra-line marker)")

    # CLI path with temp fixtures.
    with tempfile.TemporaryDirectory() as tmp:
        pa = os.path.join(tmp, "a.txt")
        pb = os.path.join(tmp, "b.txt")
        with open(pa, "wb") as fh:
            fh.write(RESP_A)
        with open(pb, "wb") as fh:
            fh.write(RESP_B)
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["--a", pa, "--b", pb])
        assert code == 0, code
        assert "VERDICT: DIFFERS" in buf.getvalue()
        ok("CLI --a/--b path works on fixture files")

        bad = os.path.join(tmp, "bad.txt")
        with open(bad, "wb") as fh:
            fh.write(b"not an http response\n")
        assert main(["--a", bad, "--b", pb]) == 1
        ok("malformed response file -> exit 1")

    print("[self-test] resp_diff: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
