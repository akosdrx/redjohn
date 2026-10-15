#!/usr/bin/env python3
"""poc_render.py - render a raw HTTP evidence request as a report PoC
(90-evidence-reporting).

Parses a raw HTTP request file (as captured per
00-master-pentest-methodology/references/evidence-gates.md: optional leading
'#' comment lines carrying origin / auth / tool, then method, path, headers,
body) and emits, in order:

  1. a curl command (method/headers/body shell-escaped with shlex rules;
     Host and Content-Length are omitted - curl derives them);
  2. a markdown fenced block with the verbatim raw request;
  3. an evidence naming suggestion per the evidence-gates format
     evidence/<phase>-<surface>-<seq>.<req|resp>.txt (an input already named
     that way keeps its name; the response pair name is derived from it).

With --response FILE a response excerpt block (status, headers, first lines
of the body, truncation marker) is added, plus a redaction check over both
files (sensitive-looking headers/body patterns get WARNING lines - the
operator redacts before D4; this tool never rewrites evidence).

This tool is OFFLINE and never executes anything: it renders text only.
Replaying a rendered command belongs to the 20-traffic-manipulation harness
inside scope. No scope guard applies because no request is sent.

Usage:
  python3 poc_render.py --request evidence/p5-api-invoices-003.req.txt \\
      [--response evidence/p5-api-invoices-003.resp.txt] [--name api-invoices]
  python3 poc_render.py --self-test

Exit codes: 0 = rendered; 1 = unreadable/unparseable input or bad arguments.
"""

import argparse
import re
import shlex
import sys

EXCERPT_LINES = 20
META_KEYS = ("origin", "auth", "tool", "timestamp")
SENSITIVE_HEADERS = ("authorization", "proxy-authorization", "cookie",
                     "set-cookie", "x-api-key", "x-auth-token", "x-session")
SENSITIVE_BODY_PATTERNS = ("password=", "passwd=", "token=", "apikey=",
                           "api_key=", "secret=", "bearer ")
EVIDENCE_RE = re.compile(
    r"^(?P<dir>.*/)?evidence/(?P<phase>p\d{1,2})-(?P<surface>[a-z0-9]"
    r"[a-z0-9-]*?)-(?P<seq>\d+)\.(?P<kind>req|resp)\.txt$")


# --------------------------------------------------------------- parsing


class Request(object):
    def __init__(self, method, target, headers, body, comments, meta, crlf):
        self.method = method
        self.target = target
        self.headers = headers          # list of (name, value), order kept
        self.body = body                # str or None when no body section
        self.comments = comments        # verbatim '#' lines
        self.meta = meta                # {origin:..., auth:..., ...}
        self.crlf = crlf


class Response(object):
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body


def _split_comments(text):
    """-> (comment lines, remainder starting at the request line)."""
    lines = text.split("\n")
    comments = []
    idx = 0
    for line in lines:
        if line.startswith("#"):
            comments.append(line)
            idx += 1
        elif line.strip() == "":
            idx += 1        # blank line before the request line
        else:
            break
    return comments, "\n".join(lines[idx:])


def _parse_meta(comments):
    meta = {}
    for line in comments:
        body = line.lstrip("#").strip()
        for key in META_KEYS:
            m = re.match(r"%s\s*[:=]\s*(.+)$" % key, body, re.IGNORECASE)
            if m:
                meta[key] = m.group(1).strip()
    return meta


def parse_request(text):
    """-> Request; raises ValueError with a specific message on bad input."""
    crlf = "\r\n" in text
    normalized = text.replace("\r\n", "\n")
    comments, remainder = _split_comments(normalized)
    head, _, body = remainder.partition("\n\n")
    lines = head.split("\n") if head else []
    if not lines or not lines[0].strip():
        raise ValueError("no request line found (expected "
                         "'METHOD /path HTTP/x.y')")
    reqline = lines[0].strip()
    parts = reqline.split()
    if len(parts) != 3 or not parts[2].upper().startswith("HTTP/"):
        raise ValueError("unparseable request line: %r" % reqline)
    method, target = parts[0].upper(), parts[1]
    headers = []
    for line in lines[1:]:
        if line.strip() == "":
            continue
        if ":" not in line:
            raise ValueError("unparseable header line: %r" % line)
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return Request(method, target, headers,
                   body if body != "" else None,
                   comments, _parse_meta(comments), crlf)


def parse_response(text):
    """-> Response; raises ValueError on bad input."""
    normalized = text.replace("\r\n", "\n")
    comments, remainder = _split_comments(normalized)
    head, _, body = remainder.partition("\n\n")
    lines = head.split("\n") if head else []
    if not lines or not lines[0].strip():
        raise ValueError("no status line found (expected 'HTTP/x.y CODE ...')")
    status = lines[0].strip()
    if not status.split()[0].upper().startswith("HTTP/"):
        raise ValueError("unparseable status line: %r" % status)
    headers = []
    for line in lines[1:]:
        if line.strip() == "" or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return Response(status, headers, body)


# --------------------------------------------------------------- rendering


def _header_dict(headers):
    return {name.lower(): value for name, value in headers}


def build_url(req):
    """-> (url, note or None). Origin comment wins; absolute targets win."""
    if req.target.lower().startswith(("http://", "https://")):
        return req.target, None
    origin = req.meta.get("origin")
    if origin:
        return origin.rstrip("/") + req.target, None
    host = _header_dict(req.headers).get("host", "")
    if not host:
        raise ValueError("no origin comment and no Host header - cannot "
                         "build a URL")
    return "http://" + host + req.target, \
        "no origin comment found - scheme assumed http://; confirm scheme" \
        " (and TLS) before D4"


def build_curl(req):
    """-> curl command string (one line, shlex-quoted arguments)."""
    url, _note = build_url(req)
    args = ["-sS", "-i"]
    if any(ch in url for ch in "{}[]"):
        args.append("-g")
    if req.method != "GET" or req.body:
        args += ["-X", req.method]
    for name, value in req.headers:
        if name.lower() in ("host", "content-length"):
            continue                      # curl derives both
        args += ["-H", "%s: %s" % (name, value)]
    if req.body:
        args += ["--data-raw", req.body]
    args.append(url)
    return "curl " + " ".join(shlex.quote(a) for a in args)


def evidence_names(request_path, req, label):
    """-> (request_name, response_name, kept bool)."""
    match = EVIDENCE_RE.match(request_path.replace("\\", "/"))
    if match:
        base = "evidence/%s-%s-%s" % (match.group("phase"),
                                      match.group("surface"),
                                      match.group("seq"))
        return base + ".req.txt", base + ".resp.txt", True
    host = _header_dict(req.headers).get("host", "target")
    first_segment = req.target.split("?", 1)[0].strip("/").split("/")[0]
    slug = (label or first_segment or host)
    slug = re.sub(r"[^a-z0-9-]+", "-", slug.lower()).strip("-") or "surface"
    return ("evidence/p9-%s-001.req.txt" % slug,
            "evidence/p9-%s-001.resp.txt" % slug, False)


def redaction_findings(req, resp=None):
    hits = []
    for name, _value in req.headers:
        if name.lower() in SENSITIVE_HEADERS:
            hits.append("request header %r carries credential material"
                        % name)
    body = (req.body or "").lower()
    for pattern in SENSITIVE_BODY_PATTERNS:
        if pattern in body:
            hits.append("request body matches %r" % pattern)
    if resp is not None:
        for name, _value in resp.headers:
            if name.lower() in SENSITIVE_HEADERS:
                hits.append("response header %r carries credential "
                            "material" % name)
        low = resp.body.lower()
        for pattern in SENSITIVE_BODY_PATTERNS:
            if pattern in low:
                hits.append("response body matches %r" % pattern)
    return hits


def response_excerpt(resp):
    body_lines = resp.body.split("\n") if resp.body else []
    if body_lines and body_lines[-1] == "":
        body_lines.pop()                  # trailing-newline split artifact
    shown = body_lines[:EXCERPT_LINES]
    text = resp.status
    for name, value in resp.headers:
        text += "\n%s: %s" % (name, value)
    text += "\n"
    if shown:
        text += "\n" + "\n".join(shown)
    if len(body_lines) > EXCERPT_LINES:
        text += "\n... [truncated %d more body lines]" % (
            len(body_lines) - EXCERPT_LINES)
    return text


def render(request_path, req, response_path=None, resp=None, label=None):
    """-> (stdout text, warnings list)."""
    out = []
    warns = []
    out.append("== PoC render (90-evidence-reporting) ==")
    out.append("label: %s" % (label or "-"))
    out.append("")

    out.append("[curl command]")
    _url, note = build_url(req)
    out.append("  " + build_curl(req))
    if note:
        out.append("  note: %s" % note)
        warns.append(note)
    out.append("")

    out.append("[raw request]")
    out.append("```http")
    out.append(_verbatim_request(req))
    out.append("```")
    out.append("")

    req_name, resp_name, kept = evidence_names(request_path, req, label)
    out.append("[evidence naming]")
    out.append("  request : %s%s" % (
        req_name, "  (existing convention name kept)" if kept else
        "  (suggested; use the capture phase, not p9, if known)"))
    out.append("  response: %s  (pair with the same phase-surface-seq)"
               % resp_name)
    out.append("  evidence expectation: keep the request+response pair for"
               " BOTH D2 runs (adjacent seq numbers).")
    out.append("")

    if resp is not None:
        suffix = " (%s)" % response_path if response_path else ""
        out.append("[response excerpt%s]" % suffix)
        out.append("```http")
        out.append(response_excerpt(resp))
        out.append("```")
        out.append("")

    out.append("[preconditions]")
    auth = req.meta.get("auth")
    if auth:
        out.append("  auth context: %s (from request comment)" % auth)
    else:
        out.append("  auth context: NOT stated in the request file - add "
                   "it (label, role) plus any state setup (e.g. object to "
                   "create first)")
        warns.append("auth context missing from the request file comments")
    out.append("  negative control: rerun the same request without the "
               "payload / with the other role's token; show the baseline "
               "behavior next to the PoC.")
    out.append("")

    out.append("[redaction check]")
    hits = redaction_findings(req, resp)
    if hits:
        for hit in hits:
            line = "  WARNING: %s - replace with a placeholder before D4" \
                   % hit
            out.append(line)
            warns.append(hit)
        out.append("  originals stay unredacted inside the engagement "
                   "namespace only")
    else:
        out.append("  no sensitive-looking headers/body patterns detected"
                   " (heuristic sweep - operator confirms before D4)")
    out.append("")
    out.append("[reminder] this tool rendered text only; replay belongs to "
               "the 20-traffic-manipulation harness, inside scope.")
    return "\n".join(out), warns


def _verbatim_request(req):
    text = "%s %s HTTP/1.1" % (req.method, req.target)
    for name, value in req.headers:
        text += "\n%s: %s" % (name, value)
    if req.body is not None:
        text += "\n\n" + req.body
    return text


# ---------------------------------------------------------------- self-test


FIX_GET = (
    "# origin: https://target.example\n"
    "# auth: user-a@example.com (role: user)\n"
    "# tool: curl 8.4.0\n"
    "\n"
    "GET /search?q=rj-pt-eng1-ab12 HTTP/1.1\r\n"
    "Host: target.example\r\n"
    "User-Agent: assessment/1.0\r\n"
    "Accept: */*\r\n"
    "\r\n"
)

FIX_FORM = (
    "# origin: https://target.example\n"
    "# auth: anonymous\n"
    "POST /login HTTP/1.1\n"
    "Host: target.example\n"
    "Content-Type: application/x-www-form-urlencoded\n"
    "Content-Length: 41\n"
    "\n"
    "username=user-a%40example.com&password=rj-pt-placeholder\n"
)

FIX_JSON = (
    "# origin: https://target.example\n"
    "# auth: user-b@example.com (role: admin)\n"
    "POST /api/notes HTTP/1.1\n"
    "Host: target.example\n"
    "Content-Type: application/json\n"
    "X-Note: it's a \"test\" (rj-pt-eng1-cd34)\n"
    "User-Agent: assess'24 agent\n"
    "\n"
    "{\"title\": \"rj-pt-eng1-cd34\", \"note\": \"line'breaks and spaces\"}\n"
)

FIX_RESP = (
    "HTTP/1.1 200 OK\n"
    "Content-Type: application/json\n"
    "Set-Cookie: session=rj-pt-placeholder; Path=/\n"
    "\n"
    + "\n".join("{\"row\": %d}" % i for i in range(30)) + "\n"
)


def self_test():
    import io
    import contextlib
    import os
    import tempfile

    # 1. GET with query (CRLF wire format, comment metadata)
    req = parse_request(FIX_GET)
    assert req.method == "GET" and req.crlf
    assert req.target == "/search?q=rj-pt-eng1-ab12"
    assert req.meta["origin"] == "https://target.example"
    assert req.meta["auth"].startswith("user-a@example.com")
    curl = build_curl(req)
    assert curl.startswith("curl -sS -i ")
    assert "'https://target.example/search?q=rj-pt-eng1-ab12'" in curl
    assert "-X" not in curl and "--data-raw" not in curl
    assert "Host:" not in curl                       # derived by curl
    # shell round-trip: the quoted command parses back to the same args
    import shlex as _sh
    parts = _sh.split(curl[len("curl "):])
    assert parts[-1] == "https://target.example/search?q=rj-pt-eng1-ab12"
    assert parts[:2] == ["-sS", "-i"]

    # 2. POST form: method flag, body flag, header filtering, body redaction
    req = parse_request(FIX_FORM)
    curl = build_curl(req)
    assert "-X POST" in curl
    assert "'Content-Type: application/x-www-form-urlencoded'" in curl
    assert "Content-Length" not in curl              # derived by curl
    assert "--data-raw" in curl and "username=user-a" in curl
    hits = redaction_findings(req)
    assert any("password=" in h for h in hits), hits

    # 3. POST JSON: headers and body needing single-quote escaping
    req = parse_request(FIX_JSON)
    assert req.headers[2] == ("X-Note", 'it\'s a "test" (rj-pt-eng1-cd34)')
    curl = build_curl(req)
    # shlex.quote escapes single quotes (as '\'' or '"'"' per version);
    # the portable proof is the full round-trip below.
    parts = _sh.split(curl[len("curl "):])
    expected = ["-sS", "-i", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-H", "X-Note: it's a \"test\" (rj-pt-eng1-cd34)",
                "-H", "User-Agent: assess'24 agent",
                "--data-raw", req.body,
                "https://target.example/api/notes"]
    assert parts == expected, parts
    assert not redaction_findings(req)

    # 3b. GET with body preserves -X GET; URL with brackets/braces adds -g
    get_body_req = parse_request(
        "# origin: https://target.example\n"
        "GET /items?filter[role]=admin&tpl={{x}} HTTP/1.1\n"
        "Host: target.example\n"
        "\n"
        "{\"q\": 1}\n"
    )
    gb_parts = _sh.split(build_curl(get_body_req)[len("curl "):])
    assert "-g" in gb_parts and "-X" in gb_parts, gb_parts
    assert gb_parts[gb_parts.index("-X") + 1] == "GET", gb_parts

    # 4. response excerpt: truncation + Set-Cookie redaction warning
    resp = parse_response(FIX_RESP)
    assert resp.status == "HTTP/1.1 200 OK"
    excerpt = response_excerpt(resp)
    assert excerpt.startswith("HTTP/1.1 200 OK")
    assert "[truncated 10 more body lines]" in excerpt
    hits = redaction_findings(parse_request(FIX_JSON), resp)
    assert any("Set-Cookie" in h for h in hits), hits

    # 5. evidence naming: convention name kept; suggestion otherwise
    n1, n2, kept = evidence_names(
        "evidence/p5-api-invoices-003.req.txt", parse_request(FIX_JSON), None)
    assert kept and n1 == "evidence/p5-api-invoices-003.req.txt"
    assert n2 == "evidence/p5-api-invoices-003.resp.txt"
    n1, n2, kept = evidence_names("/tmp/req.txt", parse_request(FIX_GET), None)
    assert not kept and n1 == "evidence/p9-search-001.req.txt", n1
    n1, _n2, kept = evidence_names("/tmp/req.txt", parse_request(FIX_GET),
                                   "api-invoices")
    assert n1 == "evidence/p9-api-invoices-001.req.txt"

    # 6. no-origin fallback + unparseable input
    bare = "GET /x HTTP/1.1\nHost: target.example\n"
    url, note = build_url(parse_request(bare))
    assert url == "http://target.example/x" and note and "http" in note
    for bad in ("", "garbage\n", "GET /x\n", "GET /x HTTP/1.1\nbad header\n"):
        try:
            parse_request(bad)
            raise AssertionError("expected ValueError for %r" % bad)
        except ValueError:
            pass

    # 7. end-to-end through main(): files, output shape, exit codes
    with tempfile.TemporaryDirectory() as tmp:
        req_path = os.path.join(tmp, "evidence",
                                "p4-api-invoices-003.req.txt")
        os.makedirs(os.path.dirname(req_path))
        with open(req_path, "w", encoding="utf-8") as fh:
            fh.write(FIX_JSON)
        resp_path = os.path.join(tmp, "evidence",
                                 "p4-api-invoices-003.resp.txt")
        with open(resp_path, "w", encoding="utf-8") as fh:
            fh.write(FIX_RESP)
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--request", req_path, "--response", resp_path,
                         "--name", "api-invoices"])
        assert code == 0, err.getvalue()
        text = buf.getvalue()
        for section in ("[curl command]", "[raw request]",
                        "[evidence naming]", "[response excerpt",
                        "[preconditions]", "[redaction check]"):
            assert section in text, section
        assert text.index("[curl command]") < text.index("[raw request]") < \
            text.index("[evidence naming]") < text.index("[response excerpt")
        assert "evidence/p4-api-invoices-003.resp.txt" in text
        assert "Set-Cookie" in text                     # redaction warning
        assert "NOT stated" not in text                 # auth came from meta

        bad_path = os.path.join(tmp, "bad.req.txt")
        with open(bad_path, "w", encoding="utf-8") as fh:
            fh.write("not an http request\n")
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(["--request", bad_path])
        assert code == 1 and "[error]" in err.getvalue()

    print("[self-test] poc_render: GET-with-query (CRLF), POST form, POST "
          "JSON with escaping-needing headers (shlex round-trip), response "
          "excerpt truncation, redaction warnings (password=/Set-Cookie), "
          "evidence naming keep+suggest, no-origin fallback, 4 parse "
          "failures, end-to-end exit codes 0/1 - passed")


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main(argv=None):
    parser = _Parser(
        description="Offline renderer: raw HTTP request file -> curl "
                    "command + raw request block + evidence naming "
                    "suggestion (+ response excerpt). Never executes "
                    "anything.")
    parser.add_argument("--request", help="raw HTTP request file "
                        "(evidence/<phase>-<surface>-<seq>.req.txt)")
    parser.add_argument("--response", help="optional response file; adds an "
                        "excerpt block and extends the redaction check")
    parser.add_argument("--name", help="short label used for the PoC and "
                        "for evidence naming when the input is not named "
                        "per the convention (e.g. api-invoices)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    if not args.request:
        parser.error("--request is required (or --self-test)")

    try:
        with open(args.request, "r", encoding="utf-8") as fh:
            req_text = fh.read()
        req = parse_request(req_text)
    except (OSError, ValueError) as exc:
        sys.stderr.write("[error] cannot parse %s: %s\n" % (args.request, exc))
        return 1

    resp = None
    if args.response:
        try:
            with open(args.response, "r", encoding="utf-8") as fh:
                resp = parse_response(fh.read())
        except (OSError, ValueError) as exc:
            sys.stderr.write("[error] cannot parse %s: %s\n"
                             % (args.response, exc))
            return 1

    try:
        text, _warns = render(args.request, req, args.response, resp,
                              args.name)
    except ValueError as exc:
        sys.stderr.write("[error] %s\n" % exc)
        return 1
    sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
