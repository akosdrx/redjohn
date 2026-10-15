#!/usr/bin/env python3
"""header_audit.py - security response-header baseline audit.

GETs the target once (no redirect following), scores each security header
present/missing/misconfigured with one-line verdicts (PASS/WARN/FAIL/INFO)
using the thresholds in references/header-baseline.md.

Usage:
  python3 header_audit.py --scope-file scope.json --target https://target.example.com
  python3 header_audit.py --self-test

Exit codes: 0 = audit completed (see verdicts); 2 = scope refusal;
1 = other error (bad args, transport failure).

Evidence expectation: keep the verbatim request and the scored response as
evidence/p2-headers-<host>-<seq>.{req,resp}.txt; re-run once for D2.
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "redjohn-pentestskills/header_audit/1.0"

# ---------------------------------------------------------------- scope guard


def host_allowed(target, scope):
    """Return (allowed, reason). Fail closed on any parse/DNS error."""
    try:
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return False, "scheme-not-http(s)"
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return False, "no-host"
        try:
            addrs = {info[4][0].split("%", 1)[0] for info in socket.getaddrinfo(host, None)}
        except socket.gaierror:
            return False, "dns-unresolvable"
        if not addrs:
            return False, "dns-unresolvable"
        parsed_addrs = [ipaddress.ip_address(a) for a in addrs]
        nets = []
        for entry in scope.get("allowed", []):
            if entry.get("host", "").lower().rstrip(".") == host:
                return True, "host"
            if "cidr" in entry:
                nets.append(ipaddress.ip_network(entry["cidr"], strict=False))
        if nets and all(any(ip in net for net in nets) for ip in parsed_addrs):
            return True, "cidr"
        return False, "not-in-scope"
    except Exception as exc:  # fail closed on anything unexpected
        return False, "error:%s" % exc


def require_in_scope(target, scope_file):
    """Exit(2) unless target is inside the engagement scope."""
    with open(scope_file, "r", encoding="utf-8") as fh:
        scope = json.load(fh)
    ok, why = host_allowed(target, scope)
    if not ok:
        sys.stderr.write(
            "[scope-guard] refused %s (%s) engagement=%s\n"
            % (target, why, scope.get("engagement", "unnamed"))
        )
        sys.exit(2)
    return scope


# ---------------------------------------------------------------- evaluation

HSTS_MIN_WARN = 15552000   # 180 days
HSTS_PASS = 31536000       # 1 year
POWERFUL_FEATURES = ("camera", "microphone", "geolocation", "payment", "usb")
REFERRER_PASS = {"no-referrer", "same-origin", "strict-origin",
                 "strict-origin-when-cross-origin"}
REFERRER_WARN = {"origin", "origin-when-cross-origin",
                 "no-referrer-when-downgrade"}


class Headers:
    """Case-insensitive read-only view over a header list."""

    def __init__(self, items):
        self._h = {}
        for name, value in items:
            key = name.lower()
            self._h[key] = (self._h.get(key, "") + (", " if key in self._h
                                                    else "") + value)

    def get(self, name, default=""):
        return self._h.get(name.lower(), default)

    def __contains__(self, name):
        return name.lower() in self._h


def parse_csp_directives(csp):
    """Return {directive: [tokens]} from a policy string."""
    out = {}
    for directive in csp.split(";"):
        tokens = directive.strip().split()
        if tokens:
            out[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return out


def csp_sources(dirs, name):
    """Effective sources for name, falling back to default-src."""
    return dirs.get(name) or dirs.get("default-src") or []


def eval_csp(h):
    lines = []
    csp = h.get("content-security-policy")
    if not csp:
        return [("Content-Security-Policy", "FAIL",
                 "missing on an HTML-rendering surface")]
    d = parse_csp_directives(csp)
    script = csp_sources(d, "script-src")
    if "unsafe-inline" in script:
        lines.append(("CSP script-src", "FAIL", "unsafe-inline allows "
                      "inline script execution"))
    if "unsafe-eval" in script:
        lines.append(("CSP script-src", "FAIL", "unsafe-eval keeps eval()"))
    if "*" in script:
        lines.append(("CSP script-src", "FAIL",
                      "wildcard source: any host may serve scripts"))
    for scheme in ("http:", "https:"):
        if scheme in script:
            lines.append(("CSP script-src", "WARN",
                          "bare scheme source %s trusts unknown hosts"
                          % scheme))
    if "unsafe-inline" in csp_sources(d, "style-src"):
        lines.append(("CSP style-src", "WARN",
                      "unsafe-inline (css exfil/defacement)"))
    obj = d.get("object-src")
    if obj is None and "default-src" not in d:
        lines.append(("CSP object-src", "WARN",
                      "no object-src and no default-src (plugin content "
                      "unconstrained)"))
    elif obj == ["*"]:
        lines.append(("CSP object-src", "FAIL", "wildcard object-src"))
    if "base-uri" not in d:
        lines.append(("CSP base-uri", "WARN",
                      "missing (<base> hijack rewrites relative URLs)"))
    if "frame-ancestors" not in d:
        lines.append(("CSP frame-ancestors", "WARN",
                      "missing (no CSP-level framing protection)"))
    if not script:
        lines.append(("CSP script-src", "FAIL",
                      "no script-src and no default-src (scripts "
                      "unconstrained)"))
    if "report-uri" not in d and "report-to" not in d:
        lines.append(("CSP reporting", "INFO", "no report-uri/report-to"))
    return lines or [("Content-Security-Policy", "PASS",
                      "no weakness matched by the threshold table")]


def eval_hsts(h, scheme):
    hsts = h.get("strict-transport-security")
    if scheme != "https":
        return [("Strict-Transport-Security", "INFO",
                 "not applicable over plain http")]
    if not hsts:
        return [("Strict-Transport-Security", "FAIL", "missing on HTTPS host")]
    m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
    if not m:
        return [("Strict-Transport-Security", "FAIL",
                 "present but max-age unparsable: %s" % hsts.strip())]
    age = int(m.group(1))
    if age >= HSTS_PASS:
        verdict = "PASS"
        detail = "max-age=%d (>= 1 year)" % age
    elif age >= HSTS_MIN_WARN:
        verdict = "WARN"
        detail = "max-age=%d below the 1-year bar" % age
    else:
        verdict = "FAIL"
        detail = "max-age=%d too short (< 180 days)" % age
    if "includesubdomains" not in hsts.lower():
        detail += "; includeSubDomains absent (subdomains unprotected)"
        if verdict == "PASS":
            verdict = "WARN"
    if "preload" in hsts.lower():
        detail += "; preload present"
    return [("Strict-Transport-Security", verdict, detail)]


def eval_framing(h):
    xfo = h.get("x-frame-options").strip()
    fa = "frame-ancestors" in parse_csp_directives(
        h.get("content-security-policy", ""))
    if xfo:
        if xfo.upper() in ("DENY", "SAMEORIGIN"):
            return [("X-Frame-Options", "PASS", xfo.upper())]
        if xfo.upper().startswith("ALLOW-FROM"):
            return [("X-Frame-Options", "WARN",
                     "ALLOW-FROM is deprecated; modern browsers ignore it")]
        return [("X-Frame-Options", "FAIL", "invalid value %r" % xfo)]
    if fa:
        return [("X-Frame-Options", "PASS",
                 "absent but CSP frame-ancestors covers framing")]
    return [("X-Frame-Options", "FAIL",
             "neither XFO nor CSP frame-ancestors: page is frameable "
             "(-> 55-client-side-attacks)")]


def eval_referrer(h):
    rp = h.get("referrer-policy").strip().lower()
    if not rp:
        return [("Referrer-Policy", "WARN",
                 "absent (browser default is strict-origin-when-cross-origin)")]
    if rp in REFERRER_PASS:
        return [("Referrer-Policy", "PASS", rp)]
    if rp == "unsafe-url":
        return [("Referrer-Policy", "FAIL",
                 "unsafe-url leaks full URL to any origin")]
    if rp in REFERRER_WARN:
        return [("Referrer-Policy", "WARN", "%s leaks more than needed" % rp)]
    return [("Referrer-Policy", "FAIL", "unknown value %r" % rp)]


def eval_permissions(h):
    pp = h.get("permissions-policy").strip()
    if not pp:
        return [("Permissions-Policy", "INFO",
                 "absent (per-feature browser defaults apply)")]
    bad = []
    for directive in pp.split(","):
        tokens = directive.strip().lower().split("=")
        if len(tokens) == 2 and tokens[0].strip() in POWERFUL_FEATURES:
            allow = tokens[1].strip()
            if allow == "*" or allow == "(*)":
                bad.append(tokens[0].strip())
    if bad:
        return [("Permissions-Policy", "FAIL",
                 "wildcard on powerful feature(s): %s" % ", ".join(bad))]
    return [("Permissions-Policy", "PASS", "no wildcard on powerful features")]


def eval_coop_cect(h):
    lines = []
    coop = h.get("cross-origin-opener-policy").strip().lower()
    if coop in ("same-origin",):
        lines.append(("Cross-Origin-Opener-Policy", "PASS", coop))
    elif coop in ("same-origin-allow-popups",):
        lines.append(("Cross-Origin-Opener-Policy", "WARN", coop))
    elif not coop:
        lines.append(("Cross-Origin-Opener-Policy", "WARN",
                      "absent on top-level document"))
    else:
        lines.append(("Cross-Origin-Opener-Policy", "WARN",
                      "value %r weakens isolation" % coop))
    ceep = h.get("cross-origin-embedder-policy").strip().lower()
    if ceep in ("require-corp", "credentialless"):
        lines.append(("Cross-Origin-Embedder-Policy", "PASS", ceep))
    elif not ceep:
        lines.append(("Cross-Origin-Embedder-Policy", "INFO", "absent"))
    else:
        lines.append(("Cross-Origin-Embedder-Policy", "WARN",
                      "value %r" % ceep))
    return lines


def eval_nosniff(h):
    xcto = h.get("x-content-type-options").strip()
    if xcto.lower() == "nosniff":
        return [("X-Content-Type-Options", "PASS", "nosniff")]
    if not xcto:
        return [("X-Content-Type-Options", "FAIL", "missing (MIME sniffing)")]
    return [("X-Content-Type-Options", "FAIL", "invalid value %r" % xcto)]


def eval_cache_control(h):
    authed = ("set-cookie" in h) or ("www-authenticate" in h)
    if not authed:
        return [("Cache-Control", "INFO",
                 "response unauthenticated; authenticated-response rule n/a")]
    cc = h.get("cache-control", "")
    if re.search(r"(^|[,\s])no-store([,\s]|$)", cc, re.I):
        return [("Cache-Control", "PASS",
                 "no-store on authenticated response (CWE-525 ok)")]
    if re.search(r"(^|[,\s])private([,\s]|$)", cc, re.I):
        return [("Cache-Control", "WARN",
                 "private without no-store on authenticated response")]
    return [("Cache-Control", "FAIL",
             "authenticated response without no-store (CWE-525)")]


def evaluate_headers(h, scheme):
    """Full audit; returns list of (header, verdict, detail) lines."""
    lines = []
    lines.extend(eval_csp(h))
    lines.extend(eval_hsts(h, scheme))
    lines.extend(eval_framing(h))
    lines.extend(eval_referrer(h))
    lines.extend(eval_permissions(h))
    lines.extend(eval_coop_cect(h))
    lines.extend(eval_nosniff(h))
    lines.extend(eval_cache_control(h))
    return lines


# ---------------------------------------------------------------- transport


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(target, timeout):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        target, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read(65536)
        return resp.status, Headers(resp.getheaders()), body


# ---------------------------------------------------------------- self-test


def _fake_getaddrinfo(host, port, *args, **kwargs):
    """Offline DNS stand-in: canned answers only, no network."""
    fake = {
        "example.com": ["93.184.216.34"],
        "target.example.com": ["203.0.113.10"],
        "localhost": ["127.0.0.1"],
        "127.0.0.1": ["127.0.0.1"],
        "10.0.0.5": ["10.0.0.5"],
    }
    if host in fake:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, port))
            for addr in fake[host]
        ]
    raise socket.gaierror(2, "offline fixture: unknown host")


GOOD_HEADERS = [
    ("Content-Security-Policy",
     "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
     "object-src 'none'; script-src 'self'"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("X-Content-Type-Options", "nosniff"),
    ("Set-Cookie", "session=redacted; HttpOnly; Secure"),
    ("Cache-Control", "no-store"),
]


def _verdicts(lines, header):
    return [v for h, v, d in lines if h.lower().startswith(header.lower())]


def self_test():
    # --- mandatory scope-guard assertions (offline via fake DNS) ---
    original = socket.getaddrinfo
    socket.getaddrinfo = _fake_getaddrinfo
    try:
        local_scope = {"engagement": "selftest",
                       "allowed": [{"host": "localhost"}]}
        ok, why = host_allowed("https://example.com", local_scope)
        assert ok is False, "example.com must be refused, got %s" % why
        ok, why = host_allowed("http://10.0.0.5/", local_scope)
        assert ok is False and why == "not-in-scope", why
        loop_scope = {"engagement": "selftest",
                      "allowed": [{"host": "127.0.0.1"}]}
        ok, why = host_allowed("http://127.0.0.1:8080/", loop_scope)
        assert ok is True, "listed loopback must be allowed, got %s" % why
        ok, why = host_allowed("http://target.example.com/",
                               {"allowed": [{"cidr": "203.0.113.0/24"}]})
        assert ok is True, "cidr entry must allow the documented host"
    finally:
        socket.getaddrinfo = original

    # --- header evaluation fixtures ---
    good = evaluate_headers(Headers(GOOD_HEADERS), "https")
    assert not [l for l in good if l[1] == "FAIL"], \
        "good fixture must have zero FAILs: %s" % good

    bad = evaluate_headers(Headers([]), "https")
    v = _verdicts(bad, "Content-Security-Policy")
    assert v and v[0] == "FAIL", v
    assert "FAIL" in _verdicts(bad, "Strict-Transport-Security")
    assert "FAIL" in _verdicts(bad, "X-Frame-Options")
    assert "FAIL" in _verdicts(bad, "X-Content-Type-Options")

    # CSP depth fixtures
    weak_csp = Headers([
        ("Content-Security-Policy",
         "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *")])
    lines = evaluate_headers(weak_csp, "https")
    assert "FAIL" in _verdicts(lines, "CSP script-src"), lines
    assert "FAIL" in [v for _h, v, _d in lines], \
        "unsafe-inline/unsafe-eval/wildcard must produce at least one FAIL"
    no_base = Headers([("Content-Security-Policy", "default-src 'self'")])
    lines = evaluate_headers(no_base, "https")
    assert "WARN" in _verdicts(lines, "CSP base-uri"), lines
    assert "WARN" in _verdicts(lines, "CSP frame-ancestors"), lines
    assert "FAIL" not in _verdicts(lines, "CSP object-src"), lines

    # HSTS thresholds
    for hsts, want in (("max-age=100", "FAIL"),
                       ("max-age=15552000", "WARN"),
                       ("max-age=31536000", "WARN"),  # includeSubDomains absent
                       ("max-age=31536000; includeSubDomains", "PASS"),
                       ("max-age=15552000; includeSubDomains", "WARN")):
        lines = evaluate_headers(
            Headers([("Strict-Transport-Security", hsts)]), "https")
        assert _verdicts(lines, "Strict-Transport-Security") == [want], \
            (hsts, lines)
    lines = evaluate_headers(
        Headers([("Strict-Transport-Security", "max-age=31536000")]), "https")
    assert _verdicts(lines, "Strict-Transport-Security") == ["WARN"], \
        "missing includeSubDomains must downgrade to WARN"
    lines = evaluate_headers(Headers([]), "http")
    assert _verdicts(lines, "Strict-Transport-Security") == ["INFO"]

    # framing interplay
    lines = evaluate_headers(Headers([("Content-Security-Policy",
                                       "frame-ancestors 'none'")]), "https")
    assert _verdicts(lines, "X-Frame-Options") == ["PASS"], lines
    lines = evaluate_headers(Headers([("X-Frame-Options", "ALLOW-FROM https://example.com")]),
                             "https")
    assert _verdicts(lines, "X-Frame-Options") == ["WARN"], lines

    # cache-control on authenticated responses
    auth_no_cc = Headers([("Set-Cookie", "s=redacted")])
    assert "FAIL" in _verdicts(evaluate_headers(auth_no_cc, "https"),
                               "Cache-Control")
    auth_private = Headers([("Set-Cookie", "s=redacted"),
                            ("Cache-Control", "private")])
    assert "WARN" in _verdicts(evaluate_headers(auth_private, "https"),
                               "Cache-Control")
    public_page = Headers([("Content-Type", "text/html")])
    assert "INFO" in _verdicts(evaluate_headers(public_page, "https"),
                               "Cache-Control")

    # referrer + permissions-policy
    lines = evaluate_headers(
        Headers([("Referrer-Policy", "unsafe-url")]), "https")
    assert "FAIL" in _verdicts(lines, "Referrer-Policy")
    lines = evaluate_headers(
        Headers([("Permissions-Policy", "camera=*, geolocation=()")]), "https")
    assert "FAIL" in _verdicts(lines, "Permissions-Policy"), lines

    print("[self-test] header_audit: guard(3+) + good/bad/weak fixtures + "
          "HSTS thresholds + framing/cache/referrer/permissions checks passed")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(description="Security response-header baseline audit.")
    parser.add_argument("--scope-file",
                        help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target", help="target URL to audit")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-request timeout seconds (default 10)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    scope_file = args.scope_file
    if not scope_file:
        import os
        scope_file = os.environ.get("REDJOHN_SCOPE_FILE")
    if not scope_file or not args.target:
        parser.error("--scope-file and --target are required")
    require_in_scope(args.target, scope_file)

    try:
        status, headers, body = fetch(args.target, args.timeout)
    except urllib.error.HTTPError as err:
        headers = Headers(err.headers.items())
        status = err.code
        sys.stderr.write("[note] target returned HTTP %d; scoring its "
                         "headers\n" % status)
    except (urllib.error.URLError, OSError) as err:
        sys.stderr.write("[error] request to %s failed: %s\n"
                         % (args.target, err))
        sys.exit(1)

    scheme = urllib.parse.urlparse(args.target).scheme
    print("[target] %s -> HTTP %d" % (args.target, status))
    if status in (301, 302, 303, 307, 308):
        loc = headers.get("location")
        print("[note] redirect to %s not followed; audit the final URL "
              "yourself" % loc)
    lines = evaluate_headers(headers, scheme)
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
    for header, verdict, detail in lines:
        counts[verdict] += 1
        print("[%-4s] %-30s %s" % (verdict, header, detail))
    print("[summary] PASS=%d WARN=%d FAIL=%d INFO=%d"
          % (counts["PASS"], counts["WARN"], counts["FAIL"], counts["INFO"]))
    print("[evidence] keep this request+response as "
          "evidence/p2-headers-<host>-<seq>.{req,resp}.txt; re-run once for "
          "D2 (stable across two fetches)")


if __name__ == "__main__":
    main()
