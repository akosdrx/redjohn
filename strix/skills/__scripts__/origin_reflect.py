#!/usr/bin/env python3
"""origin_reflect.py - CORS origin-reflection probe.

Sends GETs with a set of crafted Origin headers (arbitrary origin
https://evil.example, subdomain-suffix https://<target-host>.attacker.example,
and Origin: null) plus a self-origin control, then reports the
Access-Control-Allow-Origin / Access-Control-Allow-Credentials / Vary
reflection verdicts per references/cors-evaluation.md. Optionally also probes
preflight (OPTIONS) handling with --preflight.

Usage:
  python3 origin_reflect.py --scope-file scope.json --target https://target.example.com
  python3 origin_reflect.py --scope-file scope.json --target https://target.example.com --preflight

Exit codes: 0 = probe run completed (see verdicts); 2 = scope refusal;
1 = other error.

Evidence expectation: keep one request+response pair per probe origin as
evidence/p2-cors-<host>-<origin-slug>.{req,resp}.txt; re-run with a fresh
victim context for D2.
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

USER_AGENT = "redjohn-pentestskills/origin_reflect/1.0"

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


class Headers:
    def __init__(self, items):
        self._h = {}
        for name, value in items:
            self._h[name.lower()] = value.strip()

    def get(self, name, default=""):
        return self._h.get(name.lower(), default)


def evaluate_cors(probe_origin, h):
    """Verdict lines for one probe origin against response headers."""
    acao = h.get("access-control-allow-origin")
    acac = h.get("access-control-allow-credentials").lower()
    vary = h.get("vary", "")
    cred = acac == "true"
    lines = []
    if acao is None or acao == "":
        verdict = "NO-ACAO (no CORS for this origin)"
    elif acao.strip().lower() == "null" and probe_origin == "null":
        verdict = ("NULL-ALLOWED (FAIL: sandboxed iframe/data: pages send "
                   "Origin: null; chain via 55)"
                   if cred else
                   "NULL-ALLOWED (FAIL: Origin: null accepted)")
    elif acao.strip() == probe_origin:
        if cred:
            verdict = ("REFLECTED-CREDENTIALED (FAIL, CWE-942: any origin "
                       "reads authenticated responses with cookies)")
        else:
            verdict = ("REFLECTED (FAIL: arbitrary-origin cross-origin read)")
    elif acao.strip() == "*":
        verdict = ("WILDCARD+CREDS (FAIL as policy bug: browsers refuse "
                   "credentialed wildcard; copy-paste misconfig)"
                   if cred else
                   "WILDCARD (INFO: public data readable cross-origin)")
    else:
        verdict = "ACAO=%s (no reflection of this probe)" % acao.strip()
    lines.append(verdict)
    if cred and acao:
        lines.append("ACAC=true (credentials ride on cross-origin reads)")
    if acao and "origin" not in vary.lower():
        lines.append("Vary: Origin ABSENT with an ACAO policy "
                     "(shared-cache poisoning candidate)")
    elif acao and "origin" in vary.lower():
        lines.append("Vary: Origin present (cache keyed correctly)")
    return lines


def evaluate_preflight(h):
    """Verdict lines for an OPTIONS preflight response."""
    methods = h.get("access-control-allow-methods", "")
    headers = h.get("access-control-allow-headers", "")
    lines = []
    if "PUT" in methods.upper():
        lines.append("PREFLIGHT-REFLECT-METHOD (requested method echoed "
                     "without allowlist)")
    elif methods:
        lines.append("PREFLIGHT methods=%s (allowlist observed)" % methods)
    else:
        lines.append("PREFLIGHT no Access-Control-Allow-Methods")
    if "X-CUSTOM-PROBE" in headers.upper():
        lines.append("PREFLIGHT-REFLECT-HEADERS (custom header gate "
                     "bypassable)")
    elif headers:
        lines.append("PREFLIGHT headers=%s (allowlist observed)" % headers)
    age = h.get("access-control-max-age", "")
    if age:
        lines.append("PREFLIGHT max-age=%s (preflight result cached)" % age)
    return lines


def build_probe_origins(target):
    """Probe set: arbitrary, subdomain-suffix, null, plus self control."""
    host = urllib.parse.urlparse(target).hostname
    return [
        ("arbitrary", "https://evil.example"),
        ("subdomain-suffix", "https://%s.attacker.example" % host),
        ("null-origin", "null"),
        ("self-control", "https://%s" % host),
    ]


# ---------------------------------------------------------------- transport


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe(target, origin, method, extra_headers, timeout):
    opener = urllib.request.build_opener(_NoRedirect)
    head = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if origin:
        head["Origin"] = origin
    head.update(extra_headers)
    req = urllib.request.Request(target, headers=head, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, Headers(resp.getheaders())
    except urllib.error.HTTPError as err:
        return err.code, Headers(err.headers.items())


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


def _mk(pairs):
    return Headers([(k, v) for k, v in pairs])


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

    # --- probe origin construction ---
    probes = dict(build_probe_origins("https://target.example.com/app"))
    assert probes["arbitrary"] == "https://evil.example"
    assert probes["subdomain-suffix"] == \
        "https://target.example.com.attacker.example", probes
    assert probes["null-origin"] == "null"
    assert probes["self-control"] == "https://target.example.com"

    # --- reflection verdicts ---
    cred = evaluate_cors("https://evil.example", _mk([
        ("Access-Control-Allow-Origin", "https://evil.example"),
        ("Access-Control-Allow-Credentials", "true"),
    ]))
    assert any(l.startswith("REFLECTED-CREDENTIALED") for l in cred), cred
    assert any("ACAC=true" in l for l in cred), cred

    echo = evaluate_cors("https://evil.example", _mk([
        ("Access-Control-Allow-Origin", "https://evil.example"),
    ]))
    assert any(l.startswith("REFLECTED (") for l in echo), echo

    wild = evaluate_cors("https://evil.example", _mk([
        ("Access-Control-Allow-Origin", "*"),
    ]))
    assert any(l.startswith("WILDCARD (INFO") for l in wild), wild

    wild_cred = evaluate_cors("https://evil.example", _mk([
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
    ]))
    assert any("WILDCARD+CREDS" in l for l in wild_cred), wild_cred

    null_ok = evaluate_cors("null", _mk([
        ("Access-Control-Allow-Origin", "null"),
        ("Access-Control-Allow-Credentials", "true"),
    ]))
    assert any(l.startswith("NULL-ALLOWED") for l in null_ok), null_ok

    none = evaluate_cors("https://evil.example", _mk([("X", "y")]))
    assert any(l.startswith("NO-ACAO") for l in none), none

    suffix = evaluate_cors("https://target.example.com.attacker.example", _mk([
        ("Access-Control-Allow-Origin",
         "https://target.example.com.attacker.example"),
        ("Vary", "Origin"),
    ]))
    assert any(l.startswith("REFLECTED") for l in suffix), suffix
    assert any("Vary: Origin present" in l for l in suffix), suffix

    no_vary = evaluate_cors("https://evil.example", _mk([
        ("Access-Control-Allow-Origin", "https://evil.example"),
    ]))
    assert any("Vary: Origin ABSENT" in l for l in no_vary), no_vary

    # --- preflight verdicts ---
    pf = evaluate_preflight(_mk([
        ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"),
        ("Access-Control-Allow-Headers", "X-Custom-Probe"),
        ("Access-Control-Max-Age", "600"),
    ]))
    assert any("REFLECT-METHOD" in l for l in pf), pf
    assert any("REFLECT-HEADERS" in l for l in pf), pf
    pf2 = evaluate_preflight(_mk([
        ("Access-Control-Allow-Methods", "GET, POST"),
    ]))
    assert not any("REFLECT" in l for l in pf2), pf2

    print("[self-test] origin_reflect: guard(3) + probe-set construction + "
          "8 reflection fixtures + preflight fixtures passed")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(description="CORS origin-reflection probe (GET/OPTIONS).")
    parser.add_argument("--scope-file",
                        help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target", help="target URL to probe")
    parser.add_argument("--preflight", action="store_true",
                        help="also send an OPTIONS preflight probe")
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
    require_in_scope(args.target, scope_file)

    worst = "OK"
    rank = {"OK": 0, "INFO": 1, "FAIL": 2}
    for label, origin in build_probe_origins(args.target):
        try:
            status, headers = probe(args.target, origin, "GET", {},
                                    args.timeout)
        except (urllib.error.URLError, OSError) as err:
            print("[error] %s origin=%s failed: %s" % (label, origin, err))
            continue
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        vary = headers.get("vary")
        print("[probe] %-16s Origin: %-45s -> HTTP %d"
              % (label, origin, status))
        print("        ACAO=%r ACAC=%r Vary=%r" % (acao, acac, vary))
        for line in evaluate_cors(origin, headers):
            print("        %s" % line)
            if "FAIL" in line and worst != "FAIL":
                worst = "FAIL"
            elif "INFO" in line and worst == "OK":
                worst = "INFO"
        time.sleep(args.delay)

    if args.preflight:
        try:
            status, headers = probe(
                args.target, "https://evil.example", "OPTIONS",
                {"Access-Control-Request-Method": "PUT",
                 "Access-Control-Request-Headers": "X-Custom-Probe"},
                args.timeout)
        except (urllib.error.URLError, OSError) as err:
            print("[error] preflight failed: %s" % err)
            status, headers = None, None
        if status is not None:
            print("[preflight] OPTIONS + Origin: https://evil.example "
                  "-> HTTP %d" % status)
            for line in evaluate_preflight(headers):
                print("        %s" % line)
                if "REFLECT" in line:
                    worst = "FAIL" if rank["FAIL"] > rank[worst] else worst

    print("[summary] worst verdict: %s" % worst)
    print("[evidence] keep one request+response pair per executed probe as "
          "evidence/p2-cors-<host>-<origin-slug>.{req,resp}.txt; D2 = replay "
          "the reflected probe with a fresh victim context")


if __name__ == "__main__":
    main()
