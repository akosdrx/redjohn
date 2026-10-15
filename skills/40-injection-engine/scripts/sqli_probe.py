#!/usr/bin/env python3
"""sqli_probe.py - canonical SQL-injection probe set with baseline diffing.

Sends a bounded, canonical probe set against ONE parameter (one variable at a
time, serial requests) and compares each response against a captured baseline
on status / body length / body sha256. The time-based (sleep) probe is
refused unless --allow-time is passed (rules-of-engagement gate) and, when
run, is measured as a median of 5 on both probe and baseline sides.

Usage:
  python3 sqli_probe.py --scope-file scope.json \
      --target "http://target.example.com/item" --param id --method GET \
      [--value 1] [--allow-time] [--timeout 10] [--delay 0.2]

Exit codes: 0 = probe run completed (see verdicts in output); 2 = scope
refusal; 1 = other error (bad args, transport failure, target unreachable).

Evidence expectation: keep evidence/p5-sqli-<param>-<seq>.{req,resp}.txt for
the baseline and every probe that prints a DELTA / SIGNAL verdict.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import ipaddress
import socket

USER_AGENT = "redjohn-pentestskills/sqli_probe/1.0"

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


# ---------------------------------------------------------------- probe sets

# name, suffix appended to the original value
BASE_PROBES = [
    ("q-single", "'"),
    ("q-double", '"'),
    ("paren", "("),
    ("comment", "'-- -"),
    ("bool-true", "' AND '1'='1'-- -"),
    ("bool-false", "' AND '1'='2'-- -"),
]

SLEEP_PROBE = ("sleep", "' AND SLEEP(5)-- -")

SLEEP_SECONDS = 5.0
TIME_RUNS = 5  # medians of N>=5

DBMS_SIGNATURES = [
    ("MySQL-family", re.compile(
        rb"(SQL syntax|Warning: mysql_|MariaDB)", re.I)),
    ("PostgreSQL-family", re.compile(
        rb"(syntax error at or near|unterminated quoted string|PG::)", re.I)),
    ("MSSQL-family", re.compile(
        rb"(Unclosed quotation mark|Microsoft SQL|SqlClient|SQL Server)", re.I)),
    ("Oracle-family", re.compile(rb"ORA-[0-9]{5}")),
    ("SQLite-family", re.compile(
        rb"(SQLITE_ERROR|unrecognized token|SQLite)", re.I)),
]


def build_probe_set(allow_time):
    """Return the canonical probe list; sleep probe only when allowed."""
    probes = list(BASE_PROBES)
    if allow_time:
        probes.append(SLEEP_PROBE)
    return probes


# ---------------------------------------------------------------- transport


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def build_request(target, param, value, method):
    """Return (url, data_bytes_or_None) for the given param/value."""
    if method == "GET":
        sep = "&" if urllib.parse.urlparse(target).query else "?"
        url = target + sep + urllib.parse.urlencode({param: value})
        return url, None
    data = urllib.parse.urlencode({param: value}).encode("utf-8")
    return target, data


def send_request(target, param, value, method, timeout):
    """Send one request; return (status, body_bytes, elapsed_seconds)."""
    url, data = build_request(target, param, value, method)
    headers = {"User-Agent": USER_AGENT}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    start = time.monotonic()
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            body = resp.read()
            status = resp.status
    except urllib.error.HTTPError as err:  # keep error/redirect bodies: they are signal
        body = err.read()
        status = err.code
    except urllib.error.URLError as err:
        raise SystemExit("[error] transport failure for %s: %s" % (url, err))
    return status, body, time.monotonic() - start


def analyze(status, body, elapsed):
    return {
        "status": status,
        "len": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "elapsed": elapsed,
    }


def delta_fields(base, probe):
    fields = []
    if base["status"] != probe["status"]:
        fields.append("status")
    if base["len"] != probe["len"]:
        fields.append("len")
    if base["sha256"] != probe["sha256"]:
        fields.append("sha")
    return fields


def boolean_verdict(base, true_res, false_res):
    """Classify the boolean pair against the baseline."""
    if delta_fields(true_res, false_res):
        if true_res["sha256"] == base["sha256"]:
            return "BOOLEAN-SIGNAL (strong: TRUE==baseline, FALSE differs)"
        return ("BOOLEAN-SIGNAL (weak: TRUE!=FALSE, neither matches baseline; "
                "run false-positive checklist)")
    return "none"


def time_verdict(base_median, probe_median):
    if probe_median - base_median >= SLEEP_SECONDS - 1.0:
        return ("TIME-SIGNAL (probe median %.2fs vs baseline %.2fs)"
                % (probe_median, base_median))
    return ("none (probe median %.2fs vs baseline %.2fs)"
            % (probe_median, base_median))


def median(values):
    vals = sorted(values)
    n = len(vals)
    mid = n // 2
    if n % 2 == 1:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) / 2.0


def signature_hints(body):
    hints = []
    for name, rx in DBMS_SIGNATURES:
        if rx.search(body):
            hints.append(name)
    return hints


# ---------------------------------------------------------------- main flow


def run(args):
    scope = require_in_scope(args.target, args.scope_file)
    print("[scope] ok engagement=%s target=%s" %
          (scope.get("engagement", "unnamed"), args.target))
    print("[plan] probes=%d (sleep %s) serial delay=%.1fs" % (
        len(build_probe_set(args.allow_time)),
        "enabled" if args.allow_time else "refused-without---allow-time",
        args.delay))

    # baseline: one request for status/len/sha; five for timing when sleep runs
    results = {}
    base_runs = TIME_RUNS if args.allow_time else 1
    base_timings = []
    for i in range(base_runs):
        status, body, elapsed = send_request(
            args.target, args.param, args.value, args.method, args.timeout)
        base_timings.append(elapsed)
        if i == 0:
            baseline = analyze(status, body, elapsed)
            base_body = body
    results["baseline"] = baseline
    print("[baseline] value=%r status=%d len=%d sha256=%s elapsed=%.2fs" % (
        args.value, baseline["status"], baseline["len"],
        baseline["sha256"][:12], baseline["elapsed"]))
    for hint in signature_hints(base_body):
        print("[baseline] note: DBMS-like text already present (%s)" % hint)

    probe_results = {}
    for name, suffix in build_probe_set(args.allow_time):
        payload = args.value + suffix
        time.sleep(args.delay)
        if name == "sleep":
            timings = []
            probe = None
            for _ in range(TIME_RUNS):
                status, body, elapsed = send_request(
                    args.target, args.param, payload, args.method,
                    args.timeout)
                timings.append(elapsed)
                probe = analyze(status, body, elapsed)
            verdict = time_verdict(median(base_timings), median(timings))
            print("[probe] %-11s payload=%r timings_median=%.2fs -> %s"
                  % (name, payload, median(timings), verdict))
            probe_results[name] = verdict
            continue
        status, body, elapsed = send_request(
            args.target, args.param, payload, args.method, args.timeout)
        res = analyze(status, body, elapsed)
        changed = delta_fields(baseline, res)
        verdict = "DELTA(%s)" % ",".join(changed) if changed else "none"
        print("[probe] %-11s payload=%r status=%d len=%d sha256=%s -> %s" % (
            name, payload, res["status"], res["len"], res["sha256"][:12],
            verdict))
        for hint in signature_hints(body):
            print("[probe] %-11s error-signature: %s" % (name, hint))
        probe_results[name] = verdict
        if name == "bool-true":
            results["bool-true"] = res
        if name == "bool-false":
            results["bool-false"] = res

    if "bool-true" in results and "bool-false" in results:
        print("[verdict] boolean-pair: %s" % boolean_verdict(
            baseline, results["bool-true"], results["bool-false"]))

    print("[evidence] keep evidence/p5-sql-%s-<seq>.{req,resp}.txt for the "
          "baseline and every DELTA/SIGNAL probe" % args.param)
    print("[evidence] D2 = replay end-to-end from a clean session with both "
          "runs captured; timing claims need medians N>=%d on both runs" %
          TIME_RUNS)


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
        local_scope = {"engagement": "selftest", "allowed": [{"host": "localhost"}]}
        # 1. guard refuses https://example.com under a localhost-only scope
        ok, why = host_allowed("https://example.com", local_scope)
        assert ok is False, "example.com must be refused, got %s" % why
        # 2. guard refuses a private IP without an explicit CIDR entry
        ok, why = host_allowed("http://10.0.0.5/", local_scope)
        assert ok is False, "private IP must be refused without CIDR entry"
        assert why == "not-in-scope", why
        # 3. guard allows http://127.0.0.1:PORT when that host is listed
        loop_scope = {"engagement": "selftest",
                      "allowed": [{"host": "127.0.0.1"}]}
        ok, why = host_allowed("http://127.0.0.1:8080/", loop_scope)
        assert ok is True, "listed loopback must be allowed, got %s" % why
        # extra: cidr entry covers listed loopback; scheme check; fail-closed
        cidr_scope = {"engagement": "selftest",
                      "allowed": [{"cidr": "127.0.0.0/8"}]}
        ok, _ = host_allowed("http://127.0.0.1:9999/x", cidr_scope)
        assert ok is True, "cidr 127.0.0.0/8 must allow loopback"
        ok, why = host_allowed("ftp://127.0.0.1/x", loop_scope)
        assert ok is False and why == "scheme-not-http(s)", why
        ok, why = host_allowed("http://no-such-host.invalid/", local_scope)
        assert ok is False and why == "dns-unresolvable", why
        ok, why = host_allowed("http://10.0.0.5/", {"allowed": []})
        assert ok is False, "empty scope must refuse everything"
    finally:
        socket.getaddrinfo = original

    # probe-set gating: sleep absent unless allowed
    names = [n for n, _ in build_probe_set(False)]
    assert "sleep" not in names, "sleep probe must be gated behind --allow-time"
    names = [n for n, _ in build_probe_set(True)]
    assert "sleep" in names, "sleep probe must appear with --allow-time"

    # delta logic on canned analyses
    base = {"status": 200, "len": 100, "sha256": "aa", "elapsed": 0.1}
    same = dict(base)
    assert delta_fields(base, same) == []
    diff = {"status": 200, "len": 100, "sha256": "bb", "elapsed": 0.1}
    assert delta_fields(base, diff) == ["sha"]
    err500 = {"status": 500, "len": 40, "sha256": "cc", "elapsed": 0.1}
    assert delta_fields(base, err500) == ["status", "len", "sha"]

    # boolean verdict logic
    true_res = {"status": 200, "len": 100, "sha256": "aa", "elapsed": 0.1}
    false_res = {"status": 200, "len": 90, "sha256": "dd", "elapsed": 0.1}
    assert "strong" in boolean_verdict(base, true_res, false_res)
    both_diff = {"status": 200, "len": 80, "sha256": "ee", "elapsed": 0.1}
    assert "weak" in boolean_verdict(base, both_diff, false_res)
    assert boolean_verdict(base, true_res, true_res) == "none"

    # timing verdict + median
    assert time_verdict(0.2, 5.4).startswith("TIME-SIGNAL")
    assert time_verdict(0.2, 0.3).startswith("none")
    assert median([5.0, 5.2, 4.8, 5.1, 0.2]) == 5.0

    # signature hints
    assert signature_hints(b"... you have an error in your SQL syntax ...") == \
        ["MySQL-family"]
    assert signature_hints(b"ORA-01756: quoted string") == ["Oracle-family"]
    assert signature_hints(b"plain page") == []

    # request build: GET merges into query, POST encodes body (strings only)
    url, data = build_request("http://127.0.0.1:8080/item", "id", "1'", "GET")
    assert url.endswith("?id=1%27"), url
    url, data = build_request("http://127.0.0.1:8080/i?a=b", "id", "1'", "GET")
    assert url.endswith("&id=1%27"), url
    url, data = build_request("http://127.0.0.1:8080/i", "id", "1'", "POST")
    assert data == b"id=1%27", data

    print("[self-test] sqli_probe: all assertions passed (guard, gating, "
          "deltas, boolean, timing, signatures, request build)")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # usage errors are 'other errors' -> exit 1
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Canonical SQLi probe set with baseline diffing.")
    parser.add_argument("--scope-file", default=None,
                        help="engagement scope JSON (or env REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target", help="target URL (in scope)")
    parser.add_argument("--param", help="parameter name to probe")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--value", default="1",
                        help="original parameter value (payload prefix)")
    parser.add_argument("--allow-time", action="store_true",
                        help="RoE gate: allow the SLEEP probe (median-of-%d)"
                             % TIME_RUNS)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.2,
                        help="serial politeness delay between probes (s)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (no network) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.target or not args.param:
        parser.error("--target and --param are required")
    scope_file = args.scope_file or os.environ.get("REDJOHN_SCOPE_FILE")
    if not scope_file:
        sys.stderr.write("[error] no scope file: pass --scope-file or set "
                         "REDJOHN_SCOPE_FILE\n")
        sys.exit(1)
    args.scope_file = scope_file
    run(args)


if __name__ == "__main__":
    main()
