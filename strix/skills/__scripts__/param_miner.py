#!/usr/bin/env python3
# param_miner.py - GET parameter prober with baseline response diffing.
#
# Probes candidate parameter names against one in-scope target URL and
# reports status/length/sha256 deltas versus a parameterless baseline.
# Requests are serial with a delay between probes (pace discipline).
#
# Scope: --scope-file PATH or REDJOHN_SCOPE_FILE. Absent/unreadable scope
# file -> exit 1 (refuses to send). Target not in scope -> exit 2.
#
# Exit codes: 0 success, 2 scope refusal, 1 other errors.

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_PARAMS = [
    "debug", "admin", "test", "preview", "action", "redirect", "next", "url",
    "file", "path", "template", "lang", "theme", "access", "role", "internal",
    "draft", "backup", "restore", "export", "format", "callback", "return",
    "continue", "data", "query", "cmd", "exec", "run", "command", "download",
    "view", "display", "page", "id", "type", "mode", "version", "env",
    "config",
]

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "redjohn-param-miner/1.0"


# ---------------------------------------------------------------------------
# Scope guard (canonical, from library CONVENTIONS.md - copy-adapted)
# ---------------------------------------------------------------------------

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
    try:
        with open(scope_file, "r", encoding="utf-8") as fh:
            scope = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.stderr.write(
            "[scope-guard] scope file unreadable (%s): %s\n" % (scope_file, exc)
        )
        sys.exit(1)
    ok, why = host_allowed(target, scope)
    if not ok:
        sys.stderr.write(
            "[scope-guard] refused %s (%s) engagement=%s\n"
            % (target, why, scope.get("engagement", "unnamed"))
        )
        sys.exit(2)
    return scope


# ---------------------------------------------------------------------------
# Fetching and probing (pure logic kept separate for offline self-test)
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch(url, timeout=DEFAULT_TIMEOUT):
    """GET url; return (status, body_bytes). HTTP errors/redirects return their code."""
    req = urllib.request.Request(
        url, method="GET", headers={"User-Agent": USER_AGENT}
    )
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            return int(status), resp.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()
    except Exception as exc:
        raise RuntimeError("request failed for %s: %s" % (url, exc))


def summarize(status, body):
    return {
        "status": status,
        "length": len(body),
        "sha256": hashlib.sha256(body).hexdigest()[:16],
    }


def add_param(target, name, value):
    """Append name=value to the target URL, preserving existing query params."""
    parts = urllib.parse.urlparse(target)
    qsl = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    qsl.append((name, value))
    return urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(qsl)))


def delta_fields(base, probe):
    return [d for d in ("status", "length", "sha256") if probe[d] != base[d]]


def probe_params(target, params, value, delay, fetcher=fetch):
    """Baseline + one serial probe per param. Returns (baseline, rows)."""
    status, body = fetcher(target)
    baseline = summarize(status, body)
    rows = []
    for name in params:
        p_status, p_body = fetcher(add_param(target, name, value))
        summary = summarize(p_status, p_body)
        rows.append((name, summary, delta_fields(baseline, summary)))
        if delay:
            time.sleep(delay)
    return baseline, rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_params(path):
    names = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                names.append(line)
    return names


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Probe GET parameter names against an in-scope target and "
        "report response deltas versus a parameterless baseline.",
    )
    ap.add_argument("--scope-file", default=os.environ.get("REDJOHN_SCOPE_FILE"),
                    help="Engagement scope JSON (default: REDJOHN_SCOPE_FILE)")
    ap.add_argument("--target", help="Full target URL, e.g. https://target.example.com/app")
    ap.add_argument("--params-file",
                    help="File with one candidate param name per line "
                         "(default: built-in ~40 common names)")
    ap.add_argument("--value", default=os.environ.get("REDJOHN_CANARY", "rj-pt-param-probe"),
                    help="Probe value (default: REDJOHN_CANARY or rj-pt-param-probe)")
    ap.add_argument("--delay", type=float, default=0.5,
                    help="Seconds between probes (default: 0.5, serial pace)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="Per-request timeout in seconds")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests (no network) and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.target or not args.scope_file:
        sys.stderr.write("error: --target and --scope-file are required "
                         "(or set REDJOHN_SCOPE_FILE)\n")
        return 1

    params = load_params(args.params_file) if args.params_file else list(DEFAULT_PARAMS)

    require_in_scope(args.target, args.scope_file)

    def cli_fetch(url):
        return fetch(url, timeout=args.timeout)

    sys.stderr.write("[param-miner] probing %d params against %s (serial, delay=%.1fs)\n"
                     % (len(params), args.target, args.delay))
    try:
        baseline, rows = probe_params(args.target, params, args.value,
                                      args.delay, fetcher=cli_fetch)
    except RuntimeError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1

    print("[baseline] status=%d length=%d sha256=%s"
          % (baseline["status"], baseline["length"], baseline["sha256"]))
    deltas = 0
    for name, summary, fields in rows:
        if fields:
            deltas += 1
            print("[delta] %-12s status=%d length=%d sha256=%s fields=%s"
                  % (name, summary["status"], summary["length"],
                     summary["sha256"], ",".join(fields)))
        else:
            print("[same]  %-12s status=%d length=%d"
                  % (name, summary["status"], summary["length"]))
    print("--- probed=%d deltas=%d" % (len(rows), deltas))
    print("evidence: for each delta save the request/response pair as "
          "evidence/p1-params-<seq>.{req,resp}.txt; re-run with a fresh "
          "cache-buster and an A/A calibration before promoting to D2.")
    return 0


# ---------------------------------------------------------------------------
# Self-test: offline, no network. DNS is monkeypatched; the DNS-fail-closed
# case uses a reserved .invalid TLD host.
# ---------------------------------------------------------------------------

def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *fn_args, **fn_kwargs):
        # Simulated DNS: no network. .invalid is reserved (RFC 6761).
        if host.endswith(".invalid"):
            raise socket.gaierror(-2, "fake NXDOMAIN for .invalid")
        table = {
            "example.com": "93.184.216.34",
            "localhost": "127.0.0.1",
        }
        if host in table:
            addr = table[host]
        else:
            try:
                ipaddress.ip_address(host)
                addr = host  # IP literal needs no DNS
            except ValueError:
                raise socket.gaierror(-2, "fake NXDOMAIN")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]

    socket.getaddrinfo = fake_getaddrinfo
    try:
        loopback_scope = {
            "engagement": "selftest",
            "allowed": [
                {"host": "localhost"},
                {"cidr": "127.0.0.0/8"},
                {"host": "127.0.0.1"},
            ],
        }

        res = host_allowed("https://example.com/", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses public host under localhost-only scope")

        res = host_allowed("http://10.0.0.5/", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses private IP without explicit CIDR entry")

        res = host_allowed("http://192.0.2.10/", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses doc-range IP not listed in scope")

        res = host_allowed("http://127.0.0.1:8080/app", loopback_scope)
        assert res[0] is True and res[1] in ("host", "cidr"), res
        ok("guard allows http://127.0.0.1:PORT when that host is listed")

        res = host_allowed("https://no-such-host.invalid/", loopback_scope)
        assert res == (False, "dns-unresolvable"), res
        ok("guard fails closed on unresolvable host (invalid TLD)")

        res = host_allowed("ftp://example.com/", loopback_scope)
        assert res == (False, "scheme-not-http(s)"), res
        ok("guard refuses non-http(s) scheme")
    finally:
        socket.getaddrinfo = real_getaddrinfo

    # Pure diff logic (no network).
    base = {"status": 200, "length": 10, "sha256": "a" * 16}
    same = dict(base)
    assert delta_fields(base, same) == []
    ok("delta_fields returns [] for identical summary")
    changed = {"status": 200, "length": 11, "sha256": "b" * 16}
    assert delta_fields(base, changed) == ["length", "sha256"]
    ok("delta_fields reports length+sha256 changes")

    url = add_param("http://127.0.0.1:8080/app?x=1", "debug", "rj-pt-param-probe")
    assert url == "http://127.0.0.1:8080/app?x=1&debug=rj-pt-param-probe", url
    ok("add_param preserves existing query params")

    # End-to-end probe wiring with a fake fetcher (no network).
    calls = []

    def fake_fetcher(url):
        calls.append(url)
        if "admin=" in url:
            return 302, b"redirected"
        return 200, b"0123456789"

    baseline, rows = probe_params("http://127.0.0.1:8080/app",
                                  ["debug", "admin"], "v", 0.0,
                                  fetcher=fake_fetcher)
    assert baseline == {"status": 200, "length": 10,
                        "sha256": hashlib.sha256(b"0123456789").hexdigest()[:16]}
    assert len(calls) == 3, calls
    deltas = {name: fields for name, _, fields in rows}
    assert deltas["debug"] == [], deltas
    assert deltas["admin"] != [], deltas
    ok("probe_params: baseline + serial probes, admin flagged as delta")

    print("[self-test] param_miner: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
