#!/usr/bin/env python3
# req_replay.py - scope-guarded raw HTTP request replay.
#
# Parses a raw HTTP request file (request line, Host header, headers, body),
# applies optional --extra-header overrides, validates the FINAL Host against
# the engagement scope BEFORE any socket is opened, then replays the request
# verbatim, printing status/headers/timing. Optionally saves the evidence
# pair (<prefix>.req.txt / <prefix>.resp.txt).
#
# Scheme defaults to https (use --scheme http for plain lab fixtures).
# TLS certificate verification is ON unless --insecure-ok is given.
#
# Scope: --scope-file PATH or REDJOHN_SCOPE_FILE. Absent/unreadable scope
# file -> exit 1 (refuses to send). Final Host not in scope -> exit 2.
#
# Exit codes: 0 success, 2 scope refusal, 1 other errors.

import argparse
import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse

DEFAULT_TIMEOUT = 15.0
BODY_PREVIEW_BYTES = 2048


# ---------------------------------------------------------------------------
# Scope guard (canonical, from library CONVENTIONS.md - copy-adapted)
# ---------------------------------------------------------------------------

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
# Raw request parsing (pure; unit-tested offline)
# ---------------------------------------------------------------------------

def parse_extra_headers(items):
    headers = []
    for item in items or []:
        if ":" not in item:
            raise ValueError("bad --extra-header (expected 'K: V'): %r" % item)
        name, value = item.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return headers


def build_plan(data, extra_headers=None, scheme="https"):
    """Parse raw request bytes into a replay plan dict. Raises ValueError."""
    if b"\r\n\r\n" in data:
        head, body = data.split(b"\r\n\r\n", 1)
        sep = "\r\n"
    elif b"\n\n" in data:
        head, body = data.split(b"\n\n", 1)
        sep = "\n"
    else:
        head, body = data, b""
        sep = "\r\n" if b"\r\n" in data else "\n"

    lines = head.decode("latin-1").split(sep)
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        raise ValueError("empty request file")

    parts = lines[0].split()
    if len(parts) == 3:
        method, target, _version = parts
    elif len(parts) == 2:
        method, target = parts
    else:
        raise ValueError("malformed request line: %r" % lines[0])

    headers = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if line[0] in (" ", "\t") and headers:  # folded continuation
            name, value = headers[-1]
            headers[-1] = (name, value + " " + line.strip())
            continue
        if ":" not in line:
            raise ValueError("malformed header line: %r" % line)
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))

    for name, value in extra_headers or []:
        replaced = False
        for idx, (existing, _v) in enumerate(headers):
            if existing.lower() == name.lower():
                headers[idx] = (existing, value)
                replaced = True
                break
        if not replaced:
            headers.append((name, value))

    host_header = None
    for name, value in headers:
        if name.lower() == "host":
            host_header = value
            break
    if not host_header:
        raise ValueError("request has no Host header; cannot build target URL")

    # Absolute-form request targets carry their own origin.
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urllib.parse.urlparse(target)
        if parsed.netloc:
            host_header = parsed.netloc
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query

    if scheme not in ("http", "https"):
        raise ValueError("scheme must be http or https")

    hostport = host_header
    if ":" in hostport and not hostport.startswith("["):
        host, port_s = hostport.rsplit(":", 1)
        if not port_s.isdigit():
            raise ValueError("bad port in Host header: %r" % host_header)
        port = int(port_s)
    else:
        host, port = hostport, (443 if scheme == "https" else 80)

    if target == "*":
        target = "/"

    return {
        "method": method.upper(),
        "target": target,
        "headers": headers,
        "body": body,
        "host": host,
        "port": port,
        "scheme": scheme,
        "url": "%s://%s%s" % (scheme, hostport, target),
    }


# ---------------------------------------------------------------------------
# Sending (network; monkeypatched during self-test)
# ---------------------------------------------------------------------------

def send_request(plan, timeout=DEFAULT_TIMEOUT, insecure_ok=False):
    """Execute the plan. Returns dict(status, reason, headers, body, time_ms)."""
    if plan["scheme"] == "https":
        if insecure_ok:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(
            plan["host"], plan["port"], timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(
            plan["host"], plan["port"], timeout=timeout)

    started = time.perf_counter()
    try:
        conn.putrequest(plan["method"], plan["target"],
                        skip_host=True, skip_accept_encoding=True)
        for name, value in plan["headers"]:
            conn.putheader(name, value)
        if plan["body"] and not any(n.lower() == "content-length"
                                    for n, _ in plan["headers"]):
            conn.putheader("Content-Length", str(len(plan["body"])))
        conn.endheaders(plan["body"])
        resp = conn.getresponse()
        status, reason = resp.status, resp.reason
        headers = resp.getheaders()
        body = resp.read()
    finally:
        conn.close()
    return {
        "status": status,
        "reason": reason,
        "headers": headers,
        "body": body,
        "time_ms": (time.perf_counter() - started) * 1000.0,
    }


def save_evidence_pair(prefix, plan, result, auth_context, insecure_ok):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    comment = ("# origin=%s time=%s auth-context=%s tool=req_replay.py"
               " insecure_ok=%s\n"
               % (plan["url"], stamp, auth_context, insecure_ok))
    head = "%s %s HTTP/1.1" % (plan["method"], plan["target"])
    header_lines = ["%s: %s" % (n, v) for n, v in plan["headers"]]
    if plan["body"] and not any(n.lower() == "content-length"
                                for n, _ in plan["headers"]):
        header_lines.append("Content-Length: %d" % len(plan["body"]))
    with open(prefix + ".req.txt", "wb") as fh:
        fh.write(comment.encode("utf-8"))
        fh.write(("\n".join([head] + header_lines) + "\n\n").encode("latin-1"))
        fh.write(plan["body"])
    status_line = "HTTP/1.1 %d %s" % (result["status"], result["reason"])
    resp_headers = ["%s: %s" % (n, v) for n, v in result["headers"]]
    with open(prefix + ".resp.txt", "wb") as fh:
        fh.write(comment.encode("utf-8"))
        fh.write(("\n".join([status_line] + resp_headers) + "\n\n")
                 .encode("latin-1"))
        fh.write(result["body"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Scope-guarded replay of a raw HTTP request file. The "
        "final Host (after --extra-header overrides) is validated against "
        "the engagement scope BEFORE any connection is made.",
    )
    ap.add_argument("--scope-file", default=os.environ.get("REDJOHN_SCOPE_FILE"),
                    help="Engagement scope JSON (default: REDJOHN_SCOPE_FILE)")
    ap.add_argument("--request-file", help="Raw HTTP request file (must contain a Host header)")
    ap.add_argument("--extra-header", action="append", default=[], metavar="'K: V'",
                    help="Header to set/override (repeatable)")
    ap.add_argument("--scheme", choices=("http", "https"), default="https",
                    help="Scheme for the target URL (default: https)")
    ap.add_argument("--insecure-ok", action="store_true",
                    help="Skip TLS certificate verification (recorded in evidence)")
    ap.add_argument("--save", metavar="PREFIX",
                    help="Save evidence pair as PREFIX.req.txt / PREFIX.resp.txt")
    ap.add_argument("--auth-context", default="unlabeled",
                    help="Auth context label written into saved evidence")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="Socket timeout in seconds")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests (no network) and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.request_file or not args.scope_file:
        sys.stderr.write("error: --request-file and --scope-file are required "
                         "(or set REDJOHN_SCOPE_FILE)\n")
        return 1

    try:
        with open(args.request_file, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        sys.stderr.write("error: cannot read request file: %s\n" % exc)
        return 1

    try:
        extra = parse_extra_headers(args.extra_header)
        plan = build_plan(data, extra_headers=extra, scheme=args.scheme)
    except ValueError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1

    # Scope check on the FINAL target BEFORE any socket is opened.
    require_in_scope(plan["url"], args.scope_file)

    if args.scheme == "https" and args.insecure_ok:
        sys.stderr.write("[replay] warning: TLS certificate verification "
                         "disabled (--insecure-ok)\n")

    sys.stderr.write("[replay] %s %s://%s%s (%d byte body)\n"
                     % (plan["method"], plan["scheme"],
                        plan["host"] + (":%d" % plan["port"]
                                        if plan["port"] not in (80, 443) else ""),
                        plan["target"], len(plan["body"])))
    try:
        result = send_request(plan, timeout=args.timeout,
                              insecure_ok=args.insecure_ok)
    except Exception as exc:
        sys.stderr.write("error: request failed: %s\n" % exc)
        return 1

    print("[replay] status=%d reason=%s time_ms=%.1f"
          % (result["status"], result["reason"], result["time_ms"]))
    print("[replay] ---- response headers ----")
    for name, value in result["headers"]:
        print("%s: %s" % (name, value))
    print("[replay] ---- body (first %d bytes) ----" % BODY_PREVIEW_BYTES)
    print(result["body"][:BODY_PREVIEW_BYTES]
          .decode("utf-8", errors="replace"))
    if args.save:
        save_evidence_pair(args.save, plan, result,
                           args.auth_context, args.insecure_ok)
        print("[replay] evidence pair saved: %s.req.txt / %s.resp.txt"
              % (args.save, args.save))
    print("evidence: keep request+response pairs as "
          "evidence/<phase>-<surface>-<seq>.{req,resp}.txt; replay from a "
          "clean session before promoting any finding to D2.")
    return 0


# ---------------------------------------------------------------------------
# Self-test: offline, no network. DNS monkeypatched; the DNS-fail-closed
# case uses a reserved .invalid TLD host. Sending is monkeypatched out.
# ---------------------------------------------------------------------------

def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    import tempfile

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *fn_args, **fn_kwargs):
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
                addr = host
            except ValueError:
                raise socket.gaierror(-2, "fake NXDOMAIN")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]

    # --- guard cases (canonical assertions) + scope-before-send dispatch,
    # --- all under the fake DNS so no network is touched ---
    loopback_scope = {
        "engagement": "selftest",
        "allowed": [
            {"host": "localhost"},
            {"cidr": "127.0.0.0/8"},
            {"host": "127.0.0.1"},
        ],
    }
    sent = []
    real_send = send_request

    def fake_send(plan, timeout=DEFAULT_TIMEOUT, insecure_ok=False):
        sent.append(plan)
        return {"status": 200, "reason": "OK",
                "headers": [("Content-Type", "text/plain")],
                "body": b"ok", "time_ms": 1.0}

    socket.getaddrinfo = fake_getaddrinfo
    globals()["send_request"] = fake_send
    try:
        res = host_allowed("https://example.com/", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses public host under localhost-only scope")

        res = host_allowed("http://10.0.0.5/", loopback_scope)
        assert res == (False, "not-in-scope"), res
        ok("guard refuses private IP without explicit CIDR entry")

        res = host_allowed("http://127.0.0.1:8443/x", loopback_scope)
        assert res[0] is True and res[1] in ("host", "cidr"), res
        ok("guard allows http://127.0.0.1:PORT when that host is listed")

        res = host_allowed("https://no-such-host.invalid/", loopback_scope)
        assert res == (False, "dns-unresolvable"), res
        ok("guard fails closed on unresolvable host (invalid TLD)")

        res = host_allowed("gopher://example.com/", loopback_scope)
        assert res == (False, "scheme-not-http(s)"), res
        ok("guard refuses non-http(s) scheme")

        # --- parsing (pure) ---
        raw = (b"POST /api/v1/things HTTP/1.1\r\n"
               b"Host: target.example.com\r\n"
               b"Content-Type: application/json\r\n"
               b"\r\n"
               b'{\"n\": 1}')
        plan = build_plan(raw)
        assert plan["method"] == "POST", plan
        assert plan["target"] == "/api/v1/things", plan
        assert plan["host"] == "target.example.com", plan
        assert plan["port"] == 443, plan
        assert plan["scheme"] == "https", plan
        assert plan["body"] == b'{"n": 1}', plan
        assert plan["url"] == "https://target.example.com/api/v1/things", plan
        ok("parses request line, Host, headers, body; https default")

        raw2 = raw.replace(b"target.example.com", b"127.0.0.1:8443")
        plan2 = build_plan(raw2, scheme="http")
        assert plan2["host"] == "127.0.0.1" and plan2["port"] == 8443, plan2
        assert plan2["url"] == "http://127.0.0.1:8443/api/v1/things", plan2
        ok("Host header port honored; --scheme http supported")

        plan3 = build_plan(raw, extra_headers=[("X-Redjohn-Probe", "1"),
                                               ("Host", "127.0.0.1:8443")])
        assert plan3["host"] == "127.0.0.1", plan3
        assert ("X-Redjohn-Probe", "1") in plan3["headers"], plan3
        ok("extra headers appended; Host override replaces (single Host)")

        try:
            build_plan(b"GET / HTTP/1.1\r\nX-Other: 1\r\n\r\n")
            raised = False
        except ValueError:
            raised = True
        assert raised
        ok("missing Host header rejected")

        # --- scope-refusal BEFORE sending (sender monkeypatched out) ---
        with tempfile.TemporaryDirectory() as tmp:
            scope_path = os.path.join(tmp, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump(loopback_scope, fh)

            req_path = os.path.join(tmp, "req.txt")
            raw_ex = raw.replace(b"target.example.com", b"example.com")
            with open(req_path, "wb") as fh:
                fh.write(raw_ex)

            code = None
            try:
                main(["--scope-file", scope_path, "--request-file", req_path])
            except SystemExit as exc:
                code = exc.code
            assert code == 2 and not sent, (code, sent)
            ok("out-of-scope Host -> exit 2 and NOTHING sent")

            code = main(["--scope-file", scope_path, "--request-file", req_path,
                         "--extra-header", "Host: 127.0.0.1:8443"])
            assert code == 0 and len(sent) == 1, (code, sent)
            assert sent[0]["host"] == "127.0.0.1", sent
            ok("in-scope (overridden) Host -> request dispatched once")
    finally:
        socket.getaddrinfo = real_getaddrinfo
        globals()["send_request"] = real_send

    print("[self-test] req_replay: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
