#!/usr/bin/env python3
# token_swap_replay.py - scope-guarded multi-context auth replay (IDOR/BOLA).
#
# Parses a raw HTTP request file (baseline), then replays it once per auth
# context from --contexts (JSON: label -> {"headers": {...}, "cookies": {...}}),
# serially, printing per-context status/size/body-sha256 diffed against the
# FIRST context and flagging differing outcomes as candidate authorization
# gaps. Values may use "env:VARNAME" indirection so secrets stay in the
# environment, never in files.
#
# Context semantics: headers replace same-named headers; if "cookies" key is
# present the Cookie header is built exactly from it (empty {} removes the
# Cookie header -> anonymous arm); if absent the original Cookie passes through.
#
# Scope: --scope-file PATH or REDJOHN_SCOPE_FILE. The FINAL Host is validated
# against scope BEFORE any socket is opened. Absent scope file -> exit 1.
# Out of scope -> exit 2 and nothing is sent.
#
# Exit codes: 0 success, 2 scope refusal, 1 other errors.
#
# Evidence expectation: keep one request+response pair per context, named
# evidence/p4-<surface>-<seq>.<context>.{req,resp}.txt (--save writes them).

import argparse
import copy
import hashlib
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
        sys.stderr.write("[scope-guard] scope file unreadable (%s): %s\n"
                         % (scope_file, exc))
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

def build_plan(data, scheme="https"):
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

    host_header = None
    for name, value in headers:
        if name.lower() == "host":
            host_header = value
            break
    if not host_header:
        raise ValueError("request has no Host header; cannot build target URL")

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
# Context application (pure; unit-tested offline)
# ---------------------------------------------------------------------------

def resolve_env(value):
    """Resolve 'env:VARNAME' indirection. Raises ValueError if unset."""
    if isinstance(value, str) and value.startswith("env:"):
        var = value[4:]
        if var not in os.environ:
            raise ValueError("environment variable not set: %s" % var)
        return os.environ[var]
    return value


def apply_context(plan, context):
    """Return a context-specific copy of the plan (never mutates plan)."""
    ctx = context or {}
    newplan = copy.deepcopy(plan)
    headers = newplan["headers"]

    for name, value in ctx.get("headers", {}).items():
        value = resolve_env(value)
        replaced = False
        for idx, (existing, _v) in enumerate(headers):
            if existing.lower() == name.lower():
                headers[idx] = (existing, value)
                replaced = True
                break
        if not replaced:
            headers.append((name, value))

    if "cookies" in ctx:
        cookies = {str(k): resolve_env(v) for k, v in ctx["cookies"].items()}
        cookie_header = "; ".join("%s=%s" % (k, v) for k, v in cookies.items())
        headers[:] = [(n, v) for n, v in headers if n.lower() != "cookie"]
        if cookie_header:
            headers.append(("Cookie", cookie_header))

    return newplan


def load_contexts(path):
    """Load contexts JSON preserving insertion order. Raises ValueError."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not data:
        raise ValueError("contexts file must be a non-empty JSON object")
    for label, ctx in data.items():
        if not isinstance(ctx, dict):
            raise ValueError("context %r must be an object" % label)
        bad = set(ctx) - {"headers", "cookies"}
        if bad:
            raise ValueError("context %r has unknown keys: %s"
                             % (label, sorted(bad)))
        if "headers" in ctx and not isinstance(ctx["headers"], dict):
            raise ValueError("context %r: headers must be an object" % label)
        if "cookies" in ctx and not isinstance(ctx["cookies"], dict):
            raise ValueError("context %r: cookies must be an object" % label)
    return data


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
                                    for n, _v in plan["headers"]):
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


def save_evidence_pair(prefix, label, plan, result):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    comment = ("# origin=%s time=%s auth-context=%s tool=token_swap_replay.py\n"
               % (plan["url"], stamp, label))
    head = "%s %s HTTP/1.1" % (plan["method"], plan["target"])
    header_lines = ["%s: %s" % (n, v) for n, v in plan["headers"]]
    if plan["body"] and not any(n.lower() == "content-length"
                                for n, _v in plan["headers"]):
        header_lines.append("Content-Length: %d" % len(plan["body"]))
    with open("%s.%s.req.txt" % (prefix, label), "wb") as fh:
        fh.write(comment.encode("utf-8"))
        fh.write(("\n".join([head] + header_lines) + "\n\n").encode("latin-1"))
        fh.write(plan["body"])
    status_line = "HTTP/1.1 %d %s" % (result["status"], result["reason"])
    resp_headers = ["%s: %s" % (n, v) for n, v in result["headers"]]
    with open("%s.%s.resp.txt" % (prefix, label), "wb") as fh:
        fh.write(comment.encode("utf-8"))
        fh.write(("\n".join([status_line] + resp_headers) + "\n\n")
                 .encode("latin-1"))
        fh.write(result["body"])


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def summarize(results):
    """Attach baseline-diff fields to every non-first result entry."""
    base = results[0]
    summary = [dict(base, delta=None)]
    for res in results[1:]:
        if res["status"] != base["status"]:
            delta = "status(%s vs %s)" % (res["status"], base["status"])
        elif res["body_sha256"] != base["body_sha256"]:
            delta = "body-hash differs (same status %s)" % res["status"]
        else:
            delta = "identical"
        summary.append(dict(res, delta=delta))
    return summary


def report(summary, url):
    print("[swap] target: %s" % url)
    print("[swap] baseline context: %s" % summary[0]["label"])
    print("[swap] %-16s %-6s %-8s %-16s %s"
          % ("context", "status", "bytes", "sha256[:12]", "delta-vs-baseline"))
    for res in summary:
        print("[swap] %-16s %-6d %-8d %-16s %s"
              % (res["label"], res["status"], res["size"],
                 res["body_sha256"][:12], res["delta"] or "baseline"))
    flagged = [r for r in summary[1:] if r["delta"] != "identical"]
    print("[swap] ---- candidates ----")
    if flagged:
        for res in flagged:
            print("[swap] CANDIDATE authorization gap: context %r -> %s"
                  % (res["label"], res["delta"]))
        print("[swap] next: A/A calibration (20 harness), fresh-token re-run "
              "for BOTH contexts, then evidence pairs -> D1 only until then.")
    else:
        print("[swap] none: all contexts produced identical outcomes.")
    return flagged


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Scope-guarded IDOR/BOLA replay: send one raw HTTP "
        "request once per auth context (JSON label -> headers/cookies), "
        "diff each outcome against the first context, flag candidate "
        "authorization gaps. Secrets via env:VARNAME indirection.",
    )
    ap.add_argument("--scope-file", default=os.environ.get("REDJOHN_SCOPE_FILE"),
                    help="Engagement scope JSON (default: REDJOHN_SCOPE_FILE)")
    ap.add_argument("--request-file",
                    help="Raw HTTP request file (must contain a Host header)")
    ap.add_argument("--contexts",
                    help="JSON file: label -> {\"headers\": {...}, \"cookies\": {...}}")
    ap.add_argument("--scheme", choices=("http", "https"), default="https",
                    help="Scheme for the target URL (default: https)")
    ap.add_argument("--insecure-ok", action="store_true",
                    help="Skip TLS certificate verification")
    ap.add_argument("--save", metavar="PREFIX",
                    help="Save per-context pairs PREFIX.<label>.req/.resp.txt")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="Socket timeout in seconds")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests (no network) and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not (args.request_file and args.contexts and args.scope_file):
        sys.stderr.write("error: --request-file, --contexts and --scope-file "
                         "are required (or set REDJOHN_SCOPE_FILE)\n")
        return 1

    try:
        with open(args.request_file, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        sys.stderr.write("error: cannot read request file: %s\n" % exc)
        return 1

    try:
        plan = build_plan(data, scheme=args.scheme)
        contexts = load_contexts(args.contexts)
    except ValueError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1
    except OSError as exc:
        sys.stderr.write("error: cannot read contexts file: %s\n" % exc)
        return 1

    # Scope check on the FINAL target BEFORE any socket is opened.
    require_in_scope(plan["url"], args.scope_file)

    # Fail fast if any env: indirection is unset BEFORE sending anything.
    try:
        per_context = [(label, apply_context(plan, ctx))
                       for label, ctx in contexts.items()]
    except ValueError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1

    results = []
    for label, cplan in per_context:
        sys.stderr.write("[swap] replaying as %r -> %s %s\n"
                         % (label, cplan["method"], cplan["target"]))
        try:
            res = send_request(cplan, timeout=args.timeout,
                               insecure_ok=args.insecure_ok)
        except Exception as exc:
            sys.stderr.write("error: replay as %r failed: %s\n" % (label, exc))
            return 1
        results.append({
            "label": label,
            "status": res["status"],
            "size": len(res["body"]),
            "body_sha256": hashlib.sha256(res["body"]).hexdigest(),
            "result": res,
            "plan": cplan,
        })
        if args.save:
            save_evidence_pair(args.save, label, cplan, res)
            print("[swap] saved %s.%s.{req,resp}.txt" % (args.save, label))

    flagged = report(summarize(results), per_context[0][1]["url"])
    print("evidence: keep per-context pairs as "
          "evidence/p4-<surface>-<seq>.<context>.{req,resp}.txt; re-run with "
          "freshly issued tokens for every context before promoting a "
          "candidate to D2 (00-master false-positive checklist #5).")
    if flagged:
        print("[swap] note: candidates are D1 observations; confirm with "
              "fresh tokens and A/A calibration before claiming.")
    return 0


# ---------------------------------------------------------------------------
# Self-test: offline, no network. DNS monkeypatched; sending monkeypatched.
# ---------------------------------------------------------------------------

def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    import io
    import tempfile
    from contextlib import redirect_stdout

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *fn_args, **fn_kwargs):
        if host.endswith(".invalid"):
            raise socket.gaierror(-2, "fake NXDOMAIN for .invalid")
        table = {"example.com": "93.184.216.34", "localhost": "127.0.0.1"}
        if host in table:
            addr = table[host]
        else:
            try:
                ipaddress.ip_address(host)
                addr = host
            except ValueError:
                raise socket.gaierror(-2, "fake NXDOMAIN")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))]

    loopback_scope = {
        "engagement": "selftest",
        "allowed": [{"host": "localhost"}, {"cidr": "127.0.0.0/8"},
                    {"host": "127.0.0.1"}],
    }
    sent = []
    real_send = send_request

    def fake_send(plan, timeout=DEFAULT_TIMEOUT, insecure_ok=False):
        sent.append(plan)
        # user-b arm gets a different body (same status) to exercise the
        # body-hash diff path.
        marker = b"leak" if any(n.lower() == "authorization"
                                and v == "Bearer ctx-b" for n, v in
                                plan["headers"]) else b"ok"
        return {"status": 200, "reason": "OK",
                "headers": [("Content-Type", "application/json")],
                "body": b'{"data": "' + marker + b'"}', "time_ms": 1.0}

    socket.getaddrinfo = fake_getaddrinfo
    globals()["send_request"] = fake_send
    try:
        # --- canonical guard assertions (offline, fake DNS) ---
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

        # --- parsing (pure) ---
        raw = (b"GET /api/v1/invoices/1042 HTTP/1.1\r\n"
               b"Host: target.example.com\r\n"
               b"Authorization: Bearer ctx-a\r\n"
               b"Cookie: sid=orig-sid; other=1\r\n"
               b"\r\n")
        plan = build_plan(raw)
        assert plan["method"] == "GET" and plan["host"] == "target.example.com"
        assert plan["url"] == "https://target.example.com/api/v1/invoices/1042"
        ok("parses request line, Host, headers")

        # --- context application (pure) ---
        p2 = apply_context(plan, {"headers": {"Authorization": "Bearer ctx-b"},
                                  "cookies": {}})
        auths = [v for n, v in p2["headers"] if n.lower() == "authorization"]
        cookies = [v for n, v in p2["headers"] if n.lower() == "cookie"]
        assert auths == ["Bearer ctx-b"] and cookies == [], (auths, cookies)
        assert ("Cookie", "sid=orig-sid; other=1") in plan["headers"]
        ok("header replaced; empty cookies={} removes Cookie header; "
           "original plan untouched")

        p3 = apply_context(plan, {"cookies": {"sid": "ctx-b-sid"}})
        cookies = [v for n, v in p3["headers"] if n.lower() == "cookie"]
        assert cookies == ["sid=ctx-b-sid"], cookies
        auths = [v for n, v in p3["headers"] if n.lower() == "authorization"]
        assert auths == ["Bearer ctx-a"], auths
        ok("cookies rebuilt from dict; unrelated headers preserved")

        p4 = apply_context(plan, {"headers": {"X-New": "1"}})
        assert ("X-New", "1") in p4["headers"]
        assert ("Cookie", "sid=orig-sid; other=1") in p4["headers"]
        ok("cookies key absent -> original Cookie passes through")

        # --- env: indirection ---
        os.environ["RJ_SWAP_TEST_TOKEN"] = "Bearer env-token"
        try:
            p5 = apply_context(plan, {"headers":
                                      {"Authorization": "env:RJ_SWAP_TEST_TOKEN"}})
            assert ("Authorization", "Bearer env-token") in p5["headers"]
            ok("env: indirection resolves header values from environment")
            try:
                apply_context(plan, {"headers": {"Authorization":
                                                 "env:RJ_SWAP_TEST_MISSING"}})
                raised = False
            except ValueError:
                raised = True
            assert raised
            ok("env: indirection to unset variable raises cleanly")
        finally:
            del os.environ["RJ_SWAP_TEST_TOKEN"]

        # --- end-to-end main(): out-of-scope exits 2, nothing sent ---
        with tempfile.TemporaryDirectory() as tmp:
            scope_path = os.path.join(tmp, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump(loopback_scope, fh)

            req_path = os.path.join(tmp, "req.txt")
            with open(req_path, "wb") as fh:
                fh.write(raw)  # Host: target.example.com (not in scope)

            ctx_path = os.path.join(tmp, "contexts.json")
            with open(ctx_path, "w", encoding="utf-8") as fh:
                json.dump({"user-a": {"headers": {"Authorization":
                                                  "Bearer ctx-a"}},
                           "user-b": {"headers": {"Authorization":
                                                  "Bearer ctx-b"}}}, fh)

            code = None
            try:
                main(["--scope-file", scope_path, "--request-file", req_path,
                      "--contexts", ctx_path])
            except SystemExit as exc:
                code = exc.code
            assert code == 2 and not sent, (code, sent)
            ok("out-of-scope Host -> exit 2 and NOTHING sent")

            # in-scope run via localhost Host
            raw_local = raw.replace(b"target.example.com", b"127.0.0.1:8443")
            with open(req_path, "wb") as fh:
                fh.write(raw_local)

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--scope-file", scope_path,
                             "--request-file", req_path,
                             "--contexts", ctx_path, "--scheme", "http"])
            out = buf.getvalue()
            assert code == 0 and len(sent) == 2, (code, len(sent))
            assert "baseline context: user-a" in out
            assert "CANDIDATE authorization gap: context 'user-b'" in out
            assert "body-hash differs" in out
            ok("in-scope run: 2 serial replays, body-hash delta flagged as "
               "candidate authorization gap")

            # identical outcomes -> no candidates
            def fake_send_same(plan, timeout=DEFAULT_TIMEOUT, insecure_ok=False):
                return {"status": 200, "reason": "OK",
                        "headers": [], "body": b"same", "time_ms": 1.0}
            globals()["send_request"] = fake_send_same
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["--scope-file", scope_path,
                             "--request-file", req_path,
                             "--contexts", ctx_path, "--scheme", "http"])
            out = buf.getvalue()
            assert code == 0 and "none: all contexts produced identical" in out
            ok("identical outcomes -> no candidates line")

            # bad contexts file -> exit 1
            bad_path = os.path.join(tmp, "bad.json")
            with open(bad_path, "w", encoding="utf-8") as fh:
                fh.write('{"ctx": {"unknownkey": 1}}')
            code = main(["--scope-file", scope_path, "--request-file", req_path,
                         "--contexts", bad_path, "--scheme", "http"])
            assert code == 1
            ok("contexts file with unknown keys -> exit 1")
    finally:
        socket.getaddrinfo = real_getaddrinfo
        globals()["send_request"] = real_send

    print("[self-test] token_swap_replay: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
