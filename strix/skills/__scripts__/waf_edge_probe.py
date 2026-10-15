#!/usr/bin/env python3
"""waf_edge_probe.py - WAF, CDN & reverse proxy edge posture auditor
(25-waf-edge-posture).

Audits edge posture non-destructively:
  - Normalization discrepancies (matrix params, dot-segments, encoded slashes).
  - Direct origin exposure & header/body comparison.
  - X-Forwarded-* header trust & reflection.
  - Pre/post-test baseline diffing to detect mid-engagement SOC virtual patching.

Strictly non-destructive. Enforces scope guard on all network probes.

Usage:
  python3 waf_edge_probe.py --scope-file scope.json --target https://target.example.com --mode normalization
  python3 waf_edge_probe.py --scope-file scope.json --target https://target.example.com --mode origin-diff --origin-ip 203.0.113.10
  python3 waf_edge_probe.py --scope-file scope.json --target https://target.example.com --mode baseline-pre --baseline-file base.json
  python3 waf_edge_probe.py --self-test

Exit codes: 0 = success; 2 = scope refusal; 1 = other error.
"""

import argparse
import difflib
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

USER_AGENT = "redjohn-pentestskills/waf_edge_probe/1.0"

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


# ---------------------------------------------------------------- transport


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def send_probe(url, headers=None, timeout=10):
    req_hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        req_hdrs.update(headers)
    req = urllib.request.Request(url, method="GET", headers=req_hdrs)
    t0 = time.time()
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            elapsed_ms = (time.time() - t0) * 1000.0
            raw = resp.read(32768)
            hdrs = {}
            cookie_list = []
            for k, v in resp.getheaders():
                kl = k.lower()
                if kl == "set-cookie":
                    cookie_list.append(v)
                else:
                    hdrs[kl] = v
            if cookie_list:
                hdrs["set-cookie"] = "\n".join(cookie_list)
            return resp.status, hdrs, raw, elapsed_ms
    except urllib.error.HTTPError as err:
        elapsed_ms = (time.time() - t0) * 1000.0
        raw = err.read(32768) if err.fp else b""
        hdrs = {}
        if err.headers:
            for k, v in err.headers.items():
                kl = k.lower()
                if kl == "set-cookie":
                    continue
                hdrs[kl] = v
            cookies = err.headers.get_all("Set-Cookie") if hasattr(err.headers, "get_all") else []
            if cookies:
                hdrs["set-cookie"] = "\n".join(cookies)
            elif "set-cookie" in err.headers:
                hdrs["set-cookie"] = err.headers.get("set-cookie")
        return err.code, hdrs, raw, elapsed_ms


# ---------------------------------------------------------------- normalization


NORMALIZATION_VARIANTS = [
    (";rj_matrix=1", "semicolon matrix parameter"),
    ("/%2e", "encoded dot-segment prefix"),
    ("/..;rj/", "semicolon path traversal"),
    (".", "trailing period (IIS strip)"),
    ("%20", "trailing space (IIS strip)"),
]


def build_normalization_url(target_url, suffix):
    """Safely append normalization suffix without urljoin stripping trailing dots or injecting unwanted slashes."""
    parsed = urllib.parse.urlsplit(target_url)
    path = parsed.path or "/"
    if suffix.startswith(";"):
        new_path = path.rstrip("/") + suffix if path != "/" else "/" + suffix
    elif suffix.startswith("/"):
        new_path = path.rstrip("/") + suffix
    else:
        new_path = path + suffix
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, new_path, parsed.query, parsed.fragment))


def analyze_normalization(base_status, base_body, variant_results):
    """Detect if variant path is resolved by backend despite edge discrepancies."""
    base_hash = hashlib.sha256(base_body).hexdigest()
    findings = []
    for suffix, desc, status, hdrs, body in variant_results:
        var_hash = hashlib.sha256(body).hexdigest()
        resolved = (status == base_status and var_hash == base_hash)
        discrepancy = (status != base_status) or ("cf-cache-status" in hdrs and hdrs.get("cf-cache-status") == "MISS")
        findings.append({
            "variant": suffix,
            "description": desc,
            "status": status,
            "backend_resolved": resolved,
            "edge_discrepancy": discrepancy,
        })
    return findings


# ---------------------------------------------------------------- origin diffing


EDGE_HEADER_PREFIXES = (
    "cf-", "x-amz-cf-", "x-akamai-", "x-fastly-", "x-cdn-", "x-azure-ref",
)


def analyze_origin_diff(edge_status, edge_hdrs, edge_body, orig_status, orig_hdrs, orig_body):
    """Compare edge response against direct-to-origin response."""
    edge_hash = hashlib.sha256(edge_body).hexdigest()
    orig_hash = hashlib.sha256(orig_body).hexdigest()

    edge_specific = [k for k in edge_hdrs if any(k.startswith(p) for p in EDGE_HEADER_PREFIXES)]
    orig_specific = [k for k in orig_hdrs if not any(k.startswith(p) for p in EDGE_HEADER_PREFIXES) and k not in edge_hdrs]

    body_match = (edge_hash == orig_hash)
    status_match = (edge_status == orig_status)

    is_exposed_origin = bool(status_match and body_match and len(edge_specific) > 0)
    return {
        "status_match": status_match,
        "body_match": body_match,
        "edge_specific_headers": edge_specific,
        "origin_specific_headers": orig_specific,
        "is_exposed_origin": is_exposed_origin,
    }


# ---------------------------------------------------------------- forwarded headers


def analyze_forwarded_headers(baseline_hdrs, canary_hdrs, canary_val="127.0.0.1", body=None, host_canary="canary.internal.example"):
    """Check if injected forwarded headers (IP or Host) are reflected or processed."""
    reflected = []
    canaries = [canary_val]
    if host_canary and host_canary not in canaries:
        canaries.append(host_canary)

    for k, v in canary_hdrs.items():
        base_v = baseline_hdrs.get(k, "")
        for c in canaries:
            if c in str(v) and c not in str(base_v):
                reflected.append(k)
                break

    body_reflected = False
    if body:
        decoded_body = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
        for c in canaries:
            if c in decoded_body:
                body_reflected = True
                break

    is_trusted = len(reflected) > 0 or body_reflected
    return {
        "reflected_headers": reflected,
        "body_reflected": body_reflected,
        "trusted_upstream": is_trusted,
    }


# ---------------------------------------------------------------- baseline IR diffing


WAF_COOKIE_NAMES = {"__cf_bm", "cf_clearance", "awselb", "reese84", "incap_ses", "datadome"}
WAF_BLOCK_HEADERS = {"cf-mitigated", "x-waf-block", "x-deny-reason", "x-threat-score"}


def diff_waf_baseline(pre_baseline, post_status, post_hdrs, post_ms):
    """Diff current response against pre-test baseline to detect SOC virtual patching."""
    pre_status = pre_baseline.get("status_code", 200)
    pre_ms = pre_baseline.get("latency_ms", 100.0)
    pre_hdrs = pre_baseline.get("headers", {})

    new_waf_cookies = []
    set_cookie = post_hdrs.get("set-cookie", "")
    for c in WAF_COOKIE_NAMES:
        if c in set_cookie and c not in pre_hdrs.get("set-cookie", ""):
            new_waf_cookies.append(c)

    new_block_headers = [k for k in post_hdrs if k in WAF_BLOCK_HEADERS and k not in pre_hdrs]

    # Timing shift: sub-ms drop indicates edge rejection
    latency_drop = (pre_ms > 50.0 and post_ms < 20.0 and post_status in (403, 429))

    is_virtual_patch = bool(new_waf_cookies or new_block_headers or latency_drop or (pre_status == 200 and post_status in (403, 429)))

    return {
        "pre_status": pre_status,
        "post_status": post_status,
        "pre_latency_ms": pre_ms,
        "post_latency_ms": post_ms,
        "latency_drop": latency_drop,
        "new_waf_cookies": new_waf_cookies,
        "new_block_headers": new_block_headers,
        "detected_soc_virtual_patch": is_virtual_patch,
    }


# ---------------------------------------------------------------- self-test


def _fake_getaddrinfo(host, port, *args, **kwargs):
    fake = {
        "example.com": ["93.184.216.34"],
        "target.example.com": ["203.0.113.10"],
        "origin.example.com": ["203.0.113.20"],
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
        ok, why = host_allowed("https://example.com", local_scope)
        assert ok is False, "example.com must be refused, got %s" % why
        ok, why = host_allowed("http://10.0.0.5/", local_scope)
        assert ok is False and why == "not-in-scope", why
        loop_scope = {"engagement": "selftest", "allowed": [{"host": "127.0.0.1"}]}
        ok, why = host_allowed("http://127.0.0.1:8080/", loop_scope)
        assert ok is True, "listed loopback must be allowed, got %s" % why
        ok, why = host_allowed(
            "https://target.example.com/",
            {"allowed": [{"cidr": "203.0.113.0/24"}]},
        )
        assert ok is True, "cidr entry must allow target"
        ok, why = host_allowed(
            "https://origin.example.com/",
            {"allowed": [{"cidr": "203.0.113.0/24"}]},
        )
        assert ok is True, "cidr entry must allow origin"
    finally:
        socket.getaddrinfo = original

    # Test normalization URL builder
    assert build_normalization_url("https://target.com/admin", ".") == "https://target.com/admin."
    assert build_normalization_url("https://target.com/admin", ";rj_matrix=1") == "https://target.com/admin;rj_matrix=1"
    assert build_normalization_url("https://target.com/admin/", ".") == "https://target.com/admin/."

    # Test normalization analysis logic
    base_body = b"<html>App Home</html>"
    variant_results = [
        (";rj_matrix=1", "semicolon matrix", 200, {"cf-cache-status": "MISS"}, base_body),
        ("/%2e", "encoded dot", 403, {}, b"Forbidden"),
    ]
    norm_findings = analyze_normalization(200, base_body, variant_results)
    assert len(norm_findings) == 2
    assert norm_findings[0]["backend_resolved"] is True
    assert norm_findings[0]["edge_discrepancy"] is True

    # Test origin diffing logic
    edge_hdrs = {"cf-ray": "12345", "server": "cloudflare", "content-type": "text/html"}
    orig_hdrs = {"server": "apache/2.4", "x-powered-by": "php", "content-type": "text/html"}
    orig_res = analyze_origin_diff(200, edge_hdrs, base_body, 200, orig_hdrs, base_body)
    assert orig_res["body_match"] is True
    assert "cf-ray" in orig_res["edge_specific_headers"]
    assert "x-powered-by" in orig_res["origin_specific_headers"]
    assert orig_res["is_exposed_origin"] is True

    # Test origin diffing false positive rejection on mismatching body
    mismatch_res = analyze_origin_diff(200, {"cf-ray": "1"}, b"app", 200, {}, b"unrelated nginx page")
    assert mismatch_res["is_exposed_origin"] is False

    # Test forwarded headers reflection (both IP canary and Host canary)
    fwd_res = analyze_forwarded_headers({}, {"x-client-ip": "127.0.0.1"}, canary_val="127.0.0.1")
    assert fwd_res["trusted_upstream"] is True

    host_fwd_res = analyze_forwarded_headers(
        {}, {"location": "https://canary.internal.example/login"}, canary_val="127.0.0.1"
    )
    assert host_fwd_res["trusted_upstream"] is True

    # Test WAF baseline IR diffing with multi-cookie preservation
    pre_base = {"status_code": 200, "latency_ms": 120.0, "headers": {}}
    ir_diff = diff_waf_baseline(
        pre_base,
        post_status=403,
        post_hdrs={"set-cookie": "session=xyz\n__cf_bm=xyz\ntracker=123", "cf-mitigated": "challenge"},
        post_ms=12.0,
    )
    assert ir_diff["detected_soc_virtual_patch"] is True
    assert "__cf_bm" in ir_diff["new_waf_cookies"]
    assert "cf-mitigated" in ir_diff["new_block_headers"]
    assert ir_diff["latency_drop"] is True

    print("[self-test] waf_edge_probe: scope-guard(5) + normalization + origin-diff + forwarded-headers + baseline-diff passed")


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main(argv=None):
    parser = _Parser(
        description="WAF, CDN & reverse proxy edge posture auditor."
    )
    parser.add_argument("--scope-file", help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target", help="target edge URL (e.g. https://target.example.com)")
    parser.add_argument(
        "--mode",
        choices=["normalization", "origin-diff", "forwarded-headers", "baseline-pre", "baseline-diff"],
        default="normalization",
        help="audit mode (default: normalization)",
    )
    parser.add_argument("--origin-ip", help="candidate origin IP for origin-diff mode")
    parser.add_argument("--baseline-file", help="path to baseline JSON file")
    parser.add_argument("--timeout", type=int, default=10, help="request timeout in seconds (default 10)")
    parser.add_argument("--delay", type=float, default=0.3, help="inter-request delay in seconds (default 0.3)")
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument("--self-test", action="store_true", help="run offline self-test and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    scope_file = args.scope_file or os.environ.get("REDJOHN_SCOPE_FILE")
    if not scope_file or not args.target:
        parser.error("--scope-file and --target are required")

    # Validate mode-specific required arguments BEFORE initiating live network probes
    if args.mode == "origin-diff" and not args.origin_ip:
        parser.error("--origin-ip is required for origin-diff mode")
    if args.mode == "baseline-diff":
        if not args.baseline_file or not os.path.exists(args.baseline_file):
            parser.error("--baseline-file is required for baseline-diff mode")

    require_in_scope(args.target, scope_file)
    if args.origin_ip:
        require_in_scope("https://%s/" % args.origin_ip, scope_file)

    parsed = urllib.parse.urlparse(args.target)
    base_status, base_hdrs, base_body, base_ms = send_probe(args.target, timeout=args.timeout)

    result = {"target": args.target, "mode": args.mode}

    if args.mode == "normalization":
        variant_results = []
        for suffix, desc in NORMALIZATION_VARIANTS:
            time.sleep(args.delay)
            v_url = build_normalization_url(args.target, suffix)
            st, hd, bd, _ms = send_probe(v_url, timeout=args.timeout)
            variant_results.append((suffix, desc, st, hd, bd))
        findings = analyze_normalization(base_status, base_body, variant_results)
        result["normalization_findings"] = findings

    elif args.mode == "origin-diff":
        orig_url = "%s://%s%s" % (parsed.scheme, args.origin_ip, parsed.path or "/")
        orig_st, orig_hd, orig_bd, _ms = send_probe(orig_url, headers={"Host": parsed.netloc}, timeout=args.timeout)
        diff_res = analyze_origin_diff(base_status, base_hdrs, base_body, orig_st, orig_hd, orig_bd)
        result["origin_diff"] = diff_res

    elif args.mode == "forwarded-headers":
        canary = "127.0.0.1"
        host_canary = "canary.internal.example"
        test_hdrs = {
            "X-Forwarded-For": canary,
            "X-Real-IP": canary,
            "X-Forwarded-Host": host_canary,
        }
        _st, fwd_hd, fwd_bd, _ms = send_probe(args.target, headers=test_hdrs, timeout=args.timeout)
        result["forwarded_headers"] = analyze_forwarded_headers(
            base_hdrs, fwd_hd, canary_val=canary, body=fwd_bd, host_canary=host_canary
        )

    elif args.mode == "baseline-pre":
        baseline_data = {
            "target": args.target,
            "timestamp": time.time(),
            "status_code": base_status,
            "latency_ms": base_ms,
            "content_length": len(base_body),
            "body_sha256": hashlib.sha256(base_body).hexdigest(),
            "headers": base_hdrs,
        }
        if args.baseline_file:
            with open(args.baseline_file, "w", encoding="utf-8") as fh:
                json.dump(baseline_data, fh, indent=2)
        result["baseline_captured"] = baseline_data

    elif args.mode == "baseline-diff":
        with open(args.baseline_file, "r", encoding="utf-8") as fh:
            pre_base = json.load(fh)
        result["baseline_diff"] = diff_waf_baseline(pre_base, base_status, base_hdrs, base_ms)

    if args.json:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    else:
        print("=== WAF / Edge Posture Audit (%s) ===" % args.mode)
        print("Target: %s (Status: %d, Latency: %.1fms)" % (args.target, base_status, base_ms))
        print(json.dumps(result, indent=2))
        print("[evidence] Preserve probe outputs in evidence/p2-edge-<host>.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())
