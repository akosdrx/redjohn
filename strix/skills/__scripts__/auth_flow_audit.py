#!/usr/bin/env python3
"""auth_flow_audit.py - Server-side MFA, TOTP & CAPTCHA state-machine auditor
(32-mfa-captcha-audit).

Non-destructively audits application-side authentication state transitions:
  - Pre-MFA provisional session step-up skips.
  - TOTP single-use enforcement & replay within validity windows.
  - Server-side CAPTCHA parameter omission, empty/null, dummy acceptance.
  - Web vs API anti-automation endpoint parity.

Strictly non-destructive. Enforces scope guard on all network probes.

Usage:
  python3 auth_flow_audit.py --scope-file scope.json --target https://target.example.com/api/login --mode captcha-omission
  python3 auth_flow_audit.py --scope-file scope.json --target https://target.example.com --protected-url https://target.example.com/api/me --session "env:SESSION_COOKIE" --mode mfa-skip
  python3 auth_flow_audit.py --self-test

Exit codes: 0 = success; 2 = scope refusal; 1 = other error.
"""

import argparse
import copy
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "redjohn-pentestskills/auth_flow_audit/1.0"

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


def send_request(url, method="GET", headers=None, data=None, timeout=10):
    req_hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        req_hdrs.update(headers)
    body_bytes = None
    if data is not None:
        if isinstance(data, dict):
            body_bytes = json.dumps(data).encode("utf-8")
            req_hdrs.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            body_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            body_bytes = data
    req = urllib.request.Request(url, method=method, headers=req_hdrs, data=body_bytes)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(32768)
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hdrs, raw
    except urllib.error.HTTPError as err:
        raw = err.read(32768) if err.fp else b""
        hdrs = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
        return err.code, hdrs, raw


# ---------------------------------------------------------------- mfa step-up analysis

PROFILE_KEYS = {
    "id", "user", "email", "username", "profile", "account",
    "user_id", "sub", "role", "name",
}


def _contains_profile_data(obj):
    """Recursively search dictionaries and lists for user profile identifiers."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in PROFILE_KEYS:
                return True
            if _contains_profile_data(v):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _contains_profile_data(item):
                return True
    return False


def analyze_mfa_stepup(unauth_status, unauth_body, prov_status, prov_body):
    """Analyze if provisional pre-MFA session grants unauthorized access to protected resource.

    Handles 401/403 blocks as well as 301/302/303/307 unauthenticated redirects,
    nested JSON envelopes, and JSON arrays.
    """
    unauth_blocked = unauth_status in (401, 403, 301, 302, 303, 307, 308)
    prov_accepted = prov_status == 200

    has_profile_data = False
    try:
        data = json.loads(prov_body.decode("utf-8", errors="replace"))
        has_profile_data = _contains_profile_data(data)
    except Exception:
        pass

    if not has_profile_data:
        if len(prov_body) > 100 and unauth_status != prov_status:
            prov_text = prov_body.decode("utf-8", errors="replace").lower()
            if any(k in prov_text for k in ('"email"', '"user"', '"profile"', '"username"', "dashboard", "welcome")):
                has_profile_data = True

    is_vulnerable = unauth_blocked and prov_accepted and has_profile_data
    return {
        "unauthenticated_status": unauth_status,
        "provisional_status": prov_status,
        "access_granted": prov_accepted,
        "protected_data_leaked": has_profile_data,
        "verdict": "VULNERABLE: MFA-STEPUP-SKIP" if is_vulnerable else "SECURE: STEPUP-ENFORCED",
    }


# ---------------------------------------------------------------- captcha analysis


def analyze_captcha_omission(ctrl_status, test_results):
    """Analyze server-side CAPTCHA omission & dummy token acceptance against negative control."""
    ctrl_rejected = ctrl_status in (400, 401, 403, 422)

    # Sanitize tests to never include raw bytes
    sanitized_tests = []
    for item in test_results:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            t_name = item[0]
            t_status = item[1]
            snippet = ""
            if len(item) >= 3:
                raw_val = item[2]
                if isinstance(raw_val, bytes):
                    snippet = raw_val.decode("utf-8", errors="replace")[:100]
                elif isinstance(raw_val, str):
                    snippet = raw_val[:100]
            sanitized_tests.append({
                "test": t_name,
                "status": t_status,
                "body_snippet": snippet,
            })
        elif isinstance(item, dict):
            clean_item = {}
            for k, v in item.items():
                if isinstance(v, bytes):
                    clean_item[k] = v.decode("utf-8", errors="replace")[:100]
                else:
                    clean_item[k] = v
            sanitized_tests.append(clean_item)

    if not ctrl_rejected:
        return {
            "negative_control_status": ctrl_status,
            "negative_control_rejected": False,
            "verdict": "INCONCLUSIVE: CAPTCHA NOT ENFORCED (Negative control was not rejected)",
            "tests": sanitized_tests,
        }

    bypasses = []
    findings = []
    for test_item in sanitized_tests:
        test_name = test_item.get("test", "unknown")
        status = test_item.get("status", 0)
        # Handle 200 and HTTP redirects (301, 302, 303 PRG, 307, 308)
        success = status in (200, 301, 302, 303, 307, 308)
        if success:
            bypasses.append(test_name)
        findings.append({
            "test": test_name,
            "status": status,
            "bypassed": success,
        })

    verdict = "SECURE: ENFORCED"
    if "omitted" in bypasses:
        verdict = "VULNERABLE: CAPTCHA-FIELD-OMISSION"
    elif "empty" in bypasses or "null" in bypasses:
        verdict = "VULNERABLE: CAPTCHA-EMPTY-NULL-ACCEPTED"
    elif "dummy" in bypasses:
        verdict = "VULNERABLE: CAPTCHA-DUMMY-ACCEPTED"

    return {
        "negative_control_status": ctrl_status,
        "negative_control_rejected": True,
        "bypasses_detected": bypasses,
        "verdict": verdict,
        "tests": findings,
    }


# ---------------------------------------------------------------- otp replay analysis


def analyze_otp_replay(first_status, second_status):
    """Analyze if single OTP code is accepted multiple times within validity window."""
    first_ok = first_status in (200, 301, 302, 303, 307, 308)
    second_ok = second_status in (200, 301, 302, 303, 307, 308)
    replayed = first_ok and second_ok
    return {
        "first_attempt_status": first_status,
        "replay_attempt_status": second_status,
        "token_replayed": replayed,
        "verdict": "VULNERABLE: TOTP-REPLAY" if replayed else "SECURE: CONSUMED-ON-USE",
    }


# ---------------------------------------------------------------- token replay & parity


def analyze_token_replay(first_status, second_status):
    """Analyze if solved CAPTCHA or single-use auth token is accepted twice."""
    first_ok = first_status in (200, 301, 302, 303, 307, 308)
    second_ok = second_status in (200, 301, 302, 303, 307, 308)
    replayed = first_ok and second_ok
    return {
        "first_attempt_status": first_status,
        "replay_attempt_status": second_status,
        "token_replayed": replayed,
        "verdict": "VULNERABLE: TOKEN-REPLAY-ACCEPTED" if replayed else "SECURE: TOKEN-ONE-TIME-USE",
    }


def analyze_endpoint_parity(web_status, api_status):
    """Compare auth / CAPTCHA enforcement parity between web and API endpoints."""
    web_enforced = web_status in (400, 401, 403, 422)
    api_enforced = api_status in (400, 401, 403, 422)

    web_success = web_status in (200, 301, 302, 303, 307, 308)
    api_success = api_status in (200, 301, 302, 303, 307, 308)

    parity_gap = False
    if web_enforced and not api_enforced and api_success:
        parity_gap = True
        verdict = "VULNERABLE: API-MFA-PARITY-GAP (Web enforces auth/CAPTCHA, API does not)"
    elif api_enforced and not web_enforced and web_success:
        parity_gap = True
        verdict = "VULNERABLE: WEB-MFA-PARITY-GAP (API enforces auth/CAPTCHA, Web does not)"
    elif not web_enforced and not api_enforced and (web_success and api_success):
        verdict = "INCONCLUSIVE: NEITHER-ENFORCED"
    else:
        verdict = "SECURE: ENDPOINT-PARITY-ENFORCED"

    return {
        "web_status": web_status,
        "api_status": api_status,
        "parity_gap": parity_gap,
        "verdict": verdict,
    }


# ---------------------------------------------------------------- self-test


def _fake_getaddrinfo(host, port, *args, **kwargs):
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
        ok, why = host_allowed("ftp://example.com", local_scope)
        assert ok is False and why == "scheme-not-http(s)"
        ok, why = host_allowed("https://unresolvable.invalid/", local_scope)
        assert ok is False and why == "dns-unresolvable"
    finally:
        socket.getaddrinfo = original

    # Test MFA step-up skip analysis
    unauth_body = b'{"error": "Unauthorized"}'
    prov_body_leak = b'{"id": 42, "email": "admin@example.com", "role": "admin"}'
    stepup_vuln = analyze_mfa_stepup(401, unauth_body, 200, prov_body_leak)
    assert stepup_vuln["verdict"] == "VULNERABLE: MFA-STEPUP-SKIP"
    assert stepup_vuln["protected_data_leaked"] is True

    # 302 unauthenticated redirect handling
    stepup_302 = analyze_mfa_stepup(302, b'Found', 200, b'{"user": "alice"}')
    assert stepup_302["verdict"] == "VULNERABLE: MFA-STEPUP-SKIP"

    # Nested JSON envelope handling
    stepup_nested = analyze_mfa_stepup(401, unauth_body, 200, b'{"status": "ok", "data": {"profile": {"email": "a@b.com"}}}')
    assert stepup_nested["verdict"] == "VULNERABLE: MFA-STEPUP-SKIP"

    # JSON array handling
    stepup_array = analyze_mfa_stepup(401, unauth_body, 200, b'[{"id": 1, "username": "admin"}]')
    assert stepup_array["verdict"] == "VULNERABLE: MFA-STEPUP-SKIP"

    stepup_secure = analyze_mfa_stepup(401, unauth_body, 403, b'{"error": "MFA required"}')
    assert stepup_secure["verdict"] == "SECURE: STEPUP-ENFORCED"

    # Test CAPTCHA omission analysis (with valid negative control)
    test_cases_vuln = [
        ("omitted", 200, b'{"success": true}'),
        ("empty", 200, b'{"success": true}'),
        ("dummy", 200, b'{"success": true}'),
    ]
    captcha_vuln = analyze_captcha_omission(400, test_cases_vuln)
    assert captcha_vuln["verdict"] == "VULNERABLE: CAPTCHA-FIELD-OMISSION"
    assert "omitted" in captcha_vuln["bypasses_detected"]

    # Test CAPTCHA omission with HTTP 303 PRG redirect
    captcha_prg = analyze_captcha_omission(400, [("omitted", 303, b"")])
    assert captcha_prg["verdict"] == "VULNERABLE: CAPTCHA-FIELD-OMISSION"

    # Test CAPTCHA negative control failure without JSON crash
    captcha_inconclusive = analyze_captcha_omission(200, [("omitted", 200, b"raw_bytes_must_not_crash")])
    assert "INCONCLUSIVE" in captcha_inconclusive["verdict"]
    dumped = json.dumps(captcha_inconclusive)
    assert "raw_bytes" in dumped

    # Test OTP replay
    otp_vuln = analyze_otp_replay(200, 200)
    assert otp_vuln["verdict"] == "VULNERABLE: TOTP-REPLAY"
    otp_secure = analyze_otp_replay(200, 401)
    assert otp_secure["verdict"] == "SECURE: CONSUMED-ON-USE"

    # Test token replay
    tok_vuln = analyze_token_replay(200, 200)
    assert tok_vuln["verdict"] == "VULNERABLE: TOKEN-REPLAY-ACCEPTED"
    tok_sec = analyze_token_replay(200, 400)
    assert tok_sec["verdict"] == "SECURE: TOKEN-ONE-TIME-USE"

    # Test endpoint parity
    par_vuln = analyze_endpoint_parity(400, 200)
    assert "API-MFA-PARITY-GAP" in par_vuln["verdict"]
    par_sec = analyze_endpoint_parity(400, 400)
    assert par_sec["verdict"] == "SECURE: ENDPOINT-PARITY-ENFORCED"

    print("[self-test] auth_flow_audit: scope-guard(6) + mfa-stepup + captcha-omission + negative-control + otp-replay + token-replay + endpoint-parity passed")


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def resolve_session_value(val):
    if not val:
        return ""
    if val.startswith("env:"):
        env_var = val.split(":", 1)[1]
        return os.environ.get(env_var, "")
    return val


def main(argv=None):
    parser = _Parser(
        description="Server-side MFA, TOTP & CAPTCHA state-machine auditor."
    )
    parser.add_argument("--scope-file", help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target", help="target login or verification endpoint URL")
    parser.add_argument(
        "--mode",
        choices=["mfa-skip", "otp-replay", "captcha-omission", "token-replay", "endpoint-parity"],
        default="captcha-omission",
        help="audit mode (default: captcha-omission)",
    )
    parser.add_argument("--protected-url", help="protected endpoint URL for mfa-skip mode")
    parser.add_argument("--session", help="session cookie/token or env:VAR_NAME")
    parser.add_argument("--captcha-field", default="g-recaptcha-response", help="CAPTCHA field name")
    parser.add_argument("--payload", help="base JSON payload string or file path")
    parser.add_argument("--otp-code", default="123456", help="OTP verification code for otp-replay mode (default: 123456)")
    parser.add_argument("--token", default="SOLVED_CAPTCHA_CANARY_TOKEN", help="solved CAPTCHA or auth token for token-replay mode")
    parser.add_argument("--api-endpoint", help="API equivalent endpoint URL for endpoint-parity mode")
    parser.add_argument("--timeout", type=int, default=10, help="request timeout in seconds (default 10)")
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument("--self-test", action="store_true", help="run offline self-test and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    scope_file = args.scope_file or os.environ.get("REDJOHN_SCOPE_FILE")
    if not scope_file or not args.target:
        parser.error("--scope-file and --target are required")

    require_in_scope(args.target, scope_file)
    if args.protected_url:
        require_in_scope(args.protected_url, scope_file)

    session_val = resolve_session_value(args.session)
    base_payload = {}
    if args.payload:
        if os.path.exists(args.payload):
            with open(args.payload, "r", encoding="utf-8") as fh:
                base_payload = json.load(fh)
        else:
            base_payload = json.loads(args.payload)

    result = {"target": args.target, "mode": args.mode}

    if args.mode == "mfa-skip":
        if not args.protected_url:
            parser.error("--protected-url is required for mfa-skip mode")
        unauth_st, _hdrs, unauth_bd = send_request(args.protected_url, timeout=args.timeout)
        prov_hdrs = {}
        if session_val:
            if " " in session_val or session_val.startswith("Bearer"):
                prov_hdrs["Authorization"] = session_val
            else:
                prov_hdrs["Cookie"] = session_val
        prov_st, _hdrs, prov_bd = send_request(args.protected_url, headers=prov_hdrs, timeout=args.timeout)
        result["stepup_analysis"] = analyze_mfa_stepup(unauth_st, unauth_bd, prov_st, prov_bd)

    elif args.mode == "otp-replay":
        req_hdrs = {}
        if session_val:
            if " " in session_val or session_val.startswith("Bearer"):
                req_hdrs["Authorization"] = session_val
            else:
                req_hdrs["Cookie"] = session_val
        otp_payload = copy.deepcopy(base_payload)
        otp_key = "otp"
        for k in ("otp", "code", "totp", "token"):
            if k in otp_payload:
                otp_key = k
                break
        otp_payload[otp_key] = args.otp_code

        st1, _h1, _bd1 = send_request(args.target, method="POST", headers=req_hdrs, data=otp_payload, timeout=args.timeout)
        st2, _h2, _bd2 = send_request(args.target, method="POST", headers=req_hdrs, data=otp_payload, timeout=args.timeout)
        result["otp_replay"] = analyze_otp_replay(st1, st2)

    elif args.mode == "token-replay":
        req_hdrs = {}
        if session_val:
            if " " in session_val or session_val.startswith("Bearer"):
                req_hdrs["Authorization"] = session_val
            else:
                req_hdrs["Cookie"] = session_val
        tok_payload = copy.deepcopy(base_payload)
        tok_key = args.captcha_field or "token"
        tok_payload[tok_key] = args.token

        st1, _h1, _bd1 = send_request(args.target, method="POST", headers=req_hdrs, data=tok_payload, timeout=args.timeout)
        st2, _h2, _bd2 = send_request(args.target, method="POST", headers=req_hdrs, data=tok_payload, timeout=args.timeout)
        result["token_replay"] = analyze_token_replay(st1, st2)

    elif args.mode == "endpoint-parity":
        api_url = args.api_endpoint
        if not api_url:
            parsed = urllib.parse.urlparse(args.target)
            if parsed.path.startswith("/api"):
                api_url = args.target
            else:
                api_url = urllib.parse.urljoin(args.target, "/api" + (parsed.path or "/"))
        require_in_scope(api_url, scope_file)

        req_hdrs = {}
        if session_val:
            if " " in session_val or session_val.startswith("Bearer"):
                req_hdrs["Authorization"] = session_val
            else:
                req_hdrs["Cookie"] = session_val

        omit_payload = copy.deepcopy(base_payload)
        omit_payload.pop(args.captcha_field, None)

        web_st, _wh, _wb = send_request(args.target, method="POST", headers=req_hdrs, data=omit_payload, timeout=args.timeout)
        api_st, _ah, _ab = send_request(api_url, method="POST", headers=req_hdrs, data=omit_payload, timeout=args.timeout)

        result["endpoint_parity"] = analyze_endpoint_parity(web_st, api_st)
        result["api_endpoint"] = api_url

    elif args.mode == "captcha-omission":
        # Negative control
        ctrl_payload = copy.deepcopy(base_payload)
        ctrl_payload[args.captcha_field] = "INVALID_CANARY_CAPTCHA_TOKEN_9182"
        ctrl_st, _hdrs, _bd = send_request(args.target, method="POST", data=ctrl_payload, timeout=args.timeout)

        # Test variants
        tests = []
        # 1. Omitted
        omit_payload = copy.deepcopy(base_payload)
        omit_payload.pop(args.captcha_field, None)
        st, _h, bd = send_request(args.target, method="POST", data=omit_payload, timeout=args.timeout)
        tests.append(("omitted", st, bd))

        # 2. Empty
        empty_payload = copy.deepcopy(base_payload)
        empty_payload[args.captcha_field] = ""
        st, _h, bd = send_request(args.target, method="POST", data=empty_payload, timeout=args.timeout)
        tests.append(("empty", st, bd))

        # 3. Null
        null_payload = copy.deepcopy(base_payload)
        null_payload[args.captcha_field] = None
        st, _h, bd = send_request(args.target, method="POST", data=null_payload, timeout=args.timeout)
        tests.append(("null", st, bd))

        # 4. Dummy
        dummy_payload = copy.deepcopy(base_payload)
        dummy_payload[args.captcha_field] = "dummy_token_test_string"
        st, _h, bd = send_request(args.target, method="POST", data=dummy_payload, timeout=args.timeout)
        tests.append(("dummy", st, bd))

        result["captcha_analysis"] = analyze_captcha_omission(ctrl_st, tests)

    if args.json:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    else:
        print("=== Auth Flow & Anti-Automation Audit (%s) ===" % args.mode)
        print("Target: %s" % args.target)
        print(json.dumps(result, indent=2))
        print("[evidence] Preserve requests in evidence/p4-mfa-<host>.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())
