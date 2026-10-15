#!/usr/bin/env python3
"""attack_plan_gen.py - Strategic attack surface & engagement execution planner
(05-attack-surface-planner).

Ingests engagement scope, RoE constraints, soft-404 baselines, and recon
fingerprints to produce a prioritized phase execution blueprint (P0 -> P9),
evidence checklist, and signal-to-skill dispatch table.

Strictly non-destructive. Enforces scope guard on all network probes.

Usage:
  python3 attack_plan_gen.py --scope-file scope.json --target https://target.example.com --probe-baseline
  python3 attack_plan_gen.py --scope-file scope.json --fingerprints-file recon.json
  python3 attack_plan_gen.py --self-test

Exit codes: 0 = success; 2 = scope refusal; 1 = other error.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "redjohn-pentestskills/attack_plan_gen/1.0"

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


def fetch_path(base_url, path, timeout=8):
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(32768)
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, headers, raw
    except urllib.error.HTTPError as err:
        raw = err.read(32768) if err.fp else b""
        headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
        return err.code, headers, raw


# ---------------------------------------------------------------- baseline logic


def calibrate_soft404_responses(probes):
    """Calibrate soft-404 fingerprints from dict of {path: (status, headers, raw_bytes)}."""
    baselines = {}
    for path, (status, _hdrs, raw) in probes.items():
        h = hashlib.sha256(raw).hexdigest()
        depth = "root" if path.count("/") <= 1 else "depth_%d" % path.count("/")
        baselines[path] = {
            "status": status,
            "byte_length": len(raw),
            "sha256": h,
            "depth": depth,
            "is_soft_404": (status == 200),
        }
    return baselines


def is_soft404(status, body_bytes, baselines):
    """Check if given response matches any calibrated soft-404 baseline."""
    h = hashlib.sha256(body_bytes).hexdigest()
    for base in baselines.values():
        if base.get("is_soft_404") and base.get("sha256") == h:
            return True
    return False


# ---------------------------------------------------------------- dispatch & EV


SIGNAL_RULES = [
    {
        "signal": "okta",
        "category": "Identity",
        "tier": 1,
        "skills": ["30-auth-access-control", "32-mfa-captcha-audit"],
        "impact": 9.0,
        "confidence": 1.0,
        "maturity": 2.0,
        "cost": 3.0,
    },
    {
        "signal": "entra",
        "category": "Identity",
        "tier": 1,
        "skills": ["30-auth-access-control", "32-mfa-captcha-audit"],
        "impact": 9.0,
        "confidence": 1.0,
        "maturity": 2.0,
        "cost": 3.0,
    },
    {
        "signal": "fortinet",
        "category": "Perimeter",
        "tier": 2,
        "skills": ["70-exploit-intel"],
        "impact": 10.0,
        "confidence": 0.8,
        "maturity": 3.0,
        "cost": 1.5,
    },
    {
        "signal": "cloudflare",
        "category": "Edge",
        "tier": 3,
        "skills": ["25-waf-edge-posture", "50-config-baseline"],
        "impact": 6.0,
        "confidence": 0.9,
        "maturity": 1.5,
        "cost": 2.0,
    },
    {
        "signal": "wordpress",
        "category": "CMS",
        "tier": 4,
        "skills": ["15-cms-ecommerce-rce", "70-exploit-intel"],
        "impact": 8.5,
        "confidence": 0.8,
        "maturity": 2.5,
        "cost": 2.0,
    },
    {
        "signal": "graphql",
        "category": "API",
        "tier": 5,
        "skills": ["60-api-graphql-websockets", "40-injection-engine"],
        "impact": 7.0,
        "confidence": 0.7,
        "maturity": 1.5,
        "cost": 3.0,
    },
    {
        "signal": "oracle",
        "category": "Database/Stack",
        "tier": 2,
        "skills": ["80-oracle-stack", "70-exploit-intel"],
        "impact": 9.0,
        "confidence": 0.8,
        "maturity": 2.0,
        "cost": 2.5,
    },
    {
        "signal": "proxmox",
        "category": "Hypervisor",
        "tier": 2,
        "skills": ["82-proxmox-ve"],
        "impact": 9.5,
        "confidence": 0.8,
        "maturity": 2.0,
        "cost": 2.0,
    },
    {
        "signal": "nextjs",
        "category": "Framework",
        "tier": 4,
        "skills": ["55-client-side-attacks", "50-config-baseline"],
        "impact": 5.0,
        "confidence": 0.8,
        "maturity": 1.0,
        "cost": 2.0,
    },
]


def calculate_ev(impact, confidence, maturity, cost):
    return (impact * confidence * maturity) / max(cost, 0.5)


def plan_skills(fingerprints, max_budget=8):
    """Rank candidate skills by EV and clamp to max_budget."""
    fp_set = {fp.lower() for fp in fingerprints}
    skill_scores = {}
    triggered_rules = []

    for rule in SIGNAL_RULES:
        if rule["signal"] in fp_set:
            ev = calculate_ev(rule["impact"], rule["confidence"], rule["maturity"], rule["cost"])
            triggered_rules.append((rule, ev))
            for sk in rule["skills"]:
                if sk not in skill_scores or ev > skill_scores[sk]:
                    skill_scores[sk] = ev

    # Always ensure baseline core skills if empty
    if not skill_scores:
        default_skills = ["10-recon-endpoint-mapping", "50-config-baseline", "30-auth-access-control"]
        for ds in default_skills:
            skill_scores[ds] = 1.0

    # Sort skills by score descending
    sorted_skills = sorted(skill_scores.items(), key=lambda x: x[1], reverse=True)
    clamped = sorted_skills[:max_budget]
    return [s[0] for s in clamped], dict(sorted_skills), triggered_rules


def generate_plan(scope, fingerprints, baselines=None, profile="scan-standard"):
    active_skills, all_scores, triggered = plan_skills(fingerprints, max_budget=8)
    phases = {
        "P0": ["Scope & RoE validation", "Account setup (>= 2 roles)", "Canary token generation"],
        "P1": ["10-recon-endpoint-mapping", "05-attack-surface-planner (baseline)"],
        "P1.5": [s for s in active_skills if s in ("70-exploit-intel", "15-cms-ecommerce-rce", "80-oracle-stack", "82-proxmox-ve")],
        "P2": [s for s in active_skills if s in ("25-waf-edge-posture", "50-config-baseline", "35-cryptographic-failures")],
        "P3": [s for s in active_skills if s in ("20-traffic-manipulation", "25-waf-edge-posture")],
        "P4": [s for s in active_skills if s in ("30-auth-access-control", "32-mfa-captcha-audit")],
        "P5": [s for s in active_skills if s in ("40-injection-engine",)],
        "P6": [s for s in active_skills if s in ("45-rce-exploitation", "55-client-side-attacks", "58-logic-concurrency", "60-api-graphql-websockets")],
        "P7": [s for s in active_skills if s in ("65-supply-chain-integrity", "70-exploit-intel")],
        "P8": [s for s in active_skills if s in ("75-zeroday-research", "80-oracle-stack", "82-proxmox-ve", "85-logging-monitoring")],
        "P9": ["95-finding-verifier", "90-evidence-reporting"],
    }
    return {
        "profile": profile,
        "engagement": scope.get("engagement", "unnamed"),
        "load_budget": {"cap": 8, "allocated": len(active_skills)},
        "active_platform_skills": active_skills,
        "ev_scores": all_scores,
        "phases": phases,
        "soft404_calibrated": bool(baselines),
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
        assert ok is True, "cidr entry must allow documented host"
        ok, why = host_allowed("ftp://example.com", local_scope)
        assert ok is False and why == "scheme-not-http(s)"
        ok, why = host_allowed("http:///", local_scope)
        assert ok is False and why == "no-host"
        ok, why = host_allowed("https://unresolvable.invalid/", local_scope)
        assert ok is False and why == "dns-unresolvable"
    finally:
        socket.getaddrinfo = original

    # Test soft-404 baseline calibration
    mock_probes = {
        "/rj-nope-1": (200, {}, b"<html>Mock Soft 404 Page</html>"),
        "/rj-nope-2": (200, {}, b"<html>Mock Soft 404 Page</html>"),
        "/a/b/rj-nope-3": (404, {}, b"Not Found"),
    }
    cal = calibrate_soft404_responses(mock_probes)
    assert cal["/rj-nope-1"]["is_soft_404"] is True
    assert cal["/rj-nope-1"]["sha256"] == cal["/rj-nope-2"]["sha256"]
    assert is_soft404(200, b"<html>Mock Soft 404 Page</html>", cal) is True
    assert is_soft404(200, b"<html>Valid Admin Content</html>", cal) is False

    # Test EV calculation and budget clamping (more than 8 signals)
    rich_fingerprints = [
        "okta", "entra", "fortinet", "cloudflare", "wordpress",
        "graphql", "oracle", "proxmox", "nextjs",
    ]
    active, scores, _ = plan_skills(rich_fingerprints, max_budget=8)
    assert len(active) <= 8, "Active platform skills must be capped at 8"
    assert "70-exploit-intel" in active, "High EV Fortinet signal must trigger 70-exploit-intel"
    assert "30-auth-access-control" in active, "High EV Okta/Entra signal must trigger 30-auth-access-control"

    plan = generate_plan({"engagement": "test-client"}, rich_fingerprints, baselines=cal)
    assert plan["load_budget"]["allocated"] <= 8
    assert plan["soft404_calibrated"] is True
    assert "P1.5" in plan["phases"]

    print("[self-test] attack_plan_gen: scope-guard(7) + soft-404 + EV ranking + budget cap(8) passed")


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main(argv=None):
    parser = _Parser(
        description="Strategic attack surface & engagement execution planner."
    )
    parser.add_argument("--scope-file", help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target", help="target base URL (e.g. https://target.example.com)")
    parser.add_argument("--fingerprints-file", help="recon fingerprints JSON file")
    parser.add_argument("--baseline-file", help="saved soft-404 baseline JSON file")
    parser.add_argument("--probe-baseline", action="store_true", help="probe live target for soft-404 baseline")
    parser.add_argument("--profile", default="scan-standard", help="scan profile (default: scan-standard)")
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument("--self-test", action="store_true", help="run offline self-test and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    scope_file = args.scope_file or os.environ.get("REDJOHN_SCOPE_FILE")
    if not scope_file:
        parser.error("--scope-file is required")

    with open(scope_file, "r", encoding="utf-8") as fh:
        scope = json.load(fh)

    baselines = {}
    if args.baseline_file and os.path.exists(args.baseline_file):
        with open(args.baseline_file, "r", encoding="utf-8") as fh:
            baselines = json.load(fh)

    if args.probe_baseline:
        if not args.target:
            parser.error("--target is required with --probe-baseline")
        require_in_scope(args.target, scope_file)
        probe_paths = [
            "/rj-soft404-root-91823.html",
            "/rj-soft404-root-74621.html",
            "/a/b/rj-soft404-deep-91823.html",
            "/a/b/rj-soft404-deep-74621.html",
        ]
        probes = {}
        for p in probe_paths:
            probes[p] = fetch_path(args.target, p)
        baselines = calibrate_soft404_responses(probes)

    fingerprints = []
    if args.fingerprints_file and os.path.exists(args.fingerprints_file):
        with open(args.fingerprints_file, "r", encoding="utf-8") as fh:
            fp_data = json.load(fh)
            if isinstance(fp_data, list):
                fingerprints = fp_data
            elif isinstance(fp_data, dict):
                fingerprints = fp_data.get("fingerprints", [])

    plan = generate_plan(scope, fingerprints, baselines=baselines, profile=args.profile)

    if args.json:
        sys.stdout.write(json.dumps(plan, indent=2) + "\n")
    else:
        print("=== Attack Surface Execution Blueprint ===")
        print("Engagement: %s" % plan["engagement"])
        print("Profile:    %s" % plan["profile"])
        print("Budget:     %d / %d active skills" % (plan["load_budget"]["allocated"], plan["load_budget"]["cap"]))
        print("Active Skills: %s" % ", ".join(plan["active_platform_skills"]))
        print("\nPhased Progression:")
        for phase, items in plan["phases"].items():
            if items:
                print("  %-6s: %s" % (phase, ", ".join(items)))
        print("\n[evidence] Save blueprint to evidence/p0-blueprint-<engagement>.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())
