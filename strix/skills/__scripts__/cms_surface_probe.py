#!/usr/bin/env python3
"""cms_surface_probe.py - Read-only CMS and e-commerce surface/version probe
(15-cms-ecommerce-rce).

Performs soft-404 calibration followed by bounded, read-only HTTP GET checks
against an in-scope target to identify e-commerce/CMS platforms, extract
Tier 1-2 version numbers, and emit P1.5 candidate surfaces for 70-exploit-intel.

Strictly read-only: sends only GET requests with _NoRedirect, no payloads, no
mutations. Refuses any target outside the engagement scope (exit 2).

Usage:
  python3 cms_surface_probe.py --scope-file scope.json --target https://target.example.com
  python3 cms_surface_probe.py --self-test

Exit codes: 0 = probe completed; 2 = scope refusal; 1 = other error.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "redjohn-pentestskills/cms_surface_probe/1.0"

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
            return resp.status, headers, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        raw = err.read(32768) if err.fp else b""
        headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
        return err.code, headers, raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------- probes

PROBE_RULES = [
    {
        "platform": "magento",
        "ecosystem": "Packagist",
        "package": "magento/product-community-edition",
        "path": "/magento_version",
        "marker_re": re.compile(r"Magento/([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9.]+)?)", re.I),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "Check REST/SOAP webapi deserialization & template filters (e.g. CVE-2024-34102, CVE-2022-24086)",
    },
    {
        "platform": "woocommerce",
        "ecosystem": "Packagist",
        "package": "woocommerce/woocommerce",
        "path": "/wp-content/plugins/woocommerce/readme.txt",
        "marker_re": re.compile(r"Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "Check WooCommerce & active WP plugin REST routes (/wp-json/wc/v3)",
    },
    {
        "platform": "wordpress-rest",
        "ecosystem": "Packagist",
        "package": "wordpress/wordpress",
        "path": "/wp-json/",
        "marker_re": re.compile(r'"namespaces"\s*:\s*\[([^\]]+)\]', re.I),
        "tier_if_version": 2,
        "tier_if_marker": 2,
        "p15_note": "Enumerate exposed /wp-json/ plugin namespaces for unauthenticated RCE/SQLi advisories",
    },
    {
        "platform": "shopware",
        "ecosystem": "Packagist",
        "package": "shopware/core",
        "path": "/api/_info/version",
        "marker_re": re.compile(r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9.]+)?)"', re.I),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "Check Shopware Twig mail/template rendering & API hydration advisories",
    },
    {
        "platform": "drupal",
        "ecosystem": "Packagist",
        "package": "drupal/core",
        "path": "/core/CHANGELOG.txt",
        "marker_re": re.compile(r"Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "Check Drupal core/commerce render array & Twig filter advisories",
    },
    {
        "platform": "laravel-ignition",
        "ecosystem": "Packagist",
        "package": "facade/ignition",
        "path": "/_ignition/health-check",
        "marker_re": re.compile(r'"can_execute_commands"\s*:\s*(true|false)', re.I),
        "tier_if_version": 1,
        "tier_if_marker": 1,
        "p15_note": "Exposed Laravel Ignition debug endpoint (check CVE-2021-3129)",
    },
    {
        "platform": "spring-actuator",
        "ecosystem": "Maven",
        "package": "org.springframework.boot:spring-boot-actuator",
        "path": "/actuator/info",
        "marker_re": re.compile(r'"(?:version|build|app)"\s*:', re.I),
        "tier_if_version": 2,
        "tier_if_marker": 2,
        "p15_note": "Exposed Spring Boot Actuator surface; check /actuator/env and SpEL/view handlers",
    },
    {
        "platform": "joomla-manifest",
        "ecosystem": "Packagist",
        "package": "joomla/joomla-cms",
        "path": "/administrator/manifests/files/joomla.xml",
        "marker_re": re.compile(r"<version>\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*</version>", re.I),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "Joomla! core release manifest exposed; verify CVE-2023-23752 / REST API access",
    },
    {
        "platform": "joomla-lang",
        "ecosystem": "Packagist",
        "package": "joomla/joomla-cms",
        "path": "/language/en-GB/en-GB.xml",
        "marker_re": re.compile(r"<version>\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*</version>", re.I),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "Joomla! language XML manifest version disclosure",
    },
    {
        "platform": "joomla-api",
        "ecosystem": "Packagist",
        "package": "joomla/joomla-cms",
        "path": "/api/index.php/v1/",
        "marker_re": re.compile(r'"links"\s*:\s*\[|\{"data":|"application/vnd\.api\+json"|<title>Joomla! API</title>', re.I),
        "tier_if_version": 2,
        "tier_if_marker": 2,
        "p15_note": "Joomla 4/5 Web Services API endpoint exposed; test unauthenticated user/config endpoints",
    },
    {
        "platform": "wordpress-opml",
        "ecosystem": "Packagist",
        "package": "wordpress/wordpress",
        "path": "/wp-links-opml.php",
        "marker_re": re.compile(r'generator="WordPress/([0-9]+\.[0-9]+(?:\.[0-9]+)?)"', re.I),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "WordPress OPML export reveals exact core version",
    },
    {
        "platform": "wordpress-xmlrpc",
        "ecosystem": "Packagist",
        "package": "wordpress/wordpress",
        "path": "/xmlrpc.php",
        "marker_re": re.compile(r"XML-RPC server accepts POST requests only", re.I),
        "tier_if_version": 2,
        "tier_if_marker": 2,
        "p15_note": "WordPress XML-RPC enabled; check system.multicall brute-force amplification & pingback SSRF",
    },
    {
        "platform": "wordpress-plugin",
        "ecosystem": "Packagist",
        "package": "wpackagist-plugin/elementor",
        "path": "/wp-content/plugins/elementor/readme.txt",
        "marker_re": re.compile(r"Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "Check exposed WordPress plugin version in readme.txt for known component CVEs",
    },
    {
        "platform": "drupal-jsonapi",
        "ecosystem": "Packagist",
        "package": "drupal/core",
        "path": "/jsonapi",
        "marker_re": re.compile(r'"jsonapi"\s*:\s*\{|"meta"\s*:\s*\{.*"links"\s*:|"jsonapi"', re.I),
        "tier_if_version": 2,
        "tier_if_marker": 2,
        "p15_note": "Drupal JSON:API exposed; check anonymous entity listing and field exposure",
    },
    {
        "platform": "prestashop-channel",
        "ecosystem": "Packagist",
        "package": "prestashop/prestashop",
        "path": "/config/xml/channel.xml",
        "marker_re": re.compile(
            r"<channel>[\s\S]*?<version>\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*</version>|"
            r"<version>\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*</version>|<channel>|<prestashop>",
            re.I,
        ),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "PrestaShop channel XML configuration exposed",
    },
    {
        "platform": "prestashop-module",
        "ecosystem": "Packagist",
        "package": "prestashop/autoupgrade",
        "path": "/modules/autoupgrade/config.xml",
        "marker_re": re.compile(r"<version>(?:<!\[CDATA\[)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\]\]>)?</version>", re.I),
        "tier_if_version": 1,
        "tier_if_marker": 2,
        "p15_note": "PrestaShop module XML manifest exposed; check module version & config",
    },
    {
        "platform": "prestashop-api",
        "ecosystem": "Packagist",
        "package": "prestashop/prestashop",
        "path": "/api/",
        "marker_re": re.compile(r"<prestashop\s+xmlns:|PrestaShop\s+Webservice|PrestaShop", re.I),
        "tier_if_version": 2,
        "tier_if_marker": 2,
        "p15_note": "PrestaShop Webservice API exposed; check authentication & key permission scope",
    },
]


def body_signature(status, body):
    """Return a compact soft-404 fingerprint tuple (status, length_bucket, sha256_prefix)."""
    norm = re.sub(r"\s+", " ", (body or "").strip())
    digest = hashlib.sha256(norm.encode("utf-8", errors="replace")).hexdigest()[:12]
    return status, len(norm) // 128, digest


def analyze_responses(responses, soft404_sig=None):
    """Analyze {path: (status, headers, body)} -> list of detected surface dicts."""
    findings = []

    root_tup = responses.get("/")
    if root_tup:
        _st, hdrs, body = root_tup
        powered = hdrs.get("x-powered-by", "")
        gen = hdrs.get("x-generator", "")
        cookies = hdrs.get("set-cookie", "")
        if "next.js" in powered.lower() or "/_next/static/" in body:
            findings.append({
                "platform": "nextjs",
                "ecosystem": "npm",
                "package": "next",
                "version": "unknown",
                "tier": 2,
                "path": "/",
                "p15_note": "Next.js storefront detected; check middleware & Server Action advisories",
            })
        if "drupal" in gen.lower():
            m = re.search(r"Drupal\s+([0-9]+(?:\.[0-9]+)*)", gen, re.I)
            findings.append({
                "platform": "drupal",
                "ecosystem": "Packagist",
                "package": "drupal/core",
                "version": m.group(1) if m else "unknown",
                "tier": 1 if (m and "." in m.group(1)) else 2,
                "path": "/",
                "p15_note": "Drupal header marker detected",
            })
        if "laravel_session" in cookies.lower():
            findings.append({
                "platform": "laravel",
                "ecosystem": "Packagist",
                "package": "laravel/framework",
                "version": "unknown",
                "tier": 3,
                "path": "/",
                "p15_note": "Laravel session cookie detected; check /_ignition/health-check and Livewire routes",
            })

    for rule in PROBE_RULES:
        tup = responses.get(rule["path"])
        if not tup:
            continue
        status, _hdrs, body = tup
        if status != 200:
            continue
        if soft404_sig and body_signature(status, body) == soft404_sig:
            continue
        match = rule["marker_re"].search(body or "")
        if not match:
            continue
        val = None
        if match.lastindex:
            for g in range(1, match.lastindex + 1):
                if match.group(g):
                    val = match.group(g).strip()
                    break
        extracted = val if val else "detected"
        is_semver = bool(re.match(r"^[0-9]+\.[0-9]+", extracted))
        findings.append({
            "platform": rule["platform"],
            "ecosystem": rule["ecosystem"],
            "package": rule["package"],
            "version": extracted if is_semver else "detected",
            "tier": rule["tier_if_version"] if is_semver else rule["tier_if_marker"],
            "path": rule["path"],
            "p15_note": rule["p15_note"],
        })

    return findings


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
    finally:
        socket.getaddrinfo = original

    # Fixture 1: Magento 2.4.6 + WooCommerce 8.5.1 + Laravel Ignition
    soft_body = "<html><body>Store 404 Not Found</body></html>"
    soft_sig = body_signature(200, soft_body)
    responses = {
        "/": (200, {"x-powered-by": "Next.js", "set-cookie": "laravel_session=abc"}, "<html></html>"),
        "/magento_version": (200, {}, "Magento/2.4.6 (Community)"),
        "/wp-content/plugins/woocommerce/readme.txt": (
            200,
            {},
            "=== WooCommerce ===\nStable tag: 8.5.1\n",
        ),
        "/api/_info/version": (200, {}, soft_body),  # soft-404 must be ignored
        "/_ignition/health-check": (200, {}, '{"can_execute_commands": true}'),
    }
    hits = analyze_responses(responses, soft404_sig=soft_sig)
    by_plat = {h["platform"]: h for h in hits}
    assert "magento" in by_plat and by_plat["magento"]["version"] == "2.4.6"
    assert by_plat["magento"]["tier"] == 1
    assert "woocommerce" in by_plat and by_plat["woocommerce"]["version"] == "8.5.1"
    assert by_plat["woocommerce"]["tier"] == 1
    assert "laravel-ignition" in by_plat and by_plat["laravel-ignition"]["tier"] == 1
    assert "shopware" not in by_plat, "soft-404 response must be filtered out"

    # Fixture 2: Joomla! 5.0.3 + WordPress OPML/XML-RPC/plugin + Drupal JSON:API + PrestaShop 8.1.5
    responses_2 = {
        "/administrator/manifests/files/joomla.xml": (
            200, {}, '<extension version="5.0"><version>5.0.3</version></extension>'
        ),
        "/language/en-GB/en-GB.xml": (
            200, {}, "<metafile><version>5.0.3</version></metafile>"
        ),
        "/api/index.php/v1/": (
            200, {}, '{"links":[{"self":"/api/index.php/v1/"}],"data":[]}'
        ),
        "/wp-links-opml.php": (
            200, {}, '<!-- generator="WordPress/6.5.2" -->'
        ),
        "/xmlrpc.php": (
            200, {}, "XML-RPC server accepts POST requests only."
        ),
        "/wp-content/plugins/elementor/readme.txt": (
            200, {}, "=== Elementor ===\nStable tag: 3.20.0\n"
        ),
        "/jsonapi": (
            200, {}, '{"jsonapi":{"version":"1.0"},"meta":{"links":{"self":"/jsonapi"}}}'
        ),
        "/config/xml/channel.xml": (
            200, {}, "<channel><name>prestashop</name><version>8.1.5</version></channel>"
        ),
        "/modules/autoupgrade/config.xml": (
            200, {}, "<module><name>autoupgrade</name><version><![CDATA[5.0.0]]></version></module>"
        ),
        "/api/": (
            200, {}, '<prestashop xmlns:xlink="http://www.w3.org/1999/xlink"><api></api></prestashop>'
        ),
    }
    hits_2 = analyze_responses(responses_2)
    by_plat_2 = {h["platform"]: h for h in hits_2}
    assert "joomla-manifest" in by_plat_2 and by_plat_2["joomla-manifest"]["version"] == "5.0.3"
    assert by_plat_2["joomla-manifest"]["tier"] == 1
    assert "joomla-lang" in by_plat_2 and by_plat_2["joomla-lang"]["version"] == "5.0.3"
    assert by_plat_2["joomla-lang"]["tier"] == 1
    assert "joomla-api" in by_plat_2 and by_plat_2["joomla-api"]["tier"] == 2
    assert "wordpress-opml" in by_plat_2 and by_plat_2["wordpress-opml"]["version"] == "6.5.2"
    assert by_plat_2["wordpress-opml"]["tier"] == 1
    assert "wordpress-xmlrpc" in by_plat_2 and by_plat_2["wordpress-xmlrpc"]["tier"] == 2
    assert "wordpress-plugin" in by_plat_2 and by_plat_2["wordpress-plugin"]["version"] == "3.20.0"
    assert by_plat_2["wordpress-plugin"]["tier"] == 1
    assert "drupal-jsonapi" in by_plat_2 and by_plat_2["drupal-jsonapi"]["tier"] == 2
    assert "prestashop-channel" in by_plat_2 and by_plat_2["prestashop-channel"]["version"] == "8.1.5"
    assert by_plat_2["prestashop-channel"]["tier"] == 1
    assert "prestashop-module" in by_plat_2 and by_plat_2["prestashop-module"]["version"] == "5.0.0"
    assert by_plat_2["prestashop-module"]["tier"] == 1
    assert "prestashop-api" in by_plat_2 and by_plat_2["prestashop-api"]["tier"] == 2

    print(
        "[self-test] cms_surface_probe: scope-guard(4) + Magento/WooCommerce/"
        "Ignition/Next.js/Joomla/WordPress/Drupal/PrestaShop extraction + soft-404 filtering passed"
    )


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main(argv=None):
    parser = _Parser(
        description="Read-only CMS & e-commerce surface/version fingerprinter."
    )
    parser.add_argument("--scope-file", help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target", help="target base URL (e.g. https://target.example.com)")
    parser.add_argument("--timeout", type=int, default=8, help="timeout seconds (default 8)")
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

    try:
        s404_status, _s404_hdrs, s404_body = fetch_path(
            args.target, "/rj-soft404-calibrate-98412.txt", timeout=args.timeout
        )
        soft_sig = body_signature(s404_status, s404_body) if s404_status == 200 else None

        responses = {}
        paths = ["/"] + [r["path"] for r in PROBE_RULES]
        for path in paths:
            responses[path] = fetch_path(args.target, path, timeout=args.timeout)
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write("[error] probe failed against %s: %s\n" % (args.target, exc))
        return 1

    hits = analyze_responses(responses, soft404_sig=soft_sig)
    if args.json:
        sys.stdout.write(json.dumps({"target": args.target, "surfaces": hits}, indent=2) + "\n")
    else:
        print("[target] %s -> %d CMS/e-commerce surface(s) detected" % (args.target, len(hits)))
        for hit in hits:
            print(
                "[T%d] %-18s pkg=%-36s ver=%-12s path=%s"
                % (hit["tier"], hit["platform"], hit["package"], hit["version"], hit["path"])
            )
            print("     -> %s" % hit["p15_note"])
        print(
            "[evidence] save version/surface responses as "
            "evidence/p1-cms-<host>-<seq>.{req,resp}.txt and pass Tier 1-2 "
            "packages to vuln_intel_priority_scan / exploit_priority_rank.py"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
