#!/usr/bin/env python3
"""proxmox_surface_probe.py - Proxmox VE surface probe (82-proxmox-ve).

Guarded unauthenticated fingerprint of a pveproxy host:
  - GET /api2/json/version        (pve-manager version anchor)
  - GET /api2/json/cluster/status (cluster/node disclosure or 401)
  - GET /                         (web UI title)
Reports what is disclosed without authentication; a 401 is reported as the
hardened observation. No POSTs, no auth attempts, no state changes.

Usage:
  python3 proxmox_surface_probe.py --scope-file scope.json --host pve.example.com
  python3 proxmox_surface_probe.py --scope-file scope.json --host pve.example.com:8006

--host accepts host or host:port (default port 8006) or a bare https:// URL.
pveproxy serves TLS by default; --ca PATH pins a CA bundle, otherwise an
unverified context is used with a printed warning (assessment-container use).

Exit codes: 0 = probe run completed; 2 = scope refusal; 1 = other error.

Evidence expectation: save each endpoint pair as
evidence/p8-pve-<host>-<endpoint>.{req,resp}.txt; hand the pinned version to
70-exploit-intel for correlation.
"""

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "redjohn-pentestskills/proxmox_surface_probe/1.0"
DEFAULT_PORT = 8006

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


# ---------------------------------------------------------------- host parsing


def normalize_target(host_arg):
    """host | host:port | https://host[:port] -> (url, host)."""
    raw = host_arg.strip()
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme != "https" or not parsed.hostname:
            return None
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return None  # bare origin only
        port = parsed.port or DEFAULT_PORT
        host = parsed.hostname
    else:
        host, _, port_s = raw.partition(":")
        if not host or not re.fullmatch(r"[A-Za-z0-9._-]+", host):
            return None
        try:
            port = int(port_s) if port_s else DEFAULT_PORT
        except ValueError:
            return None
    if not 1 <= port <= 65535:
        return None
    return "https://%s:%d/" % (host, port), host


# ---------------------------------------------------------------- parsing

TITLE_RE = re.compile(rb"<title[^>]*>([^<]{0,200})</title>", re.IGNORECASE)


def parse_version_payload(body):
    """Parse /api2/json/version JSON -> dict of interesting fields."""
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, dict):
        return None
    keep = {}
    for key in ("version", "release", "repoid", "managerVersion", "console"):
        if key in data:
            keep[key] = data[key]
    return keep or None


def parse_cluster_payload(body):
    """Parse /api2/json/cluster/status JSON -> summary dict."""
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, list):
        return None
    summary = {"cluster": None, "nodes": []}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "cluster" or entry.get("id") == "cluster":
            summary["cluster"] = {
                k: entry.get(k)
                for k in ("name", "nodes", "quorate", "id", "version")
                if k in entry}
        elif entry.get("type") == "node":
            summary["nodes"].append({
                k: entry.get(k)
                for k in ("name", "ip", "level", "nodeid", "online")
                if k in entry})
    return summary if (summary["cluster"] or summary["nodes"]) else None


def parse_title(body):
    m = TITLE_RE.search(body)
    return m.group(1).decode("latin-1", "replace").strip() if m else ""


# ---------------------------------------------------------------- transport


def fetch(url, timeout, ca_file=None):
    """GET with no redirects. Returns (status, headers, body)."""
    if ca_file:
        ctx = ssl.create_default_context(cafile=ca_file)
    else:
        # pveproxy ships self-signed certs in most installs; unverified mode
        # is warned about in main() and should be replaced with --ca when the
        # engagement provides a CA bundle.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx))

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener.add_handler(_NoRedirect())
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(262144)
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read(262144)


# ---------------------------------------------------------------- self-test


def _fake_getaddrinfo(host, port, *args, **kwargs):
    """Offline DNS stand-in: canned answers only, no network."""
    fake = {
        "example.com": ["93.184.216.34"],
        "target.example.com": ["203.0.113.10"],
        "pve.example.com": ["203.0.113.20"],
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


VERSION_FIXTURE = json.dumps({
    "data": {"version": "8.2.4", "release": "8.2",
             "repoid": "00000000000000000000", "console": "kvm"}
}).encode()

CLUSTER_FIXTURE = json.dumps({"data": [
    {"id": "cluster", "name": "example-cluster", "nodes": 2,
     "quorate": 1, "version": 3},
    {"type": "node", "id": "node/pve1", "name": "pve1", "ip": "203.0.113.21",
     "level": "", "nodeid": "00000001", "online": 1},
    {"type": "node", "id": "node/pve2", "name": "pve2", "ip": "203.0.113.22",
     "level": "", "nodeid": "00000002", "online": 1},
]}).encode()


def self_test():
    # --- mandatory scope-guard assertions (offline via fake DNS) ---
    original = socket.getaddrinfo
    socket.getaddrinfo = _fake_getaddrinfo
    try:
        local_scope = {"engagement": "selftest",
                       "allowed": [{"host": "localhost"}]}
        ok, why = host_allowed("https://example.com", local_scope)
        assert ok is False, "example.com must be refused, got %s" % why
        ok, why = host_allowed("https://10.0.0.5:8006/", local_scope)
        assert ok is False and why == "not-in-scope", why
        loop_scope = {"engagement": "selftest",
                      "allowed": [{"host": "127.0.0.1"}]}
        ok, why = host_allowed("https://127.0.0.1:8006/", loop_scope)
        assert ok is True, "listed loopback must be allowed, got %s" % why
        ok, why = host_allowed("http://127.0.0.1:8006/", loop_scope)
        assert ok is True, "http scheme is still a valid guard input"
    finally:
        socket.getaddrinfo = original

    # --- host normalization ---
    assert normalize_target("pve.example.com") == (
        "https://pve.example.com:8006/", "pve.example.com")
    assert normalize_target("pve.example.com:8443") == (
        "https://pve.example.com:8443/", "pve.example.com")
    assert normalize_target("https://pve.example.com") == (
        "https://pve.example.com:8006/", "pve.example.com")
    assert normalize_target("https://pve.example.com:8006/x") is None, \
        "URLs with a path are refused (bare origin only)"
    assert normalize_target("bad host") is None
    assert normalize_target("ftp://pve.example.com") is None

    # --- /api2/json/version parsing fixtures ---
    parsed = parse_version_payload(VERSION_FIXTURE)
    assert parsed and parsed["version"] == "8.2.4", parsed
    assert parsed["release"] == "8.2" and "repoid" in parsed, parsed
    assert parse_version_payload(b"<html>not json</html>") is None
    assert parse_version_payload(b'{"data": {"unrelated": 1}}') is None
    assert parse_version_payload(
        b'{"errors": "not a data doc"}') is None

    # --- /api2/json/cluster/status parsing fixtures ---
    summary = parse_cluster_payload(CLUSTER_FIXTURE)
    assert summary["cluster"]["name"] == "example-cluster", summary
    assert summary["cluster"]["nodes"] == 2, summary
    assert [n["name"] for n in summary["nodes"]] == ["pve1", "pve2"], summary
    assert summary["nodes"][0]["ip"] == "203.0.113.21", summary
    assert parse_cluster_payload(
        b'{"data": [{"type": "other"}]}') is None, \
        "no cluster/node rows -> not a cluster disclosure"
    assert parse_cluster_payload(b"401 page") is None

    # --- title extraction ---
    assert parse_title(b"<html><head><title>pve1 - Proxmox Virtual "
                       b"Environment</title></head></html>") == \
        "pve1 - Proxmox Virtual Environment"
    assert parse_title(b"<html><body>no title</body></html>") == ""

    print("[self-test] proxmox_surface_probe: guard(3) + host-normalization "
          "+ version/cluster/title parsing fixtures passed")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Proxmox VE unauthenticated surface probe (GET only).")
    parser.add_argument("--scope-file",
                        help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--host",
                        help="host or host:port (default 8006), or bare "
                             "https://host[:port]")
    parser.add_argument("--ca",
                        help="CA bundle for pveproxy TLS verification "
                             "(default: unverified with warning)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-request timeout seconds (default 10)")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="seconds between requests (default 0.2)")
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
    if not scope_file or not args.host:
        parser.error("--scope-file and --host are required")
    norm = normalize_target(args.host)
    if norm is None:
        parser.error("--host must be host, host:port or a bare "
                     "https://host[:port] URL")
    base_url, host = norm

    require_in_scope(base_url, scope_file)

    if not args.ca:
        print("[warn] TLS certificate verification disabled (self-signed "
              "pveproxy default); pin with --ca when the engagement "
              "provides a CA")
    print("[*] target=%s (unauthenticated GET only)" % base_url)

    endpoints = [
        ("/api2/json/version", "version"),
        ("/api2/json/cluster/status", "cluster"),
        ("/", "ui-title"),
    ]

    for path, label in endpoints:
        url = base_url.rstrip("/") + path
        try:
            status, headers, body = fetch(url, args.timeout, args.ca)
        except (urllib.error.URLError, OSError) as err:
            print("[error ] %-28s %s" % (path, err))
            continue

        if label == "version":
            parsed = parse_version_payload(body)
            if status == 200 and parsed:
                print("[version] %-28s status=200 pve-manager=%s release=%s "
                      "repoid=%s" % (path, parsed.get("version", "?"),
                                     parsed.get("release", "?"),
                                     parsed.get("repoid", "?")))
                print("[version] -> hand pinned version to 70-exploit-intel "
                      "(component=pve-manager; kernel/QEMU correlate "
                      "separately)")
            elif status == 401:
                print("[version] %-28s status=401 (auth-gated; get version "
                      "via credentialed read per references/"
                      "proxmox-api-surface.md)" % path)
            else:
                print("[version] %-28s status=%d len=%d (no parseable "
                      "version payload)" % (path, status, len(body)))

        elif label == "cluster":
            if status == 200:
                summary = parse_cluster_payload(body)
                if summary:
                    c = summary["cluster"] or {}
                    print("[cluster] %-25s status=200 cluster=%s nodes=%s "
                          "quorate=%s"
                          % (path, c.get("name", "?"), c.get("nodes", "?"),
                             c.get("quorate", "?")))
                    for node in summary["nodes"]:
                        print("[cluster]   node=%s ip=%s online=%s"
                              % (node.get("name", "?"), node.get("ip", "?"),
                                 node.get("online", "?")))
                    print("[cluster] unauthenticated cluster/node disclosure "
                          "-> D1 finding; save evidence pair")
                else:
                    print("[cluster] %-25s status=200 but no cluster/node "
                          "rows (body len=%d)" % (path, len(body)))
            elif status == 401:
                print("[cluster] %-25s status=401 (hardened observation: "
                      "cluster status requires auth)" % path)
            else:
                print("[cluster] %-25s status=%d len=%d"
                      % (path, status, len(body)))

        else:  # ui title
            title = parse_title(body)
            print("[ui     ] %-28s status=%d title=%r"
                  % (path, status, title[:80]))
            if status in (301, 302, 303, 307, 308):
                print("[ui     ]   redirect->%s" % headers.get("Location",
                                                               "?"))
        time.sleep(args.delay)

    print("[summary] endpoints=3 (version, cluster/status, ui); no POSTs, no "
          "auth attempts, no state changes")
    print("[evidence] save pairs as evidence/p8-pve-%s-<endpoint>.{req,resp}"
          ".txt; credentialed reads follow references/proxmox-api-surface.md "
          "(secrets via env, redacted in evidence copies)" % host)


if __name__ == "__main__":
    main()
