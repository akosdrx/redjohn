#!/usr/bin/env python3
"""oracle_surface_probe.py - Oracle stack surface probe (80-oracle-stack).

Guarded observation-only probe for Oracle surfaces in scope:
  - TCP connect checks on 1521 (TNS) / 7001 / 7002 with a bounded timeout,
    plus a minimal read-only TNS CONNECT packet (COMMAND=VERSION) banner read.
  - HTTP GET checks for WebLogic console paths (/console,
    /console/login/LoginForm.jsp, /wls-wsat/CoordinatorPortType,
    /uddiexplorer/) and EBS /OA_HTML /OA_MEDIA /OA_JAVA markers, with
    version/marker extraction.

No exploitation: no serialized objects, no listener-mutating commands, no
POSTs. Any target outside the engagement scope is refused (exit 2).

Usage:
  python3 oracle_surface_probe.py --scope-file scope.json --host target.example.com
  python3 oracle_surface_probe.py --scope-file scope.json --host target.example.com:7001
  python3 oracle_surface_probe.py --scope-file scope.json --host https://target.example.com:7002

--host accepts host, host:port (default port 7001, https default 7002) or a
full http(s):// URL. TCP checks always test 1521/7001/7002 on the same host.

Exit codes: 0 = probe run completed; 2 = scope refusal; 1 = other error.

Evidence expectation: save every hit as
evidence/p8-oracle-<surface>-<host>-<slug>.{req,resp}.txt (packet hex for TNS,
headers+body for HTTP); re-run once for D2.
"""

import argparse
import ipaddress
import json
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "redjohn-pentestskills/oracle_surface_probe/1.0"

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

DEFAULT_HTTP_PORT = 7001
DEFAULT_HTTPS_PORT = 7002
TCP_PORTS = [1521, 7001, 7002]


def normalize_target(host_arg):
    """host | host:port | scheme://host[:port] -> (url, host, port, scheme)."""
    raw = host_arg.strip()
    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        scheme = parsed.scheme
        if scheme not in ("http", "https"):
            return None
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return None  # bare origin only; probe paths are built in-code
        host = parsed.hostname
        port = parsed.port or (
            DEFAULT_HTTP_PORT if scheme == "http" else DEFAULT_HTTPS_PORT)
    else:
        host, _, port_s = raw.partition(":")
        if not host or not re.fullmatch(r"[A-Za-z0-9._-]+", host):
            return None  # hostname-style host only (IPv6 hosts need brackets
            # and an explicit scheme; they are out of this probe's default)
        try:
            port = int(port_s) if port_s else DEFAULT_HTTP_PORT
        except ValueError:
            return None
        scheme = "http"
    if not 1 <= port <= 65535:
        return None
    url = "%s://%s:%d/" % (scheme, host, port)
    return url, host, port, scheme


# ---------------------------------------------------------------- TNS probe

TNS_CONNECT_TYPE = 1


def build_tns_packet(connect_data):
    """Minimal TNS CONNECT packet: 8-byte header + connect data."""
    data = connect_data.encode("ascii")
    header = struct.pack(">HHBBH", 8 + len(data), 0, TNS_CONNECT_TYPE, 0, 0)
    return header + data


TNS_VERSION_DATA = "(CONNECT_DATA=(COMMAND=VERSION))"

TNS_BANNER_RE = re.compile(rb"TNSLSNR[^\r\n\x00]{0,160}")
TNS_VERSION_NUM_RE = re.compile(rb"(\d{1,2}(?:\.\d{1,5}){2,4})")


def tns_probe(host, port, timeout):
    """Connect, send VERSION packet, read bounded reply. Returns report dict."""
    report = {"port": port, "connect": False}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, OSError) as err:
        report["error"] = "%s" % err
        return report
    report["connect"] = True
    reply = b""
    try:
        sock.settimeout(timeout)
        pkt = build_tns_packet(TNS_VERSION_DATA)
        report["sent_hex"] = pkt.hex()
        sock.sendall(pkt)
        try:
            reply = sock.recv(4096)
        except (socket.timeout, OSError) as err:
            report["read_error"] = "%s" % err
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if reply:
        report["recv_hex"] = reply[:512].hex()
        report["banner"] = decode_banner(reply)
    return report


def decode_banner(reply):
    """Extract readable TNSLSNR banner + version from raw reply bytes."""
    out = {"text": "", "version": ""}
    m = TNS_BANNER_RE.search(reply)
    if m:
        out["text"] = m.group(0).decode("latin-1", "replace").strip()
    scope_txt = m.group(0) if m else reply[:256]
    vm = TNS_VERSION_NUM_RE.search(scope_txt)
    if vm:
        out["version"] = vm.group(1).decode("latin-1")
    return out


# ---------------------------------------------------------------- HTTP probes

# (path, family, markers) - markers lowercase bytes, matched case-insensitive.
HTTP_PATHS = [
    ("/console", "weblogic", [b"weblogic", b"login", b"console"]),
    ("/console/login/LoginForm.jsp", "weblogic-login",
     [b"weblogic", b"password", b"loginform"]),
    ("/wls-wsat/CoordinatorPortType", "weblogic-wsat",
     [b"wsat", b"soap", b"coordinator"]),
    ("/uddiexplorer/", "weblogic-uddi", [b"uddi"]),
    ("/uddiexplorer/SearchUDI.jsp", "weblogic-uddi", [b"uddi"]),
    ("/management/tenant-monitoring/servers", "weblogic-mgmt",
     [b"servers", b"item", b"items"]),
    ("/_async/AsyncResponseService", "weblogic-async",
     [b"asyncresponseservice", b"soap", b"wsdl"]),
    ("/i/apex_version.txt", "oracle-apex",
     [b"application express", b"apex"]),
    ("/ords/apex_admin", "oracle-apex-admin",
     [b"oracle apex", b"administration services", b"apex"]),
    ("/ords/f?p=4550:1", "oracle-apex-login",
     [b"oracle apex", b"application express", b"workspace"]),
    ("/OA_HTML/", "ebs", [b"appslocallogin", b"e-business",
                          b"oracle applications"]),
    ("/OA_HTML/AppsLocalLogin.jsp", "ebs-login",
     [b"appslocallogin", b"password"]),
    ("/OA_HTML/BneUploaderService", "ebs-dmz-bne",
     [b"bneuploaderservice", b"oracle", b"service"]),
    ("/OA_HTML/OA.jsp", "ebs-dmz-oajsp",
     [b"oracle", b"oajsp", b"appslocallogin"]),
    ("/OA_HTML/cabo/", "ebs-dmz-cabo", [b"cabo", b"oracle"]),
    ("/OA_HTML/oam/", "ebs-dmz-oam",
     [b"oam", b"oracle applications manager", b"login"]),
    ("/OA_MEDIA/", "ebs-media", [b"oracle"]),
    ("/OA_JAVA/", "ebs-java", [b"oracle"]),
]

WEBLOGIC_VERSION_RE = re.compile(
    rb"weblogic[^\d]{1,120}?(\d{1,2}(?:\.\d{1,5}){2,4})",
    re.IGNORECASE)
EBS_RELEASE_RE = re.compile(
    rb"release[:\s]+(\d{1,2}(?:\.\d{1,2}){1,2})",
    re.IGNORECASE)
APEX_VERSION_RE = re.compile(
    rb"(?:application\s+express|apex)[^\d]{1,60}?(\d{1,2}(?:\.\d{1,5}){1,4})",
    re.IGNORECASE)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, timeout):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(262144)
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read(262144)


def extract_versions(body):
    """Return (weblogic_version, ebs_release, apex_version) strings ('' when absent)."""
    wls = ebs = apex = ""
    m = WEBLOGIC_VERSION_RE.search(body)
    if m:
        wls = m.group(1).decode("latin-1")
    m = EBS_RELEASE_RE.search(body)
    if m:
        ebs = m.group(1).decode("latin-1")
    m = APEX_VERSION_RE.search(body)
    if m:
        apex = m.group(1).decode("latin-1")
    return wls, ebs, apex


def marker_hits(body, markers):
    low = body.lower()
    return [m.decode("latin-1") for m in markers if m in low]


# ---------------------------------------------------------------- self-test


def _fake_getaddrinfo(host, port, *args, **kwargs):
    """Offline DNS stand-in: canned answers only, no network."""
    fake = {
        "example.com": ["93.184.216.34"],
        "target.example.com": ["203.0.113.10"],
        "db.target.example.com": ["203.0.113.20"],
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
    # --- mandatory scope-guard assertions (offline via fake DNS) ---
    original = socket.getaddrinfo
    socket.getaddrinfo = _fake_getaddrinfo
    try:
        local_scope = {"engagement": "selftest",
                       "allowed": [{"host": "localhost"}]}
        ok, why = host_allowed("https://example.com", local_scope)
        assert ok is False, "example.com must be refused, got %s" % why
        ok, why = host_allowed("http://10.0.0.5/", local_scope)
        assert ok is False and why == "not-in-scope", why
        loop_scope = {"engagement": "selftest",
                      "allowed": [{"host": "127.0.0.1"}]}
        ok, why = host_allowed("http://127.0.0.1:7001/", loop_scope)
        assert ok is True, "listed loopback must be allowed, got %s" % why
        # scheme guard
        ok, why = host_allowed("t3://127.0.0.1:7001", loop_scope)
        assert ok is False and why == "scheme-not-http(s)", why
    finally:
        socket.getaddrinfo = original

    # --- host normalization ---
    assert normalize_target("db.target.example.com") == (
        "http://db.target.example.com:7001/", "db.target.example.com",
        7001, "http")
    assert normalize_target("db.target.example.com:8001") == (
        "http://db.target.example.com:8001/", "db.target.example.com",
        8001, "http")
    assert normalize_target("https://db.target.example.com") == (
        "https://db.target.example.com:7002/", "db.target.example.com",
        7002, "https")
    assert normalize_target("https://db.example.com:8443/x") is None, \
        "URLs with a path are refused (bare origin only)"
    assert normalize_target("bad host") is None

    # --- TNS packet construction ---
    pkt = build_tns_packet(TNS_VERSION_DATA)
    length, _ck, ptype, _res, _hck = struct.unpack(">HHBBH", pkt[:8])
    assert length == len(pkt), "length field must cover header+data"
    assert ptype == TNS_CONNECT_TYPE, ptype
    assert pkt[8:].decode("ascii") == TNS_VERSION_DATA

    # --- banner decoding fixtures ---
    banner = (b"\x00\x00TNSLSNR for Linux: Version 19.0.0.0.0 - "
              b"Production\r\n")
    dec = decode_banner(banner)
    assert dec["version"] == "19.0.0.0.0", dec
    assert "TNSLSNR for Linux" in dec["text"], dec
    dec = decode_banner(b"\xfe\xff\x00\x00")  # no banner payload
    assert dec["text"] == "" and dec["version"] == "", dec
    # 11g-style version with 5 components
    dec = decode_banner(b"TNSLSNR for 64-bit Windows: Version "
                        b"11.2.0.4.0 - Production")
    assert dec["version"] == "11.2.0.4.0", dec

    # --- version/marker extraction fixtures ---
    wls, ebs, apex = extract_versions(
        b"<html><title>WebLogic Server</title>"
        b"<footer>WebLogic Server Version: 12.2.1.4.0</footer></html>")
    assert wls == "12.2.1.4.0", wls
    assert ebs == "" and apex == "", (ebs, apex)
    wls, ebs, apex = extract_versions(
        b"Oracle E-Business Suite : Release 12.2.9")
    assert ebs == "12.2.9", ebs
    assert wls == "" and apex == "", (wls, apex)
    wls, ebs, apex = extract_versions(
        b"Application Express 22.1.0.00.01")
    assert apex == "22.1.0.00.01", apex
    assert wls == "" and ebs == "", (wls, ebs)
    assert marker_hits(b"<a href=AppsLocalLogin>Sign-In</a>",
                       [b"appslocallogin"]) == ["appslocallogin"]
    assert marker_hits(b"plain 404 page", [b"weblogic"]) == []
    assert marker_hits(b"bneuploaderservice ready",
                       [b"bneuploaderservice"]) == ["bneuploaderservice"]
    assert marker_hits(b"AsyncResponseService?wsdl",
                       [b"asyncresponseservice"]) == ["asyncresponseservice"]
    assert marker_hits(b'{"servers": [{"name": "AdminServer"}]}',
                       [b"servers"]) == ["servers"]

    # --- path table sanity ---
    for path, family, markers in HTTP_PATHS:
        assert path.startswith("/") and ".." not in path, path
        assert markers, path
    assert any(f.startswith("weblogic") for _p, f, _m in HTTP_PATHS)
    assert any(f.startswith("ebs") for _p, f, _m in HTTP_PATHS)
    assert any(f.startswith("oracle-apex") for _p, f, _m in HTTP_PATHS)
    assert any("BneUploaderService" in _p for _p, _f, _m in HTTP_PATHS)
    assert any("/management/" in _p for _p, _f, _m in HTTP_PATHS)
    assert any("/_async/" in _p for _p, _f, _m in HTTP_PATHS)

    print("[self-test] oracle_surface_probe: guard(3) + host-normalization + "
          "tns-packet/banner + http-marker/version fixtures passed")


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Oracle stack observation probe (TCP/TNS + HTTP GET "
                    "only, no exploitation).")
    parser.add_argument("--scope-file",
                        help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--host",
                        help="host, host:port or http(s)://host[:port] "
                             "(default port 7001, or 7002 for https)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="per-probe timeout seconds (default 5)")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="seconds between HTTP probes (default 0.2)")
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
                     "http(s)://host[:port] URL")
    base_url, host, http_port, _scheme = norm

    # one guard check covers host + all TCP ports (guard is host/CIDR based)
    require_in_scope(base_url, scope_file)

    print("[*] target=%s tcp_ports=%s (observation only, read-only TNS "
          "VERSION command)" % (base_url, ",".join(map(str, TCP_PORTS))))

    # --- TCP + TNS ---
    for port in TCP_PORTS:
        rep = tns_probe(host, port, args.timeout)
        if not rep["connect"]:
            print("[tcp   ] %-5d closed/filtered (%s)" % (port,
                                                          rep.get("error", "")))
            continue
        line = "[tcp   ] %-5d open" % port
        if rep.get("banner", {}).get("text"):
            b = rep["banner"]
            line += " banner=%r version=%s" % (b["text"][:100],
                                               b["version"] or "?")
            print(line)
            print("[tns   ] evidence: sent=%s recv=%s -> save as "
                  "evidence/p8-oracle-tns-%s-%d.{req,resp}.txt"
                  % (rep.get("sent_hex", "")[:32],
                     rep.get("recv_hex", "")[:32], host, port))
            print("[tns   ] version -> hand to 70-exploit-intel for CPU "
                  "correlation (tier 2 banner)")
        else:
            print(line + " (no banner without full handshake; use "
                  "nmap oracle-tns-version per references/oracle-db-surface)")
        time.sleep(0.1)

    # --- HTTP paths ---
    hits = 0
    for path, family, markers in HTTP_PATHS:
        url = base_url.rstrip("/") + path
        try:
            status, headers, body = fetch(url, args.timeout)
        except (urllib.error.URLError, OSError) as err:
            print("[error ] %-36s %s" % (path, err))
            continue
        hits_list = marker_hits(body, markers)
        wls, ebs, apex = extract_versions(body)
        notes = []
        if hits_list:
            notes.append("markers=[%s]" % ",".join(hits_list))
        if wls:
            notes.append("weblogic_version=%s" % wls)
        if ebs:
            notes.append("ebs_release=%s" % ebs)
        if apex:
            notes.append("apex_version=%s" % apex)
        verdict = "surface-present" if (hits_list or wls or ebs or apex) else \
            "status-%d" % status
        if status in (301, 302, 303, 307, 308):
            verdict += " redirect->%s" % headers.get("Location", "?")
        if hits_list or wls or ebs or apex:
            hits += 1
        print("[%-14s] %-36s status=%d len=%-7d %s%s"
              % (family, path, status, len(body), verdict,
                 (" " + " ".join(notes)) if notes else ""))
        time.sleep(args.delay)

    print("[summary] tcp checked=%d http paths=%d surface-present=%d"
          % (len(TCP_PORTS), len(HTTP_PATHS), hits))
    print("[evidence] save hits as "
          "evidence/p8-oracle-<surface>-%s-<slug>.{req,resp}.txt; re-run once "
          "for D2. No POSTs, no serialized objects, no listener-mutating "
          "commands from this probe." % host)


if __name__ == "__main__":
    main()
