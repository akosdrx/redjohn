#!/usr/bin/env python3
"""exposure_probe.py - built-in sensitive-path exposure probe.

GETs a built-in list (~60) of well-known sensitive relative paths against the
target base URL, one at a time, reporting status/size/interesting markers per
path with 403-vs-404 triage. Any path that would resolve outside the target
origin is refused (exit 2). Paths and triage rules mirror
references/sensitive-files.md.

Usage:
  python3 exposure_probe.py --scope-file scope.json --target http://target.example.com
  python3 exposure_probe.py --scope-file scope.json --target http://target.example.com \
      --path custom/.env.prod

Exit codes: 0 = probe run completed (see verdicts); 2 = scope refusal (target
host or an escaping path); 1 = other error.

Evidence expectation: save every [EXPOSED] hit as
evidence/p2-exposure-<host>-<slug>.{req,resp}.txt (full body when practical);
re-fetch once for D2. GET only - never POST/PUT in this phase.
"""

import argparse
import hashlib
import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "redjohn-pentestskills/exposure_probe/1.0"

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


# ---------------------------------------------------------------- path list

GIT_MARKERS = [b"[core]", b"[remote", b"ref: refs/"]
ENV_MARKERS = [b"db_", b"app_key", b"secret", b"api_key", b"smtp_",
               b"password"]
SQL_MARKERS = [b"insert into", b"create table", b"-- mysql dump",
               b"dump completed"]
PHP_MARKERS = [b"<?php"]
HEX_RE = bytes  # marker handled specially below

MAGIC_ZIP = b"PK\x03\x04"
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_GIT_INDEX = b"DIRC"
MAGIC_DSSTORE = b"Bud1"

# (path, family, markers, magic) - markers lowercase bytes, matched case-
# insensitively; magic is a fixed prefix/substring.
PATHS = [
    # VCS metadata
    (".git/config", "vcs", GIT_MARKERS, None),
    (".git/HEAD", "vcs", [b"ref: refs/"], None),
    (".git/index", "vcs", [], MAGIC_GIT_INDEX),
    (".git/logs/HEAD", "vcs", [b"commit"], None),
    (".git/packed-refs", "vcs", [b"refs/"], None),
    (".git/refs/heads/master", "vcs", [], b"hex40"),
    (".git/refs/heads/main", "vcs", [], b"hex40"),
    (".svn/entries", "vcs", [b"svn"], None),
    (".svn/wc.db", "vcs", [b"sqlite", b"svn"], None),
    (".DS_Store", "vcs", [], MAGIC_DSSTORE),
    # environment / config files
    (".env", "env", ENV_MARKERS, None),
    (".env.local", "env", ENV_MARKERS, None),
    (".env.development", "env", ENV_MARKERS, None),
    (".env.production", "env", ENV_MARKERS, None),
    (".env.staging", "env", ENV_MARKERS, None),
    (".env.backup", "env", ENV_MARKERS, None),
    (".env.bak", "env", ENV_MARKERS, None),
    (".env.old", "env", ENV_MARKERS, None),
    ("env.txt", "env", ENV_MARKERS, None),
    (".htaccess", "config", [b"rewriterule", b"authtype"], None),
    (".htpasswd", "config", [b":$"], None),
    ("web.config", "config", [b"connectionstring", b"password"], None),
    ("WEB-INF/web.xml", "config", [b"<servlet", b"<param-value"], None),
    ("META-INF/context.xml", "config", [b"<context", b"password"], None),
    ("crossdomain.xml", "config", [b"allow-access-from"], None),
    ("clientaccesspolicy.xml", "config", [b"allow-from"], None),
    (".ssh/id_rsa", "config", [b"private key"], None),
    # editor droppings and backups
    ("index.php~", "backup", PHP_MARKERS, None),
    ("index.php.bak", "backup", PHP_MARKERS, None),
    ("index.php.old", "backup", PHP_MARKERS, None),
    ("index.php.orig", "backup", PHP_MARKERS, None),
    ("index.php.save", "backup", PHP_MARKERS, None),
    ("index.html.bak", "backup", [b"<html"], None),
    ("config.php.bak", "backup", PHP_MARKERS, None),
    ("Thumbs.db", "backup", [], MAGIC_ZIP),
    # server information pages
    ("server-status", "server-info",
     [b"apache server status", b"currently being processed"], None),
    ("server-status/", "server-info",
     [b"apache server status"], None),
    ("server-info", "server-info", [b"apache server information"], None),
    ("phpinfo.php", "server-info", [b"php version", b"phpinfo"], None),
    ("info.php", "server-info", [b"php version", b"phpinfo()"], None),
    ("test.php", "server-info", [b"php version"], None),
    ("debug", "server-info", [b"debug", b"toolbar"], None),
    ("trace.axd", "server-info", [b"trace", b"asp.net"], None),
    ("elmah.axd", "server-info", [b"elmah", b"error log"], None),
    # actuator / console
    ("actuator", "actuator", [b"_links"], None),
    ("actuator/health", "actuator", [b"status"], None),
    ("actuator/env", "actuator", [b"propertysources"], None),
    ("actuator/heapdump", "actuator", [], b"binary-any"),
    ("actuator/mappings", "actuator", [b"contexts"], None),
    ("console", "actuator", [b"websocket"], None),
    # dumps and archives
    ("backup.sql", "dump", SQL_MARKERS, None),
    ("dump.sql", "dump", SQL_MARKERS, None),
    ("db.sql", "dump", SQL_MARKERS, None),
    ("database.sql", "dump", SQL_MARKERS, None),
    ("database.sql.gz", "dump", [], MAGIC_GZIP),
    ("backup.sql.gz", "dump", [], MAGIC_GZIP),
    ("backup.zip", "dump", [], MAGIC_ZIP),
    ("backup.tar.gz", "dump", [], MAGIC_GZIP),
    ("site.zip", "dump", [], MAGIC_ZIP),
    ("www.zip", "dump", [], MAGIC_ZIP),
    # logs
    ("debug.log", "log", [b"traceback", b"exception"], None),
    ("error.log", "log", [b"error"], None),
    ("error_log", "log", [b"error"], None),
]

HEX_40 = "0123456789abcdef"


# ---------------------------------------------------------------- helpers


def _norm_port(scheme, port):
    defaults = {"http": 80, "https": 443}
    return defaults.get(scheme) if port is None else port


def same_origin(url_a, url_b):
    """True when scheme/host/port match (default ports normalized)."""
    a, b = urllib.parse.urlsplit(url_a), urllib.parse.urlsplit(url_b)
    if (a.scheme, a.hostname) != (b.scheme, b.hostname):
        return False
    return _norm_port(a.scheme, a.port) == _norm_port(b.scheme, b.port)


def build_url(base, path):
    """Join a relative path onto base; None when it escapes the origin."""
    if not path:
        return None
    raw = path.strip()
    if raw.startswith("//") or raw.startswith("\\\\") or "://" in raw \
            or raw.startswith("http:") or raw.startswith("https:"):
        return None  # escape attempt: protocol-relative / absolute URL
    url = urllib.parse.urljoin(base, "/" + raw.lstrip("/"))
    if not same_origin(base, url):
        return None
    return url


def marker_hits(body, markers, magic):
    """Return (text_markers_hit, magic_or_special_hit)."""
    hits = []
    if body:
        low = body.lower()
        for marker in markers:
            if marker in low:
                hits.append(marker.decode("latin-1"))
    special = ""
    if magic == b"hex40":
        head = body.strip()[:40].decode("latin-1", "replace").lower()
        if len(head) == 40 and all(c in HEX_40 for c in head):
            special = "git-sha1-ref"
    elif magic == b"binary-any":
        if body and b"\x00" in body[:4096]:
            special = "binary-body"
    elif magic:
        if magic in body[:16]:
            special = "magic:%s" % magic.decode("latin-1")
    return hits, special


def verdict_for(status, hits, special, soft404_hash, body_hash):
    """One-word triage per references/sensitive-files.md."""
    if status in (301, 302, 303, 307, 308):
        return "REDIRECT"
    if status == 403:
        return "403-TRIAGE (exists but ACL-protected; candidate for P5 verb/encoding checks)"
    if status == 404:
        return "absent"
    if status == 200:
        if body_hash == soft404_hash:
            return "SOFT-404 (identical body to base; treat as absent)"
        if hits or special:
            return "EXPOSED"
        return "200-nomarker (download and review manually before claiming)"
    return "status-%d (review manually)" % status


# ---------------------------------------------------------------- transport


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, timeout):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(262144)
    except urllib.error.HTTPError as err:
        return err.code, err.read(262144)


# ---------------------------------------------------------------- self-test


def _fake_getaddrinfo(host, port, *args, **kwargs):
    """Offline DNS stand-in: canned answers only, no network."""
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
        ok, why = host_allowed("http://127.0.0.1:8080/", loop_scope)
        assert ok is True, "listed loopback must be allowed, got %s" % why
    finally:
        socket.getaddrinfo = original

    # --- built-in path list sanity ---
    assert len(PATHS) >= 55, "built-in list shrunk: %d entries" % len(PATHS)
    for path, family, _markers, _magic in PATHS:
        assert not path.startswith("/"), "paths must be relative: %s" % path
        assert "://" not in path, "paths must not be absolute: %s" % path
        assert not path.startswith("//"), "protocol-relative: %s" % path
        assert "\\\\" not in path, "backslash paths: %s" % path
    families = {f for _p, f, _m, _g in PATHS}
    assert {"vcs", "env", "config", "backup", "server-info", "actuator",
            "dump", "log"} <= families, families

    # --- origin containment ---
    base = "http://target.example.com:8080/app/"
    assert build_url(base, ".git/config") == \
        "http://target.example.com:8080/.git/config"
    assert build_url(base, "a/b/../c") is not None  # normalizes in-origin
    assert build_url(base, "//evil.example/x") is None, \
        "protocol-relative path must be refused"
    assert build_url(base, "https://evil.example/x") is None, \
        "absolute URL must be refused"
    assert build_url(base, "///evil.example") is None
    assert same_origin("http://a.example/", "http://a.example:80/")
    assert not same_origin("http://a.example/", "https://a.example/")

    # --- marker matching ---
    hits, special = marker_hits(b"[core]\n\trepositoryformatversion = 0\n",
                                GIT_MARKERS, None)
    assert "core" in " ".join(hits) or hits, (hits, special)
    hits, _ = marker_hits(b"DB_PASSWORD=REDACTED\nAPP_KEY=REDACTED\n",
                          ENV_MARKERS, None)
    assert hits, hits
    hits, special = marker_hits(MAGIC_ZIP + b"junk", [], MAGIC_ZIP)
    assert special.startswith("magic:"), special
    hits, special = marker_hits(b"\x00\x00\x00\x01Bud1\x00", [],
                                MAGIC_DSSTORE)
    assert special, special
    hits, special = marker_hits(b"0f1e2d3c4b5a69788796a5b4c3d2e1f0a1b2c3d4\n",
                                [], b"hex40")
    assert special == "git-sha1-ref", special
    hits, special = marker_hits(b"<!doctype html><html>", [], None)
    assert not hits and not special

    # --- triage verdicts ---
    assert verdict_for(200, [b"db_"], "", None, "aa") .startswith("EXPOSED")
    assert verdict_for(200, [], "", "aa", "aa").startswith("SOFT-404")
    assert verdict_for(200, [], "", None, "bb").startswith("200-nomarker")
    assert verdict_for(403, [], "", None, "").startswith("403-TRIAGE")
    assert verdict_for(404, [], "", None, "") == "absent"
    assert verdict_for(302, [], "", None, "") == "REDIRECT"
    assert verdict_for(500, [], "", None, "").startswith("status-500")

    print("[self-test] exposure_probe: guard(3) + %d paths + origin/"
          "marker/triage fixtures passed" % len(PATHS))


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Built-in sensitive-path exposure probe (GET only).")
    parser.add_argument("--scope-file",
                        help="engagement scope JSON (or REDJOHN_SCOPE_FILE)")
    parser.add_argument("--target", help="base URL to probe under")
    parser.add_argument("--path", action="append", default=[],
                        help="extra relative path to probe (repeatable)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-request timeout seconds (default 10)")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="seconds between probes (default 0.2)")
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
    if not scope_file or not args.target:
        parser.error("--scope-file and --target are required")
    require_in_scope(args.target, scope_file)

    base = args.target if args.target.endswith("/") else args.target + "/"
    plan = list(PATHS) + [(p, "extra", ENV_MARKERS, None) for p in args.path]

    # base fetch doubles as the soft-404 reference
    try:
        base_status, base_body = fetch(base, args.timeout)
    except (urllib.error.URLError, OSError) as err:
        sys.stderr.write("[error] base fetch failed for %s: %s\n"
                         % (base, err))
        sys.exit(1)
    soft404 = hashlib.sha256(base_body).hexdigest()
    print("[base] %s -> %d len=%d soft404-ref=%s"
          % (base, base_status, len(base_body), soft404[:12]))

    exposed = 0
    for path, family, markers, magic in plan:
        url = build_url(base, path)
        if url is None:
            sys.stderr.write(
                "[scope-guard] refused path %r: resolves outside target "
                "origin; engagement rule = fail closed\n" % path)
            sys.exit(2)
        try:
            status, body = fetch(url, args.timeout)
        except (urllib.error.URLError, OSError) as err:
            print("[error] %-28s %s" % (path, err))
            continue
        hits, special = marker_hits(body, markers, magic)
        digest = hashlib.sha256(body).hexdigest()
        verdict = verdict_for(status, hits, special, soft404, digest)
        extra = ""
        if hits or special:
            extra = " markers=[%s]" % ",".join(hits + ([special] if special
                                                        else []))
        if verdict.startswith("EXPOSED"):
            exposed += 1
        print("[%-9s] %-28s status=%d len=%-7d %s%s"
              % (family, path, status, len(body), verdict, extra))
        time.sleep(args.delay)

    print("[summary] %d/%d probed, %d EXPOSED (capture each hit; re-fetch "
          "once for D2)" % (len(plan), len(plan), exposed))
    print("[evidence] save [EXPOSED] hits as "
          "evidence/p2-exposure-<host>-<slug>.{req,resp}.txt; 403 hits go to "
          "the P5 bypass-candidate list, not this passive phase")


if __name__ == "__main__":
    main()
