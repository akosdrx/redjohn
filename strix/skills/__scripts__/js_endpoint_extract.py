#!/usr/bin/env python3
# js_endpoint_extract.py - offline extraction from a client-side JavaScript file.
#
# Extracts URL paths, API endpoints, query parameter names and secret-looking
# NAMES (never values) from a local JS bundle. No network access, no scope
# guard needed (offline analysis).
#
# Exit codes: 0 success, 1 other errors (unreadable file, bad regex input).

import argparse
import os
import re
import sys
import tempfile

ASSET_EXTS = (
    ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".ttf",
    ".gif", ".ico", ".mp4", ".webm",
)

RE_API_CALL = re.compile(
    r"""(?x)
    (?: fetch
      | axios(?:\.(?:get|post|put|patch|delete))?
      | \$\.(?:get|post|put|delete|ajax))
    \s*\(\s*["'`]([^"'`\s]+)["'`]"""
)
RE_ABS_URL = re.compile(
    r"""https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s"'`<>{}]*)?"""
)
RE_QUOTED_PATH = re.compile(
    r"""["'`](/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%?]+/){1,6}"""
    r"""[A-Za-z0-9\-._~!$&'()*+,;=:@%?]*)["'`]"""
)
RE_QUERY_PARAM = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]*)=")
RE_SECRET_NAME = re.compile(
    r"""\b([A-Za-z_]*?(?:api[-_]?key|api[-_]?secret|secret[-_]?key|"""
    r"""access[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|"""
    r"""password|passwd)[A-Za-z0-9_]*)\b\s*[:=]""",
    re.IGNORECASE,
)
RE_SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def is_asset(path):
    lowered = path.lower().split("?")[0]
    return lowered.endswith(ASSET_EXTS)


def extract(text):
    """Return a dict of section -> sorted list of 'line:N\tvalue' strings."""
    sections = {
        "api_endpoints": [],
        "absolute_urls": [],
        "url_paths": [],
        "query_param_names": [],
        "secret_name_hits": [],
        "sourcemaps": [],
    }
    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in RE_API_CALL.findall(line):
            sections["api_endpoints"].append((lineno, match))
        for match in RE_ABS_URL.findall(line):
            sections["absolute_urls"].append((lineno, match))
        for match in RE_QUOTED_PATH.findall(line):
            if not is_asset(match):
                sections["url_paths"].append((lineno, match))
        for match in RE_QUERY_PARAM.findall(line):
            sections["query_param_names"].append((lineno, match))
        # Names only: group(1) is the identifier; the value is never captured.
        for match in RE_SECRET_NAME.findall(line):
            sections["secret_name_hits"].append((lineno, match))
        for match in RE_SOURCEMAP.findall(line):
            sections["sourcemaps"].append((lineno, match))
    return sections


def render(sections):
    out = []
    titles = {
        "api_endpoints": "API endpoints (call sites)",
        "absolute_urls": "Absolute URLs",
        "url_paths": "Quoted URL paths",
        "query_param_names": "Query parameter names",
        "secret_name_hits": "Secret-looking NAMES (values intentionally not extracted)",
        "sourcemaps": "Sourcemap references",
    }
    for key, title in titles.items():
        items = sections[key]
        out.append("== %s: %d ==" % (title, len(items)))
        seen = set()
        for lineno, value in items:
            marker = "" if value not in seen else " (dup)"
            seen.add(value)
            out.append("  line %d: %s%s" % (lineno, value, marker))
        out.append("")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Offline: extract endpoints, paths, query param names and "
        "secret-looking names from a local JavaScript file.",
    )
    ap.add_argument("--js-file", help="Path to a local .js file")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests with an embedded fixture and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.js_file:
        sys.stderr.write("error: --js-file is required\n")
        return 1
    if not os.path.isfile(args.js_file):
        sys.stderr.write("error: no such file: %s\n" % args.js_file)
        return 1
    try:
        with open(args.js_file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        sys.stderr.write("error: cannot read %s: %s\n" % (args.js_file, exc))
        return 1

    print(render(extract(text)))
    print("next: register endpoints/params in the P1 surface inventory "
          "(source=js:%s); probe candidates with param_miner.py; secret-name "
          "hits are leads for 50-config-baseline, values are never extracted."
          % os.path.basename(args.js_file))
    return 0


FIXTURE = '''// documentation-domain fixture bundle (example.com per RFC 2606)
const API_BASE = "https://api.example.com";
fetch("/api/v1/users?debug=1&lang=en")
  .then(function (r) { return r.json(); });
$.get("/api/v1/orders");
axios.post("https://api.example.com/v2/login", {user: "user-a@example.com"});
window.location.href = "/admin/export?format=csv";
var img = document.createElement("img");
img.src = "/static/logo.png";
var cfg = { apiKey: "SHOULD-NOT-APPEAR-1", client_secret: "SHOULD-NOT-APPEAR-2" };
function go() { window.open("/reports/pending/view?id=42", "_blank"); }
//# sourceMappingURL=app.min.js.map
'''


def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    with tempfile.NamedTemporaryFile(
            "w", suffix=".js", delete=False, encoding="utf-8") as fh:
        fh.write(FIXTURE)
        fixture_path = fh.name
    try:
        with open(fixture_path, "r", encoding="utf-8") as fh:
            sections = extract(fh.read())

        endpoints = {v for _, v in sections["api_endpoints"]}
        assert "/api/v1/users?debug=1&lang=en" in endpoints, endpoints
        assert "/api/v1/orders" in endpoints, endpoints
        assert "https://api.example.com/v2/login" in endpoints, endpoints
        ok("api call sites extracted (fetch/$.get/axios)")

        urls = {v for _, v in sections["absolute_urls"]}
        assert "https://api.example.com" in urls, urls
        ok("absolute URLs extracted")

        paths = {v for _, v in sections["url_paths"]}
        assert "/admin/export" in paths or "/admin/export?format=csv" in paths, paths
        assert "/reports/pending/view" in paths or \
            "/reports/pending/view?id=42" in paths, paths
        assert not any(p.startswith("/static/logo.png") for p in paths), paths
        ok("quoted paths extracted, asset paths filtered")

        params = {v for _, v in sections["query_param_names"]}
        assert {"debug", "lang", "format", "id"} <= params, params
        ok("query parameter names extracted")

        secrets = {v for _, v in sections["secret_name_hits"]}
        assert "apiKey" in secrets, secrets
        assert "client_secret" in secrets, secrets
        rendered = render(sections)
        assert "SHOULD-NOT-APPEAR-1" not in rendered
        assert "SHOULD-NOT-APPEAR-2" not in rendered
        ok("secret NAMES captured, values never emitted")

        maps = {v for _, v in sections["sourcemaps"]}
        assert maps == {"app.min.js.map"}, maps
        ok("sourcemap reference extracted")
    finally:
        os.unlink(fixture_path)

    print("[self-test] js_endpoint_extract: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
