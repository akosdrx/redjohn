#!/usr/bin/env python3
"""postmessage_scan.py - offline postMessage listener/sender triage.

Scans a saved JavaScript file (no network) for:
  - addEventListener('message', ...) / onmessage = handlers, flagging those
    with no origin comparison in the following LOOKAHEAD lines;
  - .postMessage(...) senders, extracting the targetOrigin literal
    ('*' vs explicit origin vs unresolved variable).

Findings print with line numbers and a snippet; verdicts:
LISTENER-NO-ORIGIN-CHECK / LISTENER-OK / SENDER-STAR / SENDER-EXPLICIT /
SENDER-UNRESOLVED.

Usage:
  python3 postmessage_scan.py --js-file bundle.js
  python3 postmessage_scan.py --self-test

Exit codes: 0 = scan completed (hits or not); 1 = bad args / unreadable
file / no findings (see note: exit 0 only when at least one listener or
sender was scanned; a file with none exits 1 with a note).

Offline tool: no scope guard needed; the file is already-captured evidence.
Evidence expectation: annotate the JS excerpt (file + line numbers) into
evidence/p6-postmessage-<surface>.txt for the harness-building step.
"""

import argparse
import os
import re
import sys

LOOKAHEAD = 25  # lines examined after a listener registration

LISTENER_RE = re.compile(
    r"""(?:
        addEventListener\s*\(\s*['"]message['"]\s*,
        | onmessage\s*=\s*function
        | onmessage\s*=\s*\(
    )""", re.X)

SENDER_RE = re.compile(r"\.postMessage\s*\(")

ORIGIN_CHECK_RE = re.compile(
    r"""(?: \w+\.origin
        | allowedorigins?|trustedorigins?|originallow
        | whitelist|allowlist
    )""", re.X | re.I)

def _extract_target_origin(text_from_call):
    """Given text starting right after `.postMessage(`, return the second
    top-level argument string (or '' if absent/unterminated)."""
    depth = 0
    in_str = None
    escaped = False
    arg_idx = 0
    second_chars = []
    for ch in text_from_call:
        if escaped:
            if arg_idx == 1:
                second_chars.append(ch)
            escaped = False
            continue
        if in_str:
            if ch == "\\":
                escaped = True
                if arg_idx == 1:
                    second_chars.append(ch)
                continue
            if ch == in_str:
                in_str = None
            if arg_idx == 1:
                second_chars.append(ch)
            continue
        if ch in ("'", '"', "`"):
            in_str = ch
            if arg_idx == 1:
                second_chars.append(ch)
            continue
        if ch in ("(", "[", "{"):
            depth += 1
            if arg_idx == 1:
                second_chars.append(ch)
            continue
        if ch in (")", "]", "}"):
            if depth == 0 and ch == ")":
                break
            if depth > 0:
                depth -= 1
            if arg_idx == 1:
                second_chars.append(ch)
            continue
        if ch == "," and depth == 0:
            arg_idx += 1
            if arg_idx > 1:
                break
            continue
        if arg_idx == 1:
            second_chars.append(ch)
    return "".join(second_chars).strip()


def _window(lines, start, count):
    return " ".join(lines[start:start + count])


def scan_lines(text):
    """Return (findings, total_listeners, total_senders).

    findings: (lineno, kind, detail, snippet) tuples. The listener check
    window ends at the next listener registration so adjacent handlers do
    not bleed their origin checks into each other.
    """
    lines = text.splitlines()
    listener_indexes = [i for i, ln in enumerate(lines)
                        if LISTENER_RE.search(ln)]
    findings = []
    listeners = 0
    senders = 0
    for i, line in enumerate(lines):
        if LISTENER_RE.search(line):
            listeners += 1
            bounds = [i + LOOKAHEAD]
            for j in listener_indexes:
                if i < j < bounds[0]:
                    bounds[0] = j
            window = _window(lines, i, bounds[0] - i)
            has_check = bool(ORIGIN_CHECK_RE.search(window))
            kind = "LISTENER-OK" if has_check else "LISTENER-NO-ORIGIN-CHECK"
            detail = ("origin comparison observed in the handler window"
                      if has_check else
                      "no origin comparison in the handler window - verify "
                      "event.data flow into sinks manually")
            findings.append((i + 1, kind, detail, line.strip()))
        sm = SENDER_RE.search(line)
        if sm:
            senders += 1
            tail = "\n".join(lines[i:i + 5])[sm.end():]
            target_origin = _extract_target_origin(tail)
            if (len(target_origin) >= 2
                    and target_origin[0] in ("'", '"', "`")
                    and target_origin[-1] == target_origin[0]
                    and target_origin[1:-1] == "*"):
                kind, detail = "SENDER-STAR", \
                    "postMessage(..., '*') broadcasts to any embedder"
            elif (len(target_origin) >= 2
                  and target_origin[0] in ("'", '"', "`")
                  and target_origin[-1] == target_origin[0]):
                kind = "SENDER-EXPLICIT"
                detail = "postMessage targetOrigin=%s" % target_origin
            else:
                kind = "SENDER-UNRESOLVED"
                detail = ("postMessage targetOrigin is a variable/absent - "
                          "resolve manually: %s" % (line.strip()[:80]))
            findings.append((i + 1, kind, detail, line.strip()))
    return findings, listeners, senders


# ---------------------------------------------------------------- self-test

FIXTURE_JS = """\
// bundle fixture
window.addEventListener('message', function (e) {
  document.getElementById('out').innerHTML = e.data.html;
});
window.addEventListener('message', function (e) {
  if (e.origin !== 'https://target.example.com') return;
  console.log(e.data);
});
window.onmessage = function (ev) {
  location.href = ev.data.url;
};
child.postMessage({token: 'redacted'}, '*');
parent.postMessage({hello: 1}, 'https://target.example.com');
relay.postMessage(payload, targetOriginVar);
"""


def self_test():
    findings, listeners, senders = scan_lines(FIXTURE_JS)
    kinds = [f[1] for f in findings]
    assert listeners == 3, listeners
    assert senders == 3, senders
    assert kinds.count("LISTENER-NO-ORIGIN-CHECK") == 2, kinds
    assert kinds.count("LISTENER-OK") == 1, kinds
    assert kinds.count("SENDER-STAR") == 1, kinds
    assert kinds.count("SENDER-EXPLICIT") == 1, kinds
    assert kinds.count("SENDER-UNRESOLVED") == 1, kinds
    # line numbers are reported
    linenos = [f[0] for f in findings]
    assert len(linenos) == len(set(linenos)), "one finding per line expected"

    # order: first finding is the unsafe listener near the top
    assert findings[0][1] == "LISTENER-NO-ORIGIN-CHECK"

    # empty / clean files
    findings2, l2, s2 = scan_lines("var x = 1;\nconsole.log('no pm');\n")
    assert (findings2, l2, s2) == ([], 0, 0)

    # origin check written with a local variable named allowedOrigins counts
    guarded = ("window.addEventListener('message', function (e) {\n"
               "  if (!allowedOrigins.includes(e.origin)) return;\n"
               "  apply(e.data);\n"
               "});\n")
    _f, gl, _s = scan_lines(guarded)
    assert gl == 1
    kinds = [f[1] for f in _f]
    assert kinds == ["LISTENER-OK"], kinds

    # string-quote variants both match
    dq = 'addEventListener("message", h);\n'
    _f, dql, _s = scan_lines(dq)
    assert dql == 1, "double-quoted registration must be found"
    kinds = [f[1] for f in _f]
    assert kinds == ["LISTENER-NO-ORIGIN-CHECK"], kinds

    # multi-key object literal and '*' inside payload must not confuse targetOrigin
    complex_senders = (
        "win.postMessage({ a: 1, b: 2 }, 'https://target.example.com');\n"
        "win.postMessage({ role: '*' }, 'https://target.example.com');\n"
        "win.postMessage({ a: 1, b: 2 }, '*');\n"
    )
    cf, _cl, cs = scan_lines(complex_senders)
    assert cs == 3 and [f[1] for f in cf] == [
        "SENDER-EXPLICIT", "SENDER-EXPLICIT", "SENDER-STAR"
    ], cf

    print("[self-test] postmessage_scan: %d findings from fixture "
          "(listeners %d, senders %d) + guard/clean/quote fixtures passed"
          % (len(findings), listeners, senders))


# ---------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(description="Offline postMessage listener/sender scan.")
    parser.add_argument("--js-file", help="saved JavaScript file to scan")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (fixtures) and exit")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if not args.js_file:
        parser.error("--js-file is required")
    if not os.path.isfile(args.js_file):
        sys.stderr.write("[error] no such file: %s\n" % args.js_file)
        sys.exit(1)
    with open(args.js_file, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    findings, listeners, senders = scan_lines(text)
    print("[scan] %s: %d listener(s), %d sender(s)"
          % (args.js_file, listeners, senders))
    if not findings:
        sys.stderr.write("[note] no postMessage listeners/senders found; "
                         "nothing to audit in this file\n")
        sys.exit(1)
    for lineno, kind, detail, snippet in findings:
        print("[line %-4d] %-24s %s" % (lineno, kind, detail))
        print("           | %s" % snippet[:120])
    flagged = sum(1 for f in findings if f[1] == "LISTENER-NO-ORIGIN-CHECK")
    starred = sum(1 for f in findings if f[1] == "SENDER-STAR")
    print("[summary] %d listener(s) without origin checks, %d '*' sender(s)"
          % (flagged, starred))
    print("[next] extract each flagged handler, map event.data into sinks "
          "(innerHTML/eval/src/location), build the harness page from "
          "references/postmessage-audit.md and verify under agent_browser")
    print("[evidence] annotate the JS excerpt (file + line numbers) as "
          "evidence/p6-postmessage-<surface>.txt")


if __name__ == "__main__":
    main()
