#!/usr/bin/env python3
"""secdiff.py - offline security triage of unified diffs (patch-diff helper
for 75-zeroday-research).

Ranks diff hunks by the likelihood that they are a security fix, using the
heuristics from references/patch-diffing.md:

  1. security-keyword density in added/removed lines (strong: inject,
     overflow, bypass, sanitiz*, escap*, auth (NOT "author"), permission,
     CVE ids; weak: valid*, fix*, patch*);
  2. sink-adjacent changes (eval/exec/system/popen/subprocess/shell=True/
     innerHTML/document.write/deserialize/pickle.loads/yaml.load/memcpy/
     strcpy/sprintf/query in changed or neighboring context lines);
  3. test-file naming hits (test files naming a CVE/crash/regression
     confirm; plain test churn is cosmetic).

Output: ranked candidate hunks with CWE hypotheses. Candidates are LEADS,
not proof - a fix existing never proves the old behavior exploitable; see
references/patch-diffing.md for the version-discriminating PoC rules.

Offline: no network access, no scope guard (sends nothing). The CVE id in
the embedded self-test fixture is synthetic (CVE-2099-00001).

Usage:
  python3 secdiff.py --diff fix.patch
  python3 secdiff.py --dir evidence/patches/
  python3 secdiff.py --self-test

Exit codes: 0 = triage ran (candidates or none); 1 = bad arguments or
unreadable/empty input.
"""

import argparse
import glob
import os
import re
import sys
import tempfile

STRONG_KEYWORDS = [
    ("cve-id", re.compile(r"\bcve[-_\s]?\d{4}[-_]?\d{2,7}", re.I)),
    ("inject", re.compile(r"\binject", re.I)),
    ("overflow", re.compile(r"overflow", re.I)),
    ("bypass", re.compile(r"\bbypass", re.I)),
    ("sanitiz", re.compile(r"sanitiz", re.I)),
    ("escap", re.compile(r"escap", re.I)),
    ("auth", re.compile(r"\bauth(?!or)", re.I)),
    ("permission", re.compile(r"permission", re.I)),
]
WEAK_KEYWORDS = [
    ("valid", re.compile(r"\bvalid", re.I)),
    ("fix", re.compile(r"\bfix(es|ed|ing)?\b", re.I)),
    ("patch", re.compile(r"\bpatch", re.I)),
]
SINKS = ["eval(", "exec(", "system(", "popen", "subprocess", "shell=true",
         "innerhtml", "document.write", "dangerouslysetinnerhtml",
         "unescape(", "deserialize", "pickle.loads", "yaml.load",
         "readobject", "memcpy", "strcpy", "sprintf", "query"]
TEST_PATH_MARKERS = ("test", "spec")
REGRESSION_MARK = re.compile(r"cve|crash|regress|inject|overflow|exploit|"
                             r"security|sanitize", re.I)

CWE_MAP = [
    (re.compile(r"sql|\bquery\b", re.I), "CWE-89 (SQL injection)"),
    (re.compile(r"eval\(|exec\(|popen|subprocess|shell=true|system\(",
                re.I), "CWE-78 (OS command injection) or CWE-94 (code "
                       "injection) - sink decides"),
    (re.compile(r"innerhtml|document\.write|escap|html", re.I),
     "CWE-79 (XSS)"),
    (re.compile(r"overflow|memcpy|strcpy|sprintf", re.I),
     "CWE-120 (classic buffer overflow); CWE-787 if it is an OOB write"),
    (re.compile(r"\bauth(?!or)|permission|bypass", re.I),
     "CWE-862/863 (missing/incorrect authorization)"),
    (re.compile(r"deserialize|pickle\.loads|yaml\.load|readobject", re.I),
     "CWE-502 (deserialization)"),
    (re.compile(r"traversal|\.\./|filename|basename|realpath", re.I),
     "CWE-22 (path traversal)"),
    (re.compile(r"entity|\bxxe\b|external.*dtd", re.I), "CWE-611 (XXE)"),
    (re.compile(r"redirect", re.I), "CWE-601 (open redirect)"),
]


# ---------------------------------------------------------------- parsing


def _strip_path(raw):
    path = raw.split("\t")[0].strip()
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    return None if path == "/dev/null" else path


def parse_unified_diff(text):
    """-> list of hunk dicts {file, header, added, removed, context}.
    File headers are recognized ONLY as ---/+++ pairs (lookahead), so a
    removed line whose content begins '-- ' is not mistaken for a header."""
    hunks = []
    lines = text.splitlines()
    current_file = None
    cur = None

    def close():
        nonlocal cur
        if cur is not None:
            hunks.append(cur)
            cur = None

    i = 0
    while i < len(lines):
        line = lines[i]
        if (line.startswith("--- ")
                and i + 1 < len(lines) and lines[i + 1].startswith("+++ ")):
            close()
            a = _strip_path(line[4:])
            b = _strip_path(lines[i + 1][4:])
            current_file = b or a or current_file
            i += 2
            continue
        if line.startswith("diff ") or line.startswith("Index: "):
            close()
            current_file = None
            i += 1
            continue
        if line.startswith("@@"):
            close()
            cur = {"file": current_file or "<unknown>", "header": line,
                   "added": [], "removed": [], "context": []}
            i += 1
            continue
        if cur is not None:
            if line.startswith("+"):
                cur["added"].append(line[1:])
            elif line.startswith("-"):
                cur["removed"].append(line[1:])
            elif line.startswith(" "):
                cur["context"].append(line[1:])
            # '\\ No newline', 'index', 'mode' lines: ignored
        i += 1
    close()
    return hunks


# ---------------------------------------------------------------- scoring


def _count_hits(pattern, texts):
    total = 0
    for text in texts:
        total += len(pattern.findall(text))
    return total


def score_hunk(hunk):
    """-> (score, signals dict)."""
    changed = hunk["added"] + hunk["removed"]
    lowered = [line.lower() for line in changed]
    context_lower = [line.lower() for line in hunk["context"]]

    strong = {}
    for name, pattern in STRONG_KEYWORDS:
        hits = _count_hits(pattern, changed)
        if hits:
            strong[name] = hits
    weak = {}
    for name, pattern in WEAK_KEYWORDS:
        hits = _count_hits(pattern, changed)
        if hits:
            weak[name] = hits

    sinks_changed = sorted({s for s in SINKS
                            if any(s in low for low in lowered)})
    sinks_context = sorted({s for s in SINKS
                            if any(s in low for low in context_lower)}
                           - set(sinks_changed))[:3]

    path_lower = hunk["file"].lower()
    is_test = any(marker in path_lower for marker in TEST_PATH_MARKERS)
    regression = False
    if is_test:
        blob = hunk["file"] + "\n" + "\n".join(changed)
        regression = bool(REGRESSION_MARK.search(blob))

    score = (3 * min(sum(strong.values()), 9)
             + 1 * min(sum(weak.values()), 6)
             + 4 * len(sinks_changed)
             + 2 * len(sinks_context)
             + (4 if regression else 0))
    signals = {"strong": strong, "weak": weak, "sinks_changed": sinks_changed,
               "sinks_context": sinks_context, "is_test": is_test,
               "regression": regression}
    return score, signals


def cwe_hypotheses(signals):
    blob_parts = []
    blob_parts.extend(signals["strong"].keys())
    blob_parts.extend(signals["sinks_changed"])
    blob = " ".join(blob_parts)
    hyps = []
    for pattern, cwe in CWE_MAP:
        if pattern.search(blob):
            hyps.append(cwe)
    if not hyps:
        hyps.append("no hypothesis - map manually via "
                    "70-exploit-intel/references/cwe-mapping.md")
    return hyps[:4]


def verdict(score):
    if score >= 8:
        return "security-fix-candidate"
    if score >= 4:
        return "review"
    return "likely-cosmetic"


def triage(hunks, source=""):
    scored = []
    for hunk in hunks:
        score, signals = score_hunk(hunk)
        scored.append((score, hunk, signals))
    scored.sort(key=lambda row: row[0], reverse=True)
    out = []
    out.append("== secdiff triage%s: %d hunk(s) ==" %
               (" (%s)" % source if source else "", len(hunks)))
    candidates = 0
    rank = 0
    for score, hunk, signals in scored:
        v = verdict(score)
        if v == "likely-cosmetic":
            continue
        rank += 1
        candidates += 1
        preview = next((line.strip() for line in hunk["added"] + hunk["removed"]
                        if line.strip()), "")
        out.append("[#%d %s] score=%d %s:%s" %
                   (rank, v, score, hunk["file"], hunk["header"]))
        out.append("    strong-keywords: %s" % (signals["strong"] or "-"))
        out.append("    weak-keywords: %s" % (signals["weak"] or "-"))
        out.append("    sinks-changed: %s | sinks-nearby: %s" %
                   (",".join(signals["sinks_changed"]) or "-",
                    ",".join(signals["sinks_context"]) or "-"))
        if signals["is_test"]:
            out.append("    test-file: %s" %
                       ("regression-test naming confirms" if
                        signals["regression"] else "test-only churn"))
        for hyp in cwe_hypotheses(signals):
            out.append("    cwe-hypothesis: %s" % hyp)
        out.append("    changed-line: %s" % (preview[:100] or "-"))
    cosmetic = [row for row in scored if verdict(row[0]) == "likely-cosmetic"]
    if cosmetic:
        out.append("-- likely-cosmetic (%d, deprioritized): %s" %
                   (len(cosmetic), "; ".join("%s:%s (%d)" %
                    (row[1]["file"], row[1]["header"], row[0])
                    for row in cosmetic)))
    if not candidates:
        out.append("no candidate hunks (all cosmetic/no signal).")
    out.append("--")
    out.append("candidates are LEADS, not proof: a fix existing never proves")
    out.append("the old behavior exploitable. Write a version-discriminating")
    out.append("PoC (references/patch-diffing.md section 3) before any claim.")
    out.append("evidence expectation: save the .patch next to this triage")
    out.append("output as evidence/p8-diff-<component>-<seq>.*")
    return "\n".join(out) + "\n", scored


# ---------------------------------------------------------------- fixtures

SECURITY_FIXTURE = """\
--- a/widget/multipart.py
+++ b/widget/multipart.py
@@ -120,9 +120,11 @@ def parse_upload(request):
-    filename = headers.get("filename", "")
-    compiled = eval("clean_name(%r)" % filename)
-    return db.query("INSERT INTO uploads VALUES ('%s')" % compiled)
+    filename = headers.get("filename", "")
+    if not validators.sanitize_filename(filename):
+        raise UploadRejected("invalid filename")
+    return db.query("INSERT INTO uploads VALUES (?)", compiled_safe(filename))
@@ -200,6 +202,7 @@ def handler(req):
     ctx = build_context(req)
+    # escape user data before it reaches the error page template
     page = render_error(ctx.user_text | escape_html)
--- a/tests/test_multipart.py
+++ b/tests/test_multipart.py
@@ -0,0 +1,5 @@
+def test_upload_rejected_cve_regression():
+    # regression test for CVE-2099-00001 (synthetic fixture id)
+    with pytest.raises(UploadRejected):
+        parse_upload(fake_request(filename="../../etc/passwd"))
"""

COSMETIC_FIXTURE = """\
--- a/README.md
+++ b/README.md
@@ -1,4 +1,4 @@
-ExampleWidget 2.3.0
+ExampleWidget 2.3.1
 
-Authors: see the author list page.
+Authors: see the authors page (update the author list).
\\ No newline at end of file
"""

TRICKY_FIXTURE = """\
--- a/app/core.py
+++ b/app/core.py
@@ -30,4 +30,4 @@ def render(block):
--- separator line kept for context
-legacy marker
+modern marker
 unchanged tail
"""


# ---------------------------------------------------------------- self-test


def self_test():
    # security fixture: candidates, sinks, regression naming, CWE hypotheses
    hunks = parse_unified_diff(SECURITY_FIXTURE)
    assert len(hunks) == 3, "expected 3 hunks, got %d" % len(hunks)
    text, scored = triage(hunks, "fixture-security")
    top_score, top_hunk, top_signals = scored[0]
    assert verdict(top_score) == "security-fix-candidate", top_score
    assert top_score >= 8, "security fixture scored only %d" % top_score
    assert "eval(" in top_signals["sinks_changed"]
    assert top_signals["strong"], "strong keywords missing"
    test_rows = [row for row in scored if row[2]["is_test"]]
    assert test_rows and test_rows[0][2]["regression"], \
        "regression-test naming not detected"
    hyps = cwe_hypotheses(top_signals)
    assert hyps and any("CWE-94" in h or "CWE-78" in h for h in hyps), hyps
    assert "security-fix-candidate" in text
    assert "regression-test naming confirms" in text

    # cosmetic fixture: no candidates; "author" must NOT count as auth
    cos_hunks = parse_unified_diff(COSMETIC_FIXTURE)
    assert len(cos_hunks) == 1
    cos_score, cos_signals = score_hunk(cos_hunks[0])
    assert "auth" not in cos_signals["strong"], \
        "author false-positive leaked into the auth keyword"
    assert cos_score <= 3, "cosmetic fixture scored %d" % cos_score
    cos_text, cos_scored = triage(cos_hunks, "fixture-cosmetic")
    assert "no candidate hunks" in cos_text
    assert scored[0][0] > cos_scored[0][0], "ranking order broken"

    # tricky fixture: a removed line whose content starts '-- ' renders as
    # '--- ' raw but is NOT a file header (next line is not '+++'); the
    # '\\ No newline' marker is ignored
    tr_hunks = parse_unified_diff(TRICKY_FIXTURE)
    assert len(tr_hunks) == 1, "header lookahead broke: %d hunks" % len(tr_hunks)
    assert tr_hunks[0]["removed"] == ["-- separator line kept for context",
                                      "legacy marker"], tr_hunks[0]["removed"]
    assert tr_hunks[0]["added"] == ["modern marker"]
    assert tr_hunks[0]["context"] == ["unchanged tail"]

    # --dir mode round-trips through temp files
    with tempfile.TemporaryDirectory() as tmp:
        for name, blob in (("security.patch", SECURITY_FIXTURE),
                           ("cosmetic.patch", COSMETIC_FIXTURE)):
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write(blob)
        paths = sorted(glob.glob(os.path.join(tmp, "*.patch")))
        assert len(paths) == 2
        combined = []
        for path in paths:
            with open(path, "r", encoding="utf-8") as fh:
                combined.extend(parse_unified_diff(fh.read()))
        assert len(combined) == 4
        dir_text, dir_scored = triage(combined, tmp)
        assert dir_scored[0][0] >= 8 and "security-fix-candidate" in dir_text

    print("[self-test] secdiff: security fixture -> candidate (score %d) "
          "with sinks/regression naming/CWE hypotheses, cosmetic fixture -> "
          "likely-cosmetic (author/auth guard held, score %d), header "
          "lookahead + no-newline handling and --dir mode passed"
          % (top_score, cos_score))


# --------------------------------------------------------------------- cli


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("error: %s\n" % message)
        sys.exit(1)


def main():
    parser = _Parser(
        description="Offline security triage of unified diffs "
                    "(patch-diff hunk ranking with CWE hypotheses).")
    parser.add_argument("--diff", help="path to a unified diff file")
    parser.add_argument("--dir",
                        help="directory containing .patch/.diff files")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-test (embedded fixtures)")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return
    if bool(args.diff) == bool(args.dir):
        parser.error("give exactly one of --diff FILE or --dir DIR")

    paths = ([args.diff] if args.diff
             else sorted(glob.glob(os.path.join(args.dir, "*.patch"))
                         + glob.glob(os.path.join(args.dir, "*.diff"))))
    if not paths:
        sys.stderr.write("[error] no diff files found\n")
        sys.exit(1)

    hunks = []
    label = args.diff if args.diff else "%s (%d files)" % (args.dir,
                                                           len(paths))
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                hunks.extend(parse_unified_diff(fh.read()))
        except OSError as exc:
            sys.stderr.write("[error] cannot read %s: %s\n" % (path, exc))
            sys.exit(1)
    if not hunks:
        sys.stderr.write("[error] %s: no unified-diff hunks parsed\n" % label)
        sys.exit(1)

    text, _scored = triage(hunks, label)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
