#!/usr/bin/env python3
# workflow_scan.py - OFFLINE GitHub Actions workflow injection scanner.
#
# No network access whatsoever. Regex-based triage of .github/workflows YAML
# (or any provided workflow files) for:
#   - pull_request_target usage (fork-reachable context)
#   - PR-head checkout in the same job (classic injection triad, incl.
#     make/npm/go/pytest-style execution of PR-controlled files)
#   - run: blocks interpolating user-controlled github.event.* fields /
#     github.head_ref (script injection)
#   - secrets.* referenced in fork-reachable jobs (name only, never value)
#   - floating action tags (not full-SHA pinned), missing permissions block
#
# Regexes find CANDIDATES: confirm each finding by reading the full job
# context (guards like if:, reusable-workflow indirection and composite
# actions are out of regex reach).
#
# Exit codes: 0 scan completed (findings are output, not an error),
# 1 other errors (no path given, nothing readable found).

import argparse
import os
import re
import sys

# --- detection regexes (mirrored in references/cicd-injection-patterns.md) ---

RE_ON_KEY = re.compile(r"^\s*(?:\"on\"|'on'|on)\s*:\s*(.*)$")
RE_JOBS_KEY = re.compile(r"^jobs\s*:\s*$")
RE_PULL_REQUEST_TARGET = re.compile(r"\bpull_request_target\b")
RE_WORKFLOW_RUN = re.compile(r"\bworkflow_run\b")
RE_PR_HEAD_CHECKOUT = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)"
    r"|ref:\s*['\"]?refs/pull/")
RE_EVENT_INTERP = re.compile(
    r"\$\{\{\s*(github\.event\.[A-Za-z0-9_.\[\]\"]*?|github\.head_ref)"
    r"\s*\}\}")
RE_SECRETS_REF = re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)")
RE_ACTION_REF = re.compile(r"uses:\s*([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)@(\S+)")
RE_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
RE_RUN_KEY = re.compile(r"^(\s*)(?:-\s+)?run\s*:\s*(.*)$")

# User-controlled github.event.* field prefixes (script injection sources).
USER_CONTROLLED_PREFIXES = (
    "pull_request.title", "pull_request.body",
    "pull_request.head.ref", "pull_request.head.label",
    "pull_request.head.repo",
    "issue.title", "issue.body", "issues.title", "issues.body",
    "comment.body", "comments.body",
    "review.body", "review_comment.body",
    "discussion.title", "discussion.body",
    "commits", "head_commit",  # commit message / author metadata
)

# Build tooling whose invocation reads PR-controlled workspace files.
PR_CONTROLLED_COMMANDS = frozenset((
    "make", "npm", "yarn", "pnpm", "bun", "npx", "go", "cargo", "pip",
    "python", "python3", "pytest", "bash", "sh", "mvn", "gradlew",
    "./gradlew", "rake", "composer", "dotnet",
))

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def strip_comment(line):
    """Cut a YAML comment: first '#' at line start or preceded by
    whitespace. Conservative (keeps '#' inside values)."""
    for idx, ch in enumerate(line):
        if ch == "#" and (idx == 0 or line[idx - 1] in " \t"):
            return line[:idx].rstrip()
    return line.rstrip()


def parse_trigger_tokens(text):
    text = text.replace("[", " ").replace("]", " ").replace(",", " ")
    toks = set()
    for tok in text.split():
        tok = tok.strip("\"'-:").strip()
        if tok:
            toks.add(tok)
    return toks


def extract_triggers(lines):
    """Return (trigger_name_set) from the on: section of a workflow."""
    triggers = set()
    in_on = False
    for _lineno, raw in lines:
        stripped = strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip())
        if not in_on:
            m = RE_ON_KEY.match(stripped)
            if m and indent == 0:
                rest = m.group(1).strip()
                if rest:  # inline form: on: push | on: [push, pull_request]
                    triggers |= parse_trigger_tokens(rest)
                    return triggers
                in_on = True
            continue
        if indent == 0:  # next top-level key ends the on: block
            break
        triggers |= parse_trigger_tokens(stripped.lstrip())
    return triggers


def split_jobs(lines):
    """Split the jobs: section into (job_name, [(lineno, raw), ...])."""
    jobs = []
    in_jobs = False
    jobs_indent = None
    current = None
    for lineno, raw in lines:
        stripped = strip_comment(raw)
        if not stripped.strip():
            if current is not None:
                current[1].append((lineno, raw))
            continue
        indent = len(stripped) - len(stripped.lstrip())
        if not in_jobs:
            if indent == 0 and RE_JOBS_KEY.match(stripped):
                in_jobs = True
            continue
        if indent == 0:  # left the jobs: section
            break
        header = re.match(r"^([A-Za-z0-9_.\-\"']+):\s*(#.*)?$",
                          stripped.strip())
        if header and (jobs_indent is None or indent == jobs_indent):
            jobs_indent = indent
            current = (header.group(1).strip("\"'"), [])
            jobs.append(current)
        elif current is not None:
            current[1].append((lineno, raw))
    return jobs


def iter_run_blocks(job_lines):
    """Yield run: blocks as [(lineno, content), ...]. Block-scalar
    continuation lines are the lines more-indented than the run: key."""
    i, n = 0, len(job_lines)
    while i < n:
        _lineno, raw = job_lines[i]
        stripped = strip_comment(raw)
        m = RE_RUN_KEY.match(stripped)
        if m:
            key_indent = len(m.group(1))
            block = [(_lineno, m.group(2).strip())]
            j = i + 1
            while j < n:
                lno2, raw2 = job_lines[j]
                st2 = strip_comment(raw2)
                if not st2.strip():
                    j += 1
                    continue
                ind2 = len(st2) - len(st2.lstrip())
                if ind2 > key_indent:
                    block.append((lno2, st2.strip()))
                    j += 1
                else:
                    break
            yield block
            i = j
        else:
            i += 1


def is_user_controlled(field):
    if field == "github.head_ref":
        return True
    if not field.startswith("github.event."):
        return False
    path = field[len("github.event."):]
    for prefix in USER_CONTROLLED_PREFIXES:
        if path == prefix or path.startswith(prefix + ".") \
                or path.startswith(prefix + "["):
            return True
    return False


def analyze_workflow(fname, text):
    """Return a list of finding dicts for one workflow file."""
    findings = []

    def add(severity, code, lineno, snippet, note):
        findings.append({"severity": severity, "code": code,
                         "file": fname, "line": lineno,
                         "snippet": snippet, "note": note})

    lines = list(enumerate(text.splitlines(), start=1))
    triggers = extract_triggers(lines)
    has_ptr = "pull_request_target" in triggers
    has_permissions = any(
        re.match(r"^permissions\s*:\s*$", strip_comment(raw))
        for _lno, raw in lines)

    if has_ptr:
        add("MEDIUM", "fork-context-trigger", 0,
            "on: pull_request_target",
            "jobs below run with base-repo context/secrets on fork PRs; "
            "review every job for the injection triad "
            "(references/cicd-injection-patterns.md); running PR code "
            "belongs under pull_request, not pull_request_target")
        if not has_permissions:
            add("INFO", "no-permissions-block", 0, "(permissions absent)",
                "no explicit permissions: block - workflow uses default "
                "token permissions; add a least-privilege permissions block")
    if "workflow_run" in triggers:
        add("INFO", "workflow-run-chain", 0, "on: workflow_run",
            "workflow_run chains see PR-triggered artifacts/events; check "
            "what this workflow consumes from the triggering workflow")

    for job_name, job_lines in split_jobs(lines):
        where = "job '%s'" % job_name

        pr_head = None
        for lno, raw in job_lines:
            st = strip_comment(raw)
            if RE_PR_HEAD_CHECKOUT.search(st):
                pr_head = (lno, st.strip())
                break

        pr_controlled_run = []
        injections = []
        for block in iter_run_blocks(job_lines):
            for lno, content in block:
                for m in RE_EVENT_INTERP.finditer(content):
                    injections.append((lno, m.group(1), content))
                first = content.split()[0] if content.split() else ""
                if first in PR_CONTROLLED_COMMANDS:
                    pr_controlled_run.append((lno, first, content))

        if pr_head and has_ptr:
            if pr_controlled_run:
                lno, cmd, content = pr_controlled_run[0]
                add("CRITICAL", "injection-triad", lno, content,
                    "%s: pull_request_target + PR-head checkout (line %d) "
                    "+ '%s' executes PR-controlled build files with "
                    "base-repo secrets - CWE-78-class script injection in "
                    "CI context" % (where, pr_head[0], cmd))
            else:
                add("HIGH", "pr-head-checkout", pr_head[0], pr_head[1],
                    "%s: checks out the FORK commit under "
                    "pull_request_target - any later step reading workspace "
                    "files executes fork code with base context" % where)

        for lno, field, content in injections:
            if is_user_controlled(field):
                add("HIGH", "script-injection", lno, content,
                    "%s: user-controlled ${{ %s }} interpolated into run: - "
                    "payload in the PR/issue/branch/commit text reaches the "
                    "shell verbatim (backticks/$(...)); use env indirection "
                    "and quote - CWE-78-class" % (where, field))
            else:
                add("LOW", "run-interpolation", lno, content,
                    "%s: ${{ %s }} interpolated into run: - prefer env "
                    "indirection; confirm the field is not attacker-"
                    "influenced" % (where, field))

        for lno, raw in job_lines:
            st = strip_comment(raw)
            m = RE_SECRETS_REF.search(st)
            if m and has_ptr:
                add("HIGH", "secrets-fork-reachable", lno, st.strip(),
                    "%s references secrets.%s in a pull_request_target "
                    "workflow - exposed to fork authors via the triad "
                    "(record the NAME only, never the value)"
                    % (where, m.group(1)))
                break  # one row per job is enough to prompt review

        for lno, raw in job_lines:
            st = strip_comment(raw)
            m = RE_ACTION_REF.search(st)
            if m and not RE_FULL_SHA.match(m.group(2)):
                add("LOW", "unpinned-action", lno, st.strip(),
                    "action %s@%s not pinned to a full commit SHA - tag is "
                    "mutable" % (m.group(1), m.group(2)))

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]),
                                 f["line"]))
    return findings


def render_findings(findings):
    out = []
    for f in findings:
        loc = "%s:%s" % (f["file"], f["line"] if f["line"] else "-")
        snippet = f["snippet"][:100]
        out.append("[%s] %s %s\n    %s\n    %s"
                   % (f["severity"], f["code"], loc, snippet, f["note"]))
    if not out:
        out.append("no findings (regex triage clean - still review job "
                   "context manually per the reference)")
    return "\n".join(out)


def scan_path(path):
    """Collect workflow files for a file-or-dir path; analyze each."""
    files = []
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for name in sorted(names):
                if name.endswith((".yml", ".yaml")):
                    files.append(os.path.join(root, name))
    else:
        sys.stderr.write("error: no such path: %s\n" % path)
        return None, 1
    if not files:
        sys.stderr.write("error: no .yml/.yaml files under %s\n" % path)
        return None, 1

    all_findings = []
    read_ok = 0
    for fpath in sorted(files):
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            sys.stderr.write("error: cannot read %s: %s\n" % (fpath, exc))
            continue
        read_ok += 1
        all_findings.extend(analyze_workflow(fpath, text))
    if read_ok == 0:
        return None, 1
    return all_findings, 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="OFFLINE: regex-triage GitHub Actions workflow files "
        "for pull_request_target injection triads, run: script injection, "
        "fork-reachable secrets and unpinned actions. No network access.",
    )
    ap.add_argument("--path", help="Workflow file or directory of "
                    ".github/workflows YAML")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests with embedded fixtures "
                    "(vulnerable + clean) and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.path:
        sys.stderr.write("error: --path is required\n")
        return 1

    findings, code = scan_path(args.path)
    if code != 0:
        return code

    print(render_findings(findings))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join("%s=%d" % (sev, counts[sev])
                        for sev in SEVERITY_ORDER if sev in counts)
    print("[scan] %d finding(s)%s" % (len(findings),
                                      " (%s)" % summary if summary else ""))
    print("evidence: cite file:line + verbatim snippet per finding; "
          "confirm trigger context manually (regexes cannot see if: guards "
          "or reusable-workflow indirection); record secret NAMES only.")
    return 0


# ---------------------------------------------------------------------------
# Self-test (offline; documentation fixtures only: example-org/example-repo)
# ---------------------------------------------------------------------------

FIXTURE_VULNERABLE = """\
name: CI
on:
  pull_request_target:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: example-org/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Build and test the PR
        run: make test
      - name: Report
        run: |
          echo "Testing ${{ github.event.pull_request.title }}"
          echo "branch: ${{ github.head_ref }}"
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
"""

FIXTURE_CLEAN = """\
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: example-org/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          persist-credentials: false
      - name: Test trusted code
        run: make test
"""

FIXTURE_INTERP_ONLY = """\
name: triage
on:
  issues:
    types: [opened]
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - run: echo "issue: ${{ github.event.issue.title }}"
"""


def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    import tempfile

    # --- pure helpers ---
    assert parse_trigger_tokens("[push, pull_request_target]") == \
        {"push", "pull_request_target"}
    assert parse_trigger_tokens("- pull_request_target:") == \
        {"pull_request_target"}
    ok("trigger token parsing (inline list + block list item)")

    lines = list(enumerate(FIXTURE_VULNERABLE.splitlines(), 1))
    triggers = extract_triggers(lines)
    assert "pull_request_target" in triggers, triggers
    assert extract_triggers(list(enumerate(
        "on: [push, workflow_dispatch]\njobs:\n  a:\n".splitlines(), 1)))
    ok("on: section extracted (block and inline forms)")

    assert strip_comment("  run: echo hi # comment") == "  run: echo hi"
    assert strip_comment("  url: http://example.com/#frag") == \
        "  url: http://example.com/#frag"
    ok("comment stripping keeps '#' inside values")

    jobs = split_jobs(lines)
    assert [name for name, _ in jobs] == ["test"], jobs
    job_lines = jobs[0][1]
    blocks = list(iter_run_blocks(job_lines))
    flat = [c for block in blocks for _l, c in block]
    assert any("make test" in c for c in flat), flat
    assert any("github.event.pull_request.title" in c for c in flat), flat
    assert any("github.head_ref" in c for c in flat), flat
    ok("run: blocks captured incl. block-scalar continuation lines")

    assert is_user_controlled("github.event.pull_request.title")
    assert is_user_controlled("github.head_ref")
    assert is_user_controlled("github.event.commits[0].message")
    assert not is_user_controlled("github.event.repository.name")
    ok("user-controlled field classification")

    # --- full analysis: vulnerable fixture ---
    findings = analyze_workflow("fixture-vulnerable.yml", FIXTURE_VULNERABLE)
    codes = {f["code"] for f in findings}
    assert "injection-triad" in codes, codes
    assert "script-injection" in codes, codes
    assert "secrets-fork-reachable" in codes, codes
    assert "fork-context-trigger" in codes, codes
    assert "no-permissions-block" in codes, codes
    triad = [f for f in findings if f["code"] == "injection-triad"][0]
    assert triad["severity"] == "CRITICAL" and triad["line"] == 13, triad
    inj = [f for f in findings if f["code"] == "script-injection"]
    fields = {f["note"].split("${{ ")[1].split(" }}")[0] for f in inj}
    assert fields == {"github.event.pull_request.title", "github.head_ref"}, \
        fields
    secret = [f for f in findings if f["code"] == "secrets-fork-reachable"][0]
    assert "REPORT_TOKEN" in secret["note"] and "secret-value" not in \
        secret["note"].lower()
    ok("vulnerable fixture: triad + injection + secrets + context findings")

    # --- full analysis: clean fixture ---
    findings = analyze_workflow("fixture-clean.yml", FIXTURE_CLEAN)
    assert findings == [], findings
    ok("clean fixture (push trigger, SHA-pinned action): zero findings")

    # --- interpolation-only fixture ---
    findings = analyze_workflow("fixture-interp.yml", FIXTURE_INTERP_ONLY)
    assert [f["code"] for f in findings] == ["script-injection"], findings
    assert findings[0]["severity"] == "HIGH"
    ok("issue-title interpolation flagged without pull_request_target")

    # --- end-to-end main() on a temp dir ---
    with tempfile.TemporaryDirectory() as tmp:
        wf_dir = os.path.join(tmp, ".github", "workflows")
        os.makedirs(wf_dir)
        with open(os.path.join(wf_dir, "ci.yml"), "w",
                  encoding="utf-8") as fh:
            fh.write(FIXTURE_VULNERABLE)
        with open(os.path.join(wf_dir, "clean.yml"), "w",
                  encoding="utf-8") as fh:
            fh.write(FIXTURE_CLEAN)
        code = main(["--path", wf_dir])
        assert code == 0, code
        ok("main() scans a directory of workflows, exit 0")

        code = main(["--path", os.path.join(wf_dir, "ci.yml")])
        assert code == 0, code
        ok("main() scans a single workflow file, exit 0")

        code = main(["--path", os.path.join(tmp, "nowhere")])
        assert code == 1, code
        ok("missing path -> exit 1")

    print("[self-test] workflow_scan: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
