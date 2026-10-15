#!/usr/bin/env python3
# lockfile_drift.py - OFFLINE dependency lockfile drift analyzer.
#
# No network access whatsoever. Analyzes one lockfile/manifest at a time:
#   - requirements.txt (pip): missing pins (==), floating (>=, ~=, <, >),
#     URL dependencies, duplicate names after PEP 503 normalization
#   - package-lock.json (npm v1/v2/v3): missing integrity (sha512) fields,
#     duplicate names resolving to multiple versions, legacy lockfileVersion
#   - pyproject.toml (simple parse): floating/unpinned entries in
#     [project] dependencies / [project.optional-dependencies] /
#     [tool.poetry.dependencies] / [tool.poetry.group.*.dependencies]
#
# Run once per environment's file and diff outputs across environments to
# state drift (procedure in references/dependency-integrity.md).
#
# Format is auto-detected from the filename (or content); override with
# --format. Exit codes: 0 analysis completed (findings are output, not an
# error), 1 other errors (no file, unreadable, unparseable content).

import argparse
import json
import os
import re
import sys

REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^]]*\])?\s*(.*)$")
URL_RE = re.compile(r"^(https?://|git\+|svn\+|hg\+|bzr\+)")
FLOAT_RE = re.compile(r"(>=|<=|~=|>|<|\^|~[0-9])")

SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW", "INFO")


def normalize_name(name):
    """PEP 503 / npm-ish normalization: case and -_. equivalent."""
    return re.sub(r"[-_.]+", "-", name).lower()


def classify_spec(spec, bare_means_pinned=False):
    """Classify a version specifier string. Returns one of:
    pinned, floating, unpinned, url, unknown."""
    spec = spec.strip()
    if spec == "" or spec == "*":
        return "unpinned"
    if "==" in spec or "===" in spec:
        return "pinned"
    if URL_RE.match(spec):
        return "url"
    if FLOAT_RE.search(spec):
        return "floating"
    if bare_means_pinned and re.match(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$", spec):
        return "pinned"  # poetry exact bare version, e.g. orjson = "3.9.10"
    if not bare_means_pinned:
        return "unpinned"  # bare name in PEP 508 = no specifier at all
    return "unknown"


def strip_hash_comment(line):
    for idx, ch in enumerate(line):
        if ch == "#" and (idx == 0 or line[idx - 1] in " \t"):
            return line[:idx].rstrip()
    return line.rstrip()


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------

def analyze_requirements(text):
    findings = []
    seen = {}

    def add(severity, cls, lineno, name, detail):
        findings.append({"severity": severity, "class": cls,
                         "line": lineno, "name": name, "detail": detail})

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = strip_hash_comment(raw).strip()
        if not line:
            continue
        if line.startswith("-"):
            add("INFO", "option", lineno, line.split()[0],
                "pip option line (%s) - includes/index settings must be "
                "reviewed separately (dependency-confusion check)"
                % line.split()[0])
            continue
        m = REQ_RE.match(line)
        if not m:
            add("LOW", "unparseable", lineno, line[:40],
                "line does not match a requirement; review manually")
            continue
        name, _extras, spec = m.group(1), m.group(2), m.group(3).strip()
        norm = normalize_name(name)
        if norm in seen:
            add("MEDIUM", "duplicate", lineno, name,
                "duplicate of line %d after normalization (%s)"
                % (seen[norm], norm))
        else:
            seen[norm] = lineno
        kind = classify_spec(spec)
        spec_note = "specifier: %r" % spec if spec else "no specifier"
        if kind == "floating":
            add("MEDIUM", "floating", lineno, name,
                "%s - resolves differently over time/environments" % spec_note)
        elif kind == "unpinned":
            add("HIGH", "unpinned", lineno, name,
                "%s - installs whatever the index serves today" % spec_note)
        elif kind == "url":
            add("LOW", "url-dependency", lineno, name,
                "%s - pin by commit hash/digest for reproducibility"
                % spec_note)
    return findings


# ---------------------------------------------------------------------------
# package-lock.json
# ---------------------------------------------------------------------------

def analyze_package_lock(text):
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError("package-lock.json is not valid JSON: %s" % exc)
    if not isinstance(data, dict) or "lockfileVersion" not in data:
        raise ValueError("not a package-lock.json (no lockfileVersion key)")
    findings = []

    def add(severity, cls, where, name, detail):
        findings.append({"severity": severity, "class": cls,
                         "line": where, "name": name, "detail": detail})

    if data["lockfileVersion"] < 2:
        add("LOW", "legacy-lock", "lockfileVersion",
            "v%d" % data["lockfileVersion"],
            "legacy lock format - regenerate with a current npm for "
            "packages[] integrity coverage")

    versions_by_name = {}

    def check_entry(name, entry, where):
        versions_by_name.setdefault(name, {}).setdefault(
            entry.get("version", "?"), where)
        if entry.get("link"):
            return
        if not entry.get("integrity"):
            resolved = entry.get("resolved", "(no resolved URL)")
            add("HIGH", "missing-integrity", where, name,
                "no integrity field (sha512) - artifact trusted by URL "
                "only; resolved=%s" % resolved)

    packages = data.get("packages") or {}
    if packages:
        for path, entry in packages.items():
            if path == "":  # root manifest snapshot, not a dependency
                continue
            if not isinstance(entry, dict):
                continue
            name = path.rsplit("node_modules/", 1)[-1]
            check_entry(name, entry, path)
    else:
        def walk(deps, prefix):
            for name, entry in (deps or {}).items():
                if not isinstance(entry, dict):
                    continue
                check_entry(name, entry, prefix + name)
                walk({k: v for k, v in entry.items()
                      if isinstance(v, dict) and "version" in v},
                     prefix + name + "/")
        walk(data.get("dependencies"), "")

    for name, vers in sorted(versions_by_name.items()):
        if len(vers) > 1:
            detail = "; ".join("%s at %s" % (v, w) for v, w in
                               sorted(vers.items()))
            add("MEDIUM", "duplicate-versions", "tree", name,
                "resolves to multiple versions in one tree: %s" % detail)
    return findings


# ---------------------------------------------------------------------------
# pyproject.toml (simple parse; documented subset)
# ---------------------------------------------------------------------------

def parse_toml_sections(text):
    """Naive TOML split: section headers + logical 'key = value' lines
    (multi-line arrays joined). Returns [(lineno, section, key, value)]."""
    out = []
    section = ""
    buf = []
    buf_start = None

    def bracket_delta(s):
        depth = 0
        in_str = None
        for ch in s:
            if in_str:
                if ch == in_str:
                    in_str = None
                continue
            if ch in "\"'":
                in_str = ch
            elif ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
        return depth

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = strip_hash_comment(raw).strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]") and bracket_delta(line) == 0 \
                and not line.startswith("[["):
            section = line.strip("[]").strip()
            continue
        if buf:
            buf.append(line)
            if bracket_delta(" ".join(buf)) <= 0:
                joined = " ".join(buf)
                key, _, value = joined.partition("=")
                out.append((buf_start, section, key.strip(), value.strip()))
                buf, buf_start = [], None
            continue
        if "=" in line:
            buf = [line]
            buf_start = lineno
            if bracket_delta(line) <= 0:
                joined = " ".join(buf)
                key, _, value = joined.partition("=")
                out.append((buf_start, section, key.strip(), value.strip()))
                buf, buf_start = [], None
    return out


def toml_array_items(value):
    """Items of a ['a', 'b'] array value (strings), respecting quoted commas."""
    inner = value.strip()
    if not (inner.startswith("[") and inner.endswith("]")):
        return None
    inner = inner[1:-1]
    items = []
    cur = []
    in_str = None
    escaped = False
    for ch in inner:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if in_str == '"' and ch == "\\":
            escaped = True
            cur.append(ch)
            continue
        if in_str:
            if ch == in_str:
                in_str = None
            else:
                cur.append(ch)
            continue
        if ch in ("\"", "'"):
            in_str = ch
            continue
        if ch == ",":
            tok = "".join(cur).strip()
            if tok:
                items.append(tok)
            cur = []
            continue
        cur.append(ch)
    tok = "".join(cur).strip()
    if tok:
        items.append(tok)
    return items


def poetry_version(value):
    """Extract the version constraint from a poetry value: '^1.2',
    '3.9.10', {version = '^1.2', ...}, '*'."""
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        m = re.search(r"version\s*=\s*[\"']([^\"']*)[\"']", value)
        if not m:
            return None  # path/git table -> observation upstream
        return m.group(1)
    return value.strip("\"'")


def analyze_pyproject(text):
    findings = []
    declared = {}

    def add(severity, cls, lineno, name, detail):
        findings.append({"severity": severity, "class": cls,
                         "line": lineno, "name": name, "detail": detail})

    for lineno, section, key, value in parse_toml_sections(text):
        is_project_deps = section == "project" and key == "dependencies"
        is_extra = (section == "project.optional-dependencies"
                    or section.startswith("project.optional-dependencies."))
        is_poetry = (section == "tool.poetry.dependencies"
                     or (section.startswith("tool.poetry.group.")
                         and section.endswith(".dependencies")))
        if not (is_project_deps or is_extra or is_poetry):
            continue
        where = "[%s] %s" % (section, key)
        if is_project_deps or is_extra:
            items = toml_array_items(value)
            if items is None:
                add("LOW", "unparseable", lineno, where,
                    "dependencies value is not an array; review manually")
                continue
            for item in items:
                m = REQ_RE.match(item.strip())
                if not m:
                    add("LOW", "unparseable", lineno, where,
                        "entry not PEP 508-shaped: %r" % item[:40])
                    continue
                name, spec = m.group(1), m.group(3)
                kind = classify_spec(spec)
                declared.setdefault(normalize_name(name), []).append(where)
                if kind == "floating":
                    add("MEDIUM", "floating", lineno, name,
                        "%s in %s - floating specifier %r"
                        % (name, where, spec))
                elif kind == "unpinned":
                    add("HIGH", "unpinned", lineno, name,
                        "%s in %s - no version specifier" % (name, where))
                elif kind == "url":
                    add("LOW", "url-dependency", lineno, name,
                        "%s in %s - URL dependency; pin by digest" %
                        (name, where))
        else:  # poetry table
            if key == "python":
                continue  # runtime constraint, not a dependency
            spec = poetry_version(value)
            if spec is None:
                add("LOW", "url-dependency", lineno, key,
                    "%s in %s - path/git source; pin by commit/digest"
                    % (key, where))
                continue
            kind = classify_spec(spec, bare_means_pinned=True)
            declared.setdefault(normalize_name(key), []).append(where)
            if kind == "floating":
                add("MEDIUM", "floating", lineno, key,
                    "%s in %s - floating constraint %r" % (key, where, spec))
            elif kind == "unpinned":
                add("HIGH", "unpinned", lineno, key,
                    "%s in %s - no constraint" % (key, where))

    for name, wheres in sorted(declared.items()):
        if len(wheres) > 1:
            add("MEDIUM", "duplicate", "-", name,
                "declared in multiple sections: %s" % ", ".join(wheres))
    return findings


# ---------------------------------------------------------------------------
# Detection / CLI
# ---------------------------------------------------------------------------

def detect_format(path, text):
    base = os.path.basename(path).lower()
    if "package-lock" in base or base == "npm-shrinkwrap.json":
        return "package-lock"
    if base.endswith("requirements.txt") or base.endswith(".pip"):
        return "requirements"
    if base == "pyproject.toml":
        return "pyproject"
    head = text.lstrip()[:200]
    if head.startswith("{"):
        try:
            if "lockfileVersion" in json.loads(text):
                return "package-lock"
        except ValueError:
            pass
    if "[project]" in text or "tool.poetry" in text:
        return "pyproject"
    return "requirements"


def render(findings, fmt):
    out = []
    for f in sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f["severity"]),
                                             str(f["line"]))):
        loc = "line %s" % f["line"]
        out.append("[%s] %s %s (%s)\n    %s"
                   % (f["severity"], f["class"], f["name"], loc, f["detail"]))
    if not out:
        out.append("no findings - every entry pinned and hashed where the "
                   "format supports it")
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join("%s=%d" % (s, counts[s])
                        for s in SEVERITY_ORDER if s in counts)
    out.append("[drift] format=%s findings=%d%s"
               % (fmt, len(findings), " (%s)" % summary if summary else ""))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="OFFLINE: analyze one lockfile/manifest (requirements."
        "txt, package-lock.json, pyproject.toml) for unpinned/floating "
        "entries, missing integrity hashes and duplicates. No network "
        "access.",
    )
    ap.add_argument("--lock", help="Path to the lockfile/manifest")
    ap.add_argument("--format", choices=("requirements", "package-lock",
                                         "pyproject"),
                    help="Override format detection")
    ap.add_argument("--self-test", action="store_true",
                    help="Run offline self-tests with fixtures and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.lock:
        sys.stderr.write("error: --lock is required\n")
        return 1
    try:
        with open(args.lock, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        sys.stderr.write("error: cannot read %s: %s\n" % (args.lock, exc))
        return 1

    fmt = args.format or detect_format(args.lock, text)
    try:
        if fmt == "requirements":
            findings = analyze_requirements(text)
        elif fmt == "package-lock":
            findings = analyze_package_lock(text)
        else:
            findings = analyze_pyproject(text)
    except ValueError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 1

    print(render(findings, fmt))
    print("evidence: run once per environment's lockfile and diff outputs "
          "to state drift; cite file:line per finding; version->CVE "
          "correlation goes to 70-exploit-intel.")
    return 0


# ---------------------------------------------------------------------------
# Self-test (offline; documentation fixtures only)
# ---------------------------------------------------------------------------

FIXTURE_REQUIREMENTS = """\
# doc-example requirements.txt
requests==2.31.0
urllib3>=1.26,<3
flask
Django==4.2.7
django==4.1
-r base.txt
"""

FIXTURE_PACKAGE_LOCK = """\
{
  "name": "example-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "example-app",
      "dependencies": {"left-pad": "1.3.0", "mime": "1.0.0"}
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.example.com/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-EXAMPLEHASH1"
    },
    "node_modules/mime": {
      "version": "1.0.0",
      "resolved": "https://registry.example.com/mime/-/mime-1.0.0.tgz"
    },
    "node_modules/example-lib": {
      "version": "2.0.0",
      "resolved": "https://registry.example.com/example-lib/-/example-lib-2.0.0.tgz",
      "integrity": "sha512-EXAMPLEHASH2",
      "dependencies": {"mime": "^2.0.0"}
    },
    "node_modules/example-lib/node_modules/mime": {
      "version": "2.0.0",
      "resolved": "https://registry.example.com/mime/-/mime-2.0.0.tgz",
      "integrity": "sha512-EXAMPLEHASH3"
    }
  }
}
"""

FIXTURE_PYPROJECT = """\
[project]
name = "example-app"
dependencies = [
    "requests>=2.28",
    "flask==3.0.0",
    "example-core",
    "boto3==1.34.0",
]

[project.optional-dependencies]
docs = [
    "flask==3.0.0",
]

[tool.poetry.dependencies]
python = "^3.11"
orjson = "3.9.10"
boto3 = "^1.34"
"""


def self_test():
    checks = 0

    def ok(label):
        nonlocal checks
        checks += 1
        print("[self-test] ok: %s" % label)

    import tempfile

    # --- classifier ---
    assert classify_spec("==2.31.0") == "pinned"
    assert classify_spec(">=1.26,<3") == "floating"
    assert classify_spec("") == "unpinned"
    assert classify_spec("*") == "unpinned"
    assert classify_spec("git+https://example.com/x") == "url"
    assert classify_spec("3.9.10", bare_means_pinned=True) == "pinned"
    assert classify_spec("3.9.10") == "unpinned"
    assert classify_spec("^1.34", bare_means_pinned=True) == "floating"
    ok("specifier classification (pip + poetry semantics)")

    assert normalize_name("Django") == normalize_name("django")
    assert normalize_name("python_dateutil") == "python-dateutil"
    ok("PEP 503 name normalization")

    # --- requirements ---
    findings = analyze_requirements(FIXTURE_REQUIREMENTS)
    classes = {(f["class"], f["name"]) for f in findings}
    assert ("unpinned", "flask") in classes, classes
    assert ("floating", "urllib3") in classes, classes
    assert ("duplicate", "django") in classes, classes
    assert ("option", "-r") in classes, classes
    assert not any(f["class"] == "unpinned" and f["name"] == "requests"
                   for f in findings)
    assert not any(f["name"] == "urllib3" and f["class"] == "unpinned"
                   for f in findings)
    dup = [f for f in findings if f["class"] == "duplicate"][0]
    assert dup["line"] == 6 and "line 5" in dup["detail"], dup
    ok("requirements: floating/unpinned/duplicate/option flagged, pins clean")

    # --- package-lock ---
    findings = analyze_package_lock(FIXTURE_PACKAGE_LOCK)
    miss = [f for f in findings if f["class"] == "missing-integrity"]
    assert len(miss) == 1 and miss[0]["name"] == "mime", miss
    assert miss[0]["line"] == "node_modules/mime", miss
    dup = [f for f in findings if f["class"] == "duplicate-versions"]
    assert len(dup) == 1 and dup[0]["name"] == "mime", dup
    assert "1.0.0" in dup[0]["detail"] and "2.0.0" in dup[0]["detail"], dup
    assert not any(f["name"] == "left-pad" for f in findings)
    ok("package-lock: missing integrity + multi-version duplicate, clean "
       "entries untouched")

    # --- pyproject ---
    findings = analyze_pyproject(FIXTURE_PYPROJECT)
    classes = {(f["class"], f["name"]) for f in findings}
    assert ("floating", "requests") in classes, classes
    assert ("unpinned", "example-core") in classes, classes
    assert ("floating", "boto3") in classes, classes
    assert ("duplicate", "boto3") in classes, classes   # project + poetry
    assert ("duplicate", "flask") in classes, classes    # deps + extras
    assert not any(f["name"] == "orjson" for f in findings)
    assert not any(f["name"] == "python" for f in findings)
    assert toml_array_items('["urllib3>=1.26,<3", "requests[security,socks]==2.31.0"]') == [
        "urllib3>=1.26,<3",
        "requests[security,socks]==2.31.0",
    ]
    ok("pyproject: PEP 621 + poetry tables analyzed, python key skipped")

    # --- format detection + main() end-to-end ---
    with tempfile.TemporaryDirectory() as tmp:
        req_path = os.path.join(tmp, "requirements.txt")
        with open(req_path, "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_REQUIREMENTS)
        assert detect_format(req_path, FIXTURE_REQUIREMENTS) == "requirements"
        code = main(["--lock", req_path])
        assert code == 0, code
        ok("main() requirements.txt end-to-end, exit 0")

        lock_path = os.path.join(tmp, "package-lock.json")
        with open(lock_path, "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_PACKAGE_LOCK)
        assert detect_format(lock_path, FIXTURE_PACKAGE_LOCK) == "package-lock"
        assert main(["--lock", lock_path]) == 0
        ok("main() package-lock.json end-to-end, exit 0")

        py_path = os.path.join(tmp, "pyproject.toml")
        with open(py_path, "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_PYPROJECT)
        assert detect_format(py_path, FIXTURE_PYPROJECT) == "pyproject"
        assert main(["--lock", py_path]) == 0
        ok("main() pyproject.toml end-to-end, exit 0")

        bad_path = os.path.join(tmp, "package-lock.json.broken")
        with open(bad_path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        assert main(["--lock", bad_path, "--format", "package-lock"]) == 1
        ok("invalid package-lock JSON -> exit 1")

    print("[self-test] lockfile_drift: all %d checks passed" % checks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
