#!/usr/bin/env python3
"""Offline verifier for the pentestskills library.

Checks, without any network access or process spawning:
  1. exactly the 27 expected skill folders exist, each with SKILL.md;
  2. frontmatter has name == folder stem and a unique description of sane length;
  3. every scripts/*.py compiles (py_compile);
  4. every script's --self-test passes, executed in-process via runpy with an
     alarm-based guard (self-tests are offline per CONVENTIONS.md).

Exit codes: 0 all checks passed, 1 any failure.
"""

import py_compile
import runpy
import signal
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

EXPECTED = [
    "00-master-pentest-methodology",
    "05-attack-surface-planner",
    "10-recon-endpoint-mapping",
    "15-cms-ecommerce-rce",
    "20-traffic-manipulation",
    "25-waf-edge-posture",
    "30-auth-access-control",
    "32-mfa-captcha-audit",
    "35-cryptographic-failures",
    "40-injection-engine",
    "45-rce-exploitation",
    "50-config-baseline",
    "55-client-side-attacks",
    "58-logic-concurrency",
    "60-api-graphql-websockets",
    "62-mcp-ai-surface-audit",
    "65-supply-chain-integrity",
    "70-exploit-intel",
    "75-zeroday-research",
    "80-oracle-stack",
    "82-proxmox-ve",
    "85-logging-monitoring",
    "90-evidence-reporting",
    "95-finding-verifier",
    "scan-deep",
    "scan-high",
    "scan-low",
    "scan-standard",
]

failures = []
notes = []


class SelfTestTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise SelfTestTimeout()


def run_selftest(script):
    """Run script's --self-test in-process; return (ok, detail)."""
    old_argv = sys.argv
    sys.argv = [str(script), "--self-test"]
    signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(120)
    try:
        runpy.run_path(str(script), run_name="__main__")
        return True, "exited 0"
    except SystemExit as exc:
        code = exc.code
        if code in (None, 0):
            return True, "exited 0"
        return False, "exit code %r" % (code,)
    except SelfTestTimeout:
        return False, "timed out after 120s"
    except BaseException as exc:  # noqa: BLE001 - verifier must survive any script bug
        return False, "%s: %s" % (type(exc).__name__, exc)
    finally:
        signal.alarm(0)
        sys.argv = old_argv


def parse_frontmatter(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        return None, "missing opening '---'"
    fields = {}
    for idx, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            if "name" not in fields or "description" not in fields:
                return None, "frontmatter missing name or description"
            return fields, None
        if ":" in line and not line.startswith((" ", "\t")):
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return None, "unterminated frontmatter"


def main():
    found = sorted(
        d.name for d in BASE.iterdir() if d.is_dir() and (d / "SKILL.md").exists()
    )
    if found != EXPECTED:
        failures.append(
            "folder set mismatch: missing=%s unexpected=%s"
            % (
                sorted(set(EXPECTED) - set(found)) or "none",
                sorted(set(found) - set(EXPECTED)) or "none",
            )
        )

    descriptions = {}
    names = {}
    script_count = 0
    for folder in found:
        skill = BASE / folder / "SKILL.md"
        fields, err = parse_frontmatter(skill)
        if err:
            failures.append("%s: %s" % (folder, err))
            continue
        extra = set(fields) - {"name", "description"}
        if extra:
            failures.append("%s: unexpected frontmatter keys %s" % (folder, sorted(extra)))
        if fields.get("name") != folder:
            failures.append(
                "%s: name %r != folder stem" % (folder, fields.get("name"))
            )
        desc = fields.get("description", "")
        if len(desc) < 40:
            failures.append("%s: description too short (%d chars)" % (folder, len(desc)))
        if desc in descriptions:
            failures.append(
                "%s: duplicate description with %s" % (folder, descriptions[desc])
            )
        descriptions[desc] = folder
        if fields.get("name") in names:
            failures.append(
                "%s: duplicate name with %s" % (folder, names[fields["name"]])
            )
        names[fields["name"]] = folder
        body_lines = len(skill.read_text(encoding="utf-8").splitlines())
        cap = 140 if folder == "00-master-pentest-methodology" else 60
        if body_lines > cap:
            failures.append(
                "%s: SKILL.md has %d lines (cap %d)" % (folder, body_lines, cap)
            )

        scripts_dir = BASE / folder / "scripts"
        if not scripts_dir.exists():
            notes.append("%s: no scripts/ (informational)" % folder)
            continue
        for script in sorted(scripts_dir.glob("*.py")):
            script_count += 1
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    py_compile.compile(str(script), cfile=str(Path(tmp) / "x.pyc"), doraise=True)
            except py_compile.PyCompileError as exc:
                failures.append("%s: compile error: %s" % (script, exc))
                continue
            ok, detail = run_selftest(script)
            if not ok:
                failures.append("%s: --self-test %s" % (script, detail))
            else:
                notes.append("%s: self-test ok (%s)" % (script.name, detail))

    for note in notes:
        print("[ok] %s" % note)
    if failures:
        for failure in failures:
            print("[FAIL] %s" % failure)
        print("\n%d failure(s)" % len(failures))
        return 1
    print("\nAll checks passed: %d folders, %d scripts." % (len(found), script_count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
