#!/usr/bin/env python3
"""Commit-bound command logs, external RSS samples and strict CI evidence gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "artifacts"


def write(name, value):
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def identity():
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    expected = os.environ.get("GITHUB_SHA")
    if expected and sha != expected:
        raise RuntimeError("checkout_commit_does_not_match_event")
    return {
        "commit_sha": sha,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "run_url": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/"
        + os.environ.get("GITHUB_RUN_ID", ""),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
        "machine": platform.machine(),
        "python": sys.version,
        "platform": platform.platform(),
        "image_version": os.environ.get("ImageVersion"),
    }


def process_table():
    """PID/PPID/starttime/RSS only; never export process arguments or environment."""
    rows = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            pid = int(path.parent.name)
            text = path.read_text()
            fields = text[text.rfind(")") + 2 :].split()
            rows[pid] = (int(fields[1]), fields[19], int(fields[21]) * os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError, IndexError):
            continue
    return rows


def run(name, cwd, argv):
    OUT.mkdir(exist_ok=True)
    meta = identity()
    started = time.monotonic()
    peak = count = samples = 0
    seen = {}
    log_path = OUT / (name + ".log")
    process = subprocess.Popen(
        argv, cwd=ROOT / cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    def forward():
        with log_path.open("wb") as log:
            assert process.stdout is not None
            for block in iter(lambda: process.stdout.read1(65536), b""):
                log.write(block)
                log.flush()
                sys.stdout.buffer.write(block)
                sys.stdout.buffer.flush()

    reader = threading.Thread(target=forward, daemon=True)
    reader.start()

    def stop(_signum, _frame):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    old = {s: signal.signal(s, stop) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        while process.poll() is None:
            table = process_table()
            owned = {process.pid}
            while True:
                more = {pid for pid, (ppid, _birth, _rss) in table.items() if ppid in owned}
                if more <= owned:
                    break
                owned |= more
            active = {pid: table[pid] for pid in owned if pid in table}
            seen.update({pid: row[1] for pid, row in active.items()})
            samples += 1
            peak = max(peak, sum(row[2] for row in active.values()))
            count = max(count, len(active))
            time.sleep(0.2)
        code = process.wait()
        table = process_table()
        leaked = [pid for pid, birth in seen.items() if pid != process.pid
                  and pid in table and table[pid][1] == birth]
        if leaked:
            stop(None, None)
            time.sleep(0.3)
            for pid in leaked:
                current = process_table().get(pid)
                if current and current[1] == seen[pid]:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        reader.join(timeout=5)
        value = {
            **meta, "command": argv, "cwd": cwd, "exit_code": code,
            "duration_seconds": time.monotonic() - started,
            "process_tree_peak_rss_bytes": peak, "max_process_count": count,
            "samples": samples, "leaked_descendant_pids_before_cleanup": leaked,
            "rss_method": "external /proc RSS sum; shared pages may be counted more than once; not a hard OS limit",
        }
        write(name + ".json", value)
        return code or (1 if leaked or reader.is_alive() else 0)
    finally:
        for s, handler in old.items():
            signal.signal(s, handler)


def junit_summary(path):
    cases = ET.parse(path).getroot().findall(".//testcase")
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    kinds = {}
    skips = []
    for case in cases:
        status = next((key for tag, key in (("error", "errors"), ("failure", "failed"),
                                            ("skipped", "skipped")) if case.find(tag) is not None), "passed")
        counts[status] += 1
        props = {p.get("name"): p.get("value") for p in case.findall("properties/property")}
        kind = props.get("evidence_kind", "unclassified")
        kinds.setdefault(kind, {key: 0 for key in counts})[status] += 1
        if status == "skipped":
            skips.append({"test": case.get("name"), "reason": case.find("skipped").get("message")})
    return {"counts": counts, "evidence_kinds": kinds, "skips": skips}


REQUIRED = ("python-install", "linux-dependencies", "scanner-install", "linux-setup",
            "frontend-install", "pip-check", "python-lint", "python-types", "ci-contracts", "frontend-types",
            "frontend-build", "go-vet", "go-tests", "go-build", "python-wheel",
            "python-regression", "python-integration")


def summarize():
    result = {**identity(), "commands": {}, "junit": {}, "blockers": []}
    for name in REQUIRED:
        path = OUT / (name + ".json")
        if not path.is_file():
            result["blockers"].append("missing_command:" + name)
            continue
        value = json.loads(path.read_text())
        result["commands"][name] = value
        if value["commit_sha"] != result["commit_sha"] or value["exit_code"] != 0 or value["leaked_descendant_pids_before_cleanup"]:
            result["blockers"].append("failed_command:" + name)
    for name in ("regression", "integration"):
        path = OUT / (name + ".junit.xml")
        if not path.is_file():
            result["blockers"].append("missing_junit:" + name)
            continue
        value = junit_summary(path)
        result["junit"][name] = value
        if not value["counts"]["passed"] or any(value["counts"][key] for key in ("failed", "errors", "skipped")):
            result["blockers"].append("incomplete_suite:" + name)
    cap = OUT / "capabilities.json"
    if not cap.is_file() or not json.loads(cap.read_text()).get("available"):
        result["blockers"].append("blocked_runner_capability")
    cleanup = OUT / "cgroup-cleanup.json"
    if not cleanup.is_file():
        result["blockers"].append("missing_cleanup_evidence")
    else:
        data = json.loads(cleanup.read_text())
        if not data.get("removed") or data.get("leaked_processes"):
            result["blockers"].append("failed_owned_process_cleanup")
    go_cases = {}
    go_log = OUT / "go-tests.log"
    if go_log.exists():
        for line in go_log.read_text().splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("Test") and row.get("Action") in {"pass", "fail", "skip"}:
                go_cases[(row["Package"], row["Test"])] = row
    result["go_tests"] = {status: sum(row["Action"] == action for row in go_cases.values())
                          for status, action in (("passed", "pass"), ("failed", "fail"), ("skipped", "skip"))}
    suite = ET.Element("testsuite", name="Go TUI", tests=str(len(go_cases)))
    for (package, name), row in sorted(go_cases.items()):
        case = ET.SubElement(suite, "testcase", classname=package, name=name, time=str(row.get("Elapsed", 0)))
        if row["Action"] in {"fail", "skip"}:
            ET.SubElement(case, "failure" if row["Action"] == "fail" else "skipped")
    if go_cases:
        ET.ElementTree(suite).write(OUT / "go.junit.xml", encoding="utf-8", xml_declaration=True)
        if result["go_tests"]["failed"] or result["go_tests"]["skipped"]:
            result["blockers"].append("incomplete_go_tests")
    else:
        result["blockers"].append("missing_go_test_cases")
    result["success"] = not result["blockers"]
    write("summary.json", result)
    evidence = {str(path.relative_to(OUT)): {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size} for path in sorted(OUT.rglob("*"))
                if path.is_file() and path.suffix in {".xml", ".json", ".log", ".txt"}
                and path.name != "evidence-index.json"}
    write("evidence-index.json", {**identity(), "files": evidence})
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as report:
            report.write(f"## RedJohn {result['machine']} — `{result['commit_sha']}`\n\n")
            report.write("| Suite | Passed | Failed | Errors | Skipped |\n|---|---:|---:|---:|---:|\n")
            for name, value in result["junit"].items():
                c = value["counts"]
                report.write(f"| {name} | {c['passed']} | {c['failed']} | {c['errors']} | {c['skipped']} |\n")
            report.write("\n" + ("Complete." if result["success"] else "Incomplete: " + ", ".join(result["blockers"])) + "\n")
    print(json.dumps({key: result[key] for key in
                     ("commit_sha", "machine", "success", "blockers", "junit", "go_tests")}))
    return 0 if result["success"] else 1


def snapshot():
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    hashes = {}
    for raw in paths:
        if raw:
            path = ROOT / os.fsdecode(raw)
            if path.is_file() and not path.is_symlink():
                hashes[os.fsdecode(raw)] = hashlib.sha256(path.read_bytes()).hexdigest()
    write("source.json", {**identity(), "sha256": hashes})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    command = sub.add_parser("run")
    command.add_argument("--name", required=True)
    command.add_argument("--cwd", default=".")
    command.add_argument("argv", nargs=argparse.REMAINDER)
    sub.add_parser("summary")
    sub.add_parser("snapshot")
    args = parser.parse_args()
    if args.action == "run":
        return run(args.name, args.cwd, args.argv[1:] if args.argv[:1] == ["--"] else args.argv)
    if args.action == "snapshot":
        snapshot()
        return 0
    return summarize()


if __name__ == "__main__":
    raise SystemExit(main())
