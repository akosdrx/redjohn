#!/usr/bin/env python3
"""Fail closed on incomplete attribution; a diagnostic pass is not full E2E."""

import hashlib
import json
import os
import xml.etree.ElementTree as ET

from ci import (
    OUT, RELEASED_TYPES as RELEASED_TYPES, SOAK_CHECKS, identity,
    validate_controller_details as validate_details,
    validate_controller_pymalloc, validate_soak_owner, write,
)


CASES = (
    "idle", "playwright_import", "tls_fixture", "synthetic_pressure", "traced", "compact", "untraced",
)


def summarize():
    result = {**identity(), "measurement": "controller_attribution_only",
              "full_project_validated": False, "cases": {}, "blockers": []}
    suite = ET.Element("testsuite", name="controller_attribution")
    sha = result["commit_sha"]
    for case in CASES:
        test = ET.SubElement(suite, "testcase", classname="controller_attribution", name=case)
        properties = ET.SubElement(test, "properties")
        ET.SubElement(properties, "property", name="evidence_kind",
                      value="real_integration" if case in {"traced", "compact", "untraced"}
                      else "diagnostic_control")
        ET.SubElement(properties, "property", name="commit_sha", value=sha)
        try:
            command = json.loads((OUT / f"controller-{case}.json").read_text())
            if (command["commit_sha"] != sha or command["exit_code"] != 0
                    or command["leaked_descendant_pids_before_cleanup"]):
                raise ValueError("command_failed_or_unbound")
            owner = json.loads((OUT / f"controller-{case}-owner/receipt.json").read_text())
            validate_soak_owner(owner)
            mixed = case in {"traced", "compact", "untraced"}
            name = "mixed-soak.json" if mixed else "controller-probe.json"
            value = json.loads((OUT / f"controller-{case}" / name).read_text())
            if value.get("commit_sha") != sha or value.get("ok") is not True:
                raise ValueError("diagnostic_failed_or_unbound")
            long_window = os.environ.get("REDJOHN_CONTROLLER_PROFILE_LONG") == "1" and case != "compact"
            expected_cycles = 120 if long_window else 2
            if mixed and (set(value.get("checks", {})) != SOAK_CHECKS
                          or not all(value["checks"].values())
                          or len(value["workload"]["cycles"]) != expected_cycles
                          or (long_window and value["workload"]["timing"]["loop_elapsed_seconds"] < 1200)
                          or value.get("allocation_tracing_requested") != (case != "untraced")
                          or value.get("snapshot_summary_mode") != (
                              "compact" if case == "compact" else "legacy")):
                raise ValueError("mixed_oracles_missing")
            validate_details(
                value["memory_attribution"]["controller_diagnostics"] if mixed
                else value["observations"], mixed=mixed,
            )
            if mixed:
                validate_controller_pymalloc(value.get("python_allocator_diagnostic"))
            result["cases"][case] = {
                "success": True, "scanner_evidence": mixed,
                "actual_cycles": len(value["workload"]["cycles"]) if mixed else 0,
                "minimum_loop_seconds": 1200 if mixed and long_window else 0,
            }
        except (OSError, ValueError, KeyError, TypeError) as exc:
            message = case + ":" + type(exc).__name__ + ":" + str(exc)
            result["blockers"].append(message)
            ET.SubElement(test, "failure", message=message)
    for name in ("pip-check", "controller-contracts", "controller-capability", "controller-cleanup", "sandbox-cleanup"):
        try:
            value = json.loads((OUT / (name + ".json")).read_text())
            if value["commit_sha"] != sha or value["exit_code"] != 0 or value["leaked_descendant_pids_before_cleanup"]:
                raise ValueError("failed_or_unbound")
        except (OSError, ValueError, KeyError) as exc:
            result["blockers"].append(name + ":" + type(exc).__name__)
    for name, key in (("capabilities.json", "available"), ("apparmor-cleanup.json", "success"), ("cgroup-cleanup.json", "removed")):
        try:
            value = json.loads((OUT / name).read_text())
            if value.get(key) is not True or value.get("leaked_processes", False):
                raise ValueError("capability_or_cleanup_not_proved")
        except (OSError, ValueError) as exc:
            result["blockers"].append(name + ":" + type(exc).__name__)
    result["success"] = not result["blockers"]
    write("controller-summary.json", result)
    suite.set("tests", str(len(CASES)))
    suite.set("failures", str(len(suite.findall("testcase/failure"))))
    ET.ElementTree(suite).write(OUT / "controller-attribution.junit.xml", encoding="unicode")
    evidence = {str(path.relative_to(OUT)): {"bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for path in sorted(OUT.rglob("*")) if path.is_file()
                and not any(part.startswith(".") for part in path.relative_to(OUT).parts)
                and path.suffix in {".json", ".log", ".txt", ".xml"}
                and path.name != "evidence-index.json"}
    write("evidence-index.json", {**identity(), "files": evidence})
    print(json.dumps({"success": result["success"], "blockers": result["blockers"]}))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(summarize())
