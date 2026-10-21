#!/usr/bin/env python3
"""Fail closed on incomplete attribution; a diagnostic pass is not full E2E."""

import hashlib
import json
import xml.etree.ElementTree as ET

from ci import OUT, SOAK_CHECKS, identity, validate_soak_owner, write


CASES = ("idle", "playwright_import", "tls_fixture", "synthetic_pressure", "traced", "untraced")


def summarize():
    result = {**identity(), "measurement": "controller_attribution_only",
              "full_project_validated": False, "cases": {}, "blockers": []}
    suite = ET.Element("testsuite", name="controller_attribution")
    sha = result["commit_sha"]
    for case in CASES:
        test = ET.SubElement(suite, "testcase", classname="controller_attribution", name=case)
        try:
            command = json.loads((OUT / f"controller-{case}.json").read_text())
            if (command["commit_sha"] != sha or command["exit_code"] != 0
                    or command["leaked_descendant_pids_before_cleanup"]):
                raise ValueError("command_failed_or_unbound")
            owner = json.loads((OUT / f"controller-{case}-owner/receipt.json").read_text())
            validate_soak_owner(owner)
            mixed = case in {"traced", "untraced"}
            name = "mixed-soak.json" if mixed else "controller-probe.json"
            value = json.loads((OUT / f"controller-{case}" / name).read_text())
            if value.get("commit_sha") != sha or value.get("ok") is not True:
                raise ValueError("diagnostic_failed_or_unbound")
            if mixed and (set(value.get("checks", {})) != SOAK_CHECKS
                          or not all(value["checks"].values())
                          or len(value["workload"]["cycles"]) != 2
                          or value.get("allocation_tracing_requested") != (case == "traced")):
                raise ValueError("mixed_oracles_missing")
            result["cases"][case] = {"success": True, "scanner_evidence": mixed}
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
