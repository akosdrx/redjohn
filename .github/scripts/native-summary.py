#!/usr/bin/env python3
"""Strict commit-bound native smoke evidence; never full-project validation."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ci import ROOT, identity, junit_summary

OUT = ROOT / "artifacts"
EXCLUDED_BROWSER = (
    "tests/test_owned_memory_live.py::"
    "test_actual_browser_sdk_mcp_and_native_worker_inherit_the_owner_hard_fence"
)
REQUIRED_MEMORY_GUARD = (
    "test_actual_manually_entered_writable_group_cannot_authorize_inline_profile"
)
SUITES = {
    "network": {"file": "test_network_tools_live.py", "expected": 8},
    "service": {"file": "test_service_tools_live.py", "expected": 4},
    "preparation": {"file": "test_preparation_native.py", "expected": 1},
    "memory": {"file": "test_owned_memory_live.py", "expected": 8},
    "cleanup-proof": {"file": "test_cleanup_quarantine_live.py", "expected": 1},
    "lab": {"file": "test_lab_validation_live.py", "expected": 4},
}
REQUIRED = (
    "python-install",
    "pip-check",
    "native-ci-contracts",
    "native-linux-dependencies",
    "network-scanner-install",
    "service-scanner-install",
    "preparation-tool-install",
    "linux-setup",
    "python-regression",
    "sandbox-setup",
    "native-capability",
    "native-network",
    "native-service",
    "native-preparation",
    "native-memory",
    "native-cleanup-proof",
    "native-lab",
    "native-cleanup",
    "sandbox-cleanup",
)
TOOLS = {"naabu": "2.6.1", "dnsx": "1.3.1", "nmap": "7.992", "kube-bench": "0.16.0"}


def write(name, value):
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def load(name):
    path = OUT / name
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("native_evidence_size_exceeded")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise TypeError("native_evidence_object_required")
    return value


def scope():
    source, function = EXCLUDED_BROWSER.split("::")
    names = {
        node.name
        for node in ast.walk(ast.parse((ROOT / source).read_text()))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if function not in names:
        raise ValueError("native_declared_browser_exclusion_no_longer_matches_source")
    result = {
        **identity(),
        "validation_scope": "native_components_smoke",
        "full_project_validated": False,
        "browser_install_requested": False,
        "suites": SUITES,
        "out_of_scope_not_executed": [EXCLUDED_BROWSER],
        "excluded_is_neither_skipped_nor_passed": True,
        "live_cloud_audit_executed": False,
        "live_kubernetes_audit_executed": False,
    }
    write("native-scope.json", result)
    return result


def junit(path, expected_file):
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("native_junit_size_exceeded")
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    result = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    names, errors = set(), []
    for case in cases:
        key = (case.get("classname"), case.get("name"))
        if key in names or not case.get("name"):
            errors.append("duplicate_or_unnamed_case")
        names.add(key)
        if Path(case.get("file", "")).name != expected_file:
            errors.append("unexpected_test_file")
        if case.get("name", "").startswith(EXCLUDED_BROWSER.split("::")[1]):
            errors.append("browser_case_in_native_scope")
        status = next(
            (
                kind
                for tag, kind in (
                    ("error", "errors"),
                    ("failure", "failed"),
                    ("skipped", "skipped"),
                )
                if case.find(tag) is not None
            ),
            "passed",
        )
        result[status] += 1
    for suite in root.iter("testsuite"):
        # Collection/setup errors may be suite-level rather than testcases.
        if any(suite.find(tag) is not None for tag in ("error", "failure")) or any(
            int(suite.get(attribute, "0")) != 0
            for attribute in ("errors", "failures", "skipped")
        ):
            errors.append("suite_level_error")
    properties = {
        prop.get("name"): prop.get("value")
        for prop in root.iter("property")
        if prop.get("name", "").startswith("kube_bench_preparation_")
    }
    return {
        "counts": result,
        "cases": sorted(name for _klass, name in names),
        "suite_properties": properties,
        "evidence_kind": "real_native_component",
        "scope_errors": sorted(set(errors)),
    }


def summary():
    meta = identity()
    result = {
        **meta,
        "validation_scope": "native_components_smoke",
        "full_project_validated": False,
        "commands": {},
        "suites": {},
        "tools": {},
        "blockers": [],
        "out_of_scope_not_executed": [EXCLUDED_BROWSER],
        "live_cloud_audit_executed": False,
        "live_kubernetes_audit_executed": False,
    }
    sha = meta["commit_sha"]
    for name in REQUIRED:
        try:
            record = load(name + ".json")
            result["commands"][name] = record
            if (
                record.get("commit_sha") != sha
                or type(record.get("exit_code")) is not int
                or record["exit_code"] != 0
                or record.get("leaked_descendant_pids_before_cleanup") != []
            ):
                raise ValueError("failed_or_unbound_command")
        except (OSError, ValueError, TypeError, KeyError):
            result["blockers"].append("missing_or_failed_command:" + name)
    for name, selected in SUITES.items():
        try:
            data = junit(OUT / ("native-" + name + ".junit.xml"), selected["file"])
            result["suites"][name] = data
            if (
                data["counts"]
                != {
                    "passed": selected["expected"],
                    "failed": 0,
                    "errors": 0,
                    "skipped": 0,
                }
                or data["scope_errors"]
                or (name == "memory" and REQUIRED_MEMORY_GUARD not in data["cases"])
            ):
                raise ValueError("incomplete_native_suite")
        except (OSError, ValueError, TypeError, ET.ParseError):
            result["blockers"].append("incomplete_native_suite:" + name)
    try:
        path = OUT / "regression.junit.xml"
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("regression_junit_size_exceeded")
        regression = junit_summary(path)
        result["python_regression"] = regression
        counts = regression["counts"]
        for suite in ET.parse(path).getroot().iter("testsuite"):
            if any(suite.find(tag) is not None for tag in ("error", "failure")) or any(
                int(suite.get(key, "0")) != 0 for key in ("errors", "failures", "skipped")
            ):
                raise ValueError("regression_suite_error")
        if not counts["passed"] or any(counts[key] for key in ("failed", "errors", "skipped")):
            raise ValueError("regression_incomplete")
    except (OSError, ValueError, TypeError, ET.ParseError):
        result["blockers"].append("incomplete_python_regression")
    try:
        selected = load("native-scope.json")
        if (
            selected.get("commit_sha") != sha
            or selected.get("suites") != SUITES
            or selected.get("out_of_scope_not_executed") != [EXCLUDED_BROWSER]
            or selected.get("full_project_validated") is not False
            or selected.get("browser_install_requested") is not False
        ):
            raise ValueError("scope_not_exact")
    except (OSError, ValueError, TypeError):
        result["blockers"].append("native_scope_missing_or_inexact")
    try:
        cap = load("capabilities.json")
        required = (
            "available",
            "namespace_available",
            "cgroup_available",
            "profile_escape_denied",
            "nested_raw_socket_denied",
        )
        if (
            cap.get("commit_sha") != sha
            or cap.get("validation_profile") != "native_only"
            or cap.get("browser_probe") != "not_requested_native_profile"
            or cap.get("browser_available") is not False
            or any(cap.get(key) is not True for key in required)
            or cap.get("blockers") != []
            or cap.get("uid", 0) == 0
            or any(
                cap.get(key) != "1"
                for key in (
                    "apparmor_restrict_unprivileged_userns",
                    "apparmor_restrict_unprivileged_unconfined",
                )
            )
        ):
            raise ValueError("native_runner_capability_missing")
        if (
            cap.get("apparmor_profile")
            != os.environ.get("REDJOHN_CI_APPARMOR_PROFILE", "") + " (enforce)"
            or not cap.get("network_namespace_attestations")
            or any(
                int(value, 16) != 0
                for value in cap.get("host_capabilities", {}).values()
            )
            or set(cap.get("host_capabilities", {})) != {"CapEff", "CapPrm", "CapAmb"}
        ):
            raise ValueError("native_namespace_or_uid_attestation_missing")
        result["capabilities"] = cap
    except (OSError, ValueError, TypeError):
        result["blockers"].append("blocked_native_runner_capability")
    for filename, predicate in (
        (
            "cgroup-cleanup.json",
            lambda value: (
                value.get("removed") is True and value.get("leaked_processes") is False
            ),
        ),
        (
            "apparmor-cleanup.json",
            lambda value: (
                value.get("commit_sha") == sha
                and value.get("success") is True
                and value.get("active_profile_pids") == []
                and set(value.get("restrictions_after_tests", {}).values()) == {"1"}
            ),
        ),
        (
            "source.json",
            lambda value: value.get("commit_sha") == sha and bool(value.get("sha256")),
        ),
    ):
        try:
            if not predicate(load(filename)):
                raise ValueError("native_cleanup_or_source_invalid")
        except (OSError, ValueError, TypeError):
            result["blockers"].append("missing_or_invalid:" + filename)
    for filename, names in (
        ("network-scanner-versions.json", ("naabu", "dnsx")),
        ("service-scanner-versions.json", ("nmap",)),
        ("preparation-tool-versions.json", ("kube-bench",)),
    ):
        try:
            versions = load(filename)
            for tool in names:
                record = versions[tool]
                receipt = OUT / "tool-receipts" / (tool + ".json")
                if (
                    record.get("version") != TOOLS[tool]
                    or re.fullmatch(r"[a-f0-9]{64}", record.get("binary_sha256", ""))
                    is None
                    or hashlib.sha256(receipt.read_bytes()).hexdigest()
                    != record.get("receipt_sha256")
                ):
                    raise ValueError("native_tool_receipt_not_exact")
                result["tools"][tool] = record
        except (OSError, ValueError, TypeError, KeyError):
            result["blockers"].append("missing_or_invalid_tool_versions:" + filename)
    preparation_properties = (
        result["suites"].get("preparation", {}).get("suite_properties", {})
    )
    if (
        preparation_properties.get("kube_bench_preparation_real_version") != "0.16.0"
        or preparation_properties.get("kube_bench_preparation_binary_sha256")
        != result["tools"].get("kube-bench", {}).get("binary_sha256")
        or preparation_properties.get("kube_bench_preparation_audit_executed")
        != "false"
    ):
        result["blockers"].append("missing_real_native_version_only_proof")
    result["native_smoke_success"] = not result["blockers"]
    write("native-summary.json", result)
    evidence = {
        str(path.relative_to(OUT)): {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }
        for path in sorted(OUT.rglob("*"))
        if path.is_file()
        and path.suffix in {".xml", ".json", ".log", ".txt"}
        and path.name != "native-evidence-index.json"
    }
    write(
        "native-evidence-index.json",
        {
            **meta,
            "validation_scope": "native_components_smoke",
            "full_project_validated": False,
            "files": evidence,
        },
    )
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as report:
            report.write("## RedJohn native component smoke\n\n")
            report.write(f"Commit `{sha}`; full_project_validated=false.\n\n")
            report.write(
                "| Native suite | Passed | Failed | Errors | Skipped |\n|---|---:|---:|---:|---:|\n"
            )
            for name, data in result["suites"].items():
                counts = data["counts"]
                report.write(
                    f"| {name} | {counts['passed']} | {counts['failed']} | {counts['errors']} | {counts['skipped']} |\n"
                )
            report.write(
                "\nOut of scope, not executed/skipped/passed: `"
                + EXCLUDED_BROWSER
                + "`.\n"
            )
            report.write(
                "\n"
                + (
                    "Native smoke complete; full validation remains separate."
                    if result["native_smoke_success"]
                    else "Native smoke incomplete: " + ", ".join(result["blockers"])
                )
                + "\n"
            )
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "commit_sha",
                    "native_smoke_success",
                    "full_project_validated",
                    "blockers",
                    "suites",
                )
            }
        )
    )
    return 0 if result["native_smoke_success"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("scope", "summary"))
    if parser.parse_args().phase == "scope":
        scope()
        raise SystemExit(0)
    raise SystemExit(summary())
