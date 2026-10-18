"""Synthetic native-smoke evidence contracts; never real runner proof."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

SCRIPTS = Path(__file__).parents[1] / "scripts"
CI_SPEC = importlib.util.spec_from_file_location("native_test_ci", SCRIPTS / "ci.py")
ci = importlib.util.module_from_spec(CI_SPEC)
CI_SPEC.loader.exec_module(ci)
SPEC = importlib.util.spec_from_file_location(
    "native_summary", SCRIPTS / "native-summary.py"
)
native = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {"ci": ci}):
    SPEC.loader.exec_module(native)


class NativeEvidenceContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.out = Path(temporary.name)
        for selected in (
            patch.object(native, "OUT", self.out),
            patch.object(
                native,
                "identity",
                return_value={"commit_sha": "a" * 40, "machine": "synthetic-contract"},
            ),
            patch.dict(
                os.environ,
                {
                    "GITHUB_ACTIONS": "false",
                    "GITHUB_STEP_SUMMARY": "",
                    "REDJOHN_CI_APPARMOR_PROFILE": "redjohn-ci-123-1-X64",
                },
            ),
        ):
            selected.start()
            self.addCleanup(selected.stop)

    def put(self, path, value):
        target = self.out / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value))

    def complete(self):
        sha = "a" * 40
        for name in native.REQUIRED:
            self.put(
                name + ".json",
                {
                    "commit_sha": sha,
                    "exit_code": 0,
                    "leaked_descendant_pids_before_cleanup": [],
                },
            )
        self.put(
            "native-scope.json",
            {
                "commit_sha": sha,
                "suites": native.SUITES,
                "out_of_scope_not_executed": [native.EXCLUDED_BROWSER],
                "full_project_validated": False,
                "browser_install_requested": False,
            },
        )
        self.put(
            "capabilities.json",
            {
                "commit_sha": sha,
                "available": True,
                "namespace_available": True,
                "cgroup_available": True,
                "profile_escape_denied": True,
                "nested_raw_socket_denied": True,
                "validation_profile": "native_only",
                "browser_probe": "not_requested_native_profile",
                "browser_available": False,
                "blockers": [],
                "uid": 1001,
                "apparmor_profile": "redjohn-ci-123-1-X64 (enforce)",
                "apparmor_restrict_unprivileged_userns": "1",
                "apparmor_restrict_unprivileged_unconfined": "1",
                "network_namespace_attestations": [{"synthetic": True}],
                "host_capabilities": {"CapEff": "0", "CapPrm": "0", "CapAmb": "0"},
            },
        )
        self.put("cgroup-cleanup.json", {"removed": True, "leaked_processes": False})
        self.put(
            "apparmor-cleanup.json",
            {
                "commit_sha": sha,
                "success": True,
                "active_profile_pids": [],
                "restrictions_after_tests": {"one": "1", "two": "1"},
            },
        )
        self.put("source.json", {"commit_sha": sha, "sha256": {"synthetic": "b" * 64}})
        regression = ET.Element("testsuite", tests="1")
        case = ET.SubElement(regression, "testcase", name="synthetic_contract", classname="synthetic")
        props = ET.SubElement(case, "properties")
        ET.SubElement(props, "property", name="evidence_kind", value="mock_contract")
        ET.ElementTree(regression).write(self.out / "regression.junit.xml")
        for name, selected in native.SUITES.items():
            suite = ET.Element("testsuite", tests=str(selected["expected"]))
            for index in range(selected["expected"]):
                ET.SubElement(
                    suite,
                    "testcase",
                    name=(
                        native.REQUIRED_MEMORY_GUARD
                        if name == "memory" and index == 0
                        else "synthetic_" + str(index)
                    ),
                    classname="synthetic",
                    file="RedJohn/tests/" + selected["file"],
                )
            if name == "preparation":
                props = ET.SubElement(suite, "properties")
                for key, value in {
                    "kube_bench_preparation_real_version": "0.16.0",
                    "kube_bench_preparation_binary_sha256": "b" * 64,
                    "kube_bench_preparation_audit_executed": "false",
                }.items():
                    ET.SubElement(props, "property", name=key, value=value)
            ET.ElementTree(suite).write(self.out / ("native-" + name + ".junit.xml"))
        records = {}
        for tool, version in native.TOOLS.items():
            self.put(
                "tool-receipts/" + tool + ".json",
                {"version": version, "synthetic": True},
            )
            path = self.out / "tool-receipts" / (tool + ".json")
            records[tool] = {
                "version": version,
                "binary_sha256": "b" * 64,
                "receipt_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        for name, tools in (
            ("network-scanner-versions.json", ("naabu", "dnsx")),
            ("service-scanner-versions.json", ("nmap",)),
            ("preparation-tool-versions.json", ("kube-bench",)),
        ):
            self.put(name, {tool: records[tool] for tool in tools})

    def run_summary(self):
        with contextlib.redirect_stdout(io.StringIO()):
            status = native.summary()
        return status, json.loads((self.out / "native-summary.json").read_text())

    def test_complete_synthetic_native_evidence_stays_explicitly_limited(self):
        self.complete()
        code, result = self.run_summary()
        self.assertEqual(code, 0)
        self.assertTrue(result["native_smoke_success"])
        self.assertFalse(result["full_project_validated"])
        self.assertEqual(result["out_of_scope_not_executed"], [native.EXCLUDED_BROWSER])
        self.assertEqual(
            sum(row["counts"]["passed"] for row in result["suites"].values()), 20
        )
        self.assertEqual(result["python_regression"]["counts"]["passed"], 1)
        self.assertIn("mock_contract", result["python_regression"]["evidence_kinds"])
        self.assertTrue((self.out / "native-evidence-index.json").exists())

    def test_missing_evidence_cannot_be_native_success(self):
        code, result = self.run_summary()
        self.assertEqual(code, 1)
        self.assertFalse(result["native_smoke_success"])
        self.assertIn("blocked_native_runner_capability", result["blockers"])

    def test_missing_failed_or_skipped_regression_cannot_be_native_workflow_success(self):
        for fault in ("missing", "failure", "error", "skipped", "suite-error"):
            with self.subTest(fault=fault):
                self.complete()
                path = self.out / "regression.junit.xml"
                if fault == "missing":
                    path.unlink()
                else:
                    tree = ET.parse(path)
                    if fault == "suite-error":
                        tree.getroot().set("errors", "1")
                    else:
                        ET.SubElement(tree.getroot().find("testcase"), fault)
                    tree.write(path)
                code, result = self.run_summary()
                self.assertNotEqual(code, 0)
                self.assertFalse(result["native_smoke_success"])
                self.assertIn("incomplete_python_regression", result["blockers"])

    def test_new_writable_cgroup_guard_case_cannot_be_replaced_by_another_pass(self):
        self.complete()
        path = self.out / "native-memory.junit.xml"
        tree = ET.parse(path)
        tree.getroot().find("testcase").set("name", "synthetic_unreviewed_replacement")
        tree.write(path)
        self.assertIn(
            "incomplete_native_suite:memory", self.run_summary()[1]["blockers"]
        )

    def test_any_native_skip_error_failure_or_wrong_test_file_is_incomplete(self):
        for defect in (
            "skipped",
            "error",
            "failure",
            "file",
            "count",
            "browser",
            "suite_errors",
        ):
            with self.subTest(defect=defect):
                self.complete()
                path = self.out / "native-memory.junit.xml"
                tree = ET.parse(path)
                case = tree.getroot().find("testcase")
                if defect in {"skipped", "error", "failure"}:
                    ET.SubElement(case, defect)
                elif defect == "file":
                    case.set("file", "unreviewed.py")
                elif defect == "browser":
                    case.set("name", native.EXCLUDED_BROWSER.split("::")[1])
                elif defect == "suite_errors":
                    tree.getroot().set("errors", "1")
                else:
                    tree.getroot().remove(case)
                tree.write(path)
                self.assertIn(
                    "incomplete_native_suite:memory", self.run_summary()[1]["blockers"]
                )

    def test_other_commit_or_leaked_descendants_cannot_pass(self):
        for update in (
            {"commit_sha": "c" * 40},
            {"leaked_descendant_pids_before_cleanup": [12345]},
        ):
            self.complete()
            self.put(
                "native-network.json",
                {
                    "commit_sha": "a" * 40,
                    "exit_code": 0,
                    "leaked_descendant_pids_before_cleanup": [],
                    **update,
                },
            )
            self.assertIn(
                "missing_or_failed_command:native-network",
                self.run_summary()[1]["blockers"],
            )

    def test_browser_is_not_silently_omitted_from_full_capability_or_kernel_case(self):
        source = (SCRIPTS / "capabilities.py").read_text()
        tree = ast.parse(source)
        probe = next(
            node
            for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "probe"
        )
        self.assertEqual(probe.args.kwonlyargs[0].arg, "native_only")
        self.assertIs(probe.args.kw_defaults[0].value, False)
        guarded = next(
            node
            for node in probe.body
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.UnaryOp)
            and isinstance(node.test.operand, ast.Name)
            and node.test.operand.id == "native_only"
        )
        self.assertIn("chromium.launch", ast.get_source_segment(source, guarded))
        spec = importlib.util.spec_from_file_location(
            "native_evidence", SCRIPTS / "pytest_evidence.py"
        )
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        caps = self.out / "browser-capabilities.json"
        caps.write_text(
            '{"browser_available":false,"namespace_available":true,"cgroup_available":true}'
        )
        items, markers = [], {}
        for name in (
            native.EXCLUDED_BROWSER.split("::")[1],
            "test_actual_owner_preserves_inherited_terminal_io",
        ):
            path = self.out / "test_owned_memory_live.py"
            path.write_text("")
            markers[name] = []
            items.append(
                SimpleNamespace(
                    path=path,
                    originalname=name,
                    name=name,
                    user_properties=[],
                    add_marker=markers[name].append,
                )
            )
        config = SimpleNamespace(
            getoption=lambda _: "integration",
            hook=SimpleNamespace(pytest_deselected=lambda **_: None),
        )
        with (
            patch.dict(os.environ, {"REDJOHN_CI_CAPABILITIES": str(caps)}),
            patch.object(plugin.platform, "system", return_value="Linux"),
        ):
            plugin.pytest_collection_modifyitems(config, items)
        self.assertEqual(len(markers[native.EXCLUDED_BROWSER.split("::")[1]]), 1)
        self.assertEqual(
            markers["test_actual_owner_preserves_inherited_terminal_io"], []
        )
        self.assertIn(
            (
                "required_runner_capabilities",
                "browser_available,cgroup_available,namespace_available",
            ),
            items[0].user_properties,
        )

    def test_relaxed_global_controls_bad_profile_or_missing_native_version_are_blocked(
        self,
    ):
        for defect in ("global", "profile", "version"):
            self.complete()
            if defect == "version":
                path = self.out / "native-preparation.junit.xml"
                tree = ET.parse(path)
                tree.getroot().remove(tree.getroot().find("properties"))
                tree.write(path)
            else:
                cap = json.loads((self.out / "capabilities.json").read_text())
                cap[
                    "apparmor_profile"
                    if defect == "profile"
                    else "apparmor_restrict_unprivileged_userns"
                ] = "unconfined" if defect == "profile" else "0"
                self.put("capabilities.json", cap)
            self.assertEqual(self.run_summary()[0], 1)

    def test_workflow_scope_pins_and_independent_concurrency_match_native_scripts(self):
        path = Path(__file__).parents[1] / "workflows/redjohn-native-components.yml"
        workflow = yaml.safe_load(path.read_text())
        job = workflow["jobs"]["native"]
        self.assertEqual(job["timeout-minutes"], 60)
        self.assertFalse(job["strategy"]["fail-fast"])
        self.assertIn("redjohn-native-components-", workflow["concurrency"]["group"])
        self.assertFalse(workflow["concurrency"]["cancel-in-progress"])
        self.assertEqual(
            {item["runner"] for item in job["strategy"]["matrix"]["include"]},
            {"ubuntu-24.04", "ubuntu-24.04-arm"},
        )
        for step in job["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[a-f0-9]{40}$")
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertNotIn("playwright install", commands)
        self.assertIn("native-capability", commands)
        self.assertIn("install-service-scanners.sh", commands)
        self.assertIn("install-preparation-tools.sh", commands)
        for step in job["steps"][-4:]:
            self.assertIn("always()", step.get("if", ""))
        launcher = (SCRIPTS / "linux-tests.sh").read_text()
        for item in native.SUITES.values():
            self.assertIn("RedJohn/tests/" + item["file"], launcher)
        self.assertIn("not " + native.EXCLUDED_BROWSER.split("::")[1], launcher)
        self.assertIn('--reuid="$SUDO_UID"', launcher)


if __name__ == "__main__":
    unittest.main()
