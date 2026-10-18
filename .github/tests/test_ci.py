"""Fast tests for the evidence machinery; these are CI contract tests."""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("ci", Path(__file__).parents[1] / "scripts/ci.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class EvidenceContract(unittest.TestCase):
    def setUp(self):
        # Keep synthetic rejection cases out of the real runner's step summary.
        summary = patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": "", "GITHUB_ACTIONS": "false"})
        summary.start()
        self.addCleanup(summary.stop)

    def test_junit_preserves_failures_errors_skips_and_kinds(self):
        xml = """<testsuites><testsuite><testcase name="real"><properties>
        <property name="evidence_kind" value="real_integration"/></properties></testcase>
        <testcase name="bad"><failure/></testcase><testcase name="oops"><error/></testcase>
        <testcase name="blocked"><skipped message="missing cgroup"/></testcase>
        </testsuite></testsuites>"""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "junit.xml"
            path.write_text(xml)
            result = ci.junit_summary(path)
        self.assertEqual(result["counts"], {"passed": 1, "failed": 1, "errors": 1, "skipped": 1})
        self.assertEqual(result["evidence_kinds"]["real_integration"]["passed"], 1)
        self.assertEqual(result["skips"][0]["reason"], "missing cgroup")

    def test_missing_evidence_cannot_succeed(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            self.assertEqual(ci.summarize(), 1)
            result = json.loads((Path(folder) / "summary.json").read_text())
            self.assertFalse(result["success"])
            self.assertIn("blocked_runner_capability", result["blockers"])

    def test_valid_commands_do_not_hide_skipped_integration(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            for name in ci.REQUIRED:
                (root / (name + ".json")).write_text(json.dumps({"commit_sha": "abc", "exit_code": 0,
                    "leaked_descendant_pids_before_cleanup": []}))
            (root / "capabilities.json").write_text('{"available":true}')
            (root / "regression.junit.xml").write_text('<testsuite><testcase/></testsuite>')
            (root / "integration.junit.xml").write_text('<testsuite><testcase/><testcase><skipped/></testcase></testsuite>')
            self.assertEqual(ci.summarize(), 1)
            self.assertIn("incomplete_suite:integration", json.loads((root / "summary.json").read_text())["blockers"])

    def test_commit_mismatch_cannot_succeed(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            for name in ci.REQUIRED:
                (root / (name + ".json")).write_text(json.dumps({"commit_sha": "other", "exit_code": 0,
                    "leaked_descendant_pids_before_cleanup": []}))
            self.assertEqual(ci.summarize(), 1)
            self.assertIn("failed_command:python-integration", json.loads((root / "summary.json").read_text())["blockers"])

    def test_complete_contract_writes_isolated_github_summary(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            for name in ci.REQUIRED:
                (root / (name + ".json")).write_text(json.dumps({"commit_sha": "abc", "exit_code": 0,
                    "leaked_descendant_pids_before_cleanup": []}))
            (root / "capabilities.json").write_text('{"available":true}')
            (root / "cgroup-cleanup.json").write_text('{"removed":true,"leaked_processes":false}')
            (root / "apparmor-cleanup.json").write_text('{"success":true}')
            (root / "go-tests.log").write_text('{"Package":"fixture","Test":"TestContract","Action":"pass"}\n')
            for name in ("regression", "integration", "frontend"):
                (root / (name + ".junit.xml")).write_text('<testsuite><testcase name="fixture"/></testsuite>')
            (root / "mixed-soak").mkdir()
            (root / "mixed-soak/mixed-soak.json").write_text('{"commit_sha":"abc","ok":true}')
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(root / "summary.md")}):
                self.assertEqual(ci.summarize(), 0)
            self.assertIn("Complete.", (root / "summary.md").read_text())
            self.assertTrue((root / "go.junit.xml").exists())
            index = json.loads((root / "evidence-index.json").read_text())
            self.assertEqual(index["commit_sha"], "abc")
            self.assertIn("summary.json", index["files"])

    def test_missing_browser_does_not_hide_supported_native_or_kernel_cases(self):
        spec = importlib.util.spec_from_file_location("evidence", Path(__file__).parents[1] / "scripts/pytest_evidence.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            capability = root / "capabilities.json"
            capability.write_text('{"browser_available":false,"namespace_available":false,"cgroup_available":true}')
            items, markers = [], {}
            for filename, name in (("test_nuclei_live.py", "test_live_pinned_nuclei_native_marker_then_fixed_control"),
                                   ("test_os_memory_live.py", "test_actual_kernel_memory_max_kills_oversized_tree"),
                                   ("test_assessment_browser.py", "test_real_chromium_request_admission_and_response_callbacks")):
                path = root / filename
                path.write_text("")
                markers[name] = []
                items.append(SimpleNamespace(path=path, originalname=name, name=name,
                    user_properties=[], add_marker=markers[name].append))
            config = SimpleNamespace(getoption=lambda _: "integration",
                hook=SimpleNamespace(pytest_deselected=lambda **_: None))
            with patch.dict(os.environ, {"REDJOHN_CI_CAPABILITIES": str(capability)}):
                plugin.pytest_collection_modifyitems(config, items)
            self.assertEqual(len(items), 3)
            self.assertFalse(markers["test_live_pinned_nuclei_native_marker_then_fixed_control"])
            self.assertFalse(markers["test_actual_kernel_memory_max_kills_oversized_tree"])
            self.assertEqual(len(markers["test_real_chromium_request_admission_and_response_callbacks"]), 1)

    def test_zero_go_functions_are_recorded_without_inventing_passed_tests(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            (root / "go-tests.log").write_text('{"Package":"fixture","Action":"skip"}\n')
            self.assertEqual(ci.summarize(), 1)  # Other required evidence is deliberately absent.
            result = json.loads((root / "summary.json").read_text())
            self.assertEqual(result["go_tests"], {"passed": 0, "failed": 0, "skipped": 0})
            self.assertEqual(result["go_test_coverage"], "no_test_functions_defined")
            self.assertNotIn("missing_go_results", result["blockers"])
            self.assertIn("incomplete_go_tests", result["blockers"])

    def test_soak_cannot_succeed_for_another_commit_or_a_failed_check(self):
        for payload in ({"commit_sha": "other", "ok": True}, {"commit_sha": "abc", "ok": False}):
            with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                    patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
                root = Path(folder)
                (root / "mixed-soak").mkdir()
                (root / "mixed-soak/mixed-soak.json").write_text(json.dumps(payload))
                self.assertEqual(ci.summarize(), 1)
                self.assertIn("incomplete_mixed_soak", json.loads((root / "summary.json").read_text())["blockers"])

    def test_node_junit_direct_testcase_children_are_counted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "frontend.junit.xml"
            path.write_text('<testsuites><testcase name="parser"/><testcase name="fetch"><failure/></testcase></testsuites>')
            self.assertEqual(ci.junit_summary(path)["counts"], {"passed": 1, "failed": 1, "skipped": 0, "errors": 0})

    def test_reviewed_node_fetch_double_stays_distinct_from_real_http(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "frontend.junit.xml"
            name = "dropped POST transport is an explicit failure and the next action can retry"
            path.write_text(f'<testsuites><testcase name="{name}" file="/owned/tests/server-source.test.mjs"/></testsuites>')
            result = ci.junit_summary(path)
            self.assertEqual(result["evidence_kinds"]["mock_contract"]["passed"], 1)
            self.assertNotIn("real_integration", result["evidence_kinds"])

    def test_actual_node22_format_without_file_attributes_keeps_fetch_double_label(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "frontend.junit.xml"
            name = "steering preserves agent and message, HTTP rejection stays failure"
            path.write_text(f'<testsuites><testcase name="{name}" classname="test"/>'
                            '<testcase name="parser" classname="test"/></testsuites>')
            result = ci.junit_summary(path)
            self.assertEqual(result["counts"]["passed"], 2)
            self.assertEqual(result["evidence_kinds"]["mock_contract"]["passed"], 1)
            self.assertEqual(result["evidence_kinds"]["unit_contract_or_mixed"]["passed"], 1)

    def test_darwin_cases_are_explicitly_not_applicable_and_namespace_blocks_stay_visible(self):
        spec = importlib.util.spec_from_file_location("evidence", Path(__file__).parents[1] / "scripts/pytest_evidence.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            capability = root / "capabilities.json"
            capability.write_text('{"browser_available":false,"namespace_available":false}')
            items, markers, deselected = [], {}, []
            for filename in ("test_legacy_shell_darwin_live.py", "test_source_tools_live.py"):
                path = root / filename
                path.write_text("")
                markers[filename] = []
                items.append(SimpleNamespace(path=path, originalname="test_real", name="test_real",
                    nodeid=filename + "::test_real", user_properties=[], add_marker=markers[filename].append))
            config = SimpleNamespace(getoption=lambda _: "integration",
                hook=SimpleNamespace(pytest_deselected=lambda **kw: deselected.extend(kw["items"])))
            with patch.dict(os.environ, {"REDJOHN_CI_CAPABILITIES": str(capability),
                                        "GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(root)}), \
                    patch.object(plugin.platform, "system", return_value="Linux"):
                plugin.pytest_collection_modifyitems(config, items)
            self.assertEqual([item.nodeid for item in deselected], ["test_legacy_shell_darwin_live.py::test_real"])
            self.assertEqual(len(items), 1)
            self.assertEqual(len(markers["test_source_tools_live.py"]), 1)
            evidence = json.loads((root / "artifacts/non-applicable-integration.json").read_text())
            self.assertEqual(len(evidence["cases"]), 1)
            self.assertEqual(evidence["cases"][0]["required_platform"], "Darwin")
            self.assertIn("not_passed", evidence["cases"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
