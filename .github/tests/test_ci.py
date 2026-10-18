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
        summary = patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""})
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
            for name in ("regression", "integration"):
                (root / (name + ".junit.xml")).write_text('<testsuite><testcase name="fixture"/></testsuite>')
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


if __name__ == "__main__":
    unittest.main()
