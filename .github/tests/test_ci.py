"""Fast tests for the evidence machinery; these are CI contract tests."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("ci", Path(__file__).parents[1] / "scripts/ci.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class EvidenceContract(unittest.TestCase):
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
                patch.object(ci, "identity", return_value={"commit_sha": "abc"}):
            self.assertEqual(ci.summarize(), 1)
            result = json.loads((Path(folder) / "summary.json").read_text())
            self.assertFalse(result["success"])
            self.assertIn("blocked_runner_capability", result["blockers"])

    def test_valid_commands_do_not_hide_skipped_integration(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc"}):
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
                patch.object(ci, "identity", return_value={"commit_sha": "abc"}):
            root = Path(folder)
            for name in ci.REQUIRED:
                (root / (name + ".json")).write_text(json.dumps({"commit_sha": "other", "exit_code": 0,
                    "leaked_descendant_pids_before_cleanup": []}))
            self.assertEqual(ci.summarize(), 1)
            self.assertIn("failed_command:python-integration", json.loads((root / "summary.json").read_text())["blockers"])


if __name__ == "__main__":
    unittest.main()
