"""Synthetic workflow/launcher contracts, not actual Linux integration proof."""

import copy
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml


ROOT = Path(__file__).parents[2]
CI_SPEC = importlib.util.spec_from_file_location("controller_test_ci", ROOT / ".github/scripts/ci.py")
ci = importlib.util.module_from_spec(CI_SPEC)
CI_SPEC.loader.exec_module(ci)
SPEC = importlib.util.spec_from_file_location(
    "controller_summary", ROOT / ".github/scripts/controller-summary.py",
)
controller = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {"ci": ci}):
    SPEC.loader.exec_module(controller)


class ControllerLauncherContracts(unittest.TestCase):
    def observations(self):
        return [{"checkpoint": name, "controller_details": {
            "mappings": {"status": "observed", "groups": {"synthetic": {}}},
            "glibc_allocator": {"status": "observed"}, "new_modules_truncated": False,
            "python_allocated_blocks": 1, "live_component_types": {},
        }} for name in (
            "before_synthetic_pressure", "first_browser_job_completed",
            "first_httpx_job_completed", "first_nuclei_job_completed", "after_warmup",
            "after_diagnostic_gc", "after_allocator_trim",
        )]

    def test_complete_synthetic_controller_counter_contract_is_accepted(self):
        controller.validate_details(self.observations(), mixed=True)

    def test_missing_counters_truncated_modules_and_retained_components_are_rejected(self):
        for field, replacement in (
            ("mappings", {"status": "blocked"}),
            ("glibc_allocator", {"status": "blocked"}),
            ("new_modules_truncated", True),
            ("python_allocated_blocks", None),
            ("live_component_types", {controller.RELEASED_TYPES[0]: 1}),
        ):
            value = copy.deepcopy(self.observations())
            value[-2]["controller_details"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                controller.validate_details(value, mixed=True)
        for value in (self.observations()[:-1], self.observations() * 2, []):
            with self.assertRaises(ValueError):
                controller.validate_details(value, mixed=True)

    def test_sudo_dropped_import_path_is_reestablished_after_uid_drop(self):
        source = (ROOT / ".github/scripts/controller-profile-linux.sh").read_text()
        self.assertIn('test "$(pwd -P)" = "${GITHUB_WORKSPACE:?}"', source)
        self.assertLess(source.index("/usr/bin/setpriv"), source.index("PYTHONPATH="))
        self.assertIn('PYTHONPATH="$task_workspace/RedJohn:$task_workspace/.github/scripts"', source)

    def test_workflow_keeps_both_architectures_and_valid_job_contexts(self):
        workflow = yaml.load(
            (ROOT / ".github/workflows/redjohn-controller-memory.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        job = workflow["jobs"]["controller"]
        self.assertEqual({item["runner"] for item in job["strategy"]["matrix"]["include"]},
                         {"ubuntu-24.04", "ubuntu-24.04-arm"})
        self.assertTrue(all("runner." not in value for value in job["env"].values()))
        cases = (ROOT / ".github/scripts/controller-profile-cases.sh").read_text()
        self.assertIn("--memory-budget-mib 2048 --aggregate-budget-mib 4096", cases)
        self.assertIn('"$RUNNER_TEMP/controller-attribution-memory-pool"', cases)
        self.assertNotIn('controller-$task_case-memory-pool', cases)
        self.assertNotIn("--no-sandbox", cases)


if __name__ == "__main__":
    unittest.main()
