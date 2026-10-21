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
            "mappings": {"status": "observed", "mapping_count": 1, "groups": {
                "synthetic": {"mappings": 1, "Size_bytes": 1, "Rss_bytes": 1,
                              "Pss_bytes": 1, "Private_Clean_bytes": 0, "Private_Dirty_bytes": 1}}},
            "glibc_allocator": {"status": "observed", **dict.fromkeys((
                "arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks", "fsmblks",
                "uordblks", "fordblks", "keepcost"), 0)}, "new_modules_truncated": False,
            "python_allocated_blocks": 1, "live_component_types": {}, "module_count": 1,
            "new_modules": [], "linecache_files": 0, "linecache_source_bytes": 0,
            "gc_tracked_objects": 0,
        }} for name in sorted(ci.CONTROLLER_MIXED_PHASES)]

    def test_complete_synthetic_controller_counter_contract_is_accepted(self):
        self.assertIs(controller.validate_details, ci.validate_controller_details)
        self.assertIs(controller.RELEASED_TYPES, ci.RELEASED_TYPES)
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
            after_gc = next(item for item in value if item["checkpoint"] == "after_diagnostic_gc")
            after_gc["controller_details"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                controller.validate_details(value, mixed=True)

    def test_observed_status_without_numeric_allocator_or_mapping_counters_is_rejected(self):
        for field, replacement in (
            ("mappings", {"status": "observed", "groups": {"synthetic": {}}}),
            ("glibc_allocator", {"status": "observed"}),
            ("python_allocated_blocks", True),
            ("new_modules", ["repeated", "repeated"]),
            ("live_component_types", {"synthetic.Type": -1}),
        ):
            value = self.observations()
            value[0]["controller_details"][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                controller.validate_details(value, mixed=True)

    def test_pymalloc_gate_requires_both_actual_numeric_counter_sets(self):
        valid = {phase: {"status": "observed", **dict.fromkeys(ci.PYMALLOC_COUNTERS, 1)}
                 for phase in ("before_asyncio_run", "after_asyncio_run")}
        ci.validate_controller_pymalloc(valid)
        for replacement in (None, {"status": "blocked"}, {"status": "observed"},
                            {**valid["after_asyncio_run"], "arena_size_bytes": 0}):
            value = copy.deepcopy(valid)
            value["after_asyncio_run"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                controller.validate_controller_pymalloc(value)
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
