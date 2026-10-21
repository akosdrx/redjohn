"""Synthetic workflow/launcher contracts, not actual Linux integration proof."""

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).parents[2]


class ControllerLauncherContracts(unittest.TestCase):
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
