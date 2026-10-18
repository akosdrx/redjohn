"""The source publication allowlist must not sweep up generated private files."""

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "snapshot", Path(__file__).parents[1] / "scripts/prepare-snapshot.py"
)
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


class PublicationAllowlist(unittest.TestCase):
    def test_reviewed_json_does_not_grant_other_or_nested_json_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in (
                "docs/redjohn-capabilities.json", "docs/third-party-references.json",
                "docs/redjohn-schemas.json", "docs/readme.md", "RedJohn/module.py",
                "docs/local-credentials.json", "docs/measurements/report.md",
                "docs/nested/redjohn-capabilities.json", "RedJohn/.env.production",
                "RedJohn/.tools/scanner/key.py", "docs/debug-changed-files.md",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}")
            with patch.object(snapshot, "ROOT", root):
                selected = snapshot.selected()
            self.assertEqual(set(selected), {
                "docs/redjohn-capabilities.json", "docs/third-party-references.json",
                "docs/redjohn-schemas.json", "docs/readme.md", "RedJohn/module.py",
            })


if __name__ == "__main__":
    unittest.main()
