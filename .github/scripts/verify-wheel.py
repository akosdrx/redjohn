#!/usr/bin/env python3
"""Verify actual built license payloads; metadata alone is not wheel evidence."""

import hashlib
import json
import re
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
expected_name = re.sub(r"[-_.]+", "_", project["name"]).lower()
wheels = list((ROOT / "artifacts/build").glob(expected_name + "-*.whl"))
if len(wheels) != 1:
    raise SystemExit("exactly_one_built_redjohn_wheel_required")
wheel = wheels[0]
with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
    if len(metadata_names) != 1:
        raise SystemExit("exactly_one_wheel_metadata_required")
    metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
    if re.sub(r"[-_.]+", "_", metadata.get("Name", "")).lower() != expected_name:
        raise SystemExit("built_wheel_brand_identity_mismatch")
    if metadata.get("Version") != project["version"]:
        raise SystemExit("built_wheel_version_mismatch")
    if metadata.get("License-Expression", metadata.get("License")) != "Apache-2.0":
        raise SystemExit("built_wheel_license_metadata_mismatch")
    license_files = {}
    for filename in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        expected = (ROOT / filename).read_bytes()
        members = [name for name in names if name.endswith(".dist-info/licenses/" + filename)]
        if len(members) != 1 or archive.read(members[0]) != expected:
            raise SystemExit("built_wheel_required_license_payload_missing_or_changed")
        license_files[members[0]] = hashlib.sha256(expected).hexdigest()
result = {"wheel": wheel.name, "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
          "distribution": metadata["Name"], "version": metadata["Version"],
          "license_expression": "Apache-2.0", "license_files_sha256": license_files,
          "scope": "package payload verification; full dependency legal audit remains separate"}
(ROOT / "artifacts/wheel-license.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
