"""Seed/check an isolated profile across native package upgrade/removal/reinstall."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("memory_verification", Path(__file__).with_name("verify-native-memory.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

parser = argparse.ArgumentParser()
parser.add_argument("action", choices=["seed", "check"])
parser.add_argument("--root", type=Path, required=True)
args = parser.parse_args()
args.root.mkdir(parents=True, exist_ok=True)
engine = v.Engine(Path("/opt/RedJohn/resources/engine/redjohn-engine"), args.root, 60)
try:
    engine.start()
    if args.action == "seed":
        run = engine.api("/pentests", method="POST", body={
            "name": "Package preservation fixture", "authorized_target": "http://127.0.0.1:9",
            "target_kind": "web_application", "scan_mode": "standard",
        })
        engine.api("/pentests/" + run["run_id"] + "/archive", method="POST")
        provider = engine.api("/integrations/providers", method="POST", body={
            "provider": "custom", "label": "Preservation fixture", "model": "native-fixture",
            "base_url": "http://127.0.0.1:9/v1", "api_key": "package-fixture-private",
        })
        (args.root / "expected.json").write_text(json.dumps({"run_id": run["run_id"], "provider_id": provider["id"]}))
        print("Seeded an archived assessment and an encrypted provider; no assessment started.")
    else:
        expected = json.loads((args.root / "expected.json").read_text())
        run = engine.api("/pentests/" + expected["run_id"])
        assert run["archived_at"] and run["name"] == "Package preservation fixture"
        providers = engine.api("/integrations/providers")["items"]
        assert any(p["id"] == expected["provider_id"] and p["credential_configured"] for p in providers)
        assert "package-fixture-private" not in (engine.profile / "integrations.json").read_text()
        print(json.dumps({"assessment_preserved": True, "encrypted_provider_preserved": True, "passed": True}))
finally:
    engine.stop()
