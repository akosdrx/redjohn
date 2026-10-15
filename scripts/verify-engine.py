"""Probe an engine executable outside the checkout with an isolated fixture profile."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def verify(binary: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="redjohn-packaged-smoke-") as directory:
        root = Path(directory)
        profile = root / "profiles" / "smoke"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        # Deliberately exclude provider secrets and PYTHONPATH. The frozen
        # executable must discover everything it needs in its own bundle.
        env = {
            "HOME": str(root),
            "PATH": os.defpath,
            "REDJOHN_HOME": str(profile.parent),
            "REDJOHN_PROFILE": profile.name,
            "RJ_MODEL_PROVIDER": "fixture",
        }
        if os.name == "nt":
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
        log = root / "engine.log"
        with log.open("w") as output:
            proc = subprocess.Popen(
                [str(binary), "--host", "127.0.0.1", "--port", str(port)],
                cwd=root, env=env, stdout=output, stderr=output,
            )
            try:
                deadline = time.monotonic() + 60
                ready = False
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise RuntimeError(f"engine exited {proc.returncode}: {log.read_text()[-6000:]}")
                    lock = profile / "profile.lock"
                    if lock.exists():
                        try:
                            record = json.loads(lock.read_text())
                            request = urllib.request.Request(
                                f"http://127.0.0.1:{port}/api/v1/status",
                                headers={"Authorization": f"Bearer {record['token']}"},
                            )
                            with urllib.request.urlopen(request, timeout=1) as response:
                                body = json.load(response)
                                ready = response.status == 200 and "services" in body
                            if ready:
                                break
                        except (OSError, ValueError, urllib.error.URLError):
                            pass
                    time.sleep(.2)
                if not ready:
                    raise RuntimeError(f"engine never became ready: {log.read_text()[-6000:]}")
                def api_get(path: str) -> dict:
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/v1{path}",
                        headers={"Authorization": f"Bearer {record['token']}"},
                    )
                    with urllib.request.urlopen(request, timeout=5) as response:
                        return json.load(response)

                skills = api_get("/skills?limit=50")
                names = {item["name"]: item["skill_id"] for item in skills["items"]}
                required = {"00-master-pentest-methodology", "scan-low", "scan-standard", "scan-high", "scan-deep"}
                if not required.issubset(names):
                    raise RuntimeError("Frozen engine is missing the required bundled skill profiles")
                content = api_get(f"/skills/{names['scan-low']}?include_content=1")
                if "Low scan profile" not in content.get("content", ""):
                    raise RuntimeError("Frozen engine cannot read its bundled skill content")
                # A no-op __init__.py executable cannot pass this check.
                print(json.dumps({"engine": str(binary), "authenticated_status": 200,
                                  "profile_lock": True, "isolated_cwd": True,
                                  "bundled_skill_count": skills.get("total"),
                                  "scan_profiles_readable": True,
                                  "contract_version": body.get("contract_version")}))
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                if (profile / "profile.lock").exists():
                    raise RuntimeError("engine did not clean up its profile lock on SIGTERM")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    verify(parser.parse_args().binary.resolve())
