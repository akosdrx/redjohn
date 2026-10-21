"""Real private-file approval failures; no model, browser or network request."""

import json
import shutil
import sys
from pathlib import Path

import pytest

from redjohn.assessment.host_binding import prepare_host_assessment
from redjohn.assessment.policy import PolicyDenied
from tests.test_host_binding_contract import scan_for


@pytest.fixture(autouse=True)
def private_host_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("REDJOHN_ASSESSMENT_APPROVAL_KEY", str(tmp_path / "keys/host.key"))
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "pool.sqlite3"))


@pytest.fixture
async def approved_snapshot(tmp_path):
    scan = scan_for("https://example.invalid")
    output = tmp_path / "run"
    prepared = prepare_host_assessment(scan, "snapshot-check", output)
    host = await prepared.start()
    await host.close()
    return scan, output, output / ".state/assessment-host.json"


@pytest.mark.parametrize("mac", ["\u00e9" * 64, "x" * 64, "0" * 63, None])
def test_malformed_approval_mac_is_a_stable_policy_denial(approved_snapshot, mac):
    scan, output, path = approved_snapshot
    saved = json.loads(path.read_text())
    saved["approval_mac"] = mac
    path.write_text(json.dumps(saved))
    with pytest.raises(PolicyDenied, match="assessment_snapshot_changed_without_approval"):
        prepare_host_assessment(scan, "snapshot-check", output)


def test_missing_signing_key_never_reauthorizes_a_saved_snapshot(approved_snapshot, tmp_path):
    scan, output, _path = approved_snapshot
    (tmp_path / "keys/host.key").unlink()
    with pytest.raises(PolicyDenied, match="assessment_approval_key_unavailable"):
        prepare_host_assessment(scan, "snapshot-check", output)
    assert not (tmp_path / "keys/host.key").exists()


def test_approval_snapshot_cannot_be_replayed_in_a_different_run_directory(
    approved_snapshot, tmp_path
):
    scan, _output, path = approved_snapshot
    other = tmp_path / "other-run"
    (other / ".state").mkdir(parents=True, mode=0o700)
    shutil.copyfile(path, other / ".state/assessment-host.json")
    (other / ".state/assessment-host.json").chmod(0o600)
    with pytest.raises(PolicyDenied, match="assessment_snapshot_run_mismatch"):
        prepare_host_assessment(scan, "snapshot-check", other)
    assert not (other / ".state/agents.db").exists()


async def test_rejected_private_key_leaves_no_temporary_file_or_descriptor(tmp_path):
    (tmp_path / "keys").mkdir(mode=0o755)
    (tmp_path / "keys").chmod(0o755)
    descriptor_path = "/proc/self/fd" if sys.platform == "linux" else "/dev/fd"
    before = len(list(Path(descriptor_path).iterdir()))
    for _ in range(3):
        prepared = prepare_host_assessment(
            scan_for("https://example.invalid"), "denied-signature", tmp_path / "run"
        )
        with pytest.raises(PolicyDenied, match="assessment_approval_key_not_private"):
            await prepared.start()
    assert list((tmp_path / "run/.state").glob(".assessment-host-*")) == []
    assert len(list(Path(descriptor_path).iterdir())) == before
    assert not (tmp_path / "run/.state/agents.db").exists()
