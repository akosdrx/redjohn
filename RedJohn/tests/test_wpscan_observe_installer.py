"""Archive budgets and MOCK installer-process fault contracts; no native install."""

import importlib.util
import io
import signal
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


PATH = Path(__file__).resolve().parents[1] / "scripts/install-wpscan-observe.py"
SPEC = importlib.util.spec_from_file_location("wpscan_observe_installer_contract", PATH)
assert SPEC and SPEC.loader
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for name, data, target in entries:
            member = tarfile.TarInfo(name)
            if target is not None:
                member.type, member.linkname = tarfile.SYMTYPE, target
                tar.addfile(member)
            else:
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
    return output.getvalue()


def test_only_reviewed_ruby_aliases_materialize_exact_internal_regular_target():
    data = archive(
        [
            ("arm64/lib/libruby.so.3.3.12", b"owned-target", None),
            ("arm64/lib/libruby.so", b"", "libruby.so.3.3.12"),
            ("arm64/lib/libruby.so.3.3", b"", "libruby.so.3.3.12"),
        ]
    )
    result = INSTALLER.archive_files(data, ruby_root="arm64")
    assert result["arm64/lib/libruby.so"][0] == b"owned-target"
    assert result["arm64/lib/libruby.so.3.3"][0] == b"owned-target"


@pytest.mark.parametrize(
    "entries",
    [
        [("../escape", b"bad", None)],
        [("/absolute", b"bad", None)],
        [("a", b"one", None), ("a", b"two", None)],
        [("arm64/lib/libruby.so", b"", "../../outside")],
        [("arm64/lib/libruby.so", b"", "libruby.so.3.3.12")],
        [("other-link", b"", "regular")],
    ],
)
def test_traversal_duplicate_and_unreviewed_or_dangling_links_are_rejected(entries):
    with pytest.raises(ValueError):
        INSTALLER.archive_files(archive(entries), ruby_root="arm64")


def test_materialized_alias_bytes_still_count_toward_finite_budget(monkeypatch):
    monkeypatch.setattr(INSTALLER, "MAX_TREE", 10)
    data = archive(
        [
            ("arm64/lib/libruby.so.3.3.12", b"owned-six", None),
            ("arm64/lib/libruby.so", b"", "libruby.so.3.3.12"),
        ]
    )
    with pytest.raises(ValueError, match="materialized_archive_byte_budget"):
        INSTALLER.archive_files(data, ruby_root="arm64")


def test_non_linux_installer_refuses_before_reading_or_writing_inputs(tmp_path, monkeypatch):
    monkeypatch.setattr(INSTALLER.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(PATH),
            "--cache",
            str(tmp_path / "cache"),
            "--destination",
            str(tmp_path / "destination"),
            "--logs",
            str(tmp_path / "logs"),
            "--external-operator-component",
        ],
    )
    with pytest.raises(RuntimeError, match="linux_x64_arm64_ci_only"):
        INSTALLER.main()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("failure", ["success", "exit", "timeout"])
def test_mock_owned_process_group_cleanup_on_success_failure_and_timeout(
    tmp_path, monkeypatch, failure
):
    groups, calls = [], []

    class MockProcess:
        pid = 987654321

        def wait(self, timeout):
            calls.append(timeout)
            if failure == "timeout" and len(calls) == 1:
                raise subprocess.TimeoutExpired(["mock"], timeout)
            return 1 if failure == "exit" else 0

    def mock_process(command, **kwargs):
        assert command[:4] == ["unshare", "--user", "--map-root-user", "--net"]
        assert kwargs["start_new_session"] is True
        assert kwargs["env"] == {"CONTROLLED": "yes"}
        return MockProcess()

    monkeypatch.setattr(INSTALLER.subprocess, "Popen", mock_process)
    monkeypatch.setattr(INSTALLER.os, "killpg", lambda pid, sig: groups.append((pid, sig)))
    if failure == "success":
        assert (
            INSTALLER.run_fixed(
                ["/usr/bin/true"], tmp_path, {"CONTROLLED": "yes"}, tmp_path / "build.log", 5
            )
            == ""
        )
    else:
        with pytest.raises((subprocess.CalledProcessError, subprocess.TimeoutExpired)):
            INSTALLER.run_fixed(
                ["/usr/bin/true"], tmp_path, {"CONTROLLED": "yes"}, tmp_path / "build.log", 5
            )
    assert groups and all(row == (MockProcess.pid, signal.SIGKILL) for row in groups)
    assert calls == ([5, 2] if failure == "timeout" else [5])
