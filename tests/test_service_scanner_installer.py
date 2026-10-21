"""Archive/build identity contracts; no Nmap build or scanner execution occurs."""

import importlib.util
import io
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from redjohn.assessment.service_tools import PROBE_SHA256


MODULE = Path(__file__).resolve().parents[1] / "scripts/install-service-scanners.py"
spec = importlib.util.spec_from_file_location("redjohn_service_installer", MODULE)
assert spec is not None and spec.loader is not None
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "escape", "wrong-root", "duplicate"])
def test_source_build_extraction_rejects_links_escape_and_aliases(tmp_path, kind):
    target = tmp_path / "source.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        member = tarfile.TarInfo("root/file")
        member.size = 1
        if kind == "symlink":
            member.type, member.linkname = tarfile.SYMTYPE, "/outside"
            member.size = 0
        elif kind == "hardlink":
            member.type, member.linkname = tarfile.LNKTYPE, "root/elsewhere"
            member.size = 0
        elif kind == "escape":
            member.name = "root/../outside"
        elif kind == "wrong-root":
            member.name = "not-reviewed/file"
        archive.addfile(member, io.BytesIO(b"x") if member.size else None)
        if kind == "duplicate":
            archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="schema_or_budget"):
        installer.extract(target, tmp_path / "out", "root")
    assert not (tmp_path / "outside").exists()


def test_compiled_version_is_assembled_from_actual_source_and_probe_literal_is_pinned(tmp_path):
    (tmp_path / "nmap.h").write_text(
        '#define NMAP_MAJOR 7\n#define NMAP_MINOR 992\n#define NMAP_SPECIAL ""\n'
    )
    assert installer.source_version(tmp_path) == "7.992"
    (tmp_path / "nmap.h").write_text(
        '#define NMAP_MAJOR 7\n#define NMAP_MINOR 992\n#define NMAP_SPECIAL "SVN"\n'
    )
    assert installer.source_version(tmp_path) == "7.992SVN"
    assert installer.profile_identity()["sha256"] == PROBE_SHA256


def test_build_helper_timeout_reaps_its_actual_owned_process(tmp_path):
    """Real fixed Python helper process, not an engine or compiler build."""
    with pytest.raises(subprocess.TimeoutExpired):
        installer.run_fixed(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            tmp_path,
            {"PATH": "/usr/bin:/bin"},
            1,
        )
    with pytest.raises(subprocess.CalledProcessError) as failure:
        installer.run_fixed(
            [sys.executable, "-c", "raise SystemExit(7)"], tmp_path, {"PATH": "/usr/bin:/bin"}, 1
        )
    assert failure.value.returncode == 7
