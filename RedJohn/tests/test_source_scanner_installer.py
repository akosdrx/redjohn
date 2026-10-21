"""Pinned installer boundary contracts with small synthetic archives, no downloads."""

import io
import runpy
import tarfile
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def installer():
    script = Path(__file__).resolve().parents[1] / "scripts/install-source-scanners.py"
    return runpy.run_path(str(script))


def zip_payload(name, data, *, symlink=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        member = zipfile.ZipInfo(name)
        if symlink:
            member.external_attr = 0o120777 << 16
        archive.writestr(member, data)
    return buffer.getvalue()


def test_source_installer_extracts_only_exact_native_member(installer):
    native = b"\x7fELFsynthetic-archive-contract"
    payload = zip_payload("semgrep/bin/semgrep-core", native)
    assert installer["executable"](payload, "wheel", "semgrep/bin/semgrep-core") == native
    with pytest.raises(ValueError, match="missing"):
        installer["executable"](payload, "wheel", "unexpected")


@pytest.mark.parametrize("symlink", [False, True])
def test_source_installer_rejects_non_native_or_link_member(installer, symlink):
    payload = zip_payload("semgrep/bin/semgrep-core", b"not-native", symlink=symlink)
    with pytest.raises(ValueError):
        installer["executable"](payload, "wheel", "semgrep/bin/semgrep-core")


def test_source_installer_rejects_tar_link_and_missing_member(installer):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        link = tarfile.TarInfo("trivy")
        link.type = tarfile.SYMTYPE
        link.linkname = "/outside"
        archive.addfile(link)
    with pytest.raises(ValueError, match="invalid"):
        installer["executable"](stream.getvalue(), "tar.gz", "trivy")


def test_source_installer_does_not_overwrite_existing_install_or_download(
    installer, monkeypatch, tmp_path
):
    monkeypatch.setattr(installer["platform"], "system", lambda: "Linux")
    monkeypatch.setattr(installer["platform"], "machine", lambda: "aarch64")
    target = tmp_path / "existing-user-install"
    target.mkdir()
    sentinel = target / "user-file"
    sentinel.write_text("preserve")
    with pytest.raises(ValueError, match="exists_no_overwrite"):
        installer["install"]("trivy", target)
    assert sentinel.read_text() == "preserve"


def test_source_installer_rejects_unreviewed_platform_before_network(installer, monkeypatch):
    monkeypatch.setattr(installer["platform"], "system", lambda: "UnreviewedOS")
    with pytest.raises(ValueError, match="platform_not_reviewed"):
        installer["install"]("semgrep")


def test_source_installer_pins_exact_bundled_native_libraries(installer):
    native = b"\x7fELFowned-small-library"
    member = "semgrep-1.181.0.data/purelib/semgrep/bin/semgrep-core"
    library = str(Path(member).parent / "libs/libowned.so.1")
    payload = zip_payload(library, native)
    assert installer["native_libraries"](payload, member, ["libowned.so.1"]) == {
        "libowned.so.1": native
    }
    with pytest.raises(ValueError, match="missing"):
        installer["native_libraries"](payload, member, ["libmissing.so.1"])
    with pytest.raises(ValueError, match="name_invalid"):
        installer["native_libraries"](payload, member, ["../libescape.so.1"])
    with pytest.raises(ValueError, match="invalid"):
        installer["native_libraries"](
            zip_payload(library, native, symlink=True), member, ["libowned.so.1"]
        )
