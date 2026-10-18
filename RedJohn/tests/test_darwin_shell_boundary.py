"""Platform-independent fault contracts; these do not claim real Seatbelt execution."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from redjohn.assessment.egress import EgressUnavailable
from redjohn.assessment.resources import ResourceGovernor
from redjohn.runtime.darwin_shell_boundary import DarwinShellEgressBoundary
from redjohn.runtime.legacy_execution import LegacyExecution


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:12345",
        "http://localhost:12345",
        "http://[::1]:12345",
        "http://operator:secret@127.0.0.1:12345",
        "http://127.0.0.1:12345/endpoint",
    ],
)
def test_controller_proxy_must_be_one_literal_ipv4_http_endpoint(tmp_path, url):
    pool = ResourceGovernor()
    try:
        with pytest.raises(EgressUnavailable, match="proxy_endpoint_invalid"):
            DarwinShellEgressBoundary(
                url, tmp_path, filesystem_profile="(version 1)(allow default)", governor=pool
            )
    finally:
        pool.close()


async def test_missing_seatbelt_is_blocked_and_leaves_no_reservation(tmp_path, monkeypatch):
    pool = ResourceGovernor()
    boundary = DarwinShellEgressBoundary(
        "http://127.0.0.1:12345",
        tmp_path,
        filesystem_profile="(version 1)(allow default)",
        governor=pool,
    )
    temporary = boundary.environment["TMPDIR"]
    monkeypatch.setattr("redjohn.runtime.darwin_shell_boundary.sys.platform", "darwin")
    monkeypatch.setattr(
        "redjohn.runtime.darwin_shell_boundary.shutil.which", lambda *_args, **_kwargs: None
    )
    with pytest.raises(EgressUnavailable, match="seatbelt_unavailable"):
        await boundary.start()
    with pytest.raises(EgressUnavailable, match="not_attested"):
        boundary.wrap_argv(["/usr/bin/true"])
    assert boundary.attestations == ()
    await boundary.close()
    assert not (tmp_path / temporary).exists()
    assert pool.snapshot()["active"] == {}
    pool.close()


async def test_failed_probe_cleanup_retains_owner_and_never_uses_unbound_shell(
    tmp_path, monkeypatch
):
    pool = ResourceGovernor()
    owner = LegacyExecution(
        tmp_path / "agents.db",
        pool,
        control=SimpleNamespace(),
        shell_transport=SimpleNamespace(
            request_admission=lambda _: None, tls_config=None, on_response=None
        ),
    )

    class FaultBoundary:
        def __init__(self, *_args, **_kwargs):
            self.lease = None
            self.cleanups = 0

        async def start(self):
            self.lease = pool.acquire("worker", estimated_bytes=1024)
            raise EgressUnavailable("owned_probe_failed")

        def assert_active(self):
            raise EgressUnavailable("owned_probe_not_attested")

        async def close(self):
            self.cleanups += 1
            if self.cleanups < 3:
                raise RuntimeError("owned_probe_cleanup_unconfirmed")
            self.lease.release()

    monkeypatch.setattr("redjohn.runtime.legacy_shell_boundary.LegacyShellBoundary", FaultBoundary)
    with pytest.raises(EgressUnavailable, match="owned_probe_failed"):
        await owner._ensure_shell_boundary()
    assert owner._shell_boundary is not None
    assert pool.snapshot()["active"] == {"worker": 1}
    with pytest.raises(EgressUnavailable, match="owned_probe_not_attested"):
        await owner._ensure_shell_boundary()
    with pytest.raises(RuntimeError, match="cleanup_unconfirmed"):
        await owner.close()
    assert pool.snapshot()["active"] == {"worker": 1}
    await owner.close()
    assert pool.snapshot()["active"] == {}
    pool.close()
