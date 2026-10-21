"""Transport fault doubles with an actual proxy listener and ephemeral TLS keys.

No Nuclei binary is launched by these tests; live scanner proof is separate.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import pytest

from redjohn.assessment.adapters import NucleiPipelineAdapter
from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.store import AssessmentStore
from redjohn.tools.hunt.nuclei import bundle_digest


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["cleanup", "unbind", "initial_busy"])
async def test_fault_double_closes_actual_proxy_listener_and_tls_files(
    tmp_path, monkeypatch, fault
):
    proxies = []
    transports = []

    class ObservedActualProxy(BrowserEgressProxy):
        async def start(self):
            await super().start()
            self.observed_address = urlsplit(self.url)
            self.observed_directory = self._tls_identity.directory
            assert self.observed_directory.is_dir()
            assert (self.observed_directory / "leaf-key.pem").is_file()
            proxies.append(self)

    class SessionFaultDouble:
        def __init__(self):
            self.binding = "http://127.0.0.1:39999" if fault == "initial_busy" else None
            self.calls = []

        def bind_proxy(self, url):
            self.calls.append(url)
            if url is not None and fault == "initial_busy":
                raise RuntimeError("fault_initial_busy")
            if url is None and fault == "unbind":
                raise RuntimeError("fault_unbind")
            self.binding = url

    class NucleiTransportFaultDouble:
        def __init__(self, *_args, **_kwargs):
            self.cleanup_calls = 0
            transports.append(self)

        async def run(self, *_args, **_kwargs):
            return {
                "execution_status": "succeeded",
                "coverage_status": "inconclusive",
                "findings": [],
                "no_finding_observed": False,
            }

        async def cleanup(self):
            self.cleanup_calls += 1
            if fault == "cleanup":
                raise RuntimeError("fault_cleanup")

    monkeypatch.setattr("redjohn.assessment.browser_proxy.BrowserEgressProxy", ObservedActualProxy)
    monkeypatch.setattr("redjohn.tools.hunt.nuclei.NucleiAdapter", NucleiTransportFaultDouble)
    files = {"marker.yaml": "a" * 64}
    lock = {
        "binary": {
            "path": str(tmp_path / "never-executed-nuclei"),
            "version": "3.11.1",
            "sha256": "b" * 64,
            "source": "transport-fault-double",
            "license": "test-fixture-only",
        },
        "bundle": {
            "root": str(tmp_path / "never-read-bundle"),
            "version": "fault-fixture",
            "sha256": bundle_digest(files),
            "source": "transport-fault-double",
            "license": "test-fixture-only",
            "files": files,
            "templates": [
                {
                    "path": "marker.yaml",
                    "id": "fixture-marker",
                    "profiles": ["isolated-lab"],
                    "effect": "read-only",
                    "protocol": "http",
                }
            ],
        },
    }
    store = AssessmentStore(tmp_path / "agents.db")
    session = SessionFaultDouble()
    try:
        policy = store.register(
            EngagementPolicy(
                "cleanup-fault",
                "operator",
                ("https://127.0.0.1:9443",),
                profile="isolated-lab",
                egress_mode="local-fixture",
            )
        )
        surface = Surface(policy.allowed_origins[0] + "/")
        surface_id = store.upsert_surface(policy.engagement_id, surface)
        spec = JobSpec(
            surface_id,
            "known_vulnerability",
            "nuclei_scan",
            tool_version=lock["binary"]["version"],
            template_version=lock["bundle"]["sha256"],
        )
        adapter = NucleiPipelineAdapter(policy, store, session=session, lock=lock)
        with pytest.raises(RuntimeError, match=f"fault_{fault}"):
            await adapter.run({"id": "fault-job"}, surface, spec)
        assert len(proxies) == 1
        proxy = proxies[0]
        assert proxy._server is None
        assert proxy._tls_identity is None
        assert not proxy._tasks and not proxy._writers
        assert not proxy.observed_directory.exists()
        with pytest.raises(OSError):
            await asyncio.open_connection(
                proxy.observed_address.hostname, proxy.observed_address.port
            )
        if fault == "initial_busy":
            assert session.binding == "http://127.0.0.1:39999"
            assert len(session.calls) == 1
            assert session.calls[0] is not None
            assert not transports
        else:
            assert len(transports) == 1
            assert transports[0].cleanup_calls == 1
            assert len(session.calls) == 2 and session.calls[-1] is None
            if fault == "cleanup":
                assert session.binding is None
    finally:
        store.close()
