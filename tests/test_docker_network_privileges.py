"""Container-create contracts with a fake Docker API; not live Docker attestation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from agents.sandbox.manifest import Manifest

from redjohn.runtime.docker_client import RedJohnDockerSandboxClient, _drop_network_privileges


@pytest.mark.parametrize(
    "existing",
    [{}, {"cap_add": ["SYS_ADMIN", "NET_ADMIN", "CAP_NET_RAW"]}, {"cap_drop": ["SYS_PTRACE"]}],
)
def test_network_capabilities_are_dropped_including_docker_default_raw(existing):
    options = {**existing}
    _drop_network_privileges(options)
    assert {"NET_ADMIN", "NET_RAW"} <= set(options["cap_drop"])
    assert not {"NET_ADMIN", "NET_RAW", "CAP_NET_RAW"} & set(options["cap_add"])
    if "SYS_ADMIN" in existing.get("cap_add", []):
        assert "SYS_ADMIN" in options["cap_add"]


async def test_create_override_preserves_entrypoint_ports_and_adds_no_network_authority(tmp_path):
    created = []

    def create(**kwargs):
        created.append(kwargs)
        return SimpleNamespace(short_id="fake-docker-no-attestation")

    api = SimpleNamespace(
        images=SimpleNamespace(get=lambda _: object()), containers=SimpleNamespace(create=create)
    )
    client = RedJohnDockerSandboxClient(api)
    await client._create_container(
        "operator-owned-image", manifest=Manifest(root=str(tmp_path)), exposed_ports=(8080,)
    )
    row = created[0]
    assert "entrypoint" not in row
    assert row["command"] == ["tail", "-f", "/dev/null"]
    assert row["cap_add"] == [] and set(row["cap_drop"]) == {"NET_ADMIN", "NET_RAW"}
    assert row["extra_hosts"] == {"host.docker.internal": "host-gateway"}
    assert row["ports"]["8080/tcp"] == ("127.0.0.1", None)
