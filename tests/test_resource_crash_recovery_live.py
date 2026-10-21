"""Real process death and OAST crash followed by another campaign's Chromium.

Both campaigns share one host ledger. The existing receiver/crash/restart
control still verifies an unknown poll outcome and zero duplicate target sends.
No engine, controller exit, memory observation or job result is mocked here.
"""

import asyncio
import json
import sys
from contextlib import closing, suppress
from dataclasses import replace

import pytest

from redjohn.assessment.host_resources import HostResourcePool
from redjohn.assessment.resources import MIB, ResourceAdmissionError, ResourceGovernor
from redjohn.assessment.store import AssessmentStore
from tests.test_schema_oast_live import (
    test_actual_interactsh_draining_poll_process_crash_is_not_a_negative as run_oast_crash,
)
from tests.test_specialists_live import capture, owned_fixture, policy_for


@pytest.mark.parametrize("with_unknown_lease", [False, True], ids=["in-process", "mixed"])
async def test_actual_owner_death_reclaims_only_explicit_process_lifetime(
    tmp_path, with_unknown_lease
):
    pool = HostResourcePool(tmp_path / "host.sqlite3")
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        """import json,sys
from redjohn.assessment.host_resources import HostResourcePool
from redjohn.assessment.resources import ResourceGovernor
governor=ResourceGovernor(host_pool=HostResourcePool(sys.argv[1]))
lease=governor.acquire('worker',1024*1024,owner_process_only=True)
unknown=governor.acquire('worker',1024*1024) if sys.argv[2]=='1' else None
print(json.dumps({'ready':True}),flush=True)
sys.stdin.readline()
""",
        str(pool.path),
        "1" if with_unknown_lease else "0",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        assert child.stdout is not None
        assert json.loads(await asyncio.wait_for(child.stdout.readline(), 10)) == {"ready": True}
        assert pool.recover() == 0  # A live owner is never expired by a timeout.
        child.kill()
        await asyncio.wait_for(child.wait(), 5)
        governor = ResourceGovernor(host_pool=pool)
        if with_unknown_lease:
            with pytest.raises(ResourceAdmissionError, match="host_owner_lost_requires_recovery"):
                governor.acquire("worker", MIB)
            # Even a denied admission rolls recovery back atomically. Explicit
            # recovery can remove the classified lease, never the unknown one.
            assert pool.recover() == 1
            assert pool.snapshot()["active"] == {"worker": 1}
            assert pool.snapshot()["admission_blocked"] is True
        else:
            with governor.acquire("worker", MIB):
                assert pool.snapshot()["lost_owners"] == 0
                assert pool.snapshot()["active"] == {"worker": 1}
            assert pool.snapshot()["active"] == {}
        governor.close()
    finally:
        if child.returncode is None:
            with suppress(ProcessLookupError):
                child.kill()
            await asyncio.wait_for(child.wait(), 5)


async def test_actual_oast_controller_crash_does_not_block_another_campaign(tmp_path, monkeypatch):
    pool_path = tmp_path / "host.sqlite3"
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(pool_path))
    crash_root = tmp_path / "crashed-campaign"
    crash_root.mkdir()
    await run_oast_crash(crash_root)

    with (
        owned_fixture("127.0.0.1", tmp_path / "next-tls") as fixture,
        closing(AssessmentStore(tmp_path / "next-campaign/agents.db")) as store,
    ):
        policy = replace(policy_for(fixture, remote=False), engagement_id="after-oast-crash")
        _, surface = await capture(store, policy, fixture, fixture.origin + "/params")
        assert surface.request_ref
        assert any(row["path"] == "/params" for row in fixture.wire)

    snapshot = HostResourcePool(pool_path).snapshot()
    assert snapshot["active"] == {}
    assert snapshot["lost_owners"] == 0
    assert snapshot["admission_blocked"] is False
