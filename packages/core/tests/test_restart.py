"""Integration (b): engine restart mid-run.

Crash while a tool invocation is in flight -> on the next boot the invocation
moves to ``unknown`` and is NEVER blindly re-executed; agents resume from the
durable LangGraph checkpoint and finish their scripted flow.
"""

from __future__ import annotations

from pathlib import Path

from redjohn_core.engine import Engine
from redjohn_core.models import AgentStatus, ToolInvocationStatus

from .conftest import RESTART_SCRIPT, crash_engine, make_run_in, make_settings, wait_for


async def test_engine_restart_mid_run(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, fixture_script=RESTART_SCRIPT)
    eng1 = await Engine.create(settings)
    from redjohn_core.models import RunStatus
    from redjohn_core.runs import start_run

    run = await make_run_in(eng1.store, status=RunStatus.CREATED)
    await start_run(eng1, run.run_id)

    # wait until the specialist's exec invocation is durably STARTED
    async def exec_started() -> bool:
        invs = await eng1.store.list_invocations(run.run_id)
        return any(i.tool == "builtin:exec" and i.status == ToolInvocationStatus.STARTED
                   for i in invs)

    await wait_for(exec_started, timeout=30)
    invs_before = await eng1.store.list_invocations(run.run_id)
    started = [i for i in invs_before
               if i.tool == "builtin:exec" and i.status == ToolInvocationStatus.STARTED]
    assert len(started) == 1
    crashed_inv_id = started[0].invocation_id

    # hard kill: no graceful finalize writes
    await crash_engine(eng1)

    # ---- boot a fresh engine on the same profile -------------------------------
    eng2 = await Engine.create(settings)
    try:
        inv = await eng2.store.get_invocation(crashed_inv_id)
        assert inv is not None
        assert inv.status == ToolInvocationStatus.UNKNOWN
        assert "restart" in (inv.error or "")

        # agents resume; Web completes its script without re-running the exec
        async def web_done() -> bool:
            agents = await eng2.store.list_agents(run.run_id)
            return any(a.name == "Web" and a.status == AgentStatus.COMPLETE for a in agents)

        await wait_for(web_done, timeout=60)

        # no blind re-execution: still exactly one builtin:exec invocation row
        invs_after = await eng2.store.list_invocations(run.run_id)
        exec_invs = [i for i in invs_after if i.tool == "builtin:exec"]
        assert len(exec_invs) == 1
        assert exec_invs[0].invocation_id == crashed_inv_id
        assert exec_invs[0].status == ToolInvocationStatus.UNKNOWN

        # the follow-up scripted step DID run (echo after the lost invocation)
        echo_invs = [i for i in invs_after if i.tool == "builtin:echo"]
        assert echo_invs and echo_invs[0].status == ToolInvocationStatus.COMPLETED

        # run state restored and still live
        run2 = await eng2.store.get_run(run.run_id)
        assert run2.status.value == "running"
    finally:
        from redjohn_core.runs import stop_run

        await stop_run(eng2, run.run_id)
        await eng2.shutdown()
