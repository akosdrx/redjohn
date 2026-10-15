"""Unit: RunEvent per-type data validation against contracts/run-event.schema.json."""

from __future__ import annotations

import pytest
from redjohn_core.errors import RJError
from redjohn_core.eventlog import make_event, validate_event
from redjohn_core.events import EventType, RunEvent
from redjohn_core.models import Run, ScopePolicy


def _run() -> Run:
    return Run(workspace_id="ws_1", project_id="prj_1", name="r",
               scope=ScopePolicy(project_id="prj_1"))


def _finalize(event: RunEvent) -> RunEvent:
    event.seq = 1  # server assigns >= 1 at commit
    return event


def test_valid_agent_message_event() -> None:
    ev = _finalize(make_event(_run(), EventType.AGENT_MESSAGE, {
        "message_id": "msg_1", "from_agent_id": "user", "to_agent_id": "agt_1",
        "kind": "instruction", "body": "hello",
    }))
    validate_event(ev)


def test_valid_tool_events() -> None:
    for etype, data in [
        (EventType.TOOL_STARTED, {"invocation_id": "inv_1", "tool": "builtin:echo", "status": "started"}),
        (EventType.TOOL_OUTPUT, {"invocation_id": "inv_1", "tool": "builtin:echo", "chunk": "hi"}),
        (EventType.TOOL_COMPLETED, {"invocation_id": "inv_1", "tool": "builtin:echo",
                                    "status": "completed", "exit_code": 0}),
    ]:
        validate_event(_finalize(make_event(_run(), etype, data)))


def test_valid_finding_event() -> None:
    validate_event(_finalize(make_event(_run(), EventType.FINDING_CREATED, {
        "finding_id": "fnd_1", "code": "F-001", "title": "t", "severity": "low",
        "status": "observation", "target": "app.acme.test",
    })))


def test_finding_event_missing_title_rejected() -> None:
    ev = _finalize(make_event(_run(), EventType.FINDING_CREATED, {
        "finding_id": "fnd_1", "code": "F-001", "severity": "low", "status": "observation",
    }))
    with pytest.raises(RJError) as excinfo:
        validate_event(ev)
    assert excinfo.value.code == "event_schema_violation"


def test_finding_event_bad_severity_rejected() -> None:
    ev = _finalize(make_event(_run(), EventType.FINDING_CREATED, {
        "finding_id": "fnd_1", "code": "F-001", "title": "t", "severity": "catastrophic",
        "status": "observation",
    }))
    with pytest.raises(RJError):
        validate_event(ev)


def test_seq_zero_rejected_by_schema() -> None:
    ev = make_event(_run(), EventType.RUN_STATUS, {"run_id": "run_1", "status": "created"})
    assert ev.seq == 0  # not yet assigned
    with pytest.raises(RJError):
        validate_event(ev)


def test_schema_version_const() -> None:
    ev = _finalize(make_event(_run(), EventType.RUN_STATUS, {"run_id": "run_1", "status": "created"}))
    object.__setattr__(ev, "schema_version", 2)
    with pytest.raises(RJError):
        validate_event(ev)
