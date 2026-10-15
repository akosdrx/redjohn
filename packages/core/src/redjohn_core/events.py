"""RunEvent envelope — canonical event contract (schema_version=1).

Persistence rule: business state change + event row commit in ONE transaction;
delivery to clients happens via the outbox relay. ``seq`` is assigned
server-side per run; clients must never order by wall clock.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import Field

from .models import RJModel, new_id, utcnow


class EventType(str, Enum):
    RUN_STATUS = "run.status"
    AGENT_STATUS = "agent.status"
    AGENT_ACTIVITY = "agent.activity"
    AGENT_MESSAGE = "agent.message"
    TOOL_STARTED = "tool.invocation.started"
    TOOL_OUTPUT = "tool.invocation.output"
    TOOL_COMPLETED = "tool.invocation.completed"
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    TARGET_UPDATED = "target.updated"
    SERVICE_STATUS = "service.status"
    TERMINAL_OUTPUT = "terminal.output"
    USAGE = "usage.event"


class RunEvent(RJModel):
    schema_version: int = 1
    event_id: str = Field(default_factory=lambda: new_id("evt"))
    workspace_id: str
    run_id: str
    seq: int = 0                       # assigned by the server at commit time
    occurred_at: datetime = Field(default_factory=utcnow)
    type: EventType
    agent_id: str | None = None
    correlation_id: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)  # validated per type
