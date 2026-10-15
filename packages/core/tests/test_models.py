"""Unit: canonical model validation (contract anchor behavior)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from redjohn_core.models import (
    Agent,
    AgentLimits,
    AgentMessage,
    AgentRole,
    AgentStatus,
    Evidence,
    Finding,
    FindingSeverity,
    Project,
    Run,
    RunStatus,
    ScopePolicy,
    Target,
    TargetKind,
    ToolInvocation,
    Workspace,
    new_id,
)


def _scope() -> ScopePolicy:
    return ScopePolicy(project_id="prj_x", allowed_targets=["app.acme.test"])


def test_new_id_prefixes() -> None:
    assert new_id("run").startswith("run_")
    assert len(new_id("run")) == 4 + 24


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        Workspace(name="w", slug="w", unexpected_field="nope")


def test_run_requires_scope_and_defaults() -> None:
    with pytest.raises(ValidationError):
        Run(workspace_id="ws_1", project_id="prj_1", name="r")  # type: ignore[call-arg]
    run = Run(workspace_id="ws_1", project_id="prj_1", name="r", scope=_scope())
    assert run.status == RunStatus.CREATED
    assert run.limits == AgentLimits()
    assert run.scope.version == 1


def test_agent_defaults_and_enums() -> None:
    agent = Agent(run_id="run_1", name="Web", task="t")
    assert agent.role == AgentRole.SPECIALIST
    assert agent.status == AgentStatus.PENDING
    assert agent.depth == 0
    dumped = agent.model_dump(mode="json")
    assert dumped["role"] == "specialist"


def test_agent_message_kind_literal() -> None:
    msg = AgentMessage(run_id="run_1", from_agent_id="user", to_agent_id="agt_1", body="hi")
    assert msg.kind == "instruction"
    with pytest.raises(ValidationError):
        AgentMessage(run_id="run_1", from_agent_id="u", to_agent_id="a", body="x",
                     kind="telepathy")  # type: ignore[arg-type]


def test_tool_invocation_status_enum() -> None:
    inv = ToolInvocation(run_id="run_1", agent_id="agt_1", tool="builtin:echo")
    assert inv.status.value == "started"
    assert inv.attempt == 1


def test_finding_and_target_enums() -> None:
    finding = Finding(run_id="run_1", code="F-001", title="t", severity=FindingSeverity.LOW)
    assert finding.status.value == "observation"
    target = Target(project_id="prj_1", value="10.0.0.0/8", kind=TargetKind.CIDR)
    assert target.verification.value == "unverified"


def test_evidence_access_literal() -> None:
    ev = Evidence(run_id="run_1", sha256="0" * 64, mime="text/plain", size_bytes=3,
                  source="tool:inv_x", storage_ref="evd_x.bin")
    assert ev.access == "run"


def test_scope_policy_defaults() -> None:
    scope = _scope()
    assert scope.max_agents == 24
    assert scope.max_concurrent_agents == 6
    assert scope.max_depth == 3


def test_project_serialization_roundtrip() -> None:
    project = Project(workspace_id="ws_1", name="Acme")
    data = project.model_dump(mode="json")
    assert Project.model_validate(data) == project
