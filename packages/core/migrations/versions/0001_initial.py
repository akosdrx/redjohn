"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workspaces",
        sa.Column("workspace_id", sa.String(), primary_key=True),
        sa.Column("slug", sa.String(), nullable=False, unique=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_table(
        "projects",
        sa.Column("project_id", sa.String(), primary_key=True),
        sa.Column("workspace_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_projects_workspace_id", "projects", ["workspace_id"])
    op.create_table(
        "targets",
        sa.Column("target_id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_targets_project_id", "targets", ["project_id"])
    op.create_table(
        "scope_policies",
        sa.Column("scope_id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("project_id", "version", name="uq_scope_project_version"),
    )
    op.create_index("ix_scope_policies_project_id", "scope_policies", ["project_id"])
    op.create_table(
        "runs",
        sa.Column("run_id", sa.String(), primary_key=True),
        sa.Column("workspace_id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_runs_workspace_id", "runs", ["workspace_id"])
    op.create_index("ix_runs_project_id", "runs", ["project_id"])
    op.create_index("ix_runs_status", "runs", ["status"])
    op.create_table(
        "agents",
        sa.Column("agent_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("parent_agent_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("delegation_hash", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("run_id", "parent_agent_id", "delegation_hash", name="uq_agent_delegation"),
    )
    op.create_index("ix_agents_run_id", "agents", ["run_id"])
    op.create_index("ix_agents_parent_agent_id", "agents", ["parent_agent_id"])
    op.create_index("ix_agents_status", "agents", ["status"])
    op.create_table(
        "agent_messages",
        sa.Column("message_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("from_agent_id", sa.String(), nullable=False),
        sa.Column("to_agent_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=True),
        sa.Column("correlation_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_agent_messages_run_id", "agent_messages", ["run_id"])
    op.create_index("ix_agent_messages_to_agent_id", "agent_messages", ["to_agent_id"])
    op.create_index(
        "uq_msg_dedup", "agent_messages",
        ["run_id", "from_agent_id", "idempotency_key"],
        unique=True,
        sqlite_where=sa.text("idempotency_key IS NOT NULL"),
    )
    op.create_table(
        "tool_invocations",
        sa.Column("invocation_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("started_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_tool_invocations_run_id", "tool_invocations", ["run_id"])
    op.create_index("ix_tool_invocations_agent_id", "tool_invocations", ["agent_id"])
    op.create_index("ix_tool_invocations_status", "tool_invocations", ["status"])
    op.create_table(
        "terminal_sessions",
        sa.Column("terminal_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_terminal_sessions_run_id", "terminal_sessions", ["run_id"])
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("code", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("run_id", "code", name="uq_finding_run_code"),
    )
    op.create_index("ix_findings_run_id", "findings", ["run_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_table(
        "evidence",
        sa.Column("evidence_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_evidence_run_id", "evidence", ["run_id"])
    op.create_table(
        "skill_refs",
        sa.Column("skill_id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_skill_refs_name", "skill_refs", ["name"])
    op.create_table(
        "mcp_connections",
        sa.Column("mcp_id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False, unique=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_table(
        "reports",
        sa.Column("report_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("format", sa.String(), nullable=False),
        sa.Column("storage_ref", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_index("ix_reports_run_id", "reports", ["run_id"])
    op.create_table(
        "event_store",
        sa.Column("event_id", sa.String(), primary_key=True),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("occurred_at", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("run_id", "seq", name="uq_event_run_seq"),
    )
    op.create_index("ix_event_store_run_id", "event_store", ["run_id"])
    op.create_table(
        "outbox",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(), nullable=False, unique=True),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("published_at", sa.String(), nullable=True),
    )
    op.create_index("ix_outbox_run_id", "outbox", ["run_id"])
    op.create_table(
        "idempotency_keys",
        sa.Column("key", sa.String(), primary_key=True),
        sa.Column("endpoint", sa.String(), primary_key=True),
        sa.Column("payload_hash", sa.String(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("response", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
    )
    op.create_table(
        "run_counters",
        sa.Column("run_id", sa.String(), primary_key=True),
        sa.Column("next_seq", sa.Integer(), nullable=False),
    )
    op.create_table(
        "engine_meta",
        sa.Column("key", sa.String(), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    for table in (
        "engine_meta", "run_counters", "idempotency_keys", "outbox", "event_store",
        "reports", "mcp_connections", "skill_refs", "evidence", "findings",
        "terminal_sessions", "tool_invocations", "agent_messages", "agents",
        "runs", "scope_policies", "targets", "projects", "workspaces",
    ):
        op.drop_table(table)
