"""workspace_counters table for Run.ref per-workspace sequence

Revision ID: 0002_workspace_counters
Revises: 0001_initial
Create Date: 2026-10-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_workspace_counters"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workspace_counters",
        sa.Column("workspace_id", sa.String(), primary_key=True),
        sa.Column("next_ref", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("workspace_counters")
