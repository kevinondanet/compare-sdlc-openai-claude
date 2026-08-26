# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""
Make scenario completion time a true terminal-state timestamp.

Revision ID: 5d0b7c2e9a41
Revises: 4c9a6e1f2b7d
Create Date: 2026-08-26 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence  # noqa: TC003

import sqlalchemy as sa
from alembic import op

revision: str = "5d0b7c2e9a41"
down_revision: str | None = "4c9a6e1f2b7d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Allow NULL until a run first enters a terminal state."""
    with op.batch_alter_table("ScenarioResultEntries") as batch_op:
        batch_op.alter_column(
            "completion_time",
            existing_type=sa.DateTime(),
            nullable=True,
        )
    op.execute(
        sa.text(
            'UPDATE "ScenarioResultEntries" SET completion_time = NULL '
            "WHERE scenario_run_state NOT IN ('COMPLETED', 'FAILED', 'CANCELLED')"
        )
    )


def downgrade() -> None:
    """Restore the legacy non-null shape for older application versions."""
    op.execute(sa.text('UPDATE "ScenarioResultEntries" SET completion_time = timestamp WHERE completion_time IS NULL'))
    with op.batch_alter_table("ScenarioResultEntries") as batch_op:
        batch_op.alter_column(
            "completion_time",
            existing_type=sa.DateTime(),
            nullable=False,
        )
