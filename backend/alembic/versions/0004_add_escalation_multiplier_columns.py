"""add escalation multiplier columns

Revision ID: 0004_add_escalation_multiplier
Revises: 0003_add_iam_analysis
Create Date: 2026-04-14 00:00:00.000000
"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "0004_add_escalation_multiplier"
down_revision: Union[str, None] = "0003_add_iam_analysis"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add columns for AI risk score escalation tracking."""
    op.add_column(
        "attack_paths",
        sa.Column("ai_escalation_applied", sa.Boolean, nullable=True, server_default="false")
    )
    op.add_column(
        "attack_paths",
        sa.Column("ai_escalation_multiplier", sa.Float, nullable=True)
    )


def downgrade() -> None:
    """Remove escalation multiplier columns."""
    op.drop_column("attack_paths", "ai_escalation_multiplier")
    op.drop_column("attack_paths", "ai_escalation_applied")
