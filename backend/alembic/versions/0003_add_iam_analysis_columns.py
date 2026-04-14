"""add IAM privilege escalation analysis columns

Revision ID: 0003_add_iam_analysis
Revises: 0002_add_blast_radius
Create Date: 2026-04-12 00:00:00.000000
"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_add_iam_analysis"
down_revision: Union[str, None] = "0002_add_blast_radius"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add columns for deep IAM privilege escalation analysis."""
    op.add_column(
        "attack_paths",
        sa.Column("ai_privilege_escalation", postgresql.JSON, nullable=True)
    )
    op.add_column(
        "attack_paths",
        sa.Column("ai_escalation_techniques", postgresql.JSON, nullable=True)
    )
    op.add_column(
        "attack_paths",
        sa.Column("ai_true_risk_assessment", sa.Text, nullable=True)
    )
    op.add_column(
        "attack_paths",
        sa.Column("ai_remediation_priority", sa.String(32), nullable=True, server_default="normal")
    )


def downgrade() -> None:
    """Remove IAM analysis columns."""
    op.drop_column("attack_paths", "ai_remediation_priority")
    op.drop_column("attack_paths", "ai_true_risk_assessment")
    op.drop_column("attack_paths", "ai_escalation_techniques")
    op.drop_column("attack_paths", "ai_privilege_escalation")
