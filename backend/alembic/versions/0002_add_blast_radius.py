"""add blast radius table

Revision ID: 0002_add_blast_radius
Revises: 0001_initial
Create Date: 2026-04-11 00:00:00.000000
"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_add_blast_radius"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "blast_radius",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("compromised_node_id", sa.String(256), nullable=False),
        sa.Column("compromised_node_type", sa.String(64), nullable=True),
        sa.Column("compromised_node_label", sa.String(256), nullable=True),

        # Direct reach (1 hop)
        sa.Column("direct_reach", postgresql.JSON, nullable=True),
        sa.Column("direct_reach_count", sa.Integer, nullable=False, server_default="0"),

        # Secondary reach (2 hops)
        sa.Column("secondary_reach", postgresql.JSON, nullable=True),
        sa.Column("secondary_reach_count", sa.Integer, nullable=False, server_default="0"),

        # All reachable nodes
        sa.Column("all_reachable", postgresql.JSON, nullable=True),
        sa.Column("total_reachable_count", sa.Integer, nullable=False, server_default="0"),

        # Critical resources at risk
        sa.Column("critical_at_risk", postgresql.JSON, nullable=True),
        sa.Column("critical_count", sa.Integer, nullable=False, server_default="0"),

        # Hop distance classification
        sa.Column("by_hop_distance", postgresql.JSON, nullable=True),

        # Severity and scoring
        sa.Column("blast_radius_severity", sa.String(32), nullable=False, server_default="low"),
        sa.Column("blast_radius_score", sa.Float, nullable=False, server_default="0.0"),

        # Attack paths from compromised node
        sa.Column("attack_paths_from_here", postgresql.JSON, nullable=True),

        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_blast_radius_scan_job_id", "blast_radius", ["scan_job_id"])
    op.create_index("ix_blast_radius_compromised_node", "blast_radius", ["compromised_node_id"])
    op.create_index("ix_blast_radius_severity", "blast_radius", ["blast_radius_severity"])
    op.create_index("ix_blast_radius_score", "blast_radius", ["blast_radius_score"])


def downgrade() -> None:
    op.drop_table("blast_radius")
