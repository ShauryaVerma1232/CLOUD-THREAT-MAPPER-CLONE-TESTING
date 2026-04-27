"""add threat actor and blast radius columns

Revision ID: 0005_add_threat_actor_and_blast_radius
Revises: 0004_add_escalation_multiplier
Create Date: 2026-04-20

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '0005_add_threat_actor_and_blast_radius'
down_revision = '0004_add_escalation_multiplier'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add threat actor TTP mapping columns (use IF NOT EXISTS for idempotency)
    op.execute("ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS ai_threat_actors JSONB")
    op.execute("ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS ai_mitre_mapping JSONB")

    # Add blast radius quantification columns
    op.execute("ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS ai_blast_radius JSONB")
    op.execute("ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS ai_compromise_timeline JSONB")


def downgrade() -> None:
    op.drop_column('attack_paths', 'ai_compromise_timeline')
    op.drop_column('attack_paths', 'ai_blast_radius')
    op.drop_column('attack_paths', 'ai_mitre_mapping')
    op.drop_column('attack_paths', 'ai_threat_actors')
