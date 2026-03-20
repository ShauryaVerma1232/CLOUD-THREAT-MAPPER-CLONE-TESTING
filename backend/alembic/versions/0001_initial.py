"""initial schema

Revision ID: 0001_initial
Revises: 
Create Date: 2025-01-01 00:00:00.000000
"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("aws_account_id", sa.String(12), nullable=True),
        sa.Column("aws_region", sa.String(32), nullable=False, server_default="us-east-1"),
        sa.Column("aws_profile", sa.String(128), nullable=False),
        sa.Column("status", sa.Enum("pending", "running", "complete", "failed", name="scan_status"), nullable=False, server_default="pending"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("resource_count", sa.Integer, nullable=True),
        sa.Column("attack_path_count", sa.Integer, nullable=True),
        sa.Column("critical_path_count", sa.Integer, nullable=True),
        sa.Column("overall_risk_score", sa.Float, nullable=True),
        sa.Column("artifact_path", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "attack_paths",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("path_nodes", postgresql.JSON, nullable=False),
        sa.Column("path_edges", postgresql.JSON, nullable=False),
        sa.Column("path_string", sa.Text, nullable=False),
        sa.Column("reachability_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("impact_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("exploitability_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("exposure_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("severity", sa.Enum("critical", "high", "medium", "low", name="severity_level"), nullable=False),
        sa.Column("ai_explanation", sa.Text, nullable=True),
        sa.Column("ai_remediation", sa.Text, nullable=True),
        sa.Column("validated", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("validated_exploitable", sa.Boolean, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_attack_paths_scan_job_id", "attack_paths", ["scan_job_id"])
    op.create_index("ix_attack_paths_risk_score", "attack_paths", ["risk_score"])

    op.create_table(
        "sandbox_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("status", sa.Enum("pending", "generating_clone", "deploying", "testing", "collecting", "destroying", "complete", "failed", name="sandbox_status"), nullable=False, server_default="pending"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("clone_spec", postgresql.JSON, nullable=True),
        sa.Column("terraform_state_path", sa.String(512), nullable=True),
        sa.Column("terraform_outputs", postgresql.JSON, nullable=True),
        sa.Column("sandbox_vpc_id", sa.String(32), nullable=True),
        sa.Column("sandbox_region", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sandbox_jobs_scan_job_id", "sandbox_jobs", ["scan_job_id"])

    op.create_table(
        "test_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sandbox_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sandbox_jobs.id"), nullable=False),
        sa.Column("attack_path_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("attack_paths.id"), nullable=True),
        sa.Column("test_category", sa.String(64), nullable=False),
        sa.Column("test_name", sa.String(128), nullable=False),
        sa.Column("status", sa.Enum("pass", "fail", "error", "skipped", name="test_status"), nullable=False),
        sa.Column("exploitable", sa.Boolean, nullable=True),
        sa.Column("severity", sa.Enum("critical", "high", "medium", "low", "info", name="test_severity"), nullable=True),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("ai_explanation", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.BigInteger, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_test_results_sandbox_job_id", "test_results", ["sandbox_job_id"])

    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_jobs.id"), nullable=False),
        sa.Column("sandbox_job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sandbox_jobs.id"), nullable=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("executive_summary", sa.Text, nullable=True),
        sa.Column("findings_json", postgresql.JSON, nullable=True),
        sa.Column("remediation_roadmap", postgresql.JSON, nullable=True),
        sa.Column("html_path", sa.String(512), nullable=True),
        sa.Column("pdf_path", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("test_results")
    op.drop_table("sandbox_jobs")
    op.drop_table("attack_paths")
    op.drop_table("scan_jobs")
    for name in ["scan_status", "sandbox_status", "severity_level", "test_status", "test_severity"]:
        sa.Enum(name=name).drop(op.get_bind(), checkfirst=True)
