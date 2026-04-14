"""
Core database models for the Threat Mapper platform.
All tables use UUID primary keys and include created_at / updated_at timestamps.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Enum, Float,
    ForeignKey, Integer, String, Text, JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


# ── Scan Job ──────────────────────────────────────────────────────────────────
class ScanJob(Base):
    """Represents a single infrastructure scan run."""
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    aws_account_id = Column(String(12), nullable=True)
    aws_region = Column(String(32), nullable=False, default="us-east-1")
    aws_profile = Column(String(128), nullable=False)

    status = Column(
        Enum("pending", "running", "complete", "failed", name="scan_status"),
        nullable=False,
        default="pending",
    )
    error_message = Column(Text, nullable=True)

    # Counts populated after scan completes
    resource_count = Column(Integer, nullable=True)
    attack_path_count = Column(Integer, nullable=True)
    critical_path_count = Column(Integer, nullable=True)
    overall_risk_score = Column(Float, nullable=True)

    # Raw artifact path (relative to /artifacts volume)
    artifact_path = Column(String(512), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    sandboxes = relationship("SandboxJob", back_populates="scan_job")
    attack_paths = relationship("AttackPath", back_populates="scan_job")


# ── Attack Path ───────────────────────────────────────────────────────────────
class AttackPath(Base):
    """A single identified attack path from the threat surface graph."""
    __tablename__ = "attack_paths"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)

    # Path representation
    path_nodes = Column(JSON, nullable=False)        # ["Internet", "i-0abc", "role/X", "s3/Y"]
    path_edges = Column(JSON, nullable=False)        # [{"type": "exposes"}, ...]
    path_string = Column(Text, nullable=False)       # "Internet → EC2 → IAM → S3"

    # Scoring components
    reachability_score = Column(Float, nullable=False, default=0.0)
    impact_score = Column(Float, nullable=False, default=0.0)
    exploitability_score = Column(Float, nullable=False, default=0.0)
    exposure_score = Column(Float, nullable=False, default=0.0)
    risk_score = Column(Float, nullable=False, default=0.0)  # Composite

    severity = Column(
        Enum("critical", "high", "medium", "low", name="severity_level"),
        nullable=False,
    )

    # AI enrichment
    ai_explanation = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)

    # Deep IAM privilege escalation analysis
    ai_privilege_escalation = Column(JSON, nullable=True)  # Full IAM analysis result
    ai_escalation_techniques = Column(JSON, nullable=True)  # List of detected techniques
    ai_true_risk_assessment = Column(Text, nullable=True)  # Revised risk considering escalation
    ai_remediation_priority = Column(String(32), nullable=True, server_default="normal")
    ai_escalation_applied = Column(Boolean, nullable=True, server_default="false")  # True if AI escalated risk score
    ai_escalation_multiplier = Column(Float, nullable=True)  # Multiplier applied (1.3x - 2.0x)

    # Sandbox validation
    validated = Column(Boolean, default=False, nullable=False)
    validated_exploitable = Column(Boolean, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    scan_job = relationship("ScanJob", back_populates="attack_paths")
    test_results = relationship("TestResult", back_populates="attack_path")


# ── Sandbox Job ───────────────────────────────────────────────────────────────
class SandboxJob(Base):
    """A sandbox clone deployment + test lifecycle."""
    __tablename__ = "sandbox_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)

    status = Column(
        Enum(
            "pending", "generating_clone", "deploying", "testing",
            "collecting", "destroying", "complete", "failed",
            name="sandbox_status",
        ),
        nullable=False,
        default="pending",
    )
    error_message = Column(Text, nullable=True)

    # Clone spec stored as JSON
    clone_spec = Column(JSON, nullable=True)

    # Terraform state reference
    terraform_state_path = Column(String(512), nullable=True)
    terraform_outputs = Column(JSON, nullable=True)  # resource endpoints after deploy

    # AWS sandbox details
    sandbox_vpc_id = Column(String(32), nullable=True)
    sandbox_region = Column(String(32), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    deployed_at = Column(DateTime(timezone=True), nullable=True)
    destroyed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    scan_job = relationship("ScanJob", back_populates="sandboxes")
    test_results = relationship("TestResult", back_populates="sandbox_job")


# ── Test Result ───────────────────────────────────────────────────────────────
class TestResult(Base):
    """Result of a single security test against a sandbox environment."""
    __tablename__ = "test_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sandbox_job_id = Column(UUID(as_uuid=True), ForeignKey("sandbox_jobs.id"), nullable=False)
    attack_path_id = Column(UUID(as_uuid=True), ForeignKey("attack_paths.id"), nullable=True)

    test_category = Column(String(64), nullable=False)   # "IAM", "S3", "PublicExposure", etc.
    test_name = Column(String(128), nullable=False)
    status = Column(
        Enum("pass", "fail", "error", "skipped", name="test_status"),
        nullable=False,
    )
    exploitable = Column(Boolean, nullable=True)
    severity = Column(
        Enum("critical", "high", "medium", "low", "info", name="test_severity"),
        nullable=True,
    )

    evidence = Column(Text, nullable=True)          # Raw output / proof
    remediation = Column(Text, nullable=True)       # Specific fix steps
    ai_explanation = Column(Text, nullable=True)    # LLM narrative

    duration_ms = Column(BigInteger, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    sandbox_job = relationship("SandboxJob", back_populates="test_results")
    attack_path = relationship("AttackPath", back_populates="test_results")


# ── Report ────────────────────────────────────────────────────────────────────
class Report(Base):
    """Generated security report for a completed scan+test cycle."""
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    sandbox_job_id = Column(UUID(as_uuid=True), ForeignKey("sandbox_jobs.id"), nullable=True)

    title = Column(String(256), nullable=False)
    executive_summary = Column(Text, nullable=True)  # AI-generated
    findings_json = Column(JSON, nullable=True)       # Structured findings
    remediation_roadmap = Column(JSON, nullable=True) # Ordered fix list

    html_path = Column(String(512), nullable=True)    # Path in /reports volume
    pdf_path = Column(String(512), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ── Blast Radius ───────────────────────────────────────────────────────────────
class BlastRadius(Base):
    """Blast radius analysis result for a compromised node."""
    __tablename__ = "blast_radius"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    compromised_node_id = Column(String(256), nullable=False)

    # Node metadata
    compromised_node_type = Column(String(64), nullable=True)
    compromised_node_label = Column(String(256), nullable=True)

    # Direct reach (1 hop from compromised node)
    direct_reach = Column(JSON, nullable=True)
    direct_reach_count = Column(Integer, nullable=False, default=0)

    # Secondary reach (2 hops from compromised node)
    secondary_reach = Column(JSON, nullable=True)
    secondary_reach_count = Column(Integer, nullable=False, default=0)

    # All reachable nodes
    all_reachable = Column(JSON, nullable=True)
    total_reachable_count = Column(Integer, nullable=False, default=0)

    # Critical resources at risk
    critical_at_risk = Column(JSON, nullable=True)
    critical_count = Column(Integer, nullable=False, default=0)

    # Classification by hop distance
    by_hop_distance = Column(JSON, nullable=True)

    # Severity and scoring
    blast_radius_severity = Column(String(32), nullable=False, default="low")
    blast_radius_score = Column(Float, nullable=False, default=0.0)

    # Attack paths from this node
    attack_paths_from_here = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    scan_job = relationship("ScanJob")
