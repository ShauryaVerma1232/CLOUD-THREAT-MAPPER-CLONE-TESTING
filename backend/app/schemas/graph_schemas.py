"""Pydantic schemas for graph and attack path API responses."""
from typing import Any, Optional
from pydantic import BaseModel


class CytoscapeNodeData(BaseModel):
    id: str
    node_type: str
    label: str
    risk_score: float
    public: bool
    region: str


class CytoscapeNode(BaseModel):
    data: dict[str, Any]


class CytoscapeEdge(BaseModel):
    data: dict[str, Any]


class GraphResponse(BaseModel):
    scan_job_id: str
    nodes: list[CytoscapeNode]
    edges: list[CytoscapeEdge]
    node_count: int
    edge_count: int


class AttackPathResponse(BaseModel):
    path_id: str
    path_string: str
    risk_score: float
    severity: str
    reachability_score: float
    impact_score: float
    exploitability_score: float
    exposure_score: float
    hop_count: int
    validated: bool

    # AI enrichment
    ai_explanation: Optional[str] = None
    ai_remediation: Optional[str] = None

    # Deep IAM privilege escalation analysis
    ai_privilege_escalation: Optional[dict] = None
    ai_escalation_techniques: Optional[list[dict]] = None
    ai_true_risk_assessment: Optional[str] = None
    ai_remediation_priority: Optional[str] = None


class AttackPathListResponse(BaseModel):
    scan_job_id: str
    items: list[AttackPathResponse]
    total: int
    critical_count: int
    high_count: int


class GraphBuildRequest(BaseModel):
    scan_job_id: str


class GraphBuildResponse(BaseModel):
    scan_job_id: str
    status: str
    message: str


# ── Blast Radius Schemas ───────────────────────────────────────────────────────


class CriticalResourceAtRisk(BaseModel):
    """A critical resource that would be at risk if a node is compromised."""
    node_id: str
    node_type: str
    label: str
    is_admin: bool = False
    is_public: bool = False


class AttackPathFromCompromised(BaseModel):
    """An attack path starting from a compromised node."""
    path_string: str
    path_nodes: list[str]
    target_node: str
    target_type: str
    hop_count: int
    risk_score: float
    severity: str


class BlastRadiusRequest(BaseModel):
    """Request to calculate blast radius for a compromised node."""
    compromised_node_id: str
    max_hops: int = 4
    include_attack_paths: bool = True


class BlastRadiusResponse(BaseModel):
    """Response containing blast radius analysis results."""
    result_id: Optional[str] = None
    scan_job_id: str
    compromised_node_id: str
    compromised_node_type: str
    compromised_node_label: str

    # Reach counts
    direct_reach_count: int
    secondary_reach_count: int
    total_reachable_count: int
    critical_count: int

    # Lists
    direct_reach: list[str]
    secondary_reach: list[str]
    all_reachable: list[str]
    critical_at_risk: list[CriticalResourceAtRisk]

    # Classification by hop distance
    by_hop_distance: dict[str, list[str]]

    # Severity
    blast_radius_severity: str
    blast_radius_score: float

    # Attack paths from this node
    attack_paths_from_here: list[AttackPathFromCompromised]


class BlastRadiusTriggerResponse(BaseModel):
    """Response when triggering a blast radius calculation task."""
    scan_job_id: str
    compromised_node_id: str
    status: str
    message: str


class PublicResourcesBlastRadiusResponse(BaseModel):
    """Response for blast radius analysis of all public resources."""
    scan_job_id: str
    public_resources_analyzed: int
    results: list[dict]
