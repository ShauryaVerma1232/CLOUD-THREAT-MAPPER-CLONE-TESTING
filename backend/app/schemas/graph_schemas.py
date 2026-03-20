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
