import { apiClient } from './client'

// ── Types ─────────────────────────────────────────────────────────────────────
export interface ScanJob {
  id: string
  aws_account_id: string | null
  aws_region: string
  aws_profile: string
  status: 'pending' | 'running' | 'complete' | 'failed'
  error_message: string | null
  resource_count: number | null
  attack_path_count: number | null
  critical_path_count: number | null
  overall_risk_score: number | null
  artifact_path: string | null
  created_at: string
  updated_at: string
  completed_at: string | null
}

export interface ScanJobList {
  items: ScanJob[]
  total: number
}

export interface GraphData {
  scan_job_id: string
  nodes: CyNode[]
  edges: CyEdge[]
  node_count: number
  edge_count: number
}

export interface CyNode {
  data: {
    id: string
    node_type: string
    label: string
    risk_score: number
    public: boolean
    region: string
    [key: string]: unknown
  }
}

export interface CyEdge {
  data: {
    id: string
    source: string
    target: string
    edge_type: string
    weight: number
    validated: boolean
  }
}

export interface AttackPath {
  path_id: string
  path_string: string
  risk_score: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  reachability_score: number
  impact_score: number
  exploitability_score: number
  exposure_score: number
  hop_count: number
  validated: boolean
}

export interface AttackPathList {
  scan_job_id: string
  items: AttackPath[]
  total: number
  critical_count: number
  high_count: number
}

// ── Scans API ─────────────────────────────────────────────────────────────────
export const scansApi = {
  create: (aws_profile: string, region: string) =>
    apiClient.post<{ scan_job_id: string; status: string; message: string }>(
      '/scans',
      { aws_profile, region },
    ),

  list: (limit = 20, offset = 0) =>
    apiClient.get<ScanJobList>(`/scans?limit=${limit}&offset=${offset}`),

  get: (id: string) =>
    apiClient.get<ScanJob>(`/scans/${id}`),
}

// ── Graph API ─────────────────────────────────────────────────────────────────
export const graphApi = {
  build: (scan_job_id: string) =>
    apiClient.post<{ scan_job_id: string; status: string; message: string }>(
      `/graph/build/${scan_job_id}`,
    ),

  getGraph: (scan_job_id: string) =>
    apiClient.get<GraphData>(`/graph/${scan_job_id}`),

  getPaths: (scan_job_id: string) =>
    apiClient.get<AttackPathList>(`/graph/${scan_job_id}/paths`),

  getPathDetail: (scan_job_id: string, path_id: string) =>
    apiClient.get<{ node_sequence: string[]; path_string: string; risk_score: number }>(
      `/graph/${scan_job_id}/paths/${path_id}`,
    ),
}

// ── AI API ────────────────────────────────────────────────────────────────────
export interface AIProvider {
  provider: string
  configured: boolean
  ready: boolean
  model: string
}

export interface AIStatus {
  scan_job_id: string
  ai_available: boolean
  annotated_paths: number
  total_paths: number
  has_report: boolean
  ai_provider: string
}

export interface AIAnnotatedPath {
  id: string
  path_string: string
  risk_score: number
  severity: string
  ai_explanation: string
  ai_remediation_steps: string[]
  reachability_score: number
  impact_score: number
  exploitability_score: number
  exposure_score: number
}

export interface AISummary {
  scan_job_id: string
  title: string
  executive_summary: string
  priority_ranking: Array<{
    rank: number
    path_string: string
    priority_reasoning: string
    recommended_action: string
  }>
  remediation_roadmap: {
    immediate_actions?: Array<{ action: string; rationale: string; effort: string; risk_reduction: string }>
    short_term_fixes?: Array<{ action: string; rationale: string; effort: string }>
    strategic_improvements?: string[]
    overall_risk_narrative?: string
  }
  generated_at: string | null
}

export const aiApi = {
  getProvider: () =>
    apiClient.get<AIProvider>('/ai/provider'),

  triggerAnalysis: (scan_job_id: string) =>
    apiClient.post(`/ai/analyze/${scan_job_id}`),

  getStatus: (scan_job_id: string) =>
    apiClient.get<AIStatus>(`/ai/status/${scan_job_id}`),

  getAnnotatedPaths: (scan_job_id: string) =>
    apiClient.get<{ items: AIAnnotatedPath[]; total: number }>(`/ai/paths/${scan_job_id}`),

  getSummary: (scan_job_id: string) =>
    apiClient.get<AISummary>(`/ai/summary/${scan_job_id}`),
}

// ── Blast Radius API ──────────────────────────────────────────────────────────

export interface CriticalResourceAtRisk {
  node_id: string
  node_type: string
  label: string
  is_admin: boolean
  is_public: boolean
}

export interface AttackPathFromCompromised {
  path_string: string
  path_nodes: string[]
  target_node: string
  target_type: string
  hop_count: number
  risk_score: number
  severity: string
}

export interface BlastRadiusResult {
  result_id?: string
  scan_job_id: string
  compromised_node_id: string
  compromised_node_type: string
  compromised_node_label: string
  direct_reach_count: number
  secondary_reach_count: number
  total_reachable_count: number
  critical_count: number
  direct_reach: string[]
  secondary_reach: string[]
  all_reachable: string[]
  critical_at_risk: CriticalResourceAtRisk[]
  by_hop_distance: Record<string, string[]>
  blast_radius_severity: string
  blast_radius_score: number
  attack_paths_from_here: AttackPathFromCompromised[]
}

export interface BlastRadiusTriggerResponse {
  scan_job_id: string
  compromised_node_id: string
  status: string
  message: string
}

export interface PublicResourcesBlastRadius {
  scan_job_id: string
  public_resources_analyzed: number
  results: Array<{
    node_id: string
    node_type: string
    node_label: string
    total_reachable: number
    critical_count: number
    severity: string
    score: number
  }>
}

export const blastRadiusApi = {
  triggerCalculation: (scan_job_id: string, compromised_node_id: string, max_hops = 4, include_attack_paths = true) =>
    apiClient.post<BlastRadiusTriggerResponse>(
      `/graph/${scan_job_id}/blast-radius/calculate`,
      { compromised_node_id, max_hops, include_attack_paths },
    ),

  getResult: (scan_job_id: string, node_id: string) =>
    apiClient.get<BlastRadiusResult>(`/graph/${scan_job_id}/blast-radius/${node_id}`),

  analyzePublicResources: (scan_job_id: string) =>
    apiClient.get<PublicResourcesBlastRadius>(`/graph/${scan_job_id}/blast-radius/public`),
}
