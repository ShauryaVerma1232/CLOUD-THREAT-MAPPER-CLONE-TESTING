import { useState, useRef, useCallback, useMemo, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import cytoscape from 'cytoscape'
import fcose from 'cytoscape-fcose'
import dagre from 'cytoscape-dagre'
import CytoscapeComponent from 'react-cytoscapejs'

cytoscape.use(fcose)
cytoscape.use(dagre)

import { AlertTriangle, X, Layers, ZoomIn, ZoomOut, Maximize, Eye, EyeOff, Box, Target, ShieldAlert, ChevronRight, Radio, Network, Lock, Unlock, FileText, Zap, CheckCircle, Download, Play, Pause, StepForward, RefreshCw } from 'lucide-react'
import { graphApi, blastRadiusApi, aiApi, type CyNode, type AttackPath, type BlastRadiusResult, type AISummary } from '../api/scanApi'
import clsx from 'clsx'

const NODE_COLORS: Record<string, string> = {
  INTERNET: '#EF4444',
  EC2: '#3B82F6',
  IAM_ROLE: '#F59E0B',
  IAM_USER: '#8B5CF6',
  S3_BUCKET: '#10B981',
  VPC: '#6366F1',
  SUBNET: '#14B8A6',
  SECURITY_GROUP: '#F97316',
  RDS: '#EC4899',
  LAMBDA: '#06B6D4',
}

// Compound node styling for BloodHound-style clustering
const CY_STYLESHEET = [
  // Compound nodes (VPC, Subnet containers)
  {
    selector: 'node[node_type = "VPC"]',
    style: {
      shape: 'rectangle',
      width: 600,
      height: 400,
      'background-color': '#6366F1',
      'background-opacity': 0.1,
      'border-width': 3,
      'border-color': '#6366F1',
      'border-style': 'solid',
      label: 'data(label)',
      'font-size': '14px',
      'font-weight': '700',
      color: '#6366F1',
      'text-valign': 'top',
      'text-halign': 'center',
      'text-margin-y': 15,
      'text-outline-width': 0,
      'text-wrap': 'wrap',
      'text-max-width': '580px',
    },
  },
  {
    selector: 'node[node_type = "SUBNET"]',
    style: {
      shape: 'round-rectangle',
      width: 280,
      height: 200,
      'background-color': '#14B8A6',
      'background-opacity': 0.12,
      'border-width': 2,
      'border-color': '#14B8A6',
      'border-style': 'solid',
      label: 'data(label)',
      'font-size': '12px',
      'font-weight': '600',
      color: '#14B8A6',
      'text-valign': 'top',
      'text-halign': 'center',
      'text-margin-y': 10,
      'text-outline-width': 0,
      'text-wrap': 'wrap',
    },
  },
  // Regular resource nodes
  {
    selector: 'node',
    style: {
      'background-color': (ele: any) =>
        NODE_COLORS[ele.data('node_type')] ?? '#64748b',
      label: 'data(label)',
      color: '#FFFFFF',
      'font-size': '13px',
      'font-family': 'system-ui, -apple-system, sans-serif',
      'font-weight': '600',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 10,
      'text-outline-width': 3,
      'text-outline-color': '#0F172A',
      'text-wrap': 'wrap',
      'text-max-width': '140px',
      width: (ele: any) => getNodeSize(ele.data('node_type')),
      height: (ele: any) => getNodeSize(ele.data('node_type')),
      'border-width': 3,
      'border-color': '#1E293B',
      'border-opacity': 1,
      'background-opacity': 0.9,
    },
  },
  { selector: 'node[?public]', style: {
    'border-color': '#EF4444',
    'border-width': 6,
    'border-opacity': 1,
    'border-style': 'dashed',
  }},
  { selector: 'node[node_type = "INTERNET"]', style: { shape: 'diamond', width: 60, height: 60 } },
  { selector: 'node[node_type = "EC2"]', style: { shape: 'round-rectangle', width: 55, height: 50 } },
  { selector: 'node[node_type = "RDS"]', style: { shape: 'round-rectangle', width: 55, height: 50 } },
  { selector: 'node[node_type = "S3_BUCKET"]', style: { shape: 'round-rectangle', width: 55, height: 50 } },
  { selector: 'node[node_type = "LAMBDA"]', style: { shape: 'round-rectangle', width: 50, height: 50 } },
  { selector: 'node[node_type = "SECURITY_GROUP"]', style: { shape: 'round-rectangle', width: 50, height: 50 } },
  { selector: 'node[node_type = "IAM_USER"]', style: { shape: 'round-rectangle', width: 50, height: 50 } },
  { selector: 'node[node_type = "IAM_ROLE"]', style: { shape: 'round-rectangle', width: 50, height: 50 } },
  // Default edge style
  {
    selector: 'edge',
    style: {
      width: 2,
      'line-color': (ele: any) => getEdgeColor(ele.data('edge_type')),
      'target-arrow-color': (ele: any) => getEdgeColor(ele.data('edge_type')),
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'control-point-step-size': 40,
      'control-point-weight': 0.5,
      'arrow-scale': 1.2,
      'line-opacity': 0.7,
      'target-arrow-opacity': 0.9,
    },
  },
  // Edge type: exposes (Internet -> resource) - Red
  {
    selector: 'edge[edge_type = "exposes"]',
    style: {
      'line-color': '#EF4444',
      'target-arrow-color': '#EF4444',
      'line-opacity': 0.8,
    },
  },
  // Edge type: assumes_role - Orange
  {
    selector: 'edge[edge_type = "assumes_role"]',
    style: {
      'line-color': '#F59E0B',
      'target-arrow-color': '#F59E0B',
      'line-opacity': 0.8,
    },
  },
  // Edge type: trusts - Purple
  {
    selector: 'edge[edge_type = "trusts"]',
    style: {
      'line-color': '#A855F7',
      'target-arrow-color': '#A855F7',
      'line-opacity': 0.8,
    },
  },
  // Edge type: connected_to (network) - Gray
  {
    selector: 'edge[edge_type = "connected_to"]',
    style: {
      'line-color': '#64748B',
      'target-arrow-color': '#64748B',
      'line-opacity': 0.5,
    },
  },
  {
    selector: 'edge:selected',
    style: {
      width: 4,
      'line-color': '#3B82F6',
      'target-arrow-color': '#3B82F6',
      'line-opacity': 1,
    },
  },
  // Attack path edge highlighting
  {
    selector: 'edge.attack-path',
    style: {
      width: 4,
      'line-color': '#EF4444',
      'target-arrow-color': '#EF4444',
      'line-opacity': 1,
      'line-style': 'solid',
    },
  },
  // Enhanced attack path edge (for research visualization)
  {
    selector: 'edge.attack-path-edge-highlight',
    style: {
      width: 6,
      'line-color': '#DC2626',
      'target-arrow-color': '#DC2626',
      'line-opacity': 1,
      'line-style': 'solid',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 1.5,
    },
  },
  // Attack path node highlighting
  {
    selector: 'node.attack-path-node',
    style: {
      'border-width': 8,
      'border-color': '#EF4444',
      'border-opacity': 1,
      'background-opacity': 1,
      'z-index': 10,
    },
  },
  // Current step in animation (pulsing effect)
  {
    selector: 'node.path-step-current',
    style: {
      'border-color': '#FCD34D',
      'border-width': 10,
      'background-color': '#FDE047',
      'background-opacity': 0.3,
      'shadow-color': '#FCD34D',
      'shadow-blur': 20,
      'shadow-opacity': 0.8,
    },
  },
  {
    selector: 'edge[type = "contains"]',
    style: {
      'line-style': 'dashed',
      'line-color': '#64748b',
    },
  },
  // Blast radius highlighting
  {
    selector: 'node.blast-radius-reachable',
    style: {
      'border-color': '#F59E0B',
      'border-width': 4,
      'border-opacity': 1,
      'background-opacity': 0.7,
    },
  },
  {
    selector: 'node.blast-radius-critical',
    style: {
      'border-color': '#EF4444',
      'border-width': 6,
      'border-opacity': 1,
      'border-style': 'dashed',
      'background-opacity': 0.8,
    },
  },
]

function getNodeSize(nodeType: string | undefined): number {
  if (!nodeType) return 45
  const sizes: Record<string, number> = {
    INTERNET: 60,
    VPC: 80,
    EC2: 55,
    RDS: 55,
    LAMBDA: 50,
    S3_BUCKET: 55,
    IAM_USER: 50,
    IAM_ROLE: 50,
    SUBNET: 55,
    SECURITY_GROUP: 50,
  }
  return sizes[nodeType] ?? 45
}

function getEdgeColor(edgeType: string | undefined): string {
  if (!edgeType) return '#64748B'
  const colors: Record<string, string> = {
    exposes: '#EF4444',      // Red - internet exposure
    assumes_role: '#F59E0B', // Orange - IAM role assumption
    trusts: '#A855F7',       // Purple - trust relationships
    connected_to: '#64748B', // Gray - network connectivity
    network_access: '#3B82F6', // Blue - network access
    can_access: '#10B981',   // Green - access permissions
  }
  return colors[edgeType] ?? '#64748B'
}

// Truncate long IDs for display labels
function truncateLabel(label: string, maxLength = 20): string {
  if (!label || label.length <= maxLength) return label
  // For subnet-xxx or vpc-xxx style IDs, keep the prefix and shorten the hash
  const match = label.match(/^([a-z]+-[a-z]+-)([a-zA-Z0-9]+)$/)
  if (match) {
    const prefix = match[1]
    const hash = match[2]
    if (hash.length > 12) {
      return `${prefix}${hash.slice(0, 6)}...${hash.slice(-4)}`
    }
  }
  // For ARNs and other long strings
  if (label.length > maxLength) {
    return `${label.slice(0, maxLength)}...`
  }
  return label
}

// Check if a resource is a CloudGoat resource
function isCloudGoatResource(nodeId: string, nodeType?: string): boolean {
  // Always include INTERNET node - it's the attack surface entry point
  if (nodeId === 'INTERNET' || nodeType === 'INTERNET') {
    return true
  }
  // CloudGoat resources typically have names starting with 'cg-' or 'cg_'
  // or IAM users created by CloudGoat (shepard, solus, wrex, jacktheripper)
  const cloudGoatPrefixes = ['cg-', 'cg_', 'shepard', 'solus', 'wrex', 'jacktheripper']
  const lowerId = nodeId.toLowerCase()
  return cloudGoatPrefixes.some(prefix => lowerId.startsWith(prefix) || lowerId.includes(prefix))
}

export default function GraphPage() {
  const [searchParams] = useSearchParams()
  const scanId = searchParams.get('scan') ?? ''

  const cyRef = useRef<any>(null)

  const [selectedNode, setSelectedNode] = useState<CyNode['data'] | null>(null)
  const [showEdgeLabels, setShowEdgeLabels] = useState(false)
  const [zoomLevel, setZoomLevel] = useState(1)
  const [clusterMode, setClusterMode] = useState(true) // BloodHound-style clustering
  const [selectedAttackPath, setSelectedAttackPath] = useState<AttackPath | null>(null)

  // Blast radius state
  const [blastRadiusResult, setBlastRadiusResult] = useState<BlastRadiusResult | null>(null)
  const [blastRadiusLoading, setBlastRadiusLoading] = useState(false)
  const [showBlastRadiusPanel, setShowBlastRadiusPanel] = useState(false)

  // AI Report state
  const [aiSummary, setAiSummary] = useState<AISummary | null>(null)
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false)
  const [showAiReportPanel, setShowAiReportPanel] = useState(false)
  const [aiReportTab, setAiReportTab] = useState<'summary' | 'quick-wins' | 'rankings'>('summary')

  // Track if user manually closed the attack path panel (prevents auto-reselect)
  const userClosedAttackPathRef = useRef(false)

  // Environment filter state
  const [showOnlyCloudGoat, setShowOnlyCloudGoat] = useState(false)

  // Attack path animation state
  const [animatedPath, setAnimatedPath] = useState<AttackPath | null>(null)
  const [animationPlaying, setAnimationPlaying] = useState(false)
  const [currentStep, setCurrentStep] = useState(0)

  // Graph build state
  const [isBuildingGraph, setIsBuildingGraph] = useState(false)

  // Fetch scan details for header
  const { data: scanDetails } = useQuery({
    queryKey: ['scan-details', scanId],
    enabled: !!scanId,
    queryFn: () => graphApi.getGraph(scanId).then(() =>
      fetch(`http://localhost:18000/scans/${scanId}`).then(r => r.json())
    ),
    staleTime: Infinity,
  })

  const { data: graphData, isLoading, error: graphError, refetch: refetchGraph } = useQuery({
    queryKey: ['graph', scanId],
    enabled: !!scanId,
    retry: 1, // Only 1 retry for faster load
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    refetchOnReconnect: false,
    staleTime: 30000, // 30 seconds stale time
    queryFn: () => graphApi.getGraph(scanId).then(r => r.data),
  })

  const { data: attackPathsData, isLoading: attackPathsLoading, refetch: refetchAttackPaths } = useQuery({
    queryKey: ['attack-paths', scanId],
    enabled: !!scanId,
    retry: 5, // Retry 5 times for attack paths (graph build is async)
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    staleTime: 10000, // 10 seconds stale time
    queryFn: async () => {
      const result = await graphApi.getPaths(scanId).then(r => r.data)
      // If no paths found, throw error to trigger retry (graph might still be building)
      if (!result.items || result.items.length === 0) {
        throw new Error('No attack paths found yet - graph may still be building')
      }
      return result
    },
  })

  // Auto-highlight the first (most critical) attack path when data loads
  useEffect(() => {
    if (attackPathsData?.items && attackPathsData.items.length > 0 && !selectedAttackPath && !userClosedAttackPathRef.current && cyRef.current) {
      const topPath = attackPathsData.items[0] // Already sorted by risk_score desc
      setSelectedAttackPath(topPath)
      // Small delay to ensure graph is rendered
      setTimeout(() => {
        if (cyRef.current) {
          highlightAttackPath(topPath, false)
        }
      }, 500)
    }
  }, [attackPathsData?.items, selectedAttackPath])

  // Fetch AI Summary when panel is opened
  const fetchAiSummary = useCallback(async () => {
    if (!scanId || aiSummaryLoading) return
    setAiSummaryLoading(true)
    try {
      const result = await aiApi.getSummary(scanId)
      if (result.data) {
        setAiSummary(result.data)
        setShowAiReportPanel(true)
      }
    } catch (error) {
      console.error('Failed to fetch AI summary:', error)
      // Clear cached summary on error to allow retry
      setAiSummary(null)
    } finally {
      setAiSummaryLoading(false)
    }
  }, [scanId, aiSummaryLoading])


  const handleCyInit = useCallback((cy: any) => {
    cyRef.current = cy

    cy.on('tap', 'node', (evt: any) => {
      const nodeData = evt.target?.data?.()
      if (nodeData && nodeData.id) {
        setSelectedNode(nodeData)
      }
    })

    cy.on('tap', (evt: any) => {
      if (evt.target === cy) setSelectedNode(null)
    })

    cy.on('zoom', () => {
      setZoomLevel(parseFloat(cy.zoom().toFixed(2)))
    })

    cy.on('ready', () => {
      setZoomLevel(parseFloat(cy.zoom().toFixed(2)))
    })
  }, [])

  // Highlight attack path in the graph with enhanced visualization
  const highlightAttackPath = useCallback((path: AttackPath, enableAnimation = false) => {
    if (!cyRef.current) return

    // Clear previous highlights
    cyRef.current.elements().removeClass('attack-path attack-path-node attack-path-edge-highlight')

    // Extract node IDs from path string, removing "User:", "Role:", etc. prefixes
    const pathParts = path.path_string.split(' → ')
    const nodeLabels = pathParts.map(p => {
      const trimmed = p.trim()
      // Remove prefixes like "User:", "Role:", "EC2:", etc.
      const withoutPrefix = trimmed.replace(/^(User|Role|EC2|S3|RDS|Lambda|VPC|Subnet|SecurityGroup):\s*/i, '')
      return withoutPrefix
    })

    // Find and highlight nodes in the path
    const highlightedNodes: any[] = []
    nodeLabels.forEach((label, index) => {
      // Try exact match first, then partial match
      let node = cyRef.current.nodes().filter((n: any) => n.data('label') === label)
      if (node.length === 0) {
        node = cyRef.current.nodes().filter((n: any) => n.data('label')?.includes(label))
      }
      // Fallback: try matching by node ID
      if (node.length === 0) {
        node = cyRef.current.nodes().filter((n: any) => n.data('id')?.includes(label))
      }

      if (node.length > 0) {
        node.addClass('attack-path-node')
        highlightedNodes.push(node[0])

        // Add step number badge (for research visualization)
        node.data('stepNumber', index + 1)
      }
    })

    // Highlight edges between path nodes
    for (let i = 0; i < highlightedNodes.length - 1; i++) {
      const source = highlightedNodes[i]
      const target = highlightedNodes[i + 1]
      const edge = cyRef.current.edges().filter((e: any) =>
        e.data('source') === source.data('id') && e.data('target') === target.data('id')
      )
      if (edge.length > 0) {
        edge.addClass('attack-path-edge-highlight')
        edge.data('pathEdge', true)
      }
    }

    // Fit the view to show the path
    if (highlightedNodes.length > 0) {
      cyRef.current.animate({
        fit: { eles: cyRef.current.nodes('.attack-path-node'), padding: 80 },
        duration: 800,
        easing: 'ease-in-out'
      })

      // Start step-by-step animation if enabled
      if (enableAnimation) {
        setAnimatedPath(path)
        setAnimationPlaying(true)
        setCurrentStep(0)
        animatePathStep(highlightedNodes, 0)
      }
    }
  }, [])

  // Animate path step-by-step (for research presentations)
  const animatePathStep = (nodes: any[], step: number) => {
    if (!cyRef.current || step >= nodes.length) {
      setAnimationPlaying(false)
      return
    }

    // Pulse effect on current node
    const node = nodes[step]
    cyRef.current.elements().removeClass('path-step-current')
    node.addClass('path-step-current')

    // Zoom to current step
    cyRef.current.animate({
      fit: { eles: node, padding: 100 },
      duration: 600
    })

    setCurrentStep(step + 1)

    // Continue to next step after delay
    if (step < nodes.length - 1) {
      setTimeout(() => {
        if (animationPlaying) {
          animatePathStep(nodes, step + 1)
        }
      }, 2000) // 2 seconds per step
    } else {
      setTimeout(() => {
        cyRef.current.elements().removeClass('path-step-current')
        setAnimationPlaying(false)
      }, 2000)
    }
  }

  // Stop animation
  const stopAnimation = useCallback(() => {
    setAnimationPlaying(false)
    setAnimatedPath(null)
    setCurrentStep(0)
    if (cyRef.current) {
      cyRef.current.elements().removeClass('path-step-current')
    }
  }, [])

  // Export graph as PNG (for research paper)
  const exportGraphAsPng = useCallback((filename = 'attack-path.png') => {
    if (!cyRef.current) return

    const pngData = cyRef.current.png({
      full: true,
      bg: '#0f172a',
      scale: 2 // High resolution for papers
    })

    const link = document.createElement('a')
    link.download = filename
    link.href = pngData
    link.click()
  }, [])

  // Blast radius calculation
  const calculateBlastRadius = useCallback(async (nodeId: string) => {
    if (!scanId) return

    setBlastRadiusLoading(true)
    try {
      // First trigger the calculation
      await blastRadiusApi.triggerCalculation(scanId, nodeId, 4, true)

      // Poll for results (simple polling every 1s for up to 30s)
      for (let i = 0; i < 30; i++) {
        try {
          const result = await blastRadiusApi.getResult(scanId, nodeId)
          if (result.data) {
            setBlastRadiusResult(result.data)
            setShowBlastRadiusPanel(true)

            // Highlight reachable nodes in the graph
            if (cyRef.current) {
              cyRef.current.elements().removeClass('blast-radius-reachable blast-radius-critical')
              const allReachable = result.data.all_reachable || []
              const criticalIds = new Set((result.data.critical_at_risk || []).map(c => c.node_id))

              allReachable.forEach((rid: string) => {
                const node = cyRef.current.nodes().filter((n: any) => n.data('id') === rid)
                if (node.length > 0) {
                  if (criticalIds.has(rid)) {
                    node.addClass('blast-radius-critical')
                  } else {
                    node.addClass('blast-radius-reachable')
                  }
                }
              })

              // Fit view to show affected area
              const reachableNodes = cyRef.current.nodes('.blast-radius-reachable, .blast-radius-critical')
              if (reachableNodes.length > 0) {
                cyRef.current.animate({
                  fit: { eles: reachableNodes, padding: 50 },
                  duration: 500
                })
              }
            }
            break
          }
        } catch {
          // Result not ready yet, wait and retry
        }
        await new Promise(resolve => setTimeout(resolve, 1000))
      }
    } catch (error) {
      console.error('Blast radius calculation failed:', error)
    } finally {
      setBlastRadiusLoading(false)
    }
  }, [scanId])

  /* MEMOIZED ELEMENTS TO PREVENT RE-RENDER GRAPH RESET */
  const elements = useMemo(() => {
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
      console.log('[GraphPage] No graph data available')
      return []
    }

    // Debug: Log all node IDs and edge references
    console.log('[GraphPage] Raw graph data:', {
      nodeCount: graphData.nodes.length,
      edgeCount: graphData.edges.length,
      nodeIds: graphData.nodes.map(n => n?.data?.id).slice(0, 20),
      edgeRefs: graphData.edges.map(e => `${e?.data?.source} -> ${e?.data?.target}`).slice(0, 20),
    })

    // Build parent-child relationships for BloodHound-style clustering
    // VPCs contain Subnets, Subnets contain EC2/RDS/Lambda
    const nodeMap = new Map<string, any>()

    // Find the first VPC and Subnet for default assignment
    let defaultVpcId: string | undefined
    let defaultSubnetId: string | undefined

    // First pass: identify VPCs and Subnets, pick first of each
    for (const node of (graphData.nodes ?? [])) {
      const nodeId = node?.data?.id
      const nodeType = node?.data?.node_type
      if (!nodeId) continue

      // Skip non-CloudGoat resources if filter is enabled
      if (showOnlyCloudGoat && !isCloudGoatResource(nodeId, nodeType)) {
        continue
      }

      if (nodeType === 'VPC' && !defaultVpcId) {
        defaultVpcId = nodeId
      } else if (nodeType === 'SUBNET' && !defaultSubnetId) {
        defaultSubnetId = nodeId
      }
    }

    // Second pass: create nodes with parent relationships
    // Infer parent-child from node types since all edges are "connected_to"
    for (const node of (graphData.nodes ?? [])) {
      const nodeId = node?.data?.id
      if (!nodeId || nodeMap.has(nodeId)) continue

      // Skip non-CloudGoat resources if filter is enabled
      if (showOnlyCloudGoat && !isCloudGoatResource(nodeId, node?.data?.node_type)) {
        continue
      }

      const nodeType = node?.data?.node_type
      const rawLabel = node?.data?.label ?? nodeId ?? 'Unknown'

      // Determine parent for clustering based on node type hierarchy
      let parent = undefined
      if (clusterMode) {
        if (nodeType === 'SUBNET' && defaultVpcId) {
          // All subnets belong to the first VPC
          parent = defaultVpcId
        } else if (nodeType && ['EC2', 'RDS', 'LAMBDA'].includes(nodeType)) {
          // All compute resources belong to the first subnet
          parent = defaultSubnetId
        } else if (nodeType === 'SECURITY_GROUP' && defaultVpcId) {
          // Security groups are VPC-scoped - place them inside the VPC
          parent = defaultVpcId
        }
        // Global resources (IAM, S3, INTERNET) have no parent
      }

      const nodeData = {
        ...node?.data,
        id: nodeId,
        node_type: nodeType ?? 'UNKNOWN',
        label: truncateLabel(rawLabel),
        fullLabel: rawLabel,
        parent, // For compound node clustering
      }
      nodeMap.set(nodeId, { data: nodeData })
    }

    // Deduplicate edges by source-target pair (only include edges between visible nodes)
    const edgeMap = new Map<string, any>()
    let edgeId = 0
    let skippedEdges = 0
    for (const edge of (graphData.edges ?? [])) {
      const source = edge?.data?.source
      const target = edge?.data?.target
      const edgeType = edge?.data?.edge_type
      if (!source || !target) continue

      // Skip edges connected to filtered-out nodes
      if (showOnlyCloudGoat && (!isCloudGoatResource(source) || !isCloudGoatResource(target))) {
        console.log('[GraphPage] Skipping edge (not CloudGoat):', source, '->', target)
        continue
      }

      // CRITICAL: Skip edges if source or target nodes were not added to nodeMap
      // This prevents "Cannot create edge with nonexistant source" errors
      if (!nodeMap.has(source) || !nodeMap.has(target)) {
        console.warn('[GraphPage] Skipping edge (node missing from nodeMap):',
          source, '->', target,
          'sourceInMap:', nodeMap.has(source),
          'targetInMap:', nodeMap.has(target))
        skippedEdges++
        continue
      }

      const key = `${source}-${target}-${edgeType}`
      if (edgeMap.has(key)) continue

      edgeMap.set(key, {
        data: {
          ...edge?.data,
          id: `e${edgeId++}`,
          source,
          target,
          edge_type: edgeType ?? 'connected_to',
        }
      })
    }
    console.log('[GraphPage] Edge processing complete:', edgeMap.size, 'edges,', skippedEdges, 'skipped')

    const result = [...Array.from(nodeMap.values()), ...Array.from(edgeMap.values())]
    console.log('[GraphPage] Rendered graph with', nodeMap.size, 'nodes,', edgeMap.size, 'edges', showOnlyCloudGoat ? '(CloudGoat only)' : '(all resources)')
    return result
  }, [graphData, clusterMode, showOnlyCloudGoat]) // Re-compute when clusterMode or filter changes

  if (!scanId) {
    return (
      <div className="flex items-center justify-center h-full">
        <p>No scan selected</p>
      </div>
    )
  }

  const legendItems = [
    { type: 'INTERNET', label: 'Internet', color: NODE_COLORS.INTERNET },
    { type: 'VPC', label: 'VPC', color: NODE_COLORS.VPC },
    { type: 'SUBNET', label: 'Subnet', color: NODE_COLORS.SUBNET },
    { type: 'EC2', label: 'EC2 Instance', color: NODE_COLORS.EC2 },
    { type: 'RDS', label: 'RDS Database', color: NODE_COLORS.RDS },
    { type: 'LAMBDA', label: 'Lambda Function', color: NODE_COLORS.LAMBDA },
    { type: 'S3_BUCKET', label: 'S3 Bucket', color: NODE_COLORS.S3_BUCKET },
    { type: 'IAM_USER', label: 'IAM User', color: NODE_COLORS.IAM_USER },
    { type: 'IAM_ROLE', label: 'IAM Role', color: NODE_COLORS.IAM_ROLE },
    { type: 'SECURITY_GROUP', label: 'Security Group', color: NODE_COLORS.SECURITY_GROUP },
  ]

  const edgeLegendItems = [
    { type: 'exposes', label: 'Internet Exposure', color: '#EF4444' },
    { type: 'assumes_role', label: 'Role Assumption', color: '#F59E0B' },
    { type: 'trusts', label: 'Trust Relationship', color: '#A855F7' },
    { type: 'connected_to', label: 'Network Connection', color: '#64748B' },
  ]

  const handleBuildGraph = async () => {
    setIsBuildingGraph(true)
    try {
      await graphApi.build(scanId)
      // Refetch graph and attack paths after build is triggered
      setTimeout(() => {
        refetchGraph()
        refetchAttackPaths()
      }, 2000)
    } catch (error) {
      console.error('Failed to build graph:', error)
    } finally {
      setIsBuildingGraph(false)
    }
  }

  const handleZoomIn = () => {
    if (cyRef.current) cyRef.current.zoom({ level: Math.min(cyRef.current.zoom() * 1.3, 2.5) })
  }

  const handleZoomOut = () => {
    if (cyRef.current) cyRef.current.zoom({ level: Math.max(cyRef.current.zoom() / 1.3, 0.3) })
  }

  const handleFitGraph = () => {
    if (cyRef.current) cyRef.current.fit(null, 30)
  }

  return (
    <div className="flex h-full">
      <div className="flex-1 relative bg-slate-950">

        {/* Header - Environment Info */}
        <div className="absolute top-4 left-1/2 -translate-x-1/2 z-20">
          <div className="bg-slate-900/90 backdrop-blur rounded-lg border border-slate-700 px-4 py-2.5 shadow-xl flex items-center gap-3">
            {scanDetails?.aws_profile === 'cloudgoat-vulnerable' ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-400 bg-red-400/10 px-2 py-1 rounded border border-red-400/20">
                <ShieldAlert size={12} />
                🔴 CloudGoat Environment
              </span>
            ) : scanDetails?.aws_profile === 'threatmapper-readonly' ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-400 bg-blue-400/10 px-2 py-1 rounded border border-blue-400/20">
                <ShieldAlert size={12} />
                🔵 Production Environment
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 bg-slate-800 px-2 py-1 rounded border border-slate-700">
                <ShieldAlert size={12} />
                ⚪ {scanDetails?.aws_profile || 'Unknown'} Environment
              </span>
            )}
            <div className="h-4 w-px bg-slate-700" />
            <span className="text-xs text-slate-400 font-mono">
              {scanDetails?.aws_region || 'us-east-1'}
            </span>
            {scanDetails?.aws_account_id && (
              <>
                <div className="h-4 w-px bg-slate-700" />
                <span className="text-xs text-slate-500 font-mono">
                  {scanDetails.aws_account_id}
                </span>
              </>
            )}
          </div>
        </div>

        {isLoading && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-slate-500 text-sm animate-pulse">
              Loading graph…
            </div>
          </div>
        )}

        {graphError && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <Layers size={40} className="text-slate-700 mx-auto mb-3" />
              <p className="text-slate-400 text-sm">Graph not built yet</p>
            </div>
          </div>
        )}

        {/* Control Panel */}
        <div className="absolute top-4 left-4 z-10 flex flex-col gap-2">
          <div className="bg-slate-900/90 backdrop-blur rounded-lg border border-slate-700 p-2 shadow-xl">
            <div className="flex flex-col gap-1">
              <button
                onClick={handleBuildGraph}
                disabled={isBuildingGraph}
                className={clsx(
                  "p-2 rounded transition-colors",
                  isBuildingGraph
                    ? "bg-blue-400/20 text-blue-400 cursor-wait"
                    : "hover:bg-slate-800 text-slate-400 hover:text-white"
                )}
                title="Build graph and find attack paths"
              >
                {isBuildingGraph ? <Pause size={18} /> : <Play size={18} />}
              </button>
              <button
                onClick={() => { refetchGraph(); refetchAttackPaths(); }}
                className="p-2 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                title="Refresh graph and attack paths"
              >
                <RefreshCw size={18} />
              </button>
              <button
                onClick={handleZoomIn}
                className="p-2 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                title="Zoom in"
              >
                <ZoomIn size={18} />
              </button>
              <button
                onClick={handleZoomOut}
                className="p-2 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                title="Zoom out"
              >
                <ZoomOut size={18} />
              </button>
              <button
                onClick={handleFitGraph}
                className="p-2 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                title="Fit to screen"
              >
                <Maximize size={18} />
              </button>
            </div>
          </div>

          <div className="bg-slate-900/90 backdrop-blur rounded-lg border border-slate-700 p-3 shadow-xl">
            <div className="flex items-center justify-between gap-3 mb-2">
              <span className="text-xs font-medium text-slate-400">Edge labels</span>
              <button
                onClick={() => setShowEdgeLabels(!showEdgeLabels)}
                className="text-slate-400 hover:text-white transition-colors"
              >
                {showEdgeLabels ? <Eye size={16} /> : <EyeOff size={16} />}
              </button>
            </div>
            <div className="flex items-center justify-between gap-3 mb-2">
              <span className="text-xs font-medium text-slate-400">Clustering</span>
              <button
                onClick={() => setClusterMode(!clusterMode)}
                className={clsx(
                  'text-xs px-2 py-0.5 rounded transition-colors',
                  clusterMode
                    ? 'bg-blue-400/20 text-blue-400 border border-blue-400/30'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                )}
              >
                {clusterMode ? 'ON' : 'OFF'}
              </button>
            </div>
            <div className="flex items-center justify-between gap-3 mb-2">
              <span className="text-xs font-medium text-slate-400">CloudGoat only</span>
              <button
                onClick={() => setShowOnlyCloudGoat(!showOnlyCloudGoat)}
                className={clsx(
                  'text-xs px-2 py-0.5 rounded transition-colors',
                  showOnlyCloudGoat
                    ? 'bg-purple-400/20 text-purple-400 border border-purple-400/30'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                )}
              >
                {showOnlyCloudGoat ? 'ON' : 'OFF'}
              </button>
            </div>
            <div className="text-xs text-slate-500">Zoom: {(zoomLevel * 100).toFixed(0)}%</div>
          </div>
        </div>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 z-10">
          <div className="bg-slate-900/90 backdrop-blur rounded-lg border border-slate-700 p-3 shadow-xl max-h-[80vh] overflow-y-auto">
            <h3 className="text-xs font-semibold text-slate-300 mb-3">Node Types</h3>
            <div className="flex flex-col gap-1.5 mb-4">
              {legendItems.map(item => (
                <div key={item.type} className="flex items-center gap-2">
                  <div
                    className="rounded"
                    style={{
                      width: 12,
                      height: 12,
                      backgroundColor: item.color,
                    }}
                  />
                  <span className="text-xs text-slate-400">{item.label}</span>
                </div>
              ))}
            </div>
            <h3 className="text-xs font-semibold text-slate-300 mb-2">Edge Types</h3>
            <div className="flex flex-col gap-1.5">
              {edgeLegendItems.map(item => (
                <div key={item.type} className="flex items-center gap-2">
                  <div
                    className="rounded"
                    style={{
                      width: 20,
                      height: 3,
                      backgroundColor: item.color,
                    }}
                  />
                  <span className="text-xs text-slate-400">{item.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Attack Paths Panel */}
        {!attackPathsLoading && attackPathsData && attackPathsData.items && attackPathsData.items.length > 0 && (
          <div className="absolute bottom-4 right-4 z-10 w-96 max-h-[60vh] overflow-y-auto">
            <div className="bg-slate-900/90 backdrop-blur rounded-lg border border-slate-700 p-4 shadow-xl">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Target size={16} className="text-red-400" />
                  <h3 className="text-sm font-semibold text-white">Attack Paths</h3>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">{attackPathsData.items.length} found</span>
                  <button
                    onClick={() => exportGraphAsPng(`attack-path-${scanId}.png`)}
                    className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                    title="Export as PNG"
                  >
                    <Download size={14} />
                  </button>
                </div>
              </div>
              <div className="space-y-2">
                {attackPathsData.items.map((path, idx) => (
                  <div key={path.path_id} className="space-y-2">
                    <button
                      onClick={() => {
                        if (path !== selectedAttackPath) {
                          userClosedAttackPathRef.current = false
                          setSelectedAttackPath(path)
                          highlightAttackPath(path, false)
                        } else {
                          userClosedAttackPathRef.current = true
                          setSelectedAttackPath(null)
                          cyRef.current?.elements().removeClass('attack-path attack-path-node attack-path-edge-highlight')
                        }
                      }}
                      className={clsx(
                        'w-full text-left p-2 rounded-lg border transition-colors',
                        selectedAttackPath?.path_id === path.path_id
                          ? 'bg-red-400/20 border-red-400/30'
                          : 'bg-slate-800/50 border-slate-700 hover:bg-slate-800'
                      )}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className={clsx(
                          'text-xs font-bold px-1.5 py-0.5 rounded',
                          path.severity === 'critical' ? 'bg-red-400/20 text-red-400' :
                          path.severity === 'high' ? 'bg-orange-400/20 text-orange-400' :
                          path.severity === 'medium' ? 'bg-amber-400/20 text-amber-400' :
                          'bg-slate-700 text-slate-400'
                        )}>
                          {path.severity}
                        </span>
                        <span className="text-xs font-mono text-slate-400">
                          Risk: {path.risk_score.toFixed(1)}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 font-mono truncate" title={path.path_string}>
                        {path.path_string}
                      </p>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* No Attack Paths Banner */}
        {!attackPathsLoading && attackPathsData && (!attackPathsData.items || attackPathsData.items.length === 0) && (
          <div className="absolute bottom-4 right-4 z-10 w-80">
            <div className="bg-emerald-400/10 backdrop-blur rounded-lg border border-emerald-400/20 p-4 shadow-xl">
              <div className="flex items-center gap-2">
                <ShieldAlert size={16} className="text-emerald-400" />
                <div>
                  <p className="text-sm text-emerald-400 font-medium">No Attack Paths Found</p>
                  <p className="text-xs text-slate-400 mt-0.5">
                    No attack paths detected from internet or compromised credentials
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Attack Path Detail Panel - Right side, below AI Report panel */}
        {selectedAttackPath && (
          <div className="absolute top-24 right-4 z-50 w-96">
            <div className="bg-slate-900/95 backdrop-blur rounded-lg border border-red-400/30 shadow-2xl relative" style={{ maxHeight: 'calc(100vh - 12rem)', overflowY: 'auto' }}>
              {/* Close button */}
              <button
                onClick={() => {
                  setSelectedAttackPath(null)
                  userClosedAttackPathRef.current = true
                  if (cyRef.current) {
                    cyRef.current.elements().removeClass('attack-path attack-path-node attack-path-edge-highlight')
                  }
                }}
                className="absolute top-3 right-3 z-[100] hover:bg-slate-800 rounded p-1 text-slate-400 hover:text-white transition-colors"
                style={{ pointerEvents: 'auto' }}
                title="Close"
              >
                <X size={20} strokeWidth={2.5} />
              </button>
              <div className="p-4 pt-10 space-y-3">
                {/* Severity and Risk */}
                <div className="flex items-center gap-2">
                  <span className={clsx(
                    'text-xs font-bold px-2 py-1 rounded',
                    selectedAttackPath.severity === 'critical' ? 'bg-red-400/20 text-red-400' :
                    selectedAttackPath.severity === 'high' ? 'bg-orange-400/20 text-orange-400' :
                    selectedAttackPath.severity === 'medium' ? 'bg-amber-400/20 text-amber-400' :
                    'bg-slate-700 text-slate-400'
                  )}>
                    {selectedAttackPath.severity.toUpperCase()}
                  </span>
                  <span className="text-xs text-slate-400">
                    Risk Score: <span className="text-white font-mono">{selectedAttackPath.risk_score.toFixed(1)}</span>
                  </span>
                </div>

                {/* Path Visualization */}
                <div className="p-2 bg-slate-800 rounded-lg">
                  <p className="text-xs text-slate-400 mb-2">Attack Path:</p>
                  <div className="flex items-center flex-wrap gap-1">
                    {selectedAttackPath.path_string.split(' → ').map((step, idx, arr) => (
                      <div key={idx} className="flex items-center">
                        <span className="text-xs text-white font-mono px-2 py-1 bg-slate-700 rounded">
                          {step.trim().substring(0, 20)}{step.trim().length > 20 ? '...' : ''}
                        </span>
                        {idx < arr.length - 1 && (
                          <ChevronRight size={12} className="text-slate-500 mx-0.5" />
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Score Breakdown */}
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2 bg-slate-800 rounded">
                    <p className="text-xs text-slate-500">Reachability</p>
                    <p className="text-sm font-mono text-white">{selectedAttackPath.reachability_score.toFixed(2)}</p>
                  </div>
                  <div className="p-2 bg-slate-800 rounded">
                    <p className="text-xs text-slate-500">Impact</p>
                    <p className="text-sm font-mono text-white">{selectedAttackPath.impact_score.toFixed(2)}</p>
                  </div>
                  <div className="p-2 bg-slate-800 rounded">
                    <p className="text-xs text-slate-500">Exploitability</p>
                    <p className="text-sm font-mono text-white">{selectedAttackPath.exploitability_score.toFixed(2)}</p>
                  </div>
                  <div className="p-2 bg-slate-800 rounded">
                    <p className="text-xs text-slate-500">Exposure</p>
                    <p className="text-sm font-mono text-white">{selectedAttackPath.exposure_score.toFixed(2)}</p>
                  </div>
                </div>

                {/* Hop Count */}
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <span>Hops:</span>
                  <span className="text-white font-mono">{selectedAttackPath.hop_count}</span>
                </div>

                {/* AI Analysis Sections */}
                {selectedAttackPath.ai_privilege_escalation?.detected && (
                  <div className="mt-4 pt-4 border-t border-slate-700">
                    <div className="flex items-center gap-2 mb-3">
                      <ShieldAlert size={16} className="text-red-400" />
                      <h4 className="text-sm font-semibold text-white">IAM Privilege Escalation Detected</h4>
                    </div>

                    <div className="space-y-3">
                      <div className="p-2 bg-red-500/10 border border-red-500/30 rounded">
                        <p className="text-xs text-red-300 font-medium">
                          {selectedAttackPath.ai_privilege_escalation.true_risk_assessment || 'Privilege escalation risk detected'}
                        </p>
                      </div>

                      {selectedAttackPath.ai_escalation_techniques && selectedAttackPath.ai_escalation_techniques.length > 0 && (
                        <div>
                          <p className="text-xs text-slate-400 mb-2">Techniques ({selectedAttackPath.ai_escalation_techniques.length}):</p>
                          <div className="space-y-2 max-h-48 overflow-y-auto">
                            {selectedAttackPath.ai_escalation_techniques.map((tech, idx) => (
                              <div key={idx} className="p-2 bg-slate-800 rounded border border-slate-700">
                                <p className="text-xs font-medium text-white">{tech.technique_name}</p>
                                <p className="text-xs text-slate-400 mt-1">{tech.category}</p>
                                <div className="mt-2 space-y-1">
                                  <div className="flex items-center gap-1">
                                    <Lock size={10} className="text-amber-400" />
                                    <code className="text-xs text-amber-400 truncate">{tech.required_permissions.join(', ')}</code>
                                  </div>
                                  <p className="text-xs text-slate-500">{tech.why_dangerous}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {selectedAttackPath.ai_remediation_priority && (
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-slate-400">Priority:</span>
                          <span className={clsx(
                            'text-xs font-bold px-2 py-0.5 rounded',
                            selectedAttackPath.ai_remediation_priority === 'immediate' ? 'bg-red-500/20 text-red-400' :
                            selectedAttackPath.ai_remediation_priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                            'bg-slate-700 text-slate-300'
                          )}>
                            {selectedAttackPath.ai_remediation_priority.toUpperCase()}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Threat Actor TTP Mapping */}
                {selectedAttackPath.ai_threat_actors && selectedAttackPath.ai_threat_actors.length > 0 && (
                  <div className="mt-4 pt-4 border-t border-slate-700">
                    <div className="flex items-center gap-2 mb-3">
                      <Target size={16} className="text-purple-400" />
                      <h4 className="text-sm font-semibold text-white">Threat Actor TTP Mapping</h4>
                    </div>

                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {selectedAttackPath.ai_threat_actors.map((actor, idx) => (
                        <div key={idx} className="p-2 bg-slate-800 rounded border border-slate-700">
                          <div className="flex items-center justify-between">
                            <p className="text-xs font-medium text-white">{actor.actor_name}</p>
                            <span className={clsx(
                              'text-xs px-1.5 py-0.5 rounded',
                              actor.similarity === 'high' ? 'bg-red-500/20 text-red-400' :
                              actor.similarity === 'medium' ? 'bg-orange-500/20 text-orange-400' :
                              'bg-slate-700 text-slate-400'
                            )}>
                              {actor.similarity} match
                            </span>
                          </div>
                          <p className="text-xs text-slate-400 mt-1">{actor.actor_type}</p>
                          {actor.overlapping_techniques.length > 0 && (
                            <div className="mt-1.5">
                              <p className="text-xs text-slate-500">Overlapping:</p>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {actor.overlapping_techniques.map((t, tIdx) => (
                                  <span key={tIdx} className="text-xs text-purple-300 bg-purple-500/10 px-1 rounded">
                                    {t}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                          {actor.source && (
                            <p className="text-xs text-slate-500 mt-1.5 italic">Source: {actor.source}</p>
                          )}
                        </div>
                      ))}
                    </div>

                    {selectedAttackPath.ai_mitre_mapping && (
                      <div className="mt-3 p-2 bg-slate-800 rounded border border-slate-700">
                        <p className="text-xs text-slate-400 mb-2">MITRE ATT&CK Cloud Matrix:</p>
                        <div className="space-y-1">
                          {selectedAttackPath.ai_mitre_mapping.tactics.map((tactic, idx) => (
                            <div key={idx} className="flex items-center gap-2">
                              <span className="text-xs text-purple-300 font-mono">{tactic.id}</span>
                              <span className="text-xs text-white">{tactic.name}</span>
                              {tactic.techniques_used.length > 0 && (
                                <span className="text-xs text-slate-500">({tactic.techniques_used.length} techniques)</span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Blast Radius Quantification */}
                {selectedAttackPath.ai_blast_radius && (
                  <div className="mt-4 pt-4 border-t border-slate-700">
                    <div className="flex items-center gap-2 mb-3">
                      <Radio size={16} className="text-orange-400" />
                      <h4 className="text-sm font-semibold text-white">Blast Radius</h4>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <div className="p-2 bg-slate-800 rounded">
                        <p className="text-xs text-slate-500">Resources at Risk</p>
                        <p className="text-lg font-mono text-white">{selectedAttackPath.ai_blast_radius.total_resources_at_risk}</p>
                      </div>
                      <div className="p-2 bg-slate-800 rounded">
                        <p className="text-xs text-slate-500">IAM Principals</p>
                        <p className="text-lg font-mono text-white">{selectedAttackPath.ai_blast_radius.iam_principals_accessible}</p>
                      </div>
                    </div>

                    <div className="mt-3 space-y-2">
                      <div className="p-2 bg-slate-800 rounded border border-slate-700">
                        <p className="text-xs text-slate-400 mb-1">Compute Resources</p>
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-slate-500">EC2:</span>
                          <span className="text-white font-mono">{selectedAttackPath.ai_blast_radius.compute_resources_at_risk.ec2_instances}</span>
                          {selectedAttackPath.ai_blast_radius.compute_resources_at_risk.can_deploy_code && (
                            <span className="text-red-400">(can deploy code)</span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-slate-500">Lambda:</span>
                          <span className="text-white font-mono">{selectedAttackPath.ai_blast_radius.compute_resources_at_risk.lambda_functions}</span>
                        </div>
                      </div>

                      <div className="p-2 bg-slate-800 rounded border border-slate-700">
                        <p className="text-xs text-slate-400 mb-1">Data Assets</p>
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-slate-500">S3 Buckets:</span>
                          <span className="text-white font-mono">{selectedAttackPath.ai_blast_radius.data_assets_accessible.s3_buckets}</span>
                        </div>
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-slate-500">RDS:</span>
                          <span className="text-white font-mono">{selectedAttackPath.ai_blast_radius.data_assets_accessible.rds_instances}</span>
                        </div>
                      </div>

                      <div className="p-2 bg-slate-800 rounded border border-slate-700">
                        <p className="text-xs text-slate-400 mb-1">Network Impact</p>
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-slate-500">VPCs:</span>
                          <span className="text-white font-mono">{selectedAttackPath.ai_blast_radius.network_infrastructure.vpcs_affected}</span>
                          {selectedAttackPath.ai_blast_radius.network_infrastructure.can_disable_logging && (
                            <span className="text-red-400">(can disable logging)</span>
                          )}
                        </div>
                      </div>
                    </div>

                    {selectedAttackPath.ai_compromise_timeline && (
                      <div className="mt-3 p-2 bg-slate-800 rounded border border-slate-700">
                        <p className="text-xs text-slate-400 mb-2">Estimated Compromise Timeline</p>
                        <div className="space-y-1 text-xs">
                          <div className="flex justify-between">
                            <span className="text-slate-500">Initial Access:</span>
                            <span className="text-white font-mono">{selectedAttackPath.ai_compromise_timeline.initial_access}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Privilege Escalation:</span>
                            <span className="text-white font-mono">{selectedAttackPath.ai_compromise_timeline.privilege_escalation}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Lateral Movement:</span>
                            <span className="text-white font-mono">{selectedAttackPath.ai_compromise_timeline.lateral_movement}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-slate-500">Full Compromise:</span>
                            <span className="text-white font-mono">{selectedAttackPath.ai_compromise_timeline.full_compromise}</span>
                          </div>
                        </div>
                        {selectedAttackPath.ai_compromise_timeline.confidence && (
                          <p className="text-xs text-slate-500 mt-2 italic">Confidence: {selectedAttackPath.ai_compromise_timeline.confidence}</p>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Step-by-Step Walkthrough - Removed to reduce panel height */}
              </div>
            </div>
          </div>
        )}

        {/* Node Details Panel */}
        {selectedNode && (
          <div className="absolute top-4 right-4 z-10 w-80 max-h-[80vh] overflow-y-auto">
            <div className="bg-slate-900/90 backdrop-blur rounded-lg border border-slate-700 p-4 shadow-xl">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-white">Node Details</h3>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  <X size={16} />
                </button>
              </div>
              <div className="space-y-2">
                <div>
                  <span className="text-xs text-slate-500">Type</span>
                  <p className="text-sm text-white font-mono">{selectedNode.node_type ?? 'Unknown'}</p>
                </div>
                <div>
                  <span className="text-xs text-slate-500">ID</span>
                  <p className="text-sm text-white font-mono break-all">{selectedNode.id ?? 'Unknown'}</p>
                </div>
                {selectedNode.label && (
                  <div>
                    <span className="text-xs text-slate-500">Label</span>
                    <p className="text-sm text-white font-mono break-all">{selectedNode.label}</p>
                  </div>
                )}
                {selectedNode.public && (
                  <div className="flex items-center gap-1 text-red-400">
                    <AlertTriangle size={14} />
                    <span className="text-xs font-medium">Publicly Exposed</span>
                  </div>
                )}
                {/* Blast Radius Action */}
                <div className="pt-3 mt-3 border-t border-slate-700">
                  <button
                    onClick={() => calculateBlastRadius(selectedNode.id)}
                    disabled={blastRadiusLoading}
                    className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-orange-500/20 hover:bg-orange-500/30 border border-orange-400/30 rounded-lg text-orange-400 hover:text-orange-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {blastRadiusLoading ? (
                      <>
                        <Radio size={16} className="animate-spin" />
                        <span className="text-xs font-medium">Calculating...</span>
                      </>
                    ) : (
                      <>
                        <Network size={16} />
                        <span className="text-xs font-medium">Calculate Blast Radius</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Blast Radius Results Panel */}
        {showBlastRadiusPanel && blastRadiusResult && (
          <div className="absolute top-4 right-4 z-10 w-[420px] max-h-[80vh] overflow-y-auto">
            <div className="bg-slate-900/90 backdrop-blur rounded-lg border border-orange-400/30 p-4 shadow-xl">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Radio size={18} className="text-orange-400" />
                  <h3 className="text-sm font-semibold text-white">Blast Radius Analysis</h3>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      cyRef.current?.elements().removeClass('blast-radius-reachable blast-radius-critical')
                      setShowBlastRadiusPanel(false)
                      setBlastRadiusResult(null)
                    }}
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    <X size={16} />
                  </button>
                </div>
              </div>

              {/* Compromised Node Info */}
              <div className="p-3 bg-orange-400/10 border border-orange-400/20 rounded-lg mb-3">
                <p className="text-xs text-orange-400 font-medium mb-1">If this node is compromised:</p>
                <p className="text-sm text-white font-mono">{blastRadiusResult.compromised_node_label}</p>
                <p className="text-xs text-slate-400">{blastRadiusResult.compromised_node_type}</p>
              </div>

              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-2 mb-3">
                <div className="p-2 bg-slate-800 rounded-lg text-center">
                  <p className="text-xs text-slate-500">Direct</p>
                  <p className="text-lg font-mono text-white">{blastRadiusResult.direct_reach_count}</p>
                  <p className="text-xs text-slate-400">1 hop</p>
                </div>
                <div className="p-2 bg-slate-800 rounded-lg text-center">
                  <p className="text-xs text-slate-500">Secondary</p>
                  <p className="text-lg font-mono text-white">{blastRadiusResult.secondary_reach_count}</p>
                  <p className="text-xs text-slate-400">2 hops</p>
                </div>
                <div className="p-2 bg-slate-800 rounded-lg text-center">
                  <p className="text-xs text-slate-500">Total</p>
                  <p className="text-lg font-mono text-white">{blastRadiusResult.total_reachable_count}</p>
                  <p className="text-xs text-slate-400">resources</p>
                </div>
              </div>

              {/* Severity Badge */}
              <div className="flex items-center justify-between mb-3 p-2 bg-slate-800 rounded-lg">
                <span className="text-xs text-slate-400">Blast Radius Severity:</span>
                <span className={
                  blastRadiusResult.blast_radius_severity === 'critical' ? 'text-xs font-bold px-2 py-1 rounded bg-red-400/20 text-red-400' :
                  blastRadiusResult.blast_radius_severity === 'high' ? 'text-xs font-bold px-2 py-1 rounded bg-orange-400/20 text-orange-400' :
                  blastRadiusResult.blast_radius_severity === 'medium' ? 'text-xs font-bold px-2 py-1 rounded bg-amber-400/20 text-amber-400' :
                  'text-xs font-bold px-2 py-1 rounded bg-slate-700 text-slate-400'
                }>
                  {blastRadiusResult.blast_radius_severity.toUpperCase()}
                </span>
              </div>

              {/* Critical Resources at Risk */}
              {blastRadiusResult.critical_count > 0 && (
                <div className="mb-3">
                  <div className="flex items-center gap-2 mb-2">
                    <Lock size={14} className="text-red-400" />
                    <span className="text-xs font-medium text-red-400">
                      Critical Resources at Risk ({blastRadiusResult.critical_count})
                    </span>
                  </div>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {blastRadiusResult.critical_at_risk.map((crit) => (
                      <div
                        key={crit.node_id}
                        className="p-2 bg-red-400/10 border border-red-400/20 rounded-lg"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-white font-mono truncate" title={crit.node_id}>
                            {crit.label}
                          </span>
                          {crit.is_admin && (
                            <span className="text-xs px-1.5 py-0.5 rounded bg-red-400/20 text-red-400">
                              ADMIN
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">{crit.node_type}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Attack Paths from this Node */}
              {blastRadiusResult.attack_paths_from_here && blastRadiusResult.attack_paths_from_here.length > 0 && (
                <div className="mb-3">
                  <div className="flex items-center gap-2 mb-2">
                    <Target size={14} className="text-orange-400" />
                    <span className="text-xs font-medium text-orange-400">
                      Attack Paths ({blastRadiusResult.attack_paths_from_here.length})
                    </span>
                  </div>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {blastRadiusResult.attack_paths_from_here.slice(0, 5).map((path, idx) => (
                      <div
                        key={idx}
                        className="p-2 bg-slate-800/50 border border-slate-700 rounded-lg"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className={
                            path.severity === 'critical' ? 'text-xs font-bold px-1.5 py-0.5 rounded bg-red-400/20 text-red-400' :
                            path.severity === 'high' ? 'text-xs font-bold px-1.5 py-0.5 rounded bg-orange-400/20 text-orange-400' :
                            path.severity === 'medium' ? 'text-xs font-bold px-1.5 py-0.5 rounded bg-amber-400/20 text-amber-400' :
                            'text-xs font-bold px-1.5 py-0.5 rounded bg-slate-700 text-slate-400'
                          }>
                            {path.severity}
                          </span>
                          <span className="text-xs text-slate-400">
                            Risk: {path.risk_score.toFixed(1)}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 font-mono truncate" title={path.path_string}>
                          {path.path_string}
                        </p>
                        <p className="text-xs text-slate-500 mt-0.5">
                          {path.hop_count} hops to {path.target_type}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Hop Distance Breakdown */}
              {blastRadiusResult.by_hop_distance && Object.keys(blastRadiusResult.by_hop_distance).length > 0 && (
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Unlock size={14} className="text-slate-400" />
                    <span className="text-xs font-medium text-slate-400">Reach by Hop Distance</span>
                  </div>
                  <div className="space-y-1">
                    {Object.entries(blastRadiusResult.by_hop_distance).slice(0, 4).map(([hop, nodes]) => (
                      <div key={hop} className="flex items-center justify-between text-xs">
                        <span className="text-slate-500">Hop {hop}:</span>
                        <span className="text-white font-mono">{nodes.length} resources</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* AI Report Panel - Positioned above attack path panel */}
        <div className="absolute top-4 right-4 z-20">
          {/* Toggle button */}
          {!showAiReportPanel ? (
            <button
              onClick={fetchAiSummary}
              disabled={aiSummaryLoading}
              className="flex items-center gap-2 px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-400/30 rounded-lg text-purple-400 hover:text-purple-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-xl"
            >
              {aiSummaryLoading ? (
                <>
                  <FileText size={16} className="animate-pulse" />
                  <span className="text-xs font-medium">Loading AI Report...</span>
                </>
              ) : (
                <>
                  <FileText size={16} />
                  <span className="text-xs font-medium">View AI Report</span>
                </>
              )}
            </button>
          ) : (
            <div className="w-[450px] max-h-[70vh] overflow-y-auto bg-slate-900/90 backdrop-blur rounded-lg border border-purple-400/30 p-4 shadow-xl">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <FileText size={18} className="text-purple-400" />
                  <h3 className="text-sm font-semibold text-white">AI Security Report</h3>
                </div>
                <button
                  onClick={() => setShowAiReportPanel(false)}
                  className="text-slate-400 hover:text-white transition-colors p-1 hover:bg-slate-800 rounded"
                  title="Close report"
                >
                  <X size={18} />
                </button>
              </div>

              {/* Tab Navigation */}
              <div className="flex gap-1 mb-3 border-b border-slate-700 pb-1">
                <button
                  onClick={() => setAiReportTab('summary')}
                  className={clsx(
                    'flex-1 text-xs px-2 py-1.5 rounded transition-colors',
                    aiReportTab === 'summary'
                      ? 'bg-purple-400/20 text-purple-400 border border-purple-400/30'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  )}
                >
                  Executive Summary
                </button>
                <button
                  onClick={() => setAiReportTab('quick-wins')}
                  className={clsx(
                    'flex-1 text-xs px-2 py-1.5 rounded transition-colors',
                    aiReportTab === 'quick-wins'
                      ? 'bg-emerald-400/20 text-emerald-400 border border-emerald-400/30'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  )}
                >
                  Quick Wins
                </button>
                <button
                  onClick={() => setAiReportTab('rankings')}
                  className={clsx(
                    'flex-1 text-xs px-2 py-1.5 rounded transition-colors',
                    aiReportTab === 'rankings'
                      ? 'bg-amber-400/20 text-amber-400 border border-amber-400/30'
                      : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  )}
                >
                  Priorities
                </button>
              </div>

              {/* Tab Content */}
              {aiSummary && (
                <div className="space-y-3">
                  {aiReportTab === 'summary' && (
                    <>
                      <div className="p-3 bg-purple-400/10 border border-purple-400/20 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <Zap size={14} className="text-purple-400" />
                          <span className="text-xs font-medium text-purple-400">Headline Risk</span>
                        </div>
                        <p className="text-sm text-white font-medium">{aiSummary.title}</p>
                      </div>
                      <div className="p-3 bg-slate-800 rounded-lg">
                        <p className="text-xs text-slate-400 mb-1">Executive Summary</p>
                        <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap">
                          {aiSummary.executive_summary}
                        </p>
                      </div>
                      {aiSummary.remediation_roadmap?.overall_risk_narrative && (
                        <div className="p-3 bg-slate-800 rounded-lg">
                          <p className="text-xs text-slate-400 mb-1">Risk Narrative</p>
                          <p className="text-sm text-slate-200 leading-relaxed">
                            {aiSummary.remediation_roadmap.overall_risk_narrative}
                          </p>
                        </div>
                      )}

                      {/* Enriched AI Analysis Section */}
                      {aiSummary.enriched_analysis && aiSummary.enriched_analysis.length > 0 && (
                        <div className="mt-4 space-y-4">
                          <h4 className="text-sm font-semibold text-white flex items-center gap-2">
                            <Target size={14} className="text-cyan-400" />
                            Enhanced Threat Intelligence
                          </h4>

                          {aiSummary.enriched_analysis.map((analysis, idx) => (
                            <div key={idx} className="p-3 bg-slate-800/50 border border-slate-700 rounded-lg space-y-3">
                              <p className="text-xs text-slate-400 font-mono truncate">{analysis.path_string}</p>

                              {/* Threat Actors */}
                              {analysis.threat_actors && analysis.threat_actors.length > 0 && (
                                <div>
                                  <div className="flex items-center gap-2 mb-2">
                                    <Target size={12} className="text-purple-400" />
                                    <span className="text-xs font-medium text-purple-300">Threat Actor TTP Mapping</span>
                                  </div>
                                  <div className="space-y-1.5">
                                    {analysis.threat_actors.map((actor, aIdx) => (
                                      <div key={aIdx} className="text-xs bg-purple-500/10 p-1.5 rounded">
                                        <span className="text-purple-200 font-medium">{actor.actor_name}</span>
                                        <span className="text-purple-400/70 ml-2">({actor.actor_type})</span>
                                        {actor.similarity === 'high' && <span className="text-red-400 ml-2">⚠ High match</span>}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Blast Radius */}
                              {analysis.blast_radius && (
                                <div>
                                  <div className="flex items-center gap-2 mb-2">
                                    <Radio size={12} className="text-orange-400" />
                                    <span className="text-xs font-medium text-orange-300">Blast Radius</span>
                                  </div>
                                  <div className="grid grid-cols-3 gap-2 text-xs">
                                    <div className="bg-slate-900 p-1.5 rounded text-center">
                                      <span className="text-slate-500 block">Resources</span>
                                      <span className="text-white font-mono">{analysis.blast_radius.total_resources_at_risk}</span>
                                    </div>
                                    <div className="bg-slate-900 p-1.5 rounded text-center">
                                      <span className="text-slate-500 block">Compute</span>
                                      <span className="text-white font-mono">{analysis.blast_radius.compute_resources_at_risk?.ec2_instances || 0} EC2</span>
                                    </div>
                                    <div className="bg-slate-900 p-1.5 rounded text-center">
                                      <span className="text-slate-500 block">Data</span>
                                      <span className="text-white font-mono">{analysis.blast_radius.data_assets_accessible?.s3_buckets || 0} S3</span>
                                    </div>
                                  </div>
                                </div>
                              )}

                              {/* IAM Escalation */}
                              {analysis.privilege_escalation?.detected && (
                                <div>
                                  <div className="flex items-center gap-2 mb-2">
                                    <ShieldAlert size={12} className="text-red-400" />
                                    <span className="text-xs font-medium text-red-300">IAM Privilege Escalation</span>
                                  </div>
                                  <div className="text-xs bg-red-500/10 p-1.5 rounded">
                                    <span className="text-red-200">{analysis.escalation_techniques?.length || 0} techniques detected</span>
                                    {analysis.privilege_escalation.remediation_priority === 'immediate' && (
                                      <span className="text-red-400 ml-2 font-bold">⚠ IMMEDIATE ACTION</span>
                                    )}
                                  </div>
                                </div>
                              )}

                              {/* Compromise Timeline */}
                              {analysis.compromise_timeline && (
                                <div>
                                  <div className="flex items-center gap-2 mb-2">
                                    <FileText size={12} className="text-amber-400" />
                                    <span className="text-xs font-medium text-amber-300">Estimated Compromise Timeline</span>
                                  </div>
                                  <div className="grid grid-cols-4 gap-1 text-xs">
                                    <div className="text-center">
                                      <span className="text-slate-500 block text-[10px]">Access</span>
                                      <span className="text-amber-200 font-mono">{analysis.compromise_timeline.initial_access}</span>
                                    </div>
                                    <div className="text-center">
                                      <span className="text-slate-500 block text-[10px]">Escalation</span>
                                      <span className="text-amber-200 font-mono">{analysis.compromise_timeline.privilege_escalation}</span>
                                    </div>
                                    <div className="text-center">
                                      <span className="text-slate-500 block text-[10px]">Lateral</span>
                                      <span className="text-amber-200 font-mono">{analysis.compromise_timeline.lateral_movement}</span>
                                    </div>
                                    <div className="text-center">
                                      <span className="text-slate-500 block text-[10px]">Full</span>
                                      <span className="text-amber-200 font-mono">{analysis.compromise_timeline.full_compromise}</span>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}

                  {aiReportTab === 'quick-wins' && (
                    <div className="space-y-2">
                      {aiSummary.priority_ranking?.[0]?.recommended_action && (
                        <div className="p-3 bg-emerald-400/10 border border-emerald-400/20 rounded-lg">
                          <div className="flex items-center gap-2 mb-2">
                            <CheckCircle size={14} className="text-emerald-400" />
                            <span className="text-xs font-medium text-emerald-400">Top Quick Win</span>
                          </div>
                          <p className="text-sm text-slate-200 mb-1">
                            {aiSummary.priority_ranking[0].recommended_action}
                          </p>
                          <p className="text-xs text-slate-400">
                            {aiSummary.priority_ranking[0].priority_reasoning}
                          </p>
                        </div>
                      )}
                      {aiSummary.remediation_roadmap?.immediate_actions?.slice(0, 3).map((action, idx) => (
                        <div key={idx} className="p-3 bg-slate-800 rounded-lg">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs font-bold text-emerald-400">#{idx + 1}</span>
                            <span className="text-xs text-slate-400">Effort: {action.effort}</span>
                          </div>
                          <p className="text-sm text-slate-200">{action.action}</p>
                          <p className="text-xs text-slate-500 mt-1">{action.rationale}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {aiReportTab === 'rankings' && (
                    <div className="space-y-2">
                      {aiSummary.priority_ranking?.slice(0, 5).map((item, idx) => (
                        <div key={idx} className="p-3 bg-slate-800 rounded-lg">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs font-bold text-amber-400">#{item.rank}</span>
                            <span className="text-xs text-slate-400 truncate flex-1">
                              {item.path_string}
                            </span>
                          </div>
                          <p className="text-xs text-slate-400">{item.priority_reasoning}</p>
                          <p className="text-sm text-slate-200 mt-1">{item.recommended_action}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {!aiSummary && !aiSummaryLoading && (
                <div className="text-center py-8">
                  <FileText size={32} className="text-slate-600 mx-auto mb-2" />
                  <p className="text-sm text-slate-400">No AI report available</p>
                  <p className="text-xs text-slate-500 mt-1">Run AI analysis first</p>
                </div>
              )}
            </div>
          )}
        </div>

        {!isLoading && !graphError && elements.length === 0 && graphData && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <Layers size={40} className="text-slate-700 mx-auto mb-3" />
              <p className="text-slate-400 text-sm">No graph data available</p>
              <p className="text-slate-500 text-xs mt-1">Run POST /graph/build/{scanId} first</p>
            </div>
          </div>
        )}

        {!isLoading && !graphError && elements.length > 0 && (
          <CytoscapeComponent
            elements={elements}
            stylesheet={[
              ...CY_STYLESHEET,
              ...(showEdgeLabels
                ? [
                    {
                      selector: 'edge',
                      style: {
                        label: 'data(edge_type)',
                        'font-size': '9px',
                        color: '#94A3B8',
                        'text-outline-width': 2,
                        'text-outline-color': '#0F172A',
                      },
                    },
                  ]
                : []),
            ]}
            cy={handleCyInit}
            layout={{
              name: 'fcose',
              quality: 'default',
              randomize: false,
              animate: false,
              fit: true,
              padding: 80,
              // Compound node options for BloodHound-style clustering
              nodeDimensionsIncludeLabels: true,
              nodeRepulsion: 8000,
              idealEdgeLength: 100,
              edgeElasticity: 50,
              nestingFactor: 0.15,
              gravity: 0.25,
              numIter: 1500,
              initialEnergyOnIncrement: 0.1,
              // Tiling options for better container layout
              tile: true,
              tilingPaddingVertical: 30,
              tilingPaddingHorizontal: 30,
              // Component grouping
              componentSpacing: 100,
            }}
            style={{ width: '100%', height: '100%' }}
            zoom={1}
            minZoom={0.3}
            maxZoom={2.5}
          />
        )}
      </div>
    </div>
  )
}
