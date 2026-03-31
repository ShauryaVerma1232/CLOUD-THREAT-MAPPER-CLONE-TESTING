import { useState, useRef, useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import cytoscape from 'cytoscape'
import fcose from 'cytoscape-fcose'
import dagre from 'cytoscape-dagre'
import CytoscapeComponent from 'react-cytoscapejs'

cytoscape.use(fcose)
cytoscape.use(dagre)

import { AlertTriangle, X, Layers, ZoomIn, ZoomOut, Maximize, Eye, EyeOff, Box } from 'lucide-react'
import { graphApi, type CyNode } from '../api/scanApi'
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
  {
    selector: 'edge',
    style: {
      width: 2,
      'line-color': '#475569',
      'target-arrow-color': '#475569',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'control-point-step-size': 40,
      'control-point-weight': 0.5,
      'arrow-scale': 1.2,
      'line-opacity': 0.6,
      'target-arrow-opacity': 0.8,
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
  {
    selector: 'edge[type = "contains"]',
    style: {
      'line-style': 'dashed',
      'line-color': '#64748b',
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

export default function GraphPage() {
  const [searchParams] = useSearchParams()
  const scanId = searchParams.get('scan') ?? ''

  const cyRef = useRef<any>(null)

  const [selectedNode, setSelectedNode] = useState<CyNode['data'] | null>(null)
  const [showEdgeLabels, setShowEdgeLabels] = useState(false)
  const [zoomLevel, setZoomLevel] = useState(1)
  const [clusterMode, setClusterMode] = useState(true) // BloodHound-style clustering

  const { data: graphData, isLoading, error: graphError } = useQuery({
    queryKey: ['graph', scanId],
    enabled: !!scanId,
    retry: false,

    refetchOnWindowFocus: false,
    refetchOnMount: false,
    refetchOnReconnect: false,
    staleTime: Infinity,

    queryFn: () => graphApi.getGraph(scanId).then(r => r.data),
  })


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

  /* MEMOIZED ELEMENTS TO PREVENT RE-RENDER GRAPH RESET */
  const elements = useMemo(() => {
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
      console.log('[GraphPage] No graph data available')
      return []
    }

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
        }
        // Global resources (IAM, S3, INTERNET, SECURITY_GROUP) have no parent
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

    // Deduplicate edges by source-target pair
    const edgeMap = new Map<string, any>()
    let edgeId = 0
    for (const edge of (graphData.edges ?? [])) {
      const source = edge?.data?.source
      const target = edge?.data?.target
      const edgeType = edge?.data?.edge_type
      if (!source || !target) continue

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

    const result = [...Array.from(nodeMap.values()), ...Array.from(edgeMap.values())]
    console.log('[GraphPage] Rendered graph with', nodeMap.size, 'nodes,', edgeMap.size, 'edges')
    return result
  }, [graphData, clusterMode]) // Re-compute when clusterMode changes

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
            <div className="text-xs text-slate-500">Zoom: {(zoomLevel * 100).toFixed(0)}%</div>
          </div>
        </div>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 z-10">
          <div className="bg-slate-900/90 backdrop-blur rounded-lg border border-slate-700 p-3 shadow-xl max-h-96 overflow-y-auto">
            <h3 className="text-xs font-semibold text-slate-300 mb-2">Legend</h3>
            <div className="flex flex-col gap-1.5">
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
          </div>
        </div>

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
              </div>
            </div>
          </div>
        )}

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
