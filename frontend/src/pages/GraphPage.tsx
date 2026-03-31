import { useState, useRef, useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import cytoscape from 'cytoscape'
import fcose from 'cytoscape-fcose'
import dagre from 'cytoscape-dagre'
import CytoscapeComponent from 'react-cytoscapejs'

cytoscape.use(fcose)
cytoscape.use(dagre)

import { AlertTriangle, X, Layers, ZoomIn, ZoomOut, Maximize, Eye, EyeOff } from 'lucide-react'
import { graphApi, type CyNode } from '../api/scanApi'

const NODE_COLORS: Record<string, string> = {
  INTERNET: '#EF4444',
  EC2: '#3B82F6',
  IAM_ROLE: '#F59E0B',
  IAM_USER: '#8B5CF6',
  S3_BUCKET: '#10B981',
  VPC: '#6B7280',
  SUBNET: '#4B5563',
  SECURITY_GROUP: '#9CA3AF',
  RDS: '#EC4899',
  LAMBDA: '#06B6D4',
}

const CY_STYLESHEET = [
  {
    selector: 'node',
    style: {
      'background-color': (ele: any) =>
        NODE_COLORS[ele.data('node_type')] ?? '#64748b',
      label: 'data(label)',
      color: '#E2E8F0',
      'font-size': '11px',
      'font-family': 'system-ui, -apple-system, sans-serif',
      'font-weight': '500',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 6,
      'text-outline-width': 2,
      'text-outline-color': '#0F172A',
      'text-wrap': 'wrap',
      'text-max-width': '140px',
      width: (ele: any) => getNodeSize(ele.data('node_type')),
      height: (ele: any) => getNodeSize(ele.data('node_type')),
      'border-width': 3,
      'border-color': '#1E293B',
      'border-opacity': 1,
    },
  },
  { selector: 'node[?public]', style: { 'border-color': '#EF4444', 'border-width': 5, 'border-opacity': 1 } },
  { selector: 'node[node_type = "INTERNET"]', style: { shape: 'diamond', width: 55, height: 55 } },
  { selector: 'node[node_type = "VPC"]', style: { shape: 'rectangle', width: 70, height: 55 } },
  { selector: 'node[node_type = "SUBNET"]', style: { shape: 'round-rectangle', width: 50, height: 45 } },
  { selector: 'node[node_type = "EC2"]', style: { shape: 'round-rectangle', width: 50, height: 45 } },
  { selector: 'node[node_type = "RDS"]', style: { shape: 'round-rectangle', width: 50, height: 45 } },
  { selector: 'node[node_type = "S3_BUCKET"]', style: { shape: 'round-rectangle', width: 50, height: 45 } },
  { selector: 'node[node_type = "LAMBDA"]', style: { shape: 'round-rectangle', width: 48, height: 45 } },
  { selector: 'node[node_type = "SECURITY_GROUP"]', style: { shape: 'roundrectangle', width: 45, height: 42 } },
  {
    selector: 'edge',
    style: {
      width: 2.5,
      'line-color': '#64748b',
      'target-arrow-color': '#64748b',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'control-point-step-size': 50,
      'control-point-weight': 0.5,
      'arrow-scale': 1.5,
      'line-opacity': 0.8,
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
]

function getNodeSize(nodeType: string | undefined): number {
  if (!nodeType) return 45
  const sizes: Record<string, number> = {
    INTERNET: 55,
    VPC: 70,
    EC2: 50,
    RDS: 50,
    LAMBDA: 48,
    S3_BUCKET: 50,
    IAM_USER: 45,
    IAM_ROLE: 45,
    SUBNET: 50,
    SECURITY_GROUP: 45,
  }
  return sizes[nodeType] ?? 45
}

export default function GraphPage() {
  const [searchParams] = useSearchParams()
  const scanId = searchParams.get('scan') ?? ''

  const cyRef = useRef<any>(null)

  const [selectedNode, setSelectedNode] = useState<CyNode['data'] | null>(null)
  const [showEdgeLabels, setShowEdgeLabels] = useState(false)
  const [zoomLevel, setZoomLevel] = useState(1)

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

    // Deduplicate nodes by ID
    const nodeMap = new Map<string, any>()
    for (const node of (graphData.nodes ?? [])) {
      const nodeId = node?.data?.id
      if (!nodeId || nodeMap.has(nodeId)) continue

      const nodeType = node?.data?.node_type
      const nodeData = {
        ...node?.data,
        id: nodeId,
        node_type: nodeType ?? 'UNKNOWN',
        label: node?.data?.label ?? nodeId ?? 'Unknown',
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
    console.log('[GraphPage] Rendered graph with', nodeMap.size, 'nodes and', edgeMap.size, 'edges')
    return result
  }, [graphData])

  if (!scanId) {
    return (
      <div className="flex items-center justify-center h-full">
        <p>No scan selected</p>
      </div>
    )
  }

  const legendItems = [
    { type: 'INTERNET', label: 'Internet', color: NODE_COLORS.INTERNET, shape: 'diamond' },
    { type: 'EC2', label: 'EC2 Instance', color: NODE_COLORS.EC2, shape: 'circle' },
    { type: 'IAM_USER', label: 'IAM User', color: NODE_COLORS.IAM_USER, shape: 'circle' },
    { type: 'S3_BUCKET', label: 'S3 Bucket', color: NODE_COLORS.S3_BUCKET, shape: 'circle' },
    { type: 'VPC', label: 'VPC', color: NODE_COLORS.VPC, shape: 'rectangle' },
    { type: 'SUBNET', label: 'Subnet', color: NODE_COLORS.SUBNET, shape: 'round-rectangle' },
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
            <div className="text-xs text-slate-500">Zoom: {(zoomLevel * 100).toFixed(0)}%</div>
          </div>
        </div>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 z-10">
          <div className="bg-slate-900/90 backdrop-blur rounded-lg border border-slate-700 p-3 shadow-xl">
            <h3 className="text-xs font-semibold text-slate-300 mb-2">Legend</h3>
            <div className="flex flex-col gap-1.5">
              {legendItems.map(item => (
                <div key={item.type} className="flex items-center gap-2">
                  <div
                    className="rounded-sm"
                    style={{
                      width: 14,
                      height: 14,
                      backgroundColor: item.color,
                      borderRadius: item.shape === 'circle' ? '50%' : item.shape === 'diamond' ? '2px' : '2px',
                      transform: item.shape === 'diamond' ? 'rotate(45deg)' : 'none',
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
              name: 'dagre',
              rankDir: 'TB',           // Top to Bottom layout
              rankSep: 100,            // Spacing between ranks/layers
              nodeSep: 50,             // Spacing between nodes in same rank
              edgeSep: 30,             // Spacing between edges
              fit: true,
              padding: 50,
              animate: false,
              sort: undefined,         // Don't sort - let dagre decide optimal layout
              ranker: 'network-simplex' as any, // Better for hierarchical layouts
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
