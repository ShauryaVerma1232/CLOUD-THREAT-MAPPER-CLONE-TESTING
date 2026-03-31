import { useState, useRef, useCallback, useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import cytoscape from 'cytoscape'
import fcose from 'cytoscape-fcose'
import CytoscapeComponent from 'react-cytoscapejs'

cytoscape.use(fcose)

import { GitFork, AlertTriangle, ChevronDown, ChevronRight, X, Layers } from 'lucide-react'
import { graphApi, type AttackPath, type CyNode } from '../api/scanApi'
import clsx from 'clsx'

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
      color: '#F1F5F9',
      'font-size': '10px',
      'font-family': 'monospace',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 4,
      'text-outline-width': 2,
      'text-outline-color': '#0F172A',
      width: 32,
      height: 32,
      'border-width': 2,
      'border-color': '#1E293B',
    },
  },
  { selector: 'node[?public]', style: { 'border-color': '#EF4444', 'border-width': 3 } },
  { selector: 'node[node_type = "INTERNET"]', style: { shape: 'diamond', width: 42, height: 42 } },
  {
    selector: 'edge',
    style: {
      width: 1.5,
      'line-color': '#334155',
      'target-arrow-color': '#334155',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      label: 'data(edge_type)',
      'font-size': '8px',
      color: '#475569',
      'text-outline-width': 2,
      'text-outline-color': '#0F172A',
    },
  },
]

export default function GraphPage() {
  const [searchParams] = useSearchParams()
  const scanId = searchParams.get('scan') ?? ''

  const cyRef = useRef<any>(null)

  const [selectedNode, setSelectedNode] = useState<CyNode['data'] | null>(null)
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null)
  const [showPaths, setShowPaths] = useState(true)

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

  const { data: pathsData } = useQuery({
    queryKey: ['paths', scanId],
    enabled: !!scanId,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    staleTime: Infinity,
    queryFn: () => graphApi.getPaths(scanId).then(r => r.data),
  })

  const handleCyInit = useCallback((cy: any) => {
    cyRef.current = cy

    cy.on('tap', 'node', (evt: any) => {
      setSelectedNode(evt.target.data())
    })

    cy.on('tap', (evt: any) => {
      if (evt.target === cy) setSelectedNode(null)
    })
  }, [])

  /* MEMOIZED ELEMENTS TO PREVENT RE-RENDER GRAPH RESET */
  const elements = useMemo(() => {
    if (!graphData) return []
    return [...(graphData.nodes ?? []), ...(graphData.edges ?? [])]
  }, [graphData])

  if (!scanId) {
    return (
      <div className="flex items-center justify-center h-full">
        <p>No scan selected</p>
      </div>
    )
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

        {!isLoading && !graphError && elements.length > 0 && (
          <CytoscapeComponent
            elements={elements}
            stylesheet={CY_STYLESHEET}
            cy={handleCyInit}
            layout={{
              name: 'fcose',
              quality: 'proof',
              animate: false,   // FIX: disable layout animation
              randomize: false,
              nodeRepulsion: 8000,
              idealEdgeLength: 120,
              fit: true,
            } as any}
            style={{ width: '100%', height: '100%' }}
          />
        )}
      </div>
    </div>
  )
}
