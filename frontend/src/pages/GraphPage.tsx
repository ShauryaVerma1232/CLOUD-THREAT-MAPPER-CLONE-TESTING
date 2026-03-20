import { useState, useRef, useCallback, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import CytoscapeComponent from 'react-cytoscapejs'
import { GitFork, AlertTriangle, ChevronDown, ChevronRight, X, Layers } from 'lucide-react'
import { graphApi, type AttackPath, type CyNode } from '../api/scanApi'
import clsx from 'clsx'

const NODE_COLORS: Record<string, string> = {
  INTERNET: '#EF4444', EC2: '#3B82F6', IAM_ROLE: '#F59E0B', IAM_USER: '#8B5CF6',
  S3_BUCKET: '#10B981', VPC: '#6B7280', SUBNET: '#4B5563', SECURITY_GROUP: '#9CA3AF',
  RDS: '#EC4899', LAMBDA: '#06B6D4',
}

const CY_STYLESHEET = [
  { selector: 'node', style: {
    'background-color': (ele: any) => NODE_COLORS[ele.data('node_type')] ?? '#64748b',
    'label': 'data(label)', 'color': '#F1F5F9', 'font-size': '10px', 'font-family': 'monospace',
    'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 4,
    'text-outline-width': 2, 'text-outline-color': '#0F172A',
    'width': 32, 'height': 32, 'border-width': 2, 'border-color': '#1E293B',
  }},
  { selector: 'node[?public]', style: { 'border-color': '#EF4444', 'border-width': 3 }},
  { selector: 'node[node_type = "INTERNET"]', style: { 'shape': 'diamond', 'width': 42, 'height': 42 }},
  { selector: 'edge', style: {
    'width': 1.5, 'line-color': '#334155', 'target-arrow-color': '#334155',
    'target-arrow-shape': 'triangle', 'curve-style': 'bezier',
    'label': 'data(edge_type)', 'font-size': '8px', 'color': '#475569',
    'text-outline-width': 2, 'text-outline-color': '#0F172A',
  }},
  { selector: 'edge[edge_type = "exposes"]', style: { 'line-color': '#EF4444', 'target-arrow-color': '#EF4444', 'width': 2.5 }},
  { selector: 'edge[edge_type = "assumes_role"]', style: { 'line-color': '#F59E0B', 'target-arrow-color': '#F59E0B', 'line-style': 'dashed' }},
  { selector: 'edge[edge_type = "trusts"]', style: { 'line-color': '#EF4444', 'target-arrow-color': '#EF4444', 'line-style': 'dashed', 'width': 2 }},
  { selector: '.highlighted', style: { 'background-color': '#FCD34D', 'border-color': '#F59E0B', 'border-width': 4, 'z-index': 100 }},
  { selector: 'edge.highlighted', style: { 'line-color': '#FCD34D', 'target-arrow-color': '#FCD34D', 'width': 4, 'z-index': 100 }},
  { selector: '.dimmed', style: { opacity: 0.15 }},
]

function severityColor(s: string) {
  return { critical:'text-red-400', high:'text-orange-400', medium:'text-amber-400', low:'text-slate-400' }[s] ?? 'text-slate-400'
}
function severityBg(s: string) {
  return { critical:'bg-red-400/10 border-red-400/20', high:'bg-orange-400/10 border-orange-400/20',
    medium:'bg-amber-400/10 border-amber-400/20', low:'bg-slate-800 border-slate-700' }[s] ?? 'bg-slate-800 border-slate-700'
}

function PathItem({ path, selected, onSelect }: { path: AttackPath; selected: boolean; onSelect: () => void }) {
  return (
    <button onClick={onSelect} className={clsx('w-full text-left px-3 py-2.5 border rounded-lg transition-colors',
      selected ? 'bg-brand/20 border-brand/40' : clsx('border hover:bg-slate-800/60', severityBg(path.severity)))}>
      <div className="flex items-center justify-between mb-1">
        <span className={clsx('text-xs font-semibold uppercase', severityColor(path.severity))}>{path.severity}</span>
        <span className="text-xs font-mono text-white">{path.risk_score.toFixed(1)}</span>
      </div>
      <p className="text-xs text-slate-300 leading-snug line-clamp-2">{path.path_string}</p>
      <p className="text-xs text-slate-600 mt-1">{path.hop_count} hops</p>
    </button>
  )
}

function NodeInspector({ node, onClose }: { node: CyNode['data'] | null; onClose: () => void }) {
  if (!node) return null
  const color = NODE_COLORS[node.node_type] ?? '#64748b'
  return (
    <div className="absolute bottom-4 left-4 w-72 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl z-10 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
          <span className="text-xs text-slate-400 font-mono">{node.node_type}</span>
        </div>
        <button onClick={onClose} className="text-slate-600 hover:text-slate-300"><X size={14} /></button>
      </div>
      <div className="px-4 py-3 space-y-2 max-h-64 overflow-y-auto">
        <p className="text-sm font-medium text-white">{node.label}</p>
        {Object.entries(node).filter(([k]) => !['id','label','node_type'].includes(k)).map(([k, v]) => (
          <div key={k} className="flex justify-between gap-2">
            <span className="text-xs text-slate-500 flex-shrink-0">{k}</span>
            <span className="text-xs text-slate-300 text-right break-all font-mono">{String(v)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function GraphPage() {
  const [searchParams] = useSearchParams()
  const scanId = searchParams.get('scan') ?? ''
  const cyRef = useRef<any>(null)
  const [selectedNode, setSelectedNode] = useState<CyNode['data'] | null>(null)
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null)
  const [showPaths, setShowPaths] = useState(true)

  const { data: graphData, isLoading, error: graphError } = useQuery({
    queryKey: ['graph', scanId], enabled: !!scanId, retry: false,
    queryFn: () => graphApi.getGraph(scanId).then(r => r.data),
  })
  const { data: pathsData } = useQuery({
    queryKey: ['paths', scanId], enabled: !!scanId, retry: false,
    queryFn: () => graphApi.getPaths(scanId).then(r => r.data),
  })

  const highlightPath = useCallback(async (path: AttackPath | null) => {
    const cy = cyRef.current
    if (!cy) return
    cy.elements().removeClass('highlighted dimmed')
    if (!path) return
    try {
      const detail = await graphApi.getPathDetail(scanId, path.path_id).then(r => r.data)
      const nodeIds = new Set(detail.node_sequence)
      cy.elements().addClass('dimmed')
      nodeIds.forEach(id => cy.getElementById(id).removeClass('dimmed').addClass('highlighted'))
      for (let i = 0; i < detail.node_sequence.length - 1; i++) {
        cy.edges(`[source = "${detail.node_sequence[i]}"][target = "${detail.node_sequence[i+1]}"]`)
          .removeClass('dimmed').addClass('highlighted')
      }
    } catch {}
  }, [scanId])

  useEffect(() => { highlightPath(selectedPath) }, [selectedPath, highlightPath])

  const handleCyInit = useCallback((cy: any) => {
    cyRef.current = cy
    cy.on('tap', 'node', (evt: any) => setSelectedNode(evt.target.data()))
    cy.on('tap', (evt: any) => { if (evt.target === cy) setSelectedNode(null) })
  }, [])

  const elements = [...(graphData?.nodes ?? []), ...(graphData?.edges ?? [])]

  if (!scanId) return (
    <div className="flex items-center justify-center h-full">
      <div className="text-center">
        <GitFork size={48} className="text-slate-700 mx-auto mb-4" />
        <p className="text-slate-400 text-lg font-medium">No scan selected</p>
        <p className="text-slate-600 text-sm mt-2">Go to <span className="text-brand">Scans</span> and click "View Graph".</p>
      </div>
    </div>
  )

  return (
    <div className="flex h-full">
      {/* Left panel */}
      <div className="w-72 flex-shrink-0 flex flex-col bg-slate-900 border-r border-slate-800 overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 cursor-pointer"
          onClick={() => setShowPaths(p => !p)}>
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} className="text-red-400" />
            <span className="text-sm font-semibold text-white">Attack Paths</span>
            {pathsData && <span className="text-xs bg-red-400/10 text-red-400 px-1.5 py-0.5 rounded">{pathsData.critical_count} critical</span>}
          </div>
          {showPaths ? <ChevronDown size={14} className="text-slate-500" /> : <ChevronRight size={14} className="text-slate-500" />}
        </div>
        {showPaths && (
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {!pathsData?.items.length && <p className="text-xs text-slate-600 text-center py-6">No attack paths found yet.</p>}
            {pathsData?.items.map(path => (
              <PathItem key={path.path_id} path={path} selected={selectedPath?.path_id === path.path_id}
                onSelect={() => setSelectedPath(p => p?.path_id === path.path_id ? null : path)} />
            ))}
          </div>
        )}
        <div className="px-4 py-3 border-t border-slate-800">
          <p className="text-xs text-slate-600 mb-2 uppercase tracking-wider">Node Types</p>
          <div className="grid grid-cols-2 gap-1">
            {Object.entries(NODE_COLORS).slice(0, 8).map(([type, color]) => (
              <div key={type} className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
                <span className="text-xs text-slate-500 truncate">{type.replace('_',' ')}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Graph canvas */}
      <div className="flex-1 relative bg-slate-950">
        <div className="absolute top-4 left-4 z-10 flex items-center gap-2">
          <div className="bg-slate-900/90 border border-slate-800 rounded-lg px-3 py-2 flex items-center gap-3 text-xs text-slate-400">
            <span><span className="text-white font-mono">{graphData?.node_count ?? 0}</span> nodes</span>
            <span className="text-slate-700">·</span>
            <span><span className="text-white font-mono">{graphData?.edge_count ?? 0}</span> edges</span>
            {selectedPath && (
              <><span className="text-slate-700">·</span>
              <span className="text-amber-400">Path highlighted</span>
              <button onClick={() => setSelectedPath(null)} className="text-slate-600 hover:text-slate-300"><X size={12} /></button></>
            )}
          </div>
        </div>

        {isLoading && <div className="absolute inset-0 flex items-center justify-center"><div className="text-slate-500 text-sm animate-pulse">Loading graph…</div></div>}

        {graphError && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <Layers size={40} className="text-slate-700 mx-auto mb-3" />
              <p className="text-slate-400 text-sm">Graph not built yet</p>
              <p className="text-slate-600 text-xs mt-1">Go to Scans and click "Build Graph".</p>
            </div>
          </div>
        )}

        {!isLoading && !graphError && elements.length > 0 && (
          <CytoscapeComponent elements={elements} stylesheet={CY_STYLESHEET}
            layout={{ name: 'fcose', quality: 'proof', animate: true, animationDuration: 500,
              randomize: false, nodeRepulsion: 8000, idealEdgeLength: 120 } as any}
            cy={handleCyInit} style={{ width: '100%', height: '100%' }} />
        )}

        <NodeInspector node={selectedNode} onClose={() => setSelectedNode(null)} />
      </div>
    </div>
  )
}
