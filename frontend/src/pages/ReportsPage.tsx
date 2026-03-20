import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  FileText, Brain, AlertTriangle, ChevronDown, ChevronRight,
  Zap, Clock, TrendingUp, RefreshCw, Play, Shield,
} from 'lucide-react'
import { scansApi, aiApi, type ScanJob, type AISummary } from '../api/scanApi'
import clsx from 'clsx'

// ── Helpers ───────────────────────────────────────────────────────────────────
function severityColor(s: string) {
  return {
    critical: 'text-red-400', high: 'text-orange-400',
    medium: 'text-amber-400', low: 'text-slate-400',
  }[s] ?? 'text-slate-400'
}
function effortBadge(effort: string) {
  const cfg = {
    low:    'bg-emerald-400/10 text-emerald-400',
    medium: 'bg-amber-400/10 text-amber-400',
    high:   'bg-red-400/10 text-red-400',
  }[effort] ?? 'bg-slate-800 text-slate-400'
  return <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', cfg)}>{effort}</span>
}

// ── Scan selector ─────────────────────────────────────────────────────────────
function ScanSelector({
  selectedId,
  onSelect,
}: {
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  const { data } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list(50).then(r => r.data),
  })

  const completed = data?.items?.filter(j => j.status === 'complete') ?? []

  return (
    <div className="flex items-center gap-3">
      <label className="text-sm text-slate-400">Scan:</label>
      <select
        className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2
                   text-sm text-white focus:outline-none focus:border-brand"
        value={selectedId ?? ''}
        onChange={e => onSelect(e.target.value)}
      >
        <option value="">Select a completed scan…</option>
        {completed.map(j => (
          <option key={j.id} value={j.id}>
            {j.aws_profile} · {j.aws_region} · {new Date(j.created_at).toLocaleDateString()}
            {j.aws_account_id ? ` · ${j.aws_account_id}` : ''}
          </option>
        ))}
      </select>
    </div>
  )
}

// ── AI status banner ──────────────────────────────────────────────────────────
function AIStatusBanner({ scanId }: { scanId: string }) {
  const { data: status, refetch } = useQuery({
    queryKey: ['ai-status', scanId],
    queryFn: () => aiApi.getStatus(scanId).then(r => r.data),
    refetchInterval: data => (!data?.ai_available ? 8000 : false),
  })

  const { data: provider } = useQuery({
    queryKey: ['ai-provider'],
    queryFn: () => aiApi.getProvider().then(r => r.data),
  })

  const triggerMutation = useMutation({
    mutationFn: () => aiApi.triggerAnalysis(scanId).then(r => r.data),
    onSuccess: () => { refetch() },
  })

  if (!status) return null

  if (status.ai_available) {
    return (
      <div className="flex items-center gap-3 px-4 py-3 bg-emerald-400/10
                      border border-emerald-400/20 rounded-xl text-sm">
        <Brain size={16} className="text-emerald-400 flex-shrink-0" />
        <span className="text-emerald-400 font-medium">AI analysis complete</span>
        <span className="text-slate-400">
          · {status.annotated_paths} paths analysed · powered by {provider?.model ?? status.ai_provider}
        </span>
      </div>
    )
  }

  if (!provider?.ready) {
    return (
      <div className="flex items-center justify-between px-4 py-3 bg-amber-400/10
                      border border-amber-400/20 rounded-xl">
        <div className="flex items-center gap-3">
          <Brain size={16} className="text-amber-400" />
          <div>
            <p className="text-sm text-amber-400 font-medium">AI provider not configured</p>
            <p className="text-xs text-slate-400 mt-0.5">
              Add <code className="font-mono">AI_PROVIDER=gemini</code> and{' '}
              <code className="font-mono">GEMINI_API_KEY=your-key</code> to your{' '}
              <code className="font-mono">.env</code> then restart.
            </p>
          </div>
        </div>
        <span className="text-xs text-slate-500 bg-slate-800 px-2 py-1 rounded">
          stub mode — placeholder text
        </span>
      </div>
    )
  }

  return (
    <div className="flex items-center justify-between px-4 py-3 bg-brand/10
                    border border-brand/20 rounded-xl">
      <div className="flex items-center gap-3">
        <Brain size={16} className="text-brand" />
        <p className="text-sm text-brand font-medium">AI analysis not yet run for this scan</p>
      </div>
      <button
        onClick={() => triggerMutation.mutate()}
        disabled={triggerMutation.isPending}
        className="flex items-center gap-2 px-3 py-1.5 bg-brand hover:bg-brand/90
                   text-white text-xs font-medium rounded-lg transition-colors disabled:opacity-50"
      >
        {triggerMutation.isPending
          ? <><RefreshCw size={12} className="animate-spin" /> Queuing…</>
          : <><Play size={12} /> Run AI Analysis</>
        }
      </button>
    </div>
  )
}

// ── Executive summary card ────────────────────────────────────────────────────
function ExecutiveSummaryCard({ summary }: { summary: AISummary }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-800 flex items-center gap-2">
        <FileText size={16} className="text-brand" />
        <h2 className="text-sm font-semibold text-white">Executive Summary</h2>
        {summary.generated_at && (
          <span className="ml-auto text-xs text-slate-500">
            {new Date(summary.generated_at).toLocaleString()}
          </span>
        )}
      </div>
      <div className="px-5 py-4">
        {summary.executive_summary ? (
          <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
            {summary.executive_summary}
          </p>
        ) : (
          <p className="text-sm text-slate-500 italic">Executive summary not yet generated.</p>
        )}
      </div>
    </div>
  )
}

// ── Priority ranking card ─────────────────────────────────────────────────────
function PriorityRankingCard({ items }: { items: AISummary['priority_ranking'] }) {
  const [expanded, setExpanded] = useState<number | null>(0)

  if (!items?.length) return null

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-800 flex items-center gap-2">
        <TrendingUp size={16} className="text-amber-400" />
        <h2 className="text-sm font-semibold text-white">AI Priority Ranking</h2>
        <span className="ml-auto text-xs text-slate-500">{items.length} paths ranked</span>
      </div>
      <div className="divide-y divide-slate-800">
        {items.map((item, i) => (
          <div key={i} className="px-5 py-3">
            <button
              className="w-full flex items-center gap-3 text-left"
              onClick={() => setExpanded(expanded === i ? null : i)}
            >
              <span className="w-7 h-7 rounded-full bg-brand/20 text-brand text-xs
                               font-bold flex items-center justify-center flex-shrink-0">
                {item.rank}
              </span>
              <p className="text-sm text-slate-300 flex-1 truncate font-mono text-xs">
                {item.path_string}
              </p>
              {expanded === i
                ? <ChevronDown size={14} className="text-slate-500 flex-shrink-0" />
                : <ChevronRight size={14} className="text-slate-500 flex-shrink-0" />
              }
            </button>
            {expanded === i && (
              <div className="mt-3 pl-10 space-y-2">
                <p className="text-xs text-slate-400">{item.priority_reasoning}</p>
                {item.recommended_action && (
                  <div className="flex items-start gap-2 p-2 bg-brand/5 border border-brand/20 rounded">
                    <Zap size={12} className="text-brand mt-0.5 flex-shrink-0" />
                    <p className="text-xs text-brand">{item.recommended_action}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Remediation roadmap ───────────────────────────────────────────────────────
function RemediationRoadmap({
  roadmap,
}: {
  roadmap: AISummary['remediation_roadmap']
}) {
  if (!roadmap || Object.keys(roadmap).length === 0) return null

  const immediate = roadmap.immediate_actions ?? []
  const shortTerm = roadmap.short_term_fixes ?? []
  const strategic = roadmap.strategic_improvements ?? []

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-800 flex items-center gap-2">
        <Shield size={16} className="text-emerald-400" />
        <h2 className="text-sm font-semibold text-white">Remediation Roadmap</h2>
      </div>

      {roadmap.overall_risk_narrative && (
        <div className="px-5 py-4 border-b border-slate-800 bg-slate-800/30">
          <p className="text-xs text-slate-400 leading-relaxed">
            {roadmap.overall_risk_narrative}
          </p>
        </div>
      )}

      <div className="p-5 space-y-5">
        {/* Immediate */}
        {immediate.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle size={14} className="text-red-400" />
              <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider">
                Immediate Actions
              </h3>
            </div>
            <div className="space-y-2">
              {immediate.map((item, i) => (
                <div key={i} className="p-3 bg-red-400/5 border border-red-400/10 rounded-lg">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <p className="text-sm text-white font-medium">{item.action}</p>
                    {effortBadge(item.effort)}
                  </div>
                  <p className="text-xs text-slate-400">{item.rationale}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Short term */}
        {shortTerm.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Clock size={14} className="text-amber-400" />
              <h3 className="text-xs font-semibold text-amber-400 uppercase tracking-wider">
                Short-Term Fixes (30 days)
              </h3>
            </div>
            <div className="space-y-2">
              {shortTerm.map((item, i) => (
                <div key={i} className="p-3 bg-amber-400/5 border border-amber-400/10 rounded-lg">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <p className="text-sm text-white font-medium">{item.action}</p>
                    {effortBadge(item.effort)}
                  </div>
                  <p className="text-xs text-slate-400">{item.rationale}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Strategic */}
        {strategic.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <TrendingUp size={14} className="text-brand" />
              <h3 className="text-xs font-semibold text-brand uppercase tracking-wider">
                Strategic Improvements
              </h3>
            </div>
            <ul className="space-y-1.5">
              {strategic.map((item, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                  <span className="text-brand mt-0.5 flex-shrink-0">→</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function ReportsPage() {
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null)

  const { data: summaryData, isLoading: summaryLoading, error: summaryError } = useQuery({
    queryKey: ['ai-summary', selectedScanId],
    queryFn: () => aiApi.getSummary(selectedScanId!).then(r => r.data),
    enabled: !!selectedScanId,
    retry: false,
  })

  return (
    <div className="p-8 max-w-4xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <Brain size={22} className="text-brand" />
          AI Security Reports
        </h1>
        <p className="text-slate-400 mt-1">
          AI-generated executive summaries, risk prioritization, and remediation roadmaps.
        </p>
      </div>

      {/* Scan selector */}
      <div className="mb-5">
        <ScanSelector selectedId={selectedScanId} onSelect={setSelectedScanId} />
      </div>

      {!selectedScanId && (
        <div className="py-20 text-center">
          <Brain size={48} className="text-slate-700 mx-auto mb-4" />
          <p className="text-slate-400">Select a completed scan to view its AI analysis.</p>
        </div>
      )}

      {selectedScanId && (
        <div className="space-y-4">
          {/* AI status / trigger */}
          <AIStatusBanner scanId={selectedScanId} />

          {/* Summary loading */}
          {summaryLoading && (
            <div className="py-10 text-center text-slate-500 text-sm animate-pulse">
              Loading AI report…
            </div>
          )}

          {/* No report yet */}
          {summaryError && !summaryLoading && (
            <div className="py-10 text-center">
              <FileText size={36} className="text-slate-700 mx-auto mb-3" />
              <p className="text-slate-400 text-sm">No AI report yet for this scan.</p>
              <p className="text-slate-600 text-xs mt-1">
                Click <span className="text-brand">Run AI Analysis</span> above to generate one.
              </p>
            </div>
          )}

          {/* Report content */}
          {summaryData && (
            <>
              <ExecutiveSummaryCard summary={summaryData} />
              <PriorityRankingCard items={summaryData.priority_ranking} />
              <RemediationRoadmap roadmap={summaryData.remediation_roadmap} />
            </>
          )}
        </div>
      )}
    </div>
  )
}
