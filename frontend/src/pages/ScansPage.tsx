import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  ScanSearch, Play, RefreshCw,
  CheckCircle2, Clock, XCircle, ChevronRight, GitFork,
} from 'lucide-react'
import { scansApi, graphApi, type ScanJob } from '../api/scanApi'
import clsx from 'clsx'

// ── Status badge ──────────────────────────────────────────────────────────────
function StatusBadge({ status }: { status: ScanJob['status'] }) {
  const cfg = {
    pending:  { color: 'text-slate-400 bg-slate-800',        icon: Clock,        label: 'Pending'  },
    running:  { color: 'text-amber-400 bg-amber-400/10',     icon: RefreshCw,    label: 'Running'  },
    complete: { color: 'text-emerald-400 bg-emerald-400/10', icon: CheckCircle2, label: 'Complete' },
    failed:   { color: 'text-red-400 bg-red-400/10',         icon: XCircle,      label: 'Failed'   },
  }[status] ?? { color: 'text-slate-400 bg-slate-800', icon: Clock, label: status }

  const Icon = cfg.icon
  return (
    <span className={clsx('inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium', cfg.color)}>
      <Icon size={11} className={status === 'running' ? 'animate-spin' : ''} />
      {cfg.label}
    </span>
  )
}

// ── Risk score pill ───────────────────────────────────────────────────────────
function RiskPill({ score }: { score: number | null }) {
  if (score === null || score === undefined) {
    return <span className="text-slate-600 text-xs">—</span>
  }
  const cls =
    score >= 8   ? 'text-red-400 bg-red-400/10' :
    score >= 6   ? 'text-orange-400 bg-orange-400/10' :
    score >= 3.5 ? 'text-amber-400 bg-amber-400/10' :
                   'text-slate-400 bg-slate-800'
  return (
    <span className={clsx('px-2 py-0.5 rounded text-xs font-mono font-medium', cls)}>
      {score.toFixed(1)}
    </span>
  )
}

// ── New scan form ─────────────────────────────────────────────────────────────
function NewScanForm({ onCreated }: { onCreated: () => void }) {
  const [profile, setProfile] = useState('threatmapper-readonly')
  const [region, setRegion] = useState('us-east-1')
  const [apiError, setApiError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () => scansApi.create(profile, region).then(r => r.data),
    onSuccess: () => { onCreated(); setApiError(null) },
    onError: (e: Error) => setApiError(e.message),
  })

  const REGIONS = [
    'us-east-1','us-east-2','us-west-1','us-west-2',
    'eu-west-1','eu-west-2','eu-central-1',
    'ap-southeast-1','ap-southeast-2','ap-northeast-1',
  ]

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
        <ScanSearch size={15} className="text-brand" />
        New Infrastructure Scan
      </h2>

      <div className="flex flex-wrap gap-3 items-end">
        <div className="flex-1 min-w-40">
          <label className="block text-xs text-slate-500 mb-1">AWS Profile</label>
          <input
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2
                       text-sm text-white placeholder-slate-600 focus:outline-none
                       focus:border-brand transition-colors"
            placeholder="threatmapper-readonly"
            value={profile}
            onChange={e => setProfile(e.target.value)}
          />
        </div>

        <div className="flex-1 min-w-40">
          <label className="block text-xs text-slate-500 mb-1">Region</label>
          <select
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2
                       text-sm text-white focus:outline-none focus:border-brand transition-colors"
            value={region}
            onChange={e => setRegion(e.target.value)}
          >
            {REGIONS.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>

        <button
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending || !profile.trim()}
          className="flex items-center gap-2 px-4 py-2 bg-brand hover:bg-brand/90
                     disabled:opacity-50 disabled:cursor-not-allowed
                     text-white text-sm font-medium rounded-lg transition-colors"
        >
          <Play size={14} />
          {mutation.isPending ? 'Starting…' : 'Start Scan'}
        </button>
      </div>

      {apiError && (
        <div className="mt-3 p-3 bg-red-400/10 border border-red-400/20 rounded-lg">
          <p className="text-xs text-red-400">{apiError}</p>
        </div>
      )}

      {mutation.isSuccess && (
        <div className="mt-3 p-3 bg-emerald-400/10 border border-emerald-400/20 rounded-lg">
          <p className="text-xs text-emerald-400">Scan started — check the history below for status updates.</p>
        </div>
      )}

      <p className="mt-3 text-xs text-slate-600">
        Profile must exist in <code className="font-mono">~/.aws/credentials</code> with read-only permissions.
      </p>
    </div>
  )
}

// ── Single scan row ───────────────────────────────────────────────────────────
function ScanRow({ job, onGraphClick }: {
  job: ScanJob
  onGraphClick: (id: string) => void
}) {
  const buildMutation = useMutation({
    mutationFn: () => graphApi.build(job.id).then(r => r.data),
  })

  return (
    <div className="flex items-center gap-4 px-4 py-3 border-b border-slate-800
                    last:border-0 hover:bg-slate-800/30 transition-colors">

      {/* Status */}
      <div className="w-28 flex-shrink-0">
        <StatusBadge status={job.status} />
      </div>

      {/* Profile + region + account */}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-white font-medium truncate">
          {job.aws_profile}
          <span className="text-slate-600 mx-2">·</span>
          <span className="text-slate-400 font-normal">{job.aws_region}</span>
        </p>
        <p className="text-xs text-slate-600 mt-0.5">
          {job.aws_account_id ? `Account: ${job.aws_account_id}` : 'Account pending…'}
          {' · '}
          {new Date(job.created_at).toLocaleString()}
        </p>
        {job.status === 'failed' && job.error_message && (
          <p className="text-xs text-red-400 mt-0.5 truncate" title={job.error_message}>
            {job.error_message.slice(0, 80)}
          </p>
        )}
      </div>

      {/* Resources */}
      <div className="text-center w-20 flex-shrink-0">
        <p className="text-sm font-mono text-white">{job.resource_count ?? '—'}</p>
        <p className="text-xs text-slate-600">resources</p>
      </div>

      {/* Risk score */}
      <div className="text-center w-20 flex-shrink-0">
        <RiskPill score={job.overall_risk_score} />
        <p className="text-xs text-slate-600 mt-1">risk</p>
      </div>

      {/* Attack paths */}
      <div className="text-center w-20 flex-shrink-0">
        <p className="text-sm font-mono text-white">{job.attack_path_count ?? '—'}</p>
        <p className="text-xs text-slate-600">paths</p>
      </div>

      {/* Action buttons */}
      <div className="flex items-center gap-2 flex-shrink-0 w-36">
        {job.status === 'complete' && !job.attack_path_count && (
          <button
            onClick={() => buildMutation.mutate()}
            disabled={buildMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs
                       bg-brand/20 text-brand hover:bg-brand/30 transition-colors
                       disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <GitFork size={12} />
            {buildMutation.isPending ? 'Queuing…' : 'Build Graph'}
          </button>
        )}

        {buildMutation.isSuccess && (
          <p className="text-xs text-emerald-400">Queued ✓</p>
        )}

        {job.status === 'complete' && job.resource_count != null && job.resource_count > 0 && (
          <button
            onClick={() => onGraphClick(job.id)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs
                       bg-emerald-400/10 text-emerald-400 hover:bg-emerald-400/20 transition-colors"
          >
            <ChevronRight size={12} />
            View Graph
          </button>
        )}
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function ScansPage() {
  const navigate = useNavigate()
  const qc = useQueryClient()

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
    // Simple fixed interval — avoids the React Query v5 callback signature issue
    refetchInterval: 5000,
    retry: 1,
  })

  const hasRunning = data?.items?.some(
    j => j.status === 'running' || j.status === 'pending'
  ) ?? false

  return (
    <div className="p-8 max-w-6xl mx-auto">

      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <ScanSearch size={22} className="text-brand" />
          Infrastructure Scans
        </h1>
        <p className="text-slate-400 mt-1">
          Scan your AWS environment to build the threat surface attack graph.
        </p>
      </div>

      <div className="space-y-4">

        {/* New scan form */}
        <NewScanForm onCreated={() => qc.invalidateQueries({ queryKey: ['scans'] })} />

        {/* Scan history */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <h2 className="text-sm font-semibold text-white">Scan History</h2>
              {hasRunning && (
                <span className="flex items-center gap-1.5 text-xs text-amber-400">
                  <RefreshCw size={10} className="animate-spin" />
                  Live
                </span>
              )}
            </div>
            <span className="text-xs text-slate-500">{data?.total ?? 0} total</span>
          </div>

          {/* Loading */}
          {isLoading && (
            <div className="px-4 py-10 text-center text-slate-500 text-sm">
              Loading…
            </div>
          )}

          {/* API error */}
          {isError && (
            <div className="px-4 py-8 text-center">
              <p className="text-red-400 text-sm">Could not load scans</p>
              <p className="text-slate-600 text-xs mt-1">
                {(error as Error)?.message ?? 'Check that the backend is running.'}
              </p>
            </div>
          )}

          {/* Empty state */}
          {!isLoading && !isError && data?.items?.length === 0 && (
            <div className="px-4 py-12 text-center">
              <ScanSearch size={32} className="text-slate-700 mx-auto mb-3" />
              <p className="text-slate-500 text-sm">No scans yet.</p>
              <p className="text-slate-600 text-xs mt-1">
                Enter your AWS profile above and click Start Scan.
              </p>
            </div>
          )}

          {/* Scan rows */}
          {data?.items?.map(job => (
            <ScanRow
              key={job.id}
              job={job}
              onGraphClick={id => navigate(`/graph?scan=${id}`)}
            />
          ))}
        </div>

      </div>
    </div>
  )
}
