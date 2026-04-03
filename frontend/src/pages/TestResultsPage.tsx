import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Shield, ShieldAlert, ShieldCheck, FlaskConical,
  CheckCircle, XCircle, AlertTriangle, Info,
  ChevronDown, ChevronRight, Clock, Zap, Target,
  FileText, Download, RefreshCw,
} from 'lucide-react'
import { scansApi, type ScanJob } from '../api/scanApi'
import clsx from 'clsx'

// ── Types ─────────────────────────────────────────────────────────────────────
interface TestResult {
  id: string
  test_category: string
  test_name: string
  status: 'pass' | 'fail' | 'error' | 'skipped'
  exploitable: boolean | null
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null
  evidence: string | null
  remediation: string | null
  ai_explanation: string | null
  duration_ms: number | null
  created_at: string
}

interface SandboxJob {
  id: string
  scan_job_id: string
  status: string
  terraform_outputs: Record<string, unknown> | null
  created_at: string
  deployed_at: string | null
}

interface TestResultsData {
  sandbox_jobs: SandboxJob[]
  test_results: TestResult[]
  summary: {
    total_tests: number
    passed: number
    failed: number
    errors: number
    skipped: number
    exploitable_count: number
  }
}

// ── Status Badge ──────────────────────────────────────────────────────────────
function StatusBadge({ status }: { status: string }) {
  const cfg = {
    pass:     { color: 'text-emerald-400 bg-emerald-400/10', icon: CheckCircle, label: 'Pass' },
    fail:     { color: 'text-red-400 bg-red-400/10',       icon: XCircle,     label: 'Fail' },
    error:    { color: 'text-orange-400 bg-orange-400/10', icon: AlertTriangle, label: 'Error' },
    skipped:  { color: 'text-slate-400 bg-slate-800',      icon: Info,        label: 'Skipped' },
    pending:  { color: 'text-amber-400 bg-amber-400/10',   icon: Clock,       label: 'Pending' },
    running:  { color: 'text-blue-400 bg-blue-400/10',     icon: RefreshCw,   label: 'Running' },
    complete: { color: 'text-emerald-400 bg-emerald-400/10', icon: CheckCircle, label: 'Complete' },
    failed:   { color: 'text-red-400 bg-red-400/10',       icon: XCircle,     label: 'Failed' },
  }[status] ?? { color: 'text-slate-400 bg-slate-800', icon: Info, label: status }

  const Icon = cfg.icon
  return (
    <span className={clsx('inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium', cfg.color)}>
      <Icon size={11} className={status === 'running' ? 'animate-spin' : ''} />
      {cfg.label}
    </span>
  )
}

// ── Severity Badge ────────────────────────────────────────────────────────────
function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return null
  const cfg = {
    critical: 'text-red-400 bg-red-400/10 border-red-400/20',
    high:     'text-orange-400 bg-orange-400/10 border-orange-400/20',
    medium:   'text-amber-400 bg-amber-400/10 border-amber-400/20',
    low:      'text-blue-400 bg-blue-400/10 border-blue-400/20',
    info:     'text-slate-400 bg-slate-800 border-slate-700',
  }[severity] ?? 'text-slate-400 bg-slate-800'

  return (
    <span className={clsx('px-1.5 py-0.5 rounded text-xs font-medium border', cfg)}>
      {severity.toUpperCase()}
    </span>
  )
}

// ── Summary Stats Card ────────────────────────────────────────────────────────
function SummaryStatsCard({ summary }: { summary: TestResultsData['summary'] }) {
  const stats = [
    { label: 'Total Tests', value: summary.total_tests, color: 'text-white', icon: FlaskConical },
    { label: 'Passed', value: summary.passed, color: 'text-emerald-400', icon: CheckCircle },
    { label: 'Failed', value: summary.failed, color: 'text-red-400', icon: XCircle },
    { label: 'Errors', value: summary.errors, color: 'text-orange-400', icon: AlertTriangle },
    { label: 'Skipped', value: summary.skipped, color: 'text-slate-400', icon: Info },
    { label: 'Exploitable', value: summary.exploitable_count, color: 'text-red-400', icon: ShieldAlert },
  ]

  return (
    <div className="grid grid-cols-6 gap-3 mb-6">
      {stats.map(stat => (
        <div
          key={stat.label}
          className="bg-slate-900 border border-slate-800 rounded-xl p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <stat.icon size={18} className={stat.color} />
          </div>
          <p className={clsx('text-2xl font-bold', stat.color)}>
            {stat.value}
          </p>
          <p className="text-xs text-slate-500 mt-1">{stat.label}</p>
        </div>
      ))}
    </div>
  )
}

// ── Test Result Row ───────────────────────────────────────────────────────────
function TestResultRow({
  result,
  isExpanded,
  onToggle,
}: {
  result: TestResult
  isExpanded: boolean
  onToggle: () => void
}) {
  const statusColor = {
    pass: 'text-emerald-400',
    fail: 'text-red-400',
    error: 'text-orange-400',
    skipped: 'text-slate-400',
  }[result.status] ?? 'text-slate-400'

  const duration = result.duration_ms
    ? result.duration_ms >= 1000
      ? `${(result.duration_ms / 1000).toFixed(1)}s`
      : `${result.duration_ms}ms`
    : '—'

  return (
    <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/50">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-slate-800/30 transition-colors"
        onClick={onToggle}
      >
        <button className="text-slate-500 hover:text-white transition-colors">
          {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </button>

        {/* Status */}
        <div className="w-20 flex-shrink-0">
          <StatusBadge status={result.status} />
        </div>

        {/* Test Name */}
        <div className="flex-1 min-w-0">
          <p className="text-sm text-white font-medium truncate">
            {result.test_name}
          </p>
          <p className="text-xs text-slate-500">{result.test_category}</p>
        </div>

        {/* Severity */}
        <div className="w-24 flex-shrink-0">
          <SeverityBadge severity={result.severity} />
        </div>

        {/* Exploitable */}
        <div className="w-28 flex-shrink-0 text-right">
          {result.exploitable !== null && (
            <span className={clsx(
              'text-xs font-medium px-2 py-1 rounded',
              result.exploitable
                ? 'bg-red-400/20 text-red-400'
                : 'bg-emerald-400/20 text-emerald-400'
            )}>
              {result.exploitable ? 'Exploitable' : 'Not Exploitable'}
            </span>
          )}
        </div>

        {/* Duration */}
        <div className="w-20 flex-shrink-0 text-right">
          <span className="text-xs text-slate-500 font-mono">{duration}</span>
        </div>
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="px-4 pb-4 pt-2 border-t border-slate-800 space-y-3">
          {/* AI Explanation */}
          {result.ai_explanation && (
            <div className="p-3 bg-brand/5 border border-brand/20 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <Zap size={14} className="text-brand" />
                <span className="text-xs font-semibold text-brand">AI Analysis</span>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed">
                {result.ai_explanation}
              </p>
            </div>
          )}

          {/* Evidence */}
          {result.evidence && (
            <div>
              <p className="text-xs text-slate-500 mb-1">Evidence</p>
              <pre className="text-xs text-slate-300 bg-slate-950 p-3 rounded-lg overflow-x-auto max-h-48 overflow-y-auto font-mono">
                {result.evidence}
              </pre>
            </div>
          )}

          {/* Remediation */}
          {result.remediation && (
            <div className="p-3 bg-emerald-400/5 border border-emerald-400/20 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <ShieldCheck size={14} className="text-emerald-400" />
                <span className="text-xs font-semibold text-emerald-400">Remediation</span>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed">
                {result.remediation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Sandbox Job Card ──────────────────────────────────────────────────────────
function SandboxJobCard({ job }: { job: SandboxJob }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <FlaskConical size={18} className="text-brand" />
          <div>
            <h3 className="text-sm font-semibold text-white">Sandbox Environment</h3>
            <p className="text-xs text-slate-500 font-mono">{job.id}</p>
          </div>
        </div>
        <StatusBadge status={job.status} />
      </div>
      <div className="grid grid-cols-2 gap-4 text-xs">
        <div>
          <span className="text-slate-500">Created:</span>
          <span className="text-slate-300 ml-2">
            {new Date(job.created_at).toLocaleString()}
          </span>
        </div>
        <div>
          <span className="text-slate-500">Deployed:</span>
          <span className="text-slate-300 ml-2">
            {job.deployed_at ? new Date(job.deployed_at).toLocaleString() : 'Not yet deployed'}
          </span>
        </div>
      </div>
    </div>
  )
}

// ── Feature Not Available Placeholder ────────────────────────────────────────
function FeatureNotAvailablePlaceholder() {
  return (
    <div className="py-20 text-center">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-slate-800 mb-4">
        <FlaskConical size={32} className="text-slate-600" />
      </div>
      <h2 className="text-lg font-semibold text-white mb-2">Sandbox Testing</h2>
      <p className="text-slate-400 text-sm max-w-md mx-auto mb-4">
        The sandbox testing feature allows you to validate attack paths by deploying
        isolated clone environments and running security tests against them.
      </p>
      <div className="inline-flex items-center gap-2 px-4 py-2 bg-amber-400/10 border border-amber-400/20 rounded-lg">
        <Info size={14} className="text-amber-400" />
        <span className="text-xs text-amber-400">
          This feature is coming soon — Sandbox Clone Generator
        </span>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function TestResultsPage() {
  const [expandedTestId, setExpandedTestId] = useState<string | null>(null)
  const [selectedScan, setSelectedScan] = useState<string | null>(null)

  // Fetch scans for selector
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list(50).then(r => r.data),
  })

  // Fetch test results for selected scan
  // Note: This is mock data since the backend API isn't implemented yet
  const [mockTestResults] = useState<TestResultsData | null>(null)

  const completedScans = scansData?.items?.filter(j => j.status === 'complete') ?? []

  return (
    <div className="p-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-3">
              <FlaskConical size={22} className="text-brand" />
              Security Test Results
            </h1>
            <p className="text-slate-400 mt-1">
              Sandbox-validated security test results for attack path verification.
            </p>
          </div>
          <button
            className="flex items-center gap-2 px-4 py-2 bg-brand hover:bg-brand/90 text-white text-sm font-medium rounded-lg transition-colors"
            title="Export test results report"
            disabled
          >
            <Download size={16} />
            Export Report
          </button>
        </div>
      </div>

      {/* Scan Selector */}
      <div className="mb-6">
        <div className="flex items-center gap-3">
          <label className="text-sm text-slate-400">Scan:</label>
          <select
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-brand"
            value={selectedScan ?? ''}
            onChange={e => setSelectedScan(e.target.value || null)}
          >
            <option value="">Select a scan…</option>
            {completedScans.map(job => (
              <option key={job.id} value={job.id}>
                {job.aws_profile} · {job.aws_region} · {new Date(job.created_at).toLocaleDateString()}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Content */}
      {!selectedScan && (
        <FeatureNotAvailablePlaceholder />
      )}

      {selectedScan && !mockTestResults && (
        <div className="py-20 text-center">
          <Shield size={48} className="text-slate-700 mx-auto mb-4" />
          <p className="text-slate-400 text-sm">
            No sandbox tests have been run for this scan yet.
          </p>
          <p className="text-slate-600 text-xs mt-2">
            Sandbox testing feature is coming soon — Sandbox Clone Generator
          </p>
        </div>
      )}

      {mockTestResults && (
        <>
          {/* Summary Stats */}
          <SummaryStatsCard summary={mockTestResults.summary} />

          {/* Sandbox Jobs */}
          {mockTestResults.sandbox_jobs.length > 0 && (
            <div className="mb-6">
              <h2 className="text-sm font-semibold text-white mb-3">Sandbox Environments</h2>
              <div className="grid gap-3">
                {mockTestResults.sandbox_jobs.map(job => (
                  <SandboxJobCard key={job.id} job={job} />
                ))}
              </div>
            </div>
          )}

          {/* Test Results */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Target size={16} className="text-brand" />
                Test Results
              </h2>
              <span className="text-xs text-slate-500">
                {mockTestResults.test_results.length} tests
              </span>
            </div>
            <div className="space-y-2">
              {mockTestResults.test_results.map(result => (
                <TestResultRow
                  key={result.id}
                  result={result}
                  isExpanded={expandedTestId === result.id}
                  onToggle={() => setExpandedTestId(expandedTestId === result.id ? null : result.id)}
                />
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
