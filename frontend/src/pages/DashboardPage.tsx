import { useQuery } from '@tanstack/react-query'
import {
  ShieldAlert, ScanSearch, GitFork, FlaskConical,
  AlertTriangle, CheckCircle2, Activity,
  Cpu, Network, Brain, Box, Terminal, FileBarChart2,
  ChevronRight, Zap, Server, Database, Key, RefreshCw,
  TrendingUp, Clock, ArrowRight,
} from 'lucide-react'
import { healthApi } from '../api/client'
import { scansApi, graphApi, aiApi } from '../api/scanApi'
import { useNavigate } from 'react-router-dom'
import clsx from 'clsx'

// ── Types ─────────────────────────────────────────────────────────────────────
interface DashboardStats {
  totalScans: number
  completedScans: number
  failedScans: number
  totalAttackPaths: number
  criticalPaths: number
  highRiskPaths: number
  resourcesScanned: number
  aiAnalysesRun: number
}

interface ServiceStatus {
  name: string
  status: 'online' | 'offline' | 'degraded' | 'checking'
  detail?: string
  icon: React.ElementType
}

// ── Stat Card Component ───────────────────────────────────────────────────────
function StatCard({
  label,
  value,
  icon: Icon,
  color = 'brand',
  sublabel,
  trend,
  onClick,
}: {
  label: string
  value: string | number
  icon: React.ElementType
  color?: 'brand' | 'emerald' | 'amber' | 'red' | 'violet' | 'cyan'
  sublabel?: string
  trend?: { value: number; label: string }
  onClick?: () => void
}) {
  const colorMap = {
    brand: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
    emerald: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20',
    amber: 'text-amber-400 bg-amber-400/10 border-amber-400/20',
    red: 'text-red-400 bg-red-400/10 border-red-400/20',
    violet: 'text-violet-400 bg-violet-400/10 border-violet-400/20',
    cyan: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/20',
  }

  return (
    <div
      onClick={onClick}
      className={clsx(
        'bg-gradient-to-br from-slate-900 to-slate-900/50 border rounded-xl p-5',
        'hover:border-slate-600 transition-all duration-200',
        onClick && 'cursor-pointer hover:shadow-lg hover:shadow-blue-500/5'
      )}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-xs text-slate-500 uppercase tracking-widest mb-1.5">{label}</p>
          <p className="text-3xl font-bold text-white tabular-nums">{value}</p>
          {sublabel && (
            <p className={clsx(
              'text-xs mt-1.5',
              trend ? 'text-slate-600' : 'text-slate-500'
            )}>
              {sublabel}
            </p>
          )}
          {trend && (
            <div className="flex items-center gap-1 mt-1.5 text-emerald-400">
              <TrendingUp size={10} />
              <span className="text-xs font-medium">{trend.value}</span>
              <span className="text-xs text-slate-500">{trend.label}</span>
            </div>
          )}
        </div>
        <div className={clsx(
          'w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 border',
          colorMap[color]
        )}>
          <Icon size={18} />
        </div>
      </div>
    </div>
  )
}

// ── Service Row Component ─────────────────────────────────────────────────────
function ServiceRow({ name, status, detail, icon: Icon }: {
  name: string
  status: 'online' | 'offline' | 'degraded' | 'checking'
  detail?: string
  icon: React.ElementType
}) {
  const statusConfig = {
    online: { color: 'text-emerald-400', bg: 'bg-emerald-400/10', dot: 'bg-emerald-400' },
    offline: { color: 'text-red-400', bg: 'bg-red-400/10', dot: 'bg-red-400' },
    degraded: { color: 'text-amber-400', bg: 'bg-amber-400/10', dot: 'bg-amber-400' },
    checking: { color: 'text-slate-500', bg: 'bg-slate-800', dot: 'bg-slate-500 animate-pulse' },
  }

  const cfg = statusConfig[status]

  return (
    <div className="flex items-center justify-between py-3 px-3 rounded-lg hover:bg-slate-800/30 transition-colors">
      <div className="flex items-center gap-3">
        <div className={clsx('w-2 h-2 rounded-full', cfg.dot)} />
        <Icon size={16} className="text-slate-400" />
        <span className="text-sm text-slate-200 font-medium">{name}</span>
      </div>
      <div className="flex items-center gap-2">
        {detail && (
          <span className="text-xs text-slate-500 font-mono">{detail}</span>
        )}
        <span className={clsx(
          'text-xs font-medium px-2 py-0.5 rounded-full',
          cfg.bg, cfg.color
        )}>
          {status}
        </span>
      </div>
    </div>
  )
}

// ── Pipeline Phase Component ─────────────────────────────────────────────────
function PipelinePhase({
  phase,
  isComplete,
  isCurrent,
}: {
  phase: { day: number; label: string; items: string[]; icon: React.ElementType }
  isComplete: boolean
  isCurrent: boolean
}) {
  const Icon = phase.icon

  return (
    <div className={clsx(
      'relative flex items-start gap-3 p-3 rounded-lg border transition-all duration-200',
      isComplete
        ? 'bg-emerald-950/20 border-emerald-400/20 hover:border-emerald-400/30'
        : isCurrent
          ? 'bg-blue-950/20 border-blue-400/20 hover:border-blue-400/30'
          : 'bg-slate-900/30 border-slate-800 hover:bg-slate-800/30'
    )}>
      <div className={clsx(
        'w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0',
        isComplete
          ? 'bg-emerald-400/15 text-emerald-400'
          : isCurrent
            ? 'bg-blue-400/15 text-blue-400'
            : 'bg-slate-800 text-slate-600'
      )}>
        {isComplete ? <CheckCircle2 size={14} /> : <Icon size={14} />}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className={clsx(
            'text-sm font-medium',
            isComplete || isCurrent ? 'text-white' : 'text-slate-500'
          )}>
            {phase.label}
          </span>
          {isComplete && (
            <span className="text-[9px] font-semibold text-emerald-400 bg-emerald-400/10 px-1.5 py-0.5 rounded uppercase tracking-wide">
              Complete
            </span>
          )}
          {isCurrent && (
            <span className="text-[9px] font-semibold text-blue-400 bg-blue-400/10 px-1.5 py-0.5 rounded uppercase tracking-wide">
              In Progress
            </span>
          )}
        </div>
        <p className="text-xs text-slate-600 truncate">
          {phase.items.join(' · ')}
        </p>
      </div>

      <span className={clsx(
        'text-xs font-mono tabular-nums',
        isComplete ? 'text-slate-500' : isCurrent ? 'text-blue-400' : 'text-slate-700'
      )}>
        Day {phase.day}
      </span>
    </div>
  )
}

// ── Recent Scan Row ───────────────────────────────────────────────────────────
function RecentScanRow({
  scan,
  onViewGraph,
}: {
  scan: any
  onViewGraph: (id: string) => void
}) {
  const statusConfig: Record<string, { color: string; label: string; icon: React.ElementType }> = {
    complete: { color: 'text-emerald-400', label: 'Complete', icon: CheckCircle2 },
    running: { color: 'text-amber-400', label: 'Running', icon: RefreshCw },
    pending: { color: 'text-slate-400', label: 'Pending', icon: Clock },
    failed: { color: 'text-red-400', label: 'Failed', icon: AlertTriangle },
  }

  const cfg = statusConfig[scan.status] || statusConfig.pending
  const StatusIcon = cfg.icon

  return (
    <div className="flex items-center justify-between py-3 px-3 rounded-lg hover:bg-slate-800/30 transition-colors">
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <div className={clsx('w-2 h-2 rounded-full',
          scan.status === 'complete' ? 'bg-emerald-400' :
          scan.status === 'running' ? 'bg-amber-400 animate-pulse' :
          scan.status === 'failed' ? 'bg-red-400' : 'bg-slate-500'
        )} />
        <div className="flex-1 min-w-0">
          <p className="text-sm text-white font-medium truncate">
            {scan.aws_profile} <span className="text-slate-600">·</span> {scan.aws_region}
          </p>
          <p className="text-xs text-slate-500">
            {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="text-right">
          <p className="text-sm font-mono text-white">
            {scan.resource_count ?? '—'}
          </p>
          <p className="text-xs text-slate-500">resources</p>
        </div>
        <div className="text-right">
          <p className="text-sm font-mono text-white">
            {scan.attack_path_count ?? '—'}
          </p>
          <p className="text-xs text-slate-500">paths</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={clsx(
            'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
            cfg.color, scan.status === 'running' ? 'bg-amber-400/10' : 'bg-slate-800'
          )}>
            <StatusIcon size={10} className={scan.status === 'running' ? 'animate-spin' : ''} />
            {cfg.label}
          </span>
          {scan.status === 'complete' && scan.resource_count != null && (
            <button
              onClick={() => onViewGraph(scan.id)}
              className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium
                         bg-blue-400/10 text-blue-400 hover:bg-blue-400/20 transition-colors"
            >
              View <ArrowRight size={10} />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main Dashboard ────────────────────────────────────────────────────────────
const PHASES = [
  {
    day: 1, label: 'Foundation',
    items: ['Docker stack', 'FastAPI', 'PostgreSQL', 'Neo4j', 'Celery'],
    icon: Zap,
  },
  {
    day: 2, label: 'Infrastructure Scanner',
    items: ['EC2', 'IAM', 'S3', 'VPC', 'RDS', 'Lambda'],
    icon: Cpu,
  },
  {
    day: 3, label: 'Threat Graph Builder',
    items: ['NetworkX graph', 'Attack paths', 'Risk scoring', 'Neo4j'],
    icon: Network,
  },
  {
    day: 4, label: 'AI Reasoning Engine',
    items: ['Path explanation', 'Risk prioritization', 'LLM integration'],
    icon: Brain,
  },
  {
    day: 5, label: 'Sandbox Clone Generator',
    items: ['Clone spec', 'Terraform templates', 'IaC deployment'],
    icon: Box,
  },
  {
    day: 6, label: 'Security Test Runner',
    items: ['IAM escalation', 'S3 access', 'Lateral movement'],
    icon: Terminal,
  },
  {
    day: 7, label: 'AI Report Generator',
    items: ['Executive summary', 'Findings', 'Remediation roadmap'],
    icon: FileBarChart2,
  },
]

export default function DashboardPage() {
  const navigate = useNavigate()

  // Fetch scans for statistics
  const { data: scansData, isLoading: scansLoading } = useQuery({
    queryKey: ['scans-dashboard'],
    queryFn: () => scansApi.list(100, 0).then(r => r.data),
    refetchInterval: 10000,
    retry: 1,
  })

  // Fetch health data
  const { data: health } = useQuery({
    queryKey: ['health-dashboard'],
    queryFn: () => healthApi.get().then(r => r.data),
    refetchInterval: 10000,
  })

  const { data: ready } = useQuery({
    queryKey: ['health-ready-dashboard'],
    queryFn: () => healthApi.ready().then(r => r.data),
    refetchInterval: 15000,
    retry: false,
  })

  // Calculate statistics from scan data
  const stats: DashboardStats = {
    totalScans: scansData?.total ?? 0,
    completedScans: scansData?.items?.filter(s => s.status === 'complete').length ?? 0,
    failedScans: scansData?.items?.filter(s => s.status === 'failed').length ?? 0,
    totalAttackPaths: scansData?.items?.reduce((sum, s) => sum + (s.attack_path_count ?? 0), 0) ?? 0,
    criticalPaths: scansData?.items?.reduce((sum, s) => sum + (s.critical_path_count ?? 0), 0) ?? 0,
    highRiskPaths: 0,
    resourcesScanned: scansData?.items?.reduce((sum, s) => sum + (s.resource_count ?? 0), 0) ?? 0,
    aiAnalysesRun: 0,
  }

  // Determine completed phases based on actual functionality
  const completedPhases = 3 // Foundation, Scanner, Graph Builder are complete
  const currentPhase = 3 // Working on AI Reasoning Engine

  // Service status
  const services: ServiceStatus[] = [
    { name: 'Backend API', status: health ? 'online' : 'checking', detail: health?.version, icon: Server },
    { name: 'PostgreSQL', status: ready?.checks?.postgres ? 'online' : ready ? 'offline' : 'checking', icon: Database },
    { name: 'Neo4j Graph DB', status: ready?.checks?.neo4j ? 'online' : ready ? 'offline' : 'checking', icon: Network },
    { name: 'Redis · Celery', status: ready ? 'online' : 'checking', icon: Key },
  ]

  const allServicesOnline = services.every(s => s.status === 'online')
  const recentScans = scansData?.items?.slice(0, 5) ?? []

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500/20 to-blue-600/10 border border-blue-500/30
                          flex items-center justify-center">
            <ShieldAlert size={20} className="text-blue-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">Threat Mapper</h1>
            <p className="text-xs text-slate-500">
              Cloud Infrastructure Threat Surface Mapper
            </p>
          </div>
        </div>
        <button
          onClick={() => navigate('/scans')}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500
                     text-white text-sm font-medium rounded-lg transition-colors shadow-lg shadow-blue-500/20"
        >
          <ScanSearch size={16} />
          New Scan
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Scans Run"
          value={stats.totalScans}
          icon={ScanSearch}
          color="brand"
          sublabel={stats.completedScans > 0 ? `${stats.completedScans} completed` : 'No scans yet'}
          trend={stats.failedScans > 0 ? { value: stats.failedScans, label: 'failed' } : undefined}
        />
        <StatCard
          label="Attack Paths"
          value={stats.totalAttackPaths}
          icon={GitFork}
          color="amber"
          sublabel={stats.totalAttackPaths > 0 ? 'Discovered' : 'Run a scan first'}
        />
        <StatCard
          label="Critical Paths"
          value={stats.criticalPaths}
          icon={AlertTriangle}
          color="red"
          sublabel="Risk score ≥ 8.0"
        />
        <StatCard
          label="Resources Scanned"
          value={stats.resourcesScanned.toLocaleString()}
          icon={Cpu}
          color="emerald"
          sublabel={stats.resourcesScanned > 0 ? 'Across all scans' : 'No resources yet'}
        />
      </div>

      {/* Lower section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Services & Recent Scans — 2 cols */}
        <div className="lg:col-span-2 space-y-6">
          {/* Services */}
          <div className="bg-gradient-to-br from-slate-900 to-slate-900/50 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Activity size={14} className="text-blue-400" />
                <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                  Services
                </h2>
              </div>
              {allServicesOnline && (
                <span className="text-xs text-emerald-400 bg-emerald-400/10
                                 border border-emerald-400/20 px-2 py-0.5 rounded-full">
                  All operational
                </span>
              )}
              {!allServicesOnline && (
                <span className="text-xs text-amber-400 bg-amber-400/10
                                 border border-amber-400/20 px-2 py-0.5 rounded-full">
                  Degraded
                </span>
              )}
            </div>

            <div className="space-y-1 mb-4">
              {services.map(service => (
                <ServiceRow
                  key={service.name}
                  name={service.name}
                  status={service.status}
                  detail={service.detail}
                  icon={service.icon}
                />
              ))}
            </div>

            <div className="pt-3 border-t border-slate-800">
              <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">Quick Links</p>
              <div className="space-y-1">
                {[
                  { label: 'API Documentation', href: 'http://localhost:8000/docs', desc: 'Swagger UI' },
                  { label: 'Neo4j Browser', href: 'http://localhost:7474', desc: 'Graph database' },
                ].map(({ label, href, desc }) => (
                  <a key={href} href={href} target="_blank" rel="noopener noreferrer"
                    className="flex items-center justify-between group px-3 py-2 rounded-lg
                               hover:bg-slate-800/50 transition-colors cursor-pointer">
                    <div>
                      <span className="text-sm text-slate-300 group-hover:text-white transition-colors">
                        {label}
                      </span>
                      <span className="text-xs text-slate-500 ml-2">{desc}</span>
                    </div>
                    <ChevronRight size={14} className="text-slate-600 group-hover:text-slate-400 transition-colors" />
                  </a>
                ))}
              </div>
            </div>
          </div>

          {/* Recent Scans */}
          <div className="bg-gradient-to-br from-slate-900 to-slate-900/50 border border-slate-800 rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <ScanSearch size={14} className="text-blue-400" />
                <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                  Recent Scans
                </h2>
              </div>
              <button
                onClick={() => navigate('/scans')}
                className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
              >
                View all
              </button>
            </div>

            {scansLoading ? (
              <div className="py-8 text-center text-slate-500 text-sm">Loading...</div>
            ) : recentScans.length === 0 ? (
              <div className="py-8 text-center">
                <ScanSearch size={32} className="text-slate-700 mx-auto mb-3" />
                <p className="text-slate-500 text-sm">No scans yet</p>
                <p className="text-slate-600 text-xs mt-1">Start your first scan to see results</p>
              </div>
            ) : (
              <div className="space-y-1">
                {recentScans.map(scan => (
                  <RecentScanRow
                    key={scan.id}
                    scan={scan}
                    onViewGraph={(id) => navigate(`/graph?scan=${id}`)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Build Pipeline — 1 col */}
        <div className="lg:col-span-1">
          <div className="bg-gradient-to-br from-slate-900 to-slate-900/50 border border-slate-800 rounded-xl p-5 h-full">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <GitFork size={14} className="text-blue-400" />
                <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                  Build Pipeline
                </h2>
              </div>
              <span className="text-xs text-slate-500">
                <span className="text-white font-semibold">{completedPhases}</span>
                <span className="text-slate-700"> / {PHASES.length} complete</span>
              </span>
            </div>

            {/* Progress bar */}
            <div className="mb-4">
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-blue-500 to-emerald-400 rounded-full transition-all duration-500"
                  style={{ width: `${(completedPhases / PHASES.length) * 100}%` }}
                />
              </div>
              <p className="text-xs text-slate-500 mt-1.5 text-right">
                {Math.round((completedPhases / PHASES.length) * 100)}% complete
              </p>
            </div>

            {/* Phases */}
            <div className="space-y-2">
              {PHASES.map((phase, index) => (
                <PipelinePhase
                  key={phase.day}
                  phase={phase}
                  isComplete={index < completedPhases}
                  isCurrent={index === completedPhases}
                />
              ))}
            </div>
          </div>
        </div>

      </div>
    </div>
  )
}
