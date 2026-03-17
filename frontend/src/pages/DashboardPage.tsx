import { useQuery } from '@tanstack/react-query'
import {
  ShieldAlert, ScanSearch, GitFork,
  FlaskConical, AlertTriangle, CheckCircle2,
  Clock, Activity,
} from 'lucide-react'
import { healthApi } from '../api/client'
import clsx from 'clsx'

// ── Stat card ─────────────────────────────────────────────────────────────────
function StatCard({
  label,
  value,
  icon: Icon,
  color = 'brand',
  sublabel,
}: {
  label: string
  value: string | number
  icon: React.ElementType
  color?: 'brand' | 'emerald' | 'amber' | 'red'
  sublabel?: string
}) {
  const colorMap = {
    brand:   'text-brand   bg-brand/10',
    emerald: 'text-emerald-400 bg-emerald-400/10',
    amber:   'text-amber-400  bg-amber-400/10',
    red:     'text-red-400    bg-red-400/10',
  }
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</p>
          <p className="text-3xl font-bold text-white">{value}</p>
          {sublabel && <p className="text-xs text-slate-500 mt-1">{sublabel}</p>}
        </div>
        <div className={clsx('w-10 h-10 rounded-lg flex items-center justify-center', colorMap[color])}>
          <Icon size={20} />
        </div>
      </div>
    </div>
  )
}

// ── Service health row ────────────────────────────────────────────────────────
function HealthRow({
  name,
  ok,
  detail,
}: {
  name: string
  ok: boolean | undefined
  detail?: string
}) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-slate-800 last:border-0">
      <span className="text-sm text-slate-300">{name}</span>
      <div className="flex items-center gap-2">
        {detail && <span className="text-xs text-slate-500">{detail}</span>}
        {ok === undefined ? (
          <Clock size={14} className="text-slate-500 animate-pulse" />
        ) : ok ? (
          <CheckCircle2 size={14} className="text-emerald-400" />
        ) : (
          <AlertTriangle size={14} className="text-red-400" />
        )}
      </div>
    </div>
  )
}

// ── Pipeline step ─────────────────────────────────────────────────────────────
const PIPELINE_STEPS = [
  { label: 'Infrastructure Scanner',   phase: '2', status: 'upcoming' },
  { label: 'Threat Graph Builder',     phase: '3', status: 'upcoming' },
  { label: 'AI Reasoning Engine',      phase: '4', status: 'upcoming' },
  { label: 'Sandbox Clone Generator',  phase: '5', status: 'upcoming' },
  { label: 'Terraform Deployment',     phase: '5', status: 'upcoming' },
  { label: 'Security Test Runner',     phase: '6', status: 'upcoming' },
  { label: 'AI Report Generator',      phase: '7', status: 'upcoming' },
]

// ── Page ──────────────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const { data: health, isLoading } = useQuery({
    queryKey: ['health'],
    queryFn: () => healthApi.get().then((r) => r.data),
    refetchInterval: 10_000,
  })

  const { data: ready } = useQuery({
    queryKey: ['health-ready'],
    queryFn: () => healthApi.ready().then((r) => r.data),
    refetchInterval: 15_000,
    retry: false,
  })

  return (
    <div className="p-8 max-w-6xl mx-auto">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <ShieldAlert size={24} className="text-brand" />
          Threat Mapper
        </h1>
        <p className="text-slate-400 mt-1">
          Cloud Infrastructure Threat Surface Mapper — Local Security Platform
        </p>
      </div>

      {/* ── Stats row ──────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Scans Run"
          value="0"
          icon={ScanSearch}
          color="brand"
          sublabel="No scans yet"
        />
        <StatCard
          label="Attack Paths"
          value="0"
          icon={GitFork}
          color="amber"
          sublabel="Run a scan to start"
        />
        <StatCard
          label="Critical Paths"
          value="0"
          icon={AlertTriangle}
          color="red"
          sublabel="Score ≥ 8.0"
        />
        <StatCard
          label="Tests Run"
          value="0"
          icon={FlaskConical}
          color="emerald"
          sublabel="Sandbox required"
        />
      </div>

      {/* ── Two-column lower section ────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Service health */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Activity size={16} className="text-brand" />
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
              Service Health
            </h2>
          </div>
          <HealthRow
            name="Backend API"
            ok={!isLoading && !!health}
            detail={health?.version}
          />
          <HealthRow
            name="PostgreSQL"
            ok={ready?.checks?.postgres}
          />
          <HealthRow
            name="Neo4j Graph DB"
            ok={ready?.checks?.neo4j}
          />
          <HealthRow
            name="Redis / Celery"
            ok={ready !== undefined}
          />
          {ready?.status === 'degraded' && (
            <div className="mt-4 p-3 bg-red-400/10 border border-red-400/20 rounded-lg">
              <p className="text-xs text-red-400">
                One or more services are unavailable. Check <code className="font-mono">make logs</code> for details.
              </p>
            </div>
          )}
          {ready?.status === 'ready' && (
            <div className="mt-4 p-3 bg-emerald-400/10 border border-emerald-400/20 rounded-lg">
              <p className="text-xs text-emerald-400">
                All services are healthy and ready.
              </p>
            </div>
          )}
        </div>

        {/* Pipeline status */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <GitFork size={16} className="text-brand" />
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
              Build Pipeline
            </h2>
          </div>

          {/* Day 1 badge */}
          <div className="mb-4 px-3 py-2 bg-brand/10 border border-brand/20 rounded-lg">
            <p className="text-xs text-brand font-medium">
              ✅ Day 1 — Foundation complete
            </p>
            <p className="text-xs text-slate-400 mt-0.5">
              Docker stack · FastAPI · PostgreSQL · Neo4j · Celery
            </p>
          </div>

          <div className="space-y-2">
            {PIPELINE_STEPS.map((step) => (
              <div
                key={step.label}
                className="flex items-center justify-between py-2 px-3 rounded-lg bg-slate-800/50"
              >
                <span className="text-sm text-slate-400">{step.label}</span>
                <span className="text-xs text-slate-600 font-mono">
                  Phase {step.phase}
                </span>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  )
}
