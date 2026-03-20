import { useQuery } from '@tanstack/react-query'
import {
  ShieldAlert, ScanSearch, GitFork, FlaskConical,
  AlertTriangle, CheckCircle2, Activity,
  Cpu, Network, Brain, Box, Terminal, FileBarChart2,
  ChevronRight, Zap,
} from 'lucide-react'
import { healthApi } from '../api/client'
import { useNavigate } from 'react-router-dom'
import clsx from 'clsx'

function StatCard({
  label, value, icon: Icon, color = 'brand', sublabel,
}: {
  label: string; value: string | number; icon: React.ElementType
  color?: 'brand' | 'emerald' | 'amber' | 'red'; sublabel?: string
}) {
  const colorMap = {
    brand:   'text-brand bg-brand/10',
    emerald: 'text-emerald-400 bg-emerald-400/10',
    amber:   'text-amber-400 bg-amber-400/10',
    red:     'text-red-400 bg-red-400/10',
  }
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-widest mb-2">{label}</p>
          <p className="text-3xl font-bold text-white tabular-nums">{value}</p>
          {sublabel && <p className="text-xs text-slate-600 mt-1.5">{sublabel}</p>}
        </div>
        <div className={clsx('w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0', colorMap[color])}>
          <Icon size={18} />
        </div>
      </div>
    </div>
  )
}

function ServiceRow({ name, ok, detail }: { name: string; ok: boolean | undefined; detail?: string }) {
  return (
    <div className="flex items-center justify-between py-2.5">
      <div className="flex items-center gap-2.5">
        <div className={clsx('w-1.5 h-1.5 rounded-full flex-shrink-0',
          ok === undefined ? 'bg-slate-600 animate-pulse' :
          ok ? 'bg-emerald-400' : 'bg-red-400'
        )} />
        <span className="text-sm text-slate-300">{name}</span>
      </div>
      <span className={clsx('text-xs font-medium',
        ok === undefined ? 'text-slate-600' :
        ok ? 'text-emerald-400' : 'text-red-400'
      )}>
        {detail
          ? <span className="text-slate-600 font-mono mr-2">{detail}</span>
          : null
        }
        {ok === undefined ? 'checking' : ok ? 'online' : 'offline'}
      </span>
    </div>
  )
}

const PHASES = [
  {
    day: 1, label: 'Foundation',
    items: ['Docker stack', 'FastAPI', 'PostgreSQL', 'Neo4j', 'Celery'],
    icon: Zap, status: 'complete' as const,
  },
  {
    day: 2, label: 'Infrastructure Scanner',
    items: ['EC2', 'IAM', 'S3', 'VPC', 'RDS', 'Lambda'],
    icon: Cpu, status: 'complete' as const,
  },
  {
    day: 3, label: 'Threat Graph Builder',
    items: ['NetworkX graph', 'Attack paths', 'Risk scoring', 'Neo4j'],
    icon: Network, status: 'complete' as const,
  },
  {
    day: 4, label: 'AI Reasoning Engine',
    items: ['Path explanation', 'Risk prioritization', 'LLM integration'],
    icon: Brain, status: 'upcoming' as const,
  },
  {
    day: 5, label: 'Sandbox Clone Generator',
    items: ['Clone spec', 'Terraform templates', 'IaC deployment'],
    icon: Box, status: 'upcoming' as const,
  },
  {
    day: 6, label: 'Security Test Runner',
    items: ['IAM escalation', 'S3 access', 'Lateral movement'],
    icon: Terminal, status: 'upcoming' as const,
  },
  {
    day: 7, label: 'AI Report Generator',
    items: ['Executive summary', 'Findings', 'Remediation roadmap'],
    icon: FileBarChart2, status: 'upcoming' as const,
  },
]

export default function DashboardPage() {
  const navigate = useNavigate()

  const { data: health, isLoading } = useQuery({
    queryKey: ['health'],
    queryFn: () => healthApi.get().then(r => r.data),
    refetchInterval: 10_000,
  })
  const { data: ready } = useQuery({
    queryKey: ['health-ready'],
    queryFn: () => healthApi.ready().then(r => r.data),
    refetchInterval: 15_000,
    retry: false,
  })

  const completedCount = PHASES.filter(p => p.status === 'complete').length
  const progressPct = Math.round((completedCount / PHASES.length) * 100)

  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-brand/15 border border-brand/25
                          flex items-center justify-center">
            <ShieldAlert size={20} className="text-brand" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">Threat Mapper</h1>
            <p className="text-xs text-slate-500 mt-0.5">
              Cloud Infrastructure Threat Surface Mapper · Local Platform
            </p>
          </div>
        </div>
        <button
          onClick={() => navigate('/scans')}
          className="flex items-center gap-2 px-4 py-2 bg-brand hover:bg-blue-600
                     text-white text-sm font-medium rounded-lg transition-colors"
        >
          <ScanSearch size={14} />
          New Scan
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Scans Run"      value="0" icon={ScanSearch}    color="brand"   sublabel="No scans yet" />
        <StatCard label="Attack Paths"   value="0" icon={GitFork}       color="amber"   sublabel="Run a scan first" />
        <StatCard label="Critical Paths" value="0" icon={AlertTriangle} color="red"     sublabel="Score ≥ 8.0" />
        <StatCard label="Tests Run"      value="0" icon={FlaskConical}  color="emerald" sublabel="Sandbox required" />
      </div>

      {/* Lower section */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">

        {/* Services — 2 cols */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              <Activity size={14} className="text-brand" />
              <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                Services
              </h2>
            </div>
            {ready?.status === 'ready' && (
              <span className="text-xs text-emerald-400 bg-emerald-400/10
                               border border-emerald-400/20 px-2 py-0.5 rounded-full">
                All operational
              </span>
            )}
            {ready?.status === 'degraded' && (
              <span className="text-xs text-red-400 bg-red-400/10
                               border border-red-400/20 px-2 py-0.5 rounded-full">
                Degraded
              </span>
            )}
          </div>

          <div className="divide-y divide-slate-800/60 mb-4">
            <ServiceRow name="Backend API"    ok={!isLoading && !!health} detail={health?.version} />
            <ServiceRow name="PostgreSQL"     ok={ready?.checks?.postgres} />
            <ServiceRow name="Neo4j Graph DB" ok={ready?.checks?.neo4j} />
            <ServiceRow name="Redis · Celery" ok={ready !== undefined} />
          </div>

          <div className="pt-3 border-t border-slate-800 space-y-0.5">
            <p className="text-xs text-slate-600 uppercase tracking-widest mb-2">Quick Links</p>
            {[
              { label: 'API Docs (Swagger)', href: 'http://localhost:8000/docs' },
              { label: 'Neo4j Browser',      href: 'http://localhost:7474' },
            ].map(({ label, href }) => (
              <a key={href} href={href} target="_blank" rel="noopener noreferrer"
                className="flex items-center justify-between group px-3 py-2 rounded-lg
                           hover:bg-slate-800 transition-colors cursor-pointer">
                <span className="text-xs text-slate-500 group-hover:text-slate-300 transition-colors">
                  {label}
                </span>
                <ChevronRight size={12} className="text-slate-700 group-hover:text-slate-400 transition-colors" />
              </a>
            ))}
          </div>
        </div>

        {/* Pipeline — 3 cols */}
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl p-5">

          {/* Header + progress */}
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <GitFork size={14} className="text-brand" />
              <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                Build Pipeline
              </h2>
            </div>
            <span className="text-xs text-slate-500">
              <span className="text-white font-semibold tabular-nums">{completedCount}</span>
              <span className="text-slate-700"> / {PHASES.length} complete</span>
            </span>
          </div>

          {/* Progress bar */}
          <div className="mb-4">
            <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-brand to-emerald-400 rounded-full transition-all duration-1000"
                style={{ width: `${progressPct}%` }}
              />
            </div>
          </div>

          {/* Phases */}
          <div className="space-y-1">
            {PHASES.map((phase) => {
              const Icon = phase.icon
              const done = phase.status === 'complete'
              return (
                <div key={phase.day} className={clsx(
                  'grid grid-cols-[28px_1fr_auto] items-center gap-3 px-3 py-2.5 rounded-lg transition-colors',
                  done
                    ? 'bg-emerald-950/30 border border-emerald-400/10'
                    : 'border border-transparent hover:bg-slate-800/40'
                )}>
                  {/* Icon */}
                  <div className={clsx(
                    'w-7 h-7 rounded-md flex items-center justify-center',
                    done
                      ? 'bg-emerald-400/15 text-emerald-400'
                      : 'bg-slate-800 text-slate-600'
                  )}>
                    {done ? <CheckCircle2 size={13} /> : <Icon size={13} />}
                  </div>

                  {/* Text */}
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={clsx(
                        'text-sm font-medium leading-none',
                        done ? 'text-white' : 'text-slate-500'
                      )}>
                        {phase.label}
                      </span>
                      {done && (
                        <span className="text-[10px] font-semibold text-emerald-400
                                         bg-emerald-400/10 px-1.5 py-0.5 rounded uppercase tracking-wide">
                          done
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-700 mt-0.5 truncate">
                      {phase.items.join(' · ')}
                    </p>
                  </div>

                  {/* Day */}
                  <span className={clsx(
                    'text-xs font-mono tabular-nums',
                    done ? 'text-slate-600' : 'text-slate-800'
                  )}>
                    Day {phase.day}
                  </span>
                </div>
              )
            })}
          </div>
        </div>

      </div>
    </div>
  )
}
