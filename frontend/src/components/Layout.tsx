import { Outlet, NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  ScanSearch,
  GitFork,
  FlaskConical,
  FileText,
  ShieldAlert,
  Circle,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { healthApi } from '../api/client'
import clsx from 'clsx'

const NAV_ITEMS = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans',     icon: ScanSearch,      label: 'Scans' },
  { to: '/graph',     icon: GitFork,         label: 'Attack Graph' },
  { to: '/results',   icon: FlaskConical,    label: 'Test Results' },
  { to: '/reports',   icon: FileText,        label: 'Reports' },
]

function ServiceStatus() {
  const { data, isError } = useQuery({
    queryKey: ['health-ready'],
    queryFn: () => healthApi.ready().then((r) => r.data),
    refetchInterval: 15_000,
    retry: false,
  })

  const allOk = data?.status === 'ready'
  const degraded = data?.status === 'degraded'

  return (
    <div className="px-4 py-3 border-t border-slate-800">
      <p className="text-xs text-slate-500 mb-2 uppercase tracking-wider">Services</p>
      <div className="space-y-1.5">
        {[
          { name: 'API',      ok: !isError },
          { name: 'Postgres', ok: data?.checks?.postgres },
          { name: 'Neo4j',    ok: data?.checks?.neo4j },
        ].map(({ name, ok }) => (
          <div key={name} className="flex items-center gap-2">
            <Circle
              size={8}
              className={clsx(
                'fill-current',
                ok ? 'text-emerald-400' : 'text-red-400'
              )}
            />
            <span className="text-xs text-slate-400">{name}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function Layout() {
  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden">

      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
      <aside className="w-56 flex-shrink-0 flex flex-col bg-slate-900 border-r border-slate-800">

        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-5 border-b border-slate-800">
          <div className="w-8 h-8 rounded-lg bg-brand flex items-center justify-center flex-shrink-0">
            <ShieldAlert size={18} className="text-white" />
          </div>
          <div className="leading-tight">
            <p className="text-sm font-semibold text-white">Threat Mapper</p>
            <p className="text-xs text-slate-500">v0.1.0</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-2 py-4 space-y-0.5 overflow-y-auto">
          {NAV_ITEMS.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors',
                  isActive
                    ? 'bg-brand/20 text-brand font-medium'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'
                )
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Service status indicators */}
        <ServiceStatus />
      </aside>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>

    </div>
  )
}
