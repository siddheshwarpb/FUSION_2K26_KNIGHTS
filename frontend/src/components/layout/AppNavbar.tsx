import React, { useState } from "react"
import { Link, useLocation, useNavigate } from "react-router-dom"
import {
  ShieldAlert,
  BarChart3,
  Network,
  AlertTriangle,
  ListOrdered,
  FlaskConical,
  FileText,
  Database,
  Upload,
  Layers,
  X,
  CheckCircle,
  Sparkles,
  ExternalLink,
  GitCommit,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { getDatabaseStats, loadDemoScenario } from "@/lib/api"

interface AppNavbarProps {
  currentAnalysisId?: string | null
  projectName?: string | null
}

export default function AppNavbar({ currentAnalysisId, projectName }: AppNavbarProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const [showDbModal, setShowDbModal] = useState(false)
  const [dbStats, setDbStats] = useState<any>(null)
  const [loadingDb, setLoadingDb] = useState(false)
  const [loadingDemo, setLoadingDemo] = useState<string | null>(null)

  const handleOpenDbModal = async () => {
    setLoadingDb(true)
    try {
      const stats = await getDatabaseStats()
      setDbStats(stats)
      setShowDbModal(true)
    } catch (e: any) {
      alert("Failed to fetch database telemetry: " + e.message)
    } finally {
      setLoadingDb(false)
    }
  }

  const handleQuickDemo = async (scenarioId: string) => {
    setLoadingDemo(scenarioId)
    try {
      const res = await loadDemoScenario(scenarioId)
      navigate(`/dashboard/${res.analysis_id}`)
    } catch (e: any) {
      alert("Demo scenario error: " + e.message)
    } finally {
      setLoadingDemo(null)
    }
  }

  const id = currentAnalysisId || ""

  const navItems = [
    { label: "Scanner", path: "/analyze", icon: Upload, enabled: true },
    { label: "Commit Scan", path: "/commit-scan", icon: GitCommit, enabled: true },
    { label: "Dashboard", path: id ? `/dashboard/${id}` : "/analyze", icon: BarChart3, enabled: !!id },
    { label: "Propagation Graph", path: id ? `/graph/${id}` : "/analyze", icon: Network, enabled: !!id },
    { label: "Findings", path: id ? `/findings/${id}` : "/analyze", icon: AlertTriangle, enabled: !!id },
    { label: "Patch Plan", path: id ? `/patch-plan/${id}` : "/analyze", icon: ListOrdered, enabled: !!id },
    { label: "Simulation", path: id ? `/simulate/${id}` : "/analyze", icon: FlaskConical, enabled: !!id },
    { label: "Audit Report", path: id ? `/report/${id}` : "/analyze", icon: FileText, enabled: !!id },
  ]

  return (
    <>
      <header className="sticky top-0 z-40 w-full border-b border-white/10 bg-[#070b14]/90 backdrop-blur-md">
        <div className="container mx-auto flex h-16 items-center justify-between px-4 sm:px-6">
          {/* Logo & Identity */}
          <div className="flex items-center gap-4">
            <Link to="/analyze" className="flex items-center gap-2.5 group">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-600/20 text-blue-400 ring-1 ring-blue-500/30 group-hover:bg-blue-600/30 transition-all">
                <ShieldAlert className="h-5 w-5" />
              </div>
              <div className="flex flex-col">
                <div className="flex items-center gap-1.5">
                  <span className="text-base font-bold tracking-tight text-white group-hover:text-blue-300 transition-colors">
                    PatchOrder
                  </span>
                  <span className="rounded border border-blue-500/30 bg-blue-500/10 px-1.5 py-0.2 text-[9px] font-semibold text-blue-400">
                    SCA v2.0
                  </span>
                </div>
                <span className="text-[10px] text-white/50 tracking-wider">
                  Explainable Remediation Graph
                </span>
              </div>
            </Link>

            {/* Active Analysis Badge */}
            {projectName && id && (
              <div className="hidden lg:flex items-center gap-2 pl-3 border-l border-white/10">
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-blue-950/40 border border-blue-500/30 text-xs text-blue-300">
                  <Layers className="h-3.5 w-3.5 text-blue-400" />
                  <span className="font-mono font-medium max-w-[140px] truncate">{projectName}</span>
                  <span className="text-white/40 font-mono text-[10px]">({id.slice(0, 8)})</span>
                </div>
              </div>
            )}
          </div>

          {/* Nav Links */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const active = location.pathname.startsWith(item.path) && item.path !== "/analyze"
                ? true
                : location.pathname === item.path

              return (
                <Link
                  key={item.label}
                  to={item.path}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    active
                      ? "bg-blue-600/20 text-white border border-blue-500/30 shadow-sm"
                      : item.enabled
                      ? "text-white/70 hover:text-white hover:bg-white/5"
                      : "text-white/30 cursor-not-allowed"
                  }`}
                  onClick={(e) => {
                    if (!item.enabled && item.path === "/analyze") {
                      // Allow going to upload
                    }
                  }}
                >
                  <item.icon className={`h-3.5 w-3.5 ${active ? "text-blue-400" : ""}`} />
                  <span>{item.label}</span>
                </Link>
              )
            })}
          </nav>

          {/* Quick Actions & DB Inspector */}
          <div className="flex items-center gap-2">
            {/* Quick Demo buttons */}
            <div className="hidden xl:flex items-center gap-1.5">
              <Button
                variant="ghost"
                size="sm"
                disabled={!!loadingDemo}
                onClick={() => handleQuickDemo("ecommerce-checkout")}
                className="h-8 text-xs text-white/70 hover:text-white hover:bg-white/10"
              >
                <Sparkles className="h-3 w-3 mr-1 text-amber-400" />
                {loadingDemo === "ecommerce-checkout" ? "Loading..." : "Demo: npm"}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={!!loadingDemo}
                onClick={() => handleQuickDemo("python-backend")}
                className="h-8 text-xs text-white/70 hover:text-white hover:bg-white/10"
              >
                <Sparkles className="h-3 w-3 mr-1 text-emerald-400" />
                {loadingDemo === "python-backend" ? "Loading..." : "Demo: PyPI"}
              </Button>
            </div>

            {/* SQLite telemetry */}
            <Button
              variant="outline"
              size="sm"
              onClick={handleOpenDbModal}
              disabled={loadingDb}
              className="h-8 border-blue-500/30 text-xs text-blue-300 hover:text-white bg-blue-950/30 hover:bg-blue-900/40"
            >
              <Database className="h-3.5 w-3.5 mr-1.5 text-blue-400" />
              <span>DB Stats</span>
            </Button>
          </div>
        </div>
      </header>

      {/* SQLite Telemetry Modal */}
      {showDbModal && dbStats && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="w-full max-w-3xl rounded-2xl border border-white/10 bg-[#0d1322] shadow-2xl overflow-hidden text-white">
            <div className="flex items-center justify-between p-5 border-b border-white/10 bg-white/[0.02]">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-blue-600/20 text-blue-400 border border-blue-500/30">
                  <Database className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg text-white">SQLite Persistence Telemetry</h3>
                  <p className="text-xs text-white/60 font-mono">{dbStats.database_file}</p>
                </div>
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setShowDbModal(false)}
                className="text-white/60 hover:text-white"
              >
                <X className="h-5 w-5" />
              </Button>
            </div>

            <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
              {/* Tables Metrics Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {Object.entries(dbStats.tables || {}).map(([tbl, info]: [string, any]) => (
                  <div key={tbl} className="p-3.5 rounded-xl border border-white/10 bg-black/40">
                    <div className="text-[11px] font-mono text-white/50">{tbl}</div>
                    <div className="text-2xl font-bold font-mono text-blue-400 mt-1">{info.count}</div>
                    <div className="text-[10px] text-white/60 mt-1 line-clamp-1">{info.description}</div>
                  </div>
                ))}
              </div>

              {/* Recent Scans Table */}
              <div>
                <h4 className="text-xs font-semibold text-white/70 uppercase tracking-wider mb-2">
                  Recent Scan Logs ({dbStats.recent_scans?.length || 0})
                </h4>
                <div className="rounded-xl border border-white/10 overflow-hidden bg-black/30">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-white/[0.03] border-b border-white/10 text-white/60 font-mono">
                      <tr>
                        <th className="py-2.5 px-3">Project</th>
                        <th className="py-2.5 px-3">Manifest</th>
                        <th className="py-2.5 px-3">Packages</th>
                        <th className="py-2.5 px-3">Vulnerable</th>
                        <th className="py-2.5 px-3">Latency</th>
                        <th className="py-2.5 px-3">Scanned At</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 font-mono">
                      {(dbStats.recent_scans || []).map((s: any) => (
                        <tr key={s.scan_id} className="hover:bg-white/[0.02]">
                          <td className="py-2 px-3 text-white font-medium">{s.project_name}</td>
                          <td className="py-2 px-3 text-white/70">{s.manifest_type}</td>
                          <td className="py-2 px-3 text-white/80">{s.total_components}</td>
                          <td className="py-2 px-3 text-rose-400 font-semibold">{s.vulnerable_components}</td>
                          <td className="py-2 px-3 text-white/60">{s.duration_ms ? `${s.duration_ms.toFixed(0)}ms` : "—"}</td>
                          <td className="py-2 px-3 text-white/50 text-[11px]">{new Date(s.scanned_at).toLocaleTimeString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-white/10 bg-white/[0.01] flex justify-end">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowDbModal(false)}
                className="border-white/10 text-white/80"
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

