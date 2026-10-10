import React, { useEffect, useState } from "react"
import { useParams, Link } from "react-router-dom"
import { 
  ListOrdered, 
  Sparkles, 
  ArrowRight, 
  FlaskConical, 
  ShieldCheck, 
  AlertCircle, 
  Layers, 
  CheckCircle2, 
  ExternalLink,
  ChevronRight,
  TrendingDown,
  Hammer
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { getAnalysis, AnalysisRecord, PatchRecommendation } from "@/lib/api"

export default function PatchPlanPage() {
  const { analysisId } = useParams<{ analysisId: string }>()
  const [record, setRecord] = useState<AnalysisRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!analysisId) return
    setLoading(true)
    setError(null)
    getAnalysis(analysisId)
      .then((data) => setRecord(data))
      .catch((err) => setError(err.message || "Failed to load remediation plan"))
      .finally(() => setLoading(false))
  }, [analysisId])

  if (loading) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
          <p className="text-sm text-white/60">Computing optimal remediation sequence...</p>
        </div>
      </div>
    )
  }

  if (error || !record) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="p-6 rounded-2xl border border-rose-500/30 bg-rose-950/20 text-center">
          <p className="text-sm text-rose-300">{error || "Remediation plan not available."}</p>
        </div>
      </div>
    )
  }

  const { patch_plan, project_name } = record

  return (
    <div className="container mx-auto px-4 py-8 max-w-5xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-white/10 gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <ListOrdered className="h-6 w-6 text-blue-400" />
            Ranked Remediation Plan
          </h1>
          <p className="text-xs text-white/50 mt-1 font-mono">
            Project: <strong className="text-white">{project_name}</strong> • Sequenced by Marginal Value (Risk Removed / Change Cost)
          </p>
        </div>

        <Link to={`/simulate/${record.analysis_id}`}>
          <Button size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs shadow-md shadow-emerald-600/20">
            <FlaskConical className="h-3.5 w-3.5 mr-1.5" />
            Launch Batch Simulation
          </Button>
        </Link>
      </div>

      {/* Rationale explanation card */}
      <div className="p-4 rounded-xl border border-blue-500/20 bg-blue-950/20 text-xs text-blue-200/80 leading-relaxed flex items-start gap-3">
        <Sparkles className="h-5 w-5 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-white">Why not fix everything at once?</strong> Large batch upgrades introduce high breaking-change risk, test flakiness, and dependency conflicts. PatchOrder ranks actions by <em>Marginal Value</em> (Risk Removed / ΔCost), where Change Cost incorporates SemVer step distance (major vs minor), direct vs transitive position, and blast radius of dependent services.
        </div>
      </div>

      {/* Patch Queue List */}
      {patch_plan.length === 0 ? (
        <div className="p-12 rounded-2xl border border-white/10 bg-black/30 text-center space-y-3">
          <CheckCircle2 className="h-10 w-10 text-emerald-400 mx-auto" />
          <h2 className="text-lg font-bold text-white">No Patches Required</h2>
          <p className="text-xs text-white/50">All components in this manifest are on secure versions with zero known vulnerabilities.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {patch_plan.map((patch) => {
            const isRank1 = patch.rank === 1
            return (
              <div
                key={patch.rank}
                className={`p-6 rounded-2xl border transition-all ${
                  isRank1
                    ? "bg-gradient-to-r from-blue-950/40 via-slate-900/60 to-black/60 border-blue-500/50 shadow-xl shadow-blue-950/30"
                    : "bg-[#0d1322] border-white/10 hover:border-white/20"
                }`}
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-3 border-b border-white/10">
                  <div className="flex items-start gap-3">
                    {/* Rank Badge */}
                    <div className={`h-9 w-9 rounded-xl flex items-center justify-center font-mono font-bold text-sm ${
                      isRank1
                        ? "bg-blue-600 text-white shadow-md shadow-blue-600/40"
                        : "bg-white/10 text-white/70"
                    }`}>
                      #{patch.rank}
                    </div>

                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-lg font-bold font-mono text-white">
                          {patch.package}
                        </h3>
                        <span className="text-xs text-white/40 font-mono">({patch.ecosystem})</span>
                      </div>
                      <div className="text-xs font-mono text-white/60 mt-0.5">
                        Current: <span className="text-white/80">{patch.current_version}</span>
                        {" → "}
                        Target: <strong className="text-emerald-400 font-bold">{patch.target_version}</strong>
                      </div>
                    </div>
                  </div>

                  {/* Marginal Value Metric */}
                  <div className="flex items-center sm:text-right gap-3 sm:gap-1 sm:flex-col">
                    <div className="text-[10px] text-white/50 uppercase tracking-wider">Marginal Value (R/ΔC)</div>
                    <div className="text-2xl font-bold font-mono text-emerald-400">
                      {patch.marginal_value.toFixed(2)}
                    </div>
                  </div>
                </div>

                {/* Plain-Language "Why Now?" */}
                <div className="py-3 text-xs text-white/80 leading-relaxed flex items-start gap-2">
                  <span className="text-blue-300 font-semibold shrink-0">Why Now?</span>
                  <span>{patch.why_now}</span>
                </div>

                {/* Score and Cost Factor Breakdown */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono py-2">
                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-white/40 block text-[10px]">Risk Removed</span>
                    <strong className="text-white font-bold">{patch.estimated_risk_removed.toFixed(1)} pts</strong>
                  </div>

                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-white/40 block text-[10px]">Change Cost</span>
                    <strong className="text-white font-bold">{patch.estimated_change_cost.toFixed(2)}</strong>
                  </div>

                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-white/40 block text-[10px]">Vulns Eliminated</span>
                    <strong className="text-emerald-400 font-bold">{patch.findings_removed.length}</strong>
                  </div>

                  <div className="p-2.5 rounded-lg bg-black/40 border border-white/5">
                    <span className="text-white/40 block text-[10px]">Affected Roots</span>
                    <strong className="text-blue-300 font-bold">{patch.affected_project_roots.length || 1}</strong>
                  </div>
                </div>

                {/* Resolved Vulnerabilities Pills & Action */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between pt-3 gap-3">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[10px] text-white/40 mr-1">Eliminates:</span>
                    {patch.findings_removed.map((id) => (
                      <a
                        key={id}
                        href={`https://osv.dev/vulnerability/${id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 border border-white/10 text-[10px] font-mono text-blue-300 flex items-center gap-0.5"
                      >
                        {id}
                        <ExternalLink className="h-2 w-2 text-white/40" />
                      </a>
                    ))}
                  </div>

                  <Link to={`/simulate/${record.analysis_id}?patch=${encodeURIComponent(patch.package)}`}>
                    <Button size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs">
                      <FlaskConical className="h-3.5 w-3.5 mr-1" />
                      Simulate This Patch
                      <ArrowRight className="h-3.5 w-3.5 ml-1" />
                    </Button>
                  </Link>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
