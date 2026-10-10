import React, { useEffect, useState } from "react"
import { useParams, Link, useNavigate } from "react-router-dom"
import {
  ShieldAlert,
  AlertTriangle,
  Layers,
  ArrowRight,
  Sparkles,
  Network,
  CheckCircle2,
  Flame,
  Activity,
  ListOrdered,
  FlaskConical,
  FileText,
  Cpu,
  Clock,
  ShieldCheck,
  AlertCircle,
  ExternalLink
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { getAnalysis, AnalysisRecord } from "@/lib/api"
import CytoscapeGraphView from "@/components/graph/CytoscapeGraphView"

export default function DashboardPage() {
  const { analysisId } = useParams<{ analysisId: string }>()
  const navigate = useNavigate()
  const [record, setRecord] = useState<AnalysisRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!analysisId) return
    setLoading(true)
    setError(null)
    getAnalysis(analysisId)
      .then((data) => setRecord(data))
      .catch((err) => setError(err.message || "Failed to load analysis"))
      .finally(() => setLoading(false))
  }, [analysisId])

  if (loading) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
          <p className="text-sm text-white/60">Loading operational overview...</p>
        </div>
      </div>
    )
  }

  if (error || !record) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4">
        <div className="max-w-md p-6 rounded-2xl border border-rose-500/30 bg-rose-950/20 text-center space-y-4">
          <AlertCircle className="h-10 w-10 text-rose-400 mx-auto" />
          <h2 className="text-lg font-bold text-white">Analysis Not Found</h2>
          <p className="text-xs text-rose-200/80">{error || "Could not retrieve the analysis record."}</p>
          <Button onClick={() => navigate("/analyze")} className="bg-blue-600 text-white hover:bg-blue-500">
            Return to Scanner
          </Button>
        </div>
      </div>
    )
  }

  const { summary, findings, patch_plan, graph_data } = record
  const topPatch = patch_plan.length > 0 ? patch_plan[0] : null

  // Priority tiers counts
  const tierCounts: Record<string, number> = {
    CRITICAL_URGENT: 0,
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  }
  findings.forEach((f) => {
    if (tierCounts[f.priority_tier] !== undefined) {
      tierCounts[f.priority_tier]++
    }
  })

  // Calculate removable risk percentage by top patch
  const totalRiskScore = findings.reduce((acc, f) => acc + (f.priority_score || 0), 0)
  const topPatchRiskRemoved = topPatch ? topPatch.estimated_risk_removed : 0
  const pctRemovable = totalRiskScore > 0 ? Math.min(100, Math.round((topPatchRiskRemoved / totalRiskScore) * 100)) : 0

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl space-y-8">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-white/10 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
              <ShieldAlert className="h-6 w-6 text-blue-400" />
              Operational Security Overview
            </h1>
            <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold uppercase ${
              record.resolution_status === "resolved"
                ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
                : "bg-amber-500/10 border border-amber-500/30 text-amber-400"
            }`}>
              {record.resolution_status === "resolved" ? "Resolved Lockfile" : "Manifest-Only"}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-white/50 mt-1 font-mono">
            <span>Project: <strong className="text-white">{record.project_name}</strong></span>
            <span>•</span>
            <span>Env: <strong className="text-blue-300">{record.environment}</strong></span>
            <span>•</span>
            <span>Exposure: <strong className="text-cyan-300">{record.exposure}</strong></span>
            <span>•</span>
            <span>Criticality: <strong className="text-amber-300">{record.criticality}</strong></span>
            <span>•</span>
            <span>Scanned: {new Date(record.created_at).toLocaleTimeString()} ({summary.scan_duration_ms.toFixed(0)}ms)</span>
          </div>
        </div>

        {/* Quick Route Navigations */}
        <div className="flex items-center gap-2">
          <Link to={`/graph/${record.analysis_id}`}>
            <Button variant="outline" size="sm" className="border-white/10 text-xs text-white/80 hover:text-white bg-black/40">
              <Network className="h-3.5 w-3.5 mr-1.5 text-blue-400" />
              Full Graph
            </Button>
          </Link>
          <Link to={`/findings/${record.analysis_id}`}>
            <Button variant="outline" size="sm" className="border-white/10 text-xs text-white/80 hover:text-white bg-black/40">
              <AlertTriangle className="h-3.5 w-3.5 mr-1.5 text-rose-400" />
              All Findings ({findings.length})
            </Button>
          </Link>
          <Link to={`/patch-plan/${record.analysis_id}`}>
            <Button size="sm" className="bg-blue-600 hover:bg-blue-500 text-white text-xs">
              <ListOrdered className="h-3.5 w-3.5 mr-1.5" />
              Remediation Plan
            </Button>
          </Link>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Packages */}
        <div className="p-5 rounded-2xl border border-white/10 bg-[#0d1322] space-y-1">
          <div className="flex items-center justify-between text-xs text-white/50">
            <span>Packages Analyzed</span>
            <Layers className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {summary.total_components}
          </div>
          <div className="text-[11px] text-white/60 flex items-center gap-2">
            <span>Direct: <strong className="text-white">{summary.direct_components}</strong></span>
            <span>•</span>
            <span>Transitive: <strong className="text-white">{summary.transitive_components}</strong></span>
          </div>
        </div>

        {/* Total Vulnerabilities */}
        <div className="p-5 rounded-2xl border border-white/10 bg-[#0d1322] space-y-1">
          <div className="flex items-center justify-between text-xs text-white/50">
            <span>Vulnerability Findings</span>
            <AlertTriangle className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">
            {summary.total_vulnerabilities}
          </div>
          <div className="text-[11px] text-white/60 flex items-center gap-1.5 flex-wrap">
            <span>Groups: <strong className="text-white">{summary.distinct_vulnerabilities_count || summary.total_vulnerabilities}</strong></span>
            <span>•</span>
            <span>Direct: <strong className="text-rose-300">{summary.direct_vulnerabilities}</strong></span>
            <span>•</span>
            <span>Trans: <strong className="text-rose-300">{summary.transitive_vulnerabilities}</strong></span>
          </div>
        </div>


        {/* KEV Exploit Matches */}
        <div className="p-5 rounded-2xl border border-white/10 bg-[#0d1322] space-y-1">
          <div className="flex items-center justify-between text-xs text-white/50">
            <span>CISA KEV Matches</span>
            <Flame className="h-4 w-4 text-amber-400 animate-pulse" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {summary.kev_matches}
          </div>
          <div className="text-[11px] text-amber-300/80">
            {summary.kev_matches > 0 ? "Active in-the-wild exploitation" : "Zero known exploited vulns"}
          </div>
        </div>

        {/* Risk Removable by Patch #1 */}
        <div className="p-5 rounded-2xl border border-white/10 bg-[#0d1322] space-y-1">
          <div className="flex items-center justify-between text-xs text-white/50">
            <span>Removable By Patch #1</span>
            <Sparkles className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {pctRemovable}%
          </div>
          <div className="text-[11px] text-white/60">
            {topPatch ? `${topPatch.findings_removed.length} advisories resolved` : "No patches required"}
          </div>
        </div>
      </div>

      {/* Main Operational Section: Top Patch Recommendation & Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Highest-Ranked Patch Card */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-white/70 flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-blue-400" />
              Highest-Ranked Remediation Recommendation
            </h2>
            <Link to={`/patch-plan/${record.analysis_id}`} className="text-xs text-blue-400 hover:underline">
              View all {patch_plan.length} patches →
            </Link>
          </div>

          {topPatch ? (
            <div className="p-6 rounded-2xl border border-blue-500/40 bg-gradient-to-br from-blue-950/40 via-slate-900/60 to-black/60 shadow-xl space-y-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-blue-500/20 border border-blue-500/40 text-[11px] font-mono text-blue-300 font-semibold mb-2">
                    Rank #1 Priority Action
                  </div>
                  <h3 className="text-xl font-bold text-white font-mono flex items-center gap-2">
                    <span>{topPatch.package}</span>
                    <span className="text-xs text-white/40 font-normal">
                      {topPatch.current_version} → <strong className="text-emerald-400">{topPatch.target_version}</strong>
                    </span>
                  </h3>
                </div>

                <div className="text-right">
                  <div className="text-xs text-white/50">Marginal Value (R/ΔC)</div>
                  <div className="text-2xl font-bold font-mono text-emerald-400">
                    {topPatch.marginal_value.toFixed(2)}
                  </div>
                </div>
              </div>

              {/* Rationale "Why Now?" */}
              <div className="p-3.5 rounded-xl bg-black/40 border border-white/10 text-xs text-white/80 leading-relaxed">
                <span className="text-blue-300 font-semibold">Why Now? </span>
                {topPatch.why_now}
              </div>

              {/* Metrics grid */}
              <div className="grid grid-cols-3 gap-2 text-xs">
                <div className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5">
                  <span className="text-white/40 block text-[10px]">Risk Removed</span>
                  <strong className="text-white font-mono">{topPatch.estimated_risk_removed.toFixed(1)} pts</strong>
                </div>
                <div className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5">
                  <span className="text-white/40 block text-[10px]">Change Cost</span>
                  <strong className="text-white font-mono">{topPatch.estimated_change_cost.toFixed(2)}</strong>
                </div>
                <div className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5">
                  <span className="text-white/40 block text-[10px]">Advisories Resolved</span>
                  <strong className="text-emerald-400 font-mono">{topPatch.findings_removed.length}</strong>
                </div>
              </div>

              {/* Action */}
              <div className="flex items-center justify-between pt-2">
                <div className="flex flex-wrap gap-1">
                  {topPatch.findings_removed.slice(0, 3).map((id) => (
                    <span key={id} className="px-2 py-0.5 rounded bg-white/5 border border-white/10 text-[10px] font-mono text-white/70">
                      {id}
                    </span>
                  ))}
                  {topPatch.findings_removed.length > 3 && (
                    <span className="px-1.5 py-0.5 text-[10px] text-white/40">
                      +{topPatch.findings_removed.length - 3} more
                    </span>
                  )}
                </div>

                <Link to={`/simulate/${record.analysis_id}?patch=${encodeURIComponent(topPatch.package)}`}>
                  <Button size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs shadow-md shadow-emerald-600/30">
                    <FlaskConical className="h-3.5 w-3.5 mr-1.5" />
                    Simulate This Patch
                  </Button>
                </Link>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-2xl border border-white/10 bg-black/30 text-center space-y-2">
              <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto" />
              <div className="text-sm font-semibold text-white">Clean Bill of Health</div>
              <p className="text-xs text-white/50">No known vulnerabilities detected across scanned components.</p>
            </div>
          )}
        </div>

        {/* Right Column: Severity Tier Breakdown */}
        <div className="lg:col-span-5 space-y-4">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-white/70 flex items-center gap-2">
            <Activity className="h-4 w-4 text-purple-400" />
            Policy Gate Severity Distribution
          </h2>

          <div className="p-6 rounded-2xl border border-white/10 bg-[#0d1322] space-y-4">
            <div className="space-y-3">
              {[
                { tier: "CRITICAL_URGENT", label: "Critical Urgent (KEV / Active)", color: "bg-rose-500", text: "text-rose-400" },
                { tier: "CRITICAL", label: "Critical (CVSS 9.0+ / High EPSS)", color: "bg-red-500", text: "text-red-400" },
                { tier: "HIGH", label: "High Priority", color: "bg-orange-500", text: "text-orange-400" },
                { tier: "MEDIUM", label: "Medium Priority", color: "bg-amber-500", text: "text-amber-400" },
                { tier: "LOW", label: "Low Priority", color: "bg-blue-500", text: "text-blue-400" },
              ].map(({ tier, label, color, text }) => {
                const count = tierCounts[tier] || 0
                const pct = findings.length > 0 ? (count / findings.length) * 100 : 0
                return (
                  <div key={tier} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-white/80">{label}</span>
                      <span className={`font-mono font-bold ${text}`}>{count}</span>
                    </div>
                    <div className="h-2 w-full rounded-full bg-white/5 overflow-hidden">
                      <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                )
              })}
            </div>

            <div className="p-3 rounded-xl bg-black/40 border border-white/5 text-[11px] text-white/50 space-y-1">
              <div>• <strong>CSB-03 Transparent Formulation:</strong> Priority score accounts for Base CVSS, FIRST EPSS exploit probability, CISA KEV active exploitation factor (1.5x), runtime vs dev scope, and project criticality.</div>
            </div>
          </div>
        </div>
      </div>

      {/* Propagation Graph Mini-Preview Section */}
      {graph_data && (
        <div className="p-6 rounded-2xl border border-white/10 bg-[#0d1322] space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Network className="h-5 w-5 text-blue-400" />
                Vulnerability Propagation Graph Preview
              </h2>
              <p className="text-xs text-white/50 mt-0.5">
                {graph_data.total_nodes} nodes, {graph_data.total_edges} edges, {graph_data.affected_paths_count} affected propagation paths
              </p>
            </div>
            <Link to={`/graph/${record.analysis_id}`}>
              <Button size="sm" variant="outline" className="border-blue-500/40 text-blue-300 hover:text-white bg-blue-950/30 text-xs">
                Open Full Interactive Canvas
                <ArrowRight className="h-3.5 w-3.5 ml-1.5" />
              </Button>
            </Link>
          </div>

          <div className="h-[400px] w-full rounded-xl overflow-hidden border border-white/10">
            <CytoscapeGraphView
              graphData={graph_data}
              filterMode="blast-radius"
              showClean={false}
            />
          </div>
        </div>
      )}

      {/* Affected Components Sample Table */}
      <div className="p-6 rounded-2xl border border-white/10 bg-[#0d1322] space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Layers className="h-5 w-5 text-purple-400" />
            Top Affected Components
          </h2>
          <Link to={`/findings/${record.analysis_id}`} className="text-xs text-blue-400 hover:underline">
            View all findings →
          </Link>
        </div>

        <div className="rounded-xl border border-white/10 overflow-hidden bg-black/40">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-white/[0.03] border-b border-white/10 text-white/50">
              <tr>
                <th className="py-2.5 px-3">Component</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Advisory ID</th>
                <th className="py-2.5 px-3">Priority Tier</th>
                <th className="py-2.5 px-3">CISA KEV</th>
                <th className="py-2.5 px-3">EPSS</th>
                <th className="py-2.5 px-3">Fixed In</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {findings.slice(0, 5).map((f, i) => (
                <tr key={i} className="hover:bg-white/[0.02]">
                  <td className="py-2.5 px-3 text-white font-medium">
                    {f.component.name}@{f.component.version}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                      f.is_direct ? "bg-blue-500/10 text-blue-300 border border-blue-500/20" : "bg-purple-500/10 text-purple-300 border border-purple-500/20"
                    }`}>
                      {f.is_direct ? "Direct" : `Transitive (d=${f.depth})`}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-blue-400">
                    <a
                      href={`https://osv.dev/vulnerability/${f.vulnerability.id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="hover:underline flex items-center gap-1"
                    >
                      {f.vulnerability.id}
                      <ExternalLink className="h-2.5 w-2.5" />
                    </a>
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      f.priority_tier === "CRITICAL_URGENT" || f.priority_tier === "CRITICAL"
                        ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                        : f.priority_tier === "HIGH"
                        ? "bg-orange-500/20 text-orange-300 border border-orange-500/30"
                        : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                    }`}>
                      {f.priority_tier}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    {f.vulnerability.in_kev ? (
                      <span className="px-1.5 py-0.5 rounded bg-rose-950 border border-rose-500/40 text-rose-300 text-[10px] font-bold">
                        KEV MATCH
                      </span>
                    ) : (
                      <span className="text-white/30 text-[10px]">No</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-white/70">
                    {f.vulnerability.epss_score ? `${(f.vulnerability.epss_score * 100).toFixed(1)}%` : "—"}
                  </td>
                  <td className="py-2.5 px-3 text-emerald-400">
                    {f.vulnerability.first_fixed_version || "None"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

