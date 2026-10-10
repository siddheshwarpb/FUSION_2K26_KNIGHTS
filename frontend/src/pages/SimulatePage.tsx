import React, { useEffect, useState } from "react"
import { useParams, useSearchParams, Link } from "react-router-dom"
import {
  FlaskConical,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  TrendingDown,
  Network,
  Layers,
  RotateCcw,
  Loader2,
  ListOrdered,
  ExternalLink,
  ShieldAlert
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { getAnalysis, simulatePatches, AnalysisRecord, SimulationResponse } from "@/lib/api"
import CytoscapeGraphView from "@/components/graph/CytoscapeGraphView"

export default function SimulatePage() {
  const { analysisId } = useParams<{ analysisId: string }>()
  const [searchParams] = useSearchParams()
  const initialPatchPkg = searchParams.get("patch")

  const [record, setRecord] = useState<AnalysisRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Selection of patches to simulate
  const [selectedPatches, setSelectedPatches] = useState<Record<string, boolean>>({})
  const [simulating, setSimulating] = useState(false)
  const [simResult, setSimResult] = useState<SimulationResponse | null>(null)

  useEffect(() => {
    if (!analysisId) return
    setLoading(true)
    setError(null)
    getAnalysis(analysisId)
      .then((data) => {
        setRecord(data)
        // Initialize patch selection: if initialPatchPkg is passed, select it, otherwise select Rank #1
        const initialSelection: Record<string, boolean> = {}
        if (data.patch_plan && data.patch_plan.length > 0) {
          if (initialPatchPkg) {
            initialSelection[initialPatchPkg] = true
          } else {
            initialSelection[data.patch_plan[0].package] = true
          }
        }
        setSelectedPatches(initialSelection)

        // Automatically run initial simulation for smooth UX
        if (Object.keys(initialSelection).length > 0) {
          const toApply = data.patch_plan
            .filter((p) => initialSelection[p.package])
            .map((p) => ({ package: p.package, target_version: p.target_version }))

          if (toApply.length > 0) {
            setSimulating(true)
            simulatePatches(analysisId, toApply)
              .then((res) => setSimResult(res))
              .catch(() => {})
              .finally(() => setSimulating(false))
          }
        }
      })
      .catch((err) => setError(err.message || "Failed to load analysis for simulation"))
      .finally(() => setLoading(false))
  }, [analysisId, initialPatchPkg])

  const handleTogglePatch = (pkg: string) => {
    setSelectedPatches((prev) => ({
      ...prev,
      [pkg]: !prev[pkg],
    }))
  }

  const handleRunSimulation = async () => {
    if (!record || !analysisId) return
    const toApply = record.patch_plan
      .filter((p) => selectedPatches[p.package])
      .map((p) => ({ package: p.package, target_version: p.target_version }))

    if (toApply.length === 0) {
      alert("Please select at least one patch to simulate.")
      return
    }

    setSimulating(true)
    try {
      const res = await simulatePatches(analysisId, toApply)
      setSimResult(res)
    } catch (err: any) {
      alert("Simulation failed: " + err.message)
    } finally {
      setSimulating(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 rounded-full border-2 border-emerald-500 border-t-transparent animate-spin" />
          <p className="text-sm text-white/60">Initializing counterfactual simulator...</p>
        </div>
      </div>
    )
  }

  if (error || !record) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="p-6 rounded-2xl border border-rose-500/30 bg-rose-950/20 text-center">
          <p className="text-sm text-rose-300">{error || "Analysis not found."}</p>
        </div>
      </div>
    )
  }

  const diff = simResult?.diff

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-white/10 gap-3">
        <div>
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold mb-1">
            <Sparkles className="h-3.5 w-3.5" />
            Counterfactual Remediation Sandbox
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <FlaskConical className="h-6 w-6 text-emerald-400" />
            Patch Impact Simulation
          </h1>
          <p className="text-xs text-white/50 mt-1 font-mono">
            Project: <strong className="text-white">{record.project_name}</strong> • Evaluate upgrades in isolation without mutating lockfiles
          </p>
        </div>

        <Link to={`/patch-plan/${record.analysis_id}`}>
          <Button variant="outline" size="sm" className="border-white/10 text-xs text-white/80 hover:text-white bg-black/40">
            <ListOrdered className="h-3.5 w-3.5 mr-1.5 text-blue-400" />
            View Full Patch Queue
          </Button>
        </Link>
      </div>

      {/* Simulator Control Bar: Patch Checkboxes */}
      <div className="p-6 rounded-2xl border border-white/10 bg-[#0d1322] space-y-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-white">Select Candidate Patches to Apply</h3>
            <p className="text-xs text-white/50">
              Check candidate upgrades to model dependency re-evaluation and graph pruning.
            </p>
          </div>

          <Button
            onClick={handleRunSimulation}
            disabled={simulating}
            className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs h-9 shadow-lg shadow-emerald-600/30"
          >
            {simulating ? (
              <>
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                Simulating...
              </>
            ) : (
              <>
                <Sparkles className="h-3.5 w-3.5 mr-1.5" />
                Run Counterfactual Simulation
              </>
            )}
          </Button>
        </div>

        {/* Patch options checkboxes */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 pt-2">
          {record.patch_plan.map((p) => {
            const isChecked = !!selectedPatches[p.package]
            return (
              <label
                key={p.package}
                className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-all ${
                  isChecked
                    ? "bg-emerald-950/30 border-emerald-500/50 text-white"
                    : "bg-black/30 border-white/10 hover:border-white/20 text-white/70"
                }`}
              >
                <input
                  type="checkbox"
                  checked={isChecked}
                  onChange={() => handleTogglePatch(p.package)}
                  className="mt-1 h-4 w-4 rounded border-white/20 text-emerald-600 focus:ring-emerald-500 bg-black/50"
                />
                <div className="space-y-0.5 font-mono text-xs">
                  <div className="font-bold text-white flex items-center gap-1.5">
                    <span>{p.package}</span>
                    <span className="text-[10px] text-white/40 font-normal">#{p.rank}</span>
                  </div>
                  <div className="text-[11px] text-emerald-400">
                    {p.current_version} → {p.target_version}
                  </div>
                  <div className="text-[10px] text-white/50">
                    Eliminates {p.findings_removed.length} vulns
                  </div>
                </div>
              </label>
            )
          })}
        </div>
      </div>

      {/* Before vs After Scorecard */}
      {diff && (
        <div className="space-y-4">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-white/70 flex items-center gap-2">
            <TrendingDown className="h-4 w-4 text-emerald-400" />
            Counterfactual Impact Scorecard
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
            {/* Risk Reduction */}
            <div className="p-5 rounded-2xl border border-emerald-500/30 bg-emerald-950/20 space-y-1">
              <div className="text-xs text-emerald-300/80">Net Risk Reduction</div>
              <div className="text-3xl font-extrabold text-emerald-400">
                {diff.risk_reduction_pct.toFixed(1)}%
              </div>
              <div className="text-[11px] text-white/60">
                Score: {diff.risk_before.toFixed(1)} → <strong className="text-emerald-300">{diff.risk_after.toFixed(1)}</strong>
              </div>
            </div>

            {/* Resolved Vulnerabilities */}
            <div className="p-5 rounded-2xl border border-white/10 bg-[#0d1322] space-y-1">
              <div className="text-xs text-white/50">Vulnerabilities Resolved</div>
              <div className="text-3xl font-extrabold text-white">
                {diff.resolved_findings_count}
              </div>
              <div className="text-[11px] text-emerald-400 font-semibold">
                Remaining: {diff.findings_after_count} / {diff.findings_before_count}
              </div>
            </div>

            {/* Remaining High Priority */}
            <div className="p-5 rounded-2xl border border-white/10 bg-[#0d1322] space-y-1">
              <div className="text-xs text-white/50">Remaining High Priority</div>
              <div className="text-3xl font-extrabold text-rose-400">
                {diff.remaining_high_priority_count}
              </div>
              <div className="text-[11px] text-white/60">
                In subsequent iteration
              </div>
            </div>

            {/* New Top Patch for next cycle */}
            <div className="p-5 rounded-2xl border border-white/10 bg-[#0d1322] space-y-1">
              <div className="text-xs text-white/50">Next Iteration Top Patch</div>
              {diff.new_top_patch ? (
                <div>
                  <div className="text-lg font-bold text-blue-300 truncate">
                    {diff.new_top_patch.package}
                  </div>
                  <div className="text-[11px] text-emerald-400 font-semibold">
                    → {diff.new_top_patch.target_version} (R/ΔC: {diff.new_top_patch.marginal_value.toFixed(1)})
                  </div>
                </div>
              ) : (
                <div className="text-emerald-400 font-bold text-sm mt-2">
                  All Vulnerabilities Clear!
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Simulated Cytoscape Graph Canvas */}
      {simResult?.simulated_graph && (
        <div className="p-6 rounded-2xl border border-white/10 bg-[#0d1322] space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Network className="h-5 w-5 text-emerald-400" />
                Simulated Propagation Graph
              </h2>
              <p className="text-xs text-white/50 mt-0.5">
                Simulated state (<span className="text-emerald-400 font-mono">simulated_resolved</span>) • Unverified until physical build test • Remaining active risks in red/amber
              </p>
            </div>
          </div>

          <div className="h-[480px] w-full rounded-xl overflow-hidden border border-white/10">
            <CytoscapeGraphView
              graphData={simResult.simulated_graph}
              filterMode="full-inventory"
              showClean={true}
            />
          </div>
        </div>
      )}

      {/* Resolved vs Remaining Advisories Two-Column Grid */}
      {diff && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Resolved Vulnerabilities */}
          <div className="p-5 rounded-2xl border border-emerald-500/30 bg-emerald-950/10 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-emerald-500/20">
              <h3 className="text-xs font-semibold text-emerald-300 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                Resolved Advisories ({diff.resolved_vuln_ids.length})
              </h3>
            </div>

            <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
              {diff.resolved_vuln_ids.length === 0 ? (
                <p className="text-xs text-white/50">No advisories resolved with current patch selection.</p>
              ) : (
                diff.resolved_vuln_ids.map((id) => (
                  <div key={id} className="p-2 rounded-lg bg-black/40 border border-emerald-500/20 flex items-center justify-between text-xs font-mono">
                    <span className="text-emerald-300">{id}</span>
                    <a
                      href={`https://osv.dev/vulnerability/${id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-white/40 hover:text-white"
                    >
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Remaining Risks */}
          <div className="p-5 rounded-2xl border border-rose-500/30 bg-rose-950/10 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-rose-500/20">
              <h3 className="text-xs font-semibold text-rose-300 uppercase tracking-wider flex items-center gap-1.5">
                <AlertTriangle className="h-4 w-4 text-rose-400" />
                Remaining Vulnerabilities ({simResult?.remaining_findings.length || 0})
              </h3>
            </div>

            <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
              {simResult?.remaining_findings.length === 0 ? (
                <div className="p-4 rounded-xl text-center text-xs text-emerald-400 font-medium">
                  Zero remaining vulnerabilities! Complete supply-chain hygiene achieved.
                </div>
              ) : (
                simResult?.remaining_findings.map((f, i) => (
                  <div key={i} className="p-2 rounded-lg bg-black/40 border border-white/5 flex items-center justify-between text-xs font-mono">
                    <div>
                      <span className="text-white font-medium">{f.component.name}</span>
                      <span className="text-white/40 text-[10px] ml-1">@{f.component.version}</span>
                    </div>
                    <span className="text-rose-400 text-[11px]">{f.vulnerability.id}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

