import React, { useEffect, useState } from "react"
import { useParams, Link } from "react-router-dom"
import {
  Network,
  Search,
  Filter,
  Flame,
  Layers,
  ShieldAlert,
  X,
  ExternalLink,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  GitBranch,
  FlaskConical,
  Eye,
  EyeOff
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { getAnalysis, AnalysisRecord } from "@/lib/api"
import CytoscapeGraphView from "@/components/graph/CytoscapeGraphView"

export default function GraphPage() {
  const { analysisId } = useParams<{ analysisId: string }>()
  const [record, setRecord] = useState<AnalysisRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Graph state controls
  const [filterMode, setFilterMode] = useState<"blast-radius" | "project-view" | "full-inventory">("blast-radius")
  const [showDev, setShowDev] = useState(true)
  const [showClean, setShowClean] = useState(true)
  const [kevOnly, setKevOnly] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")

  // Selected Node Drawer state
  const [selectedNode, setSelectedNode] = useState<any | null>(null)

  useEffect(() => {
    if (!analysisId) return
    setLoading(true)
    setError(null)
    getAnalysis(analysisId)
      .then((data) => {
        setRecord(data)
        // If there's a vulnerable node, select the first one by default
        const firstVulnNode = data.graph_data?.nodes.find((n) => n.data.is_vulnerable)
        if (firstVulnNode) {
          setSelectedNode(firstVulnNode.data)
        }
      })
      .catch((err) => setError(err.message || "Failed to load graph"))
      .finally(() => setLoading(false))
  }, [analysisId])

  if (loading) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
          <p className="text-sm text-white/60">Generating dependency propagation graph...</p>
        </div>
      </div>
    )
  }

  if (error || !record || !record.graph_data) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="p-6 rounded-2xl border border-rose-500/30 bg-rose-950/20 text-center">
          <p className="text-sm text-rose-300">{error || "Graph data not available."}</p>
        </div>
      </div>
    )
  }

  // Find finding details for selected node if applicable
  const selectedFindings = selectedNode?.is_vulnerable
    ? record.findings.filter((f) => f.component.name === selectedNode.name && f.component.version === selectedNode.version)
    : []

  // Check if a patch exists for the selected package
  const matchingPatch = record.patch_plan.find((p) => p.package === selectedNode?.name)

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)] overflow-hidden">
      {/* Top Controls Toolbar */}
      <div className="border-b border-white/10 bg-[#070b14] px-4 py-3 flex flex-wrap items-center justify-between gap-3 shrink-0">
        {/* Left: Mode selector & search */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Mode Tabs */}
          <div className="flex items-center rounded-xl bg-black/50 border border-white/10 p-0.5">
            <button
              onClick={() => setFilterMode("blast-radius")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                filterMode === "blast-radius"
                  ? "bg-rose-600/30 text-rose-300 border border-rose-500/40 shadow-sm"
                  : "text-white/60 hover:text-white"
              }`}
            >
              Blast Radius
            </button>
            <button
              onClick={() => setFilterMode("project-view")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                filterMode === "project-view"
                  ? "bg-blue-600/30 text-blue-300 border border-blue-500/40 shadow-sm"
                  : "text-white/60 hover:text-white"
              }`}
            >
              Project View
            </button>
            <button
              onClick={() => setFilterMode("full-inventory")}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                filterMode === "full-inventory"
                  ? "bg-slate-700/40 text-slate-200 border border-slate-500/40 shadow-sm"
                  : "text-white/60 hover:text-white"
              }`}
            >
              Full Inventory
            </button>
          </div>

          {/* Search box */}
          <div className="relative w-52 sm:w-64">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-white/40" />
            <Input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search package, CVE, OSV..."
              className="pl-8 bg-black/40 border-white/10 text-white text-xs h-8 focus:border-blue-500"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2 top-2 text-white/40 hover:text-white"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Right: Toggle filters & legends */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Dev Deps Toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowDev(!showDev)}
            className={`h-8 text-xs border ${
              showDev
                ? "bg-white/5 border-white/15 text-white"
                : "border-transparent text-white/40 line-through"
            }`}
          >
            Dev Scope
          </Button>

          {/* Clean nodes toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowClean(!showClean)}
            className={`h-8 text-xs border ${
              showClean
                ? "bg-white/5 border-white/15 text-white"
                : "border-transparent text-white/40 line-through"
            }`}
          >
            Clean Nodes
          </Button>

          {/* KEV Only Filter */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setKevOnly(!kevOnly)}
            className={`h-8 text-xs border ${
              kevOnly
                ? "bg-amber-950/60 border-amber-500/50 text-amber-300 font-semibold"
                : "bg-white/5 border-white/15 text-white/70"
            }`}
          >
            <Flame className="h-3 w-3 mr-1 text-amber-400" />
            KEV Only
          </Button>

          {/* Legend indicator */}
          <div className="hidden xl:flex items-center gap-3 pl-3 border-l border-white/10 text-[11px] text-white/60">
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-sm bg-rose-600" />
              <span>Vulnerable</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-sm bg-amber-600" />
              <span>KEV Exploit</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-sm border border-dashed border-indigo-400 bg-slate-800" />
              <span>Cycle (Tarjan)</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-sm bg-slate-700" />
              <span>Clean</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-sm bg-emerald-600" />
              <span>Simulated Fix</span>
            </span>
          </div>

          {(record.summary.cyclic_components_count || 0) > 0 && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-indigo-950/40 border border-indigo-500/40 text-[11px] text-indigo-300 font-mono">
              <GitBranch className="h-3 w-3 text-indigo-400" />
              <span>Cycles: {record.summary.cyclic_components_count} ({record.summary.vulnerable_cycle_components?.length || 0} vuln)</span>
            </div>
          )}

        </div>
      </div>

      {/* Main Canvas & Right Drawer Layout */}
      <div className="relative flex-1 flex overflow-hidden">
        {/* Cytoscape Canvas */}
        <div className="flex-1 h-full">
          <CytoscapeGraphView
            graphData={record.graph_data}
            selectedNodeId={selectedNode?.id}
            onSelectNode={(nodeData) => setSelectedNode(nodeData)}
            filterMode={filterMode}
            showDev={showDev}
            showClean={showClean}
            kevOnly={kevOnly}
            searchQuery={searchQuery}
          />
        </div>

        {/* Right-Side Evidence & Metadata Drawer */}
        {selectedNode && (
          <div className="w-80 sm:w-96 border-l border-white/10 bg-[#090e1a]/95 backdrop-blur-md h-full overflow-y-auto p-5 space-y-5 shadow-2xl shrink-0 animate-in slide-in-from-right duration-200">
            {/* Drawer Header */}
            <div className="flex items-start justify-between pb-3 border-b border-white/10">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                    selectedNode.type === "root"
                      ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30"
                      : selectedNode.is_direct
                      ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                      : "bg-purple-500/20 text-purple-300 border border-purple-500/30"
                  }`}>
                    {selectedNode.type === "root" ? "Project Root" : selectedNode.is_direct ? "Direct Dep" : "Transitive Dep"}
                  </span>
                  {selectedNode.in_cycle && (
                    <span className="px-1.5 py-0.5 rounded bg-indigo-500/20 border border-indigo-500/40 text-indigo-300 text-[10px] font-bold flex items-center gap-1">
                      <GitBranch className="h-3 w-3" />
                      CYCLIC DEP
                    </span>
                  )}
                  {selectedNode.in_kev && (
                    <span className="px-1.5 py-0.5 rounded bg-amber-500/20 border border-amber-500/40 text-amber-300 text-[10px] font-bold flex items-center gap-1">
                      <Flame className="h-3 w-3" />
                      KEV ACTIVE
                    </span>
                  )}
                </div>
                <h3 className="text-lg font-bold font-mono text-white break-all">
                  {selectedNode.name}
                </h3>
                {selectedNode.version && (
                  <span className="text-xs text-white/50 font-mono">v{selectedNode.version}</span>
                )}
              </div>

              <Button
                variant="ghost"
                size="icon"
                onClick={() => setSelectedNode(null)}
                className="text-white/40 hover:text-white"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>

            {/* Coordinates & Scope Details */}
            <div className="space-y-2 text-xs">
              <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1.5 font-mono">
                <div className="flex justify-between">
                  <span className="text-white/40">Ecosystem:</span>
                  <span className="text-white">{selectedNode.ecosystem || "npm"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-white/40">Scope:</span>
                  <span className="text-white capitalize">{selectedNode.scope || "runtime"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-white/40">Cycle:</span>
                  <span className={selectedNode.in_cycle ? "text-indigo-300 font-semibold" : "text-white/60"}>
                    {selectedNode.in_cycle ? `In Cycle (${selectedNode.cycle_id || "Tarjan SCC"})` : "Acyclic"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-white/40">Verification:</span>
                  <span className="text-white/80">{selectedNode.lookup_status || "verified"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-white/40">Status:</span>
                  <span className={selectedNode.is_vulnerable ? "text-rose-400 font-semibold" : "text-emerald-400 font-semibold"}>
                    {selectedNode.is_vulnerable ? "Vulnerable" : selectedNode.status === "simulated_resolved" ? "Simulated Resolved" : "Clean"}
                  </span>
                </div>
              </div>
            </div>


            {/* Proposed Patch Section */}
            {matchingPatch && (
              <div className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-950/20 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-emerald-400 font-semibold flex items-center gap-1">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Recommended Upgrade
                  </span>
                  <span className="font-mono text-emerald-300 font-bold">
                    → {matchingPatch.target_version}
                  </span>
                </div>
                <p className="text-[11px] text-white/70 leading-relaxed">
                  {matchingPatch.why_now}
                </p>
                <Link to={`/simulate/${record.analysis_id}?patch=${encodeURIComponent(matchingPatch.package)}`}>
                  <Button size="sm" className="w-full h-8 bg-emerald-600 hover:bg-emerald-500 text-white text-xs mt-1">
                    <FlaskConical className="h-3 w-3 mr-1" />
                    Simulate Patch
                  </Button>
                </Link>
              </div>
            )}

            {/* Advisories List */}
            {selectedFindings.length > 0 && (
              <div className="space-y-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-white/70 flex items-center justify-between">
                  <span>Detected Advisories ({selectedFindings.length})</span>
                  <span className="text-[10px] text-rose-400 font-mono">Confirmed</span>
                </div>

                <div className="space-y-3">
                  {selectedFindings.map((f, i) => {
                    const uniqueId = f.vulnerability.id || selectedNode.unique_id || "UNKNOWN-ID"
                    const cveAlias = f.vulnerability.cve_id || (f.vulnerability.aliases && f.vulnerability.aliases.length > 0 ? f.vulnerability.aliases[0] : null) || selectedNode.cve_alias || "No CVE Alias"
                    const cweId = f.vulnerability.cwe_id || selectedNode.cwe_id
                    const vulnName = f.vulnerability.vulnerability_name || f.vulnerability.summary || selectedNode.vulnerability_name || "Unclassified Security Flaw"
                    const vulnType = f.vulnerability.vulnerability_type || selectedNode.vulnerability_type || "General Security Weakness"

                    return (
                      <div key={i} className="p-3.5 rounded-xl border border-white/10 bg-black/40 space-y-3 hover:border-purple-500/30 transition-all">
                        {/* Unique ID & CVE Alias Badges */}
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <a
                              href={`https://osv.dev/vulnerability/${uniqueId}`}
                              target="_blank"
                              rel="noreferrer"
                              className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-blue-950/80 text-blue-300 border border-blue-600/50 hover:bg-blue-900 transition-colors inline-flex items-center gap-1"
                              title="Primary OSV / GHSA Advisory ID"
                            >
                              {uniqueId}
                              <ExternalLink className="h-2.5 w-2.5" />
                            </a>
                            {cveAlias && cveAlias !== "No CVE Alias" && (
                              <span
                                className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-red-950/80 text-red-300 border border-red-600/50"
                                title="Primary CVE Alias"
                              >
                                {cveAlias}
                              </span>
                            )}
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            f.priority_tier === "CRITICAL_URGENT" || f.priority_tier === "CRITICAL"
                              ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                              : "bg-orange-500/20 text-orange-300 border border-orange-500/40"
                          }`}>
                            {f.priority_tier}
                          </span>
                        </div>

                        {/* Full Descriptive Title */}
                        <div>
                          <p className="text-xs font-semibold text-white leading-snug">
                            {vulnName}
                          </p>
                        </div>

                        {/* Weakness Category Highlighted Badge */}
                        <div className="pt-0.5">
                          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-purple-950/70 border border-purple-500/50 text-purple-300 text-xs font-semibold shadow-sm">
                            <ShieldAlert className="h-3.5 w-3.5 text-purple-400 shrink-0" />
                            <span>
                              {cweId ? `${cweId} ➔ ${vulnType}` : vulnType}
                            </span>
                          </div>
                        </div>

                        {/* Risk Score & Intelligence Indicators */}
                        <div className="grid grid-cols-2 gap-2 text-[10px] font-mono text-white/70 pt-2 border-t border-white/5">
                          <div>Risk Score: <strong className="text-white">{f.priority_score ? f.priority_score.toFixed(1) : "N/A"}/10</strong></div>
                          <div>EPSS: <strong className="text-white">{f.vulnerability.epss_score ? `${(f.vulnerability.epss_score * 100).toFixed(1)}%` : "N/A"}</strong></div>
                          <div>Fixed: <strong className="text-emerald-400">{f.vulnerability.first_fixed_version || "None"}</strong></div>
                          <div>KEV Status: <strong className={f.vulnerability.in_kev ? "text-amber-300" : "text-white/50"}>{f.vulnerability.in_kev ? "Active Exploit" : "Clean"}</strong></div>
                        </div>

                        {/* Propagation Path Stack Trace */}
                        {f.propagation_paths_to_root && f.propagation_paths_to_root.length > 0 && (
                          <div className="pt-2 border-t border-white/5 text-[10px]">
                            <span className="text-white/40 block mb-1">Propagation Path:</span>
                            <div className="font-mono text-blue-300/90 bg-white/[0.02] p-1.5 rounded flex items-center gap-1 overflow-x-auto whitespace-nowrap">
                              <GitBranch className="h-3 w-3 shrink-0 text-blue-400" />
                              {f.propagation_paths_to_root[0].join(" → ")}
                            </div>
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

