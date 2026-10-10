import React, { useEffect, useState, useMemo } from "react"
import { useParams, Link } from "react-router-dom"
import {
  AlertTriangle,
  Search,
  Filter,
  Flame,
  ExternalLink,
  ShieldAlert,
  X,
  GitBranch,
  CheckCircle2,
  Sparkles,
  Layers,
  ArrowRight,
  Info,
  ChevronRight
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { getAnalysis, AnalysisRecord, VulnerableFinding } from "@/lib/api"

export default function FindingsPage() {
  const { analysisId } = useParams<{ analysisId: string }>()
  const [record, setRecord] = useState<AnalysisRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [searchQuery, setSearchQuery] = useState("")
  const [tierFilter, setTierFilter] = useState<string>("ALL")
  const [depTypeFilter, setDepTypeFilter] = useState<string>("ALL") // ALL, DIRECT, TRANSITIVE
  const [kevFilter, setKevFilter] = useState<boolean>(false)
  const [sortField, setSortField] = useState<"priority" | "package" | "epss">("priority")

  // Selected finding for explanation drawer
  const [selectedFinding, setSelectedFinding] = useState<VulnerableFinding | null>(null)

  useEffect(() => {
    if (!analysisId) return
    setLoading(true)
    setError(null)
    getAnalysis(analysisId)
      .then((data) => {
        setRecord(data)
        if (data.findings && data.findings.length > 0) {
          setSelectedFinding(data.findings[0])
        }
      })
      .catch((err) => setError(err.message || "Failed to load findings"))
      .finally(() => setLoading(false))
  }, [analysisId])

  const filteredFindings = useMemo(() => {
    if (!record) return []
    return record.findings
      .filter((f) => {
        // Search
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase()
          const pkgMatch = f.component.name.toLowerCase().includes(q)
          const idMatch = f.vulnerability.id.toLowerCase().includes(q)
          const cveMatch = f.vulnerability.cve_id?.toLowerCase().includes(q) || false
          const summaryMatch = f.vulnerability.summary?.toLowerCase().includes(q) || false
          const typeMatch = f.vulnerability.vulnerability_type?.toLowerCase().includes(q) || false
          if (!pkgMatch && !idMatch && !cveMatch && !summaryMatch && !typeMatch) return false
        }

        // Tier
        if (tierFilter !== "ALL" && f.priority_tier !== tierFilter) return false

        // Dep Type
        if (depTypeFilter === "DIRECT" && !f.is_direct) return false
        if (depTypeFilter === "TRANSITIVE" && f.is_direct) return false

        // KEV
        if (kevFilter && !f.vulnerability.in_kev) return false

        return true
      })
      .sort((a, b) => {
        if (sortField === "priority") {
          return (b.priority_score || 0) - (a.priority_score || 0)
        } else if (sortField === "epss") {
          return (b.vulnerability.epss_score || 0) - (a.vulnerability.epss_score || 0)
        } else {
          return a.component.name.localeCompare(b.component.name)
        }
      })
  }, [record, searchQuery, tierFilter, depTypeFilter, kevFilter, sortField])

  if (loading) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
          <p className="text-sm text-white/60">Loading vulnerability inventory...</p>
        </div>
      </div>
    )
  }

  if (error || !record) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="p-6 rounded-2xl border border-rose-500/30 bg-rose-950/20 text-center">
          <p className="text-sm text-rose-300">{error || "Could not retrieve findings."}</p>
        </div>
      </div>
    )
  }

  const kevMatchesCount = filteredFindings.filter((f) => f.vulnerability.in_kev).length
  const unfixableCount = filteredFindings.filter((f) => !f.vulnerability.first_fixed_version).length

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-white/10 gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <AlertTriangle className="h-6 w-6 text-rose-400" />
            Vulnerability Findings & Evidence
          </h1>
          <p className="text-xs text-white/50 mt-1 font-mono">
            Project: <strong className="text-white">{record.project_name}</strong> • Total Scanned: {record.summary.total_components} packages
          </p>
        </div>

        {/* Summary metric pills */}
        <div className="flex items-center gap-2 text-xs font-mono flex-wrap">
          <div className="px-3 py-1.5 rounded-xl border border-white/10 bg-black/40">
            Advisories: <strong className="text-white">{record.summary.advisory_records_count || record.findings.length}</strong>
          </div>
          <div className="px-3 py-1.5 rounded-xl border border-white/10 bg-black/40">
            Distinct Groups: <strong className="text-white">{record.summary.distinct_vulnerabilities_count || record.findings.length}</strong>
          </div>
          {(record.summary.cyclic_components_count || 0) > 0 && (
            <div className="px-3 py-1.5 rounded-xl border border-indigo-500/30 bg-indigo-950/30 text-indigo-300">
              In Cycles: <strong className="text-indigo-200">{record.summary.cyclic_components_count}</strong>
            </div>
          )}
          {kevMatchesCount > 0 && (
            <div className="px-3 py-1.5 rounded-xl border border-amber-500/30 bg-amber-950/30 text-amber-300 flex items-center gap-1 font-semibold">
              <Flame className="h-3.5 w-3.5" />
              KEV: {kevMatchesCount}
            </div>
          )}
        </div>

      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl border border-white/10 bg-[#0d1322] flex flex-wrap items-center justify-between gap-3">
        {/* Search Input */}
        <div className="relative w-full sm:w-72">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-white/40" />
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search package, CVE, summary..."
            className="pl-9 bg-black/40 border-white/10 text-white text-xs h-9 focus:border-blue-500"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery("")} className="absolute right-2.5 top-2.5 text-white/40 hover:text-white">
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity Tier */}
          <select
            value={tierFilter}
            onChange={(e) => setTierFilter(e.target.value)}
            className="bg-black/40 border border-white/10 rounded-lg text-white text-xs h-9 px-3 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Tiers</option>
            <option value="CRITICAL_URGENT">Critical Urgent</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Dep Type */}
          <select
            value={depTypeFilter}
            onChange={(e) => setDepTypeFilter(e.target.value)}
            className="bg-black/40 border border-white/10 rounded-lg text-white text-xs h-9 px-3 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">Direct & Transitive</option>
            <option value="DIRECT">Direct Only</option>
            <option value="TRANSITIVE">Transitive Only</option>
          </select>

          {/* KEV Toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setKevFilter(!kevFilter)}
            className={`h-9 text-xs border ${
              kevFilter
                ? "bg-amber-950/60 border-amber-500/50 text-amber-300 font-semibold"
                : "bg-black/40 border-white/10 text-white/70"
            }`}
          >
            <Flame className="h-3.5 w-3.5 mr-1 text-amber-400" />
            KEV Only
          </Button>

          {/* Sort */}
          <select
            value={sortField}
            onChange={(e) => setSortField(e.target.value as any)}
            className="bg-black/40 border border-white/10 rounded-lg text-white text-xs h-9 px-3 focus:outline-none focus:border-blue-500"
          >
            <option value="priority">Sort: CSB-03 Risk (High to Low)</option>
            <option value="epss">Sort: EPSS Exploit %</option>
            <option value="package">Sort: Package Name</option>
          </select>
        </div>
      </div>

      {/* Main Grid: Findings Table & Explain Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Table Column */}
        <div className="lg:col-span-7 rounded-2xl border border-white/10 bg-[#0d1322] overflow-hidden shadow-xl">
          <div className="overflow-x-auto max-h-[700px] overflow-y-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="sticky top-0 bg-[#0d1322] border-b border-white/10 text-white/50 z-10 backdrop-blur-md">
                <tr>
                  <th className="py-3 px-3">Component</th>
                  <th className="py-3 px-3">Type</th>
                  <th className="py-3 px-3">Advisory ID / Vulnerability Type</th>
                  <th className="py-3 px-3">Priority Tier</th>
                  <th className="py-3 px-3">KEV</th>
                  <th className="py-3 px-3">EPSS</th>
                  <th className="py-3 px-3 text-right">Fix</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredFindings.map((f, i) => {
                  const isSelected = selectedFinding?.vulnerability.id === f.vulnerability.id && selectedFinding?.component.name === f.component.name
                  const vulnType = f.vulnerability.vulnerability_type || "Unclassified"

                  return (
                    <tr
                      key={i}
                      onClick={() => setSelectedFinding(f)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? "bg-blue-600/20 text-white font-medium"
                          : "hover:bg-white/[0.02] text-white/80"
                      }`}
                    >
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-white">{f.component.name}</div>
                        <div className="text-[10px] text-white/40">v{f.component.version}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                          f.is_direct ? "bg-blue-500/10 text-blue-300 border border-blue-500/20" : "bg-purple-500/10 text-purple-300 border border-purple-500/20"
                        }`}>
                          {f.is_direct ? "Direct" : `Trans (d=${f.depth})`}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-semibold text-blue-400">
                          {f.vulnerability.cve_id || f.vulnerability.id}
                        </div>
                        <div className="text-[10px] font-sans mt-0.5">
                          <span className="px-1.5 py-0.2 rounded bg-purple-950/60 border border-purple-800/40 text-purple-300 font-medium">
                            {vulnType}
                          </span>
                        </div>
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
                          <span className="px-1.5 py-0.5 rounded bg-rose-950 border border-rose-500/50 text-rose-300 text-[10px] font-bold">
                            KEV
                          </span>
                        ) : (
                          <span className="text-white/20">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-white/70">
                        {f.vulnerability.epss_score ? `${(f.vulnerability.epss_score * 100).toFixed(1)}%` : "—"}
                      </td>
                      <td className="py-2.5 px-3 text-right text-emerald-400 font-semibold">
                        {f.vulnerability.first_fixed_version || "None"}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Explain Drawer Column */}
        <div className="lg:col-span-5">
          {selectedFinding ? (
            <div className="p-6 rounded-2xl border border-white/10 bg-[#0d1322] space-y-5 shadow-2xl">
              {/* Header */}
              <div className="pb-4 border-b border-white/10">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                    selectedFinding.is_direct
                      ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                      : "bg-purple-500/20 text-purple-300 border border-purple-500/30"
                  }`}>
                    {selectedFinding.is_direct ? "Direct Dependency" : `Transitive Dependency (Depth ${selectedFinding.depth})`}
                  </span>
                  {selectedFinding.component.in_cycle && (
                    <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-[10px] font-mono font-semibold flex items-center gap-1">
                      <GitBranch className="h-3 w-3" />
                      In Cycle ({selectedFinding.component.cycle_group_id || "Tarjan SCC"})
                    </span>
                  )}
                  {selectedFinding.vulnerability.in_kev && (
                    <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-500/40 text-rose-300 text-[10px] font-bold flex items-center gap-1">
                      <Flame className="h-3 w-3" />
                      CISA KEV EXPLOITED
                    </span>
                  )}
                </div>

                <h3 className="text-xl font-bold font-mono text-white">
                  {selectedFinding.component.name}
                  <span className="text-white/50 text-sm ml-2">@{selectedFinding.component.version}</span>
                </h3>

                <div className="flex flex-wrap items-center gap-2 mt-2 text-xs font-mono">
                  <a
                    href={`https://osv.dev/vulnerability/${selectedFinding.vulnerability.id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-blue-400 hover:underline flex items-center gap-1 font-semibold"
                  >
                    {selectedFinding.vulnerability.id}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                  {selectedFinding.vulnerability.cve_id && (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.vulnerability.cve_id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-cyan-400 hover:underline flex items-center gap-1"
                    >
                      ({selectedFinding.vulnerability.cve_id})
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </div>

                {/* Vulnerability Type / Category Badge */}
                <div className="mt-2.5">
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-purple-950/70 border border-purple-500/40 text-purple-300 text-xs font-semibold">
                    <ShieldAlert className="h-3.5 w-3.5 text-purple-400 shrink-0" />
                    <span>
                      {selectedFinding.vulnerability.cwe_id
                        ? `${selectedFinding.vulnerability.cwe_id} ➔ ${selectedFinding.vulnerability.vulnerability_type || "Unclassified"}`
                        : (selectedFinding.vulnerability.vulnerability_type || "Unclassified")}
                    </span>
                  </div>
                </div>
              </div>

              {/* Advisory Summary & Details */}
              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-white/60 uppercase tracking-wider flex items-center justify-between">
                  <span>Advisory Summary</span>
                  <span className="text-[10px] text-purple-300 font-mono">
                    Type: {selectedFinding.vulnerability.vulnerability_type || "Unclassified"}
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-black/40 border border-white/5 text-xs text-white/80 leading-relaxed max-h-40 overflow-y-auto">
                  {selectedFinding.vulnerability.summary || selectedFinding.vulnerability.details || "No advisory description available."}
                </div>
              </div>

              {/* Priority & Threat Intel Metrics */}
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-3 rounded-xl bg-black/40 border border-white/5">
                  <span className="text-white/40 block text-[10px]">CSB-03 Priority Score</span>
                  <strong className="text-rose-400 text-base">{selectedFinding.priority_score.toFixed(1)}</strong>
                  <span className="text-[10px] text-white/50 block">Tier: {selectedFinding.priority_tier}</span>
                </div>

                <div className="p-3 rounded-xl bg-black/40 border border-white/5">
                  <span className="text-white/40 block text-[10px]">EPSS Probability</span>
                  <strong className="text-amber-400 text-base">
                    {selectedFinding.vulnerability.epss_score ? `${(selectedFinding.vulnerability.epss_score * 100).toFixed(1)}%` : "N/A"}
                  </strong>
                  <span className="text-[10px] text-white/50 block">
                    {selectedFinding.vulnerability.epss_percentile ? `${(selectedFinding.vulnerability.epss_percentile * 100).toFixed(0)}th percentile` : "No percentile"}
                  </span>
                </div>
              </div>

              {/* Propagation Path Stack Trace */}
              {selectedFinding.propagation_paths_to_root && selectedFinding.propagation_paths_to_root.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-white/60 uppercase tracking-wider flex items-center gap-1.5">
                    <GitBranch className="h-3.5 w-3.5 text-blue-400" />
                    Propagation Path to Root
                  </div>
                  <div className="p-3 rounded-xl bg-black/50 border border-white/10 font-mono text-xs text-blue-300 space-y-1">
                    {selectedFinding.propagation_paths_to_root.map((path, idx) => (
                      <div key={idx} className="flex items-center gap-1 overflow-x-auto whitespace-nowrap py-0.5">
                        <ChevronRight className="h-3.5 w-3.5 text-blue-400 shrink-0" />
                        <span>{path.join(" → ")}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Remediation Fix */}
              <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/20 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-emerald-400 font-semibold flex items-center gap-1.5">
                    <CheckCircle2 className="h-4 w-4" />
                    Resolution Version
                  </span>
                  <span className="font-mono text-emerald-300 font-bold text-sm">
                    {selectedFinding.vulnerability.first_fixed_version ? `Upgrade to ${selectedFinding.vulnerability.first_fixed_version}` : "No official patch available"}
                  </span>
                </div>
                {selectedFinding.vulnerability.first_fixed_version && (
                  <Link to={`/simulate/${record.analysis_id}?patch=${encodeURIComponent(selectedFinding.component.name)}`}>
                    <Button size="sm" className="w-full h-8 bg-emerald-600 hover:bg-emerald-500 text-white text-xs mt-2">
                      <Sparkles className="h-3.5 w-3.5 mr-1.5" />
                      Simulate Remediation In Graph
                    </Button>
                  </Link>
                )}
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-2xl border border-white/10 bg-black/30 text-center text-white/50 text-xs">
              Select a vulnerability from the table to view its full evidence breakdown and propagation trace.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

