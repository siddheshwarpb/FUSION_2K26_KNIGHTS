import React, { useState, useEffect } from "react"
import { useNavigate } from "react-router-dom"
import {
  GitCommit,
  Link2,
  Terminal,
  AlertCircle,
  CheckCircle2,
  Loader2,
  ShieldOff,
  ShieldCheck,
  Info,
  ExternalLink,
  Search,
  Clock,
  Hash,
  GitCompare,
  Layers,
  ArrowRight,
  GitFork,
  CheckCircle,
  FileCode,
  Box,
  LayoutDashboard,
  Network,
  ShieldAlert,
  Wrench,
  Sparkles,
  FileText,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  startCommitScan,
  getCommitScan,
  listCommitScans,
  compareCommitScans,
  CommitScanRecord,
  UnifiedCommitFinding,
  CommitComparisonRecord,
} from "@/lib/api"

// ── Severity badge ────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toUpperCase() || "UNKNOWN"
  const map: Record<string, string> = {
    CRITICAL: "bg-red-900/60 text-red-300 border border-red-700",
    HIGH: "bg-orange-900/60 text-orange-300 border border-orange-700",
    MEDIUM: "bg-yellow-900/60 text-yellow-300 border border-yellow-700",
    LOW: "bg-blue-900/60 text-blue-300 border border-blue-700",
    UNKNOWN: "bg-gray-700/60 text-gray-300 border border-gray-600",
  }
  const cls = map[s] || map["UNKNOWN"]
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${cls}`}>
      {severity || "UNKNOWN"}
    </span>
  )
}

// ── Source badge ──────────────────────────────────────────────────────────────

function SourceBadge({ source, sourcesSeen }: { source: string; sourcesSeen?: string[] }) {
  const isMulti = sourcesSeen && sourcesSeen.length > 1
  return (
    <span
      className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${
        source === "OSV"
          ? "bg-emerald-950/70 text-emerald-400 border border-emerald-700/50"
          : source === "Qualys"
          ? "bg-purple-950/70 text-purple-400 border border-purple-700/50"
          : "bg-blue-950/70 text-blue-300 border border-blue-700/50"
      }`}
    >
      {isMulti ? `Merged: ${sourcesSeen.join(" + ")}` : source}
    </span>
  )
}

// ── Status banner ─────────────────────────────────────────────────────────────

function StatusBanner({ record }: { record: CommitScanRecord }) {
  const banners: Record<string, { icon: React.ReactNode; cls: string }> = {
    completed: {
      icon: <ShieldCheck className="w-5 h-5 text-green-400" />,
      cls: "bg-green-900/30 border border-green-700/50",
    },
    unconfigured: {
      icon: <Info className="w-5 h-5 text-blue-400" />,
      cls: "bg-blue-900/30 border border-blue-700/50",
    },
    no_matching_scan: {
      icon: <Search className="w-5 h-5 text-yellow-400" />,
      cls: "bg-yellow-900/30 border border-yellow-700/50",
    },
    sha_resolution_failed: {
      icon: <AlertCircle className="w-5 h-5 text-red-400" />,
      cls: "bg-red-900/30 border border-red-700/50",
    },
    api_error: {
      icon: <AlertCircle className="w-5 h-5 text-red-400" />,
      cls: "bg-red-900/30 border border-red-700/50",
    },
    qscanner_failed: {
      icon: <AlertCircle className="w-5 h-5 text-red-400" />,
      cls: "bg-red-900/30 border border-red-700/50",
    },
  }

  const config = banners[record.scan_status] || banners["unconfigured"]

  return (
    <div className={`rounded-lg p-4 flex items-start gap-3 ${config.cls}`}>
      <div className="mt-0.5 flex-shrink-0">{config.icon}</div>
      <div className="flex-1 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm font-medium text-white">
            Scan Status:{" "}
            <span className="font-mono text-xs bg-black/30 px-1.5 py-0.5 rounded">
              {record.scan_status}
            </span>
          </p>
          <span className="font-mono text-xs text-gray-300">
            Source: {record.evidence_source}
          </span>
          {record.coverage_status && (
            <span
              className={`px-2 py-0.5 rounded text-[11px] font-medium font-mono ${
                record.coverage_status === "complete"
                  ? "bg-emerald-950 text-emerald-300 border border-emerald-700/50"
                  : "bg-amber-950 text-amber-300 border border-amber-700/50"
              }`}
            >
              Coverage: {record.coverage_status === "complete" ? "Complete (Manifests + OSV)" : "Partial (Commit Index Only)"}
            </span>
          )}
          {record.osv_commit_query_status && (
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-blue-950 text-blue-300 border border-blue-700/50">
              OSV Commit Query: {record.osv_commit_query_status}
            </span>
          )}
        </div>

        {record.manifests_detected && record.manifests_detected.length > 0 && (
          <div className="flex items-center gap-1.5 text-xs text-gray-300">
            <span className="text-gray-400">Detected Manifests:</span>
            {record.manifests_detected.map((m, idx) => (
              <span
                key={idx}
                className="px-1.5 py-0.5 rounded bg-black/40 border border-gray-700 font-mono text-[11px] text-blue-300"
              >
                {m}
              </span>
            ))}
          </div>
        )}

        <p className="text-xs text-gray-300">{record.guidance}</p>
      </div>
    </div>
  )
}

// ── Three Commit Concepts Card ────────────────────────────────────────────────

function CommitConceptsCard({ f }: { f: UnifiedCommitFinding }) {
  return (
    <div className="mt-3 bg-black/40 border border-white/10 rounded-lg p-3 grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
      <div>
        <span className="text-gray-400 block font-semibold mb-0.5">1. Scanned Commit</span>
        <span className="font-mono text-blue-300 break-all">
          {f.scanned_commit_sha ? f.scanned_commit_sha.slice(0, 10) + "…" : "—"}
        </span>
      </div>
      <div>
        <span className="text-gray-400 block font-semibold mb-0.5">2. Introduced In Commit</span>
        <span className="font-mono text-amber-300">
          {f.dependency_introduction_sha ? f.dependency_introduction_sha.slice(0, 10) + "…" : "—"}
        </span>
        <span className="text-[10px] text-gray-500 block">({f.introduction_attribution_status})</span>
      </div>
      <div>
        <span className="text-gray-400 block font-semibold mb-0.5">3. Upstream Fix Commit</span>
        <span className="font-mono text-emerald-300">
          {f.upstream_fix_commit_sha ? f.upstream_fix_commit_sha.slice(0, 10) + "…" : "—"}
        </span>
        <span className="text-[10px] text-gray-500 block">({f.upstream_fix_attribution_status})</span>
      </div>
    </div>
  )
}

// ── Finding Row ───────────────────────────────────────────────────────────────

function FindingRow({ f }: { f: UnifiedCommitFinding }) {
  return (
    <div className="bg-[#111827] border border-gray-700/50 rounded-lg p-4 space-y-2 hover:border-blue-500/30 transition-all">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            {f.finding_type === "package" ? (
              <Box className="w-4 h-4 text-blue-400" />
            ) : (
              <FileCode className="w-4 h-4 text-purple-400" />
            )}
            <p className="text-sm font-semibold text-white">
              {f.package_name || "Code-Level Finding"}
              {f.package_version && (
                <span className="text-gray-400 font-mono text-xs ml-1">@{f.package_version}</span>
              )}
              {f.ecosystem && <span className="ml-2 text-xs text-gray-400">({f.ecosystem})</span>}
            </p>
          </div>
          {f.summary && <p className="text-xs text-gray-300 mt-1">{f.summary}</p>}
        </div>
        <div className="flex items-center gap-2">
          <SourceBadge source={f.source} sourcesSeen={f.sources_seen} />
          <SeverityBadge severity={f.severity} />
        </div>
      </div>

      {/* Advisory & Signal Badges */}
      <div className="flex flex-wrap items-center gap-3 text-xs text-gray-400 pt-1">
        {f.vulnerability_id && (
          <span className="font-mono text-blue-400 font-semibold">{f.vulnerability_id}</span>
        )}
        {f.cve_id && (
          <span className="flex items-center gap-1 font-mono text-red-300">
            <Hash className="w-3 h-3" />
            {f.cve_id}
          </span>
        )}
        {f.fixed_version && (
          <span className="text-emerald-400 font-mono">Fix: ≥ {f.fixed_version}</span>
        )}
        {f.in_kev && (
          <span className="px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-700/60 font-semibold">
            CISA KEV
          </span>
        )}
        {f.references && f.references.length > 0 && (
          <a
            href={f.references[0]}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 ml-auto"
          >
            <ExternalLink className="w-3 h-3" /> Evidence
          </a>
        )}
      </div>

      {/* 3 Distinct Commit Concepts attribution */}
      <CommitConceptsCard f={f} />
    </div>
  )
}

// ── Commit Comparison View ────────────────────────────────────────────────────

function CommitComparisonView({
  comparison,
  onClose,
}: {
  comparison: CommitComparisonRecord
  onClose: () => void
}) {
  return (
    <div className="bg-[#0d1117] border border-blue-500/40 rounded-xl p-6 space-y-6">
      <div className="flex items-center justify-between border-b border-gray-700 pb-4">
        <div className="flex items-center gap-2.5">
          <GitCompare className="w-5 h-5 text-blue-400" />
          <h3 className="text-base font-bold text-white">
            Commit Comparison & Remediation Diff
          </h3>
        </div>
        <Button variant="ghost" size="sm" onClick={onClose} className="text-gray-400 hover:text-white">
          Close Diff
        </Button>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
        <div className="p-3 bg-black/40 rounded-lg border border-gray-800">
          <span className="text-xs text-gray-500 block">Base Commit Total</span>
          <span className="text-xl font-bold text-white">{comparison.base_total_findings}</span>
        </div>
        <div className="p-3 bg-black/40 rounded-lg border border-gray-800">
          <span className="text-xs text-gray-500 block">Target Commit Total</span>
          <span className="text-xl font-bold text-white">{comparison.target_total_findings}</span>
        </div>
        <div className="p-3 bg-emerald-950/30 rounded-lg border border-emerald-700/40">
          <span className="text-xs text-emerald-400 block">Remediated / Not Detected</span>
          <span className="text-xl font-bold text-emerald-300">{comparison.resolved_count}</span>
        </div>
        <div className="p-3 bg-red-950/30 rounded-lg border border-red-700/40">
          <span className="text-xs text-red-400 block">Newly Observed</span>
          <span className="text-xl font-bold text-red-300">{comparison.newly_observed_count}</span>
        </div>
      </div>

      {/* Diff Table */}
      <div className="space-y-3">
        <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
          Individual Finding Deltas
        </h4>
        <div className="space-y-2">
          {comparison.finding_diffs.map((d, i) => (
            <div
              key={i}
              className={`p-3 rounded-lg border flex items-center justify-between text-xs ${
                d.diff_status === "not_detected_in_target"
                  ? "bg-emerald-950/20 border-emerald-700/40"
                  : d.diff_status === "newly_observed"
                  ? "bg-red-950/20 border-red-700/40"
                  : "bg-gray-900/40 border-gray-800"
              }`}
            >
              <div>
                <span className="font-semibold text-white mr-2">
                  {d.finding.package_name || d.finding.vulnerability_id}
                </span>
                <span className="text-gray-400">{d.reason}</span>
              </div>
              <span
                className={`px-2 py-0.5 rounded font-mono font-bold uppercase text-[10px] ${
                  d.diff_status === "not_detected_in_target"
                    ? "bg-emerald-900 text-emerald-300"
                    : d.diff_status === "newly_observed"
                    ? "bg-red-900 text-red-300"
                    : "bg-gray-800 text-gray-400"
                }`}
              >
                {d.diff_status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Main Page Component ───────────────────────────────────────────────────────

export default function CommitScanPage() {
  const navigate = useNavigate()

  const [activeTab, setActiveTab] = useState<"scan" | "compare">("scan")
  const [repoUrl, setRepoUrl] = useState("")
  const [revision, setRevision] = useState("HEAD")
  const [localPath, setLocalPath] = useState("")
  const [projectName, setProjectName] = useState("")

  const [loading, setLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [record, setRecord] = useState<CommitScanRecord | null>(null)
  const [recentScans, setRecentScans] = useState<Array<Record<string, any>>>([])

  // Comparison State
  const [compareBaseId, setCompareBaseId] = useState("")
  const [compareTargetId, setCompareTargetId] = useState("")
  const [comparisonResult, setComparisonResult] = useState<CommitComparisonRecord | null>(null)
  const [comparing, setComparing] = useState(false)

  // Filter state
  const [filterSource, setFilterSource] = useState<string>("ALL")
  const [filterType, setFilterType] = useState<string>("ALL")

  useEffect(() => {
    listCommitScans(20).then(setRecentScans).catch(() => {})
  }, [])

  const handleScan = async () => {
    if (!repoUrl.trim()) {
      setErrorMsg("Please enter a repository URL.")
      return
    }
    setLoading(true)
    setErrorMsg(null)
    setRecord(null)
    setComparisonResult(null)
    try {
      const result = await startCommitScan({
        repository_url: repoUrl.trim(),
        revision: revision.trim() || "HEAD",
        local_repo_path: localPath.trim() || undefined,
        project_name: projectName.trim() || undefined,
      })
      setRecord(result)
      listCommitScans(20).then(setRecentScans).catch(() => {})
    } catch (err: any) {
      setErrorMsg(err?.message || "Commit scan failed. Check backend logs.")
    } finally {
      setLoading(false)
    }
  }

  const handleRunComparison = async () => {
    if (!compareBaseId || !compareTargetId) {
      setErrorMsg("Select two scan jobs to compare.")
      return
    }
    setComparing(true)
    setErrorMsg(null)
    try {
      const res = await compareCommitScans(compareBaseId, compareTargetId)
      setComparisonResult(res)
    } catch (err: any) {
      setErrorMsg(err?.message || "Comparison failed.")
    } finally {
      setComparing(false)
    }
  }

  const filteredFindings = record?.findings.filter((f) => {
    if (filterSource !== "ALL" && f.source !== filterSource) return false
    if (filterType !== "ALL" && f.finding_type !== filterType) return false
    return true
  }) || []

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-10 space-y-8">
      {/* Page Header */}
      <div>
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2.5 bg-blue-600/20 rounded-xl border border-blue-500/30">
            <GitCommit className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">
              Commit-Based Vulnerability Analysis
            </h1>
            <p className="text-sm text-gray-400">
              Query OSV commit indexes and Qualys SCA with explicit 3-concept commit attribution
            </p>
          </div>
        </div>

        {/* Tab switcher */}
        <div className="flex gap-2 border-b border-gray-800 pt-4">
          <button
            onClick={() => setActiveTab("scan")}
            className={`px-4 py-2 text-xs font-semibold rounded-t-lg border-b-2 transition-all ${
              activeTab === "scan"
                ? "border-blue-500 text-white bg-blue-600/10"
                : "border-transparent text-gray-400 hover:text-white"
            }`}
          >
            <GitCommit className="w-3.5 h-3.5 inline mr-1.5" />
            Analyze Commit
          </button>
          <button
            onClick={() => setActiveTab("compare")}
            className={`px-4 py-2 text-xs font-semibold rounded-t-lg border-b-2 transition-all ${
              activeTab === "compare"
                ? "border-blue-500 text-white bg-blue-600/10"
                : "border-transparent text-gray-400 hover:text-white"
            }`}
          >
            <GitCompare className="w-3.5 h-3.5 inline mr-1.5" />
            Compare Commits
          </button>
        </div>
      </div>

      {activeTab === "scan" ? (
        <>
          {/* Form */}
          <div className="bg-[#0d1117] border border-gray-700/50 rounded-xl p-6 space-y-5">
            <div>
              <Label className="text-sm text-gray-300 mb-1.5 block">
                <Link2 className="w-3.5 h-3.5 inline mr-1.5 text-gray-400" />
                Repository URL <span className="text-red-400">*</span>
              </Label>
              <Input
                type="url"
                placeholder="https://github.com/myorg/myapp.git"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                className="bg-[#070b14] border-gray-600 text-white placeholder:text-gray-500 font-mono text-sm"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <Label className="text-sm text-gray-300 mb-1.5 block">
                  <GitCommit className="w-3.5 h-3.5 inline mr-1.5 text-gray-400" />
                  Revision / Commit SHA
                </Label>
                <Input
                  placeholder="HEAD, main, v1.0.0, or 40-char SHA"
                  value={revision}
                  onChange={(e) => setRevision(e.target.value)}
                  className="bg-[#070b14] border-gray-600 text-white placeholder:text-gray-500 font-mono text-sm"
                />
              </div>
              <div>
                <Label className="text-sm text-gray-300 mb-1.5 block">
                  Project Name <span className="text-gray-500">(optional)</span>
                </Label>
                <Input
                  placeholder="e.g. payment-service"
                  value={projectName}
                  onChange={(e) => setProjectName(e.target.value)}
                  className="bg-[#070b14] border-gray-600 text-white placeholder:text-gray-500 text-sm"
                />
              </div>
            </div>

            <div>
              <Label className="text-sm text-gray-300 mb-1.5 block">
                <Terminal className="w-3.5 h-3.5 inline mr-1.5 text-gray-400" />
                Local Repository Path <span className="text-gray-500">(optional)</span>
              </Label>
              <Input
                placeholder="/home/user/projects/myapp"
                value={localPath}
                onChange={(e) => setLocalPath(e.target.value)}
                className="bg-[#070b14] border-gray-600 text-white placeholder:text-gray-500 font-mono text-sm"
              />
              <p className="text-xs text-gray-500 mt-1">
                Remote repositories are automatically resolved via{" "}
                <code className="bg-black/30 px-1 rounded">git ls-remote</code>.
              </p>
            </div>

            {errorMsg && (
              <div className="flex items-start gap-2 bg-red-900/30 border border-red-700/50 rounded-lg p-3 text-sm text-red-300">
                <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                {errorMsg}
              </div>
            )}

            <Button
              onClick={handleScan}
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2.5"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Resolving Commit & Querying OSV / Qualys…
                </>
              ) : (
                <>
                  <GitCommit className="w-4 h-4 mr-2" />
                  Run Commit Analysis
                </>
              )}
            </Button>
          </div>

          {/* Results Display */}
          {record && (
            <div className="space-y-6">
              <StatusBanner record={record} />

              {/* Full SCA Workflow Deep Integration Banner */}
              {record.analysis_id && (
                <div className="bg-gradient-to-r from-blue-950/60 via-[#0d1527] to-indigo-950/60 border border-blue-500/40 rounded-xl p-5 space-y-4 shadow-xl">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-400/40 text-[11px] font-mono font-bold tracking-wide uppercase">
                          Full SCA Engine Linked
                        </span>
                        <span className="text-xs text-gray-400 font-mono">
                          Analysis ID: <code className="text-blue-300">{record.analysis_id.slice(0, 8)}…</code>
                        </span>
                      </div>
                      <h3 className="text-base font-bold text-white mt-1">
                        Explore Full Downstream Analysis & Remediation
                      </h3>
                      <p className="text-xs text-gray-300">
                        This commit is fully populated across the dependency propagation graph, CSB-03 risk scores, patch planner, simulation, and audit export.
                      </p>
                    </div>
                    <Button
                      onClick={() => navigate(`/dashboard/${record.analysis_id}`)}
                      className="bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs px-4 py-2 flex items-center gap-1.5 shadow-lg shadow-blue-900/30 whitespace-nowrap"
                    >
                      <LayoutDashboard className="w-3.5 h-3.5" />
                      Open Full Dashboard
                      <ArrowRight className="w-3.5 h-3.5 ml-1" />
                    </Button>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-1 border-t border-white/10">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate(`/graph/${record.analysis_id}`)}
                      className="bg-black/30 border-gray-700/80 hover:bg-blue-900/30 hover:border-blue-500/60 text-gray-200 text-xs flex items-center justify-center gap-1.5 py-2 h-auto"
                    >
                      <Network className="w-3.5 h-3.5 text-blue-400" />
                      <span>Propagation Graph</span>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate(`/findings/${record.analysis_id}`)}
                      className="bg-black/30 border-gray-700/80 hover:bg-blue-900/30 hover:border-blue-500/60 text-gray-200 text-xs flex items-center justify-center gap-1.5 py-2 h-auto"
                    >
                      <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                      <span>All Findings</span>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate(`/patch-plan/${record.analysis_id}`)}
                      className="bg-black/30 border-gray-700/80 hover:bg-blue-900/30 hover:border-blue-500/60 text-gray-200 text-xs flex items-center justify-center gap-1.5 py-2 h-auto"
                    >
                      <Wrench className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Patch Plan</span>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate(`/simulate/${record.analysis_id}`)}
                      className="bg-black/30 border-gray-700/80 hover:bg-blue-900/30 hover:border-blue-500/60 text-gray-200 text-xs flex items-center justify-center gap-1.5 py-2 h-auto"
                    >
                      <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                      <span>Simulation</span>
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => navigate(`/report/${record.analysis_id}`)}
                      className="bg-black/30 border-gray-700/80 hover:bg-blue-900/30 hover:border-blue-500/60 text-gray-200 text-xs flex items-center justify-center gap-1.5 py-2 h-auto col-span-2 sm:col-span-1"
                    >
                      <FileText className="w-3.5 h-3.5 text-purple-400" />
                      <span>Audit Report</span>
                    </Button>
                  </div>
                </div>
              )}

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                <div className="bg-[#0d1117] border border-gray-700/50 rounded-lg p-3">
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Resolved SHA</p>
                  <p className="text-xs font-mono text-blue-300 break-all" title={record.resolved_sha || ""}>
                    {record.resolved_sha ? record.resolved_sha.slice(0, 10) + "…" : "—"}
                  </p>
                </div>
                <div className="bg-[#0d1117] border border-gray-700/50 rounded-lg p-3">
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Total Findings</p>
                  <p className="text-2xl font-bold text-white">{record.findings_count}</p>
                </div>
                <div className="bg-[#0d1117] border border-gray-700/50 rounded-lg p-3">
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Manifest SCA</p>
                  <p className="text-2xl font-bold text-emerald-400">{record.osv_manifest_findings_count ?? 0}</p>
                </div>
                <div className="bg-[#0d1117] border border-gray-700/50 rounded-lg p-3">
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Commit Advisories</p>
                  <p className="text-2xl font-bold text-blue-400">{record.osv_findings_count}</p>
                </div>
                <div className="bg-[#0d1117] border border-gray-700/50 rounded-lg p-3">
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Qualys SCA</p>
                  <p className="text-2xl font-bold text-purple-400">{record.qualys_findings_count}</p>
                </div>
              </div>

              {/* Filters */}
              {record.findings.length > 0 && (
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 pb-3">
                  <h3 className="text-sm font-semibold text-white">
                    Unified Findings ({filteredFindings.length})
                  </h3>
                  <div className="flex items-center gap-2">
                    <select
                      value={filterSource}
                      onChange={(e) => setFilterSource(e.target.value)}
                      className="bg-[#070b14] border border-gray-700 text-xs rounded px-2 py-1 text-white"
                    >
                      <option value="ALL">All Sources</option>
                      <option value="OSV">OSV</option>
                      <option value="Qualys">Qualys</option>
                    </select>
                    <select
                      value={filterType}
                      onChange={(e) => setFilterType(e.target.value)}
                      className="bg-[#070b14] border border-gray-700 text-xs rounded px-2 py-1 text-white"
                    >
                      <option value="ALL">All Finding Types</option>
                      <option value="package">Package Level</option>
                      <option value="code_level">Code Level</option>
                    </select>
                  </div>
                </div>
              )}

              {/* Findings List */}
              <div className="space-y-3">
                {filteredFindings.map((f) => (
                  <FindingRow key={f.finding_id} f={f} />
                ))}
              </div>

              {record.findings.length === 0 && record.scan_status !== "sha_resolution_failed" && (
                <div className="bg-[#0d1117] border border-gray-700/60 rounded-xl p-6 text-center space-y-2">
                  <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-2" />
                  <h4 className="text-sm font-semibold text-white">
                    {record.manifests_detected && record.manifests_detected.length > 0
                      ? "Zero Known Vulnerabilities in Scanned Revision & Manifests"
                      : "Zero Direct Advisories for Commit SHA"}
                  </h4>
                  <p className="text-xs text-gray-400 max-w-lg mx-auto">
                    {record.manifests_detected && record.manifests_detected.length > 0
                      ? `Scanned commit ${record.resolved_sha?.slice(0, 10)} and evaluated ${record.manifests_detected.join(", ")}. No known advisories matched the installed dependencies.`
                      : `OSV direct commit query returned no entries for SHA ${record.resolved_sha?.slice(0, 10)}. No supported dependency manifests were detected at this revision.`}
                  </p>
                </div>
              )}
            </div>
          )}
        </>
      ) : (
        /* Comparison View */
        <div className="space-y-6">
          <div className="bg-[#0d1117] border border-gray-700/50 rounded-xl p-6 space-y-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <GitCompare className="w-4 h-4 text-blue-400" /> Compare Two Scanned Commits
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Baseline Scan Job</Label>
                <select
                  value={compareBaseId}
                  onChange={(e) => setCompareBaseId(e.target.value)}
                  className="w-full bg-[#070b14] border border-gray-700 rounded-lg p-2 text-xs text-white"
                >
                  <option value="">Select baseline scan…</option>
                  {recentScans.map((s) => (
                    <option key={s.job_id} value={s.job_id}>
                      {s.repository_url} (SHA: {(s.resolved_sha || s.revision || "").slice(0, 8)})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Target Scan Job</Label>
                <select
                  value={compareTargetId}
                  onChange={(e) => setCompareTargetId(e.target.value)}
                  className="w-full bg-[#070b14] border border-gray-700 rounded-lg p-2 text-xs text-white"
                >
                  <option value="">Select target scan…</option>
                  {recentScans.map((s) => (
                    <option key={s.job_id} value={s.job_id}>
                      {s.repository_url} (SHA: {(s.resolved_sha || s.revision || "").slice(0, 8)})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <Button
              onClick={handleRunComparison}
              disabled={comparing || !compareBaseId || !compareTargetId}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2"
            >
              {comparing ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Comparing Commits…
                </>
              ) : (
                <>
                  <GitCompare className="w-4 h-4 mr-2" /> Run Comparison
                </>
              )}
            </Button>
          </div>

          {comparisonResult && (
            <CommitComparisonView
              comparison={comparisonResult}
              onClose={() => setComparisonResult(null)}
            />
          )}
        </div>
      )}
    </div>
  )
}
