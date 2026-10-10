import React, { useEffect, useState } from "react"
import { useParams, Link } from "react-router-dom"
import {
  FileText,
  Download,
  Copy,
  Check,
  Printer,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Layers,
  Sparkles,
  Calendar,
  Lock
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { getAnalysis, API_BASE, AnalysisRecord } from "@/lib/api"

export default function ReportPage() {
  const { analysisId } = useParams<{ analysisId: string }>()
  const [record, setRecord] = useState<AnalysisRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [markdownText, setMarkdownText] = useState<string>("")
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!analysisId) return
    setLoading(true)
    setError(null)
    getAnalysis(analysisId)
      .then((data) => setRecord(data))
      .catch((err) => setError(err.message || "Failed to load audit report"))
      .finally(() => setLoading(false))

    // Fetch markdown text for copy
    fetch(`${API_BASE}/api/analysis/${analysisId}/report/markdown`)
      .then((res) => res.text())
      .then((txt) => setMarkdownText(txt))
      .catch(() => {})
  }, [analysisId])

  const copyMarkdown = () => {
    if (markdownText) {
      navigator.clipboard.writeText(markdownText)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  if (loading) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
          <p className="text-sm text-white/60">Compiling executive audit report...</p>
        </div>
      </div>
    )
  }

  if (error || !record) {
    return (
      <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center">
        <div className="p-6 rounded-2xl border border-rose-500/30 bg-rose-950/20 text-center">
          <p className="text-sm text-rose-300">{error || "Report not found."}</p>
        </div>
      </div>
    )
  }

  const { summary, findings, patch_plan } = record

  return (
    <div className="container mx-auto px-4 py-8 max-w-5xl space-y-8">
      {/* Action Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-white/10 gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileText className="h-6 w-6 text-blue-400" />
            Supply-Chain Security Audit Report
          </h1>
          <p className="text-xs text-white/50 mt-1 font-mono">
            Analysis ID: <span className="text-blue-300">{record.analysis_id}</span> • Formatted for compliance & executive sign-off
          </p>
        </div>

        {/* Export & Download Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={copyMarkdown}
            className="border-white/10 text-xs text-white/80 hover:text-white bg-black/40"
          >
            {copied ? <Check className="h-3.5 w-3.5 mr-1.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 mr-1.5" />}
            {copied ? "Copied!" : "Copy Markdown"}
          </Button>

          <a
            href={`${API_BASE}/api/analysis/${record.analysis_id}/report/markdown`}
            download={`patchorder-report-${record.analysis_id.slice(0, 8)}.md`}
          >
            <Button size="sm" variant="outline" className="border-blue-500/30 text-blue-300 hover:text-white bg-blue-950/30 text-xs">
              <Download className="h-3.5 w-3.5 mr-1.5 text-blue-400" />
              Download .MD
            </Button>
          </a>

          <a
            href={`${API_BASE}/api/analysis/${record.analysis_id}/report/json`}
            download={`patchorder-report-${record.analysis_id.slice(0, 8)}.json`}
          >
            <Button size="sm" className="bg-blue-600 hover:bg-blue-500 text-white text-xs">
              <Download className="h-3.5 w-3.5 mr-1.5" />
              Download .JSON
            </Button>
          </a>
        </div>
      </div>

      {/* Styled Document Sheet */}
      <div className="p-8 sm:p-12 rounded-2xl border border-white/10 bg-[#0c111e] text-white space-y-8 shadow-2xl">
        {/* Document Header Banner */}
        <div className="flex flex-col sm:flex-row justify-between items-start pb-6 border-b border-white/10 gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-blue-400 mb-1">
              <Lock className="h-3.5 w-3.5" />
              <span>PATCHORDER SUPPLY-CHAIN ATTESTATION</span>
            </div>
            <h2 className="text-3xl font-extrabold tracking-tight text-white font-mono">
              {record.project_name}
            </h2>
            <div className="text-xs text-white/60 mt-1 font-mono">
              Manifest: {record.manifest_type} ({record.resolution_status})
            </div>
          </div>

          <div className="text-left sm:text-right font-mono text-xs text-white/50 space-y-0.5">
            <div>Date: <strong className="text-white">{new Date(record.created_at).toLocaleDateString()}</strong></div>
            <div>Environment: <strong className="text-blue-300">{record.environment}</strong></div>
            <div>Exposure: <strong className="text-cyan-300">{record.exposure}</strong></div>
            <div>Criticality: <strong className="text-amber-300">{record.criticality}</strong></div>
          </div>
        </div>

        {/* 1. Executive Summary */}
        <div className="space-y-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-blue-400">
            1. Executive Summary
          </h3>
          <p className="text-xs text-white/80 leading-relaxed">
            This report presents an automated software composition analysis (SCA) and reachability evaluation for the repository{" "}
            <strong className="text-white font-mono">{record.project_name}</strong>. A total of{" "}
            <strong className="text-white font-mono">{summary.total_components} packages</strong> ({summary.direct_components} direct,{" "}
            {summary.transitive_components} transitive) were resolved and cross-referenced with OSV.dev advisories, CISA Known Exploited Vulnerabilities (KEV),
            and FIRST EPSS probability scores.
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 font-mono text-xs">
            <div className="p-3 rounded-xl bg-black/40 border border-white/5">
              <span className="text-white/40 block text-[10px]">Total Vulnerabilities</span>
              <strong className="text-rose-400 text-lg">{summary.total_vulnerabilities}</strong>
            </div>
            <div className="p-3 rounded-xl bg-black/40 border border-white/5">
              <span className="text-white/40 block text-[10px]">CISA KEV Exploited</span>
              <strong className="text-amber-400 text-lg">{summary.kev_matches}</strong>
            </div>
            <div className="p-3 rounded-xl bg-black/40 border border-white/5">
              <span className="text-white/40 block text-[10px]">Direct vs Transitive</span>
              <strong className="text-white text-lg">{summary.direct_vulnerabilities} / {summary.transitive_vulnerabilities}</strong>
            </div>
            <div className="p-3 rounded-xl bg-black/40 border border-white/5">
              <span className="text-white/40 block text-[10px]">Remediation Actions</span>
              <strong className="text-emerald-400 text-lg">{patch_plan.length}</strong>
            </div>
          </div>
        </div>

        {/* 2. Priority Patch Sequence */}
        <div className="space-y-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-blue-400">
            2. Sequenced Remediation Plan
          </h3>
          <p className="text-xs text-white/70">
            The following updates are ordered by marginal risk reduction per unit of change cost. Applying actions in this sequence minimizes breaking changes while removing maximum exploit surface.
          </p>

          <div className="rounded-xl border border-white/10 overflow-hidden bg-black/40">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-white/[0.03] border-b border-white/10 text-white/50">
                <tr>
                  <th className="py-2.5 px-3">Rank</th>
                  <th className="py-2.5 px-3">Package</th>
                  <th className="py-2.5 px-3">Upgrade Path</th>
                  <th className="py-2.5 px-3">Risk Removed</th>
                  <th className="py-2.5 px-3">Change Cost</th>
                  <th className="py-2.5 px-3">Marginal Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {patch_plan.map((p) => (
                  <tr key={p.rank} className="hover:bg-white/[0.02]">
                    <td className="py-2.5 px-3 font-bold text-white">#{p.rank}</td>
                    <td className="py-2.5 px-3 text-white font-medium">{p.package}</td>
                    <td className="py-2.5 px-3 text-emerald-400">{p.current_version} → {p.target_version}</td>
                    <td className="py-2.5 px-3 text-white/80">{p.estimated_risk_removed.toFixed(1)}</td>
                    <td className="py-2.5 px-3 text-white/80">{p.estimated_change_cost.toFixed(2)}</td>
                    <td className="py-2.5 px-3 text-emerald-400 font-bold">{p.marginal_value.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* 3. Comprehensive Vulnerability Findings Table */}
        <div className="space-y-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-blue-400">
            3. Vulnerability Register
          </h3>

          <div className="rounded-xl border border-white/10 overflow-hidden bg-black/40">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-white/[0.03] border-b border-white/10 text-white/50">
                <tr>
                  <th className="py-2.5 px-3">Component</th>
                  <th className="py-2.5 px-3">Position</th>
                  <th className="py-2.5 px-3">Advisory ID</th>
                  <th className="py-2.5 px-3">Tier</th>
                  <th className="py-2.5 px-3">KEV</th>
                  <th className="py-2.5 px-3">EPSS</th>
                  <th className="py-2.5 px-3">Fixed Version</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {findings.map((f, i) => (
                  <tr key={i} className="hover:bg-white/[0.02]">
                    <td className="py-2 px-3 text-white">{f.component.name}@{f.component.version}</td>
                    <td className="py-2 px-3 text-white/60">{f.is_direct ? "Direct" : `Transitive (d=${f.depth})`}</td>
                    <td className="py-2 px-3 text-blue-400 font-semibold">{f.vulnerability.id}</td>
                    <td className="py-2 px-3 font-bold text-rose-400">{f.priority_tier}</td>
                    <td className="py-2 px-3">{f.vulnerability.in_kev ? "YES" : "No"}</td>
                    <td className="py-2 px-3 text-white/70">{f.vulnerability.epss_score ? `${(f.vulnerability.epss_score * 100).toFixed(1)}%` : "—"}</td>
                    <td className="py-2 px-3 text-emerald-400">{f.vulnerability.first_fixed_version || "None"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer Attestation */}
        <div className="pt-6 border-t border-white/10 text-[11px] text-white/40 font-mono flex flex-col sm:flex-row justify-between gap-2">
          <div>Generated by PatchOrder SCA Engine v2.0</div>
          <div>Advisory sources: OSV.dev, CISA KEV, FIRST EPSS</div>
        </div>
      </div>
    </div>
  )
}

