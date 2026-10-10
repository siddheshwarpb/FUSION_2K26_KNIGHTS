import React, { useState, useRef } from "react"
import { useNavigate } from "react-router-dom"
import {
  UploadCloud,
  FileCode2,
  Sparkles,
  AlertCircle,
  CheckCircle2,
  ArrowRight,
  ShieldCheck,
  Layers,
  Lock,
  FileText,
  Terminal,
  Loader2,
  Cpu,
  Database,
  Radio,
  ExternalLink
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { analyzeProjectFile, loadDemoScenario, AnalysisRecord } from "@/lib/api"

export default function AnalyzePage() {
  const navigate = useNavigate()
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Form State
  const [file, setFile] = useState<File | null>(null)
  const [isDragOver, setIsDragOver] = useState(false)
  const [projectName, setProjectName] = useState("")
  const [environment, setEnvironment] = useState("production")
  const [exposure, setExposure] = useState("internet-facing")
  const [criticality, setCriticality] = useState("high")

  // Execution State
  const [loading, setLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [currentStep, setCurrentStep] = useState<number>(0)
  const [demoLoading, setDemoLoading] = useState<string | null>(null)

  const steps = [
    { title: "Component Parsing", desc: "Extracting package coordinates & lockfile tree" },
    { title: "OSV Batch Query", desc: "Evaluating exact advisory versions against OSV database" },
    { title: "Threat Enrichment", desc: "Correlating CISA KEV exploitation & FIRST EPSS probabilities" },
    { title: "Propagation Graphing", desc: "Constructing DAG and classifying direct vs transitive reachability" },
    { title: "Remediation Queue", desc: "Calculating marginal risk reduction per unit of change cost" },
  ]

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(true)
  }

  const handleDragLeave = () => {
    setIsDragOver(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragOver(false)
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleSelectFile(e.dataTransfer.files[0])
    }
  }

  const handleSelectFile = (selectedFile: File) => {
    setErrorMsg(null)
    const validNames = ["package-lock.json", "package.json", "npm-shrinkwrap.json", "requirements.txt"]
    const name = selectedFile.name.toLowerCase()
    const isValid = validNames.includes(name) || name.endsWith(".json") || name.endsWith(".txt")

    if (!isValid) {
      setErrorMsg(`Unsupported file type: ${selectedFile.name}. Please upload package-lock.json, package.json, or requirements.txt`)
      return
    }

    setFile(selectedFile)
    if (!projectName) {
      // derive name
      setProjectName(selectedFile.name.replace(/\.[^/.]+$/, ""))
    }
  }

  const handleRunAnalysis = async () => {
    if (!file) {
      setErrorMsg("Please select or drop a lockfile or manifest.")
      return
    }

    setLoading(true)
    setErrorMsg(null)
    setCurrentStep(1)

    // Simulate progress updates across pipeline
    const timer1 = setTimeout(() => setCurrentStep(2), 500)
    const timer2 = setTimeout(() => setCurrentStep(3), 1200)
    const timer3 = setTimeout(() => setCurrentStep(4), 1800)

    try {
      const record = await analyzeProjectFile(
        file,
        projectName || file.name,
        environment,
        exposure,
        criticality
      )
      setCurrentStep(5)
      setTimeout(() => {
        navigate(`/dashboard/${record.analysis_id}`)
      }, 400)
    } catch (e: any) {
      clearTimeout(timer1)
      clearTimeout(timer2)
      clearTimeout(timer3)
      setErrorMsg(e.message || "Failed to analyze manifest")
      setLoading(false)
      setCurrentStep(0)
    }
  }

  const handleLoadDemo = async (scenarioId: string) => {
    setDemoLoading(scenarioId)
    setErrorMsg(null)
    try {
      const record = await loadDemoScenario(scenarioId)
      navigate(`/dashboard/${record.analysis_id}`)
    } catch (e: any) {
      setErrorMsg(e.message || "Failed to load demo scenario")
    } finally {
      setDemoLoading(null)
    }
  }

  return (
    <div className="min-h-[calc(100vh-4rem)] container mx-auto px-4 py-8 max-w-5xl">
      {/* Hero Header */}
      <div className="text-center max-w-2xl mx-auto space-y-3 mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-xs text-blue-400 font-medium">
          <Radio className="h-3.5 w-3.5 animate-pulse text-blue-400" />
          Software Supply-Chain Vulnerability Propagation Engine
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
          Explainable Vulnerability Graph & <br className="hidden sm:inline" />
          <span className="bg-gradient-to-r from-blue-400 via-indigo-300 to-cyan-400 bg-clip-text text-transparent">
            Ranked Patch Order
          </span>
        </h1>
        <p className="text-sm text-white/60">
          Upload your project lockfile to trace direct vs. transitive blast radius, correlate CISA KEV exploitation,
          and compute marginal risk reduction per unit of change cost.
        </p>
      </div>

      {/* Main Grid: Upload & Context Setup */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Column: Dropzone & File Card */}
        <div className="lg:col-span-7 space-y-5">
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all flex flex-col items-center justify-center min-h-[260px] ${
              isDragOver
                ? "border-blue-400 bg-blue-950/40 scale-[1.01]"
                : file
                ? "border-blue-500/50 bg-blue-950/20"
                : "border-white/15 bg-black/40 hover:border-white/30 hover:bg-white/[0.02]"
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => e.target.files?.[0] && handleSelectFile(e.target.files[0])}
              className="hidden"
              accept=".json,.txt"
            />

            <div className={`p-4 rounded-2xl border mb-3 transition-all ${
              file
                ? "bg-blue-600/20 border-blue-500/40 text-blue-400"
                : "bg-white/5 border-white/10 text-white/60"
            }`}>
              <UploadCloud className="h-8 w-8" />
            </div>

            {file ? (
              <div className="space-y-1">
                <div className="text-sm font-semibold text-white flex items-center justify-center gap-2">
                  <FileCode2 className="h-4 w-4 text-blue-400" />
                  {file.name}
                </div>
                <div className="text-xs text-white/50">
                  {(file.size / 1024).toFixed(1)} KB • Ready to analyze
                </div>
                {file.name === "package.json" && (
                  <div className="mt-2 text-[11px] text-amber-300/90 bg-amber-500/10 border border-amber-500/20 px-2.5 py-1 rounded-md max-w-sm">
                    ⚠️ Manifest-only scan: Direct version ranges only. Transitive dependencies require package-lock.json.
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-1">
                <div className="text-sm font-medium text-white">
                  Drop your lockfile here, or <span className="text-blue-400 underline underline-offset-2">browse</span>
                </div>
                <div className="text-xs text-white/40">
                  Supports package-lock.json, npm-shrinkwrap.json, requirements.txt, or package.json
                </div>
              </div>
            )}
          </div>

          {/* Supported Formats Info */}
          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 rounded-xl border border-white/10 bg-black/30">
              <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                <Lock className="h-3.5 w-3.5 text-blue-400" />
                <span>npm lockfile</span>
              </div>
              <div className="text-[11px] text-white/50 mt-1">v1, v2, v3 trees + dev scope</div>
            </div>
            <div className="p-3 rounded-xl border border-white/10 bg-black/30">
              <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                <FileText className="h-3.5 w-3.5 text-emerald-400" />
                <span>PyPI reqs.txt</span>
              </div>
              <div className="text-[11px] text-white/50 mt-1">Pinned exact version specs</div>
            </div>
            <div className="p-3 rounded-xl border border-white/10 bg-black/30">
              <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                <Terminal className="h-3.5 w-3.5 text-purple-400" />
                <span>package.json</span>
              </div>
              <div className="text-[11px] text-white/50 mt-1">Direct manifest fallback</div>
            </div>
          </div>

          {/* Hackathon 3-State Remediation Showcase */}
          <div className="p-4 rounded-2xl border border-blue-500/30 bg-gradient-to-r from-blue-950/40 via-purple-950/20 to-slate-900/60 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-xs font-semibold text-blue-300 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                Judge Showcase: 3-State Remediation Pipeline
              </div>
              <span className="text-[10px] text-emerald-400/90 font-mono">Live npm Verified</span>
            </div>
            <p className="text-xs text-white/60">
              Demonstrates <strong>State 1 (Vulnerable Baseline)</strong> &rarr; <strong>State 2 (Remediation Queue & Simulation)</strong> &rarr; <strong>State 3 (Rescanned Clean Lockfile)</strong> backed by real OSV and npm audit evidence:
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <button
                type="button"
                disabled={!!demoLoading || loading}
                onClick={() => handleLoadDemo("hackathon-baseline")}
                className="text-left p-3.5 rounded-xl border border-rose-500/30 bg-rose-950/20 hover:bg-rose-950/40 transition-all group"
              >
                <div className="text-xs font-bold text-rose-300 group-hover:text-rose-200 flex items-center justify-between">
                  <span>State 1: Vulnerable Baseline</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300">34 Findings</span>
                </div>
                <div className="text-[11px] text-white/60 mt-1">
                  15 vulnerable packages, Lodash CISA KEV match, Express & Mocha transitive trees.
                </div>
              </button>

              <button
                type="button"
                disabled={!!demoLoading || loading}
                onClick={() => handleLoadDemo("hackathon-remediated")}
                className="text-left p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-950/20 hover:bg-emerald-950/40 transition-all group"
              >
                <div className="text-xs font-bold text-emerald-300 group-hover:text-emerald-200 flex items-center justify-between">
                  <span>State 3: Rescanned Final</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 font-bold">0 Vulnerabilities</span>
                </div>
                <div className="text-[11px] text-white/60 mt-1">
                  Post-remediation lockfile audited with npm audit and rescanned live. 100% clean.
                </div>
              </button>
            </div>
          </div>

          {/* Quick Demo Scenarios */}
          <div className="p-4 rounded-2xl border border-white/10 bg-black/30 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-xs font-semibold text-white/80 uppercase tracking-wider flex items-center gap-1.5">
                <Sparkles className="h-3.5 w-3.5 text-amber-400" />
                Additional Scenarios
              </div>
              <span className="text-[10px] text-white/40">Instant evaluation</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <button
                type="button"
                disabled={!!demoLoading || loading}
                onClick={() => handleLoadDemo("ecommerce-checkout")}
                className="text-left p-3 rounded-xl border border-white/10 bg-white/[0.02] hover:bg-blue-950/30 hover:border-blue-500/30 transition-all group"
              >
                <div className="text-xs font-semibold text-white group-hover:text-blue-300">
                  E-Commerce npm
                </div>
                <div className="text-[10px] text-white/50 mt-0.5">
                  Express, lodash KEV, qs, mocha dev
                </div>
              </button>

              <button
                type="button"
                disabled={!!demoLoading || loading}
                onClick={() => handleLoadDemo("python-backend")}
                className="text-left p-3 rounded-xl border border-white/10 bg-white/[0.02] hover:bg-blue-950/30 hover:border-blue-500/30 transition-all group"
              >
                <div className="text-xs font-semibold text-white group-hover:text-blue-300">
                  Python Backend
                </div>
                <div className="text-[10px] text-white/50 mt-0.5">
                  Jinja2 KEV, urllib3, requests
                </div>
              </button>

              <button
                type="button"
                disabled={!!demoLoading || loading}
                onClick={() => handleLoadDemo("clean-inventory")}
                className="text-left p-3 rounded-xl border border-white/10 bg-white/[0.02] hover:bg-blue-950/30 hover:border-blue-500/30 transition-all group"
              >
                <div className="text-xs font-semibold text-white group-hover:text-blue-300">
                  Clean PyPI
                </div>
                <div className="text-[10px] text-white/50 mt-0.5">
                  0 vulnerabilities benchmark
                </div>
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Deployment Context & Launch */}
        <div className="lg:col-span-5 space-y-5">
          <div className="p-6 rounded-2xl border border-white/10 bg-[#0d1322] space-y-4 shadow-xl">
            <div className="border-b border-white/10 pb-3">
              <h3 className="font-semibold text-white text-sm">Deployment & Risk Context</h3>
              <p className="text-xs text-white/50">
                Contextual parameters influence CSB-03 severity multipliers and policy gate thresholds.
              </p>
            </div>

            {/* Project Name */}
            <div className="space-y-1.5">
              <Label className="text-xs text-white/80">Project / Service Name</Label>
              <Input
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="e.g. payment-gateway-service"
                className="bg-black/40 border-white/10 text-white text-xs h-9 focus:border-blue-500"
              />
            </div>

            {/* Environment */}
            <div className="space-y-1.5">
              <Label className="text-xs text-white/80">Target Environment</Label>
              <select
                value={environment}
                onChange={(e) => setEnvironment(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-lg text-white text-xs h-9 px-3 focus:outline-none focus:border-blue-500"
              >
                <option value="production">Production (High urgency)</option>
                <option value="staging">Staging / Pre-prod</option>
                <option value="development">Development / Internal sandbox</option>
              </select>
            </div>

            {/* Exposure */}
            <div className="space-y-1.5">
              <Label className="text-xs text-white/80">Network Exposure</Label>
              <select
                value={exposure}
                onChange={(e) => setExposure(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-lg text-white text-xs h-9 px-3 focus:outline-none focus:border-blue-500"
              >
                <option value="internet-facing">Internet-Facing (Public endpoints)</option>
                <option value="internal">Internal VPC Only</option>
                <option value="isolated">Air-Gapped / Isolated Worker</option>
              </select>
            </div>

            {/* Business Criticality */}
            <div className="space-y-1.5">
              <Label className="text-xs text-white/80">Business Criticality</Label>
              <select
                value={criticality}
                onChange={(e) => setCriticality(e.target.value)}
                className="w-full bg-black/40 border border-white/10 rounded-lg text-white text-xs h-9 px-3 focus:outline-none focus:border-blue-500"
              >
                <option value="critical">Tier 0 — Mission Critical / Financial</option>
                <option value="high">Tier 1 — High (Core Customer Services)</option>
                <option value="medium">Tier 2 — Medium (Internal Tools)</option>
                <option value="low">Tier 3 — Low</option>
              </select>
            </div>

            {/* Error Message */}
            {errorMsg && (
              <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/40 text-xs text-rose-300 flex items-start gap-2">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5 text-rose-400" />
                <span>{errorMsg}</span>
              </div>
            )}

            {/* Submit Button */}
            <Button
              onClick={handleRunAnalysis}
              disabled={loading || !file}
              className="w-full h-11 bg-blue-600 hover:bg-blue-500 text-white font-medium shadow-lg shadow-blue-600/25 mt-2"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Analyzing Supply-Chain...
                </>
              ) : (
                <>
                  <Cpu className="h-4 w-4 mr-2 text-blue-300" />
                  Launch Propagation Analysis
                  <ArrowRight className="h-4 w-4 ml-1.5" />
                </>
              )}
            </Button>
          </div>

          {/* Progress Timeline during analysis */}
          {loading && (
            <div className="p-5 rounded-2xl border border-blue-500/30 bg-blue-950/20 space-y-3 animate-in fade-in">
              <div className="text-xs font-semibold text-blue-300 uppercase tracking-wider flex items-center justify-between">
                <span>Analysis Pipeline In Progress</span>
                <span className="font-mono">{currentStep} / {steps.length}</span>
              </div>

              <div className="space-y-2">
                {steps.map((st, i) => {
                  const stepIndex = i + 1
                  const isDone = currentStep > stepIndex
                  const isCurrent = currentStep === stepIndex
                  return (
                    <div key={st.title} className="flex items-center gap-2.5 text-xs">
                      {isDone ? (
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                      ) : isCurrent ? (
                        <Loader2 className="h-3.5 w-3.5 text-blue-400 animate-spin shrink-0" />
                      ) : (
                        <div className="h-3.5 w-3.5 rounded-full border border-white/20 shrink-0" />
                      )}
                      <span className={isDone ? "text-white/60 line-through" : isCurrent ? "text-white font-medium" : "text-white/40"}>
                        {st.title}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

