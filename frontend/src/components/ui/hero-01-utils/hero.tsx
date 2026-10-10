import React, { useState, useRef } from "react"
import { Button } from "@/components/ui/button"
import { UploadCloud, CheckCircle2, AlertTriangle, ShieldCheck, Database, GitBranch, ArrowRight, Loader2 } from "lucide-react"

export interface AvatarList {
  image: string
}

interface HeroSectionProps {
  avatarList?: AvatarList[]
  onScanResult?: (result: any) => void
}

export default function HeroSection({ avatarList, onScanResult }: HeroSectionProps) {
  const [loading, setLoading] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)
  const [scanStats, setScanStats] = useState<any>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileUpload = async (file: File) => {
    setLoading(true)
    setErrorMsg(null)
    setFileName(file.name)

    const formData = new FormData()
    formData.append("file", file)
    formData.append("project_name", file.name)

    try {
      const res = await fetch("http://localhost:8000/api/scan/file", {
        method: "POST",
        body: formData,
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || "Scan request failed")
      }

      const data = await res.json()
      setScanStats(data.summary)
      if (onScanResult) onScanResult(data)
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to scan manifest")
    } finally {
      setLoading(false)
    }
  }

  const loadDemo = async (type: "npm" | "python") => {
    setLoading(true)
    setErrorMsg(null)
    const demoPayload = type === "npm" ? {
      name: "demo-web-app",
      lockfileVersion: 2,
      packages: {
        "": { dependencies: { express: "^4.16.0" } },
        "node_modules/express": {
          version: "4.16.0",
          dependencies: { lodash: "4.17.15", qs: "6.5.1" }
        },
        "node_modules/lodash": { version: "4.17.15" },
        "node_modules/qs": { version: "6.5.1" }
      }
    } : null

    try {
      let res;
      if (type === "npm") {
        setFileName("package-lock.json (Sample)")
        res = await fetch("http://localhost:8000/api/scan/raw", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            content: JSON.stringify(demoPayload),
            filename: "package-lock.json",
            project_name: "demo-npm-app"
          })
        })
      } else {
        setFileName("requirements.txt (Sample)")
        const reqContent = "jinja2==2.11.2\nurllib3==1.25.8\nrequests==2.22.0"
        res = await fetch("http://localhost:8000/api/scan/raw", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            content: reqContent,
            filename: "requirements.txt",
            project_name: "demo-python-app"
          })
        })
      }

      if (!res.ok) throw new Error("Sample scan failed")
      const data = await res.json()
      setScanStats(data.summary)
      if (onScanResult) onScanResult(data)
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to load sample")
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="relative pt-20 pb-16 md:pt-28 md:pb-24">
      <div className="container mx-auto px-4 max-w-5xl text-center">
        {/* Pill Badge */}
        <div className="inline-flex items-center gap-2 rounded-full border border-blue-500/30 bg-blue-950/40 px-3.5 py-1 text-xs font-medium text-blue-300 backdrop-blur-sm mb-6">
          <span className="flex h-2 w-2 rounded-full bg-blue-400 animate-ping"></span>
          <span>Open Source Vulnerability (OSV) Verification Engine</span>
        </div>

        {/* Heading */}
        <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight text-white mb-6 leading-tight">
          Software Supply-Chain <br className="hidden sm:inline" />
          <span className="bg-gradient-to-r from-blue-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">
            Vulnerability Propagation
          </span>
        </h1>

        {/* Description */}
        <p className="max-w-2xl mx-auto text-base sm:text-lg text-white/70 mb-10 leading-relaxed">
          Resolve direct and transitive dependency graphs, verify CVEs and GHSAs against the live OSV database in batch, and trace every propagation path to the project root.
        </p>

        {/* Upload Box / Action Card */}
        <div className="max-w-xl mx-auto p-6 rounded-2xl border border-white/10 bg-black/60 backdrop-blur-xl shadow-2xl">
          <input
            type="file"
            ref={fileInputRef}
            className="hidden"
            accept=".json,.txt,.lock"
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleFileUpload(e.target.files[0])
              }
            }}
          />

          <div
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-white/20 hover:border-blue-500/60 rounded-xl p-8 cursor-pointer transition-all hover:bg-white/[0.02] flex flex-col items-center justify-center gap-3"
          >
            {loading ? (
              <Loader2 className="h-10 w-10 text-blue-400 animate-spin" />
            ) : (
              <UploadCloud className="h-10 w-10 text-blue-400" />
            )}
            <div>
              <p className="text-sm font-semibold text-white">
                {loading ? "Scanning with OSV API..." : "Upload Lockfile or Manifest"}
              </p>
              <p className="text-xs text-white/50 mt-1">
                Supports package-lock.json (v1, v2, v3) & requirements.txt
              </p>
            </div>
            {fileName && (
              <span className="mt-2 text-xs font-mono text-blue-300 bg-blue-950/60 px-2.5 py-1 rounded-md border border-blue-800/40">
                {fileName}
              </span>
            )}
          </div>

          {/* Quick Demo Buttons */}
          <div className="mt-5 flex items-center justify-center gap-3">
            <span className="text-xs text-white/40">Quick Test:</span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => loadDemo("npm")}
              disabled={loading}
              className="text-xs border-white/10 hover:border-white/20 text-white/80"
            >
              npm fixture (lodash, express)
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => loadDemo("python")}
              disabled={loading}
              className="text-xs border-white/10 hover:border-white/20 text-white/80"
            >
              Python fixture (jinja2)
            </Button>
          </div>

          {errorMsg && (
            <div className="mt-4 p-3 rounded-lg bg-red-950/50 border border-red-800/50 text-red-300 text-xs text-left flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Scan summary metrics badge */}
          {scanStats && (
            <div className="mt-5 grid grid-cols-3 gap-3 border-t border-white/10 pt-4 text-left">
              <div className="rounded-lg bg-white/[0.03] p-2.5 border border-white/5">
                <span className="text-[11px] text-white/50 block">Components</span>
                <span className="text-lg font-bold text-white">{scanStats.total_components}</span>
                <span className="text-[10px] text-white/40 block">
                  {scanStats.direct_components} dir / {scanStats.transitive_components} trans
                </span>
              </div>
              <div className="rounded-lg bg-red-950/20 p-2.5 border border-red-900/30">
                <span className="text-[11px] text-red-300/70 block">Vulnerabilities</span>
                <span className="text-lg font-bold text-red-400">{scanStats.total_vulnerabilities}</span>
                <span className="text-[10px] text-red-300/50 block">
                  {scanStats.vulnerable_components} pkgs affected
                </span>
              </div>
              <div className="rounded-lg bg-blue-950/20 p-2.5 border border-blue-900/30">
                <span className="text-[11px] text-blue-300/70 block">Engine Latency</span>
                <span className="text-lg font-bold text-blue-400">{scanStats.scan_duration_ms} ms</span>
                <span className="text-[10px] text-blue-300/50 block">
                  Cache hits: {scanStats.cache_hits}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

