import React, { useEffect, useState } from "react"
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom"
import KineticGrid from "@/components/ui/kinetic-grid"
import AppNavbar from "@/components/layout/AppNavbar"
import AnalyzePage from "@/pages/AnalyzePage"
import DashboardPage from "@/pages/DashboardPage"
import GraphPage from "@/pages/GraphPage"
import FindingsPage from "@/pages/FindingsPage"
import PatchPlanPage from "@/pages/PatchPlanPage"
import SimulatePage from "@/pages/SimulatePage"
import ReportPage from "@/pages/ReportPage"
import CommitScanPage from "@/pages/CommitScanPage"
import { getAnalysis } from "@/lib/api"

function AppContent() {
  const location = useLocation()
  const [currentAnalysisId, setCurrentAnalysisId] = useState<string | null>(null)
  const [projectName, setProjectName] = useState<string | null>(null)

  // Extract analysisId from path if available: e.g. /dashboard/abc-123, /graph/abc-123
  useEffect(() => {
    const segments = location.pathname.split("/").filter(Boolean)
    if (segments.length >= 2) {
      const routePrefixes = ["dashboard", "graph", "findings", "patch-plan", "simulate", "report"]
      if (routePrefixes.includes(segments[0])) {
        const id = segments[1]
        if (id && id !== currentAnalysisId) {
          setCurrentAnalysisId(id)
          getAnalysis(id)
            .then((rec) => setProjectName(rec.project_name))
            .catch(() => {})
        }
      }
    }
  }, [location.pathname, currentAnalysisId])

  return (
    <div className="min-h-screen text-white font-sans selection:bg-blue-600 selection:text-white flex flex-col bg-[#070b14]">
      <AppNavbar currentAnalysisId={currentAnalysisId} projectName={projectName} />
      <main className="flex-1">
        <Routes>
          <Route path="/" element={<AnalyzePage />} />
          <Route path="/analyze" element={<AnalyzePage />} />
          <Route path="/commit-scan" element={<CommitScanPage />} />
          <Route path="/dashboard/:analysisId" element={<DashboardPage />} />
          <Route path="/graph/:analysisId" element={<GraphPage />} />
          <Route path="/findings/:analysisId" element={<FindingsPage />} />
          <Route path="/patch-plan/:analysisId" element={<PatchPlanPage />} />
          <Route path="/simulate/:analysisId" element={<SimulatePage />} />
          <Route path="/report/:analysisId" element={<ReportPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <KineticGrid globalColor="default">
        <AppContent />
      </KineticGrid>
    </BrowserRouter>
  )
}
