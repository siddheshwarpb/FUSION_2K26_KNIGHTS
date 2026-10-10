import React, { useEffect, useRef } from "react"
import cytoscape, { Core, EventObject } from "cytoscape"
import { ZoomIn, ZoomOut, Maximize2, RotateCcw } from "lucide-react"
import { Button } from "@/components/ui/button"

interface CytoscapeGraphViewProps {
  graphData: {
    nodes: Array<{ data: any; classes?: string }>
    edges: Array<{ data: any; classes?: string }>
  }
  selectedNodeId?: string | null
  onSelectNode?: (nodeData: any) => void
  filterMode?: "blast-radius" | "project-view" | "full-inventory"
  showDev?: boolean
  showClean?: boolean
  kevOnly?: boolean
  searchQuery?: string
}

export default function CytoscapeGraphView({
  graphData,
  selectedNodeId,
  onSelectNode,
  filterMode = "full-inventory",
  showDev = true,
  showClean = true,
  kevOnly = false,
  searchQuery = "",
}: CytoscapeGraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)

  useEffect(() => {
    if (!containerRef.current || !graphData) return

    // Filter elements according to current control toggles
    const filteredNodes = graphData.nodes.filter((n) => {
      const d = n.data
      if (d.type === "root") return true
      if (!showDev && d.scope === "development") return false
      if (!showClean && !d.is_vulnerable && d.status !== "simulated_resolved") return false
      if (kevOnly && !d.in_kev && d.type !== "root") return false
      if (filterMode === "blast-radius" && !d.is_vulnerable && d.status !== "affected" && !d.is_affected && !d.in_cycle) return false
      return true
    })

    const visibleNodeIds = new Set(filteredNodes.map((n) => n.data.id))

    const filteredEdges = graphData.edges.filter((e) => {
      const srcVisible = visibleNodeIds.has(e.data.source)
      const tgtVisible = visibleNodeIds.has(e.data.target)
      if (!srcVisible || !tgtVisible) return false
      if (filterMode === "blast-radius" && !e.data.is_affected && !e.data.is_cyclic) return false
      return true
    })

    // Initialize Cytoscape
    const cy = cytoscape({
      container: containerRef.current,
      elements: [...filteredNodes, ...filteredEdges],
      boxSelectionEnabled: false,
      autounselectify: false,
      style: [
        // Base Node Style
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-family": "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
            "font-size": "11px",
            color: "#e2e8f0",
            "text-valign": "center",
            "text-halign": "center",
            "text-wrap": "ellipsis",
            "text-max-width": "120px",
            width: "135px",
            height: "44px",
            shape: "round-rectangle",
            "background-color": "#1e293b", // Slate 800
            "border-width": "1.5px",
            "border-color": "#334155", // Slate 700
            "transition-property": "background-color, border-color, width, height, border-width",
            "transition-duration": 0.2,
          },
        },
        // Root Node (non-vulnerable, affected if downstream issues exist)
        {
          selector: "node[type = 'root']",
          style: {
            shape: "round-rectangle",
            width: "160px",
            height: "48px",
            "font-size": "12px",
            "font-weight": "bold",
            "background-color": "#1e1b4b", // Deep indigo
            "border-color": "#6366f1", // Indigo 500
            "border-width": "2px",
            color: "#ffffff",
          },
        },
        // Vulnerable Node (Confirmed Red)
        {
          selector: "node[?is_vulnerable]",
          style: {
            "background-color": "#450a0a", // Red 950
            "border-color": "#ef4444", // Red 500
            "border-width": "2px",
            color: "#fecaca",
          },
        },
        // KEV Exploited Node (High Alert Amber/Red)
        {
          selector: "node[?in_kev]",
          style: {
            "background-color": "#7c2d12", // Orange 900
            "border-color": "#f97316", // Orange 500
            "border-width": "2.5px",
            color: "#ffedd5",
          },
        },
        // Cyclic Dependency Node (Dashed violet border indicator)
        {
          selector: "node[?in_cycle]",
          style: {
            "border-style": "dashed",
            "border-width": "2.5px",
            "border-color": "#818cf8", // Indigo 400
          },
        },
        // Both Cyclic and Vulnerable
        {
          selector: "node[?in_cycle][?is_vulnerable]",
          style: {
            "background-color": "#450a0a",
            "border-style": "dashed",
            "border-width": "2.5px",
            "border-color": "#f87171",
            color: "#fecaca",
          },
        },
        // Simulated Resolved Node (Green - clearly distinct from verified)
        {
          selector: "node[status = 'simulated_resolved']",
          style: {
            "background-color": "#064e3b", // Emerald 900
            "border-color": "#10b981", // Emerald 500
            "border-width": "2px",
            color: "#a7f3d0",
          },
        },
        // Selected Node Highlight (Cyan)
        {
          selector: "node:selected",
          style: {
            "border-color": "#06b6d4", // Cyan 500
            "border-width": "3px",
            "background-color": "#083344",
            color: "#cffafe",
          },
        },
        // Base Edge Style (Curved bezier for distinct opposing cyclic edges)
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#334155", // Slate 700
            "target-arrow-color": "#475569",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "control-point-step-size": 40,
            "arrow-scale": 0.8,
            "transition-property": "line-color, width, target-arrow-color",
            "transition-duration": 0.2,
          },
        },
        // Affected Propagation Path Edges (Crimson Red)
        {
          selector: "edge[?is_affected]",
          style: {
            width: 2.2,
            "line-color": "#dc2626", // Red 600
            "target-arrow-color": "#dc2626",
            "line-style": "solid",
          },
        },
        // Cyclic Dependency Edges (Dashed Indigo)
        {
          selector: "edge[?is_cyclic]",
          style: {
            width: 2.2,
            "line-style": "dashed",
            "line-color": "#818cf8", // Indigo 400
            "target-arrow-color": "#818cf8",
            "curve-style": "bezier",
            "control-point-step-size": 40,
          },
        },
        // Selected / Hover Edge Highlight
        {
          selector: "edge:selected",
          style: {
            width: 3.0,
            "line-color": "#06b6d4", // Cyan
            "target-arrow-color": "#06b6d4",
          },
        },
      ],
      layout: {
        name: "breadthfirst",
        directed: true,
        roots: ["root:project"],
        padding: 50,
        spacingFactor: 1.5,

        animate: true,
        animationDuration: 400,
      },
    })

    // Click handler
    cy.on("tap", "node", (evt: EventObject) => {
      const node = evt.target
      const data = node.data()
      if (onSelectNode) {
        onSelectNode(data)
      }
    })

    cyRef.current = cy

    return () => {
      cy.destroy()
    }
  }, [graphData, filterMode, showDev, showClean, kevOnly])

  // Handle Search Query & Selection updates
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    cy.nodes().unselect()

    if (selectedNodeId) {
      const selected = cy.$id(selectedNodeId)
      if (selected.length > 0) {
        selected.select()
      }
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      cy.nodes().forEach((node) => {
        const d = node.data()
        const match =
          (d.name && d.name.toLowerCase().includes(q)) ||
          (d.id && d.id.toLowerCase().includes(q)) ||
          (d.advisories && d.advisories.some((a: any) => (a.id && a.id.toLowerCase().includes(q)) || (a.cve && a.cve.toLowerCase().includes(q))))

        if (match) {
          node.addClass("search-hit")
          node.style("border-color", "#38bdf8")
          node.style("border-width", "3px")
        } else {
          node.removeClass("search-hit")
          node.removeStyle()
        }
      })
    }
  }, [selectedNodeId, searchQuery])

  const zoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25)
  const zoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8)
  const fit = () => cyRef.current?.fit(undefined, 40)
  const resetLayout = () => {
    cyRef.current?.layout({
      name: "breadthfirst",
      directed: true,
      roots: ["root:project"],
      padding: 50,
      spacingFactor: 1.4,
      animate: true,
      animationDuration: 300,
    }).run()
  }

  return (
    <div className="relative w-full h-full min-h-[550px] rounded-2xl border border-white/10 bg-[#0a0f1d] overflow-hidden shadow-2xl">
      {/* Background subtle grid pattern */}
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] pointer-events-none opacity-50" />

      {/* Floating Canvas Controls */}
      <div className="absolute top-4 left-4 z-10 flex items-center gap-1.5 p-1 rounded-xl bg-black/70 border border-white/10 backdrop-blur-md shadow-lg">
        <Button
          variant="ghost"
          size="icon"
          onClick={zoomIn}
          title="Zoom In"
          className="h-8 w-8 text-white/70 hover:text-white hover:bg-white/10"
        >
          <ZoomIn className="h-4 w-4" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          onClick={zoomOut}
          title="Zoom Out"
          className="h-8 w-8 text-white/70 hover:text-white hover:bg-white/10"
        >
          <ZoomOut className="h-4 w-4" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          onClick={fit}
          title="Fit to Screen"
          className="h-8 w-8 text-white/70 hover:text-white hover:bg-white/10"
        >
          <Maximize2 className="h-4 w-4" />
        </Button>
        <div className="h-4 w-[1px] bg-white/20 my-auto" />
        <Button
          variant="ghost"
          size="icon"
          onClick={resetLayout}
          title="Reset Hierarchical Layout"
          className="h-8 w-8 text-white/70 hover:text-white hover:bg-white/10"
        >
          <RotateCcw className="h-4 w-4" />
        </Button>
      </div>

      {/* Canvas Mount */}
      <div ref={containerRef} className="w-full h-full min-h-[550px]" />
    </div>
  )
}

