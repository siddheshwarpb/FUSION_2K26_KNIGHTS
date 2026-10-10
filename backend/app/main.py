from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import json
import logging
from pathlib import Path

from app.services.vulnerability_engine import VulnerabilityEngine
from app.services.range_matcher import RangeMatcher
from app.services.simulation import SimulationEngine
from app.services.report_generator import ReportGenerator
from app.services.graph_cytoscape import build_cytoscape_graph
from app.core.models import (
    ScanResponse,
    NormalizedScanResponse,
    NormalizedFinding,
    AnalysisRecord,
    SimulationRequest,
    SimulationResponse
)
from app.core.config import qualys_config
from app.routers import commit_scan as commit_scan_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("patchorder")

app = FastAPI(
    title="PatchOrder — Vulnerability Propagation & Remediation API",
    description="Explainable dependency propagation graph, transparent CSB-03 risk prioritization, and counterfactual patch simulation engine",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = VulnerabilityEngine()

# ── Register commit-scan router and inject shared cache ────────────────────────
commit_scan_router.set_cache(engine.cache)
app.include_router(commit_scan_router.router)

# ── Request DTOs ───────────────────────────────────────────────────────────────

class SingleQueryRequest(BaseModel):
    package: str = Field(..., json_schema_extra={"example": "jinja2"})
    ecosystem: str = Field(..., json_schema_extra={"example": "PyPI"})
    version: str = Field(..., json_schema_extra={"example": "2.11.2"})

class BatchQueryItem(BaseModel):
    package: str = Field(..., json_schema_extra={"example": "lodash"})
    ecosystem: str = Field(..., json_schema_extra={"example": "npm"})
    version: str = Field(..., json_schema_extra={"example": "4.17.15"})

class BatchQueryRequest(BaseModel):
    queries: List[BatchQueryItem]

class NormalizedScanRequest(BaseModel):
    content: str
    filename: Optional[str] = "package.json"
    project: Optional[str] = "my-project"

class AnalyzeRequest(BaseModel):
    content: str
    filename: Optional[str] = "package-lock.json"
    project_name: Optional[str] = "payment-gateway"
    environment: Optional[str] = "production"
    exposure: Optional[str] = "internet-facing"
    criticality: Optional[str] = "high"

class RawScanRequest(BaseModel):
    content: str
    filename: Optional[str] = "package-lock.json"
    project_name: Optional[str] = "custom-project"

# ── System & DB Stats ──────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "PatchOrder SCA & Remediation Engine",
        "osv_status": "connected",
        "qualys_configured": qualys_config.is_configured(),
        "commit_scan_available": True,
    }

@app.get("/api/database/stats")
async def get_database_stats():
    with engine.cache._get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT count(*) as cnt FROM package_queries")
        pkg_cnt = c.fetchone()["cnt"]
        c.execute("SELECT count(*) as cnt FROM vulnerability_details")
        vuln_cnt = c.fetchone()["cnt"]
        c.execute("SELECT count(*) as cnt FROM scan_logs")
        scan_cnt = c.fetchone()["cnt"]
        c.execute("SELECT count(*) as cnt FROM analysis_store")
        analysis_cnt = c.fetchone()["cnt"]
        c.execute("""
            SELECT scan_id, project_name, manifest_type, total_components, vulnerable_components, duration_ms, scanned_at 
            FROM scan_logs ORDER BY scanned_at DESC LIMIT 10
        """)
        recent_scans = [dict(r) for r in c.fetchall()]

    return {
        "database_file": engine.cache.db_path,
        "tables": {
            "package_queries": {"count": pkg_cnt, "description": "Cached package coordinates and matching vuln IDs"},
            "vulnerability_details": {"count": vuln_cnt, "description": "Full OSV advisory records, CVE aliases, fixes"},
            "scan_logs": {"count": scan_cnt, "description": "Audit trail of all manifest scans"},
            "analysis_store": {"count": analysis_cnt, "description": "Stored multi-route analyses and graph states"}
        },
        "recent_scans": recent_scans
    }

# ── Step 1, 2, 3 Low-Level OSV Endpoints ────────────────────────────────────────

@app.post("/api/v1/query")
async def query_single_version(req: SingleQueryRequest):
    try:
        raw_res = await engine.osv_client.query_version(req.ecosystem, req.package, req.version)
        raw_vulns = raw_res.get("vulns", [])
        findings: List[NormalizedFinding] = []
        for v in raw_vulns:
            rec = RangeMatcher.extract_vulnerability_record(v, req.ecosystem, req.package)
            findings.append(NormalizedFinding(
                package=req.package,
                ecosystem=req.ecosystem,
                installed_version=req.version,
                vulnerability_id=rec.id,
                summary=rec.summary,
                affected=True,
                fixed_version=rec.first_fixed_version,
                aliases=rec.aliases
            ))

        return {
            "status": "completed",
            "package": req.package,
            "ecosystem": req.ecosystem,
            "version": req.version,
            "vulnerabilities_found": len(findings),
            "findings": findings
        }
    except Exception as e:
        logger.error(f"Single query failed: {str(e)}")
        raise HTTPException(status_code=502, detail=f"OSV query failed: {str(e)}")

@app.post("/api/v1/querybatch")
async def query_batch(req: BatchQueryRequest):
    try:
        query_tuples = [(item.ecosystem, item.package, item.version) for item in req.queries]
        results = await engine.osv_client.query_batch_direct(query_tuples)
        batch_output = []
        for idx, item in enumerate(req.queries):
            res_item = results[idx] if idx < len(results) else {}
            vulns = res_item.get("vulns", [])
            batch_output.append({
                "package": item.package,
                "ecosystem": item.ecosystem,
                "version": item.version,
                "vulnerability_count": len(vulns),
                "vuln_ids": [v.get("id") for v in vulns if "id" in v]
            })
        return {
            "status": "completed",
            "total_queried": len(req.queries),
            "results": batch_output
        }
    except Exception as e:
        logger.error(f"Batch query failed: {str(e)}")
        raise HTTPException(status_code=502, detail=f"OSV batch query failed: {str(e)}")

@app.get("/api/v1/vulns/{vuln_id}")
async def get_vuln_detail(vuln_id: str):
    try:
        detail = await engine.osv_client.get_vuln_detail_by_id(vuln_id)
        if not detail:
            raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id} not found in OSV")
        return detail
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Detail fetch failed for {vuln_id}: {str(e)}")
        raise HTTPException(status_code=502, detail=f"OSV lookup failed: {str(e)}")

@app.post("/api/v1/scan", response_model=NormalizedScanResponse)
async def scan_normalized_project(req: NormalizedScanRequest):
    return await engine.scan_normalized(
        content=req.content,
        filename=req.filename or "package.json",
        project_name=req.project
    )

# ── Route A: Primary Upload & Analyze Pipeline ──────────────────────────────────

@app.post("/api/analyze", response_model=AnalysisRecord)
async def analyze_project_endpoint(req: AnalyzeRequest):
    """
    Main analysis pipeline:
    Upload/Input -> Extract Deps -> OSV Batch Query -> Enrich KEV/EPSS ->
    Risk Score P(v) -> Greedy Remediation Plan -> Cytoscape Graph -> Store & Return
    """
    try:
        record = await engine.analyze_project(
            content=req.content,
            filename=req.filename or "package-lock.json",
            project_name=req.project_name or "my-project",
            environment=req.environment or "production",
            exposure=req.exposure or "internet-facing",
            criticality=req.criticality or "high"
        )
        return record
    except Exception as e:
        logger.error(f"Analyze error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze/file", response_model=AnalysisRecord)
@app.post("/api/analyze/upload", response_model=AnalysisRecord)
async def analyze_file_endpoint(
    file: UploadFile = File(...),
    project_name: Optional[str] = Form("my-project"),
    environment: Optional[str] = Form("production"),
    exposure: Optional[str] = Form("internet-facing"),
    criticality: Optional[str] = Form("high")
):
    try:
        raw_bytes = await file.read()
        content = raw_bytes.decode("utf-8")
        filename = file.filename or "package-lock.json"

        record = await engine.analyze_project(
            content=content,
            filename=filename,
            project_name=project_name or filename,
            environment=environment or "production",
            exposure=exposure or "internet-facing",
            criticality=criticality or "high"
        )
        return record
    except Exception as e:
        logger.error(f"File analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Analysis failed: {str(e)}")

# ── Route B, C, D, E: State Fetchers by analysisId ──────────────────────────────

@app.get("/api/analysis/{analysis_id}", response_model=AnalysisRecord)
async def get_analysis_by_id(analysis_id: str):
    data = engine.cache.get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    return AnalysisRecord(**data)

@app.get("/api/analysis/{analysis_id}/graph")
async def get_analysis_graph(analysis_id: str):
    data = engine.cache.get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    record = AnalysisRecord(**data)
    return record.graph_data

@app.get("/api/analysis/{analysis_id}/findings")
async def get_analysis_findings(
    analysis_id: str,
    tier: Optional[str] = Query(None),
    in_kev: Optional[bool] = Query(None),
    is_direct: Optional[bool] = Query(None)
):
    data = engine.cache.get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    record = AnalysisRecord(**data)
    results = record.findings

    if tier:
        results = [f for f in results if f.priority_tier.lower() == tier.lower()]
    if in_kev is not None:
        results = [f for f in results if f.vulnerability.in_kev == in_kev]
    if is_direct is not None:
        results = [f for f in results if f.is_direct == is_direct]

    return {
        "analysis_id": analysis_id,
        "total": len(results),
        "findings": results
    }

@app.get("/api/analysis/{analysis_id}/patch-plan")
async def get_analysis_patch_plan(analysis_id: str):
    data = engine.cache.get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    record = AnalysisRecord(**data)
    return {
        "analysis_id": analysis_id,
        "project_name": record.project_name,
        "patch_plan": record.patch_plan
    }

# ── Route F: Counterfactual Patch Simulation ───────────────────────────────────

@app.post("/api/analysis/{analysis_id}/simulate", response_model=SimulationResponse)
async def simulate_patch_endpoint(analysis_id: str, req: SimulationRequest):
    """
    Counterfactual patch simulator:
    Applies target upgrades without modifying repository, re-evaluates advisories,
    recalculates risk removed, and re-renders simulated Cytoscape graph.
    """
    data = engine.cache.get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    record = AnalysisRecord(**data)

    graph_edges = [
        (e.data["source"], e.data["target"], e.data.get("type", "DEPENDS_ON"))
        for e in record.graph_data.edges
    ] if record.graph_data else None
    cyclic_purls = {
        n.data["id"] for n in record.graph_data.nodes if n.data.get("in_cycle")
    } if record.graph_data else None
    cyclic_edges = {
        (e.data["source"], e.data["target"]) for e in record.graph_data.edges if e.data.get("is_cyclic")
    } if record.graph_data else None

    def cytoscape_builder(comps, remaining_finds, resolved_vuln_ids=None):
        return build_cytoscape_graph(
            components=comps,
            findings=remaining_finds,
            project_name=record.project_name,
            all_edges=graph_edges,
            resolved_vuln_ids=resolved_vuln_ids,
            cyclic_purls=cyclic_purls,
            cyclic_edges=cyclic_edges
        )


    sim_res = SimulationEngine.simulate_patches(
        analysis_id=analysis_id,
        current_findings=record.findings,
        all_components=record.components,
        applied_patches=req.patches,
        cytoscape_builder_fn=cytoscape_builder
    )
    return sim_res

# ── Route G: Report Exports ────────────────────────────────────────────────────

@app.get("/api/analysis/{analysis_id}/report/markdown")
async def export_markdown_report(analysis_id: str):
    data = engine.cache.get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    record = AnalysisRecord(**data)
    md_content = ReportGenerator.generate_markdown(record)
    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=patchorder-report-{analysis_id[:8]}.md"}
    )

@app.get("/api/analysis/{analysis_id}/report/json")
async def export_json_report(analysis_id: str):
    data = engine.cache.get_analysis(analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    record = AnalysisRecord(**data)
    json_content = ReportGenerator.generate_json(record)
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=patchorder-report-{analysis_id[:8]}.json"}
    )

# ── Demo Scenarios ─────────────────────────────────────────────────────────────

@app.get("/api/demo/{scenario_id}", response_model=AnalysisRecord)
async def get_demo_scenario(scenario_id: str):
    """
    Curated realistic scenarios containing direct, transitive, dev-only, and KEV findings:
    - 'ecommerce-checkout': npm lockfile (express, lodash with KEV, qs, mocha dev)
    - 'python-backend': requirements.txt (jinja2 with KEV, requests, urllib3)
    - 'clean-inventory': clean packages with 0 vulnerabilities
    """
    if scenario_id == "ecommerce-checkout":
        lock_json = json.dumps({
            "name": "ecommerce-checkout-service",
            "version": "2.4.0",
            "lockfileVersion": 2,
            "packages": {
                "": {
                    "name": "ecommerce-checkout-service",
                    "dependencies": {"express": "^4.16.0", "axios": "0.21.1"},
                    "devDependencies": {"mocha": "^8.0.0"}
                },
                "node_modules/express": {
                    "version": "4.16.0",
                    "dependencies": {"lodash": "4.17.15", "qs": "6.5.1"}
                },
                "node_modules/axios": {"version": "0.21.1"},
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/qs": {"version": "6.5.1"},
                "node_modules/mocha": {"version": "8.0.0", "dev": True}
            }
        })
        return await engine.analyze_project(
            content=lock_json,
            filename="package-lock.json",
            project_name="ecommerce-checkout-service",
            environment="production",
            exposure="internet-facing",
            criticality="high"
        )
    elif scenario_id == "python-backend":
        reqs = "jinja2==2.11.2\nurllib3==1.25.8\nrequests==2.22.0\npytest==6.2.5"
        return await engine.analyze_project(
            content=reqs,
            filename="requirements.txt",
            project_name="payment-processing-worker",
            environment="internal-production",
            exposure="internal",
            criticality="high"
        )
    elif scenario_id == "clean-inventory":
        clean = "colorama==0.4.6\nsix==1.16.0"
        return await engine.analyze_project(
            content=clean,
            filename="requirements.txt",
            project_name="audit-clean-service",
            environment="production",
            exposure="internal",
            criticality="low"
        )
    elif scenario_id == "hackathon-baseline":
        fixtures_dir = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
        fixture_path = fixtures_dir / "patchorder-vulnerable-baseline.package-lock.json"
        content = fixture_path.read_text(encoding="utf-8")
        return await engine.analyze_project(
            content=content,
            filename="package-lock.json",
            project_name="demo-service-baseline",
            environment="production",
            exposure="internet-facing",
            criticality="high"
        )
    elif scenario_id == "hackathon-remediated":
        fixtures_dir = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
        fixture_path = fixtures_dir / "patchorder-remediated-final.package-lock.json"
        content = fixture_path.read_text(encoding="utf-8")
        return await engine.analyze_project(
            content=content,
            filename="package-lock.json",
            project_name="demo-service-remediated",
            environment="production",
            exposure="internet-facing",
            criticality="high"
        )
    else:
        raise HTTPException(status_code=404, detail=f"Demo scenario '{scenario_id}' not found")

# Legacy compatibility
@app.post("/api/scan/raw", response_model=ScanResponse)
async def scan_raw_manifest(request: RawScanRequest):
    return await engine.scan_manifest(content=request.content, filename=request.filename, project_name=request.project_name)

@app.post("/api/scan/file", response_model=ScanResponse)
async def scan_uploaded_file(file: UploadFile = File(...), project_name: Optional[str] = Form(None)):
    raw = await file.read()
    return await engine.scan_manifest(content=raw.decode("utf-8"), filename=file.filename or "package-lock.json", project_name=project_name)

@app.get("/api/vulnerability/{vuln_id}")
async def get_vulnerability_detail_legacy(vuln_id: str):
    return await get_vuln_detail(vuln_id)
