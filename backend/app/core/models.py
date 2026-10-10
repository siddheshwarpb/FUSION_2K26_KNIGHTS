from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime

class DependencyScope(str):
    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    OPTIONAL = "optional"
    PEER = "peer"
    UNKNOWN = "unknown"

class ComponentNode(BaseModel):
    """Normalized software component coordinate adhering to Package URL (PURL)."""
    purl: str
    ecosystem: str
    name: str
    version: str
    is_direct: bool = False
    scope: str = DependencyScope.RUNTIME
    integrity: Optional[str] = None
    lockfile_path: Optional[str] = None
    direct_dependents_count: int = 0
    transitive_dependents_count: int = 0
    in_cycle: bool = False
    cycle_group_id: Optional[str] = None
    lookup_status: str = "verified_clean" # "verified_clean", "vulnerable", "failed", "unverified"
    is_synthetic: bool = False

class CVSSInfo(BaseModel):
    type: str
    score: str
    base_score: Optional[float] = None

class RangeEvent(BaseModel):
    introduced: Optional[str] = None
    fixed: Optional[str] = None
    last_affected: Optional[str] = None
    limit: Optional[str] = None

class AffectedRange(BaseModel):
    type: str
    events: List[RangeEvent] = []

class VulnerabilityRecord(BaseModel):
    id: str
    aliases: List[str] = []
    cve_id: Optional[str] = None
    summary: Optional[str] = None
    details: Optional[str] = None
    published: Optional[str] = None
    modified: Optional[str] = None
    cvss: List[CVSSInfo] = []
    affected_ranges: List[AffectedRange] = []
    first_fixed_version: Optional[str] = None
    references: List[Dict[str, str]] = []
    source_database: Optional[str] = None

    # Mapped vulnerability identity & CWE type
    cwe_id: Optional[str] = None
    vulnerability_name: Optional[str] = None
    vulnerability_type: Optional[str] = None

    # Enrichment signals
    in_kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_matched_cve: Optional[str] = None
    kev_evidence_source: Optional[str] = None
    kev_verified_at: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

class VulnerableFinding(BaseModel):
    component: ComponentNode
    vulnerability: VulnerabilityRecord
    is_direct: bool
    depth: int = 0
    propagation_paths_to_root: List[List[str]] = []
    root_dependents: List[str] = []
    
    # Priority & Explainability
    priority_score: float = 0.0
    priority_tier: str = "MEDIUM" # CRITICAL_URGENT, CRITICAL, HIGH, MEDIUM, LOW
    score_breakdown: Dict[str, Any] = {}
    confidence: float = 1.0
    reachability_state: str = "POTENTIALLY_REACHABLE" # REACHABLE, POTENTIALLY_REACHABLE, UNREACHABLE

class ScanSummary(BaseModel):
    manifest_type: str
    resolution_status: str = "resolved" # resolved | manifest_only
    total_components: int
    direct_components: int
    transitive_components: int
    vulnerable_components: int
    total_vulnerabilities: int
    direct_vulnerabilities: int
    transitive_vulnerabilities: int
    kev_matches: int = 0
    high_priority_findings: int = 0
    cache_hits: int
    cache_misses: int
    scan_duration_ms: float
    # Granular separation of counts
    advisory_records_count: int = 0
    distinct_vulnerabilities_count: int = 0
    affected_packages_count: int = 0
    affected_instances_count: int = 0
    cyclic_components_count: int = 0
    vulnerable_cycle_components: List[str] = []

class PatchRecommendation(BaseModel):
    rank: int
    package: str
    ecosystem: str
    current_version: str
    target_version: str
    findings_removed: List[str] = [] # list of vuln IDs removed
    findings_introduced: List[str] = []
    affected_project_roots: List[str] = []
    estimated_risk_removed: float = 0.0
    estimated_change_cost: float = 1.0
    marginal_value: float = 0.0 # risk_removed / change_cost
    why_now: str = ""
    cost_breakdown: Dict[str, Any] = {}
    remaining_risks: List[str] = []
    evidence_urls: List[str] = []

class CytoscapeElement(BaseModel):
    data: Dict[str, Any]
    classes: Optional[str] = ""

class CytoscapeGraph(BaseModel):
    nodes: List[CytoscapeElement]
    edges: List[CytoscapeElement]
    total_nodes: int
    total_edges: int
    affected_paths_count: int
    cyclic_nodes_count: int = 0
    cyclic_edges_count: int = 0

class SimulationPatchAction(BaseModel):
    package: str
    target_version: str

class SimulationRequest(BaseModel):
    patches: List[SimulationPatchAction]

class SimulationDiff(BaseModel):
    findings_before_count: int
    findings_after_count: int
    resolved_findings_count: int
    resolved_vuln_ids: List[str]
    risk_before: float
    risk_after: float
    risk_reduction_pct: float
    affected_roots_before: int
    affected_roots_after: int
    new_top_patch: Optional[PatchRecommendation] = None
    remaining_high_priority_count: int

class SimulationResponse(BaseModel):
    analysis_id: str
    is_simulated: bool = True
    applied_patches: List[SimulationPatchAction]
    diff: SimulationDiff
    simulated_graph: CytoscapeGraph
    remaining_findings: List[VulnerableFinding]

class AnalysisRecord(BaseModel):
    analysis_id: str
    project_name: str
    environment: str = "production"
    exposure: str = "internet-facing"
    criticality: str = "high"
    manifest_type: str
    resolution_status: str = "resolved" # "resolved" or "manifest_only"
    created_at: str
    summary: ScanSummary
    findings: List[VulnerableFinding]
    components: List[ComponentNode] = []
    patch_plan: List[PatchRecommendation] = []
    graph_data: Optional[CytoscapeGraph] = None
    provenance: Dict[str, Any] = {}
    repository_url: Optional[str] = None
    commit_sha: Optional[str] = None
    manifests_detected: List[str] = []
    coverage_status: Optional[str] = None
    analysis_method: str = "manifest-upload"


class ScanResponse(BaseModel):
    project_name: Optional[str] = None
    manifest_type: str
    scanned_at: str
    summary: ScanSummary
    findings: List[VulnerableFinding]
    components: List[ComponentNode] = []
    provenance: Dict[str, Any] = {}

class NormalizedFinding(BaseModel):
    package: str
    ecosystem: str
    installed_version: str
    vulnerability_id: str
    summary: Optional[str] = None
    affected: bool = True
    fixed_version: Optional[str] = None
    aliases: List[str] = []

class NormalizedScanResponse(BaseModel):
    project: str
    scan_status: str # "completed" | "failed"
    packages_scanned: int
    vulnerable_packages: int
    findings: List[NormalizedFinding] = []
    error: Optional[str] = None


# ── Commit-Based Scan Models ───────────────────────────────────────────────────

class CommitScanRequest(BaseModel):
    """Request to run a commit-based vulnerability scan."""
    repository_url: str = Field(
        ...,
        description="HTTPS URL of the Git repository (e.g. https://github.com/org/repo)",
        json_schema_extra={"example": "https://github.com/myorg/myapp"}
    )
    revision: Optional[str] = Field(
        default="HEAD",
        description="Branch name, tag, or commit SHA to scan",
        json_schema_extra={"example": "main"}
    )
    local_repo_path: Optional[str] = Field(
        default=None,
        description="Absolute path to a local clone of the repo (used to resolve SHA and run QScanner)"
    )
    project_name: Optional[str] = Field(
        default=None,
        description="Human-readable project name for display purposes"
    )


class QualysFinding(BaseModel):
    """A single vulnerability finding returned by Qualys SCA."""
    source: str = "Qualys"                      # Always 'Qualys' for this model
    analysis_method: str = "commit-based"        # Always 'commit-based'
    repository_url: str = ""
    commit_sha: str = ""
    qualys_vuln_id: str = ""
    cve_id: Optional[str] = None
    package_name: str = ""
    package_version: str = ""
    ecosystem: str = "npm"
    severity: str = "UNKNOWN"
    summary: str = ""
    fixed_version: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict, exclude=True)  # raw API response, excluded from serialization by default


class CommitScanStatus(str):
    """Possible scan_status values for a CommitScanRecord."""
    UNCONFIGURED = "unconfigured"
    COMPLETED = "completed"
    SHA_RESOLUTION_FAILED = "sha_resolution_failed"
    NO_MATCHING_SCAN = "no_matching_scan"
    API_ERROR = "api_error"
    QSCANNER_FAILED = "qscanner_failed"


class UnifiedCommitFinding(BaseModel):
    """A unified vulnerability finding from OSV or Qualys with commit attribution."""
    finding_id: str
    source: str = "OSV"                          # "OSV" | "Qualys" | "Multiple"
    sources_seen: List[str] = []
    analysis_method: str = "commit-based"
    repository_url: str = ""
    
    # ── Three Distinct Commit Concepts ──────────────────────────────────────────
    scanned_commit_sha: str = ""                # Concept 1: Exact repository state analyzed
    dependency_introduction_sha: Optional[str] = None # Concept 2: Commit where vulnerable version was introduced (inferred)
    introduction_attribution_status: str = "unverified" # "verified" | "inferred" | "unknown"
    upstream_fix_commit_sha: Optional[str] = None     # Concept 3: Upstream commit that patched the advisory
    upstream_fix_attribution_status: str = "unknown"  # "verified_advisory" | "unknown"
    
    # Package & Vulnerability Coordinates
    finding_type: str = "package"               # "package" | "code_level"
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    ecosystem: Optional[str] = "npm"
    vulnerability_id: str = ""
    cve_id: Optional[str] = None
    aliases: List[str] = []
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    summary: Optional[str] = None
    details: Optional[str] = None
    fixed_version: Optional[str] = None
    references: List[str] = []
    
    # Threat Signals (only when independently verified)
    in_kev: bool = False
    epss_score: Optional[float] = None
    
    # Graph linking & propagation
    affected_purl: Optional[str] = None
    propagation_depth: int = 0
    
    raw_evidence: Dict[str, Any] = Field(default_factory=dict, exclude=True)


class CommitComparisonFindingDiff(BaseModel):
    finding: UnifiedCommitFinding
    diff_status: str # "observed_both" | "newly_observed" | "not_detected_in_target" | "verified_remediated"
    reason: str = ""


class CommitComparisonRecord(BaseModel):
    """Result of comparing two scanned repository commits."""
    repository_url: str
    base_commit_sha: str
    target_commit_sha: str
    compared_at: str
    
    base_total_findings: int
    target_total_findings: int
    
    newly_observed_count: int
    resolved_count: int
    unresolved_count: int
    
    finding_diffs: List[CommitComparisonFindingDiff] = []
    summary: Dict[str, Any] = {}


class CommitScanRecord(BaseModel):
    """Full record of a commit-based scan job."""
    job_id: str
    analysis_id: Optional[str] = None
    repository_url: str
    revision: str = "HEAD"
    resolved_sha: Optional[str] = None
    sha_resolution_error: Optional[str] = None
    scan_status: str = "unconfigured"  # see CommitScanStatus
    evidence_source: str = "none"      # 'OSV', 'Qualys-API', 'QScanner-CLI', 'OSV+Qualys', or 'none'
    qualys_scan_id: Optional[str] = None
    qualys_configured: bool = False
    
    # Unified & segregated findings
    findings: List[UnifiedCommitFinding] = []
    findings_count: int = 0
    package_findings_count: int = 0
    code_findings_count: int = 0
    
    # Granular statuses & coverage metadata
    osv_commit_query_status: str = "pending" # "success_findings" | "success_empty" | "error" | "skipped"
    manifests_detected: List[str] = []
    manifest_scan_status: str = "none" # "completed" | "no_manifests" | "error"
    coverage_status: str = "complete" # "complete" | "partial_no_manifest" | "error"
    
    # Source breakdown
    osv_findings_count: int = 0
    osv_manifest_findings_count: int = 0
    qualys_findings_count: int = 0
    
    scanned_at: str = ""
    project_name: Optional[str] = None
    guidance: str = Field(
        default="",
        description="Human-readable explanation of the scan_status and coverage"
    )

    def model_post_init(self, __context: Any) -> None:
        if self.guidance:
            return
        if self.scan_status == "sha_resolution_failed":
            self.guidance = f"Could not resolve revision to a commit SHA: {self.sha_resolution_error}."
        elif self.findings_count > 0:
            self.guidance = f"Identified {self.findings_count} finding(s) across {self.evidence_source}."
        elif self.manifests_detected:
            self.guidance = f"Scanned commit SHA {self.resolved_sha[:10] if self.resolved_sha else ''} and {', '.join(self.manifests_detected)}: zero known applicable vulnerabilities found at scan time."
        else:
            self.guidance = f"OSV commit query returned no direct commit-level advisories for SHA {self.resolved_sha[:10] if self.resolved_sha else ''}. No supported dependency manifests were detected at this revision."

