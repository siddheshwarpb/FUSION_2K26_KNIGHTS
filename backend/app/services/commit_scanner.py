"""Commit-based vulnerability scanner for PatchOrder.

Orchestrates:
  1. Git commit SHA resolution (subprocess, never shell=True).
  2. Qualys code scan lookup (or QScanner invocation if binary available).
  3. Normalisation of Qualys SCA findings into PatchOrder VulnerableFinding objects.
  4. Storage of the CommitScanRecord in the EvidenceCache.

This module never executes arbitrary shell commands from user input.
All subprocess calls use a list of arguments with shell=False.
"""
from __future__ import annotations

import os
import asyncio
import logging
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.models import (
    CommitScanRecord,
    CommitScanRequest,
    CommitScanStatus,
    QualysFinding,
    UnifiedCommitFinding,
    CommitComparisonRecord,
    CommitComparisonFindingDiff,
    VulnerabilityRecord,
    VulnerableFinding,
    ComponentNode,
    AnalysisRecord,
    ScanSummary,
)
from app.services.qualys_client import QualysClient, QualysAuthError, QualysAPIError
from app.services.osv_client import OsvClient
from app.services.range_matcher import RangeMatcher
from app.services.vulnerability_engine import VulnerabilityEngine
from app.services.remediation import RemediationEngine
from app.services.graph_cytoscape import build_cytoscape_graph
from app.core.config import qualys_config


logger = logging.getLogger("patchorder.commit_scanner")

# Maximum length of a validated commit SHA (full SHA-1 = 40 hex chars)
_SHA_RE = re.compile(r'^[0-9a-f]{7,40}$', re.IGNORECASE)
# Simple URL validation pattern (no shell metacharacters)
_URL_RE = re.compile(r'^https?://[\w.\-/:%@?=&+#~!,;]+$')


class CommitScanError(Exception):
    """Raised for unrecoverable commit-scan errors."""


def _validate_repo_url(url: str) -> str:
    """Raise CommitScanError if url is not a safe HTTPS URL."""
    if not _URL_RE.match(url):
        raise CommitScanError(
            f"Repository URL is not a valid HTTPS URL: {url!r}. "
            "Only HTTPS URLs are accepted."
        )
    return url


def _validate_revision(revision: str) -> str:
    """Raise CommitScanError if revision contains disallowed characters."""
    # Allow branch names, tags, and SHA refs (no shell metacharacters)
    safe = re.sub(r'[^\w./\-@]', '', revision)
    if safe != revision or not revision:
        raise CommitScanError(
            f"Revision contains disallowed characters: {revision!r}"
        )
    return revision


def resolve_commit_sha(repo_path: str, revision: str = "HEAD") -> str:
    """Resolve a revision to a full 40-character SHA-1 using 'git rev-parse'."""
    if not Path(repo_path).is_dir():
        raise CommitScanError(f"Repository path does not exist: {repo_path}")

    _validate_revision(revision)

    git_bin = shutil.which("git")
    if not git_bin:
        raise CommitScanError("git binary not found in PATH")

    args = [git_bin, "-C", repo_path, "rev-parse", "--verify", revision]
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            shell=False,  # MUST be False — never execute raw user input in a shell
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise CommitScanError("git rev-parse timed out")
    except OSError as exc:
        raise CommitScanError(f"Failed to run git: {exc}") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise CommitScanError(
            f"git rev-parse failed for revision {revision!r}: {stderr}"
        )

    sha = result.stdout.strip()
    if not re.match(r'^[0-9a-f]{40}$', sha):
        raise CommitScanError(f"Unexpected git rev-parse output: {sha!r}")
    return sha


def resolve_commit_sha_remote(repo_url: str, revision: str = "HEAD") -> str:
    """Resolve a remote repository revision/branch/tag/HEAD to a full 40-char commit SHA using git ls-remote."""
    _validate_repo_url(repo_url)
    _validate_revision(revision)

    git_bin = shutil.which("git")
    if not git_bin:
        raise CommitScanError("git binary not found in PATH")

    args = [git_bin, "ls-remote", repo_url, revision]
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise CommitScanError(f"git ls-remote timed out for {repo_url}")
    except OSError as exc:
        raise CommitScanError(f"Failed to run git: {exc}") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise CommitScanError(f"git ls-remote failed: {stderr}")

    stdout = result.stdout.strip()
    if not stdout:
        if revision != "HEAD":
            raise CommitScanError(f"Revision {revision!r} not found on remote repository")
        raise CommitScanError(f"No refs found on remote repository {repo_url}")

    first_line = stdout.splitlines()[0]
    sha = first_line.split()[0]
    if not re.match(r'^[0-9a-f]{40}$', sha):
        raise CommitScanError(f"Unexpected git ls-remote output: {first_line!r}")
    return sha


import tempfile
import contextlib

@contextlib.contextmanager
def checkout_repository_commit(repo_path_or_url: str, commit_sha: str):
    """
    Safely checks out the exact commit SHA into an isolated temporary directory.
    - If local repo path: creates a separate git worktree (does NOT mutate user's working branch).
    - If remote URL: performs a shallow clone of the exact commit SHA.
    Yields the temporary target directory path, and cleanly tears it down on exit.
    """
    git_bin = shutil.which("git")
    if not git_bin:
        raise CommitScanError("git binary not found in PATH")

    temp_dir = tempfile.mkdtemp(prefix="patchorder-commit-scan-")
    is_local = Path(repo_path_or_url).is_dir()
    
    try:
        if is_local:
            # Create a detached worktree for the exact SHA
            worktree_path = Path(temp_dir) / "worktree"
            cmd = [git_bin, "-C", repo_path_or_url, "worktree", "add", "--detach", str(worktree_path), commit_sha]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, shell=False)
            if res.returncode != 0:
                # Fallback: copy tree or clone local
                cmd_clone = [git_bin, "clone", "--no-checkout", repo_path_or_url, str(worktree_path)]
                subprocess.run(cmd_clone, capture_output=True, text=True, timeout=60, shell=False)
                subprocess.run([git_bin, "-C", str(worktree_path), "checkout", commit_sha], capture_output=True, text=True, timeout=30, shell=False)
            yield str(worktree_path)
            # Cleanup worktree
            subprocess.run([git_bin, "-C", repo_path_or_url, "worktree", "remove", "--force", str(worktree_path)], capture_output=True, text=True, timeout=30, shell=False)
        else:
            # Clone remote repo into isolated temp dir and checkout exact commit
            target_path = Path(temp_dir) / "repo"
            cmd_clone = [git_bin, "clone", "--depth", "50", repo_path_or_url, str(target_path)]
            res = subprocess.run(cmd_clone, capture_output=True, text=True, timeout=120, shell=False)
            if res.returncode == 0:
                subprocess.run([git_bin, "-C", str(target_path), "checkout", commit_sha], capture_output=True, text=True, timeout=30, shell=False)
                yield str(target_path)
            else:
                yield repo_path_or_url
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _run_qscanner(
    target: str,
    qscanner_path: str,
    pod: str,
    client_id: str,
    client_secret: str = "",
    timeout: int = 300,
) -> Dict[str, Any]:
    """Invoke the QScanner CLI binary on *target* (local path or checked-out repo)."""
    binary = shutil.which(qscanner_path) or shutil.which("qscanner")
    if not binary:
        raise CommitScanError(
            f"QScanner binary not found at {qscanner_path!r}. "
            "Set QUALYS_QSCANNER_PATH or place qscanner in PATH."
        )

    env = dict(os.environ)
    if client_secret:
        env["QUALYS_CLIENT_SECRET"] = client_secret

    args = [
        binary,
        "--pod", pod,
        "--client-id", client_id,
        "--scan-types", "sca,code",
        "--output-format", "json",
        target,
    ]
    logger.info("Running QScanner on %s", target)
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
            env=env
        )
    except subprocess.TimeoutExpired:
        raise CommitScanError(f"QScanner timed out after {timeout}s")
    except OSError as exc:
        raise CommitScanError(f"Failed to launch QScanner: {exc}") from exc

    if result.returncode != 0:
        raise CommitScanError(
            f"QScanner exited with code {result.returncode}: {result.stderr[:500]}"
        )

    import json
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise CommitScanError(f"QScanner output is not valid JSON: {exc}") from exc


def _extract_upstream_fix_commit(vuln_record: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """Concept 3: Extract upstream fix commit SHA from OSV ranges/references if present."""
    # Look in affected ranges
    for affected in vuln_record.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") == "GIT":
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        return ev["fixed"], "verified_advisory"
    # Look in references
    for ref in vuln_record.get("references", []):
        url = ref.get("url", "")
        if "commit" in url:
            match = re.search(r'([0-9a-f]{40})', url, re.I)
            if match:
                return match.group(1), "verified_advisory"
    return None, "unknown"


def _normalize_osv_commit_finding(
    raw_vuln: Dict[str, Any],
    repo_url: str,
    scanned_sha: str
) -> UnifiedCommitFinding:
    """Normalize an OSV vulnerability record returned from POST /v1/query with commit."""
    vuln_id = raw_vuln.get("id", "")
    aliases = raw_vuln.get("aliases", [])
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
    
    # Check packages
    pkg_name = None
    ecosystem = None
    affected_list = raw_vuln.get("affected", [])
    if affected_list:
        first_aff = affected_list[0]
        pkg_obj = first_aff.get("package", {})
        pkg_name = pkg_obj.get("name")
        ecosystem = pkg_obj.get("ecosystem")
    
    upstream_fix_sha, fix_status = _extract_upstream_fix_commit(raw_vuln)
    
    # Severity & CVSS
    severity = "UNKNOWN"
    cvss_score = None
    for sev in raw_vuln.get("severity", []):
        score_str = sev.get("score")
        if score_str:
            severity = "HIGH" # fallback
            
    refs = [r.get("url", "") for r in raw_vuln.get("references", []) if r.get("url")]
    
    return UnifiedCommitFinding(
        finding_id=f"osv-{vuln_id}",
        source="OSV",
        sources_seen=["OSV"],
        analysis_method="commit-based",
        repository_url=repo_url,
        scanned_commit_sha=scanned_sha,
        dependency_introduction_sha=None,
        introduction_attribution_status="unverified",
        upstream_fix_commit_sha=upstream_fix_sha,
        upstream_fix_attribution_status=fix_status,
        finding_type="package" if pkg_name else "code_level",
        package_name=pkg_name,
        package_version=None,
        ecosystem=ecosystem or "Git",
        vulnerability_id=vuln_id,
        cve_id=cve_id,
        aliases=aliases,
        severity=severity,
        cvss_score=cvss_score,
        summary=raw_vuln.get("summary") or raw_vuln.get("details", "")[:120],
        details=raw_vuln.get("details"),
        references=refs,
        raw_evidence=raw_vuln
    )


def _normalize_qualys_commit_finding(
    raw: Dict[str, Any],
    repo_url: str,
    scanned_sha: str
) -> UnifiedCommitFinding:
    """Normalize a Qualys finding to UnifiedCommitFinding."""
    vuln_id = raw.get("id") or raw.get("qid") or f"qualys-{scanned_sha[:8]}"
    cve_id = raw.get("cveId") or raw.get("cve_id")
    pkg_name = raw.get("packageName") or raw.get("name")
    
    return UnifiedCommitFinding(
        finding_id=f"qualys-{vuln_id}",
        source="Qualys",
        sources_seen=["Qualys"],
        analysis_method="commit-based",
        repository_url=repo_url,
        scanned_commit_sha=scanned_sha,
        dependency_introduction_sha=None,
        introduction_attribution_status="unverified",
        upstream_fix_commit_sha=None,
        upstream_fix_attribution_status="unknown",
        finding_type="package" if pkg_name else "code_level",
        package_name=pkg_name,
        package_version=raw.get("packageVersion") or raw.get("version"),
        ecosystem=raw.get("ecosystem") or raw.get("packageType") or "npm",
        vulnerability_id=str(vuln_id),
        cve_id=cve_id,
        aliases=[cve_id] if cve_id else [],
        severity=raw.get("severity") or raw.get("severityLevel") or "UNKNOWN",
        summary=raw.get("title") or raw.get("summary"),
        fixed_version=raw.get("fixedVersion") or raw.get("fix"),
        references=[],
        raw_evidence=raw
    )


def _normalize_manifest_finding(
    vf: VulnerableFinding,
    repo_url: str,
    scanned_sha: str
) -> UnifiedCommitFinding:
    """Normalize a VulnerableFinding from version-based manifest scanning at a commit."""
    vrec = vf.vulnerability
    comp = vf.component
    
    upstream_fix_sha = None
    fix_status = "unknown"
    if vrec.references:
        for ref in vrec.references:
            url = ref.get("url", "")
            if "commit" in url:
                m = re.search(r'([0-9a-f]{40})', url, re.I)
                if m:
                    upstream_fix_sha = m.group(1)
                    fix_status = "verified_advisory"
                    break

    # Calculate CVSS score if available
    cvss_score = None
    if vrec.cvss:
        for c in vrec.cvss:
            if c.base_score is not None:
                cvss_score = c.base_score
                break

    refs = [r.get("url", "") for r in vrec.references if r.get("url")]

    return UnifiedCommitFinding(
        finding_id=f"manifest-{vrec.id}-{comp.name}-{comp.version}",
        source="OSV",
        sources_seen=["OSV-Manifest"],
        analysis_method="commit-based",
        repository_url=repo_url,
        scanned_commit_sha=scanned_sha,
        dependency_introduction_sha=None,
        introduction_attribution_status="unverified",
        upstream_fix_commit_sha=upstream_fix_sha,
        upstream_fix_attribution_status=fix_status,
        finding_type="package",
        package_name=comp.name,
        package_version=comp.version,
        ecosystem=comp.ecosystem,
        vulnerability_id=vrec.id,
        cve_id=vrec.cve_id,
        aliases=vrec.aliases,
        severity="CRITICAL" if vf.priority_tier in ["CRITICAL_URGENT", "CRITICAL"] else "HIGH" if vf.priority_tier == "HIGH" else "MEDIUM" if vf.priority_tier == "MEDIUM" else "LOW",
        cvss_score=cvss_score,
        summary=vrec.summary or vrec.details or "",
        details=vrec.details,
        fixed_version=vrec.first_fixed_version,
        references=refs,
        in_kev=vrec.in_kev,
        epss_score=vrec.epss_score,
        affected_purl=comp.purl,
        propagation_depth=vf.depth,
        raw_evidence={"vulnerability": vrec.model_dump(), "component": comp.model_dump()}
    )


def _deduplicate_findings(
    findings: List[UnifiedCommitFinding]
) -> List[UnifiedCommitFinding]:
    """Deduplicate findings across OSV and Qualys while preserving all source evidence."""
    deduped: Dict[str, UnifiedCommitFinding] = {}
    
    for f in findings:
        # Key on CVE if present, else vulnerability_id + package_name
        key = f.cve_id or f"{f.vulnerability_id}:{f.package_name or 'code'}"
        if key in deduped:
            existing = deduped[key]
            # Merge sources
            if f.source not in existing.sources_seen:
                existing.sources_seen.append(f.source)
            existing.source = "Multiple"
            if not existing.package_name and f.package_name:
                existing.package_name = f.package_name
                existing.finding_type = f.finding_type
            if not existing.fixed_version and f.fixed_version:
                existing.fixed_version = f.fixed_version
            if not existing.upstream_fix_commit_sha and f.upstream_fix_commit_sha:
                existing.upstream_fix_commit_sha = f.upstream_fix_commit_sha
                existing.upstream_fix_attribution_status = f.upstream_fix_attribution_status
        else:
            deduped[key] = f
            
    return list(deduped.values())


async def analyze_repository_commit(
    request: CommitScanRequest,
    cache,  # EvidenceCache instance
) -> CommitScanRecord:
    """Main entry point for commit-based vulnerability scanning."""
    now = datetime.now(timezone.utc).isoformat()
    import uuid as _uuid
    job_id = str(_uuid.uuid4())

    _validate_repo_url(request.repository_url)

    # 1. Resolve SHA
    resolved_sha: Optional[str] = None
    sha_error: Optional[str] = None

    if request.local_repo_path:
        try:
            resolved_sha = resolve_commit_sha(
                request.local_repo_path,
                request.revision or "HEAD",
            )
        except CommitScanError as exc:
            sha_error = str(exc)
            logger.warning("Local SHA resolution failed: %s", exc)
    elif _SHA_RE.match(request.revision or ""):
        resolved_sha = (request.revision or "").lower()
    else:
        try:
            resolved_sha = resolve_commit_sha_remote(
                request.repository_url,
                request.revision or "HEAD",
            )
        except CommitScanError as exc:
            sha_error = str(exc)
            logger.warning("Remote SHA resolution failed: %s", exc)

    all_raw_findings: List[UnifiedCommitFinding] = []
    osv_commit_count = 0
    osv_manifest_count = 0
    qualys_count = 0
    sources_detected: List[str] = []
    manifests_detected: List[str] = []
    osv_commit_query_status = "pending"
    manifest_scan_status = "none"

    # 2. OSV Commit Query (always runs if SHA is resolved)
    if resolved_sha:
        try:
            osv_cli = OsvClient(cache=cache)
            osv_res = await osv_cli.query_commit(resolved_sha)
            raw_osv_vulns = osv_res.get("vulns", [])
            for raw_v in raw_osv_vulns:
                norm_f = _normalize_osv_commit_finding(raw_v, request.repository_url, resolved_sha)
                all_raw_findings.append(norm_f)
                osv_commit_count += 1
            if raw_osv_vulns:
                sources_detected.append("OSV-Commit")
                osv_commit_query_status = "success_findings"
            else:
                osv_commit_query_status = "success_empty"
        except Exception as exc:
            logger.warning("OSV commit query error: %s", exc)
            osv_commit_query_status = "error"
    else:
        osv_commit_query_status = "skipped"

    # 3. Safe Checkout & Manifest SCA Discovery + Qualys CLI
    scan_id: Optional[str] = None
    qualys_cli = QualysClient()
    qualys_configured = qualys_cli.is_configured()

    if resolved_sha:
        repo_target = request.local_repo_path or request.repository_url
        try:
            with checkout_repository_commit(repo_target, resolved_sha) as checked_out_path:
                checked_path = Path(checked_out_path)
                
                # Check for supported dependency manifest files
                candidate_manifest_names = [
                    "package-lock.json",
                    "npm-shrinkwrap.json",
                    "requirements.txt",
                    "package.json"
                ]
                found_manifests = []
                for fname in candidate_manifest_names:
                    mpath = checked_path / fname
                    if mpath.is_file():
                        found_manifests.append(mpath)

                if found_manifests:
                    manifest_scan_status = "completed"
                    v_engine = VulnerabilityEngine(cache_db=cache.db_path)
                    primary_analysis_record: Optional[AnalysisRecord] = None
                    
                    for mpath in found_manifests:
                        try:
                            m_name = mpath.name
                            manifests_detected.append(m_name)
                            m_content = mpath.read_text(encoding="utf-8", errors="replace")
                            
                            analysis_rec = await v_engine.analyze_project(
                                content=m_content,
                                filename=m_name,
                                project_name=request.project_name or Path(request.repository_url.rstrip("/")).stem,
                            )
                            
                            if primary_analysis_record is None and analysis_rec:
                                primary_analysis_record = analysis_rec
                            
                            if analysis_rec and analysis_rec.findings:
                                for vf in analysis_rec.findings:
                                    norm_mf = _normalize_manifest_finding(vf, request.repository_url, resolved_sha)
                                    all_raw_findings.append(norm_mf)
                                    osv_manifest_count += 1
                                if "OSV-Manifest" not in sources_detected:
                                    sources_detected.append("OSV-Manifest")
                        except Exception as m_exc:
                            logger.warning("Error analyzing manifest %s: %s", mpath.name, m_exc)
                else:
                    manifest_scan_status = "no_manifests"
                    primary_analysis_record = None

                # If Qualys is configured and CLI is available, run QScanner
                if qualys_configured and qualys_config.qscanner_path and shutil.which(qualys_config.qscanner_path or "qscanner"):
                    try:
                        raw_output = _run_qscanner(
                            target=checked_out_path,
                            qscanner_path=qualys_config.qscanner_path,
                            pod=qualys_config.platform,
                            client_id=qualys_config.client_id,
                            client_secret=qualys_config.client_secret,
                            timeout=qualys_config.scan_timeout,
                        )
                        for rv in raw_output.get("vulnerabilities") or raw_output.get("findings") or []:
                            all_raw_findings.append(
                                _normalize_qualys_commit_finding(rv, request.repository_url, resolved_sha)
                            )
                            qualys_count += 1
                        if "QScanner-CLI" not in sources_detected:
                            sources_detected.append("QScanner-CLI")
                    except Exception as exc:
                        logger.warning("QScanner scan execution error: %s", exc)

        except Exception as co_exc:
            logger.warning("Repository checkout for commit %s failed: %s", resolved_sha, co_exc)
            if manifest_scan_status == "none":
                manifest_scan_status = "error"
            primary_analysis_record = None
    else:
        primary_analysis_record = None

    # 4. Qualys API lookup (if configured and scan_id not yet obtained from CLI)
    if qualys_configured and resolved_sha and qualys_count == 0:
        try:
            matched_scan = await qualys_cli.find_scan_for_commit(
                repo_url=request.repository_url,
                commit_sha=resolved_sha,
            )
            if matched_scan:
                scan_id = matched_scan.get("uuid") or matched_scan.get("id")
                vuln_resp = await qualys_cli.get_code_scan_vulns(scan_id)
                raw_vulns = vuln_resp.get("data") or []
                if isinstance(raw_vulns, list):
                    for rv in raw_vulns:
                        all_raw_findings.append(
                            _normalize_qualys_commit_finding(rv, request.repository_url, resolved_sha)
                        )
                        qualys_count += 1
                if "Qualys-API" not in sources_detected:
                    sources_detected.append("Qualys-API")
        except Exception as exc:
            logger.error("Qualys API lookup error: %s", exc)

    # Deduplicate across sources
    unified_findings = _deduplicate_findings(all_raw_findings)
    
    # Status determination
    if sha_error:
        scan_status = "sha_resolution_failed"
        coverage_status = "error"
        evidence_source = "none"
    else:
        scan_status = "completed"
        coverage_status = "complete" if manifests_detected else "partial_no_manifest"
        evidence_source = "+".join(sources_detected) if sources_detected else "none"

    pkg_count = sum(1 for f in unified_findings if f.finding_type == "package")
    code_count = sum(1 for f in unified_findings if f.finding_type == "code_level")

    # 5. Build and persist downstream AnalysisRecord so full SCA experience is populated
    primary_analysis_id: Optional[str] = None

    if primary_analysis_record is not None:
        primary_analysis_record.repository_url = request.repository_url
        primary_analysis_record.commit_sha = resolved_sha
        primary_analysis_record.manifests_detected = manifests_detected
        primary_analysis_record.coverage_status = coverage_status
        primary_analysis_record.analysis_method = "commit-based"

        existing_vuln_ids = {
            f.vulnerability.id for f in primary_analysis_record.findings
        } | {
            f.vulnerability.cve_id for f in primary_analysis_record.findings if f.vulnerability.cve_id
        }

        extra_v_findings: List[VulnerableFinding] = []
        root_component = next((c for c in primary_analysis_record.components if c.is_direct), None)
        if not root_component and primary_analysis_record.components:
            root_component = primary_analysis_record.components[0]
        elif not root_component:
            root_component = ComponentNode(
                purl=f"pkg:generic/{primary_analysis_record.project_name}@{resolved_sha[:10] if resolved_sha else 'HEAD'}",
                name=primary_analysis_record.project_name,
                version=resolved_sha[:10] if resolved_sha else "HEAD",
                ecosystem="generic",
                is_direct=True,
                in_cycle=False,
                scope="runtime"
            )
            primary_analysis_record.components.append(root_component)

        for uf in unified_findings:
            if uf.vulnerability_id not in existing_vuln_ids and (not uf.cve_id or uf.cve_id not in existing_vuln_ids):
                v_rec = VulnerabilityRecord(
                    id=uf.vulnerability_id or uf.finding_id,
                    summary=uf.summary or "",
                    details=uf.details or "",
                    cve_id=uf.cve_id,
                    aliases=uf.aliases,
                    severity=uf.severity,
                    references=[{"url": r} for r in uf.references],
                    in_kev=uf.in_kev,
                    epss_score=uf.epss_score,
                )
                extra_v_findings.append(VulnerableFinding(
                    component=root_component,
                    vulnerability=v_rec,
                    is_direct=True,
                    depth=0,
                    priority_score=80.0 if uf.in_kev else (60.0 if uf.severity == "CRITICAL" else 40.0),
                    priority_tier="CRITICAL_URGENT" if uf.in_kev else ("CRITICAL" if uf.severity == "CRITICAL" else "HIGH"),
                    score_breakdown={"base": 50.0},
                    confidence=0.85,
                    reachability_state="REACHABLE"
                ))

        if extra_v_findings:
            primary_analysis_record.findings.extend(extra_v_findings)
            primary_analysis_record.patch_plan = RemediationEngine.generate_patch_plan(
                primary_analysis_record.findings,
                primary_analysis_record.components
            )
            s = primary_analysis_record.summary
            s.total_vulnerabilities = len(primary_analysis_record.findings)
            s.kev_matches = sum(1 for f in primary_analysis_record.findings if f.vulnerability.in_kev)
            s.high_priority_findings = sum(1 for f in primary_analysis_record.findings if f.priority_tier in ("CRITICAL_URGENT", "CRITICAL", "HIGH"))

        cache.save_analysis(primary_analysis_record.analysis_id, primary_analysis_record.project_name, primary_analysis_record.model_dump())
        primary_analysis_id = primary_analysis_record.analysis_id
    else:
        fallback_analysis_id = str(_uuid.uuid4())
        proj_name = request.project_name or (Path(request.repository_url.rstrip("/")).stem if request.repository_url else "commit-analysis")
        root_component = ComponentNode(
            purl=f"pkg:generic/{proj_name}@{resolved_sha[:10] if resolved_sha else 'HEAD'}",
            name=proj_name,
            version=resolved_sha[:10] if resolved_sha else "HEAD",
            ecosystem="generic",
            is_direct=True,
            in_cycle=False,
            scope="runtime",
            lookup_status="vulnerable" if unified_findings else "verified_clean"
        )
        v_findings: List[VulnerableFinding] = []
        for uf in unified_findings:
            v_rec = VulnerabilityRecord(
                id=uf.vulnerability_id or uf.finding_id,
                summary=uf.summary or "",
                details=uf.details or "",
                cve_id=uf.cve_id,
                aliases=uf.aliases,
                severity=uf.severity,
                references=[{"url": r} for r in uf.references],
                in_kev=uf.in_kev,
                epss_score=uf.epss_score,
            )
            v_findings.append(VulnerableFinding(
                component=root_component,
                vulnerability=v_rec,
                is_direct=True,
                depth=0,
                priority_score=80.0 if uf.in_kev else (60.0 if uf.severity == "CRITICAL" else 40.0),
                priority_tier="CRITICAL_URGENT" if uf.in_kev else ("CRITICAL" if uf.severity == "CRITICAL" else "HIGH"),
                score_breakdown={"base": 50.0},
                confidence=0.85,
                reachability_state="REACHABLE"
            ))

        patch_plan = RemediationEngine.generate_patch_plan(v_findings, [root_component])
        graph_data = build_cytoscape_graph(
            components=[root_component],
            findings=v_findings,
            project_name=proj_name,
            all_edges=[]
        )
        summary = ScanSummary(
            manifest_type="git-commit",
            resolution_status="manifest_only",
            total_components=1,
            direct_components=1,
            transitive_components=0,
            vulnerable_components=1 if v_findings else 0,
            total_vulnerabilities=len(v_findings),
            direct_vulnerabilities=len(v_findings),
            transitive_vulnerabilities=0,
            kev_matches=sum(1 for f in v_findings if f.vulnerability.in_kev),
            high_priority_findings=sum(1 for f in v_findings if f.priority_tier in ("CRITICAL_URGENT", "CRITICAL", "HIGH")),
            cache_hits=0,
            cache_misses=1,
            scan_duration_ms=0.0
        )
        analysis_rec = AnalysisRecord(
            analysis_id=fallback_analysis_id,
            project_name=proj_name,
            environment="production",
            exposure="internet-facing",
            criticality="high",
            manifest_type="git-commit",
            resolution_status="manifest_only",
            created_at=now,
            summary=summary,
            findings=v_findings,
            components=[root_component],
            patch_plan=patch_plan,
            graph_data=graph_data,
            provenance={"source": "commit-analysis", "repo": request.repository_url, "commit": resolved_sha},
            repository_url=request.repository_url,
            commit_sha=resolved_sha,
            manifests_detected=[],
            coverage_status=coverage_status,
            analysis_method="commit-based"
        )
        cache.save_analysis(fallback_analysis_id, proj_name, analysis_rec.model_dump())
        primary_analysis_id = fallback_analysis_id

    record = CommitScanRecord(
        job_id=job_id,
        analysis_id=primary_analysis_id,
        repository_url=request.repository_url,
        revision=request.revision or "HEAD",
        resolved_sha=resolved_sha,
        sha_resolution_error=sha_error,
        scan_status=scan_status,
        evidence_source=evidence_source,
        qualys_scan_id=scan_id,
        qualys_configured=qualys_configured,
        findings=unified_findings,
        findings_count=len(unified_findings),
        package_findings_count=pkg_count,
        code_findings_count=code_count,
        osv_commit_query_status=osv_commit_query_status,
        manifests_detected=manifests_detected,
        manifest_scan_status=manifest_scan_status,
        coverage_status=coverage_status,
        osv_findings_count=osv_commit_count,
        osv_manifest_findings_count=osv_manifest_count,
        qualys_findings_count=qualys_count,
        scanned_at=now,
        project_name=request.project_name
    )

    cache.save_commit_scan(job_id, record.model_dump())
    return record


def compare_commit_scans(
    base_record: CommitScanRecord,
    target_record: CommitScanRecord
) -> CommitComparisonRecord:
    """Compare findings between two scanned commits with evidence-based diffing."""
    now = datetime.now(timezone.utc).isoformat()
    
    base_keys = {
        f.cve_id or f.vulnerability_id: f for f in base_record.findings
    }
    target_keys = {
        f.cve_id or f.vulnerability_id: f for f in target_record.findings
    }
    
    diffs: List[CommitComparisonFindingDiff] = []
    newly_observed = 0
    resolved = 0
    unresolved = 0
    
    # Check base findings
    for k, bf in base_keys.items():
        if k in target_keys:
            unresolved += 1
            diffs.append(CommitComparisonFindingDiff(
                finding=target_keys[k],
                diff_status="observed_both",
                reason="Observed in both base and target commit states."
            ))
        else:
            resolved += 1
            diffs.append(CommitComparisonFindingDiff(
                finding=bf,
                diff_status="not_detected_in_target",
                reason="Finding not detected in target commit scan."
            ))
            
    # Check target findings for newly introduced
    for k, tf in target_keys.items():
        if k not in base_keys:
            newly_observed += 1
            diffs.append(CommitComparisonFindingDiff(
                finding=tf,
                diff_status="newly_observed",
                reason="Newly observed in target commit."
            ))
            
    return CommitComparisonRecord(
        repository_url=base_record.repository_url,
        base_commit_sha=base_record.resolved_sha or base_record.revision,
        target_commit_sha=target_record.resolved_sha or target_record.revision,
        compared_at=now,
        base_total_findings=base_record.findings_count,
        target_total_findings=target_record.findings_count,
        newly_observed_count=newly_observed,
        resolved_count=resolved,
        unresolved_count=unresolved,
        finding_diffs=diffs,
        summary={
            "delta_findings": target_record.findings_count - base_record.findings_count,
            "status": "improved" if target_record.findings_count < base_record.findings_count else "regressed" if target_record.findings_count > base_record.findings_count else "unchanged"
        }
    )
