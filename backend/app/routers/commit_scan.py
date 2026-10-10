"""FastAPI router for commit-based scanning endpoints.

Mount prefix: /api/commit-scan
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, BackgroundTasks

from app.core.models import CommitScanRecord, CommitScanRequest, CommitComparisonRecord
from app.services.commit_scanner import analyze_repository_commit
from app.core.cache import EvidenceCache

logger = logging.getLogger("patchorder.router.commit_scan")

router = APIRouter(prefix="/api/commit-scan", tags=["Commit Scan"])

# Shared cache — injected from main.py after router import
_cache: Optional[EvidenceCache] = None


def set_cache(cache: EvidenceCache) -> None:
    """Inject the shared EvidenceCache instance."""
    global _cache
    _cache = cache


def _get_cache() -> EvidenceCache:
    if _cache is None:
        raise RuntimeError("commit_scan router: cache not initialised")
    return _cache


@router.post("/start", response_model=CommitScanRecord, status_code=202)
async def start_commit_scan(req: CommitScanRequest) -> CommitScanRecord:
    """Start a commit-based vulnerability scan.

    Resolves the revision to a full SHA, searches Qualys for a matching
    scan record, and returns the CommitScanRecord (synchronous for now;
    fast enough because the Qualys lookup is network-bound).
    """
    cache = _get_cache()
    try:
        record = await analyze_repository_commit(req, cache)
        return record
    except Exception as exc:  # noqa: BLE001
        logger.error("Commit scan failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Commit scan failed: {exc}")


@router.get("/list", response_model=List[Dict[str, Any]])
async def list_commit_scans(limit: int = 20) -> List[Dict[str, Any]]:
    """List recent commit-scan records."""
    cache = _get_cache()
    return cache.list_commit_scans(limit=limit)


@router.get("/{job_id}", response_model=CommitScanRecord)
async def get_commit_scan(job_id: str) -> CommitScanRecord:
    """Retrieve a stored commit-scan record by job_id."""
    cache = _get_cache()
    data = cache.get_commit_scan(job_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Commit scan job {job_id!r} not found")
    return CommitScanRecord(**data)


@router.get("/{job_id}/findings", response_model=List[Dict[str, Any]])
async def get_commit_scan_findings(job_id: str) -> List[Dict[str, Any]]:
    """Return only the findings list for a commit-scan job."""
    cache = _get_cache()
    data = cache.get_commit_scan(job_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Commit scan job {job_id!r} not found")
    record = CommitScanRecord(**data)
    return [f.model_dump() for f in record.findings]


class CompareCommitsRequest(BaseModel):
    base_job_id: str
    target_job_id: str


@router.post("/compare", response_model=CommitComparisonRecord)
async def compare_commit_jobs(req: CompareCommitsRequest) -> CommitComparisonRecord:
    """Compare two scanned commits and generate an evidence-backed finding diff."""
    from app.services.commit_scanner import compare_commit_scans
    cache = _get_cache()
    base_data = cache.get_commit_scan(req.base_job_id)
    if not base_data:
        raise HTTPException(status_code=404, detail=f"Base commit scan job {req.base_job_id} not found")
    target_data = cache.get_commit_scan(req.target_job_id)
    if not target_data:
        raise HTTPException(status_code=404, detail=f"Target commit scan job {req.target_job_id} not found")
        
    base_rec = CommitScanRecord(**base_data)
    target_rec = CommitScanRecord(**target_data)
    return compare_commit_scans(base_rec, target_rec)
