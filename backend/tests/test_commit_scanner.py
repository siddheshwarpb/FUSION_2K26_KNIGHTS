"""Tests for Git Commit-based scanning and Qualys integration."""
import os
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.models import CommitScanRequest, CommitScanRecord, QualysFinding
from app.core.config import QualysConfig
from app.services.qualys_client import QualysClient, QualysAuthError, QualysAPIError
from app.services.commit_scanner import (
    resolve_commit_sha,
    analyze_repository_commit,
    CommitScanError,
    _validate_repo_url,
    _validate_revision,
)
from app.core.cache import EvidenceCache

client = TestClient(app)


def test_validate_repo_url_valid():
    url = "https://github.com/org/repo"
    assert _validate_repo_url(url) == url


def test_validate_repo_url_invalid():
    with pytest.raises(CommitScanError):
        _validate_repo_url("git@github.com:org/repo.git; rm -rf /")


def test_validate_revision():
    assert _validate_revision("HEAD") == "HEAD"
    assert _validate_revision("main") == "main"
    assert _validate_revision("v1.0.0") == "v1.0.0"
    with pytest.raises(CommitScanError):
        _validate_revision("main; echo hacked")


def test_resolve_commit_sha_local_repo(tmp_path):
    import subprocess
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)

    test_file = repo_dir / "README.md"
    test_file.write_text("hello")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)

    sha = resolve_commit_sha(str(repo_dir), "HEAD")
    assert len(sha) == 40
    assert all(c in "0123456789abcdef" for c in sha.lower())


def test_qualys_config_unconfigured():
    cfg = QualysConfig(platform="", client_id="", client_secret="")
    assert not cfg.is_configured()

    cfg2 = QualysConfig(platform="pod.qualys.com", client_id="your-client-id-here", client_secret="secret")
    assert not cfg2.is_configured()


def test_qualys_config_configured():
    cfg = QualysConfig(platform="pod.qualys.com", client_id="real-id", client_secret="real-secret")
    assert cfg.is_configured()
    assert cfg.base_url() == "https://pod.qualys.com"


@pytest.mark.asyncio
async def test_qualys_client_unconfigured_mode():
    cfg = QualysConfig(platform="", client_id="", client_secret="")
    client_q = QualysClient(cfg)
    assert not client_q.is_configured()

    scans = await client_q.list_code_scans()
    assert scans["configured"] is False
    assert "not configured" in scans["message"]


@pytest.mark.asyncio
async def test_analyze_repository_commit_unconfigured(tmp_path):
    db_file = tmp_path / "test_cache.db"
    cache = EvidenceCache(db_path=str(db_file))

    req = CommitScanRequest(
        repository_url="https://github.com/example/repo",
        revision="a" * 40,
        project_name="test-unconfigured"
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp

        record = await analyze_repository_commit(req, cache)
        assert record.scan_status == "completed"
        assert record.resolved_sha == "a" * 40
        assert record.qualys_configured is False
        assert record.osv_commit_query_status == "success_empty"
        assert record.coverage_status == "partial_no_manifest"
        assert len(record.findings) == 0
        assert "zero" in record.guidance.lower() or "no direct commit-level advisories" in record.guidance.lower()

        # Check cache retrieval
        stored = cache.get_commit_scan(record.job_id)
        assert stored is not None
        assert stored["job_id"] == record.job_id


def test_api_commit_scan_start_and_get():
    payload = {
        "repository_url": "https://github.com/example/app",
        "revision": "e" * 40,
        "project_name": "api-test"
    }
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp

        resp = client.post("/api/commit-scan/start", json=payload)
        assert resp.status_code == 202
        data = resp.json()
        assert data["scan_status"] == "completed"
        assert data["resolved_sha"] == "e" * 40
        job_id = data["job_id"]

        # Get by job_id
        get_resp = client.get(f"/api/commit-scan/{job_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["job_id"] == job_id

        # List scans
        list_resp = client.get("/api/commit-scan/list")
        assert list_resp.status_code == 200
        assert any(item["job_id"] == job_id for item in list_resp.json())


def test_api_health_includes_qualys():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "qualys_configured" in data
    assert "commit_scan_available" in data
    assert data["commit_scan_available"] is True


@pytest.mark.asyncio
async def test_osv_commit_query_with_findings(tmp_path):
    db_file = tmp_path / "test_cache.db"
    cache = EvidenceCache(db_path=str(db_file))

    req = CommitScanRequest(
        repository_url="https://github.com/example/repo",
        revision="b" * 40,
        project_name="test-osv-findings"
    )

    mock_osv_response = {
        "vulns": [
            {
                "id": "GHSA-1234-5678",
                "summary": "Buffer overflow in example library",
                "aliases": ["CVE-2021-99999"],
                "affected": [
                    {
                        "package": {"name": "libfoo", "ecosystem": "OSS-Fuzz"},
                        "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "c" * 40}]}]
                    }
                ]
            }
        ]
    }

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_osv_response
        mock_post.return_value = mock_resp

        record = await analyze_repository_commit(req, cache)
        assert record.scan_status == "completed"
        assert record.osv_commit_query_status == "success_findings"
        assert record.findings_count == 1
        assert record.findings[0].vulnerability_id == "GHSA-1234-5678"
        assert record.findings[0].cve_id == "CVE-2021-99999"
        assert record.findings[0].upstream_fix_commit_sha == "c" * 40
        assert record.findings[0].upstream_fix_attribution_status == "verified_advisory"


@pytest.mark.asyncio
async def test_osv_commit_query_empty_response(tmp_path):
    db_file = tmp_path / "test_cache.db"
    cache = EvidenceCache(db_path=str(db_file))

    req = CommitScanRequest(
        repository_url="https://github.com/example/repo",
        revision="c" * 40,
        project_name="test-empty"
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp

        record = await analyze_repository_commit(req, cache)
        assert record.scan_status == "completed"
        assert record.osv_commit_query_status == "success_empty"
        assert record.findings_count == 0


@pytest.mark.asyncio
async def test_osv_commit_query_http_error(tmp_path):
    db_file = tmp_path / "test_cache.db"
    cache = EvidenceCache(db_path=str(db_file))

    req = CommitScanRequest(
        repository_url="https://github.com/example/repo",
        revision="d" * 40,
        project_name="test-error"
    )

    with patch("httpx.AsyncClient.post", side_effect=Exception("Connection refused by remote host")):
        record = await analyze_repository_commit(req, cache)
        assert record.osv_commit_query_status == "error"
        assert record.findings_count == 0


@pytest.mark.asyncio
async def test_osv_commit_query_malformed_response(tmp_path):
    db_file = tmp_path / "test_cache.db"
    cache = EvidenceCache(db_path=str(db_file))

    req = CommitScanRequest(
        repository_url="https://github.com/example/repo",
        revision="e" * 40,
        project_name="test-malformed"
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON")
        mock_post.return_value = mock_resp

        record = await analyze_repository_commit(req, cache)
        assert record.osv_commit_query_status == "error"
        assert record.findings_count == 0


@pytest.mark.asyncio
async def test_commit_analysis_with_vulnerable_manifest_and_empty_commit_query(tmp_path):
    import subprocess
    repo_dir = tmp_path / "vulnerable_repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)

    # Write a pinned requirements.txt with a synthetic vulnerable package (cycle-a)
    reqs_file = repo_dir / "requirements.txt"
    reqs_file.write_text("cycle-a==1.0.0\n")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Add requirements.txt"], cwd=repo_dir, check=True, capture_output=True)

    commit_sha = resolve_commit_sha(str(repo_dir), "HEAD")

    db_file = tmp_path / "test_cache.db"
    cache = EvidenceCache(db_path=str(db_file))

    req = CommitScanRequest(
        repository_url="https://github.com/example/repo",
        revision=commit_sha,
        local_repo_path=str(repo_dir),
        project_name="repo-with-manifest"
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        # OSV commit query returns empty {}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp

        record = await analyze_repository_commit(req, cache)
        assert record.scan_status == "completed"
        assert record.osv_commit_query_status == "success_empty"
        assert "requirements.txt" in record.manifests_detected
        assert record.manifest_scan_status == "completed"
        assert record.coverage_status == "complete"
        assert record.findings_count > 0
        assert record.osv_manifest_findings_count > 0
        assert any(f.package_name == "cycle-a" for f in record.findings)


@pytest.mark.asyncio
async def test_commit_analysis_absent_manifests(tmp_path):
    import subprocess
    repo_dir = tmp_path / "clean_repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)

    (repo_dir / "README.md").write_text("# Clean Repo\nNo dependencies.\n")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)

    commit_sha = resolve_commit_sha(str(repo_dir), "HEAD")

    db_file = tmp_path / "test_cache.db"
    cache = EvidenceCache(db_path=str(db_file))

    req = CommitScanRequest(
        repository_url="https://github.com/example/clean",
        revision=commit_sha,
        local_repo_path=str(repo_dir),
        project_name="clean-repo"
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp

        record = await analyze_repository_commit(req, cache)
        assert record.scan_status == "completed"
        assert record.osv_commit_query_status == "success_empty"
        assert record.manifest_scan_status == "no_manifests"
        assert record.coverage_status == "partial_no_manifest"
        assert record.findings_count == 0


@pytest.mark.asyncio
async def test_osv_commit_query_mock():
    from app.services.osv_client import OsvClient
    cli = OsvClient()
    mock_resp = {
        "vulns": [
            {
                "id": "GHSA-1234-abcd",
                "summary": "Prototype pollution in lodash",
                "aliases": ["CVE-2021-23337"],
                "affected": [
                    {
                        "package": {"name": "lodash", "ecosystem": "npm"},
                        "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "1234567890123456789012345678901234567890"}]}]
                    }
                ]
            }
        ]
    }
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response_obj = MagicMock()
        mock_response_obj.status_code = 200
        mock_response_obj.json.return_value = mock_resp
        mock_post.return_value = mock_response_obj
        
        res = await cli.query_commit("b38d8373756622764be5f90846c0c3aa9f84699a")
        assert len(res.get("vulns", [])) == 1
        assert res["vulns"][0]["id"] == "GHSA-1234-abcd"


def test_compare_commit_scans_diff():
    from app.services.commit_scanner import compare_commit_scans
    from app.core.models import UnifiedCommitFinding
    
    base_f1 = UnifiedCommitFinding(
        finding_id="f1",
        vulnerability_id="CVE-2020-1234",
        cve_id="CVE-2020-1234",
        package_name="express",
        source="OSV",
        scanned_commit_sha="1111111111111111111111111111111111111111"
    )
    base_f2 = UnifiedCommitFinding(
        finding_id="f2",
        vulnerability_id="CVE-2020-5678",
        cve_id="CVE-2020-5678",
        package_name="lodash",
        source="OSV",
        scanned_commit_sha="1111111111111111111111111111111111111111"
    )
    
    target_f1 = UnifiedCommitFinding(
        finding_id="f1",
        vulnerability_id="CVE-2020-1234",
        cve_id="CVE-2020-1234",
        package_name="express",
        source="OSV",
        scanned_commit_sha="2222222222222222222222222222222222222222"
    )
    target_f3 = UnifiedCommitFinding(
        finding_id="f3",
        vulnerability_id="CVE-2023-9999",
        cve_id="CVE-2023-9999",
        package_name="axios",
        source="Qualys",
        scanned_commit_sha="2222222222222222222222222222222222222222"
    )
    
    base_rec = CommitScanRecord(
        job_id="job-base",
        repository_url="https://github.com/org/repo",
        resolved_sha="1111111111111111111111111111111111111111",
        findings=[base_f1, base_f2],
        findings_count=2
    )
    target_rec = CommitScanRecord(
        job_id="job-target",
        repository_url="https://github.com/org/repo",
        resolved_sha="2222222222222222222222222222222222222222",
        findings=[target_f1, target_f3],
        findings_count=2
    )
    
    comparison = compare_commit_scans(base_rec, target_rec)
    assert comparison.base_total_findings == 2
    assert comparison.target_total_findings == 2
    assert comparison.unresolved_count == 1
    assert comparison.resolved_count == 1
    assert comparison.newly_observed_count == 1
    assert any(d.diff_status == "not_detected_in_target" and d.finding.package_name == "lodash" for d in comparison.finding_diffs)
    assert any(d.diff_status == "newly_observed" and d.finding.package_name == "axios" for d in comparison.finding_diffs)


def test_checkout_repository_commit_worktree(tmp_path):
    import subprocess
    from app.services.commit_scanner import checkout_repository_commit
    
    repo_dir = tmp_path / "worktree_repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)
    
    (repo_dir / "app.js").write_text("console.log('v1');")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "v1 commit"], cwd=repo_dir, check=True, capture_output=True)
    
    sha_v1 = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    
    (repo_dir / "app.js").write_text("console.log('v2');")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "v2 commit"], cwd=repo_dir, check=True, capture_output=True)
    
    with checkout_repository_commit(str(repo_dir), sha_v1) as co_dir:
        assert (Path(co_dir) / "app.js").read_text() == "console.log('v1');"
        
    # Main worktree still on v2
    assert (repo_dir / "app.js").read_text() == "console.log('v2');"


def test_qscanner_mock_execution():
    from app.services.commit_scanner import _run_qscanner
    import json
    
    mock_json = json.dumps({
        "vulnerabilities": [
            {
                "id": "123456",
                "packageName": "lodash",
                "packageVersion": "4.17.15",
                "severity": "HIGH",
                "title": "Prototype Pollution"
            }
        ]
    })
    
    with patch("shutil.which", return_value="/usr/local/bin/qscanner"), \
         patch("subprocess.run") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = mock_json
        mock_sub.return_value = mock_proc
        
        res = _run_qscanner(
            target="/path/to/repo",
            qscanner_path="qscanner",
            pod="gateway.qg1.apps.qualys.com",
            client_id="test-client-id"
        )
        assert len(res.get("vulnerabilities", [])) == 1
        assert res["vulnerabilities"][0]["packageName"] == "lodash"


@pytest.mark.asyncio
async def test_commit_analysis_persists_full_sca_record_and_routes(tmp_path):
    """Verify that a commit scan creates and caches an AnalysisRecord with full graph and patch plan."""
    repo_dir = tmp_path / "repo_full_sca"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)

    reqs_file = repo_dir / "requirements.txt"
    reqs_file.write_text("cycle-a==1.0.0\n")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Add requirements.txt"], cwd=repo_dir, check=True, capture_output=True)

    commit_sha = resolve_commit_sha(str(repo_dir), "HEAD")
    db_file = tmp_path / "test_cache.db"
    cache = EvidenceCache(db_path=str(db_file))

    req = CommitScanRequest(
        repository_url="https://github.com/example/full-sca-repo",
        revision=commit_sha,
        local_repo_path=str(repo_dir),
        project_name="full-sca-repo"
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp

        record = await analyze_repository_commit(req, cache)
        assert record.scan_status == "completed"
        assert record.analysis_id is not None

        # Verify AnalysisRecord is stored in cache
        cached_analysis = cache.get_analysis(record.analysis_id)
        assert cached_analysis is not None
        assert cached_analysis["analysis_id"] == record.analysis_id
        assert cached_analysis["repository_url"] == "https://github.com/example/full-sca-repo"
        assert cached_analysis["commit_sha"] == commit_sha
        assert cached_analysis["analysis_method"] == "commit-based"
        assert "graph_data" in cached_analysis
        assert len(cached_analysis["findings"]) > 0
        assert len(cached_analysis["patch_plan"]) > 0

        # Verify ReportGenerator includes commit details
        from app.core.models import AnalysisRecord
        from app.services.report_generator import ReportGenerator
        rec_obj = AnalysisRecord(**cached_analysis)
        report_md = ReportGenerator.generate_markdown(rec_obj)
        assert commit_sha in report_md
        assert "https://github.com/example/full-sca-repo" in report_md


@pytest.mark.asyncio
async def test_commit_analysis_clean_repo_persists_valid_record(tmp_path):
    """Verify that a commit scan with no manifests still creates a valid fallback AnalysisRecord."""
    repo_dir = tmp_path / "repo_no_manifest"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_dir, check=True)

    (repo_dir / "index.html").write_text("<h1>Hello World</h1>")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)

    commit_sha = resolve_commit_sha(str(repo_dir), "HEAD")
    db_file = tmp_path / "test_cache.db"
    cache = EvidenceCache(db_path=str(db_file))

    req = CommitScanRequest(
        repository_url="https://github.com/example/clean-code",
        revision=commit_sha,
        local_repo_path=str(repo_dir),
        project_name="clean-code"
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_post.return_value = mock_resp

        record = await analyze_repository_commit(req, cache)
        assert record.scan_status == "completed"
        assert record.analysis_id is not None

        cached_analysis = cache.get_analysis(record.analysis_id)
        assert cached_analysis is not None
        assert cached_analysis["analysis_id"] == record.analysis_id
        assert cached_analysis["repository_url"] == "https://github.com/example/clean-code"
        assert cached_analysis["commit_sha"] == commit_sha
        assert cached_analysis["manifest_type"] == "git-commit"
        assert "graph_data" in cached_analysis


