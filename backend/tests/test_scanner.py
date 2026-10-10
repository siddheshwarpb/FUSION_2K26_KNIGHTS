import pytest
import os
from app.services.vulnerability_engine import VulnerabilityEngine
from app.parsers.npm_lock import NpmLockParser
from app.parsers.python_reqs import PythonReqsParser

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

@pytest.mark.asyncio
async def test_npm_vulnerable_scan():
    fixture_path = os.path.join(FIXTURES_DIR, "npm_vulnerable_lock.json")
    with open(fixture_path, "r") as f:
        content = f.read()

    engine = VulnerabilityEngine(cache_db=":memory:")
    response = await engine.scan_manifest(content, filename="package-lock.json", project_name="test-npm")

    assert response.manifest_type == "npm"
    assert response.summary.total_components >= 4
    assert response.summary.vulnerable_components > 0

    # Verify findings contain lodash and qs
    vuln_pkgs = {f.component.name for f in response.findings}
    assert "lodash" in vuln_pkgs or "qs" in vuln_pkgs

    # Find a finding for lodash
    lodash_findings = [f for f in response.findings if f.component.name == "lodash"]
    if lodash_findings:
        f = lodash_findings[0]
        # Check that lodash is correctly identified as transitive
        assert not f.is_direct
        # Check propagation path: express -> lodash
        assert len(f.propagation_paths_to_root) > 0
        path_str = " -> ".join([p.split("/")[-1].split("@")[0] for p in f.propagation_paths_to_root[0]])
        assert "express" in path_str
        # Check root dependents
        assert any("express" in r for r in f.root_dependents)

@pytest.mark.asyncio
async def test_python_vulnerable_scan():
    fixture_path = os.path.join(FIXTURES_DIR, "python_vulnerable_reqs.txt")
    with open(fixture_path, "r") as f:
        content = f.read()

    engine = VulnerabilityEngine(cache_db=":memory:")
    response = await engine.scan_manifest(content, filename="requirements.txt", project_name="test-python")

    assert response.manifest_type == "pypi"
    assert response.summary.total_components == 3
    assert response.summary.vulnerable_components > 0

    # jinja2 2.11.2 has known CVEs
    jinja_findings = [f for f in response.findings if f.component.name == "jinja2"]
    assert len(jinja_findings) > 0
    first = jinja_findings[0]
    assert first.vulnerability.first_fixed_version is not None
    assert first.vulnerability.cve_id is not None

