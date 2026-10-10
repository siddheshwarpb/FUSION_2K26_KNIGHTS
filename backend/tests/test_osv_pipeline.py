from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_step1_single_query():
    resp = client.post("/api/v1/query", json={
        "package": "jinja2",
        "ecosystem": "PyPI",
        "version": "2.11.2"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["package"] == "jinja2"
    assert data["vulnerabilities_found"] > 0
    assert len(data["findings"]) > 0
    assert "fixed_version" in data["findings"][0]

def test_step2_batch_query():
    resp = client.post("/api/v1/querybatch", json={
        "queries": [
            {"package": "lodash", "ecosystem": "npm", "version": "4.17.15"},
            {"package": "colorama", "ecosystem": "PyPI", "version": "0.4.6"}
        ]
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["total_queried"] == 2
    assert len(data["results"]) == 2

def test_step3_vuln_detail():
    resp = client.get("/api/v1/vulns/GHSA-35jh-r3h4-6jhm")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "GHSA-35jh-r3h4-6jhm"
    assert "summary" in data

def test_normalized_scan_completed_with_findings():
    resp = client.post("/api/v1/scan", json={
        "project": "payment-api",
        "filename": "package.json",
        "content": '{"name": "payment-api", "dependencies": {"lodash": "4.17.15"}}'
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["project"] == "payment-api"
    assert data["scan_status"] == "completed"
    assert data["packages_scanned"] == 1
    assert data["vulnerable_packages"] == 1
    assert len(data["findings"]) > 0
    assert data["findings"][0]["package"] == "lodash"
    assert data["findings"][0]["installed_version"] == "4.17.15"

def test_normalized_scan_completed_zero_findings():
    resp = client.post("/api/v1/scan", json={
        "project": "clean-project",
        "filename": "requirements.txt",
        "content": "colorama==0.4.6"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["project"] == "clean-project"
    assert data["scan_status"] == "completed"
    assert data["packages_scanned"] == 1
    assert data["vulnerable_packages"] == 0
    assert data["findings"] == []


def test_parse_vulnerability_identity_mapping():
    from app.services.osv_client import parse_vulnerability_identity, CWE_TYPE_MAP

    # Criterion 1: Explicit vulnerability category
    item_explicit = {
        "id": "GHSA-explicit-01",
        "aliases": ["CVE-2023-1111"],
        "summary": "Custom security flaw in package",
        "vulnerability_type": "Command Injection"
    }
    ident_explicit = parse_vulnerability_identity(item_explicit)
    assert ident_explicit["unique_id"] == "GHSA-explicit-01"
    assert ident_explicit["cve_alias"] == "CVE-2023-1111"
    assert ident_explicit["vulnerability_type"] == "Command Injection"

    # Criterion 2: Structured CWE classification (CWE-1321)
    item_prototype_pollution = {
        "id": "GHSA-29mw-wpgm-hm82",
        "aliases": ["CVE-2019-10744"],
        "summary": "Prototype Pollution in lodash",
        "database_specific": {
            "cwe_ids": ["CWE-1321"]
        }
    }
    ident_cwe = parse_vulnerability_identity(item_prototype_pollution)
    assert ident_cwe["unique_id"] == "GHSA-29mw-wpgm-hm82"
    assert ident_cwe["cve_alias"] == "CVE-2019-10744"
    assert ident_cwe["cwe_id"] == "CWE-1321"
    assert ident_cwe["vulnerability_type"] == "Prototype Pollution"

    # Criterion 3: Summary-only classification (No CWE, but summary has "SQL Injection")
    item_summary_only = {
        "id": "GHSA-summary-sql",
        "aliases": ["CVE-2022-2222"],
        "summary": "SQL injection in database connector driver",
    }
    ident_summary = parse_vulnerability_identity(item_summary_only)
    assert ident_summary["unique_id"] == "GHSA-summary-sql"
    assert ident_summary["cwe_id"] is None
    assert ident_summary["vulnerability_type"] == "SQL Injection"

    # Criterion 4: No reliable classification -> Unclassified
    item_unclassified = {
        "id": "GHSA-mystery-99",
        "summary": "Misc bug fix with unspecified security implications",
    }
    ident_unclass = parse_vulnerability_identity(item_unclassified)
    assert ident_unclass["unique_id"] == "GHSA-mystery-99"
    assert ident_unclass["cve_alias"] == "No CVE Alias"
    assert ident_unclass["cwe_id"] is None
    assert ident_unclass["vulnerability_type"] == "Unclassified"

    # Criterion 5: Completely empty payload fallback
    item_empty = {}
    ident_empty = parse_vulnerability_identity(item_empty)
    assert ident_empty["unique_id"] == "UNKNOWN-ID"
    assert ident_empty["cve_alias"] == "No CVE Alias"
    assert ident_empty["cwe_id"] is None
    assert ident_empty["vulnerability_type"] == "Unclassified"


def test_graph_endpoint_embeds_mapped_identity():
    # Run analysis and verify graph nodes contain identifiers and vulnerability_details
    resp = client.post("/api/analyze", json={
        "content": '{"name": "test-app", "dependencies": {"cycle-a": "1.0.0"}}',
        "filename": "package.json",
        "project_name": "test-cwe-graph"
    })
    assert resp.status_code == 200
    data = resp.json()
    graph_data = data["graph_data"]
    nodes = graph_data["nodes"]

    # Find cycle-a node
    vuln_node = next((n for n in nodes if n["data"].get("name") == "cycle-a"), None)
    assert vuln_node is not None
    ndata = vuln_node["data"]

    # Verify identifiers & vulnerability_details are embedded in node payload
    assert "identifiers" in ndata
    assert "vulnerability_details" in ndata
    assert len(ndata["identifiers"]) > 0
    assert len(ndata["vulnerability_details"]) > 0

    first_det = ndata["vulnerability_details"][0]
    assert "unique_id" in first_det
    assert "cve_alias" in first_det
    assert "cwe_id" in first_det
    assert "vulnerability_name" in first_det
    assert "vulnerability_type" in first_det
    assert first_det["cwe_id"] == "CWE-400"
    assert first_det["vulnerability_type"] == "Uncontrolled Resource Consumption (DoS)"


def test_findings_endpoint_includes_vulnerability_type():
    resp = client.post("/api/analyze", json={
        "content": '{"name": "findings-app", "dependencies": {"cycle-a": "1.0.0"}}',
        "filename": "package.json",
        "project_name": "test-findings-type"
    })
    assert resp.status_code == 200
    data = resp.json()
    analysis_id = data["analysis_id"]

    # Query findings route
    f_resp = client.get(f"/api/analysis/{analysis_id}/findings")
    assert f_resp.status_code == 200
    f_data = f_resp.json()
    assert f_data["total"] > 0
    finding = f_data["findings"][0]
    assert "vulnerability" in finding
    vrec = finding["vulnerability"]
    assert "vulnerability_type" in vrec
    assert vrec["vulnerability_type"] == "Uncontrolled Resource Consumption (DoS)"


