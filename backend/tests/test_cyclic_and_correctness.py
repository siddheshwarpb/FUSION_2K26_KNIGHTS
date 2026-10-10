import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.graph import DependencyGraph, ROOT_NODE_ID
from app.parsers.npm_lock import NpmLockParser
from app.services.vulnerability_engine import VulnerabilityEngine
from app.services.synthetic_vulns import is_synthetic_package, get_synthetic_vulnerabilities
from app.services.enrichment import IntelligenceEnricher
from app.services.simulation import SimulationEngine
from app.services.graph_cytoscape import build_cytoscape_graph
from app.core.models import SimulationPatchAction, VulnerableFinding, VulnerabilityRecord, ComponentNode

FIXTURES_DIR = Path(__file__).parent / "fixtures"

client = TestClient(app)

def test_cyclic_graph_topology_and_edges():
    """
    Issue 1: Cyclic dependency graph must contain all 4 edges:
    - root:project -> cycle-a@1.0.0
    - cycle-a@1.0.0 -> cycle-b@1.0.0
    - cycle-b@1.0.0 -> cycle-a@1.0.0
    - cycle-a@1.0.0 -> lodash@4.17.20
    """
    fixture_path = FIXTURES_DIR / "cyclic_vulnerable.package-lock.json"
    content = fixture_path.read_text(encoding="utf-8")

    parser = NpmLockParser()
    dep_graph = parser.parse(content, "package-lock.json")
    comps = dep_graph.get_all_components()
    
    # Verify parsed components
    purls = {c.purl: c for c in comps}
    cycle_a_purl = "pkg:npm/cycle-a@1.0.0"
    cycle_b_purl = "pkg:npm/cycle-b@1.0.0"
    lodash_purl = "pkg:npm/lodash@4.17.20"

    assert cycle_a_purl in purls
    assert cycle_b_purl in purls
    assert lodash_purl in purls

    # Verify synthetic flags
    assert purls[cycle_a_purl].is_synthetic is True
    assert purls[cycle_b_purl].is_synthetic is True

    dep_graph.compute_metrics()
    all_edges = dep_graph.get_all_edges()

    # Check edges
    edge_pairs = {(u, v) for u, v, _ in all_edges}
    assert (ROOT_NODE_ID, cycle_a_purl) in edge_pairs, "Missing root -> cycle-a edge"
    assert (cycle_a_purl, cycle_b_purl) in edge_pairs, "Missing cycle-a -> cycle-b edge"
    assert (cycle_b_purl, cycle_a_purl) in edge_pairs, "Missing cycle-b -> cycle-a return edge"
    assert (cycle_a_purl, lodash_purl) in edge_pairs, "Missing cycle-a -> lodash edge"

    # Tarjan cycle detection
    tarjan_res = dep_graph.detect_cycles_tarjan()
    assert tarjan_res["cyclic_components_count"] == 1
    assert cycle_a_purl in tarjan_res["cyclic_purls"]
    assert cycle_b_purl in tarjan_res["cyclic_purls"]
    assert lodash_purl not in tarjan_res["cyclic_purls"]

    # Build Cytoscape graph
    cy_graph = build_cytoscape_graph(
        components=comps,
        findings=[],
        project_name="cyclic-test",
        all_edges=all_edges,
        cyclic_purls=tarjan_res["cyclic_purls"],
        cyclic_edges=tarjan_res["cyclic_edges"]
    )

    # Check Cytoscape nodes
    cy_nodes = {n.data["id"]: n for n in cy_graph.nodes}
    assert ROOT_NODE_ID in cy_nodes
    assert cy_nodes[ROOT_NODE_ID].data["is_vulnerable"] is False
    assert cy_nodes[cycle_a_purl].data["in_cycle"] is True
    assert cy_nodes[cycle_b_purl].data["in_cycle"] is True
    assert cy_nodes[lodash_purl].data["in_cycle"] is False

    # Check Cytoscape edges
    cy_edge_pairs = {(e.data["source"], e.data["target"]): e for e in cy_graph.edges}
    assert (ROOT_NODE_ID, cycle_a_purl) in cy_edge_pairs
    assert (cycle_a_purl, cycle_b_purl) in cy_edge_pairs
    assert cy_edge_pairs[(cycle_a_purl, cycle_b_purl)].data["is_cyclic"] is True
    assert (cycle_b_purl, cycle_a_purl) in cy_edge_pairs
    assert cy_edge_pairs[(cycle_b_purl, cycle_a_purl)].data["is_cyclic"] is True
    assert (cycle_a_purl, lodash_purl) in cy_edge_pairs
    assert cy_edge_pairs[(cycle_a_purl, lodash_purl)].data["is_cyclic"] is False


def test_tarjan_scc_cycle_detection():
    """
    Issue 2: Implement or correct strongly connected component detection.
    - Multi-node cycle detection
    - Single-node component without self-loop is NOT cyclic
    - Single-node component with self-loop IS cyclic
    - Report vulnerable cycle members as intersection of cycle members and confirmed vulnerable packages
    """
    g = DependencyGraph(project_name="scc-test")
    c1 = ComponentNode(ecosystem="npm", name="pkg-1", version="1.0.0", purl="pkg:npm/pkg-1@1.0.0")
    c2 = ComponentNode(ecosystem="npm", name="pkg-2", version="1.0.0", purl="pkg:npm/pkg-2@1.0.0")
    c3 = ComponentNode(ecosystem="npm", name="pkg-3", version="1.0.0", purl="pkg:npm/pkg-3@1.0.0")
    self_loop = ComponentNode(ecosystem="npm", name="self-loop", version="1.0.0", purl="pkg:npm/self-loop@1.0.0")

    for c in [c1, c2, c3, self_loop]:
        g.add_component(c)

    # Normal linear dependency: root -> 1 -> 2
    g.add_dependency(ROOT_NODE_ID, c1.purl)
    g.add_dependency(c1.purl, c2.purl)

    # 2-node cycle between 2 and 3: 2 -> 3 and 3 -> 2
    g.add_dependency(c2.purl, c3.purl)
    g.add_dependency(c3.purl, c2.purl)

    # Self loop: self_loop -> self_loop
    g.add_dependency(c1.purl, self_loop.purl)
    g.add_dependency(self_loop.purl, self_loop.purl)

    res = g.detect_cycles_tarjan()
    # Should identify 2 cyclic components: {pkg-2, pkg-3} and {self-loop}
    assert res["cyclic_components_count"] == 2
    assert c2.purl in res["cyclic_purls"]
    assert c3.purl in res["cyclic_purls"]
    assert self_loop.purl in res["cyclic_purls"]
    assert c1.purl not in res["cyclic_purls"]
    assert ROOT_NODE_ID not in res["cyclic_purls"]


def test_synthetic_vulnerability_overrides():
    """
    Issue 3: Correct vulnerability matching.
    - Fictional cycle-a and cycle-b packages use test-only vulnerability overrides
    - Must NOT match real OSV malware advisory MAL-2025-5030
    """
    assert is_synthetic_package("cycle-a") is True
    assert is_synthetic_package("cycle-b", is_synthetic_flag=True) is True
    assert is_synthetic_package("lodash") is False

    vulns_a = get_synthetic_vulnerabilities("cycle-a", "1.0.0")
    assert len(vulns_a) == 1
    assert vulns_a[0].id == "SYNTH-VULN-CYCLE-A"
    assert vulns_a[0].id != "MAL-2025-5030"
    assert "CVE-2025-99001" in vulns_a[0].aliases

    vulns_b = get_synthetic_vulnerabilities("cycle-b", "1.0.0", is_synthetic_flag=True)
    assert len(vulns_b) == 1
    assert vulns_b[0].id == "SYNTH-VULN-CYCLE-B"

    vulns_lodash = get_synthetic_vulnerabilities("lodash", "4.17.20")
    assert len(vulns_lodash) == 0


def test_cisa_kev_verification():
    """
    Issue 4: Verify KEV claims against actual CISA KEV catalogue.
    - Store matched CVE, evidence source, and verification timestamp
    - Never infer KEV status from severity or text descriptions
    """
    enricher = IntelligenceEnricher()

    # Known CISA KEV entry: CVE-2021-23337 (Lodash command injection)
    in_kev, matched_cve, date_added, ev_source, verified_at, action = enricher.check_kev(
        cve_id="CVE-2021-23337", aliases=[]
    )
    assert in_kev is True
    assert matched_cve == "CVE-2021-23337"
    assert date_added == "2021-04-12"
    assert "cisa.gov" in ev_source
    assert verified_at is not None

    # Check via aliases
    in_kev_alias, matched_cve_alias, _, _, _, _ = enricher.check_kev(
        cve_id=None, aliases=["GHSA-xxxx", "CVE-2021-44228"]
    )
    assert in_kev_alias is True
    assert matched_cve_alias == "CVE-2021-44228"

    # Non-existent CVE
    in_kev_fake, matched_fake, _, _, _, _ = enricher.check_kev(
        cve_id="CVE-2099-99999", aliases=[]
    )
    assert in_kev_fake is False
    assert matched_fake is None


def test_simulation_upgrade_validation():
    """
    Issue 5: Fix patch ranking and simulation.
    - Validate target version > current version and target version >= fixed version
    - Reject downgrades or versions below fixed version
    """
    finding = VulnerableFinding(
        component=ComponentNode(ecosystem="npm", name="lodash", version="4.17.20", purl="pkg:npm/lodash@4.17.20"),
        vulnerability=VulnerabilityRecord(
            id="CVE-2021-23337",
            cve_id="CVE-2021-23337",
            summary="Command Injection in Lodash",
            first_fixed_version="4.17.21"
        ),
        is_direct=False
    )

    # Valid forward upgrade satisfying fixed version
    assert SimulationEngine._is_fixed_by(finding, "4.17.21") is True
    assert SimulationEngine._is_fixed_by(finding, "4.17.22") is True

    # Same version or downgrade: not fixed
    assert SimulationEngine._is_fixed_by(finding, "4.17.20") is False
    assert SimulationEngine._is_fixed_by(finding, "4.17.19") is False

    # Below fixed version: not fixed
    assert SimulationEngine._is_fixed_by(finding, "4.17.20-beta") is False


@pytest.mark.asyncio
async def test_acyclic_fixture_scan():
    """
    Test parsing and scanning acyclic fixture 02_acyclic_with_vulnerabilities.package-lock.json
    - Ensure cyclic_components_count == 0
    - Verify vulnerability findings and paths
    """
    fixture_path = FIXTURES_DIR / "02_acyclic_with_vulnerabilities.package-lock.json"
    content = fixture_path.read_text(encoding="utf-8")

    engine = VulnerabilityEngine()
    result = await engine.analyze_project(
        content=content,
        filename="package-lock.json",
        project_name="acyclic-demo"
    )

    assert result.summary.cyclic_components_count == 0
    assert len(result.summary.vulnerable_cycle_components) == 0
    assert result.graph_data.cyclic_nodes_count == 0
    assert result.graph_data.cyclic_edges_count == 0
    assert result.summary.vulnerable_components > 0


def test_full_cyclic_analysis_api_and_simulation():
    """
    Issue 1, 2, 3, 5, 6 End-to-End Test via API:
    - Upload cyclic fixture
    - Verify returned graph has cyclic edges and nodes
    - Verify root node is not marked vulnerable
    - Verify simulation returns updated diff and simulated graph
    """
    fixture_path = FIXTURES_DIR / "cyclic_vulnerable.package-lock.json"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("package-lock.json", f, "application/json")}
        )

    assert response.status_code == 200
    data = response.json()

    analysis_id = data["analysis_id"]
    summary = data["summary"]
    graph = data["graph_data"]

    # Verify cycle counts in summary
    assert summary["cyclic_components_count"] >= 2
    assert "cycle-a" in summary["vulnerable_cycle_components"]

    # Verify root node semantics
    root_node = next((n for n in graph["nodes"] if n["data"]["id"] == "root:project"), None)
    assert root_node is not None
    assert root_node["data"]["is_vulnerable"] is False
    assert root_node["data"]["status"] == "affected"

    # Verify cyclic nodes
    nodes_by_id = {n["data"]["id"]: n for n in graph["nodes"]}
    cycle_a = nodes_by_id["pkg:npm/cycle-a@1.0.0"]
    cycle_b = nodes_by_id["pkg:npm/cycle-b@1.0.0"]
    assert cycle_a["data"]["in_cycle"] is True
    assert cycle_b["data"]["in_cycle"] is True

    # Verify cyclic edges (both A->B and B->A)
    edges_by_pair = {(e["data"]["source"], e["data"]["target"]): e for e in graph["edges"]}
    assert ("pkg:npm/cycle-a@1.0.0", "pkg:npm/cycle-b@1.0.0") in edges_by_pair
    assert edges_by_pair[("pkg:npm/cycle-a@1.0.0", "pkg:npm/cycle-b@1.0.0")]["data"]["is_cyclic"] is True

    assert ("pkg:npm/cycle-b@1.0.0", "pkg:npm/cycle-a@1.0.0") in edges_by_pair
    assert edges_by_pair[("pkg:npm/cycle-b@1.0.0", "pkg:npm/cycle-a@1.0.0")]["data"]["is_cyclic"] is True

    # Verify cycle-a -> lodash edge exists
    assert ("pkg:npm/cycle-a@1.0.0", "pkg:npm/lodash@4.17.20") in edges_by_pair

    # Test patch simulation on lodash
    sim_resp = client.post(
        f"/api/analysis/{analysis_id}/simulate",
        json={"patches": [{"package": "lodash", "target_version": "4.17.21"}]}
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["is_simulated"] is True
    assert sim_data["diff"]["resolved_findings_count"] >= 1
    assert sim_data["diff"]["risk_reduction_pct"] > 0
