from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_full_analysis_and_demo():
    # 1. Fetch demo scenario
    resp = client.get("/api/demo/ecommerce-checkout")
    assert resp.status_code == 200
    data = resp.json()

    assert "analysis_id" in data
    analysis_id = data["analysis_id"]
    assert data["project_name"] == "ecommerce-checkout-service"
    assert data["summary"]["total_components"] >= 4
    assert data["summary"]["vulnerable_components"] > 0
    assert len(data["findings"]) > 0
    assert len(data["patch_plan"]) > 0
    assert data["graph_data"]["total_nodes"] > 0
    assert data["graph_data"]["total_edges"] > 0

    # 2. Fetch analysis by ID
    get_resp = client.get(f"/api/analysis/{analysis_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["analysis_id"] == analysis_id

    # 3. Fetch Cytoscape graph
    graph_resp = client.get(f"/api/analysis/{analysis_id}/graph")
    assert graph_resp.status_code == 200
    assert "nodes" in graph_resp.json()
    assert "edges" in graph_resp.json()

    # 4. Fetch Patch Plan
    patch_resp = client.get(f"/api/analysis/{analysis_id}/patch-plan")
    assert patch_resp.status_code == 200
    plan = patch_resp.json()["patch_plan"]
    assert len(plan) > 0
    assert plan[0]["rank"] == 1
    assert "marginal_value" in plan[0]
    assert "why_now" in plan[0]

    # 5. Run Counterfactual Patch Simulation
    top_patch = plan[0]
    sim_resp = client.post(f"/api/analysis/{analysis_id}/simulate", json={
        "patches": [
            {"package": top_patch["package"], "target_version": top_patch["target_version"]}
        ]
    })
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["is_simulated"] is True
    assert sim_data["diff"]["resolved_findings_count"] > 0
    assert sim_data["diff"]["risk_before"] > sim_data["diff"]["risk_after"]
    assert sim_data["diff"]["risk_reduction_pct"] > 0.0

    # 6. Export Markdown Report
    md_resp = client.get(f"/api/analysis/{analysis_id}/report/markdown")
    assert md_resp.status_code == 200
    assert "PatchOrder" in md_resp.text
    assert "# 1. Executive Summary" in md_resp.text

    # 7. Export JSON Report
    json_resp = client.get(f"/api/analysis/{analysis_id}/report/json")
    assert json_resp.status_code == 200
    assert "ecommerce-checkout-service" in json_resp.text

