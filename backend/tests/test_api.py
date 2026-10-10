from fastapi.testclient import TestClient
import os
import json
from app.main import app

client = TestClient(app)
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_scan_raw_endpoint():
    fixture_path = os.path.join(FIXTURES_DIR, "npm_vulnerable_lock.json")
    with open(fixture_path, "r") as f:
        content = f.read()

    response = client.post("/api/scan/raw", json={
        "content": content,
        "filename": "package-lock.json",
        "project_name": "api-test"
    })

    assert response.status_code == 200
    data = response.json()
    assert data["manifest_type"] == "npm"
    assert data["summary"]["vulnerable_components"] > 0
    assert len(data["findings"]) > 0

def test_scan_file_upload_endpoint():
    fixture_path = os.path.join(FIXTURES_DIR, "python_vulnerable_reqs.txt")
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/scan/file",
            files={"file": ("requirements.txt", f, "text/plain")},
            data={"project_name": "file-upload-test"}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["manifest_type"] == "pypi"
    assert len(data["findings"]) > 0

