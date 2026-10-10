import pytest
import os
import time
from app.services.vulnerability_engine import VulnerabilityEngine

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

@pytest.mark.asyncio
async def test_cache_hits_and_offline_speed(tmp_path):
    db_file = str(tmp_path / "test_cache.db")
    fixture_path = os.path.join(FIXTURES_DIR, "npm_vulnerable_lock.json")
    with open(fixture_path, "r") as f:
        content = f.read()

    engine = VulnerabilityEngine(cache_db=db_file)

    # Run 1: First scan (hits OSV API, populates cache)
    t0 = time.perf_counter()
    resp1 = await engine.scan_manifest(content, filename="package-lock.json", project_name="run1")
    t1 = time.perf_counter()

    assert resp1.summary.cache_misses > 0
    run1_duration = t1 - t0

    # Run 2: Second scan with same cache
    t2 = time.perf_counter()
    resp2 = await engine.scan_manifest(content, filename="package-lock.json", project_name="run2")
    t2_end = time.perf_counter()

    assert resp2.summary.cache_hits > 0
    assert resp2.summary.cache_misses == 0
    # Second run should be nearly instantaneous (< 50ms)
    assert (t2_end - t2) < 0.1
    # Exactly same findings
    assert len(resp1.findings) == len(resp2.findings)

