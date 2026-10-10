#!/usr/bin/env python3
"""
Example demonstrating the 3-step OSV API integration and the normalized scan pipeline.
Can be executed directly: python3 backend/example_usage.py
"""

import sys
import os
import asyncio
import json

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.osv_client import OsvClient
from app.services.vulnerability_engine import VulnerabilityEngine
from app.services.range_matcher import RangeMatcher

def print_section(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

async def main():
    osv = OsvClient()
    engine = VulnerabilityEngine()

    # --------------------------------------------------------------------------
    # 1. OSV API — Query by version (Start here)
    # --------------------------------------------------------------------------
    print_section("1. OSV API — Query by version (POST /v1/query)")
    pkg_name = "jinja2"
    eco = "PyPI"
    ver = "2.11.2"
    print(f"Testing single package query: {pkg_name}@{ver} ({eco})...\n")

    single_res = await osv.query_version(ecosystem=eco, name=pkg_name, version=ver)
    vulns = single_res.get("vulns", [])
    print(f"✓ Found {len(vulns)} vulnerabilities for {pkg_name}@{ver}")

    if vulns:
        sample_vuln = RangeMatcher.extract_vulnerability_record(vulns[0], eco, pkg_name)
        print("\nNormalized First Finding:")
        print(f"  ID:            {sample_vuln.id}")
        print(f"  CVE Aliases:   {sample_vuln.aliases}")
        print(f"  Summary:       {sample_vuln.summary}")
        print(f"  Fixed Version: {sample_vuln.first_fixed_version}")

    # --------------------------------------------------------------------------
    # 2. OSV API — Batch query (Main integration)
    # --------------------------------------------------------------------------
    print_section("2. OSV API — Batch query (POST /v1/querybatch)")
    batch_queries = [
        ("npm", "lodash", "4.17.15"),
        ("npm", "axios", "0.21.1"),
        ("PyPI", "colorama", "0.4.6"),  # clean package
    ]
    print(f"Submitting batch query for {len(batch_queries)} packages...")
    for eco, name, v in batch_queries:
        print(f"  - {name}@{v} ({eco})")

    batch_res = await osv.query_batch_direct(batch_queries)
    print("\nBatch Query Results:")
    for idx, (eco, name, v) in enumerate(batch_queries):
        v_count = len(batch_res[idx].get("vulns", [])) if idx < len(batch_res) else 0
        print(f"  • {name}@{v}: {v_count} vulnerability matches")

    # --------------------------------------------------------------------------
    # 3. Fetch full vulnerability details (GET /v1/vulns/{id})
    # --------------------------------------------------------------------------
    print_section("3. Fetch full vulnerability details (GET /v1/vulns/{id})")
    sample_id = "GHSA-35jh-r3h4-6jhm"
    print(f"Fetching full advisory for {sample_id}...\n")
    detail = await osv.get_vuln_detail_by_id(sample_id)
    if detail:
        print(f"  ID:          {detail.get('id')}")
        print(f"  Summary:     {detail.get('summary')}")
        print(f"  Aliases:     {detail.get('aliases')}")
        print(f"  Published:   {detail.get('published')}")
        print(f"  Modified:    {detail.get('modified')}")
        print(f"  References:  {len(detail.get('references', []))} links available")

    # --------------------------------------------------------------------------
    # 4. End-to-End Pipeline: Normalized Scan (Exact Recommended Schema)
    # --------------------------------------------------------------------------
    print_section("4. End-to-End Pipeline: Normalized Scan (Exact User Schema)")
    package_json_content = json.dumps({
        "name": "payment-api",
        "dependencies": {
            "lodash": "4.17.15",
            "axios": "0.21.1"
        }
    })

    print("Scanning project 'payment-api' with manifest 'package.json'...\n")
    scan_output = await engine.scan_normalized(
        content=package_json_content,
        filename="package.json",
        project_name="payment-api"
    )

    # Format JSON
    formatted_json = json.dumps(scan_output.model_dump(), indent=2)
    # Print the first 50 lines of formatted json
    lines = formatted_json.splitlines()
    print("\n".join(lines[:45]))
    if len(lines) > 45:
        print(f"  ... [+{len(lines) - 45} more lines of findings]")

    # --------------------------------------------------------------------------
    # 5. Clean Scan Demo (Zero findings)
    # --------------------------------------------------------------------------
    print_section("5. Clean Scan Demo (Zero findings)")
    clean_reqs = "colorama==0.4.6"
    clean_output = await engine.scan_normalized(
        content=clean_reqs,
        filename="requirements.txt",
        project_name="clean-service"
    )
    print(json.dumps(clean_output.model_dump(), indent=2))

if __name__ == "__main__":
    asyncio.run(main())

