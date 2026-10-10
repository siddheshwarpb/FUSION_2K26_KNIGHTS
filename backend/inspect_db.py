#!/usr/bin/env python3
"""
Interactive SQLite database inspector for PatchOrder.
Usage:
  backend/venv/bin/python3 backend/inspect_db.py
  backend/venv/bin/python3 backend/inspect_db.py --pkg lodash
  backend/venv/bin/python3 backend/inspect_db.py --scans
"""

import sqlite3
import json
import sys
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "patchorder_cache.db")

def get_connection():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def show_overview():
    conn = get_connection()
    c = conn.cursor()
    print("=" * 70)
    print(f"  PATCHORDER SQLITE DATABASE OVERVIEW")
    print(f"  Location: {DB_PATH}")
    print("=" * 70)

    c.execute("SELECT count(*) as cnt FROM package_queries")
    pkg_count = c.fetchone()["cnt"]

    c.execute("SELECT count(*) as cnt FROM vulnerability_details")
    vuln_count = c.fetchone()["cnt"]

    c.execute("SELECT count(*) as cnt FROM scan_logs")
    scan_count = c.fetchone()["cnt"]

    print(f"\nTables Summary:")
    print(f"  1. package_queries:       {pkg_count} cached package coordinates")
    print(f"  2. vulnerability_details: {vuln_count} full OSV vulnerability advisories")
    print(f"  3. scan_logs:             {scan_count} recorded project scan executions\n")

    print("-" * 70)
    print("  Recent 5 Scan Runs (from scan_logs):")
    print("-" * 70)
    c.execute("""
        SELECT project_name, manifest_type, total_components, vulnerable_components, duration_ms, scanned_at
        FROM scan_logs ORDER BY scanned_at DESC LIMIT 5
    """)
    rows = c.fetchall()
    for r in rows:
        print(f"  • {r['project_name']} ({r['manifest_type']}) | Components: {r['total_components']} (Vulnerable: {r['vulnerable_components']}) | Latency: {r['duration_ms']}ms | At: {r['scanned_at'][:19]}")

    print("\n" + "-" * 70)
    print("  Sample Cached Vulnerable Packages (from package_queries):")
    print("-" * 70)
    c.execute("""
        SELECT ecosystem, name, version, vuln_ids_json, retrieved_at
        FROM package_queries WHERE vuln_ids_json != '[]' LIMIT 5
    """)
    for r in c.fetchall():
        ids = json.loads(r["vuln_ids_json"])
        print(f"  • {r['name']}@{r['version']} ({r['ecosystem']}) -> {len(ids)} advisories: {ids[:3]}")

    print("\n" + "=" * 70)
    print("Tip: Run with --pkg <name> to see specific package advisories in detail.")
    print("=" * 70)

def search_package(name: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT ecosystem, name, version, vuln_ids_json, retrieved_at FROM package_queries WHERE name LIKE ?", (f"%{name}%",))
    rows = c.fetchall()
    if not rows:
        print(f"No cached packages found matching '{name}'.")
        return

    print(f"\nFound {len(rows)} cached entries matching '{name}':")
    for r in rows:
        ids = json.loads(r["vuln_ids_json"])
        print(f"\nPackage: {r['name']}@{r['version']} ({r['ecosystem']})")
        print(f"Retrieved at: {r['retrieved_at']}")
        print(f"Matching Vulnerability IDs ({len(ids)}): {ids}")

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--pkg":
        search_package(sys.argv[2])
    else:
        show_overview()

