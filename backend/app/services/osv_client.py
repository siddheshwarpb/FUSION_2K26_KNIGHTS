import asyncio
import logging
from typing import List, Dict, Any, Tuple, Optional
import httpx
from app.core.cache import EvidenceCache
from app.core.models import VulnerabilityRecord
from app.services.range_matcher import RangeMatcher

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
BATCH_CHUNK_SIZE = 500

import re

CWE_TYPE_MAP: Dict[str, str] = {
    "CWE-1321": "Prototype Pollution",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection (RCE)",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-22": "Path Traversal",
    "CWE-23": "Path Traversal",
    "CWE-502": "Insecure Deserialization",
    "CWE-400": "Denial of Service (DoS)",
    "CWE-1333": "Denial of Service (DoS)",
    "CWE-94": "Code Injection",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-287": "Authentication Bypass",
    "CWE-306": "Authentication Bypass",
    "CWE-200": "Information Disclosure",
    "CWE-119": "Memory Corruption",
    "CWE-120": "Memory Corruption",
    "CWE-125": "Memory Corruption",
    "CWE-787": "Memory Corruption",
    "CWE-20": "Improper Input Validation",
    "CWE-269": "Improper Privilege Management",
}

SUMMARY_CLASSIFIERS = [
    (re.compile(r"\bprototype\s+pollution\b", re.I), "Prototype Pollution"),
    (re.compile(r"\bos\s+command\s+injection\b", re.I), "OS Command Injection (RCE)"),
    (re.compile(r"\bcommand\s+injection\b", re.I), "Command Injection"),
    (re.compile(r"\bcross-site\s+scripting\b|\bxss\b", re.I), "Cross-Site Scripting (XSS)"),
    (re.compile(r"\bsql\s+injection\b", re.I), "SQL Injection"),
    (re.compile(r"\bpath\s+traversal\b|\bdirectory\s+traversal\b", re.I), "Path Traversal"),
    (re.compile(r"\bremote\s+code\s+execution\b|\b(?<![a-z])rce(?![a-z])\b", re.I), "Remote Code Execution (RCE)"),
    (re.compile(r"\bcode\s+injection\b", re.I), "Code Injection"),
    (re.compile(r"\bserver-side\s+request\s+forgery\b|\b(?<![a-z])ssrf(?![a-z])\b", re.I), "Server-Side Request Forgery (SSRF)"),
    (re.compile(r"\binsecure\s+deserialization\b", re.I), "Insecure Deserialization"),
    (re.compile(r"\bdenial\s+of\s+service\b|\bredos\b|\b(?<![a-z])dos(?![a-z])\b", re.I), "Denial of Service (DoS)"),
    (re.compile(r"\bauthentication\s+bypass\b|\bauth\s+bypass\b", re.I), "Authentication Bypass"),
    (re.compile(r"\bmemory\s+corruption\b|\bbuffer\s+overflow\b|\bout-of-bounds\b|\buse-after-free\b", re.I), "Memory Corruption"),
    (re.compile(r"\binformation\s+disclosure\b|\bsensitive\s+data\s+exposure\b|\binformation\s+exposure\b", re.I), "Information Disclosure"),
    (re.compile(r"\bprivilege\s+escalation\b|\bimproper\s+privilege\b", re.I), "Improper Privilege Management"),
    (re.compile(r"\binput\s+validation\b", re.I), "Improper Input Validation"),
]

def parse_vulnerability_identity(osv_item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses raw OSV vulnerability items and maps identifiers to human-readable
    flaw titles and CWE weakness type names.
    
    Returns:
        {
            "unique_id": primary_id,
            "cve_alias": cve_id,
            "cwe_id": primary_cwe,
            "vulnerability_name": vulnerability_title,
            "vulnerability_type": vulnerability_type_name
        }
    """
    if not isinstance(osv_item, dict):
        return {
            "unique_id": "UNKNOWN-ID",
            "cve_alias": "No CVE Alias",
            "cwe_id": None,
            "vulnerability_name": "Unclassified Security Flaw",
            "vulnerability_type": "Unclassified"
        }

    # 1. Primary ID (fallback "UNKNOWN-ID")
    primary_id = osv_item.get("id") or "UNKNOWN-ID"

    # 2. Aliases array -> cve_id (fallback "No CVE Alias")
    aliases = osv_item.get("aliases") or []
    cve_id = "No CVE Alias"
    if aliases:
        cve_candidate = next((a for a in aliases if isinstance(a, str) and a.startswith("CVE-")), aliases[0])
        cve_id = cve_candidate if cve_candidate else "No CVE Alias"
    elif osv_item.get("cve_id"):
        cve_id = osv_item.get("cve_id")

    # 3. Summary as vulnerability_title (fallback "Unclassified Security Flaw")
    raw_summary = osv_item.get("summary") or osv_item.get("details") or osv_item.get("title")
    if raw_summary and str(raw_summary).strip():
        vulnerability_title = str(raw_summary).strip()
    else:
        vulnerability_title = "Unclassified Security Flaw"

    # Explicit category provided upstream
    if osv_item.get("vulnerability_type") and osv_item["vulnerability_type"] not in ["General Security Weakness", "Unclassified"]:
        vulnerability_type_name = osv_item["vulnerability_type"]
        primary_cwe = osv_item.get("cwe_id")
    else:
        # 4. database_specific.cwe_ids -> primary_cwe
        db_specific = osv_item.get("database_specific")
        if not isinstance(db_specific, dict):
            db_specific = {}
        cwe_ids = db_specific.get("cwe_ids") or osv_item.get("cwe_ids") or []
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]
        
        primary_cwe = cwe_ids[0] if cwe_ids and len(cwe_ids) > 0 else (osv_item.get("cwe_id") or None)

        # 5. Look up primary_cwe in CWE_TYPE_MAP
        if primary_cwe and primary_cwe in CWE_TYPE_MAP:
            vulnerability_type_name = CWE_TYPE_MAP[primary_cwe]
        else:
            # 6. Conservative summary-based classification
            matched_cat = None
            if raw_summary:
                for pattern, cat in SUMMARY_CLASSIFIERS:
                    if pattern.search(str(raw_summary)):
                        matched_cat = cat
                        break
            vulnerability_type_name = matched_cat or "Unclassified"

    return {
        "unique_id": primary_id,
        "cve_alias": cve_id,
        "cwe_id": primary_cwe,
        "vulnerability_name": vulnerability_title,
        "vulnerability_type": vulnerability_type_name
    }


class OsvClient:
    """
    High-performance, async client for the Open Source Vulnerabilities (OSV) API.
    Features:
    - Step 1: Query by version via /v1/query
    - Step 2: Bulk batch queries via /v1/querybatch
    - Step 3: Advisory detail retrieval via /v1/vulns/{id}
    - Tiered local SQLite caching (zero network calls for cached dependencies)
    - Full record provenance and modified-timestamp tracking
    """

    def __init__(self, cache: Optional[EvidenceCache] = None, timeout: float = 30.0):
        self.cache = cache or EvidenceCache()
        self.timeout = timeout

    async def query_version(self, ecosystem: str, name: str, version: str) -> Dict[str, Any]:
        """
        Step 1: Query OSV by exact package version using POST /v1/query.
        Simplest way to test integration with a single package and version.
        """
        payload = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": version
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(OSV_QUERY_URL, json=payload)
            if resp.status_code == 200:
                return resp.json()
            else:
                raise RuntimeError(f"OSV query error ({resp.status_code}): {resp.text}")

    async def query_commit(self, commit_sha: str) -> Dict[str, Any]:
        """
        Query OSV by exact Git commit SHA using POST /v1/query with {"commit": "<SHA>"}.
        Returns dict containing 'vulns' list if matches found.
        """
        payload = {"commit": commit_sha}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(OSV_QUERY_URL, json=payload)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 400:
                logger.warning(f"OSV returned 400 for commit {commit_sha} (likely invalid or untracked)")
                return {"vulns": []}
            else:
                raise RuntimeError(f"OSV commit query error ({resp.status_code}): {resp.text}")

    async def query_batch_direct(self, queries: List[Tuple[str, str, str]]) -> List[Dict[str, Any]]:
        """
        Step 2: Batch query using POST /v1/querybatch.
        Submits multiple package/version queries in a single request.
        """
        payload = {
            "queries": [
                {"package": {"name": name, "ecosystem": eco}, "version": ver}
                for eco, name, ver in queries
            ]
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(OSV_BATCH_URL, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("results", [])
            else:
                raise RuntimeError(f"OSV batch query error ({resp.status_code}): {resp.text}")

    async def get_vuln_detail_by_id(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """
        Step 3: Fetch full vulnerability details using GET /v1/vulns/{id}.
        """
        # Check cache first
        cached = self.cache.get_vuln_detail(vuln_id)
        if cached:
            return cached

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{OSV_VULN_URL}/{vuln_id}")
            if resp.status_code == 200:
                data = resp.json()
                self.cache.set_vuln_detail(vuln_id, data)
                return data
            elif resp.status_code == 404:
                return None
            else:
                raise RuntimeError(f"OSV vuln lookup error ({resp.status_code}): {resp.text}")


    async def verify_packages(
        self,
        package_coords: List[Tuple[str, str, str]] # (ecosystem, name, version)
    ) -> Tuple[Dict[Tuple[str, str, str], List[VulnerabilityRecord]], int, int]:
        """
        Verify a list of package coordinates against OSV.
        Returns:
            - Dict mapping (ecosystem, name, version) -> List[VulnerabilityRecord]
            - cache_hits count
            - cache_misses count
        """
        results: Dict[Tuple[str, str, str], List[VulnerabilityRecord]] = {}
        uncached: List[Tuple[str, str, str]] = []
        cache_hits = 0
        cache_misses = 0

        # Step 1: Check local cache
        cached_vuln_ids_map: Dict[Tuple[str, str, str], List[str]] = {}
        all_needed_vuln_ids: set[str] = set()

        for coord in package_coords:
            eco, name, ver = coord
            cached_ids = self.cache.get_package_vulns(eco, name, ver)
            if cached_ids is not None:
                cache_hits += 1
                cached_vuln_ids_map[coord] = cached_ids
                all_needed_vuln_ids.update(cached_ids)
            else:
                cache_misses += 1
                uncached.append(coord)

        # Step 2: Query OSV querybatch for uncached coordinates
        if uncached:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for i in range(0, len(uncached), BATCH_CHUNK_SIZE):
                    chunk = uncached[i:i + BATCH_CHUNK_SIZE]
                    batch_payload = {
                        "queries": [
                            {"package": {"name": name, "ecosystem": eco}, "version": ver}
                            for eco, name, ver in chunk
                        ]
                    }

                    try:
                        resp = await client.post(OSV_BATCH_URL, json=batch_payload)
                        if resp.status_code == 200:
                            data = resp.json()
                            batch_results = data.get("results", [])
                            for idx, item in enumerate(batch_results):
                                coord = chunk[idx]
                                raw_vulns = item.get("vulns", [])
                                vuln_ids = [v["id"] for v in raw_vulns if "id" in v]

                                cached_vuln_ids_map[coord] = vuln_ids
                                all_needed_vuln_ids.update(vuln_ids)

                                # Store into cache
                                self.cache.set_package_vulns(
                                    coord[0], coord[1], coord[2], vuln_ids, resp.text
                                )
                        else:
                            logger.error(f"OSV batch query failed: {resp.status_code} - {resp.text}")
                    except Exception as e:
                        logger.error(f"OSV network error during batch query: {str(e)}")

        # Step 3: Fetch full vulnerability details for affected packages
        vuln_details_map = await self._fetch_vuln_details(list(all_needed_vuln_ids))

        # Step 4: Assemble VulnerabilityRecord objects for each coordinate
        for coord, vuln_ids in cached_vuln_ids_map.items():
            eco, name, ver = coord
            rec_list: List[VulnerabilityRecord] = []
            for vid in vuln_ids:
                raw_detail = vuln_details_map.get(vid)
                if raw_detail:
                    rec = RangeMatcher.extract_vulnerability_record(raw_detail, eco, name, ver)
                    if rec:
                        rec_list.append(rec)
            results[coord] = rec_list



        return results, cache_hits, cache_misses

    async def _fetch_vuln_details(self, vuln_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Fetch full vulnerability JSON from cache or OSV /v1/vulns/{id}."""
        details: Dict[str, Dict[str, Any]] = {}
        missing_ids: List[str] = []

        for vid in vuln_ids:
            cached_data = self.cache.get_vuln_detail(vid)
            if cached_data:
                details[vid] = cached_data
            else:
                missing_ids.append(vid)

        if not missing_ids:
            return details

        # Fetch missing in parallel with semaphore
        semaphore = asyncio.Semaphore(15)

        async def fetch_one(client: httpx.AsyncClient, vid: str):
            async with semaphore:
                try:
                    resp = await client.get(f"{OSV_VULN_URL}/{vid}")
                    if resp.status_code == 200:
                        data = resp.json()
                        details[vid] = data
                        self.cache.set_vuln_detail(vid, data)
                except Exception as e:
                    logger.error(f"Failed to fetch vulnerability detail for {vid}: {str(e)}")

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            tasks = [fetch_one(client, vid) for vid in missing_ids]
            await asyncio.gather(*tasks)

        return details

