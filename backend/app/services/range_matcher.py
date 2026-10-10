import re
from typing import List, Dict, Any, Optional, Tuple
from packaging.version import parse as parse_version, InvalidVersion
from app.core.models import VulnerabilityRecord, CVSSInfo, AffectedRange, RangeEvent

class RangeMatcher:
    """
    Evaluates OSV affected ranges and extracts canonical security metadata:
    - CVE aliases and GHSA IDs
    - Earliest fixed version
    - CVSS base score & vector
    - Exact version applicability verification (introduced, fixed, last_affected)
    """

    @staticmethod
    def is_version_affected(installed_version: str, aff_entry: Dict[str, Any]) -> bool:
        """
        Verify whether installed_version is genuinely affected by an OSV affected entry.
        Checks both explicit 'versions' list and 'ranges' events.
        """
        if not installed_version:
            return True

        # Check explicit versions array first if present
        explicit_versions = aff_entry.get("versions", [])
        if explicit_versions:
            if installed_version in explicit_versions:
                return True

        ranges = aff_entry.get("ranges", [])
        if not ranges:
            # If no ranges are defined, rely on explicit_versions result
            return len(explicit_versions) == 0 or (installed_version in explicit_versions)

        try:
            inst_v = parse_version(installed_version)
        except InvalidVersion:
            inst_v = None

        matched_any_range = False
        for r in ranges:
            events = r.get("events", [])
            introduced_v = None
            fixed_v = None
            last_affected_v = None

            for ev in events:
                if "introduced" in ev:
                    try:
                        introduced_v = parse_version(ev["introduced"]) if ev["introduced"] != "0" else None
                    except InvalidVersion:
                        introduced_v = None
                if "fixed" in ev:
                    try:
                        fixed_v = parse_version(ev["fixed"])
                    except InvalidVersion:
                        fixed_v = None
                if "last_affected" in ev:
                    try:
                        last_affected_v = parse_version(ev["last_affected"])
                    except InvalidVersion:
                        last_affected_v = None

            if inst_v is not None:
                # Check lower bound
                if introduced_v is not None and inst_v < introduced_v:
                    continue

                # Check upper bound
                if fixed_v is not None:
                    if inst_v < fixed_v:
                        return True
                    else:
                        continue

                if last_affected_v is not None:
                    if inst_v <= last_affected_v:
                        return True
                    else:
                        continue

                # No upper bound specified in this range -> affected
                return True
            else:
                # String comparison fallback
                return True

        return matched_any_range

    @classmethod
    def extract_vulnerability_record(
        cls,
        vuln_json: Dict[str, Any],
        target_ecosystem: str,
        target_pkg: str,
        target_version: Optional[str] = None
    ) -> Optional[VulnerabilityRecord]:
        vuln_id = vuln_json.get("id", "")
        aliases = vuln_json.get("aliases", [])

        # Primary CVE alias
        cve_id: Optional[str] = None
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        summary = vuln_json.get("summary")
        details = vuln_json.get("details")
        published = vuln_json.get("published")
        modified = vuln_json.get("modified")

        # CVSS extraction
        cvss_list: List[CVSSInfo] = []
        for sev in vuln_json.get("severity", []):
            sev_type = sev.get("type", "")
            score_vector = sev.get("score", "")
            base_score = cls._extract_cvss_base_score(score_vector)
            cvss_list.append(CVSSInfo(type=sev_type, score=score_vector, base_score=base_score))

        # References
        references = [
            {"type": ref.get("type", "WEB"), "url": ref.get("url", "")}
            for ref in vuln_json.get("references", [])
            if "url" in ref
        ]

        # Affected ranges & first fixed version
        affected_ranges: List[AffectedRange] = []
        fixed_versions: List[str] = []
        package_has_match = False
        version_is_affected = False

        for aff in vuln_json.get("affected", []):
            pkg_data = aff.get("package", {})
            pkg_name = pkg_data.get("name", "").lower()
            eco_name = pkg_data.get("ecosystem", "").lower()

            # Filter for this target package if relevant
            if target_pkg.lower() not in (pkg_name, ""):
                continue

            package_has_match = True

            # If target_version is provided, verify applicability
            if target_version:
                if cls.is_version_affected(target_version, aff):
                    version_is_affected = True
            else:
                version_is_affected = True

            for r in aff.get("ranges", []):
                r_type = r.get("type", "ECOSYSTEM")
                events: List[RangeEvent] = []
                for ev in r.get("events", []):
                    introduced = ev.get("introduced")
                    fixed = ev.get("fixed")
                    last_affected = ev.get("last_affected")
                    limit = ev.get("limit")

                    if fixed:
                        fixed_versions.append(fixed)

                    events.append(RangeEvent(
                        introduced=introduced,
                        fixed=fixed,
                        last_affected=last_affected,
                        limit=limit
                    ))
                affected_ranges.append(AffectedRange(type=r_type, events=events))

        # If package was targeted and version was checked but NOT affected, return None
        if target_version and package_has_match and not version_is_affected:
            return None

        # Earliest fixed version
        first_fixed: Optional[str] = None
        if fixed_versions:
            first_fixed = cls._pick_lowest_fix(fixed_versions)

        # Parse identity and CWE type mapping
        from app.services.osv_client import parse_vulnerability_identity
        ident = parse_vulnerability_identity(vuln_json)

        return VulnerabilityRecord(
            id=vuln_id,
            aliases=aliases,
            cve_id=cve_id or (ident["cve_alias"] if ident["cve_alias"] != "No CVE Alias" else None),
            summary=summary,
            details=details,
            published=published,
            modified=modified,
            cvss=cvss_list,
            affected_ranges=affected_ranges,
            first_fixed_version=first_fixed,
            references=references,
            source_database=vuln_json.get("database_specific", {}).get("source"),
            cwe_id=ident.get("cwe_id"),
            vulnerability_name=ident.get("vulnerability_name"),
            vulnerability_type=ident.get("vulnerability_type")
        )

    @staticmethod
    def _extract_cvss_base_score(vector: str) -> Optional[float]:
        """Estimate CVSS base score if vector includes it, or leave None."""
        if not vector:
            return None
        match = re.search(r"(\d+\.\d+)", vector)
        if match:
            try:
                score = float(match.group(1))
                if 0.0 <= score <= 10.0:
                    return score
            except ValueError:
                pass
        return None

    @staticmethod
    def _pick_lowest_fix(fixed_versions: List[str]) -> str:
        """Select the earliest semver fixed version from candidate list."""
        parsed: List[Tuple[Any, str]] = []
        for v in fixed_versions:
            try:
                parsed.append((parse_version(v), v))
            except InvalidVersion:
                parsed.append((parse_version("999999.0"), v))

        if not parsed:
            return fixed_versions[0]
        parsed.sort(key=lambda x: x[0])
        return parsed[0][1]
