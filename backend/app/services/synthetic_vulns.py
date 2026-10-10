from typing import Dict, List, Optional
from app.core.models import VulnerabilityRecord, CVSSInfo, AffectedRange, RangeEvent

SYNTHETIC_OVERRIDE_PACKAGES = {"cycle-a", "cycle-b"}

def is_synthetic_package(name: str, is_synthetic_flag: bool = False) -> bool:
    """Check if package is a fictional test package or marked for test-only synthetic vulnerability."""
    return is_synthetic_flag or (name.lower() in SYNTHETIC_OVERRIDE_PACKAGES)

def get_synthetic_vulnerabilities(name: str, version: str, is_synthetic_flag: bool = False) -> List[VulnerabilityRecord]:
    """
    Explicit test-only vulnerability overrides for fictional packages cycle-a and cycle-b.
    Prevents trusting coincidental OSV database matches (like MAL-2025-5030).
    """
    pkg = name.lower()

    if pkg == "cycle-a":
        return [
            VulnerabilityRecord(
                id="SYNTH-VULN-CYCLE-A",
                aliases=["CVE-2025-99001"],
                cve_id="CVE-2025-99001",
                summary="Synthetic test advisory: cycle-a ReDoS vulnerability in cyclic fixture",
                details="Deterministic test-only synthetic advisory for cycle-a used to verify cyclic graph traversal.",
                published="2025-01-01T00:00:00Z",
                modified="2025-01-01T00:00:00Z",
                cvss=[
                    CVSSInfo(
                        type="CVSS_V3",
                        score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        base_score=7.5
                    )
                ],
                affected_ranges=[
                    AffectedRange(
                        type="SEMVER",
                        events=[
                            RangeEvent(introduced="1.0.0", fixed="1.0.1")
                        ]
                    )
                ],
                first_fixed_version="1.0.1",
                references=[{"type": "EVIDENCE", "url": "https://patchorder.local/test-override/cycle-a"}],
                source_database="PatchOrder Synthetic Test Registry",
                cwe_id="CWE-400",
                vulnerability_name="Synthetic test advisory: cycle-a ReDoS vulnerability in cyclic fixture",
                vulnerability_type="Uncontrolled Resource Consumption (DoS)"
            )
        ]
    elif pkg == "cycle-b":
        # Only inject if explicitly marked as synthetic vulnerable
        if is_synthetic_flag:
            return [
                VulnerabilityRecord(
                    id="SYNTH-VULN-CYCLE-B",
                    aliases=["CVE-2025-99002"],
                    cve_id="CVE-2025-99002",
                    summary="Synthetic test advisory: cycle-b memory leak vulnerability in cyclic fixture",
                    details="Deterministic test-only synthetic advisory for cycle-b used to verify cyclic graph traversal.",
                    published="2025-01-01T00:00:00Z",
                    modified="2025-01-01T00:00:00Z",
                    cvss=[
                        CVSSInfo(
                            type="CVSS_V3",
                            score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                            base_score=7.5
                        )
                    ],
                    affected_ranges=[
                        AffectedRange(
                            type="SEMVER",
                            events=[
                                RangeEvent(introduced="1.0.0", fixed="1.0.1")
                            ]
                        )
                    ],
                    first_fixed_version="1.0.1",
                    references=[{"type": "EVIDENCE", "url": "https://patchorder.local/test-override/cycle-b"}],
                    source_database="PatchOrder Synthetic Test Registry",
                    cwe_id="CWE-400",
                    vulnerability_name="Synthetic test advisory: cycle-b memory leak vulnerability in cyclic fixture",
                    vulnerability_type="Uncontrolled Resource Consumption (DoS)"
                )
            ]
        return []

    return []

