import json
from datetime import datetime
from typing import Dict, Any
from app.core.models import AnalysisRecord

class ReportGenerator:
    """
    Generates auditable Markdown and JSON reports for PatchOrder analyses.
    """

    @classmethod
    def generate_markdown(cls, record: AnalysisRecord) -> str:
        s = record.summary
        md = []
        md.append(f"# PatchOrder Supply-Chain Security & Remediation Report")
        md.append(f"**Project:** `{record.project_name}`  ")
        md.append(f"**Analysis ID:** `{record.analysis_id}`  ")
        md.append(f"**Scanned at:** {record.created_at}  ")
        md.append(f"**Environment:** `{record.environment}` | **Exposure:** `{record.exposure}` | **Criticality:** `{record.criticality}`  ")
        md.append(f"**Manifest Type:** `{record.manifest_type}` ({record.resolution_status})  ")
        if record.repository_url:
            md.append(f"**Repository:** `{record.repository_url}`  ")
        if record.commit_sha:
            md.append(f"**Scanned Commit SHA:** `{record.commit_sha}`  ")
        if record.manifests_detected:
            md.append(f"**Detected Manifests:** `{', '.join(record.manifests_detected)}`  ")
        if record.coverage_status:
            md.append(f"**Coverage Status:** `{record.coverage_status}`  ")
        md.append("\n---\n")

        # Executive Summary
        md.append("## 1. Executive Summary\n")
        if record.commit_sha:
            md.append(f"- **Scanned Commit:** `{record.commit_sha[:10]}` (Method: `{record.analysis_method}`)")
        md.append(f"- **Total Components Scanned:** {s.total_components} ({s.direct_components} direct, {s.transitive_components} transitive)")

        md.append(f"- **Vulnerable Components:** {s.vulnerable_components} (Unique packages: {s.affected_packages_count}, Instances: {s.affected_instances_count})")
        md.append(f"- **Total Vulnerability Advisories:** {s.total_vulnerabilities} (Raw records: {s.advisory_records_count}, Distinct vulnerability groups: {s.distinct_vulnerabilities_count})")
        md.append(f"- **Confirmed CISA KEV Exploitations:** **{s.kev_matches}**")
        md.append(f"- **Cyclic Dependencies (Tarjan SCC):** {s.cyclic_components_count} components")
        if s.vulnerable_cycle_components:
            md.append(f"- **Vulnerable Cycle Members:** {', '.join(s.vulnerable_cycle_components)}")
        md.append(f"- **High/Critical Priority Findings:** {s.high_priority_findings}")
        md.append(f"- **Analysis Latency:** {s.scan_duration_ms} ms (Cache hits: {s.cache_hits})\n")


        # Remediation Plan
        md.append("## 2. Ranked Patch Plan (Risk Removed per Change Cost)\n")
        md.append("PatchOrder ranks fixes by **marginal risk removed per estimated change cost**, prioritizing KEV matches and blast-radius reach.\n")
        md.append("| Rank | Package | Current | Target Fix | Risk Removed | Est. Cost | Marginal Value | Why Now |")
        md.append("|---|---|---|---|---|---|---|---|")
        for p in record.patch_plan:
            md.append(f"| **#{p.rank}** | `{p.package}` | `{p.current_version}` | **`{p.target_version}`** | {p.estimated_risk_removed} pts | {p.estimated_change_cost} | **{p.marginal_value}** | {p.why_now} |")
        md.append("\n")

        # Findings Detail Table
        md.append("## 3. Verified Vulnerabilities & Propagation Paths\n")
        md.append("| Package | Version | Type | Advisory ID | CVE | Score | Tier | Propagation Path |")
        md.append("|---|---|---|---|---|---|---|---|")
        for f in record.findings:
            cve_str = f.vulnerability.cve_id or "-"
            path_str = " -> ".join([p.split("/")[-1].split("@")[0] for p in f.propagation_paths_to_root[0]]) if f.propagation_paths_to_root else "Direct"
            md.append(f"| `{f.component.name}` | `{f.component.version}` | { 'Direct' if f.is_direct else 'Transitive' } | `{f.vulnerability.id}` | `{cve_str}` | {f.priority_score} | `{f.priority_tier}` | `{path_str}` |")
        md.append("\n")

        # Risk Prioritization Method
        md.append("## 4. Prioritization Method & Formula\n")
        md.append("Findings are prioritized using the transparent CSB-03 policy formula:")
        md.append("```text\nP(v) = 100 * (0.35*K + 0.25*E + 0.20*C + 0.10*X + 0.10*R) / (observed_weights)\n```")
        md.append("- **K**: CISA KEV exploitation signal (0.35)")
        md.append("- **E**: FIRST EPSS 30-day forecast probability (0.25)")
        md.append("- **C**: Normalized CVSS base severity (0.20)")
        md.append("- **X**: Declared project exposure context (0.10)")
        md.append("- **R**: Graph propagation reach proxy (0.10)\n")

        # Uncertainties and Disclaimer
        md.append("## 5. Audit Boundaries & Disclaimer\n")
        md.append("> **Important:** PatchOrder estimates potential impact and prioritization from graph propagation, OSV intelligence, and declared context. It does not prove runtime exploitability, nor does it guarantee that simulated updates are free from regressions without testing.")

        return "\n".join(md)

    @classmethod
    def generate_json(cls, record: AnalysisRecord) -> str:
        return json.dumps(record.model_dump(), indent=2)

