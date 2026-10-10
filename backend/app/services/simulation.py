from typing import List, Dict, Any, Set
from packaging.version import parse as parse_version, InvalidVersion
from app.core.models import (
    VulnerableFinding,
    PatchRecommendation,
    SimulationPatchAction,
    SimulationDiff,
    SimulationResponse,
    CytoscapeGraph
)
from app.services.remediation import RemediationEngine

class SimulationEngine:
    """
    Counterfactual Patch Simulator.
    Simulates target version upgrades on the dependency tree and recomputes:
    - Findings resolved vs remaining
    - Risk reduction delta
    - Next recommended patch in the remediation queue
    - Simulated Cytoscape graph with resolved nodes marked in green
    """

    @classmethod
    def simulate_patches(
        cls,
        analysis_id: str,
        current_findings: List[VulnerableFinding],
        all_components: list,
        applied_patches: List[SimulationPatchAction],
        cytoscape_builder_fn
    ) -> SimulationResponse:
        patch_map: Dict[str, str] = {p.package: p.target_version for p in applied_patches}

        resolved_vuln_ids: List[str] = []
        remaining_findings: List[VulnerableFinding] = []

        total_risk_before = sum(f.priority_score for f in current_findings)
        affected_roots_before = set()
        for f in current_findings:
            affected_roots_before.update(f.root_dependents)

        for finding in current_findings:
            pkg_name = finding.component.name
            if pkg_name in patch_map:
                target_ver = patch_map[pkg_name]
                # Check if target_ver resolves this advisory
                if cls._is_fixed_by(finding, target_ver):
                    resolved_vuln_ids.append(finding.vulnerability.id)
                    continue

            remaining_findings.append(finding)

        total_risk_after = sum(f.priority_score for f in remaining_findings)
        risk_reduction = max(0.0, total_risk_before - total_risk_after)
        risk_reduction_pct = round((risk_reduction / total_risk_before * 100.0), 1) if total_risk_before > 0 else 100.0

        affected_roots_after = set()
        for f in remaining_findings:
            affected_roots_after.update(f.root_dependents)

        # Generate next recommended patch on remaining findings
        simulated_patch_plan = RemediationEngine.generate_patch_plan(remaining_findings, all_components)
        new_top_patch = simulated_patch_plan[0] if simulated_patch_plan else None

        remaining_high_priority = sum(1 for f in remaining_findings if f.priority_tier in ("CRITICAL_URGENT", "CRITICAL", "HIGH"))

        diff = SimulationDiff(
            findings_before_count=len(current_findings),
            findings_after_count=len(remaining_findings),
            resolved_findings_count=len(resolved_vuln_ids),
            resolved_vuln_ids=resolved_vuln_ids,
            risk_before=round(total_risk_before, 1),
            risk_after=round(total_risk_after, 1),
            risk_reduction_pct=risk_reduction_pct,
            affected_roots_before=len(affected_roots_before),
            affected_roots_after=len(affected_roots_after),
            new_top_patch=new_top_patch,
            remaining_high_priority_count=remaining_high_priority
        )

        # Build simulated Cytoscape graph
        simulated_graph = cytoscape_builder_fn(
            all_components, remaining_findings, resolved_vuln_ids=set(resolved_vuln_ids)
        )

        return SimulationResponse(
            analysis_id=analysis_id,
            is_simulated=True,
            applied_patches=applied_patches,
            diff=diff,
            simulated_graph=simulated_graph,
            remaining_findings=remaining_findings
        )

    @classmethod
    def _is_fixed_by(cls, finding: VulnerableFinding, target_ver: str) -> bool:
        """
        Validate that target_ver is a valid upgrade that resolves the finding.
        Requires target_ver > current_version and target_ver >= fixed_version.
        """
        fixed_ver = finding.vulnerability.first_fixed_version
        curr_ver = finding.component.version
        if not fixed_ver or not target_ver:
            return False

        try:
            targ_p = parse_version(target_ver)
            fix_p = parse_version(fixed_ver)
            curr_p = parse_version(curr_ver)

            # Must be a forward upgrade and satisfy the advisory fixed threshold
            return targ_p > curr_p and targ_p >= fix_p
        except InvalidVersion:
            return target_ver != curr_ver and target_ver == fixed_ver


