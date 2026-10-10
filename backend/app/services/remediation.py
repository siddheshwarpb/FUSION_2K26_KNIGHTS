import re
from typing import List, Dict, Set, Any, Optional
from packaging.version import parse as parse_version, InvalidVersion
from app.core.models import VulnerableFinding, PatchRecommendation, ComponentNode

class RemediationEngine:
    """
    Implements Section 8: Patch-Order Algorithm.
    Generates candidate patches, evaluates change cost, and computes greedy
    marginal risk removed per change cost ranking.
    """

    @classmethod
    def generate_patch_plan(
        cls,
        findings: List[VulnerableFinding],
        all_components: List[ComponentNode]
    ) -> List[PatchRecommendation]:
        if not findings:
            return []

        comp_by_name: Dict[str, ComponentNode] = {c.name: c for c in all_components}

        # Group findings by package name
        findings_by_pkg: Dict[str, List[VulnerableFinding]] = {}
        for f in findings:
            findings_by_pkg.setdefault(f.component.name, []).append(f)

        candidates: List[Dict[str, Any]] = []

        for pkg_name, pkg_findings in findings_by_pkg.items():
            comp = pkg_findings[0].component
            curr_version = comp.version
            ecosystem = comp.ecosystem

            # Collect fixed versions from all advisories for this package
            all_fixes: Set[str] = set()
            no_fix_ids: List[str] = []

            for f in pkg_findings:
                fix = f.vulnerability.first_fixed_version
                if fix:
                    all_fixes.add(fix)
                else:
                    no_fix_ids.append(f.vulnerability.id)

            if not all_fixes:
                target_version = "No known fixed version"
                fixes_available = False
            else:
                target_version = cls._pick_safest_highest_fix(list(all_fixes), curr_version)
                fixes_available = True

            # Calculate change cost heuristic
            cost, cost_breakdown = cls._calculate_change_cost(curr_version, target_version, comp.is_direct)

            # Sum of risk removed P(v) for resolved findings
            resolved_finding_ids = [f.vulnerability.id for f in pkg_findings if f.vulnerability.first_fixed_version]
            risk_removed = sum(f.priority_score for f in pkg_findings if f.vulnerability.id in resolved_finding_ids)

            # Downstream root dependents
            affected_roots = set()
            for f in pkg_findings:
                for r in f.root_dependents:
                    affected_roots.add(r.split("/")[-1].split("@")[0])

            # Marginal value
            marginal_val = round(risk_removed / cost, 2) if cost > 0 else 0.0

            # Collect evidence references
            evidence_urls = []
            for f in pkg_findings:
                for ref in f.vulnerability.references[:3]:
                    if "url" in ref:
                        evidence_urls.append(ref["url"])

            # Generate explainable "Why Now?" statement
            has_kev = any(f.vulnerability.in_kev for f in pkg_findings)
            why_now = cls._build_why_now_explanation(
                pkg_name, curr_version, target_version, len(resolved_finding_ids),
                has_kev, len(affected_roots), cost, marginal_val
            )

            remaining_risks = [f"Unresolved advisory {vid} (no fix upstream)" for vid in no_fix_ids]

            candidates.append({
                "package": pkg_name,
                "ecosystem": ecosystem,
                "current_version": curr_version,
                "target_version": target_version,
                "findings_removed": resolved_finding_ids,
                "findings_introduced": [],
                "affected_project_roots": sorted(list(affected_roots)),
                "estimated_risk_removed": round(risk_removed, 1),
                "estimated_change_cost": cost,
                "marginal_value": marginal_val,
                "why_now": why_now,
                "cost_breakdown": cost_breakdown,
                "remaining_risks": remaining_risks,
                "evidence_urls": list(set(evidence_urls))[:5],
                "has_kev": has_kev,
                "fixes_available": fixes_available
            })

        # Sort candidates using greedy tie-breakers:
        # 1. Has KEV exploitation match
        # 2. Marginal value (risk removed / cost)
        # 3. Fixes available vs none
        candidates.sort(
            key=lambda c: (
                1 if c["has_kev"] else 0,
                1 if c["fixes_available"] else 0,
                c["marginal_value"],
                c["estimated_risk_removed"]
            ),
            reverse=True
        )

        ranked_plan: List[PatchRecommendation] = []
        for idx, cand in enumerate(candidates, start=1):
            cand_copy = dict(cand)
            del cand_copy["has_kev"]
            del cand_copy["fixes_available"]
            ranked_plan.append(PatchRecommendation(rank=idx, **cand_copy))

        return ranked_plan

    @staticmethod
    def _calculate_change_cost(curr_ver: str, target_ver: str, is_direct: bool) -> tuple[float, Dict[str, Any]]:
        """
        Change-cost heuristic:
        cost = 1 + 0.5 * major_jump + 0.3 * direct_dependency + 0.2 * unknown_test_impact
        """
        major_jump = 0.0
        try:
            curr_p = parse_version(curr_ver)
            targ_p = parse_version(target_ver)
            if hasattr(curr_p, "major") and hasattr(targ_p, "major"):
                if curr_p.major != targ_p.major:
                    major_jump = 1.0
        except Exception:
            # Fallback regex
            m_curr = re.match(r"^(\d+)", curr_ver)
            m_targ = re.match(r"^(\d+)", target_ver)
            if m_curr and m_targ and m_curr.group(1) != m_targ.group(1):
                major_jump = 1.0

        direct_dep = 1.0 if is_direct else 0.0
        unknown_test = 1.0 # 0.2 term for unknown test coverage

        base_cost = 1.0 + (0.5 * major_jump) + (0.3 * direct_dep) + (0.2 * unknown_test)
        base_cost = round(base_cost, 2)

        breakdown = {
            "base": 1.0,
            "major_jump_penalty": 0.5 * major_jump,
            "direct_dependency_penalty": 0.3 * direct_dep,
            "test_uncertainty_penalty": 0.2 * unknown_test,
            "total_estimated_cost": base_cost
        }
        return base_cost, breakdown

    @staticmethod
    def _pick_safest_highest_fix(fixed_versions: List[str], current_ver: str) -> str:
        """Pick the earliest fixed version that addresses all vulnerabilities."""
        parsed = []
        for f in fixed_versions:
            try:
                parsed.append((parse_version(f), f))
            except InvalidVersion:
                parsed.append((parse_version("999999.0"), f))
        parsed.sort(key=lambda x: x[0], reverse=True)
        return parsed[0][1] if parsed else fixed_versions[0]

    @staticmethod
    def _build_why_now_explanation(
        pkg: str, curr: str, target: str, vuln_count: int,
        has_kev: bool, root_count: int, cost: float, marginal: float
    ) -> str:
        reasons = []
        if has_kev:
            reasons.append("Contains verified CISA KEV exploitation in the wild")
        if vuln_count > 1:
            reasons.append(f"Removes {vuln_count} distinct vulnerability advisories in one patch")
        else:
            reasons.append("Removes confirmed vulnerability advisory")
        if root_count > 0:
            reasons.append(f"Protects {root_count} direct application project root(s)")

        reasons.append(f"Estimated change cost is {cost} with marginal value {marginal} pts/cost")
        return ". ".join(reasons) + "."

