from typing import Dict, Any, Optional, Tuple
from app.core.models import VulnerableFinding, VulnerabilityRecord, ComponentNode

class RiskScorer:
    """
    Transparent, auditable risk-prioritization scoring engine implementing
    CSB-03 Formula from Section 7.3:
    P(v) = 100 * (0.35*K + 0.25*E + 0.20*C + 0.10*X + 0.10*R) / (sum observed weights)
    """

    WEIGHT_KEV = 0.35
    WEIGHT_EPSS = 0.25
    WEIGHT_CVSS = 0.20
    WEIGHT_EXPOSURE = 0.10
    WEIGHT_REACH = 0.10
    TOTAL_WEIGHT = 1.0

    @classmethod
    def calculate_score(
        cls,
        vuln: VulnerabilityRecord,
        component: ComponentNode,
        exposure_setting: str = "internet-facing",
        environment: str = "production",
        affected_dependents_count: int = 0,
        is_direct: bool = False
    ) -> Tuple[float, str, float, Dict[str, Any]]:
        """
        Calculate risk score P(v), priority tier, confidence, and transparent breakdown.
        """
        observed_weights = 0.0
        weighted_sum = 0.0
        breakdown: Dict[str, Any] = {}

        # 1. KEV Signal (K)
        # Always observed (either known to be in KEV, or verified not in KEV)
        k_val = 1.0 if vuln.in_kev else 0.0
        weighted_sum += cls.WEIGHT_KEV * k_val
        observed_weights += cls.WEIGHT_KEV
        breakdown["kev"] = {
            "value": k_val,
            "weight": cls.WEIGHT_KEV,
            "in_kev": vuln.in_kev,
            "observed": True
        }

        # 2. EPSS Signal (E)
        if vuln.epss_score is not None:
            e_val = float(vuln.epss_score)
            weighted_sum += cls.WEIGHT_EPSS * e_val
            observed_weights += cls.WEIGHT_EPSS
            breakdown["epss"] = {
                "value": round(e_val, 4),
                "weight": cls.WEIGHT_EPSS,
                "percentile": vuln.epss_percentile,
                "observed": True
            }
        else:
            breakdown["epss"] = {
                "value": None,
                "weight": cls.WEIGHT_EPSS,
                "observed": False,
                "note": "Missing EPSS forecast - renormalized"
            }

        # 3. CVSS Signal (C)
        cvss_score = None
        for sev in vuln.cvss:
            if sev.base_score is not None:
                cvss_score = sev.base_score
                break

        if cvss_score is not None:
            c_val = min(1.0, max(0.0, cvss_score / 10.0))
            weighted_sum += cls.WEIGHT_CVSS * c_val
            observed_weights += cls.WEIGHT_CVSS
            breakdown["cvss"] = {
                "raw_score": cvss_score,
                "normalized": round(c_val, 2),
                "weight": cls.WEIGHT_CVSS,
                "observed": True
            }
        else:
            breakdown["cvss"] = {
                "raw_score": None,
                "weight": cls.WEIGHT_CVSS,
                "observed": False,
                "note": "No CVSS vector in advisory - renormalized"
            }

        # 4. Exposure & Environment Context (X)
        exp_lower = exposure_setting.lower()
        if "internet" in exp_lower or "public" in exp_lower:
            x_val = 1.0
        elif "internal" in exp_lower:
            x_val = 0.7
        else:
            x_val = 0.3 # dev/isolated

        # If component is strictly development scope, downgrade exposure
        if component.scope == "development":
            x_val = min(x_val, 0.3)

        weighted_sum += cls.WEIGHT_EXPOSURE * x_val
        observed_weights += cls.WEIGHT_EXPOSURE
        breakdown["exposure"] = {
            "value": x_val,
            "setting": exposure_setting,
            "scope": component.scope,
            "weight": cls.WEIGHT_EXPOSURE,
            "observed": True
        }

        # 5. Graph Reach Proxy (R)
        # min(1.0, dependents / 10.0)
        r_val = min(1.0, max(0.1, affected_dependents_count / 10.0))
        weighted_sum += cls.WEIGHT_REACH * r_val
        observed_weights += cls.WEIGHT_REACH
        breakdown["graph_reach"] = {
            "value": round(r_val, 2),
            "affected_dependents": affected_dependents_count,
            "weight": cls.WEIGHT_REACH,
            "observed": True
        }

        # Renormalize by observed weights
        score = (weighted_sum / observed_weights) * 100.0 if observed_weights > 0 else 50.0
        score = round(score, 1)
        confidence = round(observed_weights / cls.TOTAL_WEIGHT, 2)
        breakdown["confidence"] = confidence

        # Policy Gate Before Score (Section 7.3)
        # KEV + runtime-reachable + internet-exposed findings go first
        if vuln.in_kev and x_val >= 0.7 and component.scope != "development":
            tier = "CRITICAL_URGENT"
        elif score >= 75.0:
            tier = "CRITICAL"
        elif score >= 55.0:
            tier = "HIGH"
        elif score >= 30.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        return score, tier, confidence, breakdown

