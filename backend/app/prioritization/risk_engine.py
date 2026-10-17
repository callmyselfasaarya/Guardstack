import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("guardstack.prioritization.risk_engine")

class RiskPrioritizationEngine:
    SEVERITY_DEFAULT_CVSS = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.5,
        "LOW": 3.0,
        "INFO": 1.0
    }

    @classmethod
    def calculate_priority_score(
        cls,
        severity: str,
        cvss_score: Optional[float],
        epss_score: Optional[float],
        in_cisa_kev: bool,
        reachability_status: str,
        exposure_status: str
    ) -> Tuple[float, str, Dict[str, Any]]:
        """
        Computes a comprehensive 0-100 Priority Risk Score based on CVSS, EPSS,
        CISA KEV, Call-Graph Reachability, and Public Exposure.

        Returns:
            priority_score: float (0.0 to 100.0)
            priority_tier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
            score_breakdown: detailed components dict
        """
        # 1. Base CVSS points (up to 35 points)
        cvss_val = cvss_score if cvss_score is not None else cls.SEVERITY_DEFAULT_CVSS.get(severity.upper(), 5.0)
        cvss_clamped = min(10.0, max(0.0, float(cvss_val)))
        cvss_contribution = (cvss_clamped / 10.0) * 35.0

        # 2. EPSS exploit likelihood points (up to 25 points)
        epss_val = epss_score if epss_score is not None else 0.05
        epss_clamped = min(1.0, max(0.0, float(epss_val)))
        epss_contribution = epss_clamped * 25.0

        # 3. CISA KEV actively exploited bonus (up to 15 points)
        kev_contribution = 15.0 if in_cisa_kev else 0.0

        threat_subtotal = cvss_contribution + epss_contribution + kev_contribution

        # 4. Reachability factor
        reach_status = reachability_status.lower()
        if reach_status == "reachable":
            reach_factor = 1.0
        elif reach_status == "unreachable":
            # Significant noise reduction for dead / unreferenced code
            reach_factor = 0.25
        else:
            reach_factor = 0.75

        # 5. Public exposure factor
        exp_status = exposure_status.lower()
        if exp_status == "public_route":
            exposure_factor = 1.0
        elif exp_status == "internal_only":
            exposure_factor = 0.45
        else:
            exposure_factor = 0.80

        # Normalized final score scaled to 0-100
        raw_final = (threat_subtotal * reach_factor * exposure_factor) * (100.0 / 75.0)
        priority_score = round(min(100.0, max(0.0, raw_final)), 1)

        # Categorize into priority tiers
        if priority_score >= 75.0:
            tier = "CRITICAL"
        elif priority_score >= 55.0:
            tier = "HIGH"
        elif priority_score >= 35.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        breakdown = {
            "cvss_score": round(cvss_clamped, 1),
            "cvss_points": round(cvss_contribution, 2),
            "epss_probability": round(epss_clamped, 4),
            "epss_points": round(epss_contribution, 2),
            "in_cisa_kev": in_cisa_kev,
            "kev_bonus_points": kev_contribution,
            "reachability_status": reach_status,
            "reachability_multiplier": reach_factor,
            "exposure_status": exp_status,
            "exposure_multiplier": exposure_factor,
            "is_actionable_blocker": priority_score >= 55.0
        }

        return priority_score, tier, breakdown