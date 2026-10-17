import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("guardstack.prioritization.risk_engine")

class RiskPrioritizationEngine:
    """
    Locked Scope Prioritization Engine combining three authoritative feeds:
    1. CVSS: Common Vulnerability Scoring System (base technical severity)
    2. EPSS: FIRST.org Exploit Prediction Scoring System (empirical exploit probability)
    3. CISA KEV: Known Exploited Vulnerabilities Catalog (active wild exploitation)
    """

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
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        in_cisa_kev: bool = False
    ) -> Tuple[float, str, Dict[str, Any]]:
        """
        Computes a 0-100 Priority Risk Score combining CVSS (45%), EPSS (35%), and CISA KEV (20%).

        Returns:
            priority_score: float (0.0 to 100.0)
            priority_tier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
            score_breakdown: detailed components dict
        """
        # 1. Base CVSS severity points (up to 45 points)
        cvss_val = cvss_score if cvss_score is not None else cls.SEVERITY_DEFAULT_CVSS.get(severity.upper(), 5.0)
        cvss_clamped = min(10.0, max(0.0, float(cvss_val)))
        cvss_points = (cvss_clamped / 10.0) * 45.0

        # 2. EPSS exploit probability points (up to 35 points)
        epss_val = epss_score if epss_score is not None else 0.05
        epss_clamped = min(1.0, max(0.0, float(epss_val)))
        epss_points = epss_clamped * 35.0

        # 3. CISA KEV actively exploited bonus (20 points)
        kev_points = 20.0 if in_cisa_kev else 0.0

        # Total 0-100
        raw_score = cvss_points + epss_points + kev_points
        priority_score = round(min(100.0, max(0.0, raw_score)), 1)

        # Categorize priority tiers
        if priority_score >= 70.0:
            tier = "CRITICAL"
        elif priority_score >= 50.0:
            tier = "HIGH"
        elif priority_score >= 30.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        breakdown = {
            "cvss_score": round(cvss_clamped, 1),
            "cvss_points": round(cvss_points, 2),
            "cvss_weight": "45%",
            "epss_probability": round(epss_clamped, 4),
            "epss_points": round(epss_points, 2),
            "epss_weight": "35%",
            "in_cisa_kev": in_cisa_kev,
            "kev_bonus_points": kev_points,
            "kev_weight": "20%",
            "is_actionable_blocker": priority_score >= 50.0
        }

        return priority_score, tier, breakdown