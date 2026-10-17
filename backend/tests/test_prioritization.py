import pytest
from app.prioritization.risk_engine import RiskPrioritizationEngine

def test_risk_prioritization_high_exploitability():
    # Critical vulnerability with high EPSS in CISA KEV
    score, tier, bd = RiskPrioritizationEngine.calculate_priority_score(
        severity="CRITICAL",
        cvss_score=9.8,
        epss_score=0.88,
        in_cisa_kev=True
    )
    # CVSS (9.8/10*45=44.1) + EPSS (0.88*35=30.8) + KEV (20.0) = ~94.9
    assert score >= 85.0
    assert tier == "CRITICAL"
    assert bd["is_actionable_blocker"] is True
    assert bd["in_cisa_kev"] is True

def test_risk_prioritization_noise_filtering():
    # Low severity vulnerability with negligible EPSS and not in KEV
    score, tier, bd = RiskPrioritizationEngine.calculate_priority_score(
        severity="LOW",
        cvss_score=3.0,
        epss_score=0.01,
        in_cisa_kev=False
    )
    # CVSS (3.0/10*45=13.5) + EPSS (0.01*35=0.35) + KEV (0) = ~13.85
    assert score < 30.0
    assert tier == "LOW"
    assert bd["is_actionable_blocker"] is False
