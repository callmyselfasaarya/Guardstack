import pytest
from pathlib import Path
from app.prioritization.reachability import PythonCallGraphAnalyzer
from app.prioritization.exposure import ExposureAnalyzer
from app.prioritization.risk_engine import RiskPrioritizationEngine

@pytest.fixture
def corpus_dir():
    return Path(__file__).resolve().parent.parent / "app" / "benchmark" / "corpus" / "vulnerable_app"

def test_reachability_distinguishes_live_route_and_dead_code(corpus_dir):
    analyzer = PythonCallGraphAnalyzer(corpus_dir)
    analyzer.build_graph()

    # Route search_user in routes/users.py: line 10
    status_live, trace_live = analyzer.analyze_finding_reachability("routes/users.py", 10)
    assert status_live == "reachable"

    # Dead helper _legacy_dead_internal_query_helper: line 23
    status_dead, trace_dead = analyzer.analyze_finding_reachability("routes/users.py", 23)
    assert status_dead == "unreachable"

def test_exposure_detection():
    public_snippet = "cursor.execute(f'SELECT * FROM users WHERE id = {request.args.get(\"id\")}')"
    status, meta = ExposureAnalyzer.evaluate_exposure(public_snippet, public_snippet, 1)
    assert status == "public_route"

def test_risk_prioritization_noise_suppression():
    # 1. Critical vulnerability that is reachable on public route
    score_live, tier_live, bd_live = RiskPrioritizationEngine.calculate_priority_score(
        severity="CRITICAL",
        cvss_score=9.8,
        epss_score=0.85,
        in_cisa_kev=True,
        reachability_status="reachable",
        exposure_status="public_route"
    )
    assert score_live >= 80.0
    assert tier_live == "CRITICAL"
    assert bd_live["is_actionable_blocker"] is True

    # 2. Critical vulnerability in dead/unreachable code
    score_dead, tier_dead, bd_dead = RiskPrioritizationEngine.calculate_priority_score(
        severity="CRITICAL",
        cvss_score=9.8,
        epss_score=0.85,
        in_cisa_kev=True,
        reachability_status="unreachable",
        exposure_status="internal_only"
    )
    # Contextual multipliers (0.25 * 0.45) reduce noise drastically
    assert score_dead < 40.0
    assert tier_dead == "LOW"
    assert bd_dead["is_actionable_blocker"] is False
