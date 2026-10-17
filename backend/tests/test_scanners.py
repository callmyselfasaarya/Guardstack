import pytest
from pathlib import Path
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.trivy_scanner import TrivyScanner

@pytest.fixture
def corpus_dir():
    return Path(__file__).resolve().parent.parent / "app" / "benchmark" / "corpus" / "vulnerable_app"

@pytest.mark.asyncio
async def test_semgrep_scanner_detects_sqli_and_xss(corpus_dir):
    scanner = SemgrepScanner()
    findings = await scanner.scan(corpus_dir)
    assert len(findings) > 0

    rule_ids = {f.rule_id for f in findings}
    # Should catch formatted SQLi and Pickle deserialization or XSS
    assert any("sqli" in r.lower() for r in rule_ids)
    assert any("pickle" in r.lower() or "deserialization" in r.lower() for r in rule_ids)

@pytest.mark.asyncio
async def test_gitleaks_scanner_detects_secrets(corpus_dir):
    scanner = GitleaksScanner()
    findings = await scanner.scan(corpus_dir)
    assert len(findings) >= 2

    # Verify AWS and GitHub PAT secrets found
    titles = [f.title for f in findings]
    assert any("AWS" in t for t in titles)
    assert any("GitHub" in t for t in titles)

@pytest.mark.asyncio
async def test_trivy_scanner_detects_cve_dependencies(corpus_dir):
    scanner = TrivyScanner()
    findings = await scanner.scan(corpus_dir)
    assert len(findings) >= 1

    cves = [f.cve_id for f in findings if f.cve_id]
    # Check pyyaml CVE-2020-14343 or requests CVE-2023-32681
    assert any("CVE-2020-14343" in c for c in cves)
