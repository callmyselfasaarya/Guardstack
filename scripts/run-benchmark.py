#!/usr/bin/env python3
"""
Guardstack Defensible Benchmark CLI Evaluator
Measures developer noise reduction %, AI precision/recall, and fix validation pass rate.
"""
import asyncio
import json
import sys
from pathlib import Path

# Add backend directory to sys.path
root_dir = Path(__file__).resolve().parent.parent
backend_dir = root_dir / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.benchmark.runner import BenchmarkSuiteRunner

async def main():
    print("=" * 65)
    print("      GUARDSTACK DEFENSIVE BENCHMARK EVALUATOR")
    print("=" * 65)
    print("Evaluating against intentionally vulnerable corpus (OWASP Top 10 patterns)...")

    result = await BenchmarkSuiteRunner.run_benchmark(suite_name="owasp_top10_corpus")

    print("\n" + "-" * 65)
    print("               CORE DEFENSE METRICS")
    print("-" * 65)
    print(f"Total Test Cases Analyzed:        {result['total_cases']}")
    print(f"Raw Scanner Findings (Semgrep/Gitleaks/Trivy): {result['raw_findings_count']}")
    print(f"Actionable PR Blockers:            {result['filtered_findings_count']}")
    print(f"Non-actionable Noise Suppressed:  {result['noise_filtered_count']}")
    print(f"-> DEVELOPER NOISE REDUCTION:      {result['noise_reduction_pct']}%")
    print(f"-> AI FALSE-POSITIVE PRECISION:    {result['fp_precision'] * 100:.1f}%")
    print(f"-> AI VULNERABILITY RECALL:        {result['fp_recall'] * 100:.1f}%")
    print(f"-> FIX VALIDATION PASS RATE:       {result['fix_validation_rate']}%")
    print("-" * 65)

    print("\nDetailed Case-by-Case Breakdown:")
    for item in result.get("evaluated_findings", []):
        kev_badge = "[CISA KEV]" if item.get("cisa_kev") else "[NO KEV]  "
        epss_str = f"EPSS:{item.get('epss', 0.05)*100:.0f}%"
        action_badge = "[PR BLOCKER]   " if item["is_actionable"] else "[FILTERED NOISE]"
        fix_badge = "[FIX VERIFIED CLEAN]" if item["fix_validated"] else "[FIX FAILED]"
        print(f" • {item['title'][:32]:<32} | {item['severity']:<8} | {kev_badge} {epss_str:<8} | {action_badge} | {fix_badge}")

    # Output JSON summary
    out_file = root_dir / "benchmark_audit_results.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nAudit results successfully saved to: {out_file}")

if __name__ == "__main__":
    asyncio.run(main())
