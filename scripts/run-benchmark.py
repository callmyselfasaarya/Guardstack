#!/usr/bin/env python3
"""
Guardstack Defensible Benchmark CLI Evaluator
Measures developer noise reduction %, AI precision/recall, and fix validation pass rate.
"""
import asyncio
import json
import sys
from pathlib import Path

# Add backend to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / ".venv" / "Lib" / "site-packages"))
sys.path.insert(0, str(root_dir / "backend"))

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
        reach_badge = "[REACHABLE]" if item["reachability"] == "reachable" else "[DEAD CODE]"
        action_badge = "[PR BLOCKER]" if item["is_actionable"] else "[FILTERED NOISE]"
        fix_badge = "[FIX VALIDATED CLEAN]" if item["fix_validated"] else "[UNVALIDATED]"
        print(f" • {item['title'][:36]:<36} | {item['severity']:<8} | {reach_badge:<12} | {action_badge:<16} | {fix_badge}")

    # Output JSON summary
    out_file = root_dir / "benchmark_audit_results.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nAudit results successfully saved to: {out_file}")

if __name__ == "__main__":
    asyncio.run(main())
