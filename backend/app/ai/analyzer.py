import logging
from typing import Dict, Any, Optional
from app.ai.providers import get_llm_provider
from app.scanners.base import RawFinding

logger = logging.getLogger("guardstack.ai.analyzer")

class FindingAIAnalyzer:
    SYSTEM_INSTRUCTIONS = """You are Guardstack ASPM Security Intelligence Engine.
Analyze the following vulnerability finding discovered in source code.
You must return a valid JSON object matching this schema:
{
  "explanation": "Clear plain-language explanation of why this code is vulnerable and what consequences it has.",
  "attack_scenario": "Step-by-step hypothetical attack scenario demonstrating how an adversary could exploit this in production.",
  "false_positive_likelihood": "low" | "medium" | "high",
  "confidence": 0.0 to 1.0,
  "proposed_patch": "Syntactically valid Unified Diff (starting with --- a/file and +++ b/file) that completely resolves the issue without breaking application functionality."
}
"""

    @classmethod
    async def analyze_finding(
        cls,
        finding: RawFinding,
        file_content: Optional[str] = None,
        reachability_info: Optional[Dict[str, Any]] = None,
        exposure_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate structured AI security analysis and patch diff for a finding."""
        provider = get_llm_provider()

        # Build prompt
        prompt = f"""{cls.SYSTEM_INSTRUCTIONS}

Vulnerability Details:
- Tool: {finding.tool}
- Rule ID: {finding.rule_id}
- Title: {finding.title}
- Message: {finding.message}
- Severity: {finding.severity}
- File Path: {finding.file_path}
- Line Range: Lines {finding.start_line} - {finding.end_line}
- CVSS Score: {finding.cvss_score or 'N/A'}

Threat Intelligence & Reachability:
- Reachability Trace: {reachability_info.get('chain') if reachability_info else 'Direct code path'}
- Exposure: {exposure_info.get('exposure_status', 'unknown') if exposure_info else 'unknown'}

Code Snippet:
```{finding.file_path.split('.')[-1] if '.' in finding.file_path else 'text'}
{finding.code_snippet}
```

Surrounding Context (if available):
```
{file_content[:1500] if file_content else finding.code_snippet}
```

Provide the JSON response now:"""

        try:
            analysis = await provider.generate_security_analysis(prompt)
            # Ensure mandatory keys
            return {
                "explanation": analysis.get("explanation", finding.message),
                "attack_scenario": analysis.get("attack_scenario", "Attacker manipulates input parameters to trigger unexpected behavior."),
                "false_positive_likelihood": analysis.get("false_positive_likelihood", "low"),
                "confidence": float(analysis.get("confidence", 0.90)),
                "proposed_patch": analysis.get("proposed_patch", "")
            }
        except Exception as e:
            logger.error(f"AI analysis failed for finding {finding.rule_id}: {e}")
            from app.ai.providers import HeuristicSecurityEngine
            fallback_engine = HeuristicSecurityEngine()
            return await fallback_engine.generate_security_analysis(prompt)