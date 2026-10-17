import logging
import re
from typing import Dict, Any, Optional

logger = logging.getLogger("guardstack.github.pr_commenter")

class PRCommentFormatter:
    SEVERITY_BADGES = {
        "CRITICAL": "🔴 Critical Priority",
        "HIGH": "🟠 High Priority",
        "MEDIUM": "🟡 Medium Priority",
        "LOW": "🔵 Low Priority",
        "INFO": "⚪ Informational"
    }

    @classmethod
    def format_finding_comment(cls, finding: Dict[str, Any], analysis: Optional[Dict[str, Any]] = None) -> str:
        """
        Formats a clean, collapsible GitHub PR review comment with risk badges,
        threat intelligence metrics (CVSS, EPSS, CISA KEV), plain-language explanation,
        and verified one-click GitHub suggestions.
        """
        priority_score = finding.get("priority_score", 0.0)
        severity = finding.get("severity", "MEDIUM")
        badge = cls.SEVERITY_BADGES.get(severity, "🟡 Medium Priority")
        tool = finding.get("tool", "Scanner")
        rule_id = finding.get("rule_id", "rule")
        title = finding.get("title", "Security Finding")
        file_path = finding.get("file_path", "")
        start_line = finding.get("start_line", 1)

        cvss = finding.get("cvss_score")
        cvss_str = f"`{cvss:.1f} / 10.0`" if cvss else "`N/A`"
        epss = finding.get("epss_score")
        epss_str = f"`{epss * 100:.1f}%`" if epss else "`< 5%`"
        kev_str = "⚠️ **Active in KEV**" if finding.get("cisa_kev") else "`Not Listed`"

        explanation = analysis.get("explanation", finding.get("message", "")) if analysis else finding.get("message", "")
        attack_scenario = analysis.get("attack_scenario", "") if analysis else ""
        patch = analysis.get("proposed_patch", "") if analysis else ""
        fix_validated = analysis.get("fix_validated", False) if analysis else False
        val_status = analysis.get("validation_status", "verified" if fix_validated else "failed") if analysis else "untested"

        # Extract suggested replacement line from patch
        suggested_code = cls._extract_suggestion_content(patch)

        comment = f"""### 🛡️ Guardstack ASPM: {title}
> **{badge}** (Risk Score: `{priority_score} / 100`)
> **Location:** `{file_path}:{start_line}` | **Tool:** `{tool}` (`{rule_id}`)

#### 📊 Risk & Threat Feeds
| Factor | Value | Details |
|---|---|---|
| **Severity (CVSS)** | {cvss_str} | Base technical vulnerability severity |
| **Exploit Likelihood (EPSS)** | {epss_str} | Probability of active in-the-wild exploitation |
| **CISA KEV** | {kev_str} | Known Exploited Vulnerabilities catalog |

---

#### 💡 Vulnerability Explanation
{explanation}

"""
        if attack_scenario:
            comment += f"""<details>
<summary><b>⚔️ Step-by-Step Attack Scenario</b></summary>

{attack_scenario}
</details>

---
"""

        if suggested_code:
            status_text = f"Fix Status: **{val_status.upper()}** (Re-scan confirms fix eliminates finding with zero regressions)" if fix_validated else f"Fix Status: **{val_status.upper()}**"
            validation_badge = "✅" if fix_validated else "⚠️"
            comment += f"""#### 🛠️ Proposed Remediation ({validation_badge} {status_text})
```suggestion
{suggested_code}
```
"""
        elif patch:
            comment += f"""#### 🛠️ Proposed Unified Patch Diff ({'✅ Verified' if fix_validated else '⚠️ Failed'})
```diff
{patch}
```
"""

        comment += f"\n*Guardstack ASPM Security Platform • [Inspect in Dashboard](http://localhost:8000/findings/{finding.get('id', '')})*"
        return comment

    @staticmethod
    def _extract_suggestion_content(diff_text: str) -> str:
        """Extract lines added with + from a unified diff for a GitHub suggestion block."""
        if not diff_text:
            return ""
        added_lines = []
        for line in diff_text.splitlines():
            if line.startswith("+ ") and not line.startswith("+++ "):
                added_lines.append(line[2:])
        return "\n".join(added_lines) if added_lines else ""
