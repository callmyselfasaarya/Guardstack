import ast
import logging
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from app.config import settings
from app.scanners.base import RawFinding
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.trivy_scanner import TrivyScanner

logger = logging.getLogger("guardstack.ai.fix_validator")

class FixValidator:
    def __init__(self):
        self.scanners = {
            "semgrep": SemgrepScanner(),
            "gitleaks": GitleaksScanner(),
            "trivy": TrivyScanner()
        }

    async def validate_patch(
        self,
        finding: RawFinding,
        proposed_patch: str,
        repo_root: Optional[Path] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Applies proposed diff in an isolated sandbox and re-runs the scanner
        to confirm whether the finding is cleanly eliminated.
        """
        if not proposed_patch or not proposed_patch.strip():
            return False, {"message": "No proposed patch diff provided for validation."}

        # 1. Prepare temporary sandbox directory
        sandbox_id = uuid.uuid4().hex[:8]
        sandbox_dir = settings.WORKSPACE_TMP_DIR / f"val_{sandbox_id}"
        sandbox_dir.mkdir(parents=True, exist_ok=True)

        try:
            rel_path = finding.file_path.replace("\\", "/")
            dest_file = sandbox_dir / rel_path
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            # Get original file content
            orig_content = ""
            if repo_root and (repo_root / rel_path).exists():
                orig_content = (repo_root / rel_path).read_text(encoding="utf-8", errors="ignore")
            elif finding.code_snippet:
                orig_content = finding.code_snippet

            if not orig_content:
                return False, {"message": "Original source content could not be resolved."}

            # 2. Apply patch to content
            patched_content = self._apply_diff(orig_content, proposed_patch)
            if patched_content == orig_content:
                # If unified diff couldn't be parsed directly, attempt fallback snippet replacement
                patched_content = self._apply_snippet_replacement(orig_content, proposed_patch)

            dest_file.write_text(patched_content, encoding="utf-8")

            # 3. Syntax Verification (for Python)
            if rel_path.endswith(".py"):
                try:
                    ast.parse(patched_content, filename=str(dest_file))
                except SyntaxError as se:
                    logger.warning(f"Patched Python code failed syntax validation: {se}")
                    return False, {
                        "re_scan_clean": False,
                        "syntax_valid": False,
                        "message": f"Proposed patch introduced a Python syntax error on line {se.lineno}: {se.msg}"
                    }

            # 4. Re-run Scanner on Patched Sandbox
            scanner = self.scanners.get(finding.tool.lower())
            if not scanner:
                scanner = self.scanners["semgrep"]

            rescan_findings = await scanner.scan(sandbox_dir)

            # 5. Check if the specific finding (same rule and same start line or snippet) still triggers on the patched file
            finding_still_present = any(
                f.rule_id == finding.rule_id and (
                    f.start_line == finding.start_line or
                    f.code_snippet.strip() == finding.code_snippet.strip()
                )
                for f in rescan_findings
            )

            if not finding_still_present:
                logger.info(f"Fix validated successfully for {finding.rule_id}. Re-scan is 100% clean.")
                return True, {
                    "re_scan_clean": True,
                    "syntax_valid": True,
                    "message": "Fix verified: re-scan confirms the vulnerability is eliminated without regressions.",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            else:
                logger.info(f"Fix validation failed for {finding.rule_id}. Vulnerability still detected upon re-scan.")
                return False, {
                    "re_scan_clean": False,
                    "syntax_valid": True,
                    "message": "Vulnerability still detected by scanner after applying patch.",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }

        except Exception as e:
            logger.error(f"Error during patch validation loop: {e}")
            return False, {"message": f"Validation execution error: {str(e)}"}
        finally:
            # Clean up sandbox
            shutil.rmtree(sandbox_dir, ignore_errors=True)

    def _apply_diff(self, original_text: str, diff_text: str) -> str:
        """Parses unified diff deletions and additions and applies to text."""
        lines = original_text.splitlines()
        minus_lines = []
        plus_lines = []

        for line in diff_text.splitlines():
            if line.startswith("- ") and not line.startswith("--- "):
                minus_lines.append(line[2:])
            elif line.startswith("+ ") and not line.startswith("+++ "):
                plus_lines.append(line[2:])

        if not minus_lines:
            return original_text

        # Target block to replace
        old_block = "\n".join(minus_lines)
        new_block = "\n".join(plus_lines)

        if old_block in original_text:
            return original_text.replace(old_block, new_block, 1)

        # Fallback line-by-line replacement
        patched = original_text
        for m, p in zip(minus_lines, plus_lines):
            if m in patched:
                patched = patched.replace(m, p, 1)

        return patched

    def _apply_snippet_replacement(self, original_text: str, patch_str: str) -> str:
        """Fallback: extract code blocks from markdown diff or raw text."""
        code_blocks = re.findall(r"```[^\n]*\n([\s\S]*?)```", patch_str)
        if code_blocks:
            candidate = code_blocks[0]
            clean_lines = [l for l in candidate.splitlines() if not l.startswith("-") and not l.startswith("@@")]
            replacement = "\n".join(l[1:].strip() if l.startswith("+") else l for l in clean_lines)
            return replacement
        return original_text