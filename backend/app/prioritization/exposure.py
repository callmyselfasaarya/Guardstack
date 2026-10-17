import re
from pathlib import Path
from typing import Tuple, Dict, Any

class ExposureAnalyzer:
    USER_INPUT_PATTERNS = [
        r"request\.(?:args|form|json|values|data|query_params|body|headers|cookies)",
        r"req\.(?:query|body|params|headers|cookies)",
        r"\bsys\.argv\b",
        r"\binput\s*\(",
        r"\bos\.environ\b",
        r"params\[['\"][^'\"]+['\"]\]",
        r"payload\[['\"][^'\"]+['\"]\]"
    ]

    PUBLIC_ROUTE_PATTERNS = [
        r"@(?:app|router|bp|api)\.(?:get|post|put|delete|patch|route)\s*\(",
        r"app\.(?:get|post|put|delete|patch)\s*\("
    ]

    AUTH_PROTECTION_PATTERNS = [
        r"Depends\s*\([^)]*(?:auth|token|user|perm)[^)]*\)",
        r"@login_required",
        r"@jwt_required",
        r"@require_auth",
        r"@authenticated"
    ]

    @classmethod
    def evaluate_exposure(cls, file_content: str, snippet: str, start_line: int) -> Tuple[str, Dict[str, Any]]:
        """
        Evaluate if code at the finding is exposed to external user input or public network traffic.
        Returns:
            status: 'public_route' | 'internal_only' | 'unknown'
            metadata: dict with reasons and matching patterns
        """
        lines = file_content.splitlines()
        # Look at surrounding context (+- 15 lines)
        context_start = max(0, start_line - 16)
        context_end = min(len(lines), start_line + 15)
        context_window = "\n".join(lines[context_start:context_end])

        touches_user_input = False
        matched_input_pattern = ""
        for pat in cls.USER_INPUT_PATTERNS:
            if re.search(pat, snippet, re.IGNORECASE) or re.search(pat, context_window, re.IGNORECASE):
                touches_user_input = True
                matched_input_pattern = pat
                break

        is_public_route = False
        for pat in cls.PUBLIC_ROUTE_PATTERNS:
            if re.search(pat, context_window, re.IGNORECASE):
                # Check if protected by authentication
                has_auth = any(re.search(a, context_window, re.IGNORECASE) for a in cls.AUTH_PROTECTION_PATTERNS)
                if not has_auth:
                    is_public_route = True
                break

        if touches_user_input or is_public_route:
            return "public_route", {
                "touches_user_input": touches_user_input,
                "input_pattern": matched_input_pattern,
                "is_public_endpoint": is_public_route
            }

        # Check if clearly internal / test / migration code
        if "test" in file_content[:500].lower() or "migration" in file_content[:500].lower():
            return "internal_only", {"reason": "Test or migration context"}

        return "unknown", {"reason": "Could not confirm public entrypoint or direct user parameter access."}