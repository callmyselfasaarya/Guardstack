import hashlib
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

@dataclass
class RawFinding:
    tool: str                          # semgrep, gitleaks, trivy
    rule_id: str                       # e.g. python.lang.security.audit.sqli
    title: str                         # Human-readable title
    message: str                       # Finding explanation / warning
    severity: str                      # CRITICAL, HIGH, MEDIUM, LOW, INFO
    file_path: str                     # Relative file path
    start_line: int                    # Starting line number (1-indexed)
    end_line: int                      # Ending line number (1-indexed)
    code_snippet: str                  # Snippet of vulnerable code
    cve_id: Optional[str] = None       # CVE identifier if applicable
    cvss_score: Optional[float] = None # Base CVSS score if known
    metadata: Dict[str, Any] = field(default_factory=dict)

    def generate_fingerprint(self) -> str:
        """
        Generate a stable SHA256 fingerprint that persists across minor whitespace 
        and line-number shifts to track findings across commits.
        """
        norm_path = self.file_path.replace("\\", "/").strip().lower()
        norm_code = re.sub(r"\s+", " ", self.code_snippet.strip())
        key = f"{self.tool}:{self.rule_id}:{norm_path}:{norm_code}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

class BaseScanner(ABC):
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the scanner."""
        pass

    @abstractmethod
    async def scan(self, target_dir: Path) -> List[RawFinding]:
        """Execute scan against a local directory and return normalized findings."""
        pass
