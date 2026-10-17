import json
import logging
import math
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Tuple
from app.scanners.base import BaseScanner, RawFinding

logger = logging.getLogger("guardstack.scanners.gitleaks")

def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

class GitleaksScanner(BaseScanner):
    def name(self) -> str:
        return "gitleaks"

    # Known secret signature regexes: (rule_id, title, pattern, min_entropy, severity)
    SECRET_RULES = [
        (
            "gitleaks.rule.aws-access-key-id",
            "Hardcoded Secret: AWS Access Key ID",
            r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            3.0,
            "CRITICAL"
        ),
        (
            "gitleaks.rule.aws-secret-access-key",
            "Hardcoded Secret: AWS Secret Access Key",
            r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            4.0,
            "CRITICAL"
        ),
        (
            "gitleaks.rule.github-pat",
            "Hardcoded Secret: GitHub Personal Access Token",
            r"ghp_[a-zA-Z0-9]{36}",
            3.8,
            "CRITICAL"
        ),
        (
            "gitleaks.rule.github-oauth",
            "Hardcoded Secret: GitHub OAuth Access Token",
            r"gho_[a-zA-Z0-9]{36}",
            3.8,
            "CRITICAL"
        ),
        (
            "gitleaks.rule.slack-webhook",
            "Hardcoded Secret: Slack Incoming Webhook URL",
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
            3.2,
            "HIGH"
        ),
        (
            "gitleaks.rule.slack-bot-token",
            "Hardcoded Secret: Slack Bot Token",
            r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}",
            3.5,
            "HIGH"
        ),
        (
            "gitleaks.rule.stripe-secret-key",
            "Hardcoded Secret: Stripe API Secret Key",
            r"sk_live_[0-9a-zA-Z]{24,34}",
            3.5,
            "CRITICAL"
        ),
        (
            "gitleaks.rule.rsa-private-key",
            "Hardcoded Secret: Unencrypted Private Key Header",
            r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----",
            2.0,
            "CRITICAL"
        ),
        (
            "gitleaks.rule.generic-high-entropy-api-key",
            "Hardcoded Secret: Generic High-Entropy API Token",
            r"(?i)(?:api_key|apikey|secret_key|auth_token|client_secret)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{28,64})['\"]",
            4.2,
            "HIGH"
        ),
        (
            "gitleaks.rule.database-connection-uri",
            "Hardcoded Secret: Database Connection URI with Plaintext Password",
            r"(?:postgres|postgresql|mysql|mongodb)://[^:]+:([^@]+)@[a-zA-Z0-9\.\-]+",
            2.5,
            "HIGH"
        )
    ]

    async def scan(self, target_dir: Path) -> List[RawFinding]:
        findings: List[RawFinding] = []
        gitleaks_bin = shutil.which("gitleaks")

        if gitleaks_bin:
            try:
                logger.info(f"Executing native gitleaks CLI on {target_dir}")
                report_path = target_dir / ".gitleaks-report.json"
                cmd = [
                    gitleaks_bin,
                    "detect",
                    "--source", str(target_dir),
                    "--no-git",
                    "--report-format", "json",
                    "--report-path", str(report_path)
                ]
                subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                if report_path.exists():
                    data = json.loads(report_path.read_text(encoding="utf-8"))
                    report_path.unlink(missing_ok=True)
                    for item in data:
                        findings.append(RawFinding(
                            tool=self.name(),
                            rule_id=f"gitleaks.{item.get('RuleID', 'generic')}",
                            title=f"Hardcoded Secret: {item.get('Description', 'Detected Secret')}",
                            message=f"Discovered secret token matching rule {item.get('RuleID')}.",
                            severity="CRITICAL",
                            file_path=str(Path(item.get("File", "")).relative_to(target_dir)).replace("\\", "/"),
                            start_line=item.get("StartLine", 1),
                            end_line=item.get("EndLine", 1),
                            code_snippet=item.get("Match", "secret-token").strip(),
                            cvss_score=8.9
                        ))
                    return findings
            except Exception as e:
                logger.warning(f"Gitleaks native binary failed, falling back to built-in secret detector: {e}")

        # Built-in High Precision & Entropy Secret Scanner
        return self._run_builtin_secrets(target_dir)

    def _run_builtin_secrets(self, target_dir: Path) -> List[RawFinding]:
        findings: List[RawFinding] = []
        skip_extensions = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".exe", ".dll", ".zip", ".tar", ".gz", ".lock"}

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tmp"}]
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in skip_extensions:
                    continue
                file_path = Path(root) / file
                try:
                    rel_path = str(file_path.relative_to(target_dir)).replace("\\", "/")
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()

                    for rule_id, title, pattern, min_entropy, severity in self.SECRET_RULES:
                        for idx, line in enumerate(lines, 1):
                            match = re.search(pattern, line)
                            if match:
                                secret_value = match.group(1) if match.groups() else match.group(0)
                                # Exclude dummy placeholders
                                if secret_value.lower() in {"your_api_key_here", "example", "placeholder", "changeme", "dummy", "secret", "xxxxxxxx"}:
                                    continue
                                is_prefixed_token = any(secret_value.startswith(p) for p in ["AKIA", "ASIA", "ghp_", "gho_", "sk_live_", "xoxb-"])
                                # Entropy validation or known high-confidence token prefix
                                if is_prefixed_token or shannon_entropy(secret_value) >= min_entropy or "PRIVATE KEY" in secret_value:
                                    # Obfuscate secret in snippet representation
                                    masked = secret_value[:4] + "*" * (len(secret_value) - 8) + secret_value[-4:] if len(secret_value) > 12 else "****"
                                    safe_snippet = line.replace(secret_value, masked).strip()

                                    findings.append(RawFinding(
                                        tool=self.name(),
                                        rule_id=rule_id,
                                        title=title,
                                        message=f"Hardcoded sensitive credential identified in {rel_path}. Storing secrets in source code risks immediate exposure.",
                                        severity=severity,
                                        file_path=rel_path,
                                        start_line=idx,
                                        end_line=idx,
                                        code_snippet=line.strip(),
                                        cvss_score=9.1 if severity == "CRITICAL" else 7.5,
                                        metadata={"cwe": "CWE-798", "masked_preview": safe_snippet}
                                    ))
                except Exception as e:
                    logger.debug(f"Failed scanning file for secrets: {file_path}: {e}")
        return findings