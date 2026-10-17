import logging
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse
import httpx
from app.config import settings
from app.scanners.base import BaseScanner, RawFinding

logger = logging.getLogger("guardstack.scanners.zap")

class ZapScanner(BaseScanner):
    def name(self) -> str:
        return "zap"

    async def scan(self, target_dir: Path) -> List[RawFinding]:
        # By default BaseScanner scans directories; ZAP scans URLs via scan_url
        return []

    async def verify_target_ownership(self, target_url: str, expected_token: str) -> Tuple[bool, str]:
        """
        Verify target domain ownership using HTTP Well-Known token verification
        or custom header to prevent unauthorized DAST scanning of arbitrary web properties.
        """
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL format."

        # Dev bypass for localhost if configured
        if settings.DAST_ALLOW_LOCALHOST and (parsed.hostname in {"localhost", "127.0.0.1", "::1"} or (parsed.hostname and parsed.hostname.endswith(".local"))):
            return True, "Local development environment verified automatically."

        challenge_url = f"{parsed.scheme}://{parsed.netloc}{settings.DAST_CHALLENGE_FILE}"
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
                res = await client.get(challenge_url)
                if res.status_code == 200 and expected_token in res.text:
                    return True, f"Verified token at {challenge_url}"

                # Also verify optional header
                root_res = await client.get(f"{parsed.scheme}://{parsed.netloc}/")
                if root_res.headers.get("X-Guardstack-Verification") == expected_token:
                    return True, "Verified via X-Guardstack-Verification HTTP header"

                return False, f"Verification failed. Expected token '{expected_token}' not found at {challenge_url} (HTTP {res.status_code})"
        except Exception as e:
            return False, f"Verification request failed: {str(e)}"

    async def scan_url(self, target_url: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        logger.info(f"Running baseline DAST assessment against target: {target_url}")

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(target_url)

                # 1. Missing Content-Security-Policy
                if "content-security-policy" not in resp.headers:
                    findings.append(RawFinding(
                        tool=self.name(),
                        rule_id="zap.dast.headers.missing-csp",
                        title="DAST: Missing Content-Security-Policy (CSP) Header",
                        message="Content-Security-Policy header is missing. CSP prevents Cross-Site Scripting (XSS) and data injection attacks by restricting sources of executable scripts.",
                        severity="MEDIUM",
                        file_path=target_url,
                        start_line=1,
                        end_line=1,
                        code_snippet="HTTP Response Headers missing Content-Security-Policy",
                        cvss_score=5.4,
                        metadata={"type": "header_audit", "cwe": "CWE-693"}
                    ))

                # 2. Missing Anti-Clickjacking (X-Frame-Options)
                if "x-frame-options" not in resp.headers and "frame-ancestors" not in resp.headers.get("content-security-policy", ""):
                    findings.append(RawFinding(
                        tool=self.name(),
                        rule_id="zap.dast.headers.missing-x-frame-options",
                        title="DAST: Anti-Clickjacking Header Missing (X-Frame-Options)",
                        message="X-Frame-Options header not configured. Malicious websites can embed this application in an invisible iframe and trick users into clicking sensitive actions.",
                        severity="LOW",
                        file_path=target_url,
                        start_line=1,
                        end_line=1,
                        code_snippet="HTTP Response Headers missing X-Frame-Options",
                        cvss_score=4.3,
                        metadata={"type": "header_audit", "cwe": "CWE-1021"}
                    ))

                # 3. Missing Strict-Transport-Security (HSTS) on HTTPS
                if target_url.startswith("https://") and "strict-transport-security" not in resp.headers:
                    findings.append(RawFinding(
                        tool=self.name(),
                        rule_id="zap.dast.headers.missing-hsts",
                        title="DAST: Strict-Transport-Security (HSTS) Header Missing",
                        message="HTTP Strict Transport Security (HSTS) header is missing on HTTPS target. Attackers can execute SSL-stripping and downgrade attacks.",
                        severity="LOW",
                        file_path=target_url,
                        start_line=1,
                        end_line=1,
                        code_snippet="HTTP Response Headers missing Strict-Transport-Security",
                        cvss_score=3.7,
                        metadata={"type": "header_audit", "cwe": "CWE-319"}
                    ))

                # 4. Insecure CORS Configuration
                cors_origin = resp.headers.get("access-control-allow-origin")
                cors_credentials = resp.headers.get("access-control-allow-credentials", "").lower()
                if cors_origin == "*" and cors_credentials == "true":
                    findings.append(RawFinding(
                        tool=self.name(),
                        rule_id="zap.dast.cors.wildcard-credentials",
                        title="DAST: Overly Permissive Cross-Origin Resource Sharing (CORS)",
                        message="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true permits untrusted websites to read private authenticated user data.",
                        severity="HIGH",
                        file_path=target_url,
                        start_line=1,
                        end_line=1,
                        code_snippet=f"Access-Control-Allow-Origin: {cors_origin}\nAccess-Control-Allow-Credentials: {cors_credentials}",
                        cvss_score=7.8,
                        metadata={"type": "cors_audit", "cwe": "CWE-942"}
                    ))

                # 5. Sensitive Path Exposure Probes
                parsed = urlparse(target_url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                sensitive_paths = [
                    ("/.env", "Exposed .env Configuration File", "CRITICAL", 9.8),
                    ("/actuator/env", "Spring Actuator Environment Endpoint", "HIGH", 8.2),
                    ("/swagger.json", "Exposed OpenAPI / Swagger Specification", "INFO", 2.0)
                ]

                for probe_path, probe_title, probe_sev, probe_cvss in sensitive_paths:
                    try:
                        probe_resp = await client.get(f"{base}{probe_path}")
                        if probe_resp.status_code == 200 and len(probe_resp.text) > 10:
                            findings.append(RawFinding(
                                tool=self.name(),
                                rule_id=f"zap.dast.sensitive-path{probe_path.replace('/', '-')}",
                                title=f"DAST: {probe_title}",
                                message=f"Discovered publicly accessible endpoint at {base}{probe_path} returning HTTP 200.",
                                severity=probe_sev,
                                file_path=f"{base}{probe_path}",
                                start_line=1,
                                end_line=1,
                                code_snippet=probe_resp.text[:200],
                                cvss_score=probe_cvss,
                                metadata={"type": "sensitive_endpoint"}
                            ))
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"DAST scan failed for {target_url}: {e}")

        return findings
