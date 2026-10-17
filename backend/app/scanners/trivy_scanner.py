import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from app.scanners.base import BaseScanner, RawFinding

logger = logging.getLogger("guardstack.scanners.trivy")

class TrivyScanner(BaseScanner):
    def name(self) -> str:
        return "trivy"

    # Known high-impact dependency CVE database with CVSS and EPSS benchmarks
    VULNERABLE_PACKAGES_DB = {
        "python": [
            {
                "package": "requests",
                "max_vulnerable_version": "2.31.0",
                "cve_id": "CVE-2023-32681",
                "cvss_score": 6.1,
                "severity": "MEDIUM",
                "title": "requests: Unintended leak of Proxy-Authorization headers",
                "fixed_version": "2.31.0"
            },
            {
                "package": "urllib3",
                "max_vulnerable_version": "2.0.7",
                "cve_id": "CVE-2023-45803",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "title": "urllib3: Request body not stripped on HTTP redirect",
                "fixed_version": "2.0.7"
            },
            {
                "package": "pyyaml",
                "max_vulnerable_version": "5.4.0",
                "cve_id": "CVE-2020-14343",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "title": "pyyaml: Arbitrary code execution via full_load/load",
                "fixed_version": "5.4"
            },
            {
                "package": "jinja2",
                "max_vulnerable_version": "3.1.3",
                "cve_id": "CVE-2024-22195",
                "cvss_score": 6.5,
                "severity": "MEDIUM",
                "title": "jinja2: Cross-site scripting (XSS) in xmlattr filter",
                "fixed_version": "3.1.3"
            },
            {
                "package": "flask",
                "max_vulnerable_version": "2.2.5",
                "cve_id": "CVE-2023-30861",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "title": "Flask: Session cookie disclosure without Vary: Cookie header",
                "fixed_version": "2.2.5"
            },
            {
                "package": "werkzeug",
                "max_vulnerable_version": "3.0.1",
                "cve_id": "CVE-2023-46136",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "title": "Werkzeug: Denial of service when parsing high numbers of multipart parts",
                "fixed_version": "3.0.1"
            }
        ],
        "javascript": [
            {
                "package": "lodash",
                "max_vulnerable_version": "4.17.21",
                "cve_id": "CVE-2021-23337",
                "cvss_score": 7.2,
                "severity": "HIGH",
                "title": "lodash: Command Injection via template function",
                "fixed_version": "4.17.21"
            },
            {
                "package": "jsonwebtoken",
                "max_vulnerable_version": "9.0.0",
                "cve_id": "CVE-2022-23529",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "title": "jsonwebtoken: Remote code execution in verify function",
                "fixed_version": "9.0.0"
            },
            {
                "package": "axios",
                "max_vulnerable_version": "1.7.4",
                "cve_id": "CVE-2024-39338",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "title": "axios: Server-Side Request Forgery (SSRF) bypass via protocol-relative URLs",
                "fixed_version": "1.7.4"
            },
            {
                "package": "express",
                "max_vulnerable_version": "4.19.2",
                "cve_id": "CVE-2024-29041",
                "cvss_score": 6.1,
                "severity": "MEDIUM",
                "title": "express: Open redirect vulnerability in res.location()",
                "fixed_version": "4.19.2"
            }
        ]
    }

    async def scan(self, target_dir: Path) -> List[RawFinding]:
        findings: List[RawFinding] = []
        trivy_bin = shutil.which("trivy")

        if trivy_bin:
            try:
                logger.info(f"Executing native trivy CLI on {target_dir}")
                cmd = [
                    trivy_bin,
                    "fs",
                    "--format", "json",
                    "--security-checks", "vuln",
                    "--quiet",
                    str(target_dir)
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if proc.stdout:
                    data = json.loads(proc.stdout)
                    for result in data.get("Results", []):
                        target_file = result.get("Target", "dependencies")
                        for vuln in result.get("Vulnerabilities", []):
                            pkg_name = vuln.get("PkgName", "")
                            installed_ver = vuln.get("InstalledVersion", "")
                            fixed_ver = vuln.get("FixedVersion", "")
                            cve_id = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
                            findings.append(RawFinding(
                                tool=self.name(),
                                rule_id=f"trivy.sca.{cve_id.lower()}",
                                title=f"Vulnerable Dependency: {pkg_name}@{installed_ver} ({cve_id})",
                                message=f"{vuln.get('Title', 'Vulnerability detected')}. Upgrade to {fixed_ver or 'latest'}.",
                                severity=vuln.get("Severity", "HIGH"),
                                file_path=target_file.replace("\\", "/"),
                                start_line=1,
                                end_line=1,
                                code_snippet=f"{pkg_name}=={installed_ver}",
                                cve_id=cve_id,
                                cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 7.5),
                                metadata={"fixed_version": fixed_ver, "installed_version": installed_ver}
                            ))
                return findings
            except Exception as e:
                logger.warning(f"Trivy native scan failed, falling back to built-in SCA engine: {e}")

        # Built-in Dependency / SCA Engine
        return self._run_builtin_sca(target_dir)

    def _run_builtin_sca(self, target_dir: Path) -> List[RawFinding]:
        findings: List[RawFinding] = []

        # 1. Scan requirements.txt & Pipfile
        for root, _, files in os.walk(target_dir):
            if "requirements.txt" in files:
                req_path = Path(root) / "requirements.txt"
                rel_path = str(req_path.relative_to(target_dir)).replace("\\", "/")
                findings.extend(self._check_python_requirements(req_path, rel_path))

            if "package.json" in files:
                pkg_path = Path(root) / "package.json"
                # Exclude root frontend dependencies from scanning if user's own project
                if "node_modules" not in str(pkg_path):
                    rel_path = str(pkg_path.relative_to(target_dir)).replace("\\", "/")
                    findings.extend(self._check_package_json(pkg_path, rel_path))

        return findings

    def _check_python_requirements(self, req_path: Path, rel_path: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        try:
            content = req_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()

            for idx, line in enumerate(lines, 1):
                clean_line = line.strip().split("#")[0].strip()
                if not clean_line or clean_line.startswith("-"):
                    continue

                # Match: package==version or package>=version or package<=version
                match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|<=|>=|<|>|~=)\s*([0-9a-zA-Z\.\-]+)", clean_line)
                if match:
                    pkg_name = match.group(1).lower()
                    pkg_ver = match.group(2)

                    for rule in self.VULNERABLE_PACKAGES_DB["python"]:
                        if rule["package"] == pkg_name:
                            # If version is lower or equal to max vulnerable
                            if self._is_version_vulnerable(pkg_ver, rule["max_vulnerable_version"]):
                                findings.append(RawFinding(
                                    tool=self.name(),
                                    rule_id=f"trivy.sca.{rule['cve_id'].lower()}",
                                    title=f"Vulnerable Dependency: {pkg_name}@{pkg_ver} ({rule['cve_id']})",
                                    message=f"{rule['title']}. Upgrade to version {rule['fixed_version']} or higher.",
                                    severity=rule["severity"],
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    code_snippet=clean_line,
                                    cve_id=rule["cve_id"],
                                    cvss_score=rule["cvss_score"],
                                    metadata={"fixed_version": rule["fixed_version"], "package": pkg_name}
                                ))
        except Exception as e:
            logger.debug(f"Failed parsing requirements.txt: {e}")
        return findings

    def _check_package_json(self, pkg_path: Path, rel_path: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        try:
            data = json.loads(pkg_path.read_text(encoding="utf-8", errors="ignore"))
            all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

            for pkg_name, raw_ver in all_deps.items():
                clean_ver = re.sub(r"^[\^~>=<]", "", raw_ver).strip()
                for rule in self.VULNERABLE_PACKAGES_DB["javascript"]:
                    if rule["package"] == pkg_name.lower():
                        if self._is_version_vulnerable(clean_ver, rule["max_vulnerable_version"]):
                            findings.append(RawFinding(
                                tool=self.name(),
                                rule_id=f"trivy.sca.{rule['cve_id'].lower()}",
                                title=f"Vulnerable Dependency: {pkg_name}@{clean_ver} ({rule['cve_id']})",
                                message=f"{rule['title']}. Upgrade to {rule['fixed_version']}.",
                                severity=rule["severity"],
                                file_path=rel_path,
                                start_line=1,
                                end_line=1,
                                code_snippet=f'"{pkg_name}": "{raw_ver}"',
                                cve_id=rule["cve_id"],
                                cvss_score=rule["cvss_score"],
                                metadata={"fixed_version": rule["fixed_version"], "package": pkg_name}
                            ))
        except Exception as e:
            logger.debug(f"Failed parsing package.json: {e}")
        return findings

    def _is_version_vulnerable(self, current: str, max_vuln: str) -> bool:
        def parse(v: str):
            parts = re.findall(r"\d+", v)
            return [int(p) for p in parts] if parts else [0]
        return parse(current) <= parse(max_vuln)
