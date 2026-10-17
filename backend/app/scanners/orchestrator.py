import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from app.scanners.base import BaseScanner, RawFinding
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.trivy_scanner import TrivyScanner
from app.scanners.zap_scanner import ZapScanner

logger = logging.getLogger("guardstack.scanners.orchestrator")

class ScannerOrchestrator:
    def __init__(self):
        self.scanners: Dict[str, BaseScanner] = {
            "semgrep": SemgrepScanner(),
            "gitleaks": GitleaksScanner(),
            "trivy": TrivyScanner(),
            "zap": ZapScanner()
        }

    async def execute_scans(
        self,
        target_dir: Path,
        enabled_scanners: Optional[List[str]] = None,
        dast_url: Optional[str] = None
    ) -> List[RawFinding]:
        """
        Run selected scanners concurrently against the target workspace directory.
        """
        if not enabled_scanners:
            enabled_scanners = ["semgrep", "gitleaks", "trivy"]

        tasks = []
        for name in enabled_scanners:
            scanner = self.scanners.get(name)
            if scanner:
                if name == "zap" and dast_url:
                    tasks.append(scanner.scan_url(dast_url))
                elif name != "zap":
                    tasks.append(scanner.scan(target_dir))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_findings: List[RawFinding] = []

        for res in results:
            if isinstance(res, Exception):
                logger.error(f"Scanner task encountered an error: {res}")
            elif isinstance(res, list):
                all_findings.extend(res)

        # Deduplicate by fingerprint
        unique_findings: List[RawFinding] = []
        seen_fingerprints: Set[str] = set()

        for f in all_findings:
            fp = f.generate_fingerprint()
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                unique_findings.append(f)

        logger.info(f"Orchestration complete. Collected {len(unique_findings)} unique findings.")
        return unique_findings

    @staticmethod
    def compute_finding_deltas(
        current_fingerprints: Set[str],
        previous_active_fingerprints: Set[str],
        previous_fixed_fingerprints: Set[str]
    ) -> Dict[str, str]:
        """
        Computes lifecycle status (new, fixed, regressed) for findings across commits.
        Returns mapping from fingerprint to status.
        """
        status_map: Dict[str, str] = {}
        for fp in current_fingerprints:
            if fp in previous_fixed_fingerprints:
                status_map[fp] = "regressed"
            elif fp in previous_active_fingerprints:
                status_map[fp] = "existing"
            else:
                status_map[fp] = "new"
        return status_map
