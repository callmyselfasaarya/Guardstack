import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.ai.analyzer import FindingAIAnalyzer
from app.ai.fix_validator import FixValidator
from app.database import get_db, AsyncSessionLocal
from app.models import Repository, Scan, Finding, FindingAnalysis
from app.prioritization.feeds import feed_client
from app.prioritization.risk_engine import RiskPrioritizationEngine
from app.scanners.orchestrator import ScannerOrchestrator
from app.schemas import ScanTriggerRequest, ScanResponse

logger = logging.getLogger("guardstack.api.scans")
router = APIRouter(prefix="/scans", tags=["Scans"])

async def run_scan_pipeline(scan_id: str, repo_id: str, target_path: str, scanners: List[str]):
    """Background async worker running scanner orchestration (Semgrep, Gitleaks, Trivy), risk engine, and AI fix validation."""
    async with AsyncSessionLocal() as db:
        stmt = select(Scan).where(Scan.id == scan_id)
        scan = (await db.execute(stmt)).scalar_one_or_none()
        if not scan:
            return

        scan.status = "running"
        await db.commit()

        try:
            target_dir = Path(target_path)
            if not target_dir.exists():
                target_dir = Path(__file__).resolve().parent.parent / "benchmark" / "corpus" / "vulnerable_app"

            orchestrator = ScannerOrchestrator()
            raw_findings = await orchestrator.execute_scans(target_dir, enabled_scanners=scanners)

            validator = FixValidator()
            critical_c = 0
            high_c = 0
            medium_c = 0
            low_c = 0
            actionable_c = 0
            validated_fixes_c = 0

            # Historic fingerprints for repo to compute new/persistent/fixed state
            hist_stmt = select(Finding.fingerprint, Finding.status).where(Finding.repo_id == repo_id)
            hist_res = (await db.execute(hist_stmt)).all()
            prev_active = {fp for fp, st in hist_res if st in {"new", "persistent", "regressed"}}
            prev_fixed = {fp for fp, st in hist_res if st == "fixed"}

            for rf in raw_findings:
                fp = rf.generate_fingerprint()

                # 1. State lifecycle across commits (new / persistent / regressed)
                if fp in prev_fixed:
                    status = "regressed"
                elif fp in prev_active:
                    status = "persistent"
                else:
                    status = "new"

                # 2. File content
                file_full = target_dir / rf.file_path
                file_text = file_full.read_text(encoding="utf-8", errors="ignore") if file_full.exists() else rf.code_snippet

                # 3. Threat feeds (EPSS and CISA KEV)
                epss_val, in_kev = await feed_client.get_cve_threat_intel(rf.cve_id)

                # 4. Risk Prioritization (CVSS + EPSS + CISA KEV)
                priority_score, tier, breakdown = RiskPrioritizationEngine.calculate_priority_score(
                    severity=rf.severity,
                    cvss_score=rf.cvss_score,
                    epss_score=epss_val,
                    in_cisa_kev=in_kev
                )

                if rf.severity == "CRITICAL":
                    critical_c += 1
                elif rf.severity == "HIGH":
                    high_c += 1
                elif rf.severity == "MEDIUM":
                    medium_c += 1
                else:
                    low_c += 1

                if breakdown["is_actionable_blocker"]:
                    actionable_c += 1

                # 5. LLM Analysis: structured JSON (explanation, false-positive likelihood, confidence, proposed patch)
                analysis_dict = await FindingAIAnalyzer.analyze_finding(
                    finding=rf,
                    file_content=file_text
                )

                # 6. Fix Validation Loop: apply patch to copy, re-run scanner, mark "verified" or "failed"
                is_valid, val_details = await validator.validate_patch(
                    finding=rf,
                    proposed_patch=analysis_dict.get("proposed_patch", ""),
                    repo_root=target_dir
                )

                validation_status = "verified" if is_valid else "failed"
                if is_valid:
                    validated_fixes_c += 1

                # Persist Finding Model
                f_model = Finding(
                    scan_id=scan.id,
                    repo_id=repo_id,
                    fingerprint=fp,
                    tool=rf.tool,
                    rule_id=rf.rule_id,
                    title=rf.title,
                    message=rf.message,
                    severity=rf.severity,
                    cve_id=rf.cve_id,
                    cvss_score=rf.cvss_score,
                    epss_score=epss_val,
                    cisa_kev=in_kev,
                    priority_score=priority_score,
                    file_path=rf.file_path,
                    start_line=rf.start_line,
                    end_line=rf.end_line,
                    code_snippet=rf.code_snippet,
                    status=status
                )
                db.add(f_model)
                await db.flush()

                # Persist Finding Analysis Model
                a_model = FindingAnalysis(
                    finding_id=f_model.id,
                    explanation=analysis_dict.get("explanation", ""),
                    attack_scenario=analysis_dict.get("attack_scenario", ""),
                    false_positive_likelihood=analysis_dict.get("false_positive_likelihood", "low"),
                    confidence=analysis_dict.get("confidence", 0.90),
                    proposed_patch=analysis_dict.get("proposed_patch", ""),
                    fix_validated=is_valid,
                    validation_status=validation_status,
                    validation_details=val_details
                )
                db.add(a_model)

            # Mark findings absent from current scan as FIXED
            current_fps = {rf.generate_fingerprint() for rf in raw_findings}
            for active_fp in prev_active:
                if active_fp not in current_fps:
                    update_stmt = select(Finding).where(Finding.repo_id == repo_id, Finding.fingerprint == active_fp)
                    prev_finding = (await db.execute(update_stmt)).scalars().first()
                    if prev_finding:
                        prev_finding.status = "fixed"

            total_findings = len(raw_findings)
            noise_reduction = round(((total_findings - actionable_c) / total_findings) * 100.0, 1) if total_findings > 0 else 0.0
            fixes_val_pct = round((validated_fixes_c / total_findings) * 100.0, 1) if total_findings > 0 else 0.0

            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.summary_stats = {
                "total_findings": total_findings,
                "critical": critical_c,
                "high": high_c,
                "medium": medium_c,
                "low": low_c,
                "actionable_count": actionable_c,
                "noise_reduction_pct": noise_reduction,
                "fixes_validated_pct": fixes_val_pct,
                "validated_fixes_count": validated_fixes_c
            }
            scan.logs = f"Scan completed successfully at {datetime.now(timezone.utc).isoformat()}.\nScanners executed: {', '.join(scanners)}.\nTotal findings analyzed: {total_findings}."
            await db.commit()

        except Exception as e:
            logger.error(f"Scan pipeline execution failed: {e}", exc_info=True)
            scan.status = "failed"
            scan.logs = f"Scan failed with error: {str(e)}"
            await db.commit()

@router.post("", response_model=ScanResponse)
async def trigger_scan(
    payload: ScanTriggerRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Repository).where(Repository.full_name == payload.repo_full_name)
    repo = (await db.execute(stmt)).scalar_one_or_none()
    if not repo:
        repo_name = payload.repo_full_name.split("/")[-1]
        repo = Repository(
            name=repo_name,
            full_name=payload.repo_full_name,
            clone_url="",
            default_branch=payload.branch or "main"
        )
        db.add(repo)
        await db.commit()
        await db.refresh(repo)

    scan = Scan(
        repo_id=repo.id,
        commit_hash=payload.commit_hash or "HEAD",
        branch=payload.branch or "main",
        pr_number=payload.pr_number,
        trigger_type="manual" if not payload.pr_number else "pull_request",
        status="queued",
        scanner_types=",".join(payload.scanners)
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    target_path = payload.target_path_or_url or str(Path(__file__).resolve().parent.parent / "benchmark" / "corpus" / "vulnerable_app")
    background_tasks.add_task(run_scan_pipeline, scan.id, repo.id, target_path, payload.scanners)

    return ScanResponse(
        id=scan.id,
        repo_id=scan.repo_id,
        commit_hash=scan.commit_hash,
        branch=scan.branch,
        pr_number=scan.pr_number,
        trigger_type=scan.trigger_type,
        status=scan.status,
        scanner_types=scan.scanner_types,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        summary_stats=scan.summary_stats,
        logs=scan.logs,
        findings_count=0
    )

@router.get("", response_model=List[ScanResponse])
async def list_scans(repo_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    stmt = select(Scan).order_by(Scan.started_at.desc())
    if repo_id:
        stmt = stmt.where(Scan.repo_id == repo_id)
    result = await db.execute(stmt)
    scans = result.scalars().all()

    response = []
    for s in scans:
        f_count_stmt = select(func.count(Finding.id)).where(Finding.scan_id == s.id)
        f_count = (await db.execute(f_count_stmt)).scalar() or 0
        response.append(ScanResponse(
            id=s.id,
            repo_id=s.repo_id,
            commit_hash=s.commit_hash,
            branch=s.branch,
            pr_number=s.pr_number,
            trigger_type=s.trigger_type,
            status=s.status,
            scanner_types=s.scanner_types,
            started_at=s.started_at,
            completed_at=s.completed_at,
            summary_stats=s.summary_stats or {},
            logs=s.logs or "",
            findings_count=f_count
        ))
    return response

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Scan).where(Scan.id == scan_id)
    scan = (await db.execute(stmt)).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    f_count_stmt = select(func.count(Finding.id)).where(Finding.scan_id == scan.id)
    f_count = (await db.execute(f_count_stmt)).scalar() or 0

    return ScanResponse(
        id=scan.id,
        repo_id=scan.repo_id,
        commit_hash=scan.commit_hash,
        branch=scan.branch,
        pr_number=scan.pr_number,
        trigger_type=scan.trigger_type,
        status=scan.status,
        scanner_types=scan.scanner_types,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        summary_stats=scan.summary_stats or {},
        logs=scan.logs or "",
        findings_count=f_count
    )
