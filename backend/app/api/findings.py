from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from app.ai.fix_validator import FixValidator
from app.database import get_db
from app.github.pr_commenter import PRCommentFormatter
from app.models import Finding, FindingAnalysis, Scan, Repository
from app.scanners.base import RawFinding
from app.schemas import FindingResponse, FindingStatusUpdate, FindingAnalysisResponse

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("", response_model=List[FindingResponse])
async def list_findings(
    repo_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    min_priority: Optional[float] = None,
    tool: Optional[str] = None,
    reachability: Optional[str] = None,
    exposure: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(Finding)
        .options(selectinload(Finding.analysis))
        .order_by(desc(Finding.priority_score), desc(Finding.created_at))
        .limit(limit)
    )

    if repo_id:
        stmt = stmt.where(Finding.repo_id == repo_id)
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.upper())
    if min_priority is not None:
        stmt = stmt.where(Finding.priority_score >= min_priority)
    if tool:
        stmt = stmt.where(Finding.tool == tool.lower())
    if reachability:
        stmt = stmt.where(Finding.reachability_status == reachability.lower())
    if exposure:
        stmt = stmt.where(Finding.exposure_status == exposure.lower())
    if status:
        stmt = stmt.where(Finding.status == status.lower())
    if search:
        search_fmt = f"%{search.lower()}%"
        stmt = stmt.where(
            Finding.title.ilike(search_fmt) | 
            Finding.rule_id.ilike(search_fmt) | 
            Finding.file_path.ilike(search_fmt)
        )

    result = await db.execute(stmt)
    findings = result.scalars().all()
    return findings

@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Finding).options(selectinload(Finding.analysis)).where(Finding.id == finding_id)
    finding = (await db.execute(stmt)).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding

@router.patch("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Finding).options(selectinload(Finding.analysis)).where(Finding.id == finding_id)
    finding = (await db.execute(stmt)).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    valid_statuses = {"new", "accepted", "false_positive", "fixed", "regressed"}
    if payload.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Choose from: {valid_statuses}")

    finding.status = payload.status
    await db.commit()
    await db.refresh(finding)
    return finding

@router.get("/{finding_id}/pr-comment-preview")
async def get_pr_comment_preview(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Returns markdown formatted comment as would be posted on a GitHub PR review thread."""
    stmt = select(Finding).options(selectinload(Finding.analysis)).where(Finding.id == finding_id)
    finding = (await db.execute(stmt)).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    finding_dict = {
        "id": finding.id,
        "title": finding.title,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "priority_score": finding.priority_score,
        "tool": finding.tool,
        "file_path": finding.file_path,
        "start_line": finding.start_line,
        "cvss_score": finding.cvss_score,
        "epss_score": finding.epss_score,
        "cisa_kev": finding.cisa_kev,
        "reachability_status": finding.reachability_status,
        "exposure_status": finding.exposure_status,
        "message": finding.message
    }
    analysis_dict = {
        "explanation": finding.analysis.explanation if finding.analysis else finding.message,
        "attack_scenario": finding.analysis.attack_scenario if finding.analysis else "",
        "proposed_patch": finding.analysis.proposed_patch if finding.analysis else "",
        "fix_validated": finding.analysis.fix_validated if finding.analysis else False
    }

    markdown = PRCommentFormatter.format_finding_comment(finding_dict, analysis_dict)
    return {"finding_id": finding.id, "markdown": markdown}

@router.post("/{finding_id}/validate-fix")
async def revalidate_fix(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Runs the sandboxed re-scan loop on demand to verify if proposed patch eliminates the finding."""
    stmt = select(Finding).options(selectinload(Finding.analysis)).where(Finding.id == finding_id)
    finding = (await db.execute(stmt)).scalar_one_or_none()
    if not finding or not finding.analysis:
        raise HTTPException(status_code=404, detail="Finding or analysis not found.")

    raw = RawFinding(
        tool=finding.tool,
        rule_id=finding.rule_id,
        title=finding.title,
        message=finding.message,
        severity=finding.severity,
        file_path=finding.file_path,
        start_line=finding.start_line,
        end_line=finding.end_line,
        code_snippet=finding.code_snippet,
        cve_id=finding.cve_id,
        cvss_score=finding.cvss_score
    )

    validator = FixValidator()
    is_valid, details = await validator.validate_patch(
        finding=raw,
        proposed_patch=finding.analysis.proposed_patch
    )

    finding.analysis.fix_validated = is_valid
    finding.analysis.validation_details = details
    await db.commit()

    return {
        "finding_id": finding.id,
        "fix_validated": is_valid,
        "details": details
    }
