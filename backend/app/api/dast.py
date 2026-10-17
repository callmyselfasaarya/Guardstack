import uuid
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.database import get_db
from app.models import DASTTarget, Scan, Finding, Repository
from app.scanners.zap_scanner import ZapScanner
from app.schemas import (
    DASTChallengeRequest,
    DASTChallengeResponse,
    DASTVerifyRequest,
    DASTScanRequest
)

router = APIRouter(prefix="/dast", tags=["DAST (OWASP ZAP)"])

@router.post("/challenge", response_model=DASTChallengeResponse)
async def generate_dast_challenge(payload: DASTChallengeRequest, db: AsyncSession = Depends(get_db)):
    url = payload.target_url.strip().rstrip("/")
    stmt = select(DASTTarget).where(DASTTarget.url == url)
    target = (await db.execute(stmt)).scalar_one_or_none()

    token = f"guardstack-verify-{uuid.uuid4().hex[:16]}"
    if not target:
        target = DASTTarget(
            url=url,
            verification_token=token,
            verified=False
        )
        db.add(target)
    else:
        target.verification_token = token
        target.verified = False

    await db.commit()

    return DASTChallengeResponse(
        target_url=url,
        verification_token=token,
        expected_path=settings.DAST_CHALLENGE_FILE,
        expected_header="X-Guardstack-Verification",
        instructions=(
            f"To prove ownership of {url}, host a text file containing exactly '{token}' at "
            f"'{url}{settings.DAST_CHALLENGE_FILE}' or return the HTTP header 'X-Guardstack-Verification: {token}'. "
            "Localhost addresses are automatically verified for development."
        )
    )

@router.post("/verify")
async def verify_target_ownership(payload: DASTVerifyRequest, db: AsyncSession = Depends(get_db)):
    url = payload.target_url.strip().rstrip("/")
    stmt = select(DASTTarget).where(DASTTarget.url == url)
    target = (await db.execute(stmt)).scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target URL not registered. Request a challenge token first.")

    scanner = ZapScanner()
    verified, message = await scanner.verify_target_ownership(url, target.verification_token)
    if verified:
        target.verified = True
        target.verified_at = datetime.now(timezone.utc)
        await db.commit()
        return {"status": "success", "verified": True, "message": message}
    else:
        return {"status": "failed", "verified": False, "message": message}

@router.post("/scan")
async def trigger_dast_scan(payload: DASTScanRequest, db: AsyncSession = Depends(get_db)):
    url = payload.target_url.strip().rstrip("/")
    stmt = select(DASTTarget).where(DASTTarget.url == url)
    target = (await db.execute(stmt)).scalar_one_or_none()

    scanner = ZapScanner()
    # Check verification
    if not target or not target.verified:
        # Check if dev localhost bypass applies
        verified, _ = await scanner.verify_target_ownership(url, "")
        if not verified:
            raise HTTPException(
                status_code=403,
                detail=f"Target '{url}' is not verified. Complete HTTP challenge verification before running DAST scans."
            )

    # Find or register DAST target repository
    repo_name = f"dast-{url.split('://')[-1].replace('/', '-').replace(':', '-')}"
    repo_stmt = select(Repository).where(Repository.full_name == repo_name)
    repo = (await db.execute(repo_stmt)).scalar_one_or_none()
    if not repo:
        repo = Repository(name=repo_name, full_name=repo_name, default_branch="live")
        db.add(repo)
        await db.commit()
        await db.refresh(repo)

    # Create scan record
    scan = Scan(
        repo_id=repo.id,
        commit_hash="LIVE",
        branch="live",
        trigger_type="dast",
        status="running",
        scanner_types="zap"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    raw_findings = await scanner.scan_url(url)
    for rf in raw_findings:
        f_model = Finding(
            scan_id=scan.id,
            repo_id=repo.id,
            fingerprint=rf.generate_fingerprint(),
            tool=rf.tool,
            rule_id=rf.rule_id,
            title=rf.title,
            message=rf.message,
            severity=rf.severity,
            cvss_score=rf.cvss_score,
            reachability_status="reachable",
            exposure_status="public_route",
            priority_score=round(rf.cvss_score * 10.0, 1) if rf.cvss_score else 50.0,
            file_path=rf.file_path,
            start_line=1,
            end_line=1,
            code_snippet=rf.code_snippet,
            status="new"
        )
        db.add(f_model)

    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)
    scan.summary_stats = {
        "total_findings": len(raw_findings),
        "critical": sum(1 for f in raw_findings if f.severity == "CRITICAL"),
        "high": sum(1 for f in raw_findings if f.severity == "HIGH"),
        "medium": sum(1 for f in raw_findings if f.severity == "MEDIUM"),
        "low": sum(1 for f in raw_findings if f.severity == "LOW")
    }
    scan.logs = f"DAST baseline scan completed on {url}. Identified {len(raw_findings)} potential security findings."
    if target:
        target.last_scanned_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        "status": "completed",
        "scan_id": scan.id,
        "target_url": url,
        "findings_count": len(raw_findings)
    }

@router.get("/targets")
async def list_dast_targets(db: AsyncSession = Depends(get_db)):
    stmt = select(DASTTarget).order_by(DASTTarget.created_at.desc())
    targets = (await db.execute(stmt)).scalars().all()
    return targets
